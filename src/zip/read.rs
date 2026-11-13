// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

//! Checked ZIP read policy, bounded output leases, and inline terminal evidence.
mod budget;
mod cipher;
mod codecs;
mod error;
mod projected;
pub use io::{BootstrapPhase, BootstrapUsage};
pub use projected::ProjectedReadSession;
#[cfg(test)]
pub(in crate::zip) use projected::observe as observe_projected;
pub(crate) use projected::{CheckedOpen, ProjectedOwner};
pub(in crate::zip) use projected::{checked_read, identity as projected_identity};
pub(super) mod io;
mod shared;
mod spool;
use crate::extract::Cancellation;
pub use budget::{EncryptedReadLimits, EncryptedReadUsage, RunUsage};
pub use error::*;
use shared::{ContextLedger, ReservationLedger};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct EncryptedReadOptions {
    limits: EncryptedReadLimits,
    temp_dir: Option<PathBuf>,
    lzma_memory_bytes: u64,
    zstd_window_log_max: u32,
}
impl Default for EncryptedReadOptions {
    fn default() -> Self {
        Self { limits: Default::default(), temp_dir: None, lzma_memory_bytes: 256 << 20, zstd_window_log_max: 27 }
    }
}
impl EncryptedReadOptions {
    pub fn with_limits(mut self, limits: EncryptedReadLimits) -> Self {
        self.limits = limits;
        self
    }
    pub fn with_temp_dir(mut self, directory: PathBuf) -> Self {
        self.temp_dir = Some(directory);
        self
    }
    pub fn with_lzma_memory_bytes(mut self, bytes: u64) -> Self {
        self.lzma_memory_bytes = bytes;
        self
    }
    pub fn with_zstd_window_log_max(mut self, log: u32) -> Self {
        self.zstd_window_log_max = log;
        self
    }
    pub fn limits(&self) -> &EncryptedReadLimits {
        &self.limits
    }
}
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct EncryptedReadOverrides {
    pub member_packed_bytes: Option<u64>,
    pub member_decoded_bytes: Option<u64>,
    pub live_spool_bytes: Option<u128>,
    pub packed_bytes: Option<u128>,
    pub decoded_bytes: Option<u128>,
    pub io_bytes: Option<u128>,
    pub work_bytes: Option<u128>,
    pub io_attempts: Option<u128>,
    pub codec_steps: Option<u128>,
    pub members: Option<u64>,
    pub kdf_calls: Option<u64>,
    pub password_bytes: Option<u64>,
    pub interrupted_retries: Option<u64>,
    pub create_attempts: Option<u64>,
    pub temp_dir: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProjectedReadScope {
    AllRegular,
    Entry(usize),
}
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ZipReadOutput<'a> {
    Discard,
    Callback,
    StagedFiles { destination: &'a Path },
    VerifiedStdout,
}

/// An action-local policy and two ledgers. Contexts and leases stay on one thread.
/// ```compile_fail
/// use zipfast::zip::{EncryptedReadContext, EncryptedReadOptions};
/// let context = EncryptedReadContext::new(EncryptedReadOptions::default()).unwrap();
/// std::thread::spawn(move || drop(context));
/// ```
/// ```compile_fail
/// use zipfast::zip::EncryptedReadContext;
/// fn sync<T: Sync>() {} sync::<EncryptedReadContext>();
/// ```
pub struct EncryptedReadContext {
    ledger: ContextLedger,
    options: EncryptedReadOptions,
    bootstrap: io::BootstrapIo,
    action: Option<projected::Action>,
    temp: Option<spool::ResolvedTempDirectory>,
}
impl Drop for EncryptedReadContext {
    fn drop(&mut self) {
        if let Some(temp) = self.temp.take() {
            let result = temp.finish_capacity(&self.ledger);
            debug_assert!(result.is_ok(), "same ledger owns temporary path capacity");
        }
        if let Some(action) = self.action.take() {
            drop(action.destination);
        }
    }
}
impl EncryptedReadContext {
    pub(in crate::zip) fn verify_identity(&self, identity: u64) -> Result<(), ReadFault> {
        if let Some(action) = &self.action {
            if action.identity != identity {
                return Err(ReadFault::InvalidPlan);
            }
            self.ledger.with_state(|s| s.verify_action(action))?;
        }
        Ok(())
    }
    // Fixed inline terminal evidence (measured in core tests) cannot be boxed on failure.
    #[allow(clippy::result_large_err)]
    pub fn new(options: EncryptedReadOptions) -> ZipReadResult<Self> {
        let state = budget::LedgerState::new(&options)?;
        let mut bootstrap = io::BootstrapIo::new(129 << 20, options.limits.interrupted_retries)?;
        bootstrap.acquisition(shared::SHARED_LEDGER_CAPACITY)?;
        let ledger = ContextLedger::try_new(state).map_err(|error| error.with_bootstrap(bootstrap.usage()))?;
        Ok(Self { ledger, options, bootstrap, action: None, temp: None })
    }
    pub(in crate::zip) fn source_group(&mut self, source: super::session::SourceStamp) -> Result<(), ReadFault> {
        self.ledger.with_state(|s| {
            if s.bound() {
                s.verify_source(source)?;
                s.charge_category(RunCategory::SourceCheckGroups, 1)?;
            }
            Ok(())
        })
    }
    pub(in crate::zip) fn source_stat<T>(
        &mut self,
        stage: IoStage,
        mut call: impl FnMut() -> std::io::Result<T>,
    ) -> Result<T, io::SourceCheckError> {
        if !self.ledger.with_state(|s| s.bound()) {
            return self.bootstrap.stat(stage, call);
        }
        let mut retries = 0u64;
        loop {
            self.ledger.with_state(|s| s.attempt(false)).map_err(io::SourceCheckError::Admission)?;
            match call() {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    retries =
                        retries.checked_add(1).ok_or(io::SourceCheckError::Admission(ReadFault::CounterOverflow))?;
                    budget::admit(
                        ReadResource::InterruptedRetries,
                        self.options.limits.interrupted_retries.into(),
                        retries.into(),
                    )
                    .map_err(io::SourceCheckError::Admission)?;
                }
                Err(error) => {
                    return Err(io::SourceCheckError::Source(CheckedSourceFault::Unavailable { stage, error }));
                }
            }
        }
    }
    pub fn usage(&self) -> EncryptedReadUsage {
        self.ledger.with_state(|s| s.encrypted.usage)
    }
    pub fn run_usage(&self) -> RunUsage {
        self.ledger.with_state(|s| s.run.usage)
    }
    pub fn options(&self) -> &EncryptedReadOptions {
        &self.options
    }
    /// Registers caller-owned files; the token borrows neither the context nor handles.
    /// Registration does not close caller handles. Unconfirmed drop retains unresolved resource usage and poisons acquisition.
    /// A catalogue-bound action is required; an unbound context refuses before I/O.
    /// The raw caller keeps the registered handles open, preserves descriptor
    /// flags, and owns actual close/storage cleanup. Caller seeks are harmless
    /// to writes, which use the lease's positional offset. Unconfirmed drop
    /// cannot prove resources retired and permanently poisons this action.
    #[allow(clippy::result_large_err)] // Fixed no-allocation terminal evidence.
    pub fn reserve_output(
        &mut self,
        file: &File,
        parent: Option<&File>,
        bytes: u64,
    ) -> ZipReadResult<OutputReservation> {
        if !cfg!(unix) {
            return Err(ReadFault::UnsupportedIdentity.into());
        }
        if !self.ledger.with_state(|s| s.bound()) {
            return Err(ReadFault::InvalidPlan.into());
        }
        let encrypted = self.ledger.with_state(|s| s.output_encrypted())?;
        let token = self.ledger.mint_reservation()?;
        let result = (|| {
            let identity = io::operation(
                &token,
                encrypted,
                RunCategory::StageFinalization,
                IoStage::Output,
                ReadIoOperation::Stat,
                None,
                || file.metadata(),
            )?;
            if bytes > i64::MAX as u64 {
                return Err(ReadFault::CounterOverflow);
            }
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let flags = io::operation(
                    &token,
                    encrypted,
                    RunCategory::StageFinalization,
                    IoStage::Output,
                    ReadIoOperation::DescriptorMode,
                    None,
                    || {
                        // SAFETY: File keeps this descriptor open for one nonmutating syscall.
                        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
                        if flags < 0 { Err(std::io::Error::last_os_error()) } else { Ok(flags) }
                    },
                )?;
                if flags & libc::O_APPEND != 0 || flags & libc::O_ACCMODE == libc::O_RDONLY {
                    return Err(ReadFault::InvalidPlan);
                }
            }
            if !identity.is_file() || identity.len() != 0 {
                return Err(ReadFault::InvalidPlan);
            }
            if let Some(parent) = parent {
                let metadata = io::operation(
                    &token,
                    encrypted,
                    RunCategory::StageFinalization,
                    IoStage::Output,
                    ReadIoOperation::Stat,
                    None,
                    || parent.metadata(),
                )?;
                if !metadata.is_dir() {
                    return Err(ReadFault::InvalidPlan);
                }
            }
            // Task4 binds member scope; selected clear registrations must never spend encrypted quota.
            token.with_state(|s| s.reserve(encrypted, bytes, if parent.is_some() { 2 } else { 1 }))?;
            Ok(OutputReservation {
                ledger: token,
                encrypted,
                bytes,
                written: 0,
                fds: if parent.is_some() { 2 } else { 1 },
                identity: FileIdentity::capture(&identity),
                handle: file_handle(file),
                retired: false,
            })
        })();
        result.map_err(|fault: ReadFault| ZipReadError::from(fault).with_usage(self.usage(), self.run_usage()))
    }
}
#[derive(Debug, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}
impl FileIdentity {
    fn capture(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self { dev: metadata.dev(), ino: metadata.ino() }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self { dev: 0, ino: 0 }
        }
    }
}
fn file_handle(file: &File) -> usize {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        file.as_raw_fd() as usize
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        file.as_raw_handle() as usize
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        0
    }
}
struct PositionedWriter<'a> {
    file: &'a File,
    offset: u64,
}
impl Write for PositionedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let offset = libc::off_t::try_from(self.offset)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            // SAFETY: the borrowed File remains live; this immutable slice is valid
            // for its entire length. One pwrite is exactly one budgeted attempt.
            let n = unsafe { libc::pwrite(self.file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), offset) };
            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::FileExt;
            self.file.seek_write(bytes, self.offset)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = bytes;
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// A bounded lease for one registered output. It is neither Send nor Sync.
/// ```compile_fail
/// use zipfast::zip::OutputReservation;
/// fn send<T: Send>() {} send::<OutputReservation>();
/// ```
/// ```compile_fail
/// use zipfast::zip::OutputReservation;
/// fn sync<T: Sync>() {} sync::<OutputReservation>();
/// ```
pub struct OutputReservation {
    ledger: ReservationLedger,
    encrypted: bool,
    bytes: u64,
    written: u64,
    fds: u64,
    identity: FileIdentity,
    handle: usize,
    retired: bool,
}
struct ScratchLease<'a> {
    ledger: &'a ReservationLedger,
    bytes: u64,
}
impl Drop for ScratchLease<'_> {
    fn drop(&mut self) {
        self.ledger.with_state(|s| s.release_capacity(self.bytes));
    }
}
impl OutputReservation {
    fn check_file(&self, file: &File, cancel: &Cancellation) -> Result<(), ReadFault> {
        let metadata = io::operation(
            &self.ledger,
            self.encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || file.metadata(),
        )?;
        if !metadata.is_file()
            || FileIdentity::capture(&metadata) != self.identity
            || file_handle(file) != self.handle
            || metadata.len() != self.bytes
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    pub fn write_all(&mut self, file: &mut File, bytes: &[u8], cancel: &Cancellation) -> ZipSinkResult<()> {
        if file_handle(file) != self.handle {
            return Err(ZipSinkFault::StageChanged);
        }
        io::canceled(Some(cancel)).map_err(io::sink)?;
        let next = self.written.checked_add(bytes.len() as u64).ok_or(ZipSinkFault::StageChanged)?;
        if next > self.bytes {
            return Err(ZipSinkFault::Limit {
                resource: ReadResource::MemberDecodedBytes,
                limit: self.bytes.into(),
                attempted: next.into(),
            });
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let n = io::write(
                &self.ledger,
                self.encrypted,
                &mut PositionedWriter { file, offset: self.written },
                IoStage::Output,
                self.written,
                remaining,
                cancel,
            )
            .map_err(io::sink)?;
            self.written += n as u64;
            remaining = &remaining[n..];
        }
        Ok(())
    }
    /// Call only after successful verification and a final source check.
    #[allow(clippy::result_large_err)] // Fixed no-allocation terminal evidence.
    pub fn copy_to(&mut self, file: &mut File, out: &mut impl Write, cancel: &Cancellation) -> ZipReadResult<u64> {
        let mut accepted = 0u64;
        self.ledger.with_state(|s| s.reserve_capacity(io::WINDOW as u64))?;
        let scratch = ScratchLease { ledger: &self.ledger, bytes: io::WINDOW as u64 };
        let result = (|| {
            self.check_file(file, cancel)?;
            if self.written != self.bytes {
                return Err(ReadFault::InvalidPlan);
            }
            io::rewind(&self.ledger, self.encrypted, file, cancel)?;
            let mut buffer = [0; io::WINDOW];
            let mut fetched = 0;
            while fetched < self.bytes {
                let count = (self.bytes - fetched).min(buffer.len() as u64) as usize;
                let n = io::read(
                    &self.ledger,
                    self.encrypted,
                    file,
                    IoStage::Output,
                    fetched,
                    &mut buffer[..count],
                    cancel,
                )?;
                if n == 0 {
                    return Err(ReadFault::Io {
                        stage: IoStage::Output,
                        operation: ReadIoOperation::Read,
                        offset: fetched,
                        error: std::io::ErrorKind::UnexpectedEof.into(),
                    });
                }
                fetched += n as u64;
                let mut remaining = &buffer[..n];
                while !remaining.is_empty() {
                    let n = io::write(
                        &self.ledger,
                        self.encrypted,
                        out,
                        IoStage::ExternalOutput,
                        accepted,
                        remaining,
                        cancel,
                    )?;
                    accepted += n as u64;
                    remaining = &remaining[n..];
                }
            }
            Ok(accepted)
        })();
        drop(scratch);
        result.map_err(|fault: ReadFault| {
            self.ledger
                .with_state(|s| ZipReadError::from(fault).with_usage(s.encrypted.usage, s.run.usage).accepted(accepted))
        })
    }
}
impl OutputReservation {
    #[allow(dead_code)] // Task5 controlled stage alone confirms its owned resources retired.
    pub(crate) fn retire_confirmed(mut self) {
        self.ledger.with_state(|s| {
            s.release_bytes(self.encrypted, self.bytes);
            for _ in 0..self.fds {
                s.retire_fd(true);
            }
        });
        self.retired = true;
    }
}
impl Drop for OutputReservation {
    fn drop(&mut self) {
        if !self.retired {
            // Caller still owns the imported resources. Registration ending proves
            // neither close nor storage cleanup: retain usage and poison acquisition.
            self.ledger.with_state(|s| s.poisoned = true);
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ZipRunReport {
    files: u64,
    dirs: u64,
    skipped: u64,
    failed: u64,
    volumes: u64,
    decoded_bytes: u128,
    usage: EncryptedReadUsage,
    run_usage: RunUsage,
}
impl ZipRunReport {
    pub fn files(&self) -> u64 {
        self.files
    }
    pub fn dirs(&self) -> u64 {
        self.dirs
    }
    pub fn skipped(&self) -> u64 {
        self.skipped
    }
    pub fn failed(&self) -> u64 {
        self.failed
    }
    pub fn volumes(&self) -> u64 {
        self.volumes
    }
    pub fn decoded_bytes(&self) -> u128 {
        self.decoded_bytes
    }
    pub fn usage(&self) -> EncryptedReadUsage {
        self.usage
    }
    pub fn run_usage(&self) -> RunUsage {
        self.run_usage
    }
}
#[cfg(test)]
mod tests;
