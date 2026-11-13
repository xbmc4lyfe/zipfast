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

//! One immutable projected catalogue, kept with its original data handle.
use super::shared::LedgerAccess;
use super::*;
use crate::zip::session::{SourceBinding, SourceStamp};
use crate::zip::{self, EntryId, ReadDescription, ZipEntry};
use std::io::{Read, Seek};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(super) struct Observations {
    pub(super) opens: usize,
    pub(super) parses: usize,
    pub(super) records: usize,
    pub(super) names: usize,
    pub(super) headers: usize,
}
#[cfg(test)]
thread_local! {pub(super) static OBSERVATIONS:std::cell::Cell<Observations>=const{std::cell::Cell::new(Observations{opens:0,parses:0,records:0,names:0,headers:0})};}
#[cfg(test)]
thread_local! {pub(super) static CLOSE_FAULT:std::cell::Cell<Option<i32>>=const{std::cell::Cell::new(None)};}
#[cfg(test)]
thread_local! {pub(super) static IDENTITY_FAULT:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};}
#[cfg(test)]
thread_local! {pub(super) static LEGACY_CWD_FAULT:std::cell::Cell<Option<i32>>=const{std::cell::Cell::new(None)};}
#[cfg(test)]
type OpeningHook = Option<Box<dyn FnMut(u8)>>;
#[cfg(test)]
thread_local! {pub(super) static OPEN_HOOK:std::cell::RefCell<OpeningHook>=const {std::cell::RefCell::new(None)};}
#[cfg(test)]
pub(in crate::zip) fn observe(kind: u8) {
    OBSERVATIONS.with(|s| {
        let mut n = s.get();
        match kind {
            0 => n.opens += 1,
            1 => n.parses += 1,
            2 => n.records += 1,
            3 => n.names += 1,
            4 => n.headers += 1,
            5 | 6 | 8 => {} // Legacy proof, completed parse, explicit postfactory controls only.
            _ => unreachable!(),
        };
        s.set(n);
    });
    let mut hook = OPEN_HOOK.with(|s| s.borrow_mut().take());
    if let Some(callback) = &mut hook {
        callback(kind);
    }
    OPEN_HOOK.with(|s| *s.borrow_mut() = hook);
}
static IDENTITIES: AtomicU64 = AtomicU64::new(1);
pub(super) fn next_identity(counter: &AtomicU64) -> Result<u64, ReadFault> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| ReadFault::CounterOverflow)
}
pub(in crate::zip) fn identity() -> Result<u64, ReadFault> {
    #[cfg(test)]
    if IDENTITY_FAULT.with(|s| s.take()) {
        return Err(ReadFault::CounterOverflow);
    }
    next_identity(&IDENTITIES)
}

pub(super) struct Action {
    pub(super) identity: u64,
    pub(super) scope: ProjectedReadScope,
    pub(super) output: budget::PlannedOutput,
    pub(super) caller_max: Option<u64>,
    pub(super) password_bytes: u64,
    pub(super) consumed: bool,
    pub(super) destination: Option<PathBuf>,
    pub(super) completed: bool,
}
/// A checked owner of one original projected parse. No mutable catalogue is exposed.
/// Handle/path identity, length, mtime and ctime checks are optimistic observations:
/// writers may race checks or restore observed state. Sink bytes remain provisional
/// through verification and a final caller source check before publication.
pub struct ProjectedReadSession {
    pub(crate) owner: ProjectedOwner,
}
pub(crate) struct ProjectedOwner {
    pub(super) file: File,
    pub(super) entries: Vec<ZipEntry>,
    pub(super) source: Result<SourceBinding, io::SourceCheckError>,
    pub(super) identity: u64,
    len: u64,
    opening: io::BootstrapIo,
    parser_usage: zip::Usage,
}
#[allow(clippy::result_large_err)] // The inline evidence never allocates on failure.
impl ProjectedReadSession {
    pub fn open(path: &Path, cancel: &Cancellation) -> ZipReadResult<Self> {
        let owner = ProjectedOwner::open_checked(path, cancel)?;
        Ok(Self { owner })
    }
    pub fn entries(&self) -> impl ExactSizeIterator<Item = &ZipEntry> {
        self.owner.entries.iter()
    }
    pub fn entry_id(&self, ordinal: usize) -> Option<EntryId> {
        (ordinal < self.owner.entries.len()).then(|| EntryId::projected(self.owner.identity, ordinal))
    }
    pub fn entry(&self, id: &EntryId) -> ZipReadResult<&ZipEntry> {
        if !id.is_projected(self.owner.identity) {
            return Err(ReadFault::InvalidPlan.into());
        }
        self.owner.entries.get(id.ordinal).ok_or_else(|| ReadFault::InvalidPlan.into())
    }
    pub fn bootstrap_usage(&self) -> BootstrapUsage {
        self.owner.opening.usage()
    }
    pub fn dispatch_bytes(&self) -> u64 {
        self.owner.opening.usage().dispatch_bytes()
    }
    pub fn parser_usage(&self) -> zip::Usage {
        self.owner.parser_usage
    }
    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast)] // Device/inode widths differ across Unix ABIs.
    pub fn admit_output_fd(
        &mut self,
        fd: std::os::fd::BorrowedFd<'_>,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<()> {
        use std::os::fd::AsRawFd;
        if !context.ledger.with_state(|s| s.bound()) {
            return Err(ReadFault::InvalidPlan.into());
        }
        self.check_source(context)?;
        let source = self.owner.source.as_ref().map_err(|_| ReadFault::InvalidPlan)?.stamp;
        let stat = io::operation(
            &context.ledger,
            false,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            None,
            || {
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                // SAFETY: the borrowed descriptor is live and the output is exact stat storage.
                raw_io(unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })?;
                Ok(unsafe { stat.assume_init() })
            },
        )?;
        if source.dev == stat.st_dev as u64 && source.ino == stat.st_ino as u64 {
            return Err(ReadFault::CheckedFormat { reason: "output aliases ZIP source" }.into());
        }
        Ok(())
    }
    pub fn check_source(&mut self, context: &mut EncryptedReadContext) -> ZipReadResult<()> {
        self.owner.check_source(context)
    }
    pub fn read_at_with_context(
        &mut self,
        index: usize,
        password: Option<&str>,
        max_bytes: u64,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut sink: impl FnMut(&[u8]) -> ZipSinkResult<()>,
    ) -> ZipReadResult<()> {
        self.owner.read_checked(index, password, max_bytes, cancel, context, &mut sink)
    }
}
#[allow(clippy::result_large_err)]
impl ProjectedOwner {
    pub(crate) fn open_checked(path: &Path, cancel: &Cancellation) -> ZipReadResult<Self> {
        if !cfg!(unix) {
            return Err(ReadFault::UnsupportedIdentity.into());
        }
        let mut bootstrap = io::BootstrapIo::opening()?;
        let result = (|| -> ZipReadResult<_> {
            io::canceled(Some(cancel))?;
            let path = checked_path(path, &mut bootstrap, cancel)?;
            let mut file = checked_open(&path, &mut bootstrap, cancel)?;
            let stamp = match SourceStamp::capture_checked(&file, &path, |stage, call| bootstrap.stat(stage, call)) {
                Ok(stamp) => stamp,
                Err(error) => return Err(retire_open(file, error.into(), &mut bootstrap)),
            };
            let parsed = parse_projected(&mut file, stamp.len, &mut bootstrap, cancel);
            let completed_parser_usage = parsed.as_ref().ok().map(|(_, usage)| *usage);
            let final_source = SourceStamp::capture_checked(&file, &path, |stage, call| bootstrap.stat(stage, call));
            let result = match final_source {
                Ok(after) if after == stamp => parsed,
                Ok(_) => Err(match parsed {
                    Ok(_) => CheckedSourceFault::StampMismatch.into(),
                    Err(error) => error.merge_source(CheckedSourceFault::StampMismatch),
                }),
                Err(io::SourceCheckError::Source(fault)) => Err(match parsed {
                    Ok(_) => fault.into(),
                    Err(error) => error.merge_source(fault),
                }),
                Err(io::SourceCheckError::Admission(fault)) => Err(match parsed {
                    Ok(_) => fault.into(),
                    Err(error) => merge_source_admission(error, fault),
                }),
            };
            let (entries, parser_usage) = match result {
                Ok(result) => result,
                Err(error) => {
                    let error = match completed_parser_usage {
                        Some(usage) => error.with_parser_usage(usage),
                        None => error,
                    };
                    return Err(retire_open(file, error, &mut bootstrap));
                }
            };
            if let Err(fault) = io::canceled(Some(cancel)) {
                return Err(retire_open(
                    file,
                    ZipReadError::from(fault).with_parser_usage(parser_usage),
                    &mut bootstrap,
                ));
            }
            let identity = match identity() {
                Ok(id) => id,
                Err(fault) => {
                    return Err(retire_open(
                        file,
                        ZipReadError::from(fault).with_parser_usage(parser_usage),
                        &mut bootstrap,
                    ));
                }
            };
            Ok((file, entries, SourceBinding::from_checked(path, stamp), identity, parser_usage))
        })();
        match result {
            Ok((file, entries, source, identity, parser_usage)) => {
                let len = source.stamp.len;
                Ok(Self { file, entries, source: Ok(source), identity, len, opening: bootstrap, parser_usage })
            }
            Err(error) => Err(error.with_bootstrap(bootstrap.usage())),
        }
    }

    pub(crate) fn open_legacy(path: &Path, cancel: &Cancellation) -> crate::Result<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        #[cfg(test)]
        observe(5);
        let mut bootstrap =
            io::BootstrapIo::legacy_proof().map_err(|_| crate::Error::Corrupt("ZIP bootstrap overflow"))?;
        // Optional legacy identity setup cannot become a new old-API prerequisite.
        // Its partial provenance deliberately excludes legacy open/parser calls.
        let source = legacy_proof_path(path, &mut bootstrap).and_then(|path| {
            SourceStamp::capture_checked(&file, &path, |stage, call| bootstrap.stat(stage, call)).and_then(|stamp| {
                if stamp.len != len {
                    return Err(io::SourceCheckError::Source(CheckedSourceFault::StampMismatch));
                }
                Ok(SourceBinding::from_checked(path, stamp))
            })
        });
        let (entries, parser_usage) = zip::read_projected_legacy(&mut file, len, Some(cancel))?;
        let identity = identity().map_err(|_| crate::Error::Corrupt("ZIP identity counter exhausted"))?;
        Ok(Self { file, entries, source, identity, len, opening: bootstrap, parser_usage })
    }
    fn proof(&mut self) -> ZipReadResult<()> {
        if !cfg!(unix) {
            return Err(ReadFault::UnsupportedIdentity.into());
        }
        if let Err(error) = &self.source {
            let replacement = match error {
                io::SourceCheckError::Source(fault) => {
                    let (code, raw_os_error) = fault.invalidation();
                    io::SourceCheckError::Source(CheckedSourceFault::PreviouslyInvalidated { code, raw_os_error })
                }
                // No source observation occurred. Permanently unproved metadata
                // cannot be blessed later, but this is not SourceChanged.
                io::SourceCheckError::Admission(_) => io::SourceCheckError::Admission(ReadFault::InvalidPlan),
            };
            std::mem::replace(&mut self.source, Err(replacement))
                .map_err(|error| ZipReadError::from(error).with_bootstrap(self.opening.usage()))?;
        }
        Ok(())
    }
    pub(crate) fn read_checked(
        &mut self,
        index: usize,
        password: Option<&str>,
        max_bytes: u64,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut sink: impl FnMut(&[u8]) -> ZipSinkResult<()>,
    ) -> ZipReadResult<()> {
        context.verify_identity(self.identity)?;
        let e = self.entries.get(index).ok_or(ReadFault::InvalidPlan)?;
        if e.is_dir() || e.is_link() {
            return Err(ReadFault::CheckedFormat { reason: "selected ZIP entry is not a regular file" }.into());
        }
        self.proof()?;
        let e = &self.entries[index];
        checked_read(
            &mut self.file,
            self.source.as_mut().map_err(|_| ReadFault::InvalidPlan)?,
            self.identity,
            index,
            e.read_description(),
            password,
            max_bytes,
            cancel,
            context,
            &mut sink,
        )
    }
    pub(crate) fn reject(mut self, error: ZipReadError) -> ZipReadError {
        retire_open(self.file, error.with_parser_usage(self.parser_usage), &mut self.opening)
            .with_bootstrap(self.opening.usage())
    }
    pub(crate) fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }
    pub(crate) fn legacy_read(
        &mut self,
        index: usize,
        password: Option<&str>,
        max_bytes: u64,
        cancel: &Cancellation,
        mut sink: impl FnMut(&[u8]) -> crate::Result<()>,
    ) -> crate::Result<()> {
        let entry =
            self.entries.get(index).ok_or_else(|| crate::Error::Unsupported("entry index is out of range".into()))?;
        zip::check_selection(entry.is_dir(), entry.is_link(), entry.packed, entry.size, max_bytes)?;
        let mut buffer = vec![0; zip::BUF];
        zip::read_entry(
            &mut self.file,
            self.len,
            &entry.read_description(),
            password,
            &mut buffer,
            &mut sink,
            Some(cancel),
        )
    }
    pub(crate) fn check_source(&mut self, context: &mut EncryptedReadContext) -> ZipReadResult<()> {
        context.verify_identity(self.identity)?;
        self.proof()?;
        let source = self.source.as_mut().map_err(|_| ReadFault::InvalidPlan)?;
        context.source_group(source.stamp)?;
        source
            .verify_checked(&self.file, context)
            .map_err(ZipReadError::from)
            .map_err(|e| e.with_usage(context.usage(), context.run_usage()))
    }
}
fn merge_source_admission(error: ZipReadError, fault: ReadFault) -> ZipReadError {
    let mut report = ObjectCleanupReport::new(OwnedObject::Source);
    report.push(CleanupFault {
        object: OwnedObject::Source,
        operation: ReadIoOperation::Stat,
        offset: None,
        cause: CleanupCause::Admission(fault),
        close: CloseDisposition::NotApplicable,
    });
    error.merge_cleanup(report)
}
pub(super) fn directory_fault(error: zip::DirectoryError) -> ReadFault {
    match error {
        zip::DirectoryError::NotZip => ReadFault::CheckedFormat { reason: "not a ZIP archive" },
        error => ReadFault::Directory { error },
    }
}
#[allow(clippy::result_large_err)]
fn parse_projected(
    file: &mut File,
    len: u64,
    bootstrap: &mut io::BootstrapIo,
    cancel: &Cancellation,
) -> ZipReadResult<(Vec<ZipEntry>, zip::Usage)> {
    #[cfg(test)]
    observe(1);
    let limits = zip::Limits {
        fetched_bytes: (129u64 << 20)
            .checked_sub(bootstrap.usage().dispatch_bytes())
            .ok_or(ReadFault::CounterOverflow)?,
        ..Default::default()
    };
    let mut parser = zip::projected_parser(len, limits).map_err(directory_fault)?;
    let mut scratch = Vec::new();
    let mut position = None;
    let parsed = (|| -> ZipReadResult<()> {
        while let Some(range) = parser.next_read().map_err(directory_fault)? {
            io::canceled(Some(cancel))?;
            let wanted = usize::try_from(range.end.checked_sub(range.start).ok_or(ReadFault::CounterOverflow)?)
                .map_err(|_| ReadFault::CounterOverflow)?
                .min(io::WINDOW);
            if wanted == 0 || range.end > len {
                return Err(ReadFault::CheckedFormat { reason: "invalid directory range" }.into());
            }
            if scratch.len() < wanted {
                bootstrap.acquisition(io::WINDOW)?;
                scratch.try_reserve_exact(io::WINDOW).map_err(|_| ReadFault::Allocation { capacity: io::WINDOW })?;
                scratch.resize(io::WINDOW, 0);
            }
            if position != Some(range.start) {
                bootstrap.seek(file, range.start, cancel)?;
            }
            let mut have = 0;
            while have < wanted {
                let n = bootstrap.read(file, &mut scratch[have..wanted], cancel)?;
                if n == 0 {
                    return Err(ReadFault::CheckedFormat { reason: "truncated directory" }.into());
                }
                have += n;
            }
            position = Some(range.start + wanted as u64);
            parser.supply(range.start, &scratch[..wanted]).map_err(directory_fault)?;
        }
        io::canceled(Some(cancel))?;
        Ok(())
    })();
    parsed.map_err(|error| error.with_parser_usage(parser.usage()))?;
    let last_usage = parser.usage();
    let directory =
        parser.finish().map_err(|error| ZipReadError::from(directory_fault(error)).with_parser_usage(last_usage))?;
    let usage = directory.usage;
    let mut entries = directory.entries;
    zip::relocate_projected(&mut entries, directory.prefix_shift, len, Some(cancel))
        .map_err(|fault| ZipReadError::from(fault).with_parser_usage(usage))?;
    #[cfg(test)]
    observe(6);
    Ok((entries, usage))
}
#[cfg(unix)]
fn raw_io(value: libc::c_int) -> std::io::Result<libc::c_int> {
    if value < 0 { Err(std::io::Error::last_os_error()) } else { Ok(value) }
}
#[cfg(unix)]
fn terminated(path: &Path) -> Result<[u8; libc::PATH_MAX as usize], ReadFault> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut buffer = [0; libc::PATH_MAX as usize];
    if bytes.len() >= buffer.len() || bytes.contains(&0) {
        return Err(ReadFault::CheckedFormat { reason: "invalid source path" });
    }
    buffer[..bytes.len()].copy_from_slice(bytes);
    Ok(buffer)
}
#[cfg(unix)]
fn close_raw_once(fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: caller transferred ownership of this descriptor; close is called
    // once and never retried, even when the platform reports EINTR.
    raw_io(unsafe { libc::close(fd) })?;
    #[cfg(test)]
    if let Some(code) = CLOSE_FAULT.with(|s| s.take()) {
        return Err(std::io::Error::from_raw_os_error(code));
    }
    Ok(())
}
#[cfg(unix)]
fn checked_open(path: &Path, bootstrap: &mut io::BootstrapIo, cancel: &Cancellation) -> Result<File, ReadFault> {
    use std::os::fd::FromRawFd;
    io::canceled(Some(cancel))?;
    let path = terminated(path)?;
    let fd = bootstrap.opened(|| {
        raw_io(unsafe { libc::open(path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK) })
    })?;
    #[cfg(test)]
    observe(0);
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(not(unix))]
fn checked_open(_: &Path, _: &mut io::BootstrapIo, _: &Cancellation) -> Result<File, ReadFault> {
    Err(ReadFault::UnsupportedIdentity)
}
#[cfg(unix)]
#[allow(clippy::result_large_err)]
fn checked_path(path: &Path, bootstrap: &mut io::BootstrapIo, cancel: &Cancellation) -> ZipReadResult<PathBuf> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    io::canceled(Some(cancel))?;
    let input = path.as_os_str().as_bytes();
    if input.contains(&0) {
        return Err(ReadFault::CheckedFormat { reason: "NUL in source path" }.into());
    }
    let mut cwd = [0u8; libc::PATH_MAX as usize];
    let prefix: &[u8] = if path.is_absolute() {
        &[]
    } else {
        #[cfg(target_os = "linux")]
        bootstrap.path(|| {
            let n = unsafe { libc::syscall(libc::SYS_getcwd, cwd.as_mut_ptr(), cwd.len()) };
            if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
        })?;
        #[cfg(target_os = "macos")]
        {
            let fd = bootstrap.path(|| {
                raw_io(unsafe { libc::open(c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })
            })?;
            let result = bootstrap.path(|| raw_io(unsafe { libc::fcntl(fd, libc::F_GETPATH, cwd.as_mut_ptr()) }));
            // Close exactly once, including when path acquisition failed. This
            // phase ends before any source data descriptor may be acquired.
            let closed = bootstrap.retire_once(OwnedObject::SourcePathDirectory, || close_raw_once(fd));
            if let Err(fault) = closed {
                let mut report = ObjectCleanupReport::new(OwnedObject::SourcePathDirectory);
                report.push(fault);
                return Err(match result {
                    Ok(_) => ZipReadError::from(report),
                    Err(fault) => ZipReadError::from(fault).merge_cleanup(report),
                });
            }
            result?;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(ReadFault::UnsupportedIdentity.into());
        let end = cwd.iter().position(|b| *b == 0).ok_or(ReadFault::CheckedFormat { reason: "unterminated cwd" })?;
        if end == 0 || cwd[0] != b'/' {
            return Err(ReadFault::CheckedFormat { reason: "invalid cwd" }.into());
        }
        &cwd[..end]
    };
    let capacity = prefix
        .len()
        .checked_add(usize::from(!prefix.is_empty()))
        .and_then(|n| n.checked_add(input.len()))
        .ok_or(ReadFault::CounterOverflow)?;
    if capacity >= libc::PATH_MAX as usize {
        return Err(ReadFault::CheckedFormat { reason: "source path too long" }.into());
    }
    bootstrap.acquisition(capacity)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| ReadFault::Allocation { capacity })?;
    bytes.extend_from_slice(prefix);
    if !prefix.is_empty() {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(input);
    Ok(std::ffi::OsString::from_vec(bytes).into())
}
#[cfg(not(unix))]
#[allow(clippy::result_large_err)]
fn checked_path(_: &Path, _: &mut io::BootstrapIo, _: &Cancellation) -> ZipReadResult<PathBuf> {
    Err(ReadFault::UnsupportedIdentity.into())
}
#[allow(clippy::result_large_err)] // Eight inline close-fault slots must survive allocation refusal.
fn close_source(file: File, bootstrap: &mut io::BootstrapIo) -> Result<(), ObjectCleanupReport> {
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        if let Err(fault) = bootstrap.retire_once(OwnedObject::Source, || close_raw_once(fd)) {
            let mut report = ObjectCleanupReport::new(OwnedObject::Source);
            report.push(fault);
            return Err(report);
        }
    }
    #[cfg(not(unix))]
    {
        drop(file);
        let _ = bootstrap;
    }
    Ok(())
}
fn retire_open(file: File, error: ZipReadError, bootstrap: &mut io::BootstrapIo) -> ZipReadError {
    match close_source(file, bootstrap) {
        Ok(()) => error,
        Err(report) => error.merge_cleanup(report),
    }
}

#[cfg(unix)]
fn legacy_proof_path(path: &Path, bootstrap: &mut io::BootstrapIo) -> Result<PathBuf, io::SourceCheckError> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let input = path.as_os_str().as_bytes();
    let mut bytes = if path.is_absolute() {
        Vec::new()
    } else {
        #[cfg(test)]
        if let Some(code) = LEGACY_CWD_FAULT.with(|s| s.take()) {
            return Err(io::SourceCheckError::Admission(ReadFault::Io {
                stage: IoStage::SourcePath,
                operation: ReadIoOperation::Directory,
                offset: 0,
                error: std::io::Error::from_raw_os_error(code),
            }));
        }
        // The old constructor retains its standard-library cwd behavior. Only
        // new checked opens promise the finite, fallible raw cwd driver.
        let cwd = std::env::current_dir().map_err(|error| {
            io::SourceCheckError::Admission(ReadFault::Io {
                stage: IoStage::SourcePath,
                operation: ReadIoOperation::Directory,
                offset: 0,
                error,
            })
        })?;
        cwd.into_os_string().into_vec()
    };
    let separator = usize::from(!path.is_absolute());
    let extra =
        input.len().checked_add(separator).ok_or(io::SourceCheckError::Admission(ReadFault::CounterOverflow))?;
    let capacity = bytes.len().checked_add(extra).ok_or(io::SourceCheckError::Admission(ReadFault::CounterOverflow))?;
    bootstrap.acquisition(capacity).map_err(io::SourceCheckError::Admission)?;
    bytes.try_reserve_exact(extra).map_err(|_| io::SourceCheckError::Admission(ReadFault::Allocation { capacity }))?;
    if separator != 0 {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(input);
    Ok(std::ffi::OsString::from_vec(bytes).into())
}
#[cfg(not(unix))]
fn legacy_proof_path(_: &Path, _: &mut io::BootstrapIo) -> Result<PathBuf, io::SourceCheckError> {
    Err(io::SourceCheckError::Admission(ReadFault::UnsupportedIdentity))
}

fn output_mode(output: ZipReadOutput<'_>) -> (budget::PlannedOutput, u128, usize) {
    match output {
        ZipReadOutput::Discard => (budget::PlannedOutput::Discard, 0, 0),
        ZipReadOutput::Callback => (budget::PlannedOutput::Callback, 0, 0),
        ZipReadOutput::StagedFiles { destination } => {
            (budget::PlannedOutput::StagedFiles, 1, destination.as_os_str().len())
        }
        ZipReadOutput::VerifiedStdout => (budget::PlannedOutput::VerifiedStdout, 3, 0),
    }
}
fn add(a: u128, b: u128) -> Result<u128, ReadFault> {
    budget::checked_sum(a, b)
}
fn mul(a: u128, b: u128) -> Result<u128, ReadFault> {
    a.checked_mul(b).ok_or(ReadFault::CounterOverflow)
}
fn cipher_geometry(e: &ReadDescription<'_>) -> (Option<CipherKind>, u64, cipher::InputKind) {
    if !e.encrypted() {
        return (None, e.packed, cipher::InputKind::Clear);
    }
    if e.method == 99 || e.aes_info.is_some() {
        let (strength, version, _) = e.aes_info.unwrap_or((0, 0, 0));
        let framing = match strength {
            1 => 20,
            2 => 24,
            3 => 28,
            _ => u64::MAX,
        };
        (Some(CipherKind::Aes), e.packed.saturating_sub(framing), cipher::InputKind::Aes { strength, version })
    } else {
        (
            Some(CipherKind::ZipCrypto),
            e.packed.saturating_sub(12),
            cipher::InputKind::ZipCrypto { descriptor: e.flags & zip::FLAG_DESCRIPTOR != 0, time: 0 },
        )
    }
}
/// The iterator borrows the original catalogue exactly once. No names, secrets,
/// entry arrays or per-record state are retained by the resulting action.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub(super) fn factory<'a>(
    context: &mut EncryptedReadContext,
    derive_limits: bool,
    records: impl Iterator<Item = (ReadDescription<'a>, bool, bool)>,
    identity: u64,
    stamp: SourceStamp,
    source_path_bytes: usize,
    scope: ProjectedReadScope,
    caller_max: Option<u64>,
    output: ZipReadOutput<'_>,
    password: Option<&str>,
    overrides: &EncryptedReadOverrides,
    cancel: &Cancellation,
) -> ZipReadResult<()> {
    let destination = match output {
        ZipReadOutput::StagedFiles { destination } => Some(destination),
        _ => None,
    };
    let (output, passes, destination_bytes) = output_mode(output);
    let password_bytes = u64::try_from(password.map_or(0, str::len)).map_err(|_| ReadFault::CounterOverflow)?;
    let retries = if derive_limits {
        overrides.interrupted_retries.unwrap_or(16)
    } else {
        context.options.limits.interrupted_retries
    };
    let creates =
        if derive_limits { overrides.create_attempts.unwrap_or(16) } else { context.options.limits.create_attempts };
    let mut g = budget::PlanGeometry { output_passes: passes, ..Default::default() };
    let mut n = 0u64;
    let mut aes = 0u64;
    let (mut sp, mut su, mut sf) = (0u128, 0u128, 0u128);
    let (mut mp, mut mu, mut mf, mut live) = (0u64, 0u64, 0u64, 0u128);
    let mut needs_temp = false;
    let threshold = if derive_limits { 64 << 10 } else { context.options.limits.ciphertext_memory_bytes };
    for (e, dir, link) in records {
        io::canceled(Some(cancel))?;
        g.records = add(g.records, 1)?;
        g.path_bytes = add(g.path_bytes, e.name.len() as u128)?;
        if dir {
            g.directories = add(g.directories, 1)?;
            continue;
        }
        if link {
            continue;
        }
        g.regular = add(g.regular, 1)?;
        g.packed = add(g.packed, e.packed.into())?;
        g.decoded = add(g.decoded, e.size.into())?;
        let (kind, c, _) = cipher_geometry(&e);
        let f = if kind == Some(CipherKind::Aes) && c > threshold { c } else { 0 };
        let o = if passes > 0 { e.size } else { 0 };
        g.live_spool = g.live_spool.max(add(f.into(), o.into())?);
        g.ciphertext = add(g.ciphertext, f.into())?;
        if f > 0 {
            g.large_aes = add(g.large_aes, 1)?;
        }
        let pcap = caller_max.unwrap_or(u64::MAX).min(if derive_limits {
            overrides.member_packed_bytes.unwrap_or(u64::MAX)
        } else {
            context.options.limits.member_packed_bytes
        });
        let ucap = caller_max.unwrap_or(u64::MAX).min(if derive_limits {
            overrides.member_decoded_bytes.unwrap_or(u64::MAX)
        } else {
            context.options.limits.member_decoded_bytes
        });
        let eligible = if kind.is_some() {
            e.packed <= pcap && e.size <= ucap
        } else {
            caller_max.is_none_or(|cap| e.packed <= cap && e.size <= cap)
        };
        needs_temp |= eligible && (f > 0 || output == budget::PlannedOutput::VerifiedStdout);
        if kind.is_none() {
            continue;
        }
        g.output_encrypted = true;
        n = n.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        if kind == Some(CipherKind::Aes) {
            aes = aes.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        }
        sp = add(sp, e.packed.into())?;
        su = add(su, e.size.into())?;
        sf = add(sf, f.into())?;
        mp = mp.max(e.packed);
        mu = mu.max(e.size);
        mf = mf.max(f);
        live = live.max(add(f.into(), o.into())?);
    }
    let limits = EncryptedReadLimits {
        member_packed_bytes: mp
            .min(caller_max.unwrap_or(u64::MAX))
            .min(overrides.member_packed_bytes.unwrap_or(u64::MAX)),
        member_decoded_bytes: mu
            .min(caller_max.unwrap_or(u64::MAX))
            .min(overrides.member_decoded_bytes.unwrap_or(u64::MAX)),
        member_spool_bytes: mf,
        live_spool_bytes: live.min(overrides.live_spool_bytes.unwrap_or(u128::MAX)),
        packed_bytes: sp.min(overrides.packed_bytes.unwrap_or(u128::MAX)),
        decoded_bytes: add(su, n.into())?.min(overrides.decoded_bytes.unwrap_or(u128::MAX)),
        source_bytes: add(sp, mul(30, n.into())?)?,
        io_bytes: add(add(sp, mul(30, n.into())?)?, add(mul(3, sf)?, mul(passes, su)?)?)?
            .min(overrides.io_bytes.unwrap_or(u128::MAX)),
        work_bytes: add(
            add(mul(3, sp)?, mul(2, su)?)?,
            add(mul(n.into(), password_bytes.into())?, mul(64, n.into())?)?,
        )?
        .min(overrides.work_bytes.unwrap_or(u128::MAX)),
        members: n.min(overrides.members.unwrap_or(u64::MAX)),
        kdf_calls: aes.min(overrides.kdf_calls.unwrap_or(u64::MAX)),
        password_bytes: password_bytes.min(overrides.password_bytes.unwrap_or(u64::MAX)),
        codec_steps: mul(4, add(add(sp, su)?, add(mul(64, n.into())?, 1)?)?)?
            .min(overrides.codec_steps.unwrap_or(u128::MAX)),
        io_attempts: u128::MAX,
        interrupted_retries: retries,
        create_attempts: creates,
        ciphertext_memory_bytes: 64 << 10,
        reader_capacity: 256 << 10,
        allocation_attempts: 32,
        live_fds: 5,
    };
    if derive_limits {
        context.options.limits = limits;
        context.ledger.with_state(|s| s.encrypted.limits = context.options.limits.clone());
    }
    let resolved = (|| -> ZipReadResult<()> {
        if needs_temp {
            context.bootstrap.acquisition(spool::ResolvedTempDirectory::CAPACITY)?;
            let ledger = &context.ledger;
            let bootstrap = &mut context.bootstrap;
            context.temp = Some(spool::ResolvedTempDirectory::resolve_plan(
                ledger,
                overrides.temp_dir.as_deref().or(context.options.temp_dir.as_deref()),
                cancel,
                retries,
                |charge| bootstrap.resolve_charge(charge),
            )?);
        }
        let r1 = add(g.records, 1)?;
        let path_base = add(add(source_path_bytes as u128, destination_bytes as u128)?, 64)?;
        let temp_bytes = context.temp.as_ref().map_or(0, spool::ResolvedTempDirectory::path_bytes) as u128;
        g.path_bytes = add(g.path_bytes, mul(r1, add(path_base, temp_bytes)?)?)?;
        let plan = budget::ActionPlan::derive(g, creates, retries)?.with_binding(budget::PlanBinding {
            source: stamp,
            scope,
            output,
            configuration_id: identity,
        })?;
        let attempts = plan.attempt_bound();
        context.options.limits.io_attempts = attempts.min(if derive_limits {
            overrides.io_attempts.unwrap_or(u128::MAX)
        } else {
            context.options.limits.io_attempts
        });
        context.ledger.with_state(|s| {
            s.encrypted.limits.io_attempts = context.options.limits.io_attempts;
            s.bind(plan)
        })?;
        let owned_destination = if let Some(destination) = destination {
            context.bootstrap.configuration_acquisition(destination_bytes)?;
            #[cfg(unix)]
            let path = {
                use std::os::unix::ffi::{OsStrExt, OsStringExt};
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(destination_bytes).is_err() {
                    return Err(ReadFault::Allocation { capacity: destination_bytes }.into());
                }
                bytes.extend_from_slice(destination.as_os_str().as_bytes());
                PathBuf::from(std::ffi::OsString::from_vec(bytes))
            };
            #[cfg(not(unix))]
            let path = return Err(ReadFault::UnsupportedIdentity.into());
            Some(path)
        } else {
            None
        };
        context.action = Some(Action {
            identity,
            scope,
            output,
            caller_max,
            password_bytes,
            consumed: false,
            destination: owned_destination,
            completed: false,
        });
        Ok(())
    })();
    resolved.map_err(|error| error.with_bootstrap(context.bootstrap.usage()))
}
#[allow(clippy::result_large_err)]
impl EncryptedReadContext {
    pub fn bootstrap_usage(&self) -> BootstrapUsage {
        self.bootstrap.usage()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn for_projected(
        session: &mut ProjectedReadSession,
        scope: ProjectedReadScope,
        caller_max_bytes: Option<u64>,
        output: ZipReadOutput<'_>,
        password: Option<&str>,
        overrides: &EncryptedReadOverrides,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        Self::for_owner(&mut session.owner, scope, caller_max_bytes, output, password, overrides, cancel)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_owner(
        owner: &mut ProjectedOwner,
        scope: ProjectedReadScope,
        caller_max_bytes: Option<u64>,
        output: ZipReadOutput<'_>,
        password: Option<&str>,
        overrides: &EncryptedReadOverrides,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let range = match scope {
            ProjectedReadScope::AllRegular => 0..owner.entries.len(),
            ProjectedReadScope::Entry(i) if i < owner.entries.len() => i..i + 1,
            _ => return Err(ReadFault::InvalidPlan.into()),
        };
        owner.proof()?;
        let source = owner.source.as_mut().map_err(|_| ReadFault::InvalidPlan)?;
        let mut context = planning_context(overrides)?;
        io::canceled(Some(cancel))
            .map_err(|fault| ZipReadError::from(fault).with_bootstrap(context.bootstrap.usage()))?;
        source
            .verify_with(&owner.file, |stage, call| context.bootstrap.stat(stage, call))
            .map_err(|fault| ZipReadError::from(fault).with_bootstrap(context.bootstrap.usage()))?;
        let entries = &owner.entries;
        let result = factory(
            &mut context,
            true,
            range.map(|i| {
                let e = &entries[i];
                (e.read_description(), e.is_dir(), e.is_link())
            }),
            owner.identity,
            source.stamp,
            source.path.as_os_str().len(),
            scope,
            caller_max_bytes,
            output,
            password,
            overrides,
            cancel,
        );
        let final_check = source.verify_with(&owner.file, |stage, call| context.bootstrap.stat(stage, call));
        finish_factory(result, final_check, context, cancel)
    }
}

struct HeldSource<'a> {
    file: &'a mut File,
    binding: &'a mut SourceBinding,
    local_at: u64,
    prepared: bool,
}
impl Read for HeldSource<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(bytes)
    }
}
impl cipher::CiphertextSource for HeldSource<'_> {
    fn verify_source(&mut self, ledger: shared::LedgerView<'_>) -> Result<(), io::SourceCheckError> {
        ledger
            .with_state(|s| {
                s.verify_source(self.binding.stamp)?;
                s.charge_category(RunCategory::SourceCheckGroups, 1)
            })
            .map_err(io::SourceCheckError::Admission)?;
        let retries = ledger.with_state(|s| s.encrypted.limits.interrupted_retries);
        self.binding.verify_with(self.file, |stage, call| {
            let mut interrupted = 0u64;
            loop {
                ledger.with_state(|s| s.attempt(false)).map_err(io::SourceCheckError::Admission)?;
                match call() {
                    Ok(value) => return Ok(value),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                        interrupted += 1;
                        budget::admit(ReadResource::InterruptedRetries, retries.into(), interrupted.into())
                            .map_err(io::SourceCheckError::Admission)?;
                    }
                    Err(error) => {
                        return Err(io::SourceCheckError::Source(CheckedSourceFault::Unavailable { stage, error }));
                    }
                }
            }
        })
    }
    fn prepare_member(
        &mut self,
        plan: &budget::MemberPlan,
        ledger: shared::LedgerView<'_>,
        cancel: &Cancellation,
    ) -> ZipReadResult<cipher::PrepareReceipt> {
        if self.prepared {
            return Err(ReadFault::InvalidPlan.into());
        }
        self.prepared = true;
        let encrypted = plan.cipher.is_some();
        let len = self.binding.stamp.len;
        if self.local_at.checked_add(30).is_none_or(|end| end > len) {
            return Err(ReadFault::CheckedFormat { reason: "truncated local header" }.into());
        }
        source_seek(ledger, encrypted, self.file, self.local_at, cancel)?;
        #[cfg(test)]
        observe(4);
        let mut head = [0u8; 30];
        let mut have = 0;
        while have < head.len() {
            let n = io::read(
                &ledger,
                encrypted,
                self.file,
                IoStage::Source,
                self.local_at + have as u64,
                &mut head[have..],
                cancel,
            )?;
            if n == 0 {
                return Err(ReadFault::CheckedFormat { reason: "truncated local header" }.into());
            }
            have += n;
        }
        let header =
            zip::LocalHeader::parse(&head).map_err(|_| ReadFault::CheckedFormat { reason: "invalid local header" })?;
        let layout = zip::local_layout(header, self.local_at, len)
            .map_err(|_| ReadFault::CheckedFormat { reason: "invalid local layout" })?;
        let payload = layout
            .payload_range(plan.packed, len)
            .map_err(|_| ReadFault::CheckedFormat { reason: "invalid payload extent" })?;
        source_seek(ledger, encrypted, self.file, payload.start, cancel)?;
        Ok(cipher::PrepareReceipt { time: Some(head[11]) })
    }
}
fn source_seek(
    ledger: shared::LedgerView<'_>,
    encrypted: bool,
    file: &mut File,
    at: u64,
    cancel: &Cancellation,
) -> Result<(), ReadFault> {
    let actual = io::operation(
        &ledger,
        encrypted,
        RunCategory::SourceSeeks,
        IoStage::Source,
        ReadIoOperation::Seek,
        Some(cancel),
        || file.seek(std::io::SeekFrom::Start(at)),
    )?;
    if actual != at {
        return Err(ReadFault::CheckedFormat { reason: "incorrect source seek" });
    }
    Ok(())
}
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
fn checked_read_inner(
    file: &mut File,
    binding: &mut SourceBinding,
    identity: u64,
    index: usize,
    e: ReadDescription<'_>,
    password: Option<&str>,
    max_bytes: u64,
    cancel: &Cancellation,
    context: &mut EncryptedReadContext,
    sink: &mut impl FnMut(&[u8]) -> ZipSinkResult<()>,
) -> ZipReadResult<()> {
    if context.action.is_none() {
        let binding_result = (|| -> ZipReadResult<()> {
            io::canceled(Some(cancel))?;
            binding.verify_with(file, |stage, call| context.bootstrap.stat(stage, call))?;
            let result = factory(
                context,
                false,
                std::iter::once((
                    ReadDescription {
                        name: e.name,
                        flags: e.flags,
                        method: e.method,
                        crc32: e.crc32,
                        packed: e.packed,
                        size: e.size,
                        local_at: e.local_at,
                        aes_info: e.aes_info,
                    },
                    false,
                    false,
                )),
                identity,
                binding.stamp,
                binding.path.as_os_str().len(),
                ProjectedReadScope::Entry(index),
                Some(max_bytes),
                ZipReadOutput::Callback,
                password,
                &EncryptedReadOverrides::default(),
                cancel,
            );
            #[cfg(test)]
            observe(8);
            let checked = binding.verify_with(file, |stage, call| context.bootstrap.stat(stage, call));
            match checked {
                Ok(()) => result?,
                Err(io::SourceCheckError::Source(fault)) => {
                    return Err(match result {
                        Ok(()) => fault.into(),
                        Err(error) => error.merge_source(fault),
                    });
                }
                Err(io::SourceCheckError::Admission(fault)) => {
                    return Err(match result {
                        Ok(()) => fault.into(),
                        Err(error) => merge_source_admission(error, fault),
                    });
                }
            }
            Ok(())
        })();
        binding_result.map_err(|error| match error.bootstrap_usage().map(|usage| usage.phase()) {
            None | Some(BootstrapPhase::ActionPlan) => error.with_bootstrap(context.bootstrap.usage()),
            // A genuine earlier opening/legacy origin must never be relabelled.
            Some(_) => error,
        })?;
    } else {
        io::canceled(Some(cancel))?;
    }
    context.verify_identity(identity)?;
    let action = context.action.as_mut().ok_or(ReadFault::InvalidPlan)?;
    if action.identity != identity
        || action.scope != ProjectedReadScope::Entry(index)
        || action.consumed
        || action.completed
        || action.password_bytes != password.map_or(0, str::len) as u64
        || action.caller_max.is_some_and(|cap| cap != max_bytes)
    {
        return Err(ReadFault::InvalidPlan.into());
    }
    action.consumed = true;
    context.ledger.with_state(|s| s.charge_category(RunCategory::Records, 1))?;
    let rejection = if e.packed > max_bytes {
        Some(ReadFault::Limit {
            resource: ReadResource::MemberPackedBytes,
            limit: max_bytes.into(),
            attempted: e.packed.into(),
        })
    } else if e.size > max_bytes {
        Some(ReadFault::Limit {
            resource: ReadResource::MemberDecodedBytes,
            limit: max_bytes.into(),
            attempted: e.size.into(),
        })
    } else if !zip::supported(e.effective_method()) {
        Some(ReadFault::UnsupportedMethod { method: e.effective_method() })
    } else {
        None
    };
    let (cipher, ciphertext, kind) = cipher_geometry(&e);
    let crc = if matches!(kind, cipher::InputKind::Aes { version: 2, .. }) { None } else { Some(e.crc32) };
    let plan = budget::MemberPlan {
        source: binding.stamp,
        scope: action.scope,
        ordinal: index as u64,
        packed: e.packed,
        decoded: e.size,
        ciphertext,
        cipher,
        crc,
        output: action.output,
    };
    let mut source = HeldSource { file, binding, local_at: e.local_at, prepared: false };
    if let Some(fault) = rejection {
        let fault = if cipher.is_some() {
            context.ledger.with_state(|s| s.encrypted.reject_member(e.packed, fault))
        } else {
            fault
        };
        return cipher::checked(Err(fault.into()), &mut source, context.ledger.view());
    }
    let admitted = cipher::Admission::new(&context.ledger, &mut source, plan, password, kind)?.prepare(cancel)?;
    let (admitted, mut workspace) = admitted.workspace()?;
    let input = match kind {
        cipher::InputKind::Clear => admitted.clear()?,
        cipher::InputKind::ZipCrypto { .. } => {
            codecs::PlainInput::ZipCrypto(cipher::ZipCryptoInput::open_admitted(admitted, cancel)?)
        }
        cipher::InputKind::Aes { .. } => {
            let pending =
                cipher::PendingAes::copy_admitted(admitted, context.temp.as_ref(), &mut workspace.input, cancel)?;
            codecs::PlainInput::Aes(pending.authenticate(&mut workspace.input, cancel)?)
        }
    };
    let receipt = codecs::decode(input, &mut workspace, e.effective_method(), e.flags, &context.options, cancel, sink)?;
    if receipt.consumed != ciphertext || receipt.decoded != e.size {
        return Err(ReadFault::InvalidPlan.into());
    }
    context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.completed = true;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn planning_context(overrides: &EncryptedReadOverrides) -> ZipReadResult<EncryptedReadContext> {
    let limits =
        EncryptedReadLimits { interrupted_retries: overrides.interrupted_retries.unwrap_or(16), ..Default::default() };
    EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits))
}
#[allow(clippy::result_large_err)]
impl EncryptedReadContext {
    #[allow(clippy::too_many_arguments)]
    pub fn for_session(
        session: &mut zip::ReadSession,
        id: &EntryId,
        caller_max_bytes: Option<u64>,
        output: ZipReadOutput<'_>,
        password: Option<&str>,
        overrides: &EncryptedReadOverrides,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let index = session.metadata.ordinal(id).map_err(|_| ReadFault::InvalidPlan)?;
        let mut context = planning_context(overrides)?;
        io::canceled(Some(cancel))
            .map_err(|fault| ZipReadError::from(fault).with_bootstrap(context.bootstrap.usage()))?;
        session
            .source
            .verify_with(&session.file, |stage, call| context.bootstrap.stat(stage, call))
            .map_err(|f| ZipReadError::from(f).with_bootstrap(context.bootstrap.usage()))?;
        let e = session.metadata.view(index);
        let result = factory(
            &mut context,
            true,
            std::iter::once((e.read_description(), e.is_dir(), e.is_link())),
            session.checked_identity,
            session.source.stamp,
            session.source.path.as_os_str().len(),
            ProjectedReadScope::Entry(index),
            caller_max_bytes,
            output,
            password,
            overrides,
            cancel,
        );
        let final_check = session.source.verify_with(&session.file, |stage, call| context.bootstrap.stat(stage, call));
        finish_factory(result, final_check, context, cancel)
    }
}

#[allow(clippy::result_large_err)]
fn finish_factory(
    result: ZipReadResult<()>,
    final_check: Result<(), io::SourceCheckError>,
    context: EncryptedReadContext,
    cancel: &Cancellation,
) -> ZipReadResult<EncryptedReadContext> {
    let usage = context.bootstrap.usage();
    let result = result.and_then(|()| io::canceled(Some(cancel)).map_err(ZipReadError::from));
    let result = match final_check {
        Ok(()) => result,
        Err(io::SourceCheckError::Source(fault)) => Err(match result {
            Ok(()) => fault.into(),
            Err(error) => error.merge_source(fault),
        }),
        Err(io::SourceCheckError::Admission(fault)) => Err(match result {
            Ok(()) => fault.into(),
            Err(error) => merge_source_admission(error, fault),
        }),
    };
    result.map(|()| context).map_err(|error| error.with_bootstrap(usage))
}

/// A raw bounded format probe shares both its handle and fetch budget with ZIP.
pub(crate) struct CheckedOpen {
    pub(crate) file: File,
    pub(crate) path: PathBuf,
    pub(crate) len: u64,
    source: Result<SourceStamp, io::SourceCheckError>,
    bootstrap: io::BootstrapIo,
}
#[allow(clippy::result_large_err)]
impl CheckedOpen {
    pub(crate) fn open(path: &Path, cancel: &Cancellation) -> ZipReadResult<Self> {
        let mut bootstrap = io::BootstrapIo::opening()?;
        let result = (|| -> ZipReadResult<Self> {
            let path = checked_path(path, &mut bootstrap, cancel)?;
            let file = checked_open(&path, &mut bootstrap, cancel)?;
            let mut len = None;
            let source = SourceStamp::capture_checked(&file, &path, |stage, call| {
                let result = bootstrap.stat(stage, call);
                if let Ok(stamp) = &result
                    && stage == IoStage::SourceHandle
                {
                    len = Some(stamp.len);
                }
                result
            });
            let len = match len {
                Some(len) => len,
                None => {
                    let error = match source {
                        Err(fault) => ZipReadError::from(fault),
                        Ok(_) => ReadFault::InvalidPlan.into(),
                    };
                    return Err(retire_open(file, error, &mut bootstrap));
                }
            };
            Ok(Self { file, path, len, source, bootstrap: io::BootstrapIo::opening()? })
        })();
        match result {
            Ok(mut opened) => {
                opened.bootstrap = bootstrap;
                Ok(opened)
            }
            Err(error) => Err(error.with_bootstrap(bootstrap.usage())),
        }
    }
    pub(crate) fn probe(mut self, count: usize, cancel: &Cancellation) -> ZipReadResult<(Self, Vec<u8>)> {
        let result = (|| -> ZipReadResult<Vec<u8>> {
            io::canceled(Some(cancel))?;
            self.bootstrap.acquisition(count)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(count).map_err(|_| ReadFault::Allocation { capacity: count })?;
            bytes.resize(count, 0);
            self.bootstrap.seek(&mut self.file, 0, cancel)?;
            let mut have = 0;
            while have < count {
                let n = self.bootstrap.read(&mut self.file, &mut bytes[have..], cancel)?;
                if n == 0 {
                    break;
                }
                have += n;
                self.bootstrap.dispatch(n as u64)?;
            }
            bytes.truncate(have);
            io::canceled(Some(cancel))?;
            Ok(bytes)
        })();
        match result {
            Ok(bytes) => Ok((self, bytes)),
            Err(error) => {
                let error = match self.source {
                    Ok(_) => error,
                    Err(io::SourceCheckError::Source(fault)) => error.merge_source(fault),
                    Err(io::SourceCheckError::Admission(fault)) => merge_source_admission(error, fault),
                };
                Err(retire_open(self.file, error, &mut self.bootstrap).with_bootstrap(self.bootstrap.usage()))
            }
        }
    }
    pub(crate) fn retire(mut self) -> ZipReadResult<()> {
        close_source(self.file, &mut self.bootstrap)
            .map_err(|report| ZipReadError::from(report).with_bootstrap(self.bootstrap.usage()))
    }

    pub(crate) fn recognize_rar(self, head: &[u8]) -> Result<(crate::rar5::reader::HeldSignature, PathBuf), Self> {
        let Self { file, path, len, source, bootstrap } = self;
        match crate::rar5::reader::HeldSignature::recognize(file, len, head) {
            Ok(signature) => Ok((signature, path)),
            Err(file) => Err(Self { file, path, len, source, bootstrap }),
        }
    }
    pub(crate) fn into_zip(mut self, cancel: &Cancellation) -> ZipReadResult<ProjectedOwner> {
        let stamp = match self.source {
            Ok(source) => source,
            Err(error) => {
                return Err(
                    retire_open(self.file, error.into(), &mut self.bootstrap).with_bootstrap(self.bootstrap.usage())
                );
            }
        };
        let source = SourceBinding::from_checked(self.path, stamp);
        let parsed = parse_projected_with_dispatch(&mut self.file, source.stamp.len, &mut self.bootstrap, cancel);
        let completed_parser_usage = parsed.as_ref().ok().map(|(_, usage)| *usage);
        let checked =
            SourceStamp::capture_checked(&self.file, &source.path, |stage, call| self.bootstrap.stat(stage, call));
        let result = match checked {
            Ok(stamp) if stamp == source.stamp => parsed,
            Ok(_) => Err(match parsed {
                Ok(_) => CheckedSourceFault::StampMismatch.into(),
                Err(e) => e.merge_source(CheckedSourceFault::StampMismatch),
            }),
            Err(io::SourceCheckError::Source(fault)) => Err(match parsed {
                Ok(_) => fault.into(),
                Err(e) => e.merge_source(fault),
            }),
            Err(io::SourceCheckError::Admission(fault)) => Err(match parsed {
                Ok(_) => fault.into(),
                Err(e) => merge_source_admission(e, fault),
            }),
        };
        let (entries, parser_usage) = match result {
            Ok(value) => value,
            Err(error) => {
                let error = match completed_parser_usage {
                    Some(usage) => error.with_parser_usage(usage),
                    None => error,
                };
                return Err(retire_open(self.file, error, &mut self.bootstrap).with_bootstrap(self.bootstrap.usage()));
            }
        };
        if let Err(fault) = io::canceled(Some(cancel)) {
            return Err(retire_open(
                self.file,
                ZipReadError::from(fault).with_parser_usage(parser_usage),
                &mut self.bootstrap,
            )
            .with_bootstrap(self.bootstrap.usage()));
        }
        let identity = match identity() {
            Ok(value) => value,
            Err(fault) => {
                return Err(retire_open(
                    self.file,
                    ZipReadError::from(fault).with_parser_usage(parser_usage),
                    &mut self.bootstrap,
                )
                .with_bootstrap(self.bootstrap.usage()));
            }
        };
        Ok(ProjectedOwner {
            file: self.file,
            entries,
            source: Ok(source),
            identity,
            len: self.len,
            opening: self.bootstrap,
            parser_usage,
        })
    }
}
#[allow(clippy::result_large_err)]
fn parse_projected_with_dispatch(
    file: &mut File,
    len: u64,
    bootstrap: &mut io::BootstrapIo,
    cancel: &Cancellation,
) -> ZipReadResult<(Vec<ZipEntry>, zip::Usage)> {
    parse_projected(file, len, bootstrap, cancel)
}

#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub(in crate::zip) fn checked_read(
    file: &mut File,
    binding: &mut SourceBinding,
    identity: u64,
    index: usize,
    e: ReadDescription<'_>,
    password: Option<&str>,
    max_bytes: u64,
    cancel: &Cancellation,
    context: &mut EncryptedReadContext,
    sink: &mut impl FnMut(&[u8]) -> ZipSinkResult<()>,
) -> ZipReadResult<()> {
    checked_read_inner(file, binding, identity, index, e, password, max_bytes, cancel, context, sink)
        .map_err(|error| error.with_usage(context.usage(), context.run_usage()))
}

/// Test-only actual retained-source pump control for the derived AllRegular
/// envelope. Whole-run ordering/events/publication remain Task5 consumers.
#[cfg(test)]
#[allow(clippy::result_large_err)]
pub(super) fn test_original_all_member(
    session: &mut ProjectedReadSession,
    index: usize,
    context: &mut EncryptedReadContext,
    sink: &mut impl FnMut(&[u8]) -> ZipSinkResult<()>,
) -> ZipReadResult<()> {
    let owner = &mut session.owner;
    let e = owner.entries[index].read_description();
    let binding = owner.source.as_mut().map_err(|_| ReadFault::InvalidPlan)?;
    let cancel = Cancellation::default();
    let (cipher, ciphertext, kind) = cipher_geometry(&e);
    let crc = if matches!(kind, cipher::InputKind::Aes { version: 2, .. }) { None } else { Some(e.crc32) };
    let plan = budget::MemberPlan {
        source: binding.stamp,
        scope: ProjectedReadScope::AllRegular,
        ordinal: index as u64,
        packed: e.packed,
        decoded: e.size,
        ciphertext,
        cipher,
        crc,
        output: budget::PlannedOutput::Callback,
    };
    context.ledger.with_state(|s| s.charge_category(RunCategory::Records, 1))?;
    let mut source = HeldSource { file: &mut owner.file, binding, local_at: e.local_at, prepared: false };
    let admission = cipher::Admission::new(&context.ledger, &mut source, plan, Some("pw"), kind)?.prepare(&cancel)?;
    let (admission, mut workspace) = admission.workspace()?;
    let pending = cipher::PendingAes::copy_admitted(admission, context.temp.as_ref(), &mut workspace.input, &cancel)?;
    let input = codecs::PlainInput::Aes(pending.authenticate(&mut workspace.input, &cancel)?);
    codecs::decode(input, &mut workspace, e.effective_method(), e.flags, &context.options, &cancel, sink).map(|_| ())
}
