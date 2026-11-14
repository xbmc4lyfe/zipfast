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

//! Controlled publication receives only borrowed original entry provenance.
use super::*;
use crate::zip::{ReadDescription, session::SourceBinding};
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) mod directory;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod file;
#[cfg(unix)]
pub(super) mod metadata;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) mod named;
#[cfg(unix)]
pub(super) mod parent;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) mod target;

/// A borrowed original catalogue record, consumed synchronously by preparation.
/// It cannot outlive or be manufactured independently of its original source.
/// ```compile_fail
/// use zipfast::{extract::Cancellation, zip::ProjectedReadSession};
/// let mut session = ProjectedReadSession::open(std::path::Path::new("a.zip"), &Cancellation::default()).unwrap();
/// let receipt = session.stage_entry(0).unwrap();
/// drop(session);
/// drop(receipt);
/// ```
pub struct ZipStageEntry<'a> {
    pub(super) file: &'a File,
    pub(super) source: &'a mut SourceBinding,
    pub(super) owner: u64,
    pub(super) ordinal: usize,
    pub(super) entry: ReadDescription<'a>,
    pub(super) windows_names: bool,
    pub(super) mode: Option<u32>,
    pub(super) mtime: Option<(i64, u32)>,
    pub(super) relative: Option<&'a Path>,
}
impl<'a> ZipStageEntry<'a> {
    #[allow(clippy::too_many_arguments)] // Exact borrowed original parts, no new owner/catalogue.
    pub(in crate::zip) fn original(
        file: &'a File,
        source: &'a mut SourceBinding,
        owner: u64,
        ordinal: usize,
        entry: ReadDescription<'a>,
        windows_names: bool,
        mode: Option<u32>,
        mtime: Option<(i64, u32)>,
        relative: Option<&'a Path>,
    ) -> Self {
        Self { file, source, owner, ordinal, entry, windows_names, mode, mtime, relative }
    }
}

use super::shared::{LedgerAccess, LedgerIdentity};
/// Private proof of fresh final source observation, distinct from codec completion.
pub(super) struct FinalSourceProof {
    owner: u64,
    ledger: LedgerIdentity,
}
impl FinalSourceProof {
    pub(super) fn original(owner: u64, context: &EncryptedReadContext) -> Result<Self, ReadFault> {
        context.verify_identity(owner)?;
        if context.action.is_none() {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(Self { owner, ledger: context.ledger.identity() })
    }
    #[allow(clippy::result_large_err)] // Fixed inline evidence must survive callback/allocator failure.
    pub(super) fn observe(
        &self,
        context: &mut EncryptedReadContext,
        check: &mut impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadResult<()> {
        if self.ledger != context.ledger.identity() {
            return Err(ReadFault::InvalidPlan.into());
        }
        context.verify_identity(self.owner)?;
        let before = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.source_observation;
        check(context)?;
        if self.ledger != context.ledger.identity() {
            return Err(ReadFault::InvalidPlan.into());
        }
        context.verify_identity(self.owner)?;
        let after = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.source_observation;
        if after <= before {
            return Err(ReadFault::InvalidPlan.into());
        }
        Ok(())
    }
}

#[cfg(unix)]
use std::os::fd::{AsRawFd, IntoRawFd};

/// One owned verified-output stage. File-backed stdout includes empty members.
/// Publication/copy requires exact member completion and fresh original-source checks.
///
/// Storage currently requires ownership-enforced local APFS on macOS, or
/// ext/XFS/Btrfs/tmpfs on Linux. Named Linux output also requires a trusted
/// kernel procfs descriptor view. Darwin atomic private birth has a checked
/// native limit on the combined parent/leaf spelling. Unsupported storage or
/// native capabilities fail without selecting another storage route.
/// Namespace and source checks are optimistic observations, not filesystem locks.
pub struct ZipReadStage {
    pub(super) file: Option<File>,
    reservation: OutputReservation,
    source: FinalSourceProof,
    uid: u32,
    descriptor: (usize, u64, u64, u32),
    terminal: bool,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    named: Option<file::PreparedNamed>,
}
impl ZipStageEntry<'_> {
    fn validate_limits(&self, context: &EncryptedReadContext) -> Result<bool, ReadFault> {
        let encrypted = self.entry.encrypted();
        let caller = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.caller_max.unwrap_or(u64::MAX);
        let packed = caller.min(if encrypted { context.options.limits.member_packed_bytes } else { u64::MAX });
        let decoded = caller.min(if encrypted { context.options.limits.member_decoded_bytes } else { u64::MAX });
        if self.entry.packed > packed {
            return Err(ReadFault::Limit {
                resource: ReadResource::MemberPackedBytes,
                limit: packed.into(),
                attempted: self.entry.packed.into(),
            });
        }
        if self.entry.size > decoded {
            return Err(ReadFault::Limit {
                resource: ReadResource::MemberDecodedBytes,
                limit: decoded.into(),
                attempted: self.entry.size.into(),
            });
        }
        Ok(encrypted)
    }
    #[allow(clippy::result_large_err)]
    fn prepare_stdout(
        self,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<(FinalSourceProof, bool, u64)> {
        context.verify_identity(self.owner)?;
        let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
        if action.output != budget::PlannedOutput::VerifiedStdout
            || !(action.scope == ProjectedReadScope::Entry(self.ordinal)
                || action.scope == ProjectedReadScope::AllRegular
                    && action.active_ordinal == Some(self.ordinal)
                    && action.run_bound
                    && action.active_record_charged)
            || action.consumed
            || action.completed
            || action.controlled_output
            || action.raw_output
            || action.output_descriptor.is_none()
        {
            return Err(ReadFault::InvalidPlan.into());
        }
        let encrypted = self.validate_limits(context)?;
        if context.ledger.with_state(|s| s.output_encrypted())? != encrypted {
            return Err(ReadFault::InvalidPlan.into());
        }
        io::canceled(Some(cancel))?;
        context.source_group(self.source.stamp)?;
        self.source.verify_checked(self.file, context)?;
        context.successful_source_observation(self.owner, self.source.stamp)?;
        let proof = FinalSourceProof::original(self.owner, context)?;
        context.ledger.with_state(|s| s.register_controlled_source())?;
        context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.controlled_output = true;
        Ok((proof, encrypted, self.entry.size))
    }
}
#[allow(clippy::result_large_err)] // Fixed inline source/operation/cleanup evidence.
impl ZipReadStage {
    /// Acquires a private anonymous file after consuming original entry provenance.
    /// The actual output descriptor must first be admitted by the same source owner.
    #[allow(clippy::unnecessary_cast)] // Native identity widths vary by Unix ABI.
    pub fn prepare_stdout(
        entry: ZipStageEntry<'_>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<Self> {
        let result: ZipReadResult<Self> = (|| {
            #[cfg(not(unix))]
            {
                let _ = (entry, cancel);
                Err(ReadFault::UnsupportedIdentity.into())
            }
            #[cfg(unix)]
            {
                let (source, encrypted, bytes) = entry.prepare_stdout(cancel, context)?;
                let descriptor = context
                    .action
                    .as_ref()
                    .ok_or(ReadFault::InvalidPlan)?
                    .output_descriptor
                    .ok_or(ReadFault::InvalidPlan)?;
                let token = context.ledger.mint_reservation()?;
                let (file, identity, uid) = spool::PrivateCiphertextFile::create_output(
                    token.view(),
                    context.temp.as_ref().ok_or(ReadFault::InvalidPlan)?,
                    bytes,
                    cancel,
                    encrypted,
                )?
                .into_output();
                let handle = file_handle(&file);
                Ok(Self {
                    file: Some(file),
                    reservation: OutputReservation {
                        ledger: token,
                        encrypted,
                        bytes,
                        written: 0,
                        fds: 1,
                        identity: FileIdentity { dev: identity.dev as u64, ino: identity.ino as u64 },
                        handle,
                        retired: false,
                    },
                    source,
                    uid,
                    descriptor,
                    terminal: false,
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    named: None,
                })
            }
        })();
        result.map_err(|error| {
            context
                .ledger
                .with_state(|s| error.with_usage(s.encrypted.usage, s.run.usage).with_policy_usage(s.policy_metadata))
        })
    }
    pub fn write_all(&mut self, bytes: &[u8], cancel: &Cancellation) -> ZipSinkResult<()> {
        if self.reservation.ledger.with_state(|s| s.poisoned) {
            return Err(ZipSinkFault::StageChanged);
        }
        let result = self.reservation.write_all(self.file.as_mut().ok_or(ZipSinkFault::StageChanged)?, bytes, cancel);
        if result.is_err() {
            self.reservation.ledger.with_state(|s| s.poisoned = true);
        }
        result
    }
    fn validate(&self, context: &EncryptedReadContext) -> Result<(), ReadFault> {
        if self.reservation.ledger.identity() != context.ledger.identity()
            || self.reservation.ledger.with_state(|s| s.poisoned)
        {
            return Err(ReadFault::InvalidPlan);
        }
        context.verify_identity(self.source.owner)?;
        let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
        if !action.controlled_output
            || action.raw_output
            || !action.consumed
            || !action.completed
            || action.output != budget::PlannedOutput::VerifiedStdout
            || self.reservation.written != self.reservation.bytes
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    #[cfg(unix)]
    #[allow(clippy::unnecessary_cast)] // Native stat widths differ by Unix ABI.
    fn output_identity(
        &self,
        out: &impl std::os::fd::AsFd,
        cancel: &Cancellation,
        context: &EncryptedReadContext,
    ) -> Result<(), ReadFault> {
        let fd = out.as_fd();
        let actual = io::operation(
            &self.reservation.ledger,
            false,
            RunCategory::StageFinalization,
            IoStage::ExternalOutput,
            ReadIoOperation::Stat,
            Some(cancel),
            || native_policy::stat(fd.as_raw_fd()),
        )?;
        let expected =
            context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.output_descriptor.ok_or(ReadFault::InvalidPlan)?;
        if expected != self.descriptor
            || self.descriptor
                != (fd.as_raw_fd() as usize, actual.st_dev as u64, actual.st_ino as u64, actual.st_mode as u32)
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    #[cfg(unix)]
    pub fn copy_verified(
        mut self,
        out: &mut (impl Write + std::os::fd::AsFd),
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut final_check: impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadResult<u64> {
        let ready = (|| -> ZipReadResult<()> {
            self.validate(context)?;
            self.source.observe(context, &mut final_check)?;
            self.output_identity(out, cancel, context)?;
            Ok(())
        })();
        if let Err(error) = ready {
            return Err(self.finish_error(error, context));
        }
        let result = self.reservation.copy_to(self.file.as_mut().ok_or(ReadFault::InvalidPlan)?, out, cancel);
        // A write failure does not skip the mandatory source boundary observation.
        let boundary = self.source.observe(context, &mut final_check);
        let result = match (result, boundary) {
            (Ok(n), Ok(())) => Ok(n),
            (Ok(n), Err(error)) => Err(error.accepted(n)),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(boundary)) => Err(error.merge_source_boundary(boundary)),
        };
        match result {
            Err(error) => Err(self.finish_error(error, context)),
            Ok(n) => {
                self.terminal = true;
                let (admission, report) = self.retire(true);
                let mut error = admission.map(ZipReadError::from);
                if !report.is_empty() {
                    error = Some(match error {
                        Some(error) => error.merge_cleanup(report),
                        None => report.into(),
                    });
                }
                match error {
                    None => Ok(n),
                    Some(error) => Err(self.usage(error.accepted(n))),
                }
            }
        }
    }
    /// Explicitly retires owned storage on a failed read, retaining all terminal evidence.
    pub fn finish_error(mut self, error: ZipReadError, context: &mut EncryptedReadContext) -> ZipReadError {
        self.terminal = true;
        let mut error = error;
        if self.reservation.ledger.identity() != context.ledger.identity() {
            let mut report = ObjectCleanupReport::new(OwnedObject::Output);
            report.push(CleanupFault {
                object: OwnedObject::Output,
                operation: ReadIoOperation::Stat,
                offset: None,
                cause: CleanupCause::Admission(ReadFault::InvalidPlan),
                close: CloseDisposition::NotApplicable,
            });
            error = error.merge_cleanup(report);
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if self.named.is_some() {
            if let Some(cleanup) = self.retire_named() {
                error = error.merge_cleanup_only(cleanup);
            }
            return self.usage(error);
        }
        // Cleanup mode has no normal-success admission to retain.
        let (_, report) = self.retire(false);
        if !report.is_empty() {
            error = error.merge_cleanup(report);
        }
        self.usage(error)
    }
    fn usage(&self, error: ZipReadError) -> ZipReadError {
        self.reservation
            .ledger
            .with_state(|s| error.with_usage(s.encrypted.usage, s.run.usage).with_policy_usage(s.policy_metadata))
    }
    #[allow(clippy::unnecessary_cast)] // Native identity widths vary by Unix ABI.
    fn retire(&mut self, normal: bool) -> (Option<ReadFault>, ObjectCleanupReport) {
        let mut report = ObjectCleanupReport::new(OwnedObject::Output);
        let Some(file) = self.file.take() else {
            return (None, report);
        };
        let admission;
        #[cfg(unix)]
        {
            let observation =
                self.reservation.ledger.with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1));
            let observation = match observation {
                Err(fault) => Err(CleanupCause::Admission(fault)),
                Ok(()) => native_policy::stat(file.as_raw_fd()).map_err(CleanupCause::Io).and_then(|stat| {
                    if stat.st_mode & libc::S_IFMT == libc::S_IFREG
                        && stat.st_uid == self.uid
                        && stat.st_nlink == 0
                        && stat.st_dev as u64 == self.reservation.identity.dev
                        && stat.st_ino as u64 == self.reservation.identity.ino
                    {
                        Ok(())
                    } else {
                        Err(CleanupCause::Policy("output stage changed"))
                    }
                }),
            };
            let verified = observation.is_ok();
            if let Err(cause) = observation {
                report.push(CleanupFault {
                    object: OwnedObject::Output,
                    operation: ReadIoOperation::Stat,
                    offset: None,
                    cause,
                    close: CloseDisposition::NotApplicable,
                });
            }
            let fd = file.into_raw_fd();
            let closed = io::retire_in(
                &self.reservation.ledger,
                self.reservation.encrypted,
                OwnedObject::Output,
                Some(RunCategory::StageFinalization),
                normal,
                || native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ()),
            );
            let confirmed = closed.closed;
            admission = closed.admission;
            if let Some(fault) = closed.fault {
                report.push(fault);
            }
            if verified && confirmed {
                self.reservation
                    .ledger
                    .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
            } else {
                self.reservation.ledger.with_state(|s| s.poisoned = true);
            }
        }
        #[cfg(not(unix))]
        {
            drop(file);
            admission = Some(ReadFault::UnsupportedIdentity);
            self.reservation.ledger.with_state(|s| s.poisoned = true);
        }
        // FD retirement was already performed exactly once by retire_once.
        self.reservation.retired = true;
        (admission, report)
    }
}
impl Drop for ZipReadStage {
    fn drop(&mut self) {
        if !self.terminal {
            self.reservation.ledger.with_state(|s| s.poisoned = true);
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if self.named.is_some() {
                let _ = self.retire_named();
                return;
            }
            let _ = self.retire(false);
        }
    }
}

#[cfg(unix)]
pub(super) fn sanitized_matches(name: &str, windows_names: bool, relative: &Path) -> Result<(), ReadFault> {
    use std::os::unix::ffi::OsStrExt;
    let fail = || ReadFault::CheckedFormat { reason: "unsafe or foreign original ZIP output path" };
    let mut expected = relative.as_os_str().as_bytes().iter();
    let mut matches = true;
    let mut emitted = false;
    for (index, part) in name.split(|c| c == '/' || (windows_names && c == '\\')).enumerate() {
        if part.is_empty() && index == 0 && !name.is_empty() {
            return Err(fail());
        }
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".."
            || part.contains('\0')
            || (windows_names && index == 0 && part.len() == 2 && part.ends_with(':'))
        {
            return Err(fail());
        }
        if emitted && expected.next() != Some(&b'/') {
            matches = false;
        }
        emitted = true;
        for ch in part.chars() {
            let clean = if windows_names && matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*') { '_' } else { ch };
            let mut bytes = [0u8; 4];
            for byte in clean.encode_utf8(&mut bytes).as_bytes() {
                if expected.next() != Some(byte) {
                    matches = false;
                }
            }
        }
    }
    if !emitted || !matches || expected.next().is_some() {
        return Err(fail());
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) struct FileBinding<'r> {
    pub(super) relative: &'r Path,
    pub(super) source: FinalSourceProof,
    pub(super) bytes: u64,
    pub(super) encrypted: bool,
    pub(super) mode: Option<u32>,
    pub(super) mtime: Option<(i64, u32)>,
}
impl ZipStageEntry<'_> {
    #[allow(clippy::result_large_err)] // Original-source checks carry fixed inline terminal evidence.
    fn observe_source(&mut self, context: &mut EncryptedReadContext) -> ZipReadResult<()> {
        context.source_group(self.source.stamp)?;
        self.source.verify_checked(self.file, context)?;
        context.successful_source_observation(self.owner, self.source.stamp)?;
        Ok(())
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[allow(clippy::result_large_err)] // Failure retirement and source evidence never allocate.
    pub(super) fn bind_file<'r>(
        &mut self,
        relative: &'r Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<FileBinding<'r>> {
        let mut started = false;
        let result = (|| -> ZipReadResult<FileBinding<'r>> {
            context.verify_identity(self.owner)?;
            let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
            if context.ledger.with_state(|s| s.poisoned)
                || !(action.scope == ProjectedReadScope::Entry(self.ordinal)
                    || action.scope == ProjectedReadScope::AllRegular
                        && action.active_ordinal == Some(self.ordinal)
                        && action.run_bound
                        && action.active_record_charged)
                || action.output != budget::PlannedOutput::StagedFiles
                || action.consumed
                || action.completed
                || action.controlled_output
                || action.raw_output
                || options.mode != crate::extract::Mode::Extract
                || action.destination.as_ref().is_none_or(|d| d.as_os_str() != options.dest.as_os_str())
            {
                return Err(ReadFault::InvalidPlan.into());
            }
            if let Some(original) = self.relative {
                if original.as_os_str() != relative.as_os_str() {
                    return Err(ReadFault::InvalidPlan.into());
                }
            } else {
                sanitized_matches(self.entry.name, self.windows_names, relative)?;
            }
            if relative.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
                return Err(ReadFault::InvalidPlan.into());
            }
            let operational = if options.flatten {
                relative.file_name().ok_or(ReadFault::InvalidPlan)?
            } else {
                relative.as_os_str()
            };
            let operational = Path::new(operational);
            if let Some(policy) = action.policy.as_ref()
                && !action.run_bound
                && !policy.matches(options, action.destination.as_ref().unwrap())
            {
                return Err(ReadFault::InvalidPlan.into());
            }
            started = true;
            context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.controlled_output = true;
            self.observe_source(context)?;
            let encrypted = self.validate_limits(context)?;
            if context.ledger.with_state(|s| s.output_encrypted())? != encrypted {
                return Err(ReadFault::InvalidPlan.into());
            }
            io::canceled(Some(cancel))?;
            context.ledger.with_state(|s| s.register_controlled_source())?;
            let fresh = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.policy.is_none();
            if fresh {
                let ceiling = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.attempt_ceiling;
                let bound = policy::FrozenPolicy::bind(
                    &context.ledger,
                    options,
                    &self.source.path,
                    self.file,
                    self.source.stamp,
                    ceiling,
                    cancel,
                );
                context.options.limits.io_attempts = context.ledger.with_state(|s| s.encrypted.limits.io_attempts);
                match bound {
                    Ok(policy) => context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.policy = Some(policy),
                    Err(error) => {
                        return Err(match self.observe_source(context) {
                            Ok(()) => error,
                            Err(boundary) => error.merge_source_boundary(boundary),
                        });
                    }
                }
            }
            let proof = FinalSourceProof::original(self.owner, context)?;
            if fresh {
                self.observe_source(context)?;
            }
            Ok(FileBinding {
                relative: operational,
                source: proof,
                bytes: self.entry.size,
                encrypted,
                mode: self.mode,
                mtime: self.mtime,
            })
        })();
        if started && result.is_err() {
            context.ledger.with_state(|s| s.poisoned = true);
        }
        result.map_err(|error| {
            context
                .ledger
                .with_state(|s| error.with_usage(s.encrypted.usage, s.run.usage).with_policy_usage(s.policy_metadata))
        })
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(super) fn control_layout() -> [usize; 12] {
    file::control_layout()
}
