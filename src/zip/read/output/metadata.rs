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

//! Required captured creation policy, followed by best-effort archived metadata.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use std::os::fd::AsRawFd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::zip::read) enum MetadataStep {
    Time,
    AclWrite,
    AclRead,
    BaselineMode,
    ArchiveMode,
    Identity,
}
pub(in crate::zip::read) struct MetadataPlan<'a> {
    pub(in crate::zip::read) identity: FileIdentity,
    pub(in crate::zip::read) uid: libc::uid_t,
    pub(in crate::zip::read) gid: libc::gid_t,
    pub(in crate::zip::read) bytes: u64,
    pub(in crate::zip::read) baseline: u32,
    pub(in crate::zip::read) mode: Option<u32>,
    pub(in crate::zip::read) mtime: Option<(i64, u32)>,
    pub(in crate::zip::read) acl: Option<&'a [u8]>,
}
#[cfg(test)]
type Hook = Option<Box<dyn FnMut(MetadataStep) -> Option<std::io::Error>>>;
#[cfg(test)]
thread_local! {pub(in crate::zip::read) static HOOK:std::cell::RefCell<Hook>=const {std::cell::RefCell::new(None)};}
fn syscall<T>(step: MetadataStep, call: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    #[cfg(test)]
    {
        let mut hook = HOOK.with(|state| state.borrow_mut().take());
        let fault = hook.as_mut().and_then(|h| h(step));
        HOOK.with(|state| *state.borrow_mut() = hook);
        if let Some(error) = fault {
            return Err(error);
        }
    }
    #[cfg(not(test))]
    let _ = step;
    call()
}
fn time(at: Option<(i64, u32)>) -> Option<libc::timespec> {
    let (seconds, nanos) = at?;
    crate::extract::archive_time(seconds, nanos)?;
    // The complete i64 seconds/u32 nanoseconds domain fits comfortably in i128.
    let total = seconds as i128 * 1_000_000_000 + nanos as i128;
    Some(libc::timespec {
        tv_sec: libc::time_t::try_from(total.div_euclid(1_000_000_000)).ok()?,
        tv_nsec: total.rem_euclid(1_000_000_000) as libc::c_long,
    })
}
fn operation<T>(
    ledger: &impl LedgerAccess,
    encrypted: bool,
    step: MetadataStep,
    op: ReadIoOperation,
    cancel: &Cancellation,
    mut call: impl FnMut() -> std::io::Result<T>,
) -> Result<T, ReadFault> {
    io::operation(ledger, encrypted, RunCategory::StageFinalization, IoStage::Output, op, Some(cancel), || {
        spool::syscall(op, -1, || syscall(step, &mut call))
    })
}
fn ordinary(result: Result<(), ReadFault>) -> Result<(), ReadFault> {
    match result {
        Ok(()) | Err(ReadFault::Io { .. }) => Ok(()),
        Err(error) => Err(error),
    }
}
#[allow(clippy::unnecessary_cast)] // stat identity and mode widths vary by Unix target.
pub(in crate::zip::read) fn restore(
    ledger: &impl LedgerAccess,
    encrypted: bool,
    file: &File,
    plan: &MetadataPlan<'_>,
    scratch: &mut [u8],
    cancel: &Cancellation,
) -> Result<(), ReadFault> {
    if plan.baseline & !0o777 != 0 {
        return Err(ReadFault::InvalidPlan);
    }
    // Prepare the complete native request before charging any physical call.
    let prepared = native_policy::prepare_acl_write(plan.acl, scratch)
        .map_err(|_| ReadFault::CheckedFormat { reason: "invalid retained output security policy" })?;
    if let Some(modified) = time(plan.mtime) {
        let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT as libc::c_long }, modified];
        ordinary(operation(ledger, encrypted, MetadataStep::Time, ReadIoOperation::SetTime, cancel, || {
            native_policy::cvt(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) }).map(|_| ())
        }))?;
    }
    // fsetattrlist/fsetxattr/removexattr is exactly one required native operation.
    // PreparedAcl is consumed; interrupted metadata mutation is not retried with a spent request.
    ledger.with_state(|s| s.charge_category(RunCategory::StageFinalization, 1))?;
    io::canceled(Some(cancel))?;
    ledger.with_state(|s| s.attempt(encrypted))?;
    spool::syscall(ReadIoOperation::SetAcl, file.as_raw_fd(), || {
        syscall(MetadataStep::AclWrite, || prepared.apply(file.as_raw_fd()))
    })
    .map_err(|error| ReadFault::Io {
        stage: IoStage::Output,
        operation: ReadIoOperation::SetAcl,
        offset: 0,
        error,
    })?;
    let matches = operation(ledger, encrypted, MetadataStep::AclRead, ReadIoOperation::ReadAcl, cancel, || {
        native_policy::read_acl(file.as_raw_fd(), false, scratch).map(|actual| actual == plan.acl)
    })?;
    if !matches {
        return Err(ReadFault::CheckedFormat { reason: "output security reconstruction changed" });
    }
    // Required even when no archive mode exists: a failed optional chmod must
    // leave the same baseline as incumbent ordinary creation, never private0600.
    operation(ledger, encrypted, MetadataStep::BaselineMode, ReadIoOperation::DescriptorMode, cancel, || {
        native_policy::cvt(unsafe { libc::fchmod(file.as_raw_fd(), plan.baseline as libc::mode_t) }).map(|_| ())
    })?;
    if let Some(mode) = plan.mode {
        ordinary(operation(
            ledger,
            encrypted,
            MetadataStep::ArchiveMode,
            ReadIoOperation::DescriptorMode,
            cancel,
            || {
                native_policy::cvt(unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o777) as libc::mode_t) })
                    .map(|_| ())
            },
        ))?;
    }
    let actual = operation(ledger, encrypted, MetadataStep::Identity, ReadIoOperation::Stat, cancel, || {
        native_policy::stat(file.as_raw_fd())
    })?;
    if actual.st_mode & libc::S_IFMT != libc::S_IFREG
        || actual.st_uid != plan.uid
        || actual.st_gid != plan.gid
        || actual.st_nlink != 1
        || actual.st_size < 0
        || actual.st_size as u64 != plan.bytes
        || actual.st_dev as u64 != plan.identity.dev
        || actual.st_ino as u64 != plan.identity.ino
    {
        return Err(ReadFault::CheckedFormat { reason: "output stage identity or creation group changed" });
    }
    Ok(())
}
