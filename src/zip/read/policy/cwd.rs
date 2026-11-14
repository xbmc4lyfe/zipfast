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

//! One closed, phase-exclusive CWD acquisition, preserving its own close evidence.
use super::*;
use crate::zip::read::shared::{LedgerAccess, LedgerView};
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[derive(Debug)]
pub(in crate::zip::read) struct CwdFailure {
    operation: Option<ReadFault>,
    cleanup: [Option<CleanupFault>; 2],
}
impl From<ReadFault> for CwdFailure {
    fn from(operation: ReadFault) -> Self {
        Self { operation: Some(operation), cleanup: [None, None] }
    }
}
impl CwdFailure {
    pub(in crate::zip::read) fn into_stage_error(mut self) -> ZipReadError {
        if self.operation.is_none() {
            for slot in &mut self.cleanup {
                if slot.as_ref().is_some_and(|f| matches!(f.cause, CleanupCause::Admission(_))) {
                    if let Some(CleanupFault { cause: CleanupCause::Admission(f), .. }) = slot.take() {
                        self.operation = Some(f);
                    }
                    break;
                }
            }
        }
        self.into_error()
    }
    fn into_error(self) -> ZipReadError {
        let mut cleanup = ObjectCleanupReport::new(OwnedObject::SourcePathDirectory);
        for fault in self.cleanup.into_iter().flatten() {
            cleanup.push(fault);
        }
        match self.operation {
            Some(op) => ZipReadError::from(op).merge_cleanup(cleanup),
            None => cleanup.into(),
        }
    }
    pub(in crate::zip::read) fn merge(self, error: ZipReadError) -> ZipReadError {
        if error.is_placeholder() {
            self.into_error()
        } else {
            error.merge_cleanup_only(
                self.into_error()
                    .owned_boundary_error(OwnedObject::SourcePathDirectory, ReadIoOperation::DescriptorMode),
            )
        }
    }
}
#[cfg(all(test, target_os = "macos"))]
type Hook = Option<Box<dyn FnMut(ReadIoOperation) -> Option<i32>>>;
#[cfg(all(test, target_os = "macos"))]
thread_local! {pub(in crate::zip::read) static HOOK:std::cell::RefCell<Hook>=const{std::cell::RefCell::new(None)};}
#[cfg(target_os = "macos")]
fn native<T>(operation: ReadIoOperation, call: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    #[cfg(test)]
    let fault = {
        let mut hook = HOOK.with(|s| s.borrow_mut().take());
        let fault = hook.as_mut().and_then(|h| h(operation));
        HOOK.with(|s| *s.borrow_mut() = hook);
        fault
    };
    #[cfg(not(test))]
    let _ = operation;
    #[cfg(test)]
    if operation != ReadIoOperation::Close
        && let Some(code) = fault
    {
        return Err(std::io::Error::from_raw_os_error(code));
    }
    let result = call();
    #[cfg(test)]
    if operation == ReadIoOperation::Close
        && let Some(code) = fault
    {
        result?;
        return Err(std::io::Error::from_raw_os_error(code));
    }
    result
}
#[cfg(target_os = "macos")]
#[allow(clippy::result_large_err)] // The closed operation plus two owned close slots remain inline.
pub(in crate::zip::read) fn capture<'a>(
    ledger: LedgerView<'a>,
    scratch: &mut PolicyScratch<'a>,
    cancel: &Cancellation,
    record: &mut dyn FnMut() -> std::io::Result<()>,
) -> Result<MetadataLease<'a, u8>, CwdFailure> {
    ledger.with_state(|s| {
        s.charge_category(RunCategory::PathSteps, 1)?;
        s.acquire_fds(1)
    })?;
    let acquired =
        io::attempted_operation(&ledger, false, IoStage::SourcePath, ReadIoOperation::Open, Some(cancel), || {
            record()?;
            native(ReadIoOperation::Open, || {
                native_policy::cvt(unsafe {
                    libc::open(c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
                })
            })
        });
    let fd = match acquired {
        Ok(fd) => fd,
        Err(f) => {
            ledger.with_state(|s| s.retire_fd(true));
            return Err(f.into());
        }
    };
    let file = unsafe { File::from_raw_fd(fd) };
    let body = (|| -> Result<MetadataLease<'a, u8>, ReadFault> {
        io::attempted_operation(
            &ledger,
            false,
            IoStage::SourcePath,
            ReadIoOperation::DescriptorMode,
            Some(cancel),
            || {
                record()?;
                native(ReadIoOperation::DescriptorMode, || {
                    native_policy::cvt(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, scratch.as_mut_ptr()) })
                })
            },
        )?;
        let n = scratch[..libc::PATH_MAX as usize]
            .iter()
            .position(|b| *b == 0)
            .ok_or(ReadFault::CheckedFormat { reason: "unterminated frozen cwd" })?;
        if n == 0 || scratch[0] != b'/' {
            return Err(ReadFault::CheckedFormat { reason: "invalid frozen cwd" });
        }
        let mut copy = MetadataLease::zeroed(ledger, PolicyComponent::Caller, n + 1)?;
        copy.copy_from_slice(&scratch[..=n]);
        Ok(copy)
    })();
    let fd = file.into_raw_fd();
    let retired = io::retire_in(&ledger, false, OwnedObject::SourcePathDirectory, None, body.is_ok(), || {
        record()?;
        native(ReadIoOperation::Close, || native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ()))
    });
    let admission = retired.admission.map(|f| CleanupFault {
        object: OwnedObject::SourcePathDirectory,
        operation: ReadIoOperation::Close,
        offset: None,
        cause: CleanupCause::Admission(f),
        close: CloseDisposition::NotApplicable,
    });
    let cleanup = [admission, retired.fault];
    if cleanup.iter().any(Option::is_some) {
        return Err(CwdFailure { operation: body.err(), cleanup });
    }
    body.map_err(CwdFailure::from)
}
#[cfg(target_os = "linux")]
#[allow(clippy::result_large_err)] // The closed operation plus two owned close slots remain inline.
pub(in crate::zip::read) fn capture<'a>(
    ledger: LedgerView<'a>,
    scratch: &mut PolicyScratch<'a>,
    cancel: &Cancellation,
    record: &mut dyn FnMut() -> std::io::Result<()>,
) -> Result<MetadataLease<'a, u8>, CwdFailure> {
    ledger.with_state(|s| s.charge_category(RunCategory::PathSteps, 1))?;
    let n = io::attempted_operation(&ledger, false, IoStage::SourcePath, ReadIoOperation::Read, Some(cancel), || {
        record()?;
        let n = unsafe { libc::syscall(libc::SYS_getcwd, scratch.as_mut_ptr(), libc::PATH_MAX as usize) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    })?;
    if n < 2 || n > libc::PATH_MAX as usize || scratch[n - 1] != 0 || scratch[0] != b'/' {
        return Err(ReadFault::CheckedFormat { reason: "invalid native frozen cwd" }.into());
    }
    let mut copy = MetadataLease::zeroed(ledger, PolicyComponent::Caller, n)?;
    copy.copy_from_slice(&scratch[..n]);
    Ok(copy)
}
