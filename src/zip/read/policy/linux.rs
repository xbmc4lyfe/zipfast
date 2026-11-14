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

//! Bounded Linux metadata-only canonical resolution through a trusted kernel procfs view.
//! Each observed procfd/canonical spelling must agree with the live owned handle.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;

type Failure = CanonicalFailure;
pub(in crate::zip::read) struct CanonicalRequest<'a> {
    pub(in crate::zip::read) input: &'a Path,
    pub(in crate::zip::read) cwd: &'a Path,
    // Only the original-source role uses a borrowed existing data handle.
    pub(in crate::zip::read) held: Option<&'a File>,
}
fn malformed() -> Failure {
    Failure::Terminal(ReadFault::CheckedFormat {
        reason: "inconsistent or malformed Linux canonical namespace observation",
    })
}
fn original(error: std::io::Error) -> Failure {
    Failure::Ordinary(ReadFault::Io { stage: IoStage::SourcePath, operation: ReadIoOperation::Open, offset: 0, error })
}
fn observed(failure: Failure) -> Failure {
    match failure {
        Failure::Ordinary(fault) => Failure::Terminal(fault),
        other => other,
    }
}
struct Calls<'a, F> {
    charge: &'a mut F,
    retries: u64,
    cancel: &'a Cancellation,
}
#[allow(clippy::result_large_err)] // Linux terminal metadata failures keep inline, allocation-free evidence.
impl<F: FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>> Calls<'_, F> {
    fn call<T>(&mut self, op: CanonicalOperation, mut call: impl FnMut() -> std::io::Result<T>) -> Result<T, Failure> {
        let mut retries = 0u64;
        loop {
            io::canceled(Some(self.cancel)).map_err(Failure::Terminal)?;
            (self.charge)(op, retries == 0).map_err(Failure::Terminal)?;
            let operation = match op {
                CanonicalOperation::Open => ReadIoOperation::Open,
                CanonicalOperation::ReadLink => ReadIoOperation::Read,
                _ => ReadIoOperation::Stat,
            };
            match spool::syscall(operation, -1, &mut call) {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    retries = retries.checked_add(1).ok_or(Failure::Terminal(ReadFault::CounterOverflow))?;
                    budget::admit(ReadResource::InterruptedRetries, self.retries.into(), retries.into())
                        .map_err(Failure::Terminal)?;
                }
                Err(error) => {
                    return Err(Failure::Ordinary(ReadFault::Io {
                        stage: IoStage::SourcePath,
                        operation: match op {
                            CanonicalOperation::Open => ReadIoOperation::Open,
                            CanonicalOperation::ReadLink => ReadIoOperation::Read,
                            _ => ReadIoOperation::Stat,
                        },
                        offset: 0,
                        error,
                    }));
                }
            }
        }
    }
}
/// Seven metadata calls plus one owned close; the original-source shortcut
/// borrows its actual original File and performs six metadata calls, no open.
#[allow(clippy::result_large_err)] // Fixed inline cleanup evidence, never allocated on FD failure.
pub(in crate::zip::read) fn canonicalize(
    ledger: &impl LedgerAccess,
    request: CanonicalRequest<'_>,
    scratch: &mut [u8],
    retries: u64,
    cancel: &Cancellation,
    charge: &mut impl FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>,
) -> Result<CanonicalEvidence, Failure> {
    let h = libc::PATH_MAX as usize;
    let region = h.checked_add(1).ok_or(Failure::Terminal(ReadFault::CounterOverflow))?;
    if scratch.len() < 2 * region {
        return Err(malformed());
    }
    let raw = request.input.as_os_str().as_bytes();
    let cwd = request.cwd.as_os_str().as_bytes();
    if raw.contains(&0) || cwd.contains(&0) {
        return Err(original(std::io::ErrorKind::InvalidInput.into()));
    }
    if raw.is_empty() {
        return Err(original(std::io::Error::from_raw_os_error(libc::ENOENT)));
    }
    if !request.cwd.is_absolute() {
        return Err(malformed());
    }
    let prefix = if raw.starts_with(b"/") {
        0
    } else {
        cwd.len().checked_add(1).ok_or(Failure::Terminal(ReadFault::CounterOverflow))?
    };
    let n = prefix.checked_add(raw.len()).ok_or(Failure::Terminal(ReadFault::CounterOverflow))?;
    if n >= h {
        return Err(original(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG)));
    }
    let (original_bytes, result_bytes) = scratch.split_at_mut(region);
    if prefix != 0 {
        original_bytes[..cwd.len()].copy_from_slice(cwd);
        original_bytes[cwd.len()] = b'/';
    }
    original_bytes[prefix..n].copy_from_slice(raw);
    original_bytes[n] = 0;
    let spelling = CStr::from_bytes_with_nul(&original_bytes[..=n]).map_err(|_| malformed())?;
    let mut calls = Calls { charge, retries, cancel };
    let mut owned = None;
    if request.held.is_none() {
        ledger.with_state(|s| s.acquire_fds(1)).map_err(Failure::Terminal)?;
        let opened = calls.call(CanonicalOperation::Open, || {
            native_policy::cvt(unsafe { libc::open(spelling.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })
        });
        match opened {
            Ok(fd) => owned = Some(unsafe { File::from_raw_fd(fd) }),
            Err(failure) => {
                ledger.with_state(|s| s.retire_fd(true));
                let failure = match failure {
                    Failure::Ordinary(ReadFault::Io { ref error, .. })
                        if error.raw_os_error() == Some(libc::EINVAL)
                            || error.kind() == std::io::ErrorKind::Unsupported =>
                    {
                        observed(failure)
                    }
                    other => other,
                };
                return Err(failure);
            }
        }
    }
    let file = request.held.or(owned.as_ref()).expect("original or newly acquired canonical metadata handle");
    let result = (|| -> Result<CanonicalEvidence, Failure> {
        let first =
            calls.call(CanonicalOperation::HeldStat, || native_policy::stat(file.as_raw_fd())).map_err(observed)?;
        let identity = CanonicalIdentity::of(&first);
        let original =
            calls.call(CanonicalOperation::OriginalStat, || native_policy::path_stat(spelling)).map_err(observed)?;
        if CanonicalIdentity::of(&original) != identity {
            return Err(malformed());
        }
        let mut proc_bytes = [0u8; 64];
        let procfd = native_policy::procfd_path(file.as_raw_fd(), &mut proc_bytes).map_err(|_| malformed())?;
        let proc = calls.call(CanonicalOperation::ProcStat, || native_policy::path_stat(procfd)).map_err(observed)?;
        if CanonicalIdentity::of(&proc) != identity {
            return Err(malformed());
        }
        let count = calls
            .call(CanonicalOperation::ReadLink, || {
                let count = unsafe { libc::readlink(procfd.as_ptr(), result_bytes.as_mut_ptr().cast(), region) };
                if count < 0 { Err(std::io::Error::last_os_error()) } else { Ok(count as usize) }
            })
            .map_err(observed)?;
        if count == 0 || count >= h || result_bytes[0] != b'/' {
            return Err(malformed());
        }
        result_bytes[count] = 0;
        // Never strip a deleted suffix or guess another hardlink spelling.
        let resolved = CStr::from_bytes_with_nul(&result_bytes[..=count]).map_err(|_| malformed())?;
        let actual =
            calls.call(CanonicalOperation::CanonicalStat, || native_policy::path_stat(resolved)).map_err(observed)?;
        let last =
            calls.call(CanonicalOperation::FinalStat, || native_policy::stat(file.as_raw_fd())).map_err(observed)?;
        if CanonicalIdentity::of(&actual) != identity || CanonicalIdentity::of(&last) != identity {
            return Err(malformed());
        }
        Ok(CanonicalEvidence { identity, start: region, len: count })
    })();
    let closing = owned.and_then(|file| {
        let fd = file.into_raw_fd();
        let closed = io::retire_in(
            ledger,
            false,
            OwnedObject::PolicyPath,
            Some(RunCategory::CanonicalMetadataOperations),
            true,
            || {
                spool::syscall(ReadIoOperation::Close, fd, || {
                    native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                })
            },
        );
        let mut error = closed.admission.map(ZipReadError::from);
        if let Some(fault) = closed.fault {
            let mut report = ObjectCleanupReport::new(OwnedObject::PolicyPath);
            report.push(fault);
            error = Some(match error {
                Some(error) => error.merge_cleanup(report),
                None => report.into(),
            });
        }
        error
    });
    match (result, closing) {
        (result, None) => result,
        (Ok(_), Some(error)) => Err(Failure::Cleanup(error)),
        (Err(failure), Some(error)) => Err(Failure::Cleanup(
            failure.into_error().merge_cleanup_only(error.retirement_cleanup(OwnedObject::PolicyPath)),
        )),
    }
}
