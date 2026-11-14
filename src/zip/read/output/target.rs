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

//! Target ordering and bounded native canonical protection.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

pub(in crate::zip::read) enum Target {
    Missing,
    Existing,
    Skip,
}
#[allow(clippy::result_large_err)]
pub(in crate::zip::read) fn inspect(
    ledger: &impl LedgerAccess,
    parent: &mut parent::HeldParent,
    policy: &policy::FrozenPolicy,
    overwrite: crate::extract::Overwrite,
    category: RunCategory,
    scratch: &mut [u8],
    cancel: &Cancellation,
) -> ZipReadResult<Target> {
    let actual = io::operation(ledger, false, category, IoStage::Output, ReadIoOperation::Stat, Some(cancel), || {
        spool::syscall(ReadIoOperation::Stat, parent.file.as_raw_fd(), || {
            let mut stat = std::mem::MaybeUninit::uninit();
            match native_policy::cvt(unsafe {
                libc::fstatat(
                    parent.file.as_raw_fd(),
                    parent.target().as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            }) {
                Ok(_) => Ok(Some(unsafe { stat.assume_init() })),
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
                Err(error) => Err(error),
            }
        })
    })?;
    let Some(actual) = actual else {
        return Ok(Target::Missing);
    };
    if actual.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err(ReadFault::CheckedFormat { reason: "output target is a symlink" }.into());
    }
    if overwrite == crate::extract::Overwrite::Skip {
        return Ok(Target::Skip);
    }
    if actual.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return Err(ReadFault::CheckedFormat { reason: "output target is a directory" }.into());
    }
    let expected = policy::CanonicalIdentity::of(&actual);
    let retries = ledger.with_state(|s| s.creation_policy(false).map(|p| p.1))?;
    let target = parent.target_path();
    let mut charge = |_, first| {
        ledger.with_state(|s| {
            if first {
                s.charge_category(RunCategory::CanonicalMetadataOperations, 1)?;
            }
            s.attempt(false)
        })
    };
    #[cfg(target_os = "macos")]
    let evidence = policy::canonicalize(&target, policy.cwd(), scratch, retries, cancel, &mut charge)
        .map_err(policy::CanonicalFailure::into_error)?;
    #[cfg(target_os = "linux")]
    let evidence = policy::canonicalize(
        ledger,
        policy::CanonicalRequest { input: &target, cwd: policy.cwd(), held: None },
        scratch,
        retries,
        cancel,
        &mut charge,
    )
    .map_err(policy::CanonicalFailure::into_error)?;
    if evidence.identity != expected {
        return Err(
            ReadFault::CheckedFormat { reason: "output target identity changed during canonical observation" }.into()
        );
    }
    let name = Path::new(std::ffi::OsStr::from_bytes(evidence.bytes(scratch)));
    if policy.protects(name, evidence.identity) {
        return Err(ReadFault::CheckedFormat { reason: "output target replaces a protected input" }.into());
    }
    Ok(Target::Existing)
}
