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

//! Held output-parent traversal. Configured-root aliases and archive components differ.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;

pub(in crate::zip::read) struct HeldParent {
    pub(in crate::zip::read) file: File,
    pub(in crate::zip::read) identity: FileIdentity,
    path: policy::OwnedMetadata<u8>,
    parent_end: usize,
}
pub(in crate::zip::read) struct TargetPath<'a> {
    bytes: &'a mut policy::OwnedMetadata<u8>,
    separator: usize,
}
impl std::ops::Deref for TargetPath<'_> {
    type Target = Path;
    fn deref(&self) -> &Path {
        Path::new(std::ffi::OsStr::from_bytes(&self.bytes[..self.bytes.len() - 1]))
    }
}
impl Drop for TargetPath<'_> {
    fn drop(&mut self) {
        self.bytes[self.separator] = 0;
    }
}
impl HeldParent {
    pub(in crate::zip::read) fn target_path(&mut self) -> TargetPath<'_> {
        self.path[self.parent_end] = b'/';
        TargetPath { bytes: &mut self.path, separator: self.parent_end }
    }
    pub(in crate::zip::read) fn path(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.path[..=self.parent_end]).expect("checked parent path")
    }
    pub(in crate::zip::read) fn target(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.path[self.parent_end + 1..]).expect("checked target leaf")
    }
    #[allow(clippy::unnecessary_cast)] // Native identity widths vary by Unix ABI.
    pub(in crate::zip::read) fn verify_normal_name(
        &self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        cancel: &Cancellation,
    ) -> Result<(), ReadFault> {
        let actual = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || {
                spool::syscall(ReadIoOperation::Stat, self.file.as_raw_fd(), || {
                    let mut stat = std::mem::MaybeUninit::uninit();
                    native_policy::cvt(unsafe { libc::stat(self.path().as_ptr(), stat.as_mut_ptr()) })?;
                    Ok(unsafe { stat.assume_init() })
                })
            },
        )?;
        if actual.st_dev as u64 != self.identity.dev
            || actual.st_ino as u64 != self.identity.ino
            || actual.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(ReadFault::CheckedFormat { reason: "output parent original spelling changed" });
        }
        Ok(())
    }
    #[allow(clippy::unnecessary_cast)] // Native identity widths vary by Unix ABI.
    pub(in crate::zip::read) fn verify_cleanup_name(&self, ledger: &impl LedgerAccess) -> Result<(), CleanupFault> {
        let fault = |cause| CleanupFault {
            object: OwnedObject::OutputParent,
            operation: ReadIoOperation::Stat,
            offset: None,
            close: CloseDisposition::NotApplicable,
            cause,
        };
        ledger
            .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
            .map_err(|error| fault(CleanupCause::Admission(error)))?;
        let mut actual = std::mem::MaybeUninit::uninit();
        spool::syscall(ReadIoOperation::Stat, self.file.as_raw_fd(), || {
            native_policy::cvt(unsafe { libc::stat(self.path().as_ptr(), actual.as_mut_ptr()) })
        })
        .map_err(|error| fault(CleanupCause::Io(error)))?;
        let actual = unsafe { actual.assume_init() };
        if actual.st_dev as u64 != self.identity.dev
            || actual.st_ino as u64 != self.identity.ino
            || actual.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(fault(CleanupCause::Policy("output parent original spelling changed")));
        }
        Ok(())
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn finish(self, ledger: &impl LedgerAccess) -> ZipReadResult<()> {
        let observed = self.verify_cleanup_name(ledger);
        let result = self.finish_observed(ledger, observed.is_ok(), false);
        match observed {
            Ok(()) => result,
            Err(fault) => {
                let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                report.push(fault);
                Err(match result {
                    Ok(()) => report.into(),
                    Err(error) => ZipReadError::from(report).merge_cleanup_only(error),
                })
            }
        }
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn finish_observed(
        self,
        ledger: &impl LedgerAccess,
        normal: bool,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        let result = close(ledger, self.file, encrypted, RunCategory::StageFinalization, normal);
        let released = self.path.finish(ledger).map_err(|(_, fault)| ZipReadError::from(fault));
        match (result, released) {
            (Err(error), _) => Err(error),
            (Ok(()), result) => result,
        }
    }
}
#[allow(clippy::result_large_err)]
fn close(
    ledger: &impl LedgerAccess,
    file: File,
    encrypted: bool,
    category: RunCategory,
    normal: bool,
) -> ZipReadResult<()> {
    let fd = file.into_raw_fd();
    let retired = io::retire_in(ledger, encrypted, OwnedObject::OutputParent, Some(category), normal, || {
        spool::syscall(ReadIoOperation::Close, fd, || native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ()))
    });
    let mut error = retired.admission.map(ZipReadError::from);
    if let Some(fault) = retired.fault {
        let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
        report.push(fault);
        error = Some(match error {
            Some(error) => error.merge_cleanup(report),
            None => report.into(),
        });
    }
    error.map_or(Ok(()), Err)
}
fn operation<T>(
    ledger: &impl LedgerAccess,
    op: ReadIoOperation,
    cancel: &Cancellation,
    mut call: impl FnMut() -> std::io::Result<T>,
) -> Result<T, ReadFault> {
    io::operation(ledger, false, RunCategory::PathSteps, IoStage::Output, op, Some(cancel), || {
        spool::syscall(op, -1, &mut call)
    })
}
fn mkdir(ledger: &impl LedgerAccess, fd: Option<i32>, name: &CStr, cancel: &Cancellation) -> Result<(), ReadFault> {
    ledger.with_state(|s| s.charge_category(RunCategory::PathSteps, 1))?;
    io::canceled(Some(cancel))?;
    ledger.with_state(|s| s.attempt(false))?;
    spool::syscall(ReadIoOperation::Directory, fd.unwrap_or(-1), || {
        let result = unsafe {
            match fd {
                Some(fd) => libc::mkdirat(fd, name.as_ptr(), 0o777),
                None => libc::mkdir(name.as_ptr(), 0o777),
            }
        };
        match native_policy::cvt(result) {
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            result => result.map(|_| ()),
        }
    })
    .map_err(|error| ReadFault::Io {
        stage: IoStage::Output,
        operation: ReadIoOperation::Directory,
        offset: 0,
        error,
    })
}
fn c(bytes: &[u8]) -> Result<&CStr, ReadFault> {
    CStr::from_bytes_with_nul(bytes).map_err(|_| ReadFault::InvalidPlan)
}
#[allow(clippy::result_large_err, clippy::unnecessary_cast)] // Inline fault evidence; Unix stat ABI widths.
pub(in crate::zip::read) fn open_parent(
    ledger: &impl LedgerAccess,
    root: &Path,
    relative: &Path,
    cwd: &Path,
    cancel: &Cancellation,
) -> ZipReadResult<HeldParent> {
    // One parent slot was reserved with the complete output envelope before this
    // function. It is released on every failed acquisition, never double-charged.
    let mut file = None;
    let result = (|| -> ZipReadResult<_> {
        if !cwd.is_absolute() || relative.components().any(|p| !matches!(p, std::path::Component::Normal(_))) {
            return Err(ReadFault::InvalidPlan.into());
        }
        let root = root.as_os_str().as_bytes();
        let rel = relative.as_os_str().as_bytes();
        let cwd = cwd.as_os_str().as_bytes();
        if root.contains(&0) || rel.contains(&0) || cwd.contains(&0) || rel.is_empty() {
            return Err(ReadFault::InvalidPlan.into());
        }
        let prefix =
            if root.starts_with(b"/") { 0 } else { cwd.len().checked_add(1).ok_or(ReadFault::CounterOverflow)? };
        let root_end = prefix.checked_add(root.len()).ok_or(ReadFault::CounterOverflow)?;
        let capacity =
            root_end.checked_add(rel.len()).and_then(|n| n.checked_add(2)).ok_or(ReadFault::CounterOverflow)?;
        let mut path = policy::MetadataLease::zeroed(ledger.view(), policy::PolicyComponent::Caller, capacity)?;
        if prefix != 0 {
            path[..cwd.len()].copy_from_slice(cwd);
            path[cwd.len()] = b'/';
        }
        path[prefix..root_end].copy_from_slice(root);
        path[root_end] = b'/';
        path[root_end + 1..capacity - 1].copy_from_slice(rel);
        // Root aliases are caller configuration. Follow them, matching incumbent
        // create_dir_all semantics; archive-relative components below never follow.
        for end in 1..=root_end {
            if end == root_end || path[end] == b'/' {
                if path[end - 1] == b'/' {
                    continue;
                }
                let saved = path[end];
                path[end] = 0;
                let made = mkdir(ledger, None, c(&path[..=end])?, cancel);
                path[end] = saved;
                made?;
            }
        }
        let saved = path[root_end];
        path[root_end] = 0;
        let opened = operation(ledger, ReadIoOperation::Open, cancel, || {
            native_policy::cvt(unsafe {
                libc::open(
                    c(&path[..=root_end]).map_err(|_| std::io::ErrorKind::InvalidInput)?.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            })
        });
        path[root_end] = saved;
        file = Some(unsafe { File::from_raw_fd(opened?) });
        let mut component = root_end + 1;
        for end in root_end + 1..capacity - 1 {
            if path[end] != b'/' {
                continue;
            }
            path[end] = 0;
            let name = c(&path[component..=end])?;
            let parent = file.as_ref().unwrap().as_raw_fd();
            let observed = operation(ledger, ReadIoOperation::Stat, cancel, || {
                let mut stat = std::mem::MaybeUninit::uninit();
                let result = native_policy::cvt(unsafe {
                    libc::fstatat(parent, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
                });
                match result {
                    Ok(_) => Ok(Some(unsafe { stat.assume_init() })),
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
                    Err(error) => Err(error),
                }
            })?;
            if observed.as_ref().is_some_and(|s| s.st_mode & libc::S_IFMT != libc::S_IFDIR) {
                return Err(ReadFault::CheckedFormat {
                    reason: "archive-relative parent is a symlink or nondirectory",
                }
                .into());
            }
            if observed.is_none() {
                mkdir(ledger, Some(parent), name, cancel)?;
            }
            ledger.with_state(|s| s.acquire_fds(1))?;
            let opened = operation(ledger, ReadIoOperation::Open, cancel, || {
                native_policy::cvt(unsafe {
                    libc::openat(
                        parent,
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })
            });
            let next = match opened {
                Ok(fd) => unsafe { File::from_raw_fd(fd) },
                Err(error) => {
                    ledger.with_state(|s| s.retire_fd(true));
                    return Err(error.into());
                }
            };
            let checked = operation(ledger, ReadIoOperation::Stat, cancel, || native_policy::stat(next.as_raw_fd()));
            let validation = checked.and_then(|s| {
                if s.st_mode & libc::S_IFMT != libc::S_IFDIR
                    || observed.as_ref().is_some_and(|before| s.st_dev != before.st_dev || s.st_ino != before.st_ino)
                {
                    Err(ReadFault::CheckedFormat { reason: "archive-relative parent identity changed" })
                } else {
                    Ok(())
                }
            });
            if let Err(error) = validation {
                let cleanup = close(ledger, next, false, RunCategory::PathSteps, false);
                return Err(match cleanup {
                    Ok(()) => error.into(),
                    Err(cleanup) => ZipReadError::from(error).merge_cleanup_only(cleanup),
                });
            }
            let old = file.replace(next).unwrap();
            close(ledger, old, false, RunCategory::PathSteps, true)?;
            path[end] = b'/';
            component = end + 1;
        }
        let final_stat = operation(ledger, ReadIoOperation::Stat, cancel, || {
            native_policy::stat(file.as_ref().unwrap().as_raw_fd())
        })?;
        if final_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(ReadFault::InvalidPlan.into());
        }
        let parent_end = component - 1;
        path[parent_end] = 0;
        Ok((
            path.into_owned(),
            parent_end,
            FileIdentity { dev: final_stat.st_dev as u64, ino: final_stat.st_ino as u64 },
        ))
    })();
    match result {
        Ok((path, parent_end, identity)) => Ok(HeldParent { file: file.take().unwrap(), path, parent_end, identity }),
        Err(error) => {
            ledger.with_state(|s| s.poisoned = true);
            let closed = match file.take() {
                Some(file) => close(ledger, file, false, RunCategory::PathSteps, false),
                None => {
                    ledger.with_state(|s| s.retire_fd(true));
                    Ok(())
                }
            };
            Err(match closed {
                Ok(()) => error,
                Err(cleanup) => error.merge_cleanup_only(cleanup),
            })
        }
    }
}
