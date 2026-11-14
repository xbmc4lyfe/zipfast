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

//! Atomic private directory birth and explicit empty-directory retirement.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use parent::HeldParent;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

#[derive(Debug)]
pub(in crate::zip::read) struct DirectoryFailure {
    pub(in crate::zip::read) error: ZipReadError,
    pub(in crate::zip::read) parent_valid: bool,
}
pub(in crate::zip::read) struct PrivateDirectory {
    pub(in crate::zip::read) file: Option<File>,
    pub(in crate::zip::read) identity: Option<FileIdentity>,
    pub(in crate::zip::read) name: [u8; 41],
    named: bool,
    unknown: bool,
    uid: libc::uid_t,
    cleanup_open_attempted: bool,
    named_verified: bool,
    reopened: bool,
    cleanup_name_verified: bool,
}
fn policy() -> ReadFault {
    ReadFault::CheckedFormat { reason: "output private directory changed" }
}
fn statat(parent: &HeldParent, name: &CStr) -> std::io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    native_policy::cvt(unsafe {
        libc::fstatat(parent.file.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
    })?;
    Ok(unsafe { stat.assume_init() })
}
#[allow(clippy::unnecessary_cast)]
fn identity(s: &libc::stat) -> FileIdentity {
    FileIdentity { dev: s.st_dev as u64, ino: s.st_ino as u64 }
}
fn operation<T>(
    ledger: &impl LedgerAccess,
    encrypted: bool,
    op: ReadIoOperation,
    cancel: &Cancellation,
    mut call: impl FnMut() -> std::io::Result<T>,
) -> Result<T, ReadFault> {
    io::operation(ledger, encrypted, RunCategory::OutputDirectoryOperations, IoStage::Output, op, Some(cancel), || {
        spool::syscall(op, -1, &mut call)
    })
}
impl PrivateDirectory {
    pub(in crate::zip::read) fn leaf(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.name).expect("generated private directory leaf")
    }
    fn matches(&self, s: &libc::stat) -> bool {
        s.st_mode & libc::S_IFMT == libc::S_IFDIR
            && s.st_mode & 0o777 == 0o700
            && s.st_uid == self.uid
            && self.identity == Some(identity(s))
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn create(
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
        uid: libc::uid_t,
        tilde: bool,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<Self, DirectoryFailure> {
        let mut directory = Self {
            file: None,
            identity: None,
            name: [0; 41],
            named: false,
            unknown: false,
            uid,
            cleanup_open_attempted: false,
            named_verified: false,
            reopened: false,
            cleanup_name_verified: false,
        };
        let result = (|| -> Result<(), ReadFault> {
            let mut group = io::CreationGroup::new(ledger, encrypted, IoStage::Output, cancel)?;
            group.ensure_next()?;
            loop {
                group.ensure_next()?;
                operation(ledger, encrypted, ReadIoOperation::Read, cancel, || {
                    spool::random_leaf(&mut directory.name, tilde)
                })?;
                native_policy::check_atomic_path(parent.path(), directory.leaf()).map_err(|error| ReadFault::Io {
                    stage: IoStage::Output,
                    operation: ReadIoOperation::Directory,
                    offset: 0,
                    error,
                })?;
                ledger.with_state(|s| s.charge_category(RunCategory::OutputDirectoryOperations, 1))?;
                match group.create_once(cancel, || {
                    spool::syscall(ReadIoOperation::Directory, parent.file.as_raw_fd(), || {
                        native_policy::atomic_directory(parent.file.as_raw_fd(), parent.path(), directory.leaf())
                    })
                }) {
                    Ok(()) => {
                        directory.named = true;
                        break;
                    }
                    Err(ReadFault::Io { error, .. }) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        directory.unknown = matches!(error, ReadFault::Io { .. });
                        return Err(error);
                    }
                }
            }
            #[cfg(target_os = "macos")]
            {
                let mut before =
                    operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || statat(parent, directory.leaf()))?;
                directory.identity = Some(identity(&before));
                if before.st_mode & libc::S_IFMT != libc::S_IFDIR
                    || before.st_uid != uid
                    || before.st_mode & 0o077 != 0
                    || identity(&before).dev != parent.identity.dev
                {
                    return Err(policy());
                }
                if before.st_mode & 0o777 != 0o700 {
                    // No descriptor can yet be opened under an owner-masking umask.
                    // The nofollow mutation and full identity recheck occur while
                    // this newly born directory is empty and has no inherited ACL.
                    operation(ledger, encrypted, ReadIoOperation::DescriptorMode, cancel, || {
                        native_policy::cvt(unsafe {
                            libc::fchmodat(
                                parent.file.as_raw_fd(),
                                directory.leaf().as_ptr(),
                                0o700,
                                libc::AT_SYMLINK_NOFOLLOW,
                            )
                        })
                        .map(|_| ())
                    })?;
                    before = operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || {
                        statat(parent, directory.leaf())
                    })?;
                    if !directory.matches(&before) {
                        return Err(policy());
                    }
                }
                ledger.with_state(|s| s.acquire_fds(1))?;
                let acquired = operation(ledger, encrypted, ReadIoOperation::Open, cancel, || {
                    native_policy::cvt(unsafe {
                        libc::openat(
                            parent.file.as_raw_fd(),
                            directory.leaf().as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    })
                });
                match acquired {
                    Ok(fd) => directory.file = Some(unsafe { File::from_raw_fd(fd) }),
                    Err(error) => {
                        ledger.with_state(|s| s.retire_fd(true));
                        return Err(error);
                    }
                }
                let held = operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || {
                    native_policy::stat(directory.file.as_ref().unwrap().as_raw_fd())
                })?;
                if !directory.matches(&held) {
                    return Err(policy());
                }
                let private = operation(ledger, encrypted, ReadIoOperation::ReadAcl, cancel, || {
                    native_policy::private_acl(directory.file.as_ref().unwrap().as_raw_fd(), scratch)
                })?;
                if !private {
                    return Err(policy());
                }
            }
            #[cfg(target_os = "linux")]
            {
                let _ = scratch;
                ledger.with_state(|s| s.acquire_fds(1))?;
                let opened = operation(ledger, encrypted, ReadIoOperation::Open, cancel, || {
                    native_policy::cvt(unsafe {
                        libc::openat(
                            parent.file.as_raw_fd(),
                            directory.leaf().as_ptr(),
                            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    })
                });
                match opened {
                    Ok(fd) => directory.file = Some(unsafe { File::from_raw_fd(fd) }),
                    Err(error) => {
                        ledger.with_state(|s| s.retire_fd(true));
                        return Err(error);
                    }
                }
                let fd = directory.file.as_ref().unwrap().as_raw_fd();
                let before = operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || native_policy::stat(fd))?;
                directory.identity = Some(identity(&before));
                if before.st_mode & libc::S_IFMT != libc::S_IFDIR
                    || before.st_uid != uid
                    || before.st_mode & 0o077 != 0
                    || identity(&before).dev != parent.identity.dev
                {
                    return Err(policy());
                }
                if before.st_mode & 0o777 != 0o700 {
                    let mut spelling = [0u8; 64];
                    let procfd = native_policy::procfd_path(fd, &mut spelling).map_err(|error| ReadFault::Io {
                        stage: IoStage::Output,
                        operation: ReadIoOperation::DescriptorMode,
                        offset: 0,
                        error,
                    })?;
                    let observed = operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || {
                        native_policy::path_stat(procfd)
                    })?;
                    if identity(&observed) != identity(&before)
                        || observed.st_mode & libc::S_IFMT != libc::S_IFDIR
                        || observed.st_uid != uid
                    {
                        return Err(policy());
                    }
                    operation(ledger, encrypted, ReadIoOperation::DescriptorMode, cancel, || {
                        let result =
                            unsafe { libc::syscall(libc::SYS_fchmodat, libc::AT_FDCWD, procfd.as_ptr(), 0o700) };
                        if result < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
                    })?;
                    let restored =
                        operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || native_policy::stat(fd))?;
                    if !directory.matches(&restored) {
                        return Err(policy());
                    }
                }
            }
            let observed = operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || {
                let mut value = std::mem::MaybeUninit::uninit();
                native_policy::cvt(unsafe { libc::stat(parent.path().as_ptr(), value.as_mut_ptr()) })?;
                Ok(unsafe { value.assume_init() })
            })?;
            if identity(&observed) != parent.identity || observed.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(policy());
            }
            let named =
                operation(ledger, encrypted, ReadIoOperation::Stat, cancel, || statat(parent, directory.leaf()))?;
            if !directory.matches(&named) {
                return Err(policy());
            }
            directory.named_verified = true;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(directory),
            Err(error) => {
                ledger.with_state(|s| s.poisoned = true);
                let mut error = ZipReadError::from(error);
                let parent_valid = match parent.verify_cleanup_name(ledger) {
                    Ok(()) => true,
                    Err(fault) => {
                        let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                        report.push(fault);
                        error = error.merge_cleanup(report);
                        false
                    }
                };
                let mut report = if parent_valid {
                    directory.cleanup(ledger, parent, encrypted)
                } else {
                    directory.cleanup_blocked(ledger, encrypted)
                };
                if !parent_valid && (directory.named || directory.unknown) {
                    report.push(CleanupFault {
                        object: OwnedObject::OutputPrivateDirectory,
                        operation: ReadIoOperation::Stat,
                        offset: None,
                        close: CloseDisposition::NotApplicable,
                        cause: CleanupCause::Policy(
                            "full-path private directory candidate remains unobserved after parent change",
                        ),
                    });
                }
                if !report.is_empty() {
                    error = error.merge_cleanup(report);
                }
                Err(DirectoryFailure { error, parent_valid })
            }
        }
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn reopen_normal(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> ZipReadResult<()> {
        if self.file.is_some() || !self.named || self.identity.is_none() {
            return Err(ReadFault::InvalidPlan.into());
        }
        ledger.with_state(|s| s.acquire_fds(1))?;
        let opened = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Open,
            Some(cancel),
            || {
                spool::syscall(ReadIoOperation::Open, parent.file.as_raw_fd(), || {
                    native_policy::cvt(unsafe {
                        libc::openat(
                            parent.file.as_raw_fd(),
                            self.leaf().as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    })
                })
            },
        );
        match opened {
            Ok(fd) => {
                self.file = Some(unsafe { File::from_raw_fd(fd) });
                self.reopened = true;
            }
            Err(error) => {
                ledger.with_state(|s| s.retire_fd(true));
                return Err(error.into());
            }
        }
        let held = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || {
                spool::syscall(ReadIoOperation::Stat, -1, || {
                    native_policy::stat(self.file.as_ref().unwrap().as_raw_fd())
                })
            },
        )?;
        if !self.matches(&held) {
            return Err(policy().into());
        }
        #[cfg(target_os = "macos")]
        {
            let private = io::operation(
                ledger,
                encrypted,
                RunCategory::StageFinalization,
                IoStage::Output,
                ReadIoOperation::ReadAcl,
                Some(cancel),
                || {
                    spool::syscall(ReadIoOperation::ReadAcl, -1, || {
                        native_policy::private_acl(self.file.as_ref().unwrap().as_raw_fd(), scratch)
                    })
                },
            )?;
            if !private {
                return Err(policy().into());
            }
        }
        #[cfg(target_os = "linux")]
        let _ = scratch;
        let named = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || spool::syscall(ReadIoOperation::Stat, -1, || statat(parent, self.leaf())),
        )?;
        if !self.matches(&named) {
            return Err(policy().into());
        }
        self.named_verified = true;
        Ok(())
    }
    /// At most one cleanup acquisition after poison; no allocation, payload,
    /// canonicalization or publication is reachable from this capability.
    pub(in crate::zip::read) fn reopen_cleanup(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
    ) -> Result<(), CleanupFault> {
        let fault = |operation, cause| CleanupFault {
            object: OwnedObject::OutputPrivateDirectory,
            operation,
            offset: None,
            close: CloseDisposition::NotApplicable,
            cause,
        };
        if self.file.is_some() && self.named_verified {
            return Ok(());
        }
        if self.cleanup_open_attempted || !self.named || self.identity.is_none() || !ledger.with_state(|s| s.poisoned) {
            return Err(fault(
                ReadIoOperation::Open,
                CleanupCause::Policy("private directory cleanup reopen unavailable"),
            ));
        }
        self.cleanup_open_attempted = true;
        let fd = if let Some(file) = self.file.as_ref() {
            file.as_raw_fd()
        } else {
            ledger
                .with_state(|s| s.acquire_cleanup_fd())
                .map_err(|error| fault(ReadIoOperation::Open, CleanupCause::Admission(error)))?;
            let opened = spool::syscall(ReadIoOperation::Open, parent.file.as_raw_fd(), || {
                native_policy::cvt(unsafe {
                    libc::openat(
                        parent.file.as_raw_fd(),
                        self.leaf().as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })
            });
            let fd = match opened {
                Ok(fd) => fd,
                Err(error) => {
                    ledger.with_state(|s| s.retire_fd(true));
                    return Err(fault(ReadIoOperation::Open, CleanupCause::Io(error)));
                }
            };
            self.file = Some(unsafe { File::from_raw_fd(fd) });
            self.reopened = true;
            fd
        };
        let emergency = |operation, call: &mut dyn FnMut() -> std::io::Result<()>| -> Result<(), CleanupFault> {
            ledger
                .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
                .map_err(|error| fault(operation, CleanupCause::Admission(error)))?;
            spool::syscall(operation, fd, call).map_err(|error| fault(operation, CleanupCause::Io(error)))
        };
        let mut held = None;
        emergency(ReadIoOperation::Stat, &mut || {
            held = Some(native_policy::stat(fd)?);
            Ok(())
        })?;
        if !self.matches(&held.unwrap()) {
            return Err(fault(
                ReadIoOperation::Stat,
                CleanupCause::Policy("reopened private directory identity changed"),
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let mut empty = [0; 56];
            let mut private = false;
            emergency(ReadIoOperation::ReadAcl, &mut || {
                private = native_policy::private_acl(fd, &mut empty)?;
                Ok(())
            })?;
            if !private {
                return Err(fault(
                    ReadIoOperation::ReadAcl,
                    CleanupCause::Policy("reopened private directory ACL changed"),
                ));
            }
        }
        let mut named = None;
        emergency(ReadIoOperation::Stat, &mut || {
            named = Some(statat(parent, self.leaf())?);
            Ok(())
        })?;
        if !self.matches(&named.unwrap()) {
            return Err(fault(ReadIoOperation::Stat, CleanupCause::Policy("reopened private directory name changed")));
        }
        self.named_verified = true;
        self.cleanup_name_verified = true;
        Ok(())
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn close_before_payload(
        &mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        self.named_verified = false;
        self.close_normal(ledger, encrypted, RunCategory::OutputDirectoryOperations)
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn close_final(
        &mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        if !self.reopened || !self.named_verified {
            return Err(ReadFault::InvalidPlan.into());
        }
        self.close_normal(ledger, encrypted, RunCategory::StageFinalization)
    }
    #[allow(clippy::result_large_err)]
    fn close_normal(
        &mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        category: RunCategory,
    ) -> ZipReadResult<()> {
        let Some(file) = self.file.take() else {
            return Err(ReadFault::InvalidPlan.into());
        };
        let fd = file.into_raw_fd();
        let closed =
            io::retire_in(ledger, encrypted, OwnedObject::OutputPrivateDirectory, Some(category), true, || {
                spool::syscall(ReadIoOperation::Close, fd, || {
                    native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                })
            });
        let mut error = closed.admission.map(ZipReadError::from);
        if let Some(fault) = closed.fault {
            let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
            report.push(fault);
            error = Some(match error {
                Some(error) => error.merge_cleanup(report),
                None => report.into(),
            });
        }
        error.map_or(Ok(()), Err)
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn remove_empty_normal(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
        cancel: &Cancellation,
    ) -> ZipReadResult<()> {
        if self.file.is_some() || !self.named_verified || !self.named {
            return Err(ReadFault::InvalidPlan.into());
        }
        ledger.with_state(|s| s.charge_category(RunCategory::StageFinalization, 1))?;
        io::canceled(Some(cancel))?;
        ledger.with_state(|s| s.attempt(encrypted))?;
        spool::syscall(ReadIoOperation::Directory, parent.file.as_raw_fd(), || {
            native_policy::cvt(unsafe {
                libc::unlinkat(parent.file.as_raw_fd(), self.leaf().as_ptr(), libc::AT_REMOVEDIR)
            })
        })
        .map_err(|error| ReadFault::Io {
            stage: IoStage::Output,
            operation: ReadIoOperation::Directory,
            offset: 0,
            error,
        })?;
        self.named = false;
        self.unknown = false;
        let absent = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || {
                spool::syscall(ReadIoOperation::Stat, -1, || match statat(parent, self.leaf()) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(true),
                    Ok(_) => Ok(false),
                    Err(error) => Err(error),
                })
            },
        )?;
        if !absent {
            return Err(policy().into());
        }
        Ok(())
    }
    pub(in crate::zip::read) fn cleanup(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
    ) -> ObjectCleanupReport {
        let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
        let emergency = |call: &mut dyn FnMut() -> std::io::Result<()>| -> Result<(), CleanupCause> {
            ledger
                .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
                .map_err(|_| CleanupCause::Policy("private directory cleanup allowance exhausted"))?;
            call().map_err(CleanupCause::Io)
        };
        if self.named || self.unknown {
            let removed = (|| -> Result<(), (ReadIoOperation, CleanupCause)> {
                let mut absent = false;
                let mut same = self.cleanup_name_verified;
                if !self.cleanup_name_verified {
                    emergency(&mut || {
                        spool::syscall(ReadIoOperation::Stat, parent.file.as_raw_fd(), || {
                            match statat(parent, self.leaf()) {
                                Ok(s) => {
                                    same = self.identity == Some(identity(&s))
                                        && s.st_mode & libc::S_IFMT == libc::S_IFDIR
                                        && s.st_uid == self.uid
                                }
                                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => absent = true,
                                Err(e) => return Err(e),
                            }
                            Ok(())
                        })
                    })
                    .map_err(|e| (ReadIoOperation::Stat, e))?;
                }
                if absent {
                    self.named = false;
                    self.unknown = false;
                    return Ok(());
                }
                if !same {
                    return Err((
                        ReadIoOperation::Stat,
                        CleanupCause::Policy("unobserved or replaced private directory preserved"),
                    ));
                }
                emergency(&mut || {
                    spool::syscall(ReadIoOperation::Directory, parent.file.as_raw_fd(), || {
                        native_policy::cvt(unsafe {
                            libc::unlinkat(parent.file.as_raw_fd(), self.leaf().as_ptr(), libc::AT_REMOVEDIR)
                        })
                        .map(|_| ())
                    })
                })
                .map_err(|e| (ReadIoOperation::Directory, e))?;
                self.named = false;
                self.unknown = false;
                emergency(&mut || {
                    spool::syscall(ReadIoOperation::Stat, parent.file.as_raw_fd(), || {
                        match statat(parent, self.leaf()) {
                            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                            Ok(_) => Err(std::io::ErrorKind::AlreadyExists.into()),
                            Err(e) => Err(e),
                        }
                    })
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                Ok(())
            })();
            if let Err((operation, cause)) = removed {
                report.push(CleanupFault {
                    object: OwnedObject::OutputPrivateDirectory,
                    operation,
                    offset: None,
                    close: CloseDisposition::NotApplicable,
                    cause,
                });
            }
        }
        if let Some(fault) = self.close_cleanup(ledger, encrypted) {
            report.push(fault);
        }
        if !report.is_empty() {
            ledger.with_state(|s| s.poisoned = true);
        }
        report
    }
    fn close_cleanup(&mut self, ledger: &impl LedgerAccess, encrypted: bool) -> Option<CleanupFault> {
        let file = self.file.take()?;
        let fd = file.into_raw_fd();
        io::retire_in(
            ledger,
            encrypted,
            OwnedObject::OutputPrivateDirectory,
            Some(if self.reopened { RunCategory::StageFinalization } else { RunCategory::OutputDirectoryOperations }),
            false,
            || {
                spool::syscall(ReadIoOperation::Close, fd, || {
                    native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                })
            },
        )
        .fault
    }
    pub(in crate::zip::read) fn cleanup_blocked(
        &mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
    ) -> ObjectCleanupReport {
        let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
        if let Some(fault) = self.close_cleanup(ledger, encrypted) {
            report.push(fault);
        }
        report
    }
    #[cfg(test)]
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn retire_empty(
        mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        let report = self.cleanup(ledger, parent, encrypted);
        if report.is_empty() { Ok(()) } else { Err(report.into()) }
    }
}
