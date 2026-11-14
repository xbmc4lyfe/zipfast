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

//! Empty atomic-private stage placement and bounded two-location retirement.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use directory::PrivateDirectory;
use parent::HeldParent;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, IntoRawFd};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Location {
    None,
    Outside,
    Inside,
    Unknown,
}
#[derive(Debug)]
pub(in crate::zip::read) struct PlacementFailure {
    pub(in crate::zip::read) error: ZipReadError,
    pub(in crate::zip::read) retired: bool,
    pub(in crate::zip::read) parent_valid: bool,
}
pub(in crate::zip::read) struct NamedFile {
    pub(in crate::zip::read) file: Option<File>,
    pub(in crate::zip::read) identity: Option<FileIdentity>,
    pub(in crate::zip::read) name: [u8; 41],
    location: Location,
    unknown_name: bool,
    fd_reserved: bool,
    close_resolved: bool,
    uid: libc::uid_t,
    bytes: u64,
}
fn policy() -> ReadFault {
    ReadFault::CheckedFormat { reason: "named private output stage changed" }
}
#[allow(clippy::unnecessary_cast)]
fn identity(stat: &libc::stat) -> FileIdentity {
    FileIdentity { dev: stat.st_dev as u64, ino: stat.st_ino as u64 }
}
fn statat(fd: i32, name: &CStr) -> std::io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    native_policy::cvt(unsafe { libc::fstatat(fd, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(unsafe { stat.assume_init() })
}
impl NamedFile {
    pub(in crate::zip::read) fn leaf(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.name).expect("generated private stage leaf")
    }
    fn owned(&self, stat: &libc::stat, links: libc::nlink_t) -> bool {
        self.identity == Some(identity(stat))
            && stat.st_mode & libc::S_IFMT == libc::S_IFREG
            && stat.st_uid == self.uid
            && stat.st_nlink == links
            && stat.st_size >= 0
            && stat.st_size as u64 <= self.bytes
    }
    #[allow(clippy::result_large_err, clippy::too_many_arguments, clippy::unnecessary_cast)] // Lexical borrowed phase inputs; no extra owner or target name copy.
    pub(in crate::zip::read) fn create_and_place(
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        directory: &PrivateDirectory,
        parent_policy: &policy::ParentPolicy,
        child: &policy::ChildPolicy,
        encrypted: bool,
        bytes: u64,
        tilde: bool,
        group: &mut io::CreationGroup<'_>,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<Self, PlacementFailure> {
        let mut stage = Self {
            file: None,
            identity: None,
            name: [0; 41],
            location: Location::None,
            unknown_name: false,
            fd_reserved: true,
            close_resolved: true,
            uid: child.uid,
            bytes,
        };
        let scope = spool::PrivateScope {
            encrypted,
            object: OwnedObject::Output,
            parent: OwnedObject::OutputParent,
            stage: IoStage::Output,
        };
        let result = (|| -> Result<(), ReadFault> {
            let file = spool::create_private_at(
                ledger,
                cancel,
                scope,
                group,
                spool::PrivateCreation {
                    parent: &parent.file,
                    path: parent.path(),
                    name: &mut stage.name,
                    tilde,
                    unknown: &mut stage.unknown_name,
                },
            )?;
            stage.file = Some(file);
            stage.location = Location::Outside;
            let mut captured = None;
            let established = spool::establish_private_file(
                ledger,
                cancel,
                scope,
                stage.file.as_ref().unwrap(),
                parent.identity.dev as libc::dev_t,
                child.uid,
                &mut captured,
            );
            stage.identity = captured.map(|id| FileIdentity { dev: id.dev as u64, ino: id.ino as u64 });
            let actual = established?;
            if actual.st_size != 0 || actual.st_gid != child.gid {
                return Err(policy());
            }
            parent_policy.matches_namespace(ledger, parent.file.as_raw_fd(), scratch, cancel)?;
            let outside = spool::namespace(ledger, cancel, scope, ReadIoOperation::Stat, || {
                statat(parent.file.as_raw_fd(), stage.leaf())
            })?;
            if !stage.owned(&outside, 1)
                || outside.st_size != 0
                || outside.st_gid != child.gid
                || outside.st_mode & 0o777 != 0o600
            {
                return Err(policy());
            }
            let dir = spool::namespace(ledger, cancel, scope, ReadIoOperation::Stat, || {
                statat(parent.file.as_raw_fd(), directory.leaf())
            })?;
            if directory.identity != Some(identity(&dir))
                || dir.st_mode & libc::S_IFMT != libc::S_IFDIR
                || dir.st_mode & 0o777 != 0o700
                || dir.st_uid != child.uid
            {
                return Err(policy());
            }
            let inside = directory.file.as_ref().ok_or(ReadFault::InvalidPlan)?.as_raw_fd();
            io::canceled(Some(cancel))?;
            ledger.with_state(|s| s.attempt(encrypted))?;
            // From entry to the actual mutation onward, either name is a
            // candidate until observations prove one owned location.
            stage.location = Location::Unknown;
            spool::syscall(ReadIoOperation::Publish, parent.file.as_raw_fd(), || {
                native_policy::cvt(unsafe {
                    libc::renameat(parent.file.as_raw_fd(), stage.leaf().as_ptr(), inside, stage.leaf().as_ptr())
                })
            })
            .map_err(|error| ReadFault::Io {
                stage: IoStage::Output,
                operation: ReadIoOperation::Publish,
                offset: 0,
                error,
            })?;
            stage.location = Location::Inside;
            let moved =
                spool::namespace(ledger, cancel, scope, ReadIoOperation::Stat, || statat(inside, stage.leaf()))?;
            if !stage.owned(&moved, 1)
                || moved.st_size != 0
                || moved.st_gid != child.gid
                || moved.st_mode & 0o777 != 0o600
            {
                return Err(policy());
            }
            let absent = spool::namespace(ledger, cancel, scope, ReadIoOperation::Stat, || {
                match statat(parent.file.as_raw_fd(), stage.leaf()) {
                    Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(true),
                    Ok(_) => Ok(false),
                    Err(error) => Err(error),
                }
            })?;
            if !absent {
                return Err(policy());
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(stage),
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
                let (retired, report) = if parent_valid {
                    stage.retire(ledger, parent, directory, encrypted)
                } else {
                    stage.retire_blocked(ledger, parent, directory, encrypted)
                };
                if !report.is_empty() {
                    error = error.merge_cleanup(report);
                }
                Err(PlacementFailure { retired, error, parent_valid })
            }
        }
    }
    #[allow(clippy::result_large_err)]
    pub(in crate::zip::read) fn close_for_publish(
        &mut self,
        ledger: &impl LedgerAccess,
        file: File,
        encrypted: bool,
    ) -> ZipReadResult<()> {
        let fd = file.into_raw_fd();
        let closed =
            io::retire_in(ledger, encrypted, OwnedObject::Output, Some(RunCategory::StageFinalization), true, || {
                spool::syscall(ReadIoOperation::Close, fd, || {
                    native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                })
            });
        self.close_resolved = closed.closed;
        self.fd_reserved = false;
        let mut error = closed.admission.map(ZipReadError::from);
        if let Some(fault) = closed.fault {
            let mut report = ObjectCleanupReport::new(OwnedObject::Output);
            report.push(fault);
            error = Some(match error {
                Some(error) => error.merge_cleanup(report),
                None => report.into(),
            });
        }
        error.map_or(Ok(()), Err)
    }
    pub(in crate::zip::read) fn published(&mut self) {
        debug_assert!(!self.fd_reserved && self.close_resolved && self.file.is_none());
        self.location = Location::None;
        self.unknown_name = false;
    }
    pub(in crate::zip::read) fn check_inside(
        &self,
        ledger: &impl LedgerAccess,
        directory: &PrivateDirectory,
        gid: libc::gid_t,
        encrypted: bool,
        cancel: &Cancellation,
    ) -> Result<(), ReadFault> {
        let fd = directory.file.as_ref().ok_or(ReadFault::InvalidPlan)?.as_raw_fd();
        let actual = io::operation(
            ledger,
            encrypted,
            RunCategory::StageFinalization,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || spool::syscall(ReadIoOperation::Stat, fd, || statat(fd, self.leaf())),
        )?;
        if !self.owned(&actual, 1) || actual.st_size as u64 != self.bytes || actual.st_gid != gid {
            return Err(policy());
        }
        Ok(())
    }
    pub(in crate::zip::read) fn retire(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        directory: &PrivateDirectory,
        encrypted: bool,
    ) -> (bool, ObjectCleanupReport) {
        self.retire_in(ledger, parent, directory, encrypted, true)
    }
    pub(in crate::zip::read) fn retire_blocked(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        directory: &PrivateDirectory,
        encrypted: bool,
    ) -> (bool, ObjectCleanupReport) {
        self.retire_in(ledger, parent, directory, encrypted, false)
    }
    fn retire_in(
        &mut self,
        ledger: &impl LedgerAccess,
        parent: &HeldParent,
        directory: &PrivateDirectory,
        encrypted: bool,
        allow_namespace: bool,
    ) -> (bool, ObjectCleanupReport) {
        let mut report = ObjectCleanupReport::new(OwnedObject::Output);
        let emergency = |op, call: &mut dyn FnMut() -> std::io::Result<()>| -> Result<(), CleanupCause> {
            ledger
                .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
                .map_err(|_| CleanupCause::Policy("output cleanup allowance exhausted"))?;
            spool::syscall(op, -1, call).map_err(CleanupCause::Io)
        };
        let mut unlinked = self.location == Location::None && !self.unknown_name;
        let cleanup = (|| -> Result<(), (ReadIoOperation, CleanupCause)> {
            if let Some(file) = self.file.as_ref() {
                let mut held = None;
                emergency(ReadIoOperation::Stat, &mut || {
                    held = Some(native_policy::stat(file.as_raw_fd())?);
                    Ok(())
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                let held = held.unwrap();
                if self.identity.is_none()
                    && held.st_mode & libc::S_IFMT == libc::S_IFREG
                    && held.st_uid == self.uid
                    && held.st_nlink == 1
                {
                    self.identity = Some(identity(&held));
                }
                if self.owned(&held, 0) {
                    unlinked = true;
                    self.location = Location::None;
                    self.unknown_name = false;
                    return Ok(());
                }
                if !self.owned(&held, 1) {
                    return Err((ReadIoOperation::Stat, CleanupCause::Policy("output held identity changed")));
                }
            }
            if !allow_namespace {
                return Err((
                    ReadIoOperation::Stat,
                    CleanupCause::Policy("output namespace retirement blocked by parent or directory proof"),
                ));
            }
            let mut matched = None;
            let mut present = false;
            let candidates = [
                (
                    self.location == Location::Outside || self.location == Location::Unknown || self.unknown_name,
                    Some(parent.file.as_raw_fd()),
                ),
                (
                    self.location == Location::Inside || self.location == Location::Unknown,
                    directory.file.as_ref().map(AsRawFd::as_raw_fd),
                ),
            ];
            for (needed, fd) in candidates {
                if !needed {
                    continue;
                }
                let fd = fd.ok_or((
                    ReadIoOperation::Open,
                    CleanupCause::Policy("private directory unavailable for output cleanup"),
                ))?;
                let mut actual = None;
                emergency(ReadIoOperation::Stat, &mut || {
                    match statat(fd, self.leaf()) {
                        Ok(stat) => actual = Some(stat),
                        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
                        Err(error) => return Err(error),
                    }
                    Ok(())
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                if let Some(actual) = actual {
                    present = true;
                    if !self.owned(&actual, 1) || matched.replace(fd).is_some() {
                        return Err((
                            ReadIoOperation::Stat,
                            CleanupCause::Policy("unobserved, linked or replaced stage name preserved"),
                        ));
                    }
                }
            }
            if let Some(fd) = matched {
                emergency(ReadIoOperation::Unlink, &mut || {
                    native_policy::cvt(unsafe { libc::unlinkat(fd, self.leaf().as_ptr(), 0) }).map(|_| ())
                })
                .map_err(|e| (ReadIoOperation::Unlink, e))?;
                let mut verified = false;
                emergency(ReadIoOperation::Stat, &mut || {
                    if let Some(file) = self.file.as_ref() {
                        verified = self.owned(&native_policy::stat(file.as_raw_fd())?, 0);
                    } else {
                        match statat(fd, self.leaf()) {
                            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => verified = true,
                            Ok(_) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                if !verified {
                    return Err((ReadIoOperation::Stat, CleanupCause::Policy("stage storage retirement unobserved")));
                }
                unlinked = true;
            } else if !present && self.file.is_none() && self.identity.is_none() {
                // An ambiguous creation with no returned FD is clear only once
                // its sole possible public name is observed absent.
                unlinked = true;
            } else if !unlinked {
                return Err((
                    ReadIoOperation::Stat,
                    CleanupCause::Policy("owned stage disappeared without unlink proof"),
                ));
            }
            self.location = Location::None;
            self.unknown_name = false;
            Ok(())
        })();
        if let Err((operation, cause)) = cleanup {
            report.push(CleanupFault {
                object: OwnedObject::Output,
                operation,
                offset: None,
                close: CloseDisposition::NotApplicable,
                cause,
            });
        }
        if let Some(file) = self.file.take() {
            let fd = file.into_raw_fd();
            let closed = io::retire_in(
                ledger,
                encrypted,
                OwnedObject::Output,
                Some(RunCategory::StageFinalization),
                false,
                || {
                    spool::syscall(ReadIoOperation::Close, fd, || {
                        native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                    })
                },
            );
            self.close_resolved = closed.closed;
            self.fd_reserved = false;
            if let Some(fault) = closed.fault {
                report.push(fault);
            }
        } else if self.fd_reserved {
            ledger.with_state(|s| s.retire_fd(true));
            self.fd_reserved = false;
        }
        let clear = unlinked && self.close_resolved;
        if !clear || !report.is_empty() {
            ledger.with_state(|s| s.poisoned = true);
        }
        (clear, report)
    }
}
