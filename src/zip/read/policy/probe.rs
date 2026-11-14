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

//! Empty ordinary creation in the actual parent; no payload enters this file.
use super::*;
use crate::zip::read::shared::{LedgerAccess, LedgerView};
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

pub(in crate::zip::read) struct ChildPolicy {
    pub(in crate::zip::read) uid: libc::uid_t,
    pub(in crate::zip::read) gid: libc::gid_t,
    pub(in crate::zip::read) mode: u32,
    pub(in crate::zip::read) acl: Option<OwnedMetadata<u8>>,
}
impl ChildPolicy {
    pub(in crate::zip::read) fn finish(self, ledger: &impl LedgerAccess) -> Result<(), ReadFault> {
        self.acl.map(|acl| acl.finish(ledger).map_err(|(_, fault)| fault)).transpose().map(|_| ())
    }
}
struct Probe<'a> {
    ledger: LedgerView<'a>,
    parent: &'a File,
    file: Option<File>,
    name: [u8; 41],
    identity: Option<CanonicalIdentity>,
    parent_identity: CanonicalIdentity,
    named: bool,
    unknown: bool,
}
fn mismatch() -> ReadFault {
    ReadFault::CheckedFormat { reason: "empty output policy probe changed" }
}
fn statat(fd: i32, name: &CStr) -> std::io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    native_policy::cvt(unsafe { libc::fstatat(fd, name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(unsafe { stat.assume_init() })
}
fn operation<T>(
    ledger: &impl LedgerAccess,
    op: ReadIoOperation,
    cancel: &Cancellation,
    mut call: impl FnMut() -> std::io::Result<T>,
) -> Result<T, ReadFault> {
    io::operation(ledger, false, RunCategory::PolicyProbeOperations, IoStage::Output, op, Some(cancel), || {
        spool::syscall(op, -1, &mut call)
    })
}
impl Probe<'_> {
    fn leaf(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.name).expect("generated bounded leaf")
    }
    #[allow(clippy::result_large_err)]
    fn close(&mut self, normal: bool) -> ZipReadResult<()> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        let fd = file.into_raw_fd();
        let closed = io::retire_in(
            &self.ledger,
            false,
            OwnedObject::ProbeFile,
            Some(RunCategory::PolicyProbeOperations),
            normal,
            || {
                spool::syscall(ReadIoOperation::Close, fd, || {
                    native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                })
            },
        );
        let mut result = closed.admission.map(ZipReadError::from);
        if let Some(fault) = closed.fault {
            let mut report = ObjectCleanupReport::new(OwnedObject::ProbeFile);
            report.push(fault);
            result = Some(match result {
                Some(error) => error.merge_cleanup(report),
                None => report.into(),
            });
        }
        result.map_or(Ok(()), Err)
    }
    #[allow(clippy::result_large_err)]
    fn finish(&mut self, cancel: &Cancellation) -> ZipReadResult<()> {
        let named =
            operation(&self.ledger, ReadIoOperation::Stat, cancel, || statat(self.parent.as_raw_fd(), self.leaf()))?;
        if Some(CanonicalIdentity::of(&named)) != self.identity || named.st_nlink != 1 || named.st_size != 0 {
            return Err(mismatch().into());
        }
        self.close(true)?;
        // Mutation is one shot: even EINTR is an ambiguous terminal observation.
        self.ledger.with_state(|s| s.charge_category(RunCategory::PolicyProbeOperations, 1))?;
        io::canceled(Some(cancel))?;
        self.ledger.with_state(|s| s.attempt(false))?;
        spool::syscall(ReadIoOperation::Unlink, self.parent.as_raw_fd(), || {
            native_policy::cvt(unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.leaf().as_ptr(), 0) })
        })
        .map_err(|error| ReadFault::Io {
            stage: IoStage::Output,
            operation: ReadIoOperation::Unlink,
            offset: 0,
            error,
        })?;
        self.named = false;
        let absent = operation(&self.ledger, ReadIoOperation::Stat, cancel, || {
            match statat(self.parent.as_raw_fd(), self.leaf()) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(true),
                Ok(_) => Ok(false),
                Err(error) => Err(error),
            }
        })?;
        if !absent {
            return Err(mismatch().into());
        }
        Ok(())
    }
    fn cleanup(&mut self) -> ObjectCleanupReport {
        let mut report = ObjectCleanupReport::new(OwnedObject::ProbeFile);
        let ledger = self.ledger;
        let emergency = |op, call: &mut dyn FnMut() -> std::io::Result<()>| -> Result<(), CleanupCause> {
            ledger
                .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
                .map_err(|_| CleanupCause::Policy("probe cleanup allowance exhausted"))?;
            spool::syscall(op, -1, call).map_err(CleanupCause::Io)
        };
        if self.named || self.unknown {
            let cleanup = (|| -> Result<(), (ReadIoOperation, CleanupCause)> {
                if self.identity.is_none() && self.file.is_some() {
                    emergency(ReadIoOperation::Stat, &mut || {
                        let s = native_policy::stat(self.file.as_ref().unwrap().as_raw_fd())?;
                        if s.st_mode & libc::S_IFMT == libc::S_IFREG && s.st_nlink == 1 && s.st_size == 0 {
                            self.identity = Some(CanonicalIdentity::of(&s));
                        }
                        Ok(())
                    })
                    .map_err(|e| (ReadIoOperation::Stat, e))?;
                }
                let mut absent = false;
                let mut same = false;
                emergency(ReadIoOperation::Stat, &mut || {
                    match statat(self.parent.as_raw_fd(), self.leaf()) {
                        Ok(s) => {
                            same = Some(CanonicalIdentity::of(&s)) == self.identity && s.st_nlink == 1 && s.st_size == 0
                        }
                        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => absent = true,
                        Err(e) => return Err(e),
                    }
                    Ok(())
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                if absent {
                    self.named = false;
                    self.unknown = false;
                    return Ok(());
                }
                if !same {
                    return Err((
                        ReadIoOperation::Stat,
                        CleanupCause::Policy("unobserved or replaced probe name preserved"),
                    ));
                }
                emergency(ReadIoOperation::Unlink, &mut || {
                    native_policy::cvt(unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.leaf().as_ptr(), 0) })
                        .map(|_| ())
                })
                .map_err(|e| (ReadIoOperation::Unlink, e))?;
                self.named = false;
                self.unknown = false;
                emergency(ReadIoOperation::Stat, &mut || match statat(self.parent.as_raw_fd(), self.leaf()) {
                    Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(()),
                    Ok(_) => Err(std::io::ErrorKind::AlreadyExists.into()),
                    Err(e) => Err(e),
                })
                .map_err(|e| (ReadIoOperation::Stat, e))?;
                Ok(())
            })();
            if let Err((operation, cause)) = cleanup {
                report.push(CleanupFault {
                    object: OwnedObject::ProbeFile,
                    operation,
                    offset: None,
                    close: CloseDisposition::NotApplicable,
                    cause,
                });
            }
        }
        if let Some(file) = self.file.take() {
            let fd = file.into_raw_fd();
            if let Some(fault) = io::retire_in(
                &self.ledger,
                false,
                OwnedObject::ProbeFile,
                Some(RunCategory::PolicyProbeOperations),
                false,
                || {
                    spool::syscall(ReadIoOperation::Close, fd, || {
                        native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
                    })
                },
            )
            .fault
            {
                report.push(fault);
            }
        }
        report
    }
}
impl Drop for Probe<'_> {
    fn drop(&mut self) {
        if self.file.is_some() || self.named || self.unknown {
            self.ledger.with_state(|s| s.poisoned = true);
            let _ = self.cleanup();
        }
    }
}
#[allow(clippy::result_large_err, clippy::unnecessary_cast)] // Fixed inline evidence; native mode_t is u16 on Darwin and u32 on Linux.
pub(in crate::zip::read) fn probe(
    ledger: &impl LedgerAccess,
    parent: &File,
    uid: libc::uid_t,
    tilde: bool,
    scratch: &mut [u8],
    cancel: &Cancellation,
) -> ZipReadResult<(ParentPolicy, ChildPolicy)> {
    let mut group = io::CreationGroup::new(ledger, false, IoStage::Output, cancel)?;
    group.ensure_next()?;
    let snapshot =
        ParentPolicy::capture(ledger, parent.as_raw_fd(), RunCategory::PolicyProbeOperations, scratch, cancel)?;
    // Snapshot already validates the held parent; reuse its identity without an
    // additional stat by obtaining the captured immutable copy.
    let mut probe = Probe {
        ledger: ledger.view(),
        parent,
        file: None,
        name: [0; 41],
        identity: None,
        parent_identity: snapshot.identity(),
        named: false,
        unknown: false,
    };
    let result = (|| -> ZipReadResult<ChildPolicy> {
        loop {
            group.ensure_next()?;
            operation(ledger, ReadIoOperation::Read, cancel, || spool::random_leaf(&mut probe.name, tilde))?;
            ledger.with_state(|s| s.acquire_fds(1))?;
            // Charge the semantic creation operation separately; group owns the
            // ordinary I/O attempt and finite collision policy.
            let admitted = ledger.with_state(|s| s.charge_category(RunCategory::PolicyProbeOperations, 1));
            let acquired = admitted.and_then(|_| {
                group.create_once(cancel, || {
                    spool::syscall(ReadIoOperation::Create, parent.as_raw_fd(), || {
                        native_policy::cvt(unsafe {
                            libc::openat(
                                parent.as_raw_fd(),
                                probe.leaf().as_ptr(),
                                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                                0o666,
                            )
                        })
                    })
                })
            });
            match acquired {
                Ok(fd) => {
                    probe.file = Some(unsafe { File::from_raw_fd(fd) });
                    probe.named = true;
                    break;
                }
                Err(ReadFault::Io { error, .. }) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    ledger.with_state(|s| s.retire_fd(true));
                    continue;
                }
                Err(error) => {
                    ledger.with_state(|s| s.retire_fd(true));
                    probe.unknown = matches!(error, ReadFault::Io { .. });
                    return Err(error.into());
                }
            }
        }
        let fd = probe.file.as_ref().unwrap().as_raw_fd();
        let before = operation(ledger, ReadIoOperation::Stat, cancel, || native_policy::stat(fd))?;
        probe.identity = Some(CanonicalIdentity::of(&before));
        if before.st_mode & libc::S_IFMT != libc::S_IFREG
            || before.st_uid != uid
            || before.st_size != 0
            || before.st_nlink != 1
            || CanonicalIdentity::of(&before).dev != probe.parent_identity.dev
        {
            return Err(mismatch().into());
        }
        let acl = security::retained(ledger.view(), fd, false, RunCategory::PolicyProbeOperations, scratch, cancel)?;
        let middle = operation(ledger, ReadIoOperation::Stat, cancel, || native_policy::stat(fd))?;
        let same = operation(ledger, ReadIoOperation::ReadAcl, cancel, || {
            native_policy::read_acl(fd, false, scratch).map(|value| value == acl.as_deref())
        })?;
        let after = operation(ledger, ReadIoOperation::Stat, cancel, || native_policy::stat(fd))?;
        if !security::same_snapshot(&before, &middle) || !security::same_snapshot(&middle, &after) || !same {
            return Err(mismatch().into());
        }
        probe.finish(cancel)?;
        snapshot.matches(ledger, parent.as_raw_fd(), RunCategory::PolicyProbeOperations, scratch, cancel)?;
        Ok(ChildPolicy {
            uid,
            gid: before.st_gid,
            mode: before.st_mode as u32 & 0o777,
            acl: acl.map(MetadataLease::into_owned),
        })
    })();
    match result {
        Ok(child) => Ok((snapshot, child)),
        Err(error) => {
            ledger.with_state(|s| s.poisoned = true);
            let report = probe.cleanup();
            let error = if report.is_empty() { error } else { error.merge_cleanup(report) };
            // We retain unresolved namespace flags only as accounted error
            // evidence, never issue a second cleanup pass from Drop.
            probe.named = false;
            probe.unknown = false;
            let finished = snapshot.finish(ledger);
            debug_assert!(finished.is_ok(), "same-owner parent policy teardown");
            Err(error)
        }
    }
}
