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

//! Exclusive owned ciphertext; no payload path/handle escapes this module.
use super::{
    shared::{LedgerAccess, LedgerIdentity, LedgerView},
    *,
};
use crate::extract::Cancellation;
#[cfg(unix)]
use std::{
    ffi::CStr,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
    },
};
#[cfg(unix)]
use std::{
    fs::File,
    io::{Seek, SeekFrom},
};
use std::{io::Read, path::Path};

fn fault(operation: ReadIoOperation, error: std::io::Error) -> ReadFault {
    ReadFault::Io { stage: IoStage::Ciphertext, operation, offset: 0, error }
}
#[cfg(unix)]
fn policy() -> ReadFault {
    ReadFault::UnsupportedIdentity
}

/// Repeated syscalls have independent attempt charges, without a long ledger borrow.
#[cfg(unix)]
fn namespace<T>(
    ledger: &impl LedgerAccess,
    cancel: &Cancellation,
    operation: ReadIoOperation,
    mut call: impl FnMut() -> std::io::Result<T>,
) -> Result<T, ReadFault> {
    let limit = ledger.with_state(|s| s.creation_policy(true).map(|p| p.1))?;
    let mut retries = 0;
    loop {
        io::canceled(Some(cancel))?;
        ledger.with_state(|s| s.attempt(true))?;
        match syscall(operation, -1, &mut call) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                retries += 1;
                budget::admit(ReadResource::InterruptedRetries, limit.into(), retries)?;
            }
            Err(e) => return Err(fault(operation, e)),
        }
    }
}
#[cfg(unix)]
fn cvt(n: libc::c_int) -> std::io::Result<libc::c_int> {
    if n == -1 { Err(std::io::Error::last_os_error()) } else { Ok(n) }
}
#[cfg(unix)]
#[derive(Clone, Copy)]
struct Identity {
    dev: libc::dev_t,
    ino: libc::ino_t,
}
#[cfg(unix)]
impl Identity {
    fn of(s: &libc::stat) -> Self {
        Self { dev: s.st_dev, ino: s.st_ino }
    }
    fn matches(self, s: &libc::stat) -> bool {
        self.dev == s.st_dev && self.ino == s.st_ino
    }
}
#[cfg(unix)]
fn stat(fd: &File) -> std::io::Result<libc::stat> {
    let mut s = std::mem::MaybeUninit::uninit();
    // SAFETY: valid borrowed descriptor and initialized output on success.
    syscall(ReadIoOperation::Stat, fd.as_raw_fd(), || cvt(unsafe { libc::fstat(fd.as_raw_fd(), s.as_mut_ptr()) }))?;
    Ok(unsafe { s.assume_init() })
}
#[cfg(unix)]
pub(super) fn trusted_dir(s: &libc::stat, uid: libc::uid_t) -> bool {
    s.st_mode & libc::S_IFMT == libc::S_IFDIR
        && (s.st_uid == uid || s.st_uid == 0)
        && (s.st_mode & 0o022 == 0 || s.st_mode & libc::S_ISVTX != 0)
}
#[cfg(unix)]
pub(super) fn trusted_file(s: &libc::stat, links: u64, uid: libc::uid_t) -> bool {
    s.st_mode & libc::S_IFMT == libc::S_IFREG
        && s.st_uid == uid
        && s.st_mode & 0o777 == 0o600
        && s.st_nlink as u64 == links
}

pub(super) struct FixedCiphertext<'a> {
    bytes: Vec<u8>,
    position: usize,
    ledger: LedgerView<'a>,
    capacity: u64,
}
impl Drop for FixedCiphertext<'_> {
    fn drop(&mut self) {
        self.ledger.with_state(|s| s.release_capacity(self.capacity));
    }
}
/// Single owner. Completed file owners expose neither Write nor a descriptor.
pub(super) enum OwnedCiphertext<'a> {
    Memory(FixedCiphertext<'a>),
    #[cfg(unix)]
    File(PrivateCiphertextFile<'a>),
}

#[cfg(unix)]
pub(super) struct PrivateCiphertextFile<'a> {
    file: Option<File>,
    ledger: LedgerView<'a>,
    len: u64,
    position: u64,
    #[cfg(unix)]
    identity: Identity,
    uid: libc::uid_t,
    reserved: u64,
}
impl<'a> OwnedCiphertext<'a> {
    #[allow(clippy::result_large_err)] // Inline terminal evidence is allocation independent.
    pub(super) fn copy(
        ledger: &'a impl LedgerAccess,
        directory: &ResolvedTempDirectory,
        source: &mut (impl Read + ?Sized),
        len: u64,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let threshold = ledger.with_state(|s| s.encrypted.limits.ciphertext_memory_bytes);
        let view = ledger.view();
        if len <= threshold {
            let capacity = usize::try_from(len).map_err(|_| ReadFault::CounterOverflow)?;
            let mut bytes = Vec::new();
            if capacity != 0 {
                ledger.with_state(|s| s.encrypted.allocation(len))?;
                if bytes.try_reserve_exact(capacity).is_err() {
                    ledger.with_state(|s| s.release_capacity(len));
                    return Err(ReadFault::Allocation { capacity }.into());
                }
                // The allocator's requested capacity, rather than initialized length, is charged.
                assert_eq!(bytes.capacity(), capacity);
                bytes.resize(capacity, 0);
            }
            let mut owned = Self::Memory(FixedCiphertext { bytes, position: 0, ledger: view, capacity: len });
            let result = match &mut owned {
                Self::Memory(m) => read_exact(view, source, &mut m.bytes, IoStage::Source, cancel),
                #[cfg(unix)]
                _ => unreachable!(),
            };
            return match result {
                Ok(()) => Ok(owned),
                Err(e) => Err(owned.finish_error(e.into())),
            };
        }
        if scratch.is_empty() || scratch.len() > io::WINDOW {
            return Err(ReadFault::InvalidPlan.into());
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            Err(ReadFault::UnsupportedIdentity.into())
        }
        #[cfg(unix)]
        {
            let mut file = PrivateCiphertextFile::create(view, directory, len, cancel)?;
            let copied = (|| -> Result<(), ReadFault> {
                let mut position = 0;
                while position < len {
                    let count = scratch.len().min((len - position).min(io::WINDOW as u64) as usize);
                    read_exact(view, source, &mut scratch[..count], IoStage::Source, cancel)?;
                    let mut written = 0;
                    while written < count {
                        written += io::write(
                            &view,
                            true,
                            &mut PayloadFile(file.file.as_mut().unwrap()),
                            IoStage::Ciphertext,
                            position + written as u64,
                            &scratch[written..count],
                            cancel,
                        )?;
                    }
                    position += count as u64;
                }
                file.check(cancel)?;
                file.rewind(cancel)
            })();
            match copied {
                Ok(()) => Ok(Self::File(file)),
                Err(e) => Err(Self::File(file).finish_error(e.into())),
            }
        }
    }
    pub(super) fn len(&self) -> u64 {
        match self {
            Self::Memory(m) => m.bytes.len() as u64,
            #[cfg(unix)]
            Self::File(f) => f.len,
        }
    }
    pub(super) fn read_chunk(&mut self, out: &mut [u8], cancel: &Cancellation) -> Result<usize, ReadFault> {
        io::canceled(Some(cancel))?;
        match self {
            Self::Memory(m) => {
                let n = out.len().min(io::WINDOW).min(m.bytes.len() - m.position);
                out[..n].copy_from_slice(&m.bytes[m.position..m.position + n]);
                m.position += n;
                Ok(n)
            }
            #[cfg(unix)]
            Self::File(f) => {
                if f.position == f.len {
                    return Ok(0);
                }
                let n = out.len().min(io::WINDOW).min((f.len - f.position).min(io::WINDOW as u64) as usize);
                if n == 0 {
                    return Err(ReadFault::InvalidPlan);
                }
                let n = io::read(
                    &f.ledger,
                    true,
                    &mut PayloadFile(f.file.as_mut().unwrap()),
                    IoStage::Ciphertext,
                    f.position,
                    &mut out[..n],
                    cancel,
                )?;
                if n == 0 {
                    return Err(fault(ReadIoOperation::Read, std::io::ErrorKind::UnexpectedEof.into()));
                }
                f.position += n as u64;
                Ok(n)
            }
        }
    }
    pub(super) fn rewind(&mut self, cancel: &Cancellation) -> Result<(), ReadFault> {
        match self {
            Self::Memory(m) => {
                io::canceled(Some(cancel))?;
                m.position = 0;
                Ok(())
            }
            #[cfg(unix)]
            Self::File(f) => f.rewind(cancel),
        }
    }
    #[allow(clippy::result_large_err)] // Eight inline cleanup slots (656 bytes), including allocator refusal.
    pub(super) fn finish(self) -> Result<(), ObjectCleanupReport> {
        match self {
            Self::Memory(_) => Ok(()),
            #[cfg(unix)]
            Self::File(f) => f.finish(),
        }
    }
    #[allow(clippy::result_large_err)]
    pub(super) fn finish_error(self, error: ZipReadError) -> ZipReadError {
        let ledger = match &self {
            Self::Memory(m) => m.ledger,
            #[cfg(unix)]
            Self::File(f) => f.ledger,
        };
        let error = match self.finish() {
            Ok(()) => error,
            Err(report) => error.merge_cleanup(report),
        };
        ledger.with_state(|s| error.with_usage(s.encrypted.usage, s.run.usage))
    }
    #[cfg(all(test, unix))]
    pub(super) fn is_unlinked_file(&self) -> bool {
        matches!(self, Self::File(f) if stat(f.file.as_ref().unwrap()).unwrap().st_nlink == 0)
    }
}
pub(super) fn read_exact(
    ledger: impl LedgerAccess,
    source: &mut (impl Read + ?Sized),
    mut bytes: &mut [u8],
    stage: IoStage,
    cancel: &Cancellation,
) -> Result<(), ReadFault> {
    let mut offset = 0;
    while !bytes.is_empty() {
        let n = io::read(&ledger, true, source, stage, offset, bytes, cancel)?;
        if n == 0 {
            return Err(ReadFault::Io {
                stage,
                operation: ReadIoOperation::Read,
                offset,
                error: std::io::ErrorKind::UnexpectedEof.into(),
            });
        }
        offset += n as u64;
        bytes = &mut bytes[n..];
    }
    Ok(())
}

#[cfg(unix)]
struct AcquiredHandle<'a> {
    file: Option<File>,
    ledger: LedgerView<'a>,
    object: OwnedObject,
}
#[cfg(unix)]
impl AcquiredHandle<'_> {
    fn into_file(mut self) -> File {
        self.file.take().expect("owned acquired file")
    }
}
#[cfg(unix)]
impl std::ops::Deref for AcquiredHandle<'_> {
    type Target = File;
    fn deref(&self) -> &File {
        self.file.as_ref().unwrap()
    }
}
#[cfg(unix)]
impl Drop for AcquiredHandle<'_> {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = close(self.ledger, file, self.object);
        }
    }
}

#[cfg(unix)]
impl<'a> PrivateCiphertextFile<'a> {
    #[allow(clippy::result_large_err)]
    fn create(
        ledger: LedgerView<'a>,
        directory: &ResolvedTempDirectory,
        len: u64,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        Self::create_at(ledger, directory.as_cstr(), directory.uid, len, cancel)
    }
    #[allow(clippy::result_large_err)]
    fn create_at(
        ledger: LedgerView<'a>,
        path: &CStr,
        uid: libc::uid_t,
        len: u64,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        // Reserve the entire file and both descriptors before acquisition.
        ledger.with_state(|s| s.reserve(true, len, 2))?;
        let mut directory: Option<AcquiredHandle<'_>> = None;
        let mut file: Option<AcquiredHandle<'_>> = None;
        let mut named = false;
        let mut unlinked_verified = false;
        let mut identity: Option<Identity> = None;
        let mut parent_identity: Option<Identity> = None;
        let mut name = [0u8; 41];
        let result = (|| -> Result<(), ReadFault> {
            let mut group = io::CreationGroup::new(&ledger, true, IoStage::Ciphertext, cancel)?;
            // The namespace envelope is 12*creates. At zero, even opening the
            // parent or requesting random bytes must be refused before a call.
            let creates = ledger.with_state(|s| s.creation_policy(true).map(|p| p.0))?;
            budget::next_creation_attempt(0, creates)?;
            let fd = namespace(&ledger, cancel, ReadIoOperation::Open, || {
                cvt(unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })
            })?;
            directory = Some(AcquiredHandle {
                file: Some(unsafe { File::from_raw_fd(fd) }),
                ledger,
                object: OwnedObject::CiphertextDirectory,
            });
            let parent = directory.as_ref().unwrap();
            let s = namespace(&ledger, cancel, ReadIoOperation::Stat, || stat(parent))?;
            if !trusted_dir(&s, uid) {
                return Err(policy());
            }
            parent_identity = Some(Identity::of(&s));
            loop {
                let mut random = [0u8; 16];
                namespace(&ledger, cancel, ReadIoOperation::Read, || random_name_bytes(&mut random))?;
                name[..8].copy_from_slice(b".zipfast");
                for (i, b) in random.into_iter().enumerate() {
                    name[8 + 2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                    name[9 + 2 * i] = b"0123456789abcdef"[(b & 15) as usize];
                }
                match group.create(cancel, || {
                    syscall(ReadIoOperation::Create, parent.as_raw_fd(), || {
                        cvt(unsafe {
                            libc::openat(
                                parent.as_raw_fd(),
                                name.as_ptr().cast(),
                                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                                0o600,
                            )
                        })
                    })
                }) {
                    Ok(fd) => {
                        file = Some(AcquiredHandle {
                            file: Some(unsafe { File::from_raw_fd(fd) }),
                            ledger,
                            object: OwnedObject::Ciphertext,
                        });
                        named = true;
                        break;
                    }
                    Err(ReadFault::Io { error, .. }) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => return Err(e),
                }
            }
            let s = namespace(&ledger, cancel, ReadIoOperation::Stat, || stat(file.as_ref().unwrap()))?;
            identity = Some(Identity::of(&s));
            if !trusted_file(&s, 1, uid) {
                return Err(policy());
            }
            let s = namespace(&ledger, cancel, ReadIoOperation::Stat, || stat(parent))?;
            if !trusted_dir(&s, uid) || !parent_identity.unwrap().matches(&s) {
                return Err(policy());
            }
            let mut s = std::mem::MaybeUninit::uninit();
            namespace(&ledger, cancel, ReadIoOperation::Stat, || {
                cvt(unsafe {
                    libc::fstatat(parent.as_raw_fd(), name.as_ptr().cast(), s.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
                })
            })?;
            let s = unsafe { s.assume_init() };
            if !identity.unwrap().matches(&s) || !trusted_file(&s, 1, uid) {
                return Err(policy());
            }
            namespace(&ledger, cancel, ReadIoOperation::Unlink, || {
                cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr().cast(), 0) })
            })?;
            named = false;
            let s = namespace(&ledger, cancel, ReadIoOperation::Stat, || stat(file.as_ref().unwrap()))?;
            if !identity.unwrap().matches(&s) || !trusted_file(&s, 0, uid) {
                return Err(policy());
            }
            unlinked_verified = true;
            Ok(())
        })();
        let mut error = result.err().map(ZipReadError::from);
        // Explicit bounded cleanup is independent of cancellation/main exhaustion.
        // A named partial file is removed only after validating all observable identities.
        if named {
            let mut report = ObjectCleanupReport::new(OwnedObject::Ciphertext);
            let cleanup = (|| -> Result<(), (ReadIoOperation, CleanupCause)> {
                let parent = directory.as_ref().unwrap();
                let held = file.as_ref().unwrap();
                let mut calls = 0;
                let mut checked = |op,
                                   call: &mut dyn FnMut() -> std::io::Result<()>|
                 -> Result<(), (ReadIoOperation, CleanupCause)> {
                    calls += 1;
                    assert!(calls <= 5);
                    ledger
                        .with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1))
                        .map_err(|_| (op, CleanupCause::Policy("cleanup allowance exhausted")))?;
                    syscall(op, -1, call).map_err(|e| (op, CleanupCause::Io(e)))
                };
                let mut parent_ok = false;
                checked(ReadIoOperation::Stat, &mut || {
                    let s = stat(parent)?;
                    parent_ok = trusted_dir(&s, uid) && parent_identity.is_some_and(|id| id.matches(&s));
                    Ok(())
                })?;
                if !parent_ok {
                    return Err((ReadIoOperation::Stat, CleanupCause::Policy("ciphertext parent changed")));
                }
                let mut held_id = None;
                checked(ReadIoOperation::Stat, &mut || {
                    let s = stat(held)?;
                    if trusted_file(&s, 1, uid) {
                        held_id = Some(Identity::of(&s));
                    }
                    Ok(())
                })?;
                let id =
                    held_id.ok_or((ReadIoOperation::Stat, CleanupCause::Policy("ciphertext held identity changed")))?;
                if identity.is_some_and(|expected| expected.dev != id.dev || expected.ino != id.ino) {
                    return Err((ReadIoOperation::Stat, CleanupCause::Policy("ciphertext held identity changed")));
                }
                let mut same = false;
                checked(ReadIoOperation::Stat, &mut || {
                    let mut s = std::mem::MaybeUninit::uninit();
                    cvt(unsafe {
                        libc::fstatat(
                            parent.as_raw_fd(),
                            name.as_ptr().cast(),
                            s.as_mut_ptr(),
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    })?;
                    let s = unsafe { s.assume_init() };
                    same = id.matches(&s) && trusted_file(&s, 1, uid);
                    Ok(())
                })?;
                if !same {
                    return Err((ReadIoOperation::Stat, CleanupCause::Policy("ciphertext name changed")));
                }
                checked(ReadIoOperation::Unlink, &mut || {
                    cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr().cast(), 0) }).map(|_| ())
                })?;
                named = false;
                let mut verified = false;
                checked(ReadIoOperation::Stat, &mut || {
                    let s = stat(held)?;
                    verified = id.matches(&s) && trusted_file(&s, 0, uid);
                    Ok(())
                })?;
                if !verified {
                    return Err((
                        ReadIoOperation::Stat,
                        CleanupCause::Policy("ciphertext post-unlink identity changed"),
                    ));
                }
                unlinked_verified = true;
                Ok(())
            })();
            if let Err((operation, cause)) = cleanup {
                report.push(CleanupFault {
                    object: OwnedObject::Ciphertext,
                    operation,
                    offset: None,
                    cause,
                    close: CloseDisposition::NotApplicable,
                });
            }
            if !report.is_empty() {
                error = Some(match error {
                    Some(e) => e.merge_cleanup(report),
                    None => report.into(),
                });
            }
            if named || !unlinked_verified {
                ledger.with_state(|s| s.poisoned = true);
            }
        }
        // Directory final check + close are always attempted once, on both paths.
        if let Some(parent) = directory {
            let mut report = ObjectCleanupReport::new(OwnedObject::CiphertextDirectory);
            let admitted = ledger.with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1));
            let observation = if admitted.is_ok() {
                stat(&parent).map_err(CleanupCause::Io).and_then(|s| {
                    if trusted_dir(&s, uid) && parent_identity.is_some_and(|id| id.matches(&s)) {
                        Ok(())
                    } else {
                        Err(CleanupCause::Policy("ciphertext parent changed"))
                    }
                })
            } else {
                Err(CleanupCause::Policy("cleanup allowance exhausted"))
            };
            if let Err(cause) = observation {
                report.push(CleanupFault {
                    object: OwnedObject::CiphertextDirectory,
                    operation: ReadIoOperation::Stat,
                    offset: None,
                    cause,
                    close: CloseDisposition::NotApplicable,
                });
            }
            if let Err(e) = close(ledger, parent.into_file(), OwnedObject::CiphertextDirectory) {
                report.push(e);
            }
            if !report.is_empty() {
                error = Some(match error {
                    Some(e) => e.merge_cleanup(report),
                    None => report.into(),
                });
            }
        } else {
            ledger.with_state(|s| s.retire_fd(true));
        }
        if let Some(error) = error {
            if let Some(file) = file {
                if !unlinked_verified {
                    ledger.with_state(|s| s.poisoned = true);
                }
                let mut report = ObjectCleanupReport::new(OwnedObject::Ciphertext);
                if let Err(e) = close(ledger, file.into_file(), OwnedObject::Ciphertext) {
                    report.push(e);
                }
                // Logical bytes are released only after confirmed close and no retained name.
                if report.is_empty() && !named && unlinked_verified {
                    ledger.with_state(|s| s.release_bytes(true, len));
                }
                return Err(if report.is_empty() { error } else { error.merge_cleanup(report) });
            }
            ledger.with_state(|s| {
                s.retire_fd(true);
                s.release_bytes(true, len);
            });
            return Err(error);
        }
        Ok(Self {
            file: file.map(AcquiredHandle::into_file),
            ledger,
            len,
            position: 0,
            identity: identity.unwrap(),
            uid,
            reserved: len,
        })
    }
    fn check(&self, cancel: &Cancellation) -> Result<(), ReadFault> {
        let s = io::operation(
            &self.ledger,
            true,
            RunCategory::StageFinalization,
            IoStage::Ciphertext,
            ReadIoOperation::Stat,
            Some(cancel),
            || stat(self.file.as_ref().unwrap()),
        )?;
        if !self.identity.matches(&s) || !trusted_file(&s, 0, self.uid) || s.st_size < 0 || s.st_size as u64 != self.len
        {
            return Err(policy());
        }
        Ok(())
    }
    fn rewind(&mut self, cancel: &Cancellation) -> Result<(), ReadFault> {
        self.check(cancel)?;
        io::operation(
            &self.ledger,
            true,
            RunCategory::StageFinalization,
            IoStage::Ciphertext,
            ReadIoOperation::Seek,
            Some(cancel),
            || {
                let file = self.file.as_mut().unwrap();
                syscall(ReadIoOperation::Seek, file.as_raw_fd(), || file.seek(SeekFrom::Start(0)))
            },
        )?;
        self.position = 0;
        Ok(())
    }
    #[allow(clippy::result_large_err)] // Eight inline cleanup slots (656 bytes), including allocator refusal.
    pub(super) fn finish(mut self) -> Result<(), ObjectCleanupReport> {
        self.finish_inner()
    }
    #[allow(clippy::result_large_err)] // Eight inline cleanup slots (656 bytes), including allocator refusal.
    fn finish_inner(&mut self) -> Result<(), ObjectCleanupReport> {
        let Some(file) = self.file.take() else {
            return Ok(());
        };
        let mut report = ObjectCleanupReport::new(OwnedObject::Ciphertext);
        let admitted = self.ledger.with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1));
        let observation = if admitted.is_ok() {
            stat(&file).map_err(CleanupCause::Io).and_then(|s| {
                if self.identity.matches(&s) && trusted_file(&s, 0, self.uid) {
                    Ok(())
                } else {
                    Err(CleanupCause::Policy("ciphertext identity changed"))
                }
            })
        } else {
            Err(CleanupCause::Policy("cleanup allowance exhausted"))
        };
        let verified_unlinked = observation.is_ok();
        if let Err(cause) = observation {
            report.push(CleanupFault {
                object: OwnedObject::Ciphertext,
                operation: ReadIoOperation::Stat,
                offset: None,
                cause,
                close: CloseDisposition::NotApplicable,
            });
        }
        match close(self.ledger, file, OwnedObject::Ciphertext) {
            Ok(()) if verified_unlinked => self.ledger.with_state(|s| s.release_bytes(true, self.reserved)),
            Ok(()) => self.ledger.with_state(|s| s.poisoned = true),
            Err(e) => report.push(e),
        }
        if report.is_empty() { Ok(()) } else { Err(report) }
    }
}
#[cfg(unix)]
fn close(ledger: LedgerView<'_>, file: File, object: OwnedObject) -> Result<(), CleanupFault> {
    let raw = file.into_raw_fd();
    io::retire_once(&ledger, true, object, || {
        syscall(ReadIoOperation::Close, raw, || cvt(unsafe { libc::close(raw) }).map(|_| ()))
    })
}
#[cfg(unix)]
impl Drop for PrivateCiphertextFile<'_> {
    fn drop(&mut self) {
        let _ = self.finish_inner();
    }
}

/// A bounded, single snapshot for both future plan geometry and spool opening.
/// Keeping this value prevents a factory from querying environment state twice.
pub(super) enum ResolveCharge {
    Group,
    Attempt,
}
pub(super) struct ResolvedTempDirectory {
    bytes: Vec<u8>,
    #[cfg(unix)]
    uid: libc::uid_t,
    identity: LedgerIdentity,
}
impl ResolvedTempDirectory {
    pub(super) const CAPACITY: usize = 4096;
    #[cfg_attr(not(test), allow(dead_code))] // Task4 derives geometry from this same retained path choice.
    pub(super) fn resolve(
        ledger: &impl LedgerAccess,
        configured: Option<&Path>,
        cancel: &Cancellation,
    ) -> Result<Self, ReadFault> {
        let retries = ledger.with_state(|s| s.encrypted.limits.interrupted_retries);
        Self::resolve_charged(ledger, configured, cancel, retries, |charge| {
            ledger.with_state(|s| match charge {
                ResolveCharge::Group => s.charge_category(RunCategory::PathSteps, 1),
                ResolveCharge::Attempt => s.attempt(true),
            })
        })
    }
    /// Task4 supplies finite pre-plan bootstrap charges, then carries this same
    /// bounded value into ActionPlan derivation/binding and file acquisition.
    #[cfg(unix)]
    pub(super) fn resolve_charged(
        ledger: &impl LedgerAccess,
        configured: Option<&Path>,
        cancel: &Cancellation,
        retries: u64,
        mut charge: impl FnMut(ResolveCharge) -> Result<(), ReadFault>,
    ) -> Result<Self, ReadFault> {
        charge(ResolveCharge::Group)?;
        ledger.with_state(|s| s.encrypted.allocation(Self::CAPACITY as u64))?;
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(Self::CAPACITY).is_err() {
            ledger.with_state(|s| s.release_capacity(Self::CAPACITY as u64));
            return Err(ReadFault::Allocation { capacity: Self::CAPACITY });
        }
        let mut resolved = Self { bytes, uid: 0, identity: ledger.identity() };
        let result = (|| -> Result<(), ReadFault> {
            io::canceled(Some(cancel))?;
            charge(ResolveCharge::Attempt)?;
            // Infallible identity snapshot; trusted process credentials remain fixed
            // for the action. All later trust checks reuse it without extra syscalls.
            resolved.uid = unsafe { libc::geteuid() };
            if let Some(path) = configured {
                resolved.set(path.as_os_str().as_bytes())?;
            } else {
                io::canceled(Some(cancel))?;
                charge(ResolveCharge::Attempt)?;
                // SAFETY: Unix process environment reads rely on the documented
                // process-wide environment-mutation contract (no concurrent unsafe
                // mutation). No private mutex can synchronize arbitrary C writers.
                // The pointer is consumed here, before any callback/syscall; only
                // indices 0..CAPACITY are examined, stopping at the first NUL.
                let value = unsafe { libc::getenv(c"TMPDIR".as_ptr()) };
                if !value.is_null() {
                    for i in 0..Self::CAPACITY {
                        let byte = unsafe { *value.add(i) } as u8;
                        if byte == 0 {
                            break;
                        }
                        resolved.bytes.push(byte);
                    }
                    if resolved.bytes.len() == Self::CAPACITY {
                        return Err(ReadFault::InvalidPlan);
                    }
                    resolved.terminate()?;
                } else {
                    resolved.platform_default(cancel, retries, &mut charge)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            drop(resolved);
            ledger.with_state(|s| s.release_capacity(Self::CAPACITY as u64));
            return Err(error);
        }
        Ok(resolved)
    }
    #[cfg(not(unix))]
    pub(super) fn resolve_charged(
        _ledger: &impl LedgerAccess,
        _configured: Option<&Path>,
        _cancel: &Cancellation,
        _retries: u64,
        _charge: impl FnMut(ResolveCharge) -> Result<(), ReadFault>,
    ) -> Result<Self, ReadFault> {
        Err(ReadFault::UnsupportedIdentity)
    }
    #[cfg(unix)]
    fn set(&mut self, path: &[u8]) -> Result<(), ReadFault> {
        if path.len() >= Self::CAPACITY || path.contains(&0) {
            return Err(ReadFault::InvalidPlan);
        }
        self.bytes.extend_from_slice(path);
        self.terminate()
    }
    #[cfg(unix)]
    fn terminate(&mut self) -> Result<(), ReadFault> {
        if self.bytes.is_empty() {
            self.bytes.push(b'.');
        }
        if self.bytes.len() >= Self::CAPACITY {
            return Err(ReadFault::InvalidPlan);
        }
        self.bytes.push(0);
        Ok(())
    }
    #[cfg(target_os = "macos")]
    fn platform_default(
        &mut self,
        cancel: &Cancellation,
        retry_limit: u64,
        charge: &mut impl FnMut(ResolveCharge) -> Result<(), ReadFault>,
    ) -> Result<(), ReadFault> {
        self.bytes.resize(Self::CAPACITY, 0);
        let mut retries = 0;
        let needed = loop {
            io::canceled(Some(cancel))?;
            charge(ResolveCharge::Attempt)?;
            let result = syscall(ReadIoOperation::Directory, -1, || {
                // SAFETY: exactly CAPACITY writable bytes; confstr reports required
                // length and never writes beyond that supplied capacity.
                let n = unsafe {
                    libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, self.bytes.as_mut_ptr().cast(), Self::CAPACITY)
                };
                if n == 0 { Err(std::io::Error::last_os_error()) } else { Ok(n) }
            });
            match result {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    retries += 1;
                    budget::admit(ReadResource::InterruptedRetries, retry_limit.into(), retries)?;
                }
                result => break result,
            }
        };
        self.complete_default(needed)
    }
    #[cfg(any(target_os = "macos", all(test, unix)))]
    fn complete_default(&mut self, needed: std::io::Result<usize>) -> Result<(), ReadFault> {
        match needed {
            Ok(n) if n > 0 && n <= Self::CAPACITY => {
                self.bytes.truncate(n);
                if n == 1 {
                    self.bytes.clear();
                    self.set(b".")?;
                }
                Ok(())
            }
            Ok(_) => Err(ReadFault::InvalidPlan),
            Err(_) => {
                self.bytes.clear();
                self.set(b"/tmp")
            }
        }
    }
    #[cfg(all(test, unix))]
    pub(super) fn test_confstr(&mut self, needed: std::io::Result<usize>) -> Result<(), ReadFault> {
        self.bytes.resize(Self::CAPACITY, b'x');
        if let Ok(n) = &needed
            && *n > 0
            && *n <= Self::CAPACITY
        {
            self.bytes[*n - 1] = 0;
        }
        self.complete_default(needed)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    fn platform_default(
        &mut self,
        _cancel: &Cancellation,
        _retries: u64,
        _charge: &mut impl FnMut(ResolveCharge) -> Result<(), ReadFault>,
    ) -> Result<(), ReadFault> {
        self.set(b"/tmp")
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 context/action controlled teardown releases this owned path capacity.
    pub(super) fn finish_capacity(self, ledger: &impl LedgerAccess) -> Result<(), ReadFault> {
        if self.identity != ledger.identity() {
            return Err(ReadFault::InvalidPlan);
        }
        drop(self);
        ledger.with_state(|s| s.release_capacity(Self::CAPACITY as u64));
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn test_path(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() - 1]
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 derives geometry from this same retained path choice.
    pub(super) fn path_bytes(&self) -> usize {
        self.bytes.len() - 1
    }
    #[cfg(unix)]
    fn as_cstr(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.bytes).expect("bounded resolved C path")
    }
}

#[cfg(target_os = "linux")]
fn random_name_bytes(bytes: &mut [u8; 16]) -> std::io::Result<()> {
    // One actual kernel request: libc getentropy may internally retry getrandom.
    let n = unsafe { libc::syscall(libc::SYS_getrandom, bytes.as_mut_ptr(), bytes.len(), 0) };
    if n == -1 {
        Err(std::io::Error::last_os_error())
    } else if n as usize != bytes.len() {
        Err(std::io::ErrorKind::UnexpectedEof.into())
    } else {
        Ok(())
    }
}
#[cfg(all(unix, not(target_os = "linux")))]
fn random_name_bytes(bytes: &mut [u8; 16]) -> std::io::Result<()> {
    cvt(unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) }).map(|_| ())
}

fn syscall<T>(operation: ReadIoOperation, fd: i32, call: impl FnOnce() -> std::io::Result<T>) -> std::io::Result<T> {
    #[cfg(test)]
    if let Some(error) = hooks::HOOK.with(|h| h.borrow_mut().as_mut().and_then(|h| h(operation, fd))) {
        return Err(error);
    }
    #[cfg(not(test))]
    let _ = (operation, fd);
    call()
}

#[cfg(unix)]
struct PayloadFile<'a>(&'a mut File);
#[cfg(unix)]
impl Read for PayloadFile<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        syscall(ReadIoOperation::Read, self.0.as_raw_fd(), || self.0.read(bytes))
    }
}
#[cfg(unix)]
impl std::io::Write for PayloadFile<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        syscall(ReadIoOperation::Write, self.0.as_raw_fd(), || std::io::Write::write(self.0, bytes))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

// A syscall fault/namespace mutation seam exists only in unit-test builds.
#[cfg(test)]
pub(super) mod hooks {
    use super::*;
    pub(in crate::zip::read) type Hook = Box<dyn FnMut(ReadIoOperation, i32) -> Option<std::io::Error>>;
    thread_local! { pub(in crate::zip::read) static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) }; }
}
