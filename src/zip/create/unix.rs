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

use std::ffi::{CStr, CString};
use std::fs::{self, File, Metadata};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use libc::{fstatat as native_fstatat, stat as NativeStat};
#[cfg(target_os = "linux")]
use libc::{fstatat64 as native_fstatat, stat64 as NativeStat};

use super::{Attempts, CreateError, CreateLimit, Result, STAGE_ATTEMPTS, absolute, limit};

#[cfg(target_os = "linux")]
const LARGE_FILE: libc::c_int = libc::O_LARGEFILE;
#[cfg(target_os = "macos")]
const LARGE_FILE: libc::c_int = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::zip) struct Identity(pub(in crate::zip) u64, pub(in crate::zip) u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::zip) struct Stamp {
    pub(in crate::zip) identity: Identity,
    pub(in crate::zip) len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    pub(in crate::zip) mode: u16,
}

impl Stamp {
    pub(in crate::zip) fn regular(meta: &Metadata) -> Result<Self> {
        if !meta.is_file() {
            return Err(CreateError::SourceNotRegular);
        }
        Ok(Self::from_metadata(meta))
    }

    fn from_metadata(meta: &Metadata) -> Self {
        Self {
            identity: identity(meta),
            len: meta.len(),
            modified: (meta.mtime(), meta.mtime_nsec()),
            changed: (meta.ctime(), meta.ctime_nsec()),
            mode: (meta.mode() & 0o7777) as u16,
        }
    }

    pub(in crate::zip) fn same_payload(self, other: Self) -> bool {
        self.identity == other.identity && self.len == other.len && self.modified == other.modified
    }

    #[allow(clippy::unnecessary_cast, reason = "libc timestamp widths vary across Unix architectures")]
    fn from_stat(meta: &NativeStat) -> Self {
        #[cfg(target_os = "macos")]
        let mode = meta.st_mode & 0o7777;
        #[cfg(target_os = "linux")]
        let mode = (meta.st_mode & 0o7777) as u16;
        Self {
            identity: stat_identity(meta),
            len: meta.st_size as u64,
            modified: (meta.st_mtime as i64, meta.st_mtime_nsec as i64),
            changed: (meta.st_ctime as i64, meta.st_ctime_nsec as i64),
            mode,
        }
    }
}

pub(in crate::zip) enum NameState {
    Regular(Stamp),
    Other,
}

fn identity(meta: &Metadata) -> Identity {
    Identity(meta.dev(), meta.ino())
}

pub(in crate::zip) fn open_source(path: &Path, budget: &Attempts<'_>) -> Result<File> {
    let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC | LARGE_FILE;
    let cpath = c_path(path)?;
    budget.run(|| {
        #[cfg(test)]
        super::tests::event_io(super::tests::Event::SourceOpen, Some(path))?;
        // cpath is nul-terminated and stays alive across this call.
        opened(unsafe { libc::open(cpath.as_ptr(), flags) })
    })
}

pub(in crate::zip) fn file_stamp(file: &File, budget: &Attempts<'_>) -> Result<Stamp> {
    Stamp::regular(&budget.run(|| file.metadata())?)
}

pub(in crate::zip) fn path_stamp(path: &Path, budget: &Attempts<'_>) -> Result<Stamp> {
    Stamp::regular(&budget.run(|| fs::symlink_metadata(path))?)
}

pub(in crate::zip) fn directory_stamp(meta: &Metadata) -> Result<Stamp> {
    if !meta.is_dir() {
        return Err(CreateError::InvalidOptions("directory source is not a directory"));
    }
    Ok(Stamp::from_metadata(meta))
}

pub(in crate::zip) struct Parent {
    pub(in crate::zip) destination: PathBuf,
    pub(super) real_path: PathBuf,
    pub(in crate::zip) leaf: CString,
    pub(in crate::zip) file: File,
    pub(in crate::zip) identity: Identity,
}

impl Parent {
    pub(super) fn open(destination: &Path, budget: &Attempts<'_>, max: u64) -> Result<Self> {
        let parent = Self::bind(destination, budget, max)?;
        if parent.lookup(&parent.leaf, budget)?.is_some() {
            return Err(CreateError::Conflict);
        }
        Ok(parent)
    }

    pub(in crate::zip) fn bind(destination: &Path, budget: &Attempts<'_>, max: u64) -> Result<Self> {
        let raw = destination.as_os_str().as_bytes();
        limit(raw.len() as u64, max, CreateLimit::PlanCapacity)?;
        let final_component = raw.rsplit(|&b| b == b'/').next().unwrap_or_default();
        if final_component.is_empty() || matches!(final_component, b"." | b"..") || final_component.contains(&0) {
            return Err(CreateError::InvalidDestination);
        }
        let destination = absolute(destination, max, budget)?;
        let real_path = budget.run(|| {
            fs::canonicalize(destination.parent().ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?)
        })?;
        let remaining = max
            .checked_sub(destination.capacity() as u64 + real_path.capacity() as u64)
            .ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?;
        limit(final_component.len() as u64 + 1, remaining, CreateLimit::PlanCapacity)?;
        let mut leaf = Vec::new();
        leaf.try_reserve_exact(final_component.len() + 1)?;
        leaf.extend_from_slice(final_component);
        leaf.push(0);
        let leaf = CString::from_vec_with_nul(leaf).map_err(|_| CreateError::InvalidDestination)?;
        let cpath = c_path(&real_path)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // cpath is nul-terminated and stays alive across this call.
        let file = budget.run(|| opened(unsafe { libc::open(cpath.as_ptr(), flags) }))?;
        let id = identity(&budget.run(|| file.metadata())?);
        let parent = Self { destination, real_path, leaf, file, identity: id };
        parent.check(budget)?;
        if !budget.run(|| filesystem(&parent.file))?.eligible() {
            return Err(CreateError::UnsupportedFilesystem);
        }
        Ok(parent)
    }

    pub(in crate::zip) fn open_existing_regular(&self, budget: &Attempts<'_>) -> Result<(File, Stamp)> {
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC | LARGE_FILE;
        let file = budget.run(|| {
            // The descriptor and the validated single component remain live.
            opened(unsafe { libc::openat(self.file.as_raw_fd(), self.leaf.as_ptr(), flags) })
        })?;
        let stamp = file_stamp(&file, budget)?;
        Ok((file, stamp))
    }

    pub(in crate::zip) fn capacity(&self) -> u64 {
        self.destination.capacity() as u64
            + self.real_path.capacity() as u64
            + self.leaf.as_bytes_with_nul().len() as u64
    }

    pub(in crate::zip) fn check(&self, budget: &Attempts<'_>) -> Result<()> {
        let path = self.destination.parent().ok_or(CreateError::InvalidDestination)?;
        let observed = budget.run(|| fs::metadata(path))?;
        let real = budget.run(|| fs::symlink_metadata(&self.real_path))?;
        if !observed.is_dir()
            || !real.is_dir()
            || identity(&observed) != self.identity
            || identity(&real) != self.identity
        {
            return Err(CreateError::ParentChanged);
        }
        Ok(())
    }

    pub(in crate::zip) fn lookup(&self, leaf: &CStr, budget: &Attempts<'_>) -> Result<Option<NameState>> {
        budget.run(|| {
            let mut meta = MaybeUninit::<NativeStat>::uninit();
            // The descriptor and C string remain live. fstatat initializes
            // the result on success and does not follow the final component.
            let status = unsafe {
                native_fstatat(self.file.as_raw_fd(), leaf.as_ptr(), meta.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW)
            };
            if status == 0 {
                let meta = unsafe { meta.assume_init() };
                return Ok(Some(if meta.st_mode & libc::S_IFMT == libc::S_IFREG {
                    NameState::Regular(Stamp::from_stat(&meta))
                } else {
                    NameState::Other
                }));
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) { Ok(None) } else { Err(error) }
        })
    }
}

fn stat_identity(meta: &NativeStat) -> Identity {
    #[cfg(target_os = "linux")]
    let device = meta.st_dev;
    #[cfg(target_os = "macos")]
    let device = meta.st_dev as u64;
    Identity(device, meta.st_ino)
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Filesystem {
    #[cfg(target_os = "macos")]
    Apfs,
    #[cfg(target_os = "linux")]
    Tmpfs,
    #[cfg(target_os = "linux")]
    ExtFamily,
    Other,
}

impl Filesystem {
    fn eligible(self) -> bool {
        !matches!(self, Self::Other)
    }
}

pub(super) fn filesystem(file: &File) -> io::Result<Filesystem> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    // fstatfs initializes the result on success; the held directory FD
    // identifies the filesystem where relative operations will occur.
    if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    #[cfg(target_os = "linux")]
    let filesystem = match stat.f_type {
        libc::TMPFS_MAGIC => Filesystem::Tmpfs,
        libc::EXT4_SUPER_MAGIC => Filesystem::ExtFamily,
        _ => Filesystem::Other,
    };
    #[cfg(target_os = "macos")]
    let filesystem = if stat.f_fstypename[..5]
        == [b'a' as libc::c_char, b'p' as libc::c_char, b'f' as libc::c_char, b's' as libc::c_char, 0]
        && stat.f_flags & libc::MNT_LOCAL as u32 != 0
    {
        Filesystem::Apfs
    } else {
        Filesystem::Other
    };
    Ok(filesystem)
}

fn c_path(path: &Path) -> Result<CString> {
    let raw = path.as_os_str().as_bytes();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(raw.len() + 1)?;
    bytes.extend_from_slice(raw);
    bytes.push(0);
    CString::from_vec_with_nul(bytes)
        .map_err(|error| CreateError::Io(io::Error::new(io::ErrorKind::InvalidInput, error)))
}

fn opened(fd: libc::c_int) -> io::Result<File> {
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // A successful open returned an owned descriptor for the new File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

const RANDOM_LEN: usize = 16;
const STAGE_PREFIX_WITH_TILDE: &str = ".zipfast-~";
const STAGE_PREFIX_WITHOUT_TILDE: &str = ".zipfast-@";
const STAGE_NAME_LEN: usize = STAGE_PREFIX_WITH_TILDE.len() + RANDOM_LEN + 1;

pub(in crate::zip) struct Stage {
    pub(in crate::zip) file: File,
    path: tempfile::TempPath,
    name: [u8; STAGE_NAME_LEN],
}

impl Stage {
    pub(in crate::zip) fn create(parent: &Parent, budget: &Attempts<'_>, stage_attempts: &mut u64) -> Result<Self> {
        parent.check(budget)?;
        let mut terminal = None;
        // ASCII tilde presence survives case folding and canonical
        // normalization. Give stage and destination opposite presence so
        // the exclusive open cannot create an alias of the destination.
        let prefix =
            if parent.leaf.as_bytes().contains(&b'~') { STAGE_PREFIX_WITHOUT_TILDE } else { STAGE_PREFIX_WITH_TILDE };
        let candidate = tempfile::Builder::new().prefix(prefix).rand_bytes(RANDOM_LEN).disable_cleanup(true).make_in(
            &parent.real_path,
            |path| {
                let attempted = (|| {
                    limit(*stage_attempts + 1, STAGE_ATTEMPTS, CreateLimit::StageAttempts)?;
                    budget.charge()?;
                    *stage_attempts += 1;
                    let bytes = path.file_name().ok_or(CreateError::InvalidDestination)?.as_bytes();
                    let mut name = [0; STAGE_NAME_LEN];
                    if bytes.len() + 1 != name.len() {
                        return Err(CreateError::InvalidDestination);
                    }
                    name[..bytes.len()].copy_from_slice(bytes);
                    let leaf = CStr::from_bytes_with_nul(&name).map_err(|_| CreateError::InvalidDestination)?;
                    if leaf == parent.leaf.as_c_str() {
                        return Err(io::Error::from(io::ErrorKind::AlreadyExists).into());
                    }
                    #[cfg(test)]
                    super::tests::event(super::tests::Event::StageOpen, Some(path))?;
                    let flags =
                        libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CLOEXEC | LARGE_FILE;
                    // The directory FD and C string remain live. The name
                    // is one generated component in that held directory.
                    let file = opened(unsafe {
                        libc::openat(parent.file.as_raw_fd(), leaf.as_ptr(), flags, 0o600 as libc::c_int)
                    })?;
                    Ok((file, name))
                })();
                match attempted {
                    Ok(value) => Ok(value),
                    Err(CreateError::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                        if *stage_attempts == STAGE_ATTEMPTS {
                            terminal = Some(CreateError::Limit(CreateLimit::StageAttempts));
                            Err(io::Error::other("private ZIP stage names exhausted"))
                        } else {
                            Err(error)
                        }
                    }
                    Err(error) => {
                        terminal = Some(error);
                        Err(io::Error::other("could not create private ZIP stage"))
                    }
                }
            },
        );
        let named = candidate.map_err(|error| terminal.unwrap_or_else(|| error.into()))?;
        let ((file, name), path) = named.into_parts();
        Ok(Self { file, path, name })
    }

    pub(in crate::zip) fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.name).expect("checked generated stage name")
    }

    #[cfg(test)]
    pub(in crate::zip) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub(in crate::zip) fn into_path(self) -> PathBuf {
        // On Unix keep has no I/O side effects. Cleanup was disabled
        // before creating the path, including on this error branch.
        self.path.keep().unwrap_or_else(|error| error.path.to_path_buf())
    }
}

pub(in crate::zip) fn publication_stamp(stage: &Stage, verified: Stamp, budget: &Attempts<'_>) -> Option<Stamp> {
    // This optional probe runs before required cleanup and synchronization.
    // Never retry it against the reserve used by those operations.
    budget.charge().ok()?;
    #[cfg(test)]
    super::tests::event_io(super::tests::Event::PublicationStamp, None).ok()?;
    let held = Stamp::regular(&stage.file.metadata().ok()?).ok()?;
    // Native publication can change ctime. Keep the already verified
    // payload geometry, identity and permissions as the baseline.
    (held.same_payload(verified) && held.mode == verified.mode).then_some(held)
}

pub(in crate::zip) fn bound_publication(
    parent: &Parent,
    stage: &Stage,
    expected: Stamp,
    budget: &Attempts<'_>,
) -> Option<super::PublishedArchiveBinding> {
    parent.check(budget).ok()?;
    let Some(NameState::Regular(named)) = parent.lookup(&parent.leaf, budget).ok()? else { return None };
    if named != expected || file_stamp(&stage.file, budget).ok()? != expected {
        return None;
    }
    let file = budget.run(|| stage.file.try_clone()).ok()?;
    Some(super::PublishedArchiveBinding { file, stamp: expected })
}

pub(in crate::zip) enum PublishError {
    Definite(CreateError),
    Uncertain(CreateError),
}

impl PublishError {
    pub(in crate::zip) fn into_cause(self) -> CreateError {
        match self {
            Self::Definite(error) | Self::Uncertain(error) => error,
        }
    }

    fn from_syscall(error: io::Error) -> Self {
        match error.raw_os_error() {
            Some(libc::EEXIST | libc::ENOTEMPTY | libc::EISDIR) => Self::Definite(CreateError::Conflict),
            Some(libc::ENOSYS | libc::ENOTSUP | libc::EINVAL | libc::EXDEV) => {
                Self::Definite(CreateError::UnsupportedPublication(error))
            }
            Some(
                libc::EACCES
                | libc::EPERM
                | libc::EROFS
                | libc::ENOENT
                | libc::ENOTDIR
                | libc::ENAMETOOLONG
                | libc::ENOSPC
                | libc::EDQUOT
                | libc::EMLINK
                | libc::EBUSY
                | libc::EBADF,
            ) => Self::Definite(CreateError::Io(error)),
            _ => Self::Uncertain(CreateError::Io(error)),
        }
    }
}

impl Parent {
    pub(super) fn publish_noreplace(
        &self,
        stage: &CStr,
        budget: &Attempts<'_>,
    ) -> std::result::Result<(), PublishError> {
        budget.charge().map_err(PublishError::Definite)?;
        #[cfg(test)]
        super::tests::event_io(super::tests::Event::NativePublish, None).map_err(PublishError::from_syscall)?;
        let fd = self.file.as_raw_fd();
        // Both nul-terminated names are single components in this held
        // directory. The syscall is the only publication operation.
        #[cfg(target_os = "linux")]
        let status = unsafe {
            libc::syscall(libc::SYS_renameat2, fd, stage.as_ptr(), fd, self.leaf.as_ptr(), libc::RENAME_NOREPLACE)
        };
        #[cfg(target_os = "macos")]
        let status = unsafe { libc::renameatx_np(fd, stage.as_ptr(), fd, self.leaf.as_ptr(), libc::RENAME_EXCL) };
        if status == 0 { Ok(()) } else { Err(PublishError::from_syscall(io::Error::last_os_error())) }
    }

    pub(in crate::zip) fn publish_replace(
        &self,
        stage: &CStr,
        budget: &Attempts<'_>,
    ) -> std::result::Result<(), PublishError> {
        budget.charge().map_err(PublishError::Definite)?;
        #[cfg(test)]
        crate::zip::rewrite::test_event(crate::zip::rewrite::Event::NativePublish, None)
            .map_err(PublishError::from_syscall)?;
        let fd = self.file.as_raw_fd();
        // Both names are single components in the same held directory.
        // This replacement is performed once. Its result is never retried.
        let status = unsafe { libc::renameat(fd, stage.as_ptr(), fd, self.leaf.as_ptr()) };
        if status == 0 { Ok(()) } else { Err(PublishError::from_syscall(io::Error::last_os_error())) }
    }

    pub(super) fn unlink(&self, stage: &CStr, budget: &Attempts<'_>) -> Result<()> {
        budget.charge()?;
        #[cfg(test)]
        super::tests::event(super::tests::Event::Unlink, None)?;
        // The caller already checked the controlled parent and stage name.
        // An unlink error is reported without a second pathname mutation.
        status(unsafe { libc::unlinkat(self.file.as_raw_fd(), stage.as_ptr(), 0) }).map_err(CreateError::from)
    }
}

pub(in crate::zip) fn chmod(file: &File, permissions: u16, budget: &Attempts<'_>) -> Result<()> {
    budget.run(|| {
        #[cfg(test)]
        super::tests::event_io(super::tests::Event::Chmod, None)?;
        // This File owns the target descriptor. The mode was validated.
        #[cfg(target_os = "linux")]
        let permissions = libc::mode_t::from(permissions);
        status(unsafe { libc::fchmod(file.as_raw_fd(), permissions) })
    })
}

pub(in crate::zip) fn sync_stage(file: &File, budget: &Attempts<'_>) -> Result<()> {
    budget.run(|| {
        #[cfg(test)]
        super::tests::event_io(super::tests::Event::FileSync, None)?;
        // Use counted fsync directly. On macOS, File::sync_all uses
        // F_FULLFSYNC, which is stronger than this API requests.
        status(unsafe { libc::fsync(file.as_raw_fd()) })
    })
}

pub(in crate::zip) fn sync_directory(file: &File, budget: &Attempts<'_>) -> Result<()> {
    budget.run(|| {
        #[cfg(test)]
        super::tests::event_io(super::tests::Event::DirectorySync, None)?;
        // The directory descriptor remains valid through finalization.
        status(unsafe { libc::fsync(file.as_raw_fd()) })
    })
}

fn status(result: libc::c_int) -> io::Result<()> {
    if result == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}
