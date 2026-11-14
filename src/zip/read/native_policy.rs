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

//! Single-call native security primitives. Callers admit each call before entry.
//! The Darwin extended-operation ABI is an explicitly qualified checked-path dependency.
use std::os::fd::RawFd;
use std::{ffi::CStr, io};

pub(super) fn cvt(result: libc::c_int) -> io::Result<libc::c_int> {
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}
pub(super) fn stat(fd: RawFd) -> io::Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::uninit();
    // SAFETY: one borrowed live descriptor and exact initialized-on-success output.
    cvt(unsafe { libc::fstat(fd, value.as_mut_ptr()) })?;
    Ok(unsafe { value.assume_init() })
}
#[cfg(target_os = "macos")]
#[repr(C)]
struct EmptySecurity {
    magic: u32,
    owner: [u8; 16],
    group: [u8; 16],
    entries: u32,
    flags: u32,
}
#[cfg(target_os = "macos")]
impl EmptySecurity {
    fn new() -> Self {
        Self { magic: 0x012cc16d, owner: [0; 16], group: [0; 16], entries: 0, flags: 1 << 17 }
    }
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn __open_extended(
        path: *const libc::c_char,
        flags: libc::c_int,
        uid: libc::uid_t,
        gid: libc::gid_t,
        mode: libc::c_int,
        security: *const EmptySecurity,
    ) -> libc::c_int;
    fn __mkdir_extended(
        path: *const libc::c_char,
        uid: libc::uid_t,
        gid: libc::gid_t,
        mode: libc::c_int,
        security: *const EmptySecurity,
    ) -> libc::c_int;
}
#[cfg(all(test, target_os = "macos"))]
pub(super) fn atomic_abi_layout() -> (usize, usize, usize, usize, u32) {
    (
        std::mem::size_of::<EmptySecurity>(),
        std::mem::align_of::<EmptySecurity>(),
        std::mem::offset_of!(EmptySecurity, entries),
        std::mem::offset_of!(EmptySecurity, flags),
        u32::MAX - 100,
    )
}
#[cfg(target_os = "macos")]
fn joined<'a>(parent: &CStr, leaf: &CStr, bytes: &'a mut [u8; 1024]) -> io::Result<&'a CStr> {
    let parent = parent.to_bytes();
    let leaf = leaf.to_bytes();
    let n = parent
        .len()
        .checked_add(leaf.len())
        .and_then(|n| n.checked_add(2))
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENAMETOOLONG))?;
    if n > bytes.len() {
        return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    bytes[..parent.len()].copy_from_slice(parent);
    bytes[parent.len()] = b'/';
    bytes[parent.len() + 1..n - 1].copy_from_slice(leaf);
    bytes[n - 1] = 0;
    CStr::from_bytes_with_nul(&bytes[..n]).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}
/// Pure geometry admission occurs before any charged create attempt.
pub(super) fn check_atomic_path(parent: &CStr, leaf: &CStr) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        if parent
            .to_bytes()
            .len()
            .checked_add(leaf.to_bytes().len())
            .and_then(|n| n.checked_add(2))
            .is_none_or(|n| n > 1024)
        {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (parent, leaf);
    Ok(())
}
#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum BirthKind {
    File,
    Directory,
}
#[cfg(test)]
type BirthHook = Option<Box<dyn FnMut(BirthKind, RawFd, &CStr, &CStr) -> Option<io::Result<RawFd>>>>;
#[cfg(test)]
thread_local! {pub(super) static BIRTH_HOOK:std::cell::RefCell<BirthHook>=const {std::cell::RefCell::new(None)};}
#[cfg(test)]
fn birth_override(kind: BirthKind, fd: RawFd, parent: &CStr, leaf: &CStr) -> Option<io::Result<RawFd>> {
    let mut hook = BIRTH_HOOK.with(|state| state.borrow_mut().take());
    let result = hook.as_mut().and_then(|h| h(kind, fd, parent, leaf));
    BIRTH_HOOK.with(|state| *state.borrow_mut() = hook);
    result
}
pub(super) fn atomic_file(parent_fd: RawFd, parent: &CStr, leaf: &CStr) -> io::Result<RawFd> {
    #[cfg(test)]
    if let Some(result) = birth_override(BirthKind::File, parent_fd, parent, leaf) {
        return result;
    }
    let flags = libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDWR;
    #[cfg(target_os = "macos")]
    {
        let _ = parent_fd;
        let mut bytes = [0; 1024];
        let path = joined(parent, leaf, &mut bytes)?;
        // SAFETY: checked NUL path and exact SDK kauth_filesec header, zero ACEs.
        cvt(unsafe {
            __open_extended(path.as_ptr(), flags, u32::MAX - 100, u32::MAX - 100, 0o600, &EmptySecurity::new())
        })
    }
    #[cfg(target_os = "linux")]
    {
        let _ = parent;
        cvt(unsafe { libc::openat(parent_fd, leaf.as_ptr(), flags, 0o600) })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (parent_fd, parent, leaf, flags);
        Err(io::ErrorKind::Unsupported.into())
    }
}
pub(super) fn atomic_directory(parent_fd: RawFd, parent: &CStr, leaf: &CStr) -> io::Result<()> {
    #[cfg(test)]
    if let Some(result) = birth_override(BirthKind::Directory, parent_fd, parent, leaf) {
        return result.map(|_| ());
    }
    #[cfg(target_os = "macos")]
    {
        let _ = parent_fd;
        let mut bytes = [0; 1024];
        let path = joined(parent, leaf, &mut bytes)?;
        cvt(unsafe { __mkdir_extended(path.as_ptr(), u32::MAX - 100, u32::MAX - 100, 0o700, &EmptySecurity::new()) })?;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = parent;
        cvt(unsafe { libc::mkdirat(parent_fd, leaf.as_ptr(), 0o700) })?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (parent_fd, parent, leaf);
        return Err(io::ErrorKind::Unsupported.into());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
pub(super) fn mac_backend(name: &[u8], flags: u32, extended: u32) -> bool {
    name.split(|b| *b == 0).next() == Some(b"apfs".as_slice())
        && name.contains(&0)
        && flags & libc::MNT_LOCAL as u32 != 0
        && flags & 0x00200000 == 0
        && extended & 2 == 0
}
pub(super) fn backend(fd: RawFd) -> io::Result<()> {
    let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
    cvt(unsafe { libc::fstatfs(fd, value.as_mut_ptr()) })?;
    let value = unsafe { value.assume_init() };
    #[cfg(target_os = "macos")]
    let allowed = {
        let name = value.f_fstypename.map(|b| b as u8);
        mac_backend(&name, value.f_flags, value.f_flags_ext)
    };
    #[cfg(target_os = "linux")]
    let allowed = matches!(value.f_type as u64, 0xef53 | 0x58465342 | 0x9123683e | 0x01021994);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let allowed = false;
    if allowed { Ok(()) } else { Err(io::ErrorKind::Unsupported.into()) }
}
#[cfg(target_os = "macos")]
fn attributes() -> libc::attrlist {
    libc::attrlist {
        bitmapcount: 5,
        reserved: 0,
        commonattr: 0x00400000,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    }
}
#[cfg(target_os = "macos")]
pub(super) fn parse_mac_acl(buffer: &[u8]) -> io::Result<Option<&[u8]>> {
    if buffer.len() < 12 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let field = |i| u32::from_ne_bytes(buffer[i..i + 4].try_into().unwrap());
    let total = field(0) as usize;
    let offset = field(4) as i32;
    let size = field(8) as usize;
    if total > buffer.len() || total < 12 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if size == 0 {
        if offset != 0 && (offset < 8 || 4usize.checked_add(offset as usize).is_none_or(|n| n > total)) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(None);
    }
    if offset < 8 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let start = 4usize.checked_add(offset as usize).ok_or(io::ErrorKind::InvalidData)?;
    let end = start.checked_add(size).ok_or(io::ErrorKind::InvalidData)?;
    if end > total || size < 44 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let data = &buffer[start..end];
    validate_mac_security(data)
}
#[cfg(target_os = "macos")]
fn validate_mac_security(data: &[u8]) -> io::Result<Option<&[u8]>> {
    if data.len() < 44 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let size = data.len();
    let entries = u32::from_ne_bytes(data[36..40].try_into().unwrap());
    if u32::from_ne_bytes(data[..4].try_into().unwrap()) != 0x012cc16d
        || u32::from_ne_bytes(data[40..44].try_into().unwrap()) & (1 << 16) != 0
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if entries == u32::MAX {
        if size != 44 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(None);
    }
    if entries > 128 || size != 44 + entries as usize * 24 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(Some(data))
}
/// Validated borrowed native security bytes; absence stays distinct from an empty ACL.
pub(super) fn read_acl(fd: RawFd, default: bool, buffer: &mut [u8]) -> io::Result<Option<&[u8]>> {
    #[cfg(target_os = "macos")]
    {
        if default {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut attrs = attributes();
        cvt(unsafe {
            libc::fgetattrlist(
                fd,
                (&mut attrs as *mut libc::attrlist).cast(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        })?;
        parse_mac_acl(buffer)
    }
    #[cfg(target_os = "linux")]
    {
        let name = if default { c"system.posix_acl_default" } else { c"system.posix_acl_access" };
        let n = unsafe { libc::fgetxattr(fd, name.as_ptr(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENODATA) {
                return Ok(None);
            }
            return Err(error);
        }
        let n = n as usize;
        if n > buffer.len() || n < 4 || (n - 4) & 7 != 0 || u32::from_le_bytes(buffer[..4].try_into().unwrap()) != 2 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Some(&buffer[..n]))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (fd, default, buffer);
        Err(io::ErrorKind::Unsupported.into())
    }
}
#[cfg(any(target_os = "macos", test))]
pub(super) fn private_acl(fd: RawFd, buffer: &mut [u8]) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        Ok(read_acl(fd, false, buffer)?.is_none_or(|data| u32::from_ne_bytes(data[36..40].try_into().unwrap()) == 0))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (fd, buffer);
        Ok(true)
    }
}

/// A fully formed native request, prepared without I/O before its single charged call.
pub(super) struct PreparedAcl<'a> {
    #[cfg(target_os = "macos")]
    bytes: &'a mut [u8],
    #[cfg(not(target_os = "macos"))]
    data: Option<&'a [u8]>,
}
pub(super) fn prepare_acl_write<'a>(data: Option<&'a [u8]>, scratch: &'a mut [u8]) -> io::Result<PreparedAcl<'a>> {
    #[cfg(target_os = "macos")]
    {
        if let Some(data) = data {
            validate_mac_security(data)?;
        }
        let n = data.map_or(44, <[u8]>::len);
        let total = 8usize.checked_add(n).ok_or(io::ErrorKind::InvalidData)?;
        if total > scratch.len() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        scratch[..total].fill(0);
        scratch[..4].copy_from_slice(&8i32.to_ne_bytes());
        scratch[4..8].copy_from_slice(&(n as u32).to_ne_bytes());
        if let Some(data) = data {
            scratch[8..total].copy_from_slice(data);
        } else {
            scratch[8..12].copy_from_slice(&0x012cc16du32.to_ne_bytes());
            scratch[44..48].copy_from_slice(&u32::MAX.to_ne_bytes());
        }
        Ok(PreparedAcl { bytes: &mut scratch[..total] })
    }
    #[cfg(target_os = "linux")]
    {
        let _ = scratch;
        // Each native entry occupies eight bytes; bitmask preserves the
        // existing MSRV while rejecting incomplete serialized records.
        if let Some(data) = data
            && (data.len() < 4
                || data.len() > 65536
                || (data.len() - 4) & 7 != 0
                || u32::from_le_bytes(data[..4].try_into().unwrap()) != 2)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(PreparedAcl { data })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (data, scratch);
        Err(io::ErrorKind::Unsupported.into())
    }
}
impl PreparedAcl<'_> {
    pub(super) fn apply(self, fd: RawFd) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let mut attrs = attributes();
            cvt(unsafe {
                libc::fsetattrlist(
                    fd,
                    (&mut attrs as *mut libc::attrlist).cast(),
                    self.bytes.as_mut_ptr().cast(),
                    self.bytes.len(),
                    0,
                )
            })
            .map(|_| ())
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(data) = self.data {
                cvt(unsafe {
                    libc::fsetxattr(fd, c"system.posix_acl_access".as_ptr(), data.as_ptr().cast(), data.len(), 0)
                })
                .map(|_| ())
            } else {
                match cvt(unsafe { libc::fremovexattr(fd, c"system.posix_acl_access".as_ptr()) }) {
                    Err(error) if error.raw_os_error() == Some(libc::ENODATA) => Ok(()),
                    result => result.map(|_| ()),
                }
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (self, fd);
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}

/// Fixed procfd spelling. Its identity is checked separately against the live
/// descriptor; this string alone is never treated as native identity evidence.
#[cfg(any(target_os = "linux", test))]
pub(super) fn procfd_path(fd: std::os::fd::RawFd, bytes: &mut [u8; 64]) -> io::Result<&CStr> {
    if fd < 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let prefix = b"/proc/self/fd/";
    let mut value = fd as u32;
    let mut at = bytes.len();
    loop {
        at -= 1;
        bytes[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let digits = bytes.len() - at;
    bytes.copy_within(at.., prefix.len());
    bytes[..prefix.len()].copy_from_slice(prefix);
    let len = prefix.len() + digits;
    bytes[len] = 0;
    CStr::from_bytes_with_nul(&bytes[..=len]).map_err(|_| io::ErrorKind::InvalidData.into())
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn path_stat(path: &CStr) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::uninit();
    cvt(unsafe { libc::stat(path.as_ptr(), stat.as_mut_ptr()) })?;
    Ok(unsafe { stat.assume_init() })
}

/// One namespace mutation; no no-clobber fallback or retry after ambiguity.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) fn rename_file(
    from: std::os::fd::RawFd,
    leaf: &CStr,
    to: std::os::fd::RawFd,
    target: &CStr,
    replace: bool,
) -> io::Result<()> {
    if replace {
        return cvt(unsafe { libc::renameat(from, leaf.as_ptr(), to, target.as_ptr()) }).map(|_| ());
    }
    #[cfg(target_os = "macos")]
    let result =
        unsafe { libc::renameatx_np(from, leaf.as_ptr(), to, target.as_ptr(), libc::RENAME_EXCL) } as libc::c_long;
    #[cfg(target_os = "linux")]
    let result =
        unsafe { libc::syscall(libc::SYS_renameat2, from, leaf.as_ptr(), to, target.as_ptr(), libc::RENAME_NOREPLACE) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
