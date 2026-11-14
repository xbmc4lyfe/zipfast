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

//! First-party component walks; no following stat of the whole original input.
use super::*;
use std::{ffi::CStr, os::unix::ffi::OsStrExt};
const H: usize = libc::PATH_MAX as usize;
const S: usize = 33;
const MAX_VISITS: usize = (S + 1) * (H + 1);
const RESOLVED: usize = H;
const SAVED: usize = 5 * H;
type Failure = CanonicalFailure;

#[cfg(test)]
thread_local! { pub(super) static BETWEEN_PASSES: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const {std::cell::RefCell::new(None)}; }

fn malformed() -> Failure {
    Failure::Terminal(ReadFault::CheckedFormat { reason: "inconsistent or malformed canonical namespace observation" })
}
fn ordinary(code: i32) -> Failure {
    Failure::Ordinary(ReadFault::Io {
        stage: IoStage::SourcePath,
        operation: ReadIoOperation::Stat,
        offset: 0,
        error: std::io::Error::from_raw_os_error(code),
    })
}
fn cstr(bytes: &[u8]) -> Result<&CStr, Failure> {
    CStr::from_bytes_with_nul(bytes).map_err(|_| malformed())
}
struct Calls<'a, F> {
    meter: &'a mut F,
    retries: u64,
    cancel: &'a Cancellation,
}
impl<F: FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>> Calls<'_, F> {
    fn call<T>(&mut self, op: CanonicalOperation, mut call: impl FnMut() -> std::io::Result<T>) -> Result<T, Failure> {
        let mut retries = 0u64;
        loop {
            io::canceled(Some(self.cancel)).map_err(Failure::Terminal)?;
            (self.meter)(op, retries == 0).map_err(Failure::Terminal)?;
            match call() {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    retries = retries.checked_add(1).ok_or(Failure::Terminal(ReadFault::CounterOverflow))?;
                    budget::admit(ReadResource::InterruptedRetries, self.retries.into(), retries.into())
                        .map_err(Failure::Terminal)?;
                }
                Err(error) => {
                    return Err(Failure::Ordinary(ReadFault::Io {
                        stage: IoStage::SourcePath,
                        operation: if matches!(op, CanonicalOperation::ReadLink) {
                            ReadIoOperation::Read
                        } else {
                            ReadIoOperation::Stat
                        },
                        offset: 0,
                        error,
                    }));
                }
            }
        }
    }
    fn stat(&mut self, op: CanonicalOperation, path: &CStr) -> Result<libc::stat, Failure> {
        self.call(op, || {
            let mut s = std::mem::MaybeUninit::uninit();
            native_policy::cvt(unsafe { libc::lstat(path.as_ptr(), s.as_mut_ptr()) })?;
            Ok(unsafe { s.assume_init() })
        })
    }
}
struct Facts<'a> {
    name: &'a [u8],
    dev: u64,
    kind: u32,
    full: Option<CanonicalIdentity>,
}
fn native_facts(bytes: &[u8]) -> Result<Facts<'_>, Failure> {
    if bytes.len() < 28 {
        return Err(malformed());
    }
    let u = |i| u32::from_ne_bytes(bytes[i..i + 4].try_into().unwrap());
    let total = u(0) as usize;
    let off = u(4) as i32;
    let len = u(8) as usize;
    if total > bytes.len() || total < 28 || off < 24 || len == 0 {
        return Err(malformed());
    }
    let begin = 4usize.checked_add(off as usize).ok_or_else(malformed)?;
    let end = begin.checked_add(len).ok_or_else(malformed)?;
    if end > total {
        return Err(malformed());
    }
    let name = &bytes[begin..end];
    if name.last() != Some(&0) || name[..len - 1].contains(&0) {
        return Err(malformed());
    }
    let kind = match u(16) {
        1 => libc::S_IFREG,
        2 => libc::S_IFDIR,
        3 => libc::S_IFBLK,
        4 => libc::S_IFCHR,
        5 => libc::S_IFLNK,
        6 => libc::S_IFSOCK,
        7 => libc::S_IFIFO,
        _ => return Err(malformed()),
    } as u32;
    Ok(Facts { name: &name[..len - 1], dev: u(12) as libc::dev_t as u64, kind, full: None })
}
fn component<'a, F: FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>>(
    calls: &mut Calls<'_, F>,
    path: &CStr,
    requested: &'a [u8],
    attrs: &'a mut [u8],
) -> Result<Facts<'a>, Failure> {
    let result = calls.call(CanonicalOperation::ComponentName, || {
        let mut list = libc::attrlist {
            bitmapcount: 5,
            reserved: 0,
            commonattr: 1 | 2 | 8 | 32,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        native_policy::cvt(unsafe {
            libc::getattrlist(
                path.as_ptr(),
                (&mut list as *mut libc::attrlist).cast(),
                attrs.as_mut_ptr().cast(),
                attrs.len(),
                1,
            )
        })
    });
    match result {
        Ok(_) => native_facts(attrs),
        Err(Failure::Ordinary(ReadFault::Io { error, .. }))
            if matches!(error.raw_os_error(), Some(libc::ENOTSUP) | Some(libc::EINVAL)) =>
        {
            let s = calls.stat(CanonicalOperation::ComponentStat, path)?;
            let identity = CanonicalIdentity::of(&s);
            Ok(Facts { name: requested, dev: identity.dev, kind: identity.kind, full: Some(identity) })
        }
        Err(error) => Err(error),
    }
}
fn append(buffer: &mut [u8], prefix: usize, name: &[u8]) -> Result<usize, Failure> {
    let sep = usize::from(prefix > 1);
    let end =
        prefix.checked_add(sep).and_then(|v| v.checked_add(name.len())).ok_or_else(|| ordinary(libc::ENAMETOOLONG))?;
    if end >= buffer.len() {
        return Err(ordinary(libc::ENAMETOOLONG));
    }
    if sep != 0 {
        buffer[prefix] = b'/';
    }
    buffer[prefix + sep..end].copy_from_slice(name);
    buffer[end] = 0;
    Ok(end)
}
fn mount_spelling<F: FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>>(
    calls: &mut Calls<'_, F>,
    path: &CStr,
    identity: CanonicalIdentity,
    resolved: &mut [u8],
    prefix: &mut [u8],
    storage: &mut [u8],
) -> Result<Option<usize>, Failure> {
    if storage.len() < std::mem::size_of::<libc::statfs>()
        || storage.as_ptr().align_offset(std::mem::align_of::<libc::statfs>()) != 0
    {
        return Err(Failure::Terminal(ReadFault::InvalidPlan));
    }
    let pointer = storage.as_mut_ptr().cast::<libc::statfs>();
    calls.call(CanonicalOperation::MountInfo, || {
        native_policy::cvt(unsafe { libc::statfs(path.as_ptr(), pointer) }).map(|_| ())
    })?;
    // SAFETY: aligned exact native storage was initialized by successful statfs;
    // its character array is valid as bytes and remains inside phase scratch.
    let fs = unsafe { &*pointer };
    let raw = unsafe { std::slice::from_raw_parts(fs.f_mntonname.as_ptr().cast::<u8>(), fs.f_mntonname.len()) };
    let len = raw.iter().position(|b| *b == 0).ok_or_else(malformed)?;
    if len == 0 || raw[0] != b'/' || len >= H {
        return Err(malformed());
    }
    let mounted = cstr(&raw[..=len])?;
    let observed = match calls.stat(CanonicalOperation::MountRootStat, mounted) {
        Ok(s) => CanonicalIdentity::of(&s),
        Err(Failure::Ordinary(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    if observed != identity {
        return Ok(None);
    }
    // Validate every strict reported prefix with nofollow observations.
    prefix[..=len].copy_from_slice(&raw[..=len]);
    for i in 1..len {
        if prefix[i] != b'/' {
            continue;
        }
        prefix[i] = 0;
        let s = calls.stat(CanonicalOperation::MountPrefixStat, cstr(&prefix[..=i])?);
        prefix[i] = b'/';
        match s {
            Ok(s) if s.st_mode & libc::S_IFMT == libc::S_IFDIR => {}
            Ok(_) | Err(Failure::Ordinary(_)) => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    resolved[..=len].copy_from_slice(&raw[..=len]);
    Ok(Some(len))
}
fn walk<F: FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>>(
    original: &[u8],
    cwd: &[u8],
    scratch: &mut [u8],
    calls: &mut Calls<'_, F>,
) -> Result<(usize, CanonicalIdentity), Failure> {
    if original.is_empty() {
        return Err(ordinary(libc::ENOENT));
    }
    if original.contains(&0) || cwd.contains(&0) {
        return Err(ordinary(libc::EINVAL));
    }
    let (pending, rest) = scratch.split_at_mut(H);
    let (resolved, rest) = rest.split_at_mut(H);
    let (link, rest) = rest.split_at_mut(H);
    let (attrs, rest) = rest.split_at_mut(2 * H);
    let (_, rest) = rest.split_at_mut(H); // Saved first result survives pass2.
    let (mount_path, rest) = rest.split_at_mut(H);
    let (mount_prefix, mount_storage) = rest.split_at_mut(H);
    let mut len = if original[0] == b'/' {
        if original.len() >= H {
            return Err(ordinary(libc::ENAMETOOLONG));
        }
        pending[..original.len()].copy_from_slice(original);
        original.len()
    } else {
        if cwd.first() != Some(&b'/') {
            return Err(malformed());
        }
        let total = cwd
            .len()
            .checked_add(original.len())
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| ordinary(libc::ENAMETOOLONG))?;
        if total >= H {
            return Err(ordinary(libc::ENAMETOOLONG));
        }
        pending[..cwd.len()].copy_from_slice(cwd);
        pending[cwd.len()] = b'/';
        pending[cwd.len() + 1..total].copy_from_slice(original);
        total
    };
    resolved[0] = b'/';
    resolved[1] = 0;
    let root = calls.stat(CanonicalOperation::RootStat, c"/")?;
    let mut current = CanonicalIdentity::of(&root);
    if current.kind != libc::S_IFDIR as u32 {
        return Err(malformed());
    }
    let mut prefix = 1;
    let mut cursor = 0;
    let mut links = 0;
    let mut visits = 0usize;
    let mut terminal = None;
    while cursor < len {
        while cursor < len && pending[cursor] == b'/' {
            cursor += 1;
        }
        if cursor == len {
            break;
        }
        visits = visits.checked_add(1).ok_or(Failure::Terminal(ReadFault::CounterOverflow))?;
        if visits > MAX_VISITS {
            return Err(malformed());
        }
        io::canceled(Some(calls.cancel)).map_err(Failure::Terminal)?;
        let start = cursor;
        while cursor < len && pending[cursor] != b'/' {
            cursor += 1;
        }
        let end = cursor;
        let requested = &pending[start..end];
        if requested == b"." {
            terminal = None;
            continue;
        }
        if requested == b".." {
            if prefix > 1 {
                prefix = resolved[..prefix].iter().rposition(|b| *b == b'/').unwrap_or(0).max(1);
                resolved[prefix] = 0;
            }
            let s = calls.stat(CanonicalOperation::ComponentStat, cstr(&resolved[..=prefix])?)?;
            current = CanonicalIdentity::of(&s);
            if current.kind != libc::S_IFDIR as u32 {
                return Err(malformed());
            }
            terminal = None;
            continue;
        }
        // Darwin canonicalization consumes dot/dot-dot and trailing separators
        // logically, including after a non-directory; a real child still requires a directory.
        if current.kind != libc::S_IFDIR as u32 {
            return Err(ordinary(libc::ENOTDIR));
        }
        let before = prefix;
        let candidate = append(resolved, prefix, requested)?;
        let mut facts = component(calls, cstr(&resolved[..=candidate])?, requested, attrs)?;
        if facts.kind == libc::S_IFLNK as u32 {
            if links == S {
                return Err(ordinary(libc::ELOOP));
            }
            let n = calls.call(CanonicalOperation::ReadLink, || {
                let n = unsafe { libc::readlink(resolved.as_ptr().cast(), link.as_mut_ptr().cast(), link.len()) };
                if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
            })?;
            if n == 0 {
                return Err(ordinary(libc::ENOENT));
            }
            if n >= H {
                return Err(ordinary(libc::ENAMETOOLONG));
            }
            if link[..n].contains(&0) {
                return Err(malformed());
            }
            links += 1;
            let suffix = len - end;
            let total = n.checked_add(suffix).ok_or_else(|| ordinary(libc::ENAMETOOLONG))?;
            if total >= H {
                return Err(ordinary(libc::ENAMETOOLONG));
            }
            pending.copy_within(end..len, n);
            pending[..n].copy_from_slice(&link[..n]);
            len = total;
            cursor = 0;
            terminal = None;
            prefix = if link[0] == b'/' {
                current = CanonicalIdentity::of(&root);
                1
            } else {
                before
            };
            resolved[prefix] = 0;
            continue;
        }
        let last = pending[end..len].iter().all(|b| *b == b'/');
        if facts.dev != current.dev || last {
            let full = match facts.full {
                Some(id) => id,
                None => CanonicalIdentity::of(&calls.stat(
                    if last { CanonicalOperation::TerminalRequestedStat } else { CanonicalOperation::ComponentStat },
                    cstr(&resolved[..=candidate])?,
                )?),
            };
            if full.dev != facts.dev || full.kind != facts.kind || full.kind == libc::S_IFLNK as u32 {
                return Err(malformed());
            }
            facts.full = Some(full);
        }
        let mut mounted = None;
        if facts.dev != current.dev {
            // This component crossed devices; validate the kernel mount spelling.
            mount_path[..=candidate].copy_from_slice(&resolved[..=candidate]);
            mounted = mount_spelling(
                calls,
                cstr(&mount_path[..=candidate])?,
                facts.full.ok_or_else(malformed)?,
                resolved,
                mount_prefix,
                mount_storage,
            )?;
        }
        if let Some(n) = mounted {
            prefix = n;
        } else {
            if facts.name.is_empty() || facts.name.contains(&b'/') || facts.name == b"." || facts.name == b".." {
                return Err(malformed());
            }
            prefix = append(resolved, before, facts.name)?;
        }
        current = CanonicalIdentity { dev: facts.dev, ino: facts.full.map_or(0, |id| id.ino), kind: facts.kind };
        terminal = if last { facts.full } else { None };
    }
    let expected = match terminal {
        Some(id) => id,
        None => {
            CanonicalIdentity::of(&calls.stat(CanonicalOperation::TerminalRequestedStat, cstr(&resolved[..=prefix])?)?)
        }
    };
    let actual = CanonicalIdentity::of(&calls.stat(CanonicalOperation::TerminalStat, cstr(&resolved[..=prefix])?)?);
    if actual != expected || actual.kind == libc::S_IFLNK as u32 {
        return Err(malformed());
    }
    Ok((prefix, actual))
}
/// Two fresh original-spelling walks share one admitted phase scratch window.
pub(in crate::zip::read) fn canonicalize(
    path: &Path,
    cwd: &Path,
    scratch: &mut [u8],
    retries: u64,
    cancel: &Cancellation,
    meter: &mut impl FnMut(CanonicalOperation, bool) -> Result<(), ReadFault>,
) -> Result<CanonicalEvidence, Failure> {
    if scratch.len() != 65536 || scratch.as_ptr().align_offset(std::mem::align_of::<libc::statfs>()) != 0 {
        return Err(Failure::Terminal(ReadFault::InvalidPlan));
    }
    let mut calls = Calls { meter, retries, cancel };
    let (len, identity) = walk(path.as_os_str().as_bytes(), cwd.as_os_str().as_bytes(), scratch, &mut calls)?;
    scratch.copy_within(RESOLVED..RESOLVED + len, SAVED);
    #[cfg(test)]
    {
        let mut hook = BETWEEN_PASSES.with(|state| state.borrow_mut().take());
        if let Some(callback) = hook.as_mut() {
            callback();
        }
        BETWEEN_PASSES.with(|state| *state.borrow_mut() = hook);
    }
    let (second, observed) = walk(path.as_os_str().as_bytes(), cwd.as_os_str().as_bytes(), scratch, &mut calls)
        .map_err(|e| match e {
            Failure::Ordinary(f) | Failure::Terminal(f) => Failure::Terminal(f),
        })?;
    if second != len || observed != identity || scratch[RESOLVED..RESOLVED + len] != scratch[SAVED..SAVED + len] {
        return Err(malformed());
    }
    Ok(CanonicalEvidence { identity, start: RESOLVED, len })
}

#[cfg(test)]
pub(super) fn layout() -> [usize; 4] {
    [65536, 8 * H + std::mem::size_of::<libc::statfs>(), H, 2 * ((H + 4) * MAX_VISITS + S + 8)]
}
