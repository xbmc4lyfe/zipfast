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

//! Prepared raw paths for split transaction checks after publication begins.
use super::*;

pub(in crate::zip::create) struct Probe {
    path: Vec<u8>,
}
impl Probe {
    pub(in crate::zip::create) fn new(path: &Path) -> Result<Self> {
        let raw = path.as_os_str().as_bytes();
        if raw.contains(&0) {
            return Err(CreateError::InvalidDestination);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(raw.len().checked_add(1).ok_or(CreateError::Overflow)?)?;
        bytes.extend_from_slice(raw);
        bytes.push(0);
        Ok(Self { path: bytes })
    }
    pub(in crate::zip::create) fn capacity(&self) -> u64 {
        self.path.capacity() as u64
    }
    pub(in crate::zip::create) fn stamp(&self, directory: bool, follow: bool, budget: &Attempts<'_>) -> Result<Stamp> {
        budget.run(|| {
            let mut meta = MaybeUninit::<NativeStat>::uninit();
            // The prepared C string stays alive; stat initializes meta only on success.
            status(unsafe {
                native_fstatat(
                    libc::AT_FDCWD,
                    self.path.as_ptr().cast(),
                    meta.as_mut_ptr(),
                    if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW },
                )
            })?;
            let meta = unsafe { meta.assume_init() };
            let kind = if directory { libc::S_IFDIR } else { libc::S_IFREG };
            if meta.st_mode & libc::S_IFMT != kind {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            Ok(Stamp::from_stat(&meta))
        })
    }
}

pub(in crate::zip::create) fn create(
    parent: &Parent,
    leaf: &CStr,
    budget: &Attempts<'_>,
    counter: &std::cell::Cell<u64>,
) -> Result<File> {
    // This is a single attempted mutation. Interrupted/ambiguous opens are not retried.
    budget.charge()?;
    counter.set(counter.get() + 1);
    #[cfg(test)]
    super::super::tests::event(super::super::tests::Event::StageOpen, None)?;
    let flags = libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CLOEXEC | LARGE_FILE;
    opened(unsafe { libc::openat(parent.file.as_raw_fd(), leaf.as_ptr(), flags, 0o600 as libc::c_int) })
        .map_err(Into::into)
}

pub(in crate::zip::create) fn component_limit(parent: &Parent, budget: &Attempts<'_>) -> Result<Option<u64>> {
    budget.run(|| {
        // A negative unlimited/indeterminate result is left to the actual no-replace syscall.
        let value = unsafe { libc::fpathconf(parent.file.as_raw_fd(), libc::_PC_NAME_MAX) };
        Ok((value >= 0).then_some(value as u64))
    })
}
