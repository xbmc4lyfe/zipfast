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

use super::*;
use std::ffi::OsStr;
use std::mem::MaybeUninit;
use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Stamp {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
    pub mode: libc::mode_t,
    pub links: u64,
}
impl Stamp {
    fn identity(self) -> (u64, u64) {
        (self.dev, self.ino)
    }
    fn directory(self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }
    fn regular(self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }
    pub(super) fn source(self) -> SourceStamp {
        SourceStamp { device: self.dev, inode: self.ino, len: self.len, mtime: self.mtime, ctime: self.ctime }
    }
}
fn convert(s: libc::stat) -> io::Result<Stamp> {
    #[cfg(target_os = "macos")]
    let (mtime, ctime) = ((s.st_mtime, s.st_mtime_nsec), (s.st_ctime, s.st_ctime_nsec));
    #[cfg(not(target_os = "macos"))]
    let (mtime, ctime) = ((s.st_mtime, s.st_mtime_nsec), (s.st_ctime, s.st_ctime_nsec));
    #[cfg(target_os = "macos")]
    let device = s.st_dev as u64;
    #[cfg(not(target_os = "macos"))]
    let device = s.st_dev;
    #[allow(
        clippy::useless_conversion,
        reason = "libc st_nlink is u16 on macOS, u32 on Linux ARM64 and u64 on Linux AMD64"
    )]
    let links = u64::from(s.st_nlink);
    Ok(Stamp {
        links,
        dev: device,
        ino: s.st_ino,
        len: u64::try_from(s.st_size).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
        mtime,
        ctime,
        mode: s.st_mode,
    })
}
pub(super) fn stat_fd(file: &File) -> io::Result<Stamp> {
    let mut out = MaybeUninit::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), out.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    convert(unsafe { out.assume_init() })
}
pub(super) fn stat_at(fd: libc::c_int, path: &[u8]) -> io::Result<Option<Stamp>> {
    stat_at_flags(fd, path, libc::AT_SYMLINK_NOFOLLOW)
}
pub(super) fn stat_at_flags(fd: libc::c_int, path: &[u8], flags: libc::c_int) -> io::Result<Option<Stamp>> {
    stat_at_probe(fd, path, flags, true)
}
fn stat_at_probe(fd: libc::c_int, path: &[u8], flags: libc::c_int, missing_parent: bool) -> io::Result<Option<Stamp>> {
    let mut out = MaybeUninit::uninit();
    let result = unsafe { libc::fstatat(fd, path.as_ptr().cast(), out.as_mut_ptr(), flags) };
    if result < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) || (missing_parent && e.raw_os_error() == Some(libc::ENOTDIR)) {
            return Ok(None);
        }
        return Err(e);
    }
    convert(unsafe { out.assume_init() }).map(Some)
}
pub(super) fn search_flags() -> libc::c_int {
    #[cfg(target_os = "macos")]
    let access = libc::O_SEARCH;
    #[cfg(not(target_os = "macos"))]
    let access = libc::O_PATH;
    access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
}
struct Record {
    path: Vec<u8>,
    expected: Option<Stamp>,
    original: Option<(u64, u64)>,
    stage: Option<(u64, u64)>,
    ordinal: Option<u64>,
    leaf: bool,
    follow: bool,
}
struct SourceProbe {
    path: Vec<u8>,
}
#[derive(Clone, Copy)]
struct PendingUnlink {
    index: usize,
    old: Stamp,
}
#[derive(Default)]
pub(super) struct Guard {
    pub(super) anchor: Option<File>,
    records: Vec<Record>,
    sources: Vec<SourceProbe>,
    prepared: bool,
    identity: Option<(u64, u64)>,
    deferred: Option<RarDiagnosticFailure>,
    pending_unlink: Option<PendingUnlink>,
    pending_publication: Option<usize>,
}
fn metadata(source: io::Error) -> RarDiagnosticFailure {
    RarDiagnosticFailure::Metadata { operation: IoOperation::Metadata, source }
}
fn checked(a: u64, b: u64) -> Result<u64, RarDiagnosticFailure> {
    a.checked_add(b).ok_or(RarDiagnosticFailure::CounterOverflow)
}
// Restores ownership even if a probe/fault hook unwinds; cleanup must never
// devolve into an unobserved File drop for a newly introduced handle.
struct GuardLease<'a> {
    control: &'a mut RarExtractControl,
    guard: Option<Guard>,
}
impl Drop for GuardLease<'_> {
    fn drop(&mut self) {
        self.control.guard = self.guard.take().expect("guard lease");
        if std::thread::panicking() {
            self.control.release_guard();
        }
    }
}
impl RarExtractControl {
    fn with_guard<T>(&mut self, f: impl FnOnce(&mut Guard, &mut RarExtractControl) -> T) -> T {
        let guard = std::mem::take(&mut self.guard);
        let mut lease = GuardLease { control: self, guard: Some(guard) };
        f(lease.guard.as_mut().expect("guard lease"), lease.control)
    }

    pub(super) fn proof_work(&mut self, n: u64) -> Result<(), RarDiagnosticFailure> {
        let next = checked(self.usage.diagnostics.work, n)?;
        if next > self.limits.diagnostics.work {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Work));
        }
        self.usage.diagnostics.work = next;
        Ok(())
    }
    fn proof_io(&mut self, checkpoint: &mut u64) -> Result<(), RarDiagnosticFailure> {
        let next = checked(self.usage.diagnostics.io_attempts, 1)?;
        let local = checked(*checkpoint, 1)?;
        if next > self.limits.diagnostics.io_attempts {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::IoAttempts));
        }
        if local > self.limits.diagnostics.checkpoint_attempts {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::CheckpointAttempts));
        }
        self.usage.diagnostics.io_attempts = next;
        *checkpoint = local;
        self.usage.diagnostics.checkpoint_attempts_peak = self.usage.diagnostics.checkpoint_attempts_peak.max(local);
        Ok(())
    }
    fn proof_capacity(&mut self, bytes: u64) -> Result<(), RarDiagnosticFailure> {
        let next = checked(self.usage.diagnostics.capacity, bytes)?;
        if next > self.limits.diagnostics.capacity {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
        }
        self.usage.diagnostics.capacity = next;
        self.usage.diagnostics.capacity_peak = self.usage.diagnostics.capacity_peak.max(next);
        Ok(())
    }
    fn reserve_proof<T>(&mut self, items: &mut Vec<T>, additional: usize) -> Result<(), RarDiagnosticFailure> {
        let wanted = items.len().checked_add(additional).ok_or(RarDiagnosticFailure::CounterOverflow)?;
        if wanted <= items.capacity() {
            return Ok(());
        }
        let old = items.capacity();
        let minimum = wanted
            .checked_sub(old)
            .and_then(|v| v.checked_mul(size_of::<T>()))
            .ok_or(RarDiagnosticFailure::CounterOverflow)?;
        let current = self.usage.diagnostics.capacity;
        let requested = checked(current, minimum as u64)?;
        if requested > self.limits.diagnostics.capacity {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
        }
        items.try_reserve_exact(additional).map_err(RarDiagnosticFailure::Allocation)?;
        self.usage.diagnostics.capacity = current;
        self.proof_capacity(
            items
                .capacity()
                .checked_sub(old)
                .and_then(|v| v.checked_mul(size_of::<T>()))
                .ok_or(RarDiagnosticFailure::CounterOverflow)? as u64,
        )
    }
    fn proof_path(&mut self, path: &[u8]) -> Result<Vec<u8>, RarDiagnosticFailure> {
        self.proof_work(
            (path.len() as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or(RarDiagnosticFailure::CounterOverflow)?,
        )?;
        if path.contains(&0) {
            return Err(metadata(io::Error::from_raw_os_error(libc::EINVAL)));
        }
        let mut out = Vec::new();
        self.reserve_proof(&mut out, path.len().checked_add(1).ok_or(RarDiagnosticFailure::CounterOverflow)?)?;
        out.extend_from_slice(path);
        out.push(0);
        Ok(out)
    }
    pub(super) fn prepare(
        &mut self,
        session: &RarSession,
        selection: &RarSelection,
        options: &crate::extract::Options,
    ) {
        if matches!(self.state, RarDiagnosticState::Muted(_) | RarDiagnosticState::Closed) {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.prepare(c, session, selection, options, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    pub(super) fn refresh(&mut self, sources: Option<&[HeldVolume]>) -> Result<(), RarDiagnosticFailure> {
        let checkpoints = checked(self.usage.diagnostics.checkpoints, 1)?;
        self.usage.diagnostics.checkpoints = checkpoints;
        let mut attempts = 0;
        self.with_guard(|guard, c| guard.refresh(c, sources, &mut attempts))
    }
    pub(super) fn capture_before_path(&mut self, index: usize) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.before_path(c, index, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    pub(super) fn capture_before_directories(&mut self) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.check_followed(c, &mut attempts));
        if let Err(failure) = result {
            self.mute(failure);
        }
    }
    pub(super) fn capture_created(&mut self, path: &Path) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.created(c, path, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
    pub(super) fn capture_stage(&mut self, index: usize, stamp: SourceStamp) {
        if self.failure.is_some() {
            return;
        }
        let identity = (stamp.device, stamp.inode);
        for i in 0..self.guard.records.len() {
            if let Err(failure) = self.proof_work(1) {
                self.mute(failure);
                return;
            }
            let r = &mut self.guard.records[i];
            if r.leaf && r.ordinal == Some(index as u64) {
                r.stage = Some(identity);
            }
        }
        if self.guard.identity == Some(identity) {
            self.mute(RarDiagnosticFailure::AliasTarget { ordinal: index as u64 });
        }
    }
    pub(super) fn capture_before_publication(&mut self, index: usize, initial: Option<SourceStamp>) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.before_publication(c, index, initial, &mut attempts));
        if let Err(failure) = result {
            self.mute(failure);
        }
    }
    pub(super) fn capture_published(&mut self, index: usize, target: &Path, held: &File, published: bool) {
        if !self.guard.prepared || self.failure.is_some() {
            return;
        }
        if !published {
            return;
        }
        let mut attempts = 0;
        let result = self.with_guard(|guard, c| guard.published(c, index, target, held, &mut attempts));
        if let Err(f) = result {
            self.mute(f);
        }
    }
}
impl Guard {
    fn classify(&mut self, c: &mut RarExtractControl, attempts: &mut u64) -> Result<bool, RarDiagnosticFailure> {
        if c.diagnostic.is_none() {
            return Err(RarDiagnosticFailure::NoDescriptor);
        }
        c.proof_work(1)?;
        c.proof_io(attempts)?;
        let file = c.diagnostic.as_ref().expect("diagnostic exists");
        let stamp = stat_fd(file).map_err(metadata)?;
        if stamp.regular() {
            if self.identity.is_some_and(|identity| identity != stamp.identity()) {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: None });
            }
            self.identity = Some(stamp.identity());
            Ok(true)
        } else if [libc::S_IFCHR, libc::S_IFIFO, libc::S_IFSOCK].contains(&(stamp.mode & libc::S_IFMT)) {
            c.state = RarDiagnosticState::AllowedByKind;
            Ok(false)
        } else {
            Err(RarDiagnosticFailure::UnsupportedKind)
        }
    }
    fn prepare(
        &mut self,
        c: &mut RarExtractControl,
        session: &RarSession,
        selection: &RarSelection,
        options: &crate::extract::Options,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        if !self.classify(c, attempts)? {
            return Ok(());
        }
        // Known aliases are examined before namespace binding faults.
        for (i, volume) in session.volumes.iter().enumerate() {
            c.proof_work(1)?;
            if self.identity == Some((volume.stamp.device, volume.stamp.inode)) {
                return Err(RarDiagnosticFailure::AliasInput { volume: i as u64 });
            }
        }
        c.handle_admission(RarControlHandleKind::Guard).map_err(|e| match e {
            RarExtractControlError::CounterOverflow => RarDiagnosticFailure::CounterOverflow,
            _ => RarDiagnosticFailure::Limit(RarDiagnosticLimit::OpenHandles),
        })?;
        c.proof_io(attempts)?;
        self.anchor = Some(
            handles::open_search(b"/\0")
                .map_err(|source| RarDiagnosticFailure::Metadata { operation: IoOperation::Open, source })?,
        );
        c.acquired(RarControlHandleKind::Guard);
        for volume in &session.volumes {
            c.proof_work(1)?;
            c.reserve_proof(&mut self.sources, 1)?;
            let path = c.proof_path(volume.path.as_os_str().as_bytes())?;
            self.sources.push(SourceProbe { path });
        }
        let cwd = cwd(c, attempts)?;
        for (word, mut bits) in selection.bits.iter().copied().enumerate() {
            c.proof_work(1)?;
            while bits != 0 {
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let header = &session.members[index].header;
                // Precharge a conservative bound for UTF-8 validation,
                // component splitting, normalization, copying and final parsing.
                let name_work = checked(header.name.len() as u64, session.members[index].wire.name.len() as u64)?
                    .checked_mul(8)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(RarDiagnosticFailure::CounterOverflow)?;
                c.proof_work(name_work)?;
                if header.is_dir() && options.flatten {
                    continue;
                }
                let targets = checked(c.usage.diagnostics.targets, 1)?;
                if targets > c.limits.diagnostics.targets {
                    return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Targets));
                }
                if header.name.contains('\u{fffe}') || std::str::from_utf8(&session.members[index].wire.name).is_err() {
                    return Err(RarDiagnosticFailure::ProjectionUnavailable { ordinal: index as u64 });
                }
                // Temporary projection capacity is charged while live, then released.
                if checked(c.usage.diagnostics.capacity, header.name.len() as u64)? > c.limits.diagnostics.capacity {
                    return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
                }
                let relative =
                    crate::path::sanitize_fallible(&header.name, !header.is_unix()).map_err(|e| match e {
                        crate::path::ProjectionError::Unsafe => {
                            RarDiagnosticFailure::ProjectionUnavailable { ordinal: index as u64 }
                        }
                        crate::path::ProjectionError::Allocation(e) => RarDiagnosticFailure::Allocation(e),
                    })?;
                c.proof_capacity(relative.capacity() as u64)?;
                let projection_work =
                    checked(options.dest.as_os_str().len() as u64, relative.as_os_str().len() as u64)?
                        .checked_mul(4)
                        .and_then(|n| n.checked_add(2))
                        .ok_or(RarDiagnosticFailure::CounterOverflow)?;
                c.proof_work(projection_work)?;
                let target_capacity = super::super::extraction::target_capacity(options, &relative, options.flatten)
                    .ok_or(RarDiagnosticFailure::CounterOverflow)?;
                if checked(c.usage.diagnostics.capacity, target_capacity as u64)? > c.limits.diagnostics.capacity {
                    return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Capacity));
                }
                c.proof_work(target_capacity as u64)?;
                let native_target =
                    super::super::extraction::project_target(options, &relative, options.flatten, target_capacity)
                        .map_err(RarDiagnosticFailure::Allocation)?;
                c.proof_capacity(native_target.capacity() as u64)?;
                let target = project_bytes(c, &cwd, &native_target, Path::new(""))?;
                self.admit_path(c, &target, index as u64, attempts)?;
                let released = checked(
                    checked(target.capacity() as u64, relative.capacity() as u64)?,
                    native_target.capacity() as u64,
                )?;
                drop(target);
                drop(relative);
                drop(native_target);
                c.usage.diagnostics.capacity =
                    c.usage.diagnostics.capacity.checked_sub(released).ok_or(RarDiagnosticFailure::CounterOverflow)?;
                c.usage.diagnostics.targets = targets;
            }
        }
        if let Some(failure) = self.deferred.take() {
            return Err(failure);
        }
        self.prepared = true;
        Ok(())
    }
    fn admit_path(
        &mut self,
        c: &mut RarExtractControl,
        path: &[u8],
        ordinal: u64,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        c.proof_work(path.len() as u64)?;
        for end in (1..=path.len()).filter(|&i| i == path.len() || path[i] == b'/') {
            c.proof_work(end as u64)?;
            let leaf = end == path.len();
            let expected = self.admit_record(c, &path[..end], ordinal, leaf, false, attempts)?;
            if expected.is_some_and(|stamp| stamp.mode & libc::S_IFMT == libc::S_IFLNK) {
                // Keep the no-follow binding and separately protect the object
                // reached when this prefix is traversed by the actual lookup.
                self.admit_record(c, &path[..end], ordinal, leaf, true, attempts)?;
            }
        }
        Ok(())
    }
    fn admit_record(
        &mut self,
        c: &mut RarExtractControl,
        path: &[u8],
        ordinal: u64,
        leaf: bool,
        follow: bool,
        attempts: &mut u64,
    ) -> Result<Option<Stamp>, RarDiagnosticFailure> {
        let parents = checked(c.usage.diagnostics.parents, 1)?;
        if parents > c.limits.diagnostics.parents {
            return Err(RarDiagnosticFailure::Limit(RarDiagnosticLimit::Parents));
        }
        c.reserve_proof(&mut self.records, 1)?;
        let probe = c.proof_path(path)?;
        let expected = match self.observe(c, &probe, attempts, follow) {
            Ok(observation) => observation,
            Err(failure @ RarDiagnosticFailure::Metadata { .. }) => {
                if self.deferred.is_none() {
                    self.deferred = Some(failure);
                }
                None
            }
            Err(failure) => return Err(failure),
        };
        if expected.is_some_and(|stamp| self.identity == Some(stamp.identity())) {
            return Err(if leaf {
                RarDiagnosticFailure::AliasTarget { ordinal }
            } else {
                RarDiagnosticFailure::AliasAncestor { ordinal: Some(ordinal) }
            });
        }
        self.records.push(Record {
            path: probe,
            expected,
            original: expected.map(Stamp::identity),
            stage: None,
            ordinal: Some(ordinal),
            leaf,
            follow,
        });
        c.usage.diagnostics.parents = parents;
        Ok(expected)
    }
    fn observe(
        &self,
        c: &mut RarExtractControl,
        path: &[u8],
        attempts: &mut u64,
        follow: bool,
    ) -> Result<Option<Stamp>, RarDiagnosticFailure> {
        loop {
            c.proof_io(attempts)?;
            match stat_at_probe(
                self.anchor.as_ref().expect("guard anchor").as_raw_fd(),
                anchored(path),
                if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW },
                !follow,
            ) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result.map_err(metadata),
            }
        }
    }
    fn observe_source(
        &self,
        c: &mut RarExtractControl,
        path: &[u8],
        attempts: &mut u64,
    ) -> Result<Option<Stamp>, RarDiagnosticFailure> {
        loop {
            c.proof_io(attempts)?;
            match stat_at_flags(self.anchor.as_ref().expect("anchor").as_raw_fd(), anchored(path), 0) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result.map_err(metadata),
            }
        }
    }
    fn refresh(
        &mut self,
        c: &mut RarExtractControl,
        sources: Option<&[HeldVolume]>,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        if !self.classify(c, attempts)? {
            return Ok(());
        }
        if !self.prepared {
            c.state = RarDiagnosticState::PendingTargets;
            return Ok(());
        }
        let sources = sources.ok_or(RarDiagnosticFailure::BindingChanged { ordinal: None })?;
        for (i, source) in sources.iter().enumerate() {
            c.proof_work(checked(source.path.as_os_str().len() as u64, 1)?)?;
            if self.identity == Some((source.stamp.device, source.stamp.inode)) {
                return Err(RarDiagnosticFailure::AliasInput { volume: i as u64 });
            }
            c.proof_io(attempts)?;
            let held = stat_fd(&source.file).map_err(metadata)?;
            let bound = self.observe_source(c, &self.sources[i].path, attempts)?;
            if held.source() != source.stamp || bound.map(Stamp::source) != Some(source.stamp) {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: None });
            }
        }
        // Alias detection precedes unrelated binding faults in this single inventory pass.
        let mut changed = None;
        for r in &self.records {
            c.proof_work(checked(r.path.len() as u64, 1)?)?;
            if r.original == self.identity || r.stage == self.identity {
                return Err(if r.leaf {
                    RarDiagnosticFailure::AliasTarget { ordinal: r.ordinal.expect("selected ordinal") }
                } else {
                    RarDiagnosticFailure::AliasAncestor { ordinal: r.ordinal }
                });
            }
            let now = self.observe(c, &r.path, attempts, r.follow)?;
            if now.is_some_and(|s| Some(s.identity()) == self.identity) {
                return Err(if r.leaf {
                    RarDiagnosticFailure::AliasTarget { ordinal: r.ordinal.expect("selected ordinal") }
                } else {
                    RarDiagnosticFailure::AliasAncestor { ordinal: r.ordinal }
                });
            }
            let matches = match (r.expected, now) {
                (Some(a), Some(b)) if a.directory() && b.directory() => a.identity() == b.identity(),
                (a, b) => a == b,
            };
            if !matches && changed.is_none() {
                changed = Some(r.ordinal);
            }
        }
        if let Some(ordinal) = changed {
            return Err(RarDiagnosticFailure::BindingChanged { ordinal });
        }
        c.state = RarDiagnosticState::AllowedByBindings;
        Ok(())
    }
    fn before_path(
        &self,
        c: &mut RarExtractControl,
        index: usize,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        // Validate the previous expected binding before any known engine change.
        // This cannot adopt a foreign object and then erase its identity at publish.
        for r in &self.records {
            c.proof_work(1)?;
            if r.ordinal != Some(index as u64) {
                continue;
            }
            c.proof_work(r.path.len() as u64)?;
            let now = self.observe(c, &r.path, attempts, r.follow)?;
            if now.is_some_and(|s| Some(s.identity()) == self.identity) {
                return Err(if r.leaf {
                    RarDiagnosticFailure::AliasTarget { ordinal: index as u64 }
                } else {
                    RarDiagnosticFailure::AliasAncestor { ordinal: r.ordinal }
                });
            }
            let matches = match (r.expected, now) {
                (Some(a), Some(b)) if a.directory() && b.directory() => a.identity() == b.identity(),
                (a, b) => a == b,
            };
            if !matches {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal });
            }
        }
        Ok(())
    }
    fn check_followed(&self, c: &mut RarExtractControl, attempts: &mut u64) -> Result<(), RarDiagnosticFailure> {
        for r in &self.records {
            c.proof_work(1)?;
            if !r.follow {
                continue;
            }
            c.proof_work(r.path.len() as u64)?;
            let now = self.observe(c, &r.path, attempts, true)?;
            if now.is_some_and(|stamp| Some(stamp.identity()) == self.identity) {
                return Err(if r.leaf {
                    RarDiagnosticFailure::AliasTarget { ordinal: r.ordinal.expect("selected ordinal") }
                } else {
                    RarDiagnosticFailure::AliasAncestor { ordinal: r.ordinal }
                });
            }
            let matches = match (r.expected, now) {
                (Some(a), Some(b)) if a.directory() && b.directory() => a.identity() == b.identity(),
                (a, b) => a == b,
            };
            if !matches {
                return Err(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal });
            }
        }
        Ok(())
    }
    fn followed_created_directory(
        &mut self,
        c: &mut RarExtractControl,
        known: Stamp,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        for i in 0..self.records.len() {
            c.proof_work(1)?;
            let r = &self.records[i];
            if !r.follow || r.expected.is_some() {
                continue;
            }
            c.proof_work(r.path.len() as u64)?;
            let now = self.observe(c, &r.path, attempts, true)?;
            if now.is_some_and(|stamp| stamp.directory() && stamp.identity() == known.identity()) {
                self.records[i].expected = now;
            }
        }
        Ok(())
    }
    fn created(
        &mut self,
        c: &mut RarExtractControl,
        path: &Path,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let cwd = cwd(c, attempts)?;
        let target = project_bytes(c, &cwd, path, Path::new(""))?;
        for i in 0..self.records.len() {
            comparison_work(c, self.records[i].path.len(), target.len())?;
            let r = &self.records[i];
            let bytes = &r.path[..r.path.len() - 1];
            if r.expected.is_none() && as_path(&target).starts_with(as_path(bytes)) {
                let now = self.observe(c, &r.path, attempts, r.follow)?;
                if let Some(stamp) = now {
                    if !stamp.directory() {
                        return Err(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal });
                    }
                    self.records[i].expected = Some(stamp);
                    self.followed_created_directory(c, stamp, attempts)?;
                }
            }
        }
        c.usage.diagnostics.capacity = c
            .usage
            .diagnostics
            .capacity
            .checked_sub(target.capacity() as u64)
            .ok_or(RarDiagnosticFailure::CounterOverflow)?;
        Ok(())
    }
    fn before_publication(
        &mut self,
        c: &mut RarExtractControl,
        index: usize,
        initial: Option<SourceStamp>,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        self.pending_unlink = None;
        self.pending_publication = None;
        self.check_followed(c, attempts)?;
        let Some(initial) = initial else {
            self.pending_publication = Some(index);
            return Ok(());
        };
        let mut old = None;
        for r in &self.records {
            c.proof_work(1)?;
            if r.leaf && r.ordinal == Some(index as u64) {
                old = r.expected;
                break;
            }
        }
        let old = old
            .filter(|stamp| stamp.regular() && stamp.source() == initial && stamp.links != 0)
            .ok_or(RarDiagnosticFailure::BindingChanged { ordinal: Some(index as u64) })?;
        // Validate every known binding to the incumbent immediately before the
        // engine's one unlink. No foreign observation becomes a new baseline.
        for r in &self.records {
            c.proof_work(1)?;
            if r.expected.is_some_and(|s| s.identity() == old.identity()) {
                c.proof_work(r.path.len() as u64)?;
                if r.expected != Some(old) || self.observe(c, &r.path, attempts, r.follow)? != Some(old) {
                    return Err(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal });
                }
            }
        }
        self.pending_unlink = Some(PendingUnlink { index, old });
        self.pending_publication = Some(index);
        Ok(())
    }
    fn published(
        &mut self,
        c: &mut RarExtractControl,
        index: usize,
        target: &Path,
        held: &File,
        attempts: &mut u64,
    ) -> Result<(), RarDiagnosticFailure> {
        let pending = self.pending_unlink.take().filter(|pending| pending.index == index);
        let prepared = self.pending_publication.take() == Some(index);
        let cwd = cwd(c, attempts)?;
        let target = project_bytes(c, &cwd, target, Path::new(""))?;
        c.proof_io(attempts)?;
        let stamp = stat_fd(held).map_err(metadata)?;
        if self.identity == Some(stamp.identity()) {
            return Err(RarDiagnosticFailure::AliasTarget { ordinal: index as u64 });
        }
        let mut found = false;
        for i in 0..self.records.len() {
            comparison_work(c, self.records[i].path.len(), target.len())?;
            let r = &self.records[i];
            if as_path(&r.path[..r.path.len() - 1]) == as_path(&target) {
                let now = self.observe(c, &r.path, attempts, r.follow)?;
                if now != Some(stamp) {
                    return Err(RarDiagnosticFailure::PublicationUnverified { ordinal: index as u64 });
                }
                if r.ordinal == Some(index as u64) && r.leaf {
                    if r.stage != Some(stamp.identity()) {
                        return Err(RarDiagnosticFailure::PublicationUnverified { ordinal: index as u64 });
                    }
                    found = true;
                }
                self.records[i].expected = Some(stamp);
            } else if prepared && r.follow && r.expected.is_none() {
                let now = self.observe(c, &r.path, attempts, true)?;
                if now == Some(stamp) {
                    self.records[i].expected = Some(stamp);
                } else if now.is_some() {
                    return Err(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal });
                }
            } else if let Some(pending) =
                pending.filter(|pending| r.expected.is_some_and(|old| old.identity() == pending.old.identity()))
            {
                let now = self
                    .observe(c, &r.path, attempts, r.follow)?
                    .ok_or(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal })?;
                let permitted = Stamp {
                    ctime: now.ctime,
                    links: pending.old.links.checked_sub(1).ok_or(RarDiagnosticFailure::CounterOverflow)?,
                    ..pending.old
                };
                let follows_published = r.follow && now == stamp;
                // Exactly the known link removal may advance ctime. Every
                // other field stays strict, including all future checkpoints.
                if r.expected != Some(pending.old) || (!follows_published && now != permitted) {
                    return Err(RarDiagnosticFailure::BindingChanged { ordinal: r.ordinal });
                }
                self.records[i].expected = Some(now);
            }
        }
        c.usage.diagnostics.capacity = c
            .usage
            .diagnostics
            .capacity
            .checked_sub(target.capacity() as u64)
            .ok_or(RarDiagnosticFailure::CounterOverflow)?;
        if !found {
            return Err(RarDiagnosticFailure::PublicationUnverified { ordinal: index as u64 });
        }
        Ok(())
    }
}
fn cwd(c: &mut RarExtractControl, attempts: &mut u64) -> Result<[u8; 4096], RarDiagnosticFailure> {
    let mut bytes = [0; 4096];
    c.proof_work(4096)?;
    c.proof_io(attempts)?;
    if unsafe { libc::getcwd(bytes.as_mut_ptr().cast(), bytes.len()) }.is_null() {
        return Err(metadata(io::Error::last_os_error()));
    }
    Ok(bytes)
}
fn project_bytes(
    c: &mut RarExtractControl,
    cwd: &[u8],
    root: &Path,
    relative: &Path,
) -> Result<Vec<u8>, RarDiagnosticFailure> {
    c.proof_work(cwd.len() as u64)?;
    let cwd = &cwd[..cwd.iter().position(|&b| b == 0).unwrap_or(cwd.len())];
    let root = root.as_os_str().as_bytes();
    let relative = relative.as_os_str().as_bytes();
    let mut out = Vec::new();
    let size = root
        .len()
        .checked_add(relative.len())
        .and_then(|n| n.checked_add(cwd.len()))
        .and_then(|n| n.checked_add(2))
        .ok_or(RarDiagnosticFailure::CounterOverflow)?;
    c.proof_work(
        (size as u64).checked_mul(2).and_then(|n| n.checked_add(1)).ok_or(RarDiagnosticFailure::CounterOverflow)?,
    )?;
    c.reserve_proof(&mut out, size)?;
    if !root.starts_with(b"/") {
        out.extend_from_slice(cwd);
        out.push(b'/');
    }
    out.extend_from_slice(root);
    if !relative.is_empty() {
        if !out.ends_with(b"/") {
            out.push(b'/');
        }
        out.extend_from_slice(relative);
    }
    while out.len() > 1 && out.ends_with(b"/") {
        out.pop();
    }
    Ok(out)
}

fn as_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}
fn comparison_work(c: &mut RarExtractControl, a: usize, b: usize) -> Result<(), RarDiagnosticFailure> {
    let work = checked(a as u64, b as u64)?
        .checked_mul(4)
        .and_then(|n| n.checked_add(2))
        .ok_or(RarDiagnosticFailure::CounterOverflow)?;
    c.proof_work(work)
}

fn anchored(path: &[u8]) -> &[u8] {
    path.strip_prefix(b"/").unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_reservation_refusal_retains_owned_cause_and_has_no_allocation_in_cleanup() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(true));
        let error = c.proof_path(b"a").unwrap_err();
        c.mute(error);
        let recovery = c.into_diagnostic();
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(false));
        assert!(matches!(recovery.aftermath.diagnostic_failure, Some(RarDiagnosticFailure::Allocation(_))));
        assert_eq!(recovery.aftermath.usage.diagnostics.capacity_peak, 0);
    }
    #[test]
    fn overflow_never_wraps_into_diagnostic_permission() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.usage.diagnostics.writer_requests = u64::MAX;
        assert!(c.early_diagnostic().writer().is_none());
        assert_eq!(c.usage.diagnostics.writer_requests, u64::MAX);
        assert!(matches!(c.failure, Some(RarDiagnosticFailure::CounterOverflow)));
        c.usage.diagnostics.checkpoints = u64::MAX;
        assert!(matches!(c.refresh(None), Err(RarDiagnosticFailure::CounterOverflow)));
        assert_eq!(c.usage.diagnostics.checkpoints, u64::MAX);
        c.usage.diagnostics.work = u64::MAX;
        assert!(matches!(c.proof_work(1), Err(RarDiagnosticFailure::CounterOverflow)));
        assert_eq!(c.usage.diagnostics.work, u64::MAX);
        c.usage.diagnostics.io_attempts = u64::MAX;
        assert!(matches!(c.proof_io(&mut 0), Err(RarDiagnosticFailure::CounterOverflow)));
        c.usage.diagnostics.capacity = u64::MAX;
        assert!(matches!(c.proof_capacity(1), Err(RarDiagnosticFailure::CounterOverflow)));
    }
}
