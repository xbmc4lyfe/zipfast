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

use super::super::extraction::{DirectoryOutput, Extraction, ExtractionHooks};
use super::*;
use crate::extract::{Options, Overwrite};
use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

impl RarSession {
    /// Extract in one ordered run with engine-bound decisions and lazy diagnostics.
    /// The report borrows this session and control, but not options or observer.
    pub fn extract_selected_controlled<'a>(
        &'a mut self,
        selection: &RarSelection,
        options: &Options,
        decode: RarDecodeLimits,
        control: &'a mut RarExtractControl,
        observer: &mut (impl RarExtractObserver + ?Sized),
    ) -> RarControlledExtractReport<'a> {
        let outcome = if control.usage.phase != RarExtractControlPhase::Ready {
            Err(RarExtractError::ControlNotReset { partial: self.summary(0) })
        } else {
            control.usage.phase = RarExtractControlPhase::Extracting;
            if Arc::ptr_eq(&self.token, &selection.token) {
                control.prepare(self, selection, options);
            }
            let mut driver = Driver {
                extraction: Extraction::new(options),
                control,
                observer,
                retained: 0,
                event_bytes: 0,
                source_paths: Vec::new(),
            };
            let result = self.execute_driver(selection, decode, &mut driver);
            // I2: only the incumbent drain body is exempt from the new control ceilings.
            driver.control.close_parent();
            driver.extraction.finalize();
            driver.control.usage.capacity = 0;
            result.map_err(|error| match error {
                DriverError::Native(error) => RarExtractError::Native(error),
                DriverError::Owned { partial, entry, cause } => match cause {
                    SelectedStop::Control(cause) => RarExtractError::Control { partial, entry, cause },
                    SelectedStop::Decision(cause) => RarExtractError::Decision {
                        partial,
                        entry: entry.expect("decision has current identity"),
                        cause,
                    },
                    SelectedStop::Native(_) => unreachable!("native stop classified in executor"),
                },
            })
        };
        if control.usage.phase == RarExtractControlPhase::Extracting {
            control.usage.phase = RarExtractControlPhase::Terminal;
        }
        RarControlledExtractReport { outcome: Some(outcome), sources: &self.volumes, control }
    }
}
struct Driver<'a, O: ?Sized> {
    extraction: Extraction<'a>,
    control: &'a mut RarExtractControl,
    observer: &'a mut O,
    retained: u64,
    event_bytes: u64,
    source_paths: Vec<Vec<u8>>,
}
impl<O: RarExtractObserver + ?Sized> SelectedDriver for Driver<'_, O> {
    fn prepare(&mut self, session: &RarSession) -> Result<(), SelectedStop> {
        let n = session.volumes.len();
        let minimum = n.checked_mul(size_of::<Vec<u8>>()).ok_or(RarExtractControlError::CounterOverflow)?;
        self.control.check_capacity(add_capacity(self.retained, minimum as u64)?)?;
        self.source_paths.try_reserve_exact(n).map_err(RarExtractControlError::Allocation)?;
        let bytes = self
            .source_paths
            .capacity()
            .checked_mul(size_of::<Vec<u8>>())
            .ok_or(RarExtractControlError::CounterOverflow)? as u64;
        self.retained = add_capacity(self.retained, bytes)?;
        self.control.capacity(self.retained)?;
        for volume in &session.volumes {
            let path = volume.path.as_os_str().as_bytes();
            self.control.native_charge(RarResource::ExtractControlWork, add_capacity(path.len() as u64, 1)?)?;
            let n = path.len().checked_add(1).ok_or(RarExtractControlError::CounterOverflow)?;
            self.control.check_capacity(add_capacity(self.retained, n as u64)?)?;
            let mut probe = Vec::new();
            probe.try_reserve_exact(n).map_err(RarExtractControlError::Allocation)?;
            self.retained = add_capacity(self.retained, probe.capacity() as u64)?;
            self.control.capacity(self.retained)?;
            probe.extend_from_slice(path);
            probe.push(0);
            self.source_paths.push(probe);
        }
        Ok(())
    }

    fn identity(&mut self, session: &RarSession, index: usize) -> Result<RarEntryIdentity, SelectedStop> {
        self.control.native_charge(
            RarResource::ExtractControlWork,
            add_capacity(session.members[index].header.name.len() as u64, 1)?,
        )?;
        let mut name = String::new();
        let len = session.members[index].header.name.len();
        self.control.check_capacity(add_capacity(self.retained, len as u64)?)?;
        name.try_reserve_exact(len).map_err(RarExtractControlError::Allocation)?;
        self.event_bytes = name.capacity() as u64;
        self.control.capacity(add_capacity(self.retained, self.event_bytes)?)?;
        name.push_str(&session.members[index].header.name);
        Ok(RarEntryIdentity { index: Some(index as u64), order: index as u64, name })
    }
    fn member(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
        entry: &RarEntryIdentity,
    ) -> Result<RarOutcome, SelectedStop> {
        let mut hooks = Hooks {
            control: self.control,
            observer: self.observer,
            retained: &mut self.retained,
            parent_path: Vec::new(),
            leaf: Vec::new(),
            parent_stamp: None,
            ancestors: Vec::new(),
            pending_directory: 0,
            trailing_directory_fallback: false,
            source_paths: &self.source_paths,
        };
        let result = self.extraction.member_controlled(run, session, index, entry, &mut hooks);
        drop(hooks);
        self.control.usage.capacity = add_capacity(self.retained, self.event_bytes)?;
        result
    }
    fn entry(&mut self, event: &RarEntryOutcome, session: &mut RarSession) -> Result<(), SelectedStop> {
        self.observer.entry(event, RarDiagnostic { control: self.control, sources: Some(&session.volumes) });
        sources(self.control, session, &self.source_paths)?;
        self.control.usage.capacity = self.retained;
        self.event_bytes = 0;
        Ok(())
    }
}
// Shared standard-library path normalization performs several linear passes.
// Admit their bounded work before entering them, rather than counting only a copy.
fn linear_work(bytes: usize, passes: u64) -> Result<u64, RarExtractControlError> {
    u64::try_from(bytes)
        .ok()
        .and_then(|n| n.checked_mul(passes))
        .and_then(|n| n.checked_add(2))
        .ok_or(RarExtractControlError::CounterOverflow)
}
fn add_capacity(a: u64, b: u64) -> Result<u64, RarExtractControlError> {
    a.checked_add(b).ok_or(RarExtractControlError::CounterOverflow)
}
fn sources(control: &mut RarExtractControl, session: &mut RarSession, paths: &[Vec<u8>]) -> Result<(), SelectedStop> {
    check_cancel(&session.options.cancel).map_err(|e| SelectedStop::Native(Arc::from(e.failure)))?;
    if let Some(failure) = &session.invalid_binding {
        return Err(SelectedStop::Native(Arc::clone(failure)));
    }
    for (i, path) in paths.iter().enumerate() {
        control.native_charge(RarResource::ExtractControlWork, add_capacity(path.len() as u64, 1)?)?;
        let volume = &session.volumes[i];
        let result = (|| {
            let before = native_probe(control, &volume.path, || guard::stat_fd(&volume.file))?;
            let bound = native_probe(control, &volume.path, || {
                guard::stat_at_flags(libc::AT_FDCWD, path, 0)
                    .and_then(|s| s.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
            })?;
            let after = native_probe(control, &volume.path, || guard::stat_fd(&volume.file))?;
            if before.source() != volume.stamp || bound.source() != volume.stamp || after.source() != volume.stamp {
                return Err(SelectedStop::Native(Arc::from(SourceStamp::changed(&volume.path).failure)));
            }
            Ok(())
        })();
        if let Err(SelectedStop::Native(failure)) = &result {
            session.invalid_binding = Some(Arc::clone(failure));
        }
        result?;
    }
    Ok(())
}
fn native_probe<T>(
    control: &mut RarExtractControl,
    path: &Path,
    mut call: impl FnMut() -> io::Result<T>,
) -> Result<T, SelectedStop> {
    loop {
        control.native_charge(RarResource::ExtractControlIoAttempts, 1)?;
        match call() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(SelectedStop::Native(Arc::new(RarFailure::Input {
                    operation: IoOperation::Metadata,
                    path: Some(path.to_path_buf()),
                    offset: None,
                    source,
                })));
            }
            Ok(value) => return Ok(value),
        }
    }
}
struct NativeBinding {
    path: Vec<u8>,
    identity: (u64, u64),
}
struct Hooks<'a, O: ?Sized> {
    control: &'a mut RarExtractControl,
    observer: &'a mut O,
    retained: &'a mut u64,
    parent_path: Vec<u8>,
    leaf: Vec<u8>,
    parent_stamp: Option<guard::Stamp>,
    ancestors: Vec<NativeBinding>,
    pending_directory: u64,
    trailing_directory_fallback: bool,
    source_paths: &'a [Vec<u8>],
}
impl<O: ?Sized> Hooks<'_, O> {
    fn reserve(&mut self, n: usize) -> Result<(), SelectedStop> {
        self.control.check_capacity(add_capacity(self.control.usage.capacity, n as u64)?)?;
        Ok(())
    }
    fn allocated(&mut self, n: usize) -> Result<(), SelectedStop> {
        self.control.capacity(add_capacity(self.control.usage.capacity, n as u64)?)?;
        Ok(())
    }
    fn bytes(&mut self, path: &Path) -> Result<Vec<u8>, SelectedStop> {
        let bytes = path.as_os_str().as_bytes();
        self.control.native_charge(RarResource::ExtractControlWork, add_capacity(bytes.len() as u64, 1)?)?;
        let n = bytes.len().checked_add(1).ok_or(RarExtractControlError::CounterOverflow)?;
        self.reserve(n)?;
        let mut out = Vec::new();
        out.try_reserve_exact(n).map_err(RarExtractControlError::Allocation)?;
        self.allocated(out.capacity())?;
        out.extend_from_slice(bytes);
        out.push(0);
        Ok(out)
    }
    fn io<T>(
        &mut self,
        operation: IoOperation,
        target: &Path,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, SelectedStop> {
        loop {
            self.control.native_charge(RarResource::ExtractControlIoAttempts, 1)?;
            match call() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(SelectedStop::Native(Arc::new(RarFailure::Output {
                        operation,
                        path: Some(target.to_path_buf()),
                        offset: None,
                        source,
                    })));
                }
                Ok(value) => return Ok(value),
            }
        }
    }
    fn directory_io<T>(
        &mut self,
        operation: IoOperation,
        target: &Path,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, SelectedStop> {
        loop {
            self.control.native_charge(RarResource::ExtractControlIoAttempts, 1)?;
            #[cfg(test)]
            let result = directory_event(operation, target).and_then(|()| call());
            #[cfg(not(test))]
            let result = call();
            match result {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(SelectedStop::Native(Arc::new(RarFailure::Output {
                        operation,
                        path: Some(self.owned_path(target)?),
                        offset: None,
                        source,
                    })));
                }
                Ok(value) => return Ok(value),
            }
        }
    }
    fn owned_path(&mut self, path: &Path) -> Result<PathBuf, SelectedStop> {
        let bytes = path.as_os_str().len();
        self.control.native_charge(RarResource::ExtractControlWork, add_capacity(bytes as u64, 1)?)?;
        self.reserve(bytes)?;
        let mut owned = PathBuf::new();
        owned.try_reserve_exact(bytes).map_err(RarExtractControlError::Allocation)?;
        self.allocated(owned.capacity())?;
        owned.push(path);
        Ok(owned)
    }
    // Walk only the configured root and relative ancestors, in order. In
    // particular, ENOTDIR is not evidence of an absent ancestor. The generic
    // diagnostic stat helper intentionally coalesces those errors, so do not
    // use it for this compatibility decision.
    fn missing_directory_ancestor(&mut self, root: &Path, target: &Path) -> Result<bool, SelectedStop> {
        let parent = target.parent().expect("sanitized directory parent");
        let relative = parent.strip_prefix(root).expect("directory below destination");
        self.control.native_charge(RarResource::ExtractControlWork, linear_work(target.as_os_str().len(), 2)?)?;
        let capacity = target.as_os_str().len();
        self.reserve(capacity)?;
        let mut at = PathBuf::new();
        at.try_reserve_exact(capacity).map_err(RarExtractControlError::Allocation)?;
        self.allocated(at.capacity())?;
        // An empty destination projects relative to cwd; an empty metadata
        // pathname would instead report ENOENT. Normalize observation only.
        at.push(if root.as_os_str().is_empty() { Path::new(".") } else { root });
        for component in std::iter::once(None).chain(relative.components().map(Some)) {
            if let Some(component) = component {
                at.push(component);
            }
            self.control
                .native_charge(RarResource::ExtractControlWork, add_capacity(at.as_os_str().len() as u64, 1)?)?;
            let observed = self.directory_io(IoOperation::Metadata, &at, || match fs::symlink_metadata(&at) {
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
                result => result.map(Some),
            })?;
            let Some(observed) = observed else { return Ok(true) };
            let reason = if observed.file_type().is_symlink() {
                crate::error::RarPolicyReason::Symlink
            } else if !observed.is_dir() {
                crate::error::RarPolicyReason::ParentIsFile
            } else {
                continue;
            };
            return Err(SelectedStop::Native(Arc::new(RarFailure::Policy { reason, path: at })));
        }
        Ok(false)
    }
    fn directory_uncertain(&mut self) -> SelectedStop {
        self.control.mute(RarDiagnosticFailure::BindingChanged { ordinal: None });
        SelectedStop::Native(Arc::new(RarFailure::Internal(crate::error::RarInternal::Invariant(
            "directory binding changed during final creation",
        ))))
    }
    fn directory_binding(&mut self, root: &Path, path: &Path, expected: (u64, u64)) -> Result<(), SelectedStop> {
        use std::os::unix::fs::MetadataExt;
        match self.missing_directory_ancestor(root, path) {
            Ok(false) => {}
            Ok(true) => return Err(self.directory_uncertain()),
            Err(SelectedStop::Native(failure)) if matches!(failure.as_ref(), RarFailure::Policy { .. }) => {
                return Err(self.directory_uncertain());
            }
            Err(stop) => return Err(stop),
        }
        self.control.native_charge(RarResource::ExtractControlWork, add_capacity(path.as_os_str().len() as u64, 1)?)?;
        let observed = self.directory_io(IoOperation::Metadata, path, || fs::symlink_metadata(path))?;
        if !observed.is_dir() || (observed.dev(), observed.ino()) != expected {
            return Err(self.directory_uncertain());
        }
        Ok(())
    }
    fn changed(target: &Path) -> SelectedStop {
        SelectedStop::Native(Arc::new(RarFailure::Policy {
            reason: crate::error::RarPolicyReason::TargetChanged,
            path: target.to_path_buf(),
        }))
    }
    fn bind(&mut self, target: &Path, initial: SourceStamp) -> Result<(), SelectedStop> {
        self.control.native_charge(RarResource::ExtractControlWork, linear_work(target.as_os_str().len(), 2)?)?;
        self.parent_path = self.bytes(target.parent().expect("sanitized parent"))?;
        self.leaf = self.bytes(Path::new(target.file_name().expect("sanitized leaf")))?;
        self.control.handle_admission(RarControlHandleKind::DecisionParent)?;
        let path = self.parent_path.as_ptr();
        let n = self.parent_path.len();
        let file = self
            .io(IoOperation::Open, target, || handles::open_search(unsafe { std::slice::from_raw_parts(path, n) }))?;
        self.control.decision_parent = Some(file);
        self.control.acquired(RarControlHandleKind::DecisionParent);
        let fd = self.control.decision_parent.as_ref().expect("held parent").as_raw_fd();
        // fstat on the actual held parent, no read-open requirement on the target.
        self.control.native_charge(RarResource::ExtractControlIoAttempts, 1)?;
        self.parent_stamp = Some(guard::stat_fd(self.control.decision_parent.as_ref().unwrap()).map_err(|source| {
            SelectedStop::Native(Arc::new(RarFailure::Output {
                operation: IoOperation::Metadata,
                path: None,
                offset: None,
                source,
            }))
        })?);
        let leaf = self.leaf.as_ptr();
        let n = self.leaf.len();
        let observed = self
            .io(IoOperation::Metadata, target, || guard::stat_at(fd, unsafe { std::slice::from_raw_parts(leaf, n) }))?;
        if observed.filter(|s| s.mode & libc::S_IFMT == libc::S_IFREG).map(guard::Stamp::source) != Some(initial) {
            return Err(Self::changed(target));
        }
        self.bind_ancestors(target)?;
        Ok(())
    }
    fn bind_ancestors(&mut self, target: &Path) -> Result<(), SelectedStop> {
        self.control.native_charge(RarResource::ExtractControlWork, linear_work(target.as_os_str().len(), 2)?)?;
        let parent = target.parent().expect("target parent");
        for component in parent.ancestors() {
            let path = if component.as_os_str().is_empty() { Path::new(".") } else { component };
            self.control
                .native_charge(RarResource::ExtractControlWork, add_capacity(path.as_os_str().len() as u64, 1)?)?;
            let old = self.ancestors.capacity();
            if self.ancestors.len() == old {
                self.reserve(size_of::<NativeBinding>())?;
                self.ancestors.try_reserve_exact(1).map_err(RarExtractControlError::Allocation)?;
                let delta = self
                    .ancestors
                    .capacity()
                    .checked_sub(old)
                    .and_then(|n| n.checked_mul(size_of::<NativeBinding>()))
                    .ok_or(RarExtractControlError::CounterOverflow)?;
                self.allocated(delta)?;
            }
            let probe = self.bytes(path)?;
            let observed = self
                .io(IoOperation::Metadata, target, || guard::stat_at(libc::AT_FDCWD, &probe))?
                .ok_or_else(|| Self::changed(target))?;
            if ![libc::S_IFDIR, libc::S_IFLNK].contains(&(observed.mode & libc::S_IFMT)) {
                return Err(Self::changed(target));
            }
            self.ancestors.push(NativeBinding { path: probe, identity: (observed.dev, observed.ino) });
        }
        Ok(())
    }
    fn binding(&mut self, target: &Path, initial: Option<SourceStamp>) -> Result<(), SelectedStop> {
        let Some(parent) = self.parent_stamp else {
            return Ok(());
        };
        self.control.native_charge(
            RarResource::ExtractControlWork,
            add_capacity(self.parent_path.len() as u64, self.leaf.len() as u64)?,
        )?;
        for i in 0..self.ancestors.len() {
            let r = &self.ancestors[i];
            let path = r.path.as_ptr();
            let n = r.path.len();
            let identity = r.identity;
            self.control.native_charge(RarResource::ExtractControlWork, add_capacity(n as u64, 1)?)?;
            if self
                .io(IoOperation::Metadata, target, || {
                    guard::stat_at(libc::AT_FDCWD, unsafe { std::slice::from_raw_parts(path, n) })
                })?
                .map(|s| (s.dev, s.ino))
                != Some(identity)
            {
                return Err(Self::changed(target));
            }
        }
        let path = self.parent_path.as_ptr();
        let n = self.parent_path.len();
        let parent_now = self.io(IoOperation::Metadata, target, || {
            guard::stat_at(libc::AT_FDCWD, unsafe { std::slice::from_raw_parts(path, n) })
        })?;
        if parent_now.map(|s| (s.dev, s.ino)) != Some((parent.dev, parent.ino)) {
            return Err(Self::changed(target));
        }
        let fd = self.control.decision_parent.as_ref().expect("held parent").as_raw_fd();
        let leaf = self.leaf.as_ptr();
        let n = self.leaf.len();
        if self
            .io(IoOperation::Metadata, target, || guard::stat_at(fd, unsafe { std::slice::from_raw_parts(leaf, n) }))?
            .map(guard::Stamp::source)
            != initial
        {
            return Err(Self::changed(target));
        }
        Ok(())
    }
}
impl<O: RarExtractObserver + ?Sized> ExtractionHooks for Hooks<'_, O> {
    fn before_directories(&mut self) {
        self.control.capture_before_directories();
    }
    fn before_publication(&mut self, index: usize, initial: Option<SourceStamp>) {
        self.control.capture_before_publication(index, initial);
    }
    fn before_path(&mut self, index: usize) {
        self.control.capture_before_path(index);
    }
    fn observe_publication(&self) -> bool {
        true
    }
    fn project(&mut self, header: &FileHeader) -> Result<PathBuf, SelectedStop> {
        self.control.native_charge(RarResource::ExtractControlWork, linear_work(header.name.len(), 8)?)?;
        self.reserve(header.name.len())?;
        let relative = crate::path::sanitize_fallible(&header.name, !header.is_unix()).map_err(|e| match e {
            crate::path::ProjectionError::Allocation(e) => SelectedStop::Control(RarExtractControlError::Allocation(e)),
            crate::path::ProjectionError::Unsafe => SelectedStop::Native(Arc::new(RarFailure::Policy {
                reason: crate::error::RarPolicyReason::UnsafePath,
                path: PathBuf::from(&header.name),
            })),
        })?;
        self.allocated(relative.capacity())?;
        Ok(relative)
    }
    fn target(&mut self, options: &Options, relative: &Path, flatten: bool) -> Result<PathBuf, SelectedStop> {
        let projection_bytes = options
            .dest
            .as_os_str()
            .len()
            .checked_add(relative.as_os_str().len())
            .ok_or(RarExtractControlError::CounterOverflow)?;
        self.control.native_charge(RarResource::ExtractControlWork, linear_work(projection_bytes, 4)?)?;
        let len = super::super::extraction::target_capacity(options, relative, flatten)
            .ok_or(RarExtractControlError::CounterOverflow)?;
        self.control.native_charge(RarResource::ExtractControlWork, len as u64)?;
        self.reserve(len)?;
        let out = super::super::extraction::project_target(options, relative, flatten, len)
            .map_err(RarExtractControlError::Allocation)?;
        self.allocated(out.capacity())?;
        Ok(out)
    }
    fn reserve_directory(
        &mut self,
        dirs: &mut Vec<DirectoryOutput>,
        path: &Path,
        path_capacity: usize,
        root: &Path,
        header: &FileHeader,
        wire_name: &[u8],
    ) -> Result<(), SelectedStop> {
        self.trailing_directory_fallback = header.format == RarFormat::Rar5
            && header.is_unix()
            && wire_name.ends_with(b"/")
            && self.missing_directory_ancestor(root, path)?;
        self.control.native_charge(RarResource::ExtractControlWork, add_capacity(path.as_os_str().len() as u64, 1)?)?;
        let old = dirs.capacity();
        if dirs.len() == old {
            self.reserve(size_of::<DirectoryOutput>())?;
            dirs.try_reserve_exact(1).map_err(RarExtractControlError::Allocation)?;
            let delta = dirs
                .capacity()
                .checked_sub(old)
                .and_then(|n| n.checked_mul(size_of::<DirectoryOutput>()))
                .ok_or(RarExtractControlError::CounterOverflow)?;
            self.allocated(delta)?;
            *self.retained = add_capacity(*self.retained, delta as u64)?;
        }
        self.pending_directory = add_capacity(*self.retained, path_capacity as u64)?;
        Ok(())
    }
    fn complete_directory(
        &mut self,
        session: &mut RarSession,
        root: &Path,
        path: &Path,
        identity: (u64, u64),
    ) -> Result<Option<Arc<RarFailure>>, SelectedStop> {
        if !self.trailing_directory_fallback {
            return Ok(None);
        }
        sources(self.control, session, self.source_paths)?;
        self.directory_binding(root, path, identity)?;
        // Preparation has created the terminal slash's prefix. Reproduce the
        // actual final native attempt; only its EEXIST is a member failure.
        let failure = match self.directory_io(IoOperation::CreateDirectory, path, || fs::create_dir(path)) {
            Err(SelectedStop::Native(failure))
                if matches!(failure.as_ref(), RarFailure::Output {
                    operation: IoOperation::CreateDirectory, source, ..
                } if source.kind() == io::ErrorKind::AlreadyExists) =>
            {
                failure
            }
            Err(stop) => return Err(stop),
            Ok(()) => {
                // Concurrent removal allowed a new directory to be created.
                // The earlier created(path) proof cannot bind its identity.
                return Err(self.directory_uncertain());
            }
        };
        sources(self.control, session, self.source_paths)?;
        self.directory_binding(root, path, identity)?;
        Ok(Some(failure))
    }

    fn directory_committed(&mut self) {
        *self.retained = self.pending_directory;
    }
    fn replace(
        &mut self,
        session: &mut RarSession,
        entry: &RarEntryIdentity,
        target: &Path,
        initial: Option<SourceStamp>,
        _: Overwrite,
    ) -> Result<bool, SelectedStop> {
        let Some(initial) = initial else {
            return Ok(true);
        };
        self.bind(target, initial)?;
        let decision = match self.control.overwrite {
            RarOverwriteMode::Skip => RarOverwriteDecision::Skip,
            RarOverwriteMode::Always => RarOverwriteDecision::Replace,
            RarOverwriteMode::Ask => {
                self.control.native_charge(RarResource::ExtractDecisionCalls, 1)?;
                self.observer
                    .overwrite(
                        &RarOverwriteConflict { entry, target, existing: initial.into() },
                        RarDiagnostic { control: self.control, sources: Some(&session.volumes) },
                    )
                    .map_err(SelectedStop::Decision)?
            }
        };
        sources(self.control, session, self.source_paths)?;
        self.binding(target, Some(initial))?;
        Ok(decision == RarOverwriteDecision::Replace)
    }
    fn recheck(
        &mut self,
        session: &mut RarSession,
        target: &Path,
        initial: Option<SourceStamp>,
    ) -> Result<(), SelectedStop> {
        sources(self.control, session, self.source_paths)?;
        self.binding(target, initial)
    }
    fn release_parent(&mut self) {
        self.control.close_parent();
    }
    fn created(&mut self, path: &Path) {
        self.control.capture_created(path);
    }
    fn stage(&mut self, index: usize, stamp: SourceStamp) {
        self.control.capture_stage(index, stamp);
    }
    fn published(&mut self, index: usize, target: &Path, held: &File, published: bool) {
        self.control.capture_published(index, target, held, published);
    }
}

impl<O: ?Sized> Drop for Hooks<'_, O> {
    fn drop(&mut self) {
        self.control.close_parent();
    }
}

#[cfg(test)]
type DirectoryHook = Box<dyn FnMut(IoOperation, &Path) -> io::Result<()>>;
#[cfg(test)]
thread_local! {
    static DIRECTORY_HOOK: std::cell::RefCell<Option<DirectoryHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn directory_event(operation: IoOperation, path: &Path) -> io::Result<()> {
    DIRECTORY_HOOK.with_borrow_mut(|hook| hook.as_mut().map_or(Ok(()), |hook| hook(operation, path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(path: &Path) {
        fn block(out: &mut Vec<u8>, body: &[u8], payload: &[u8]) {
            let mut framed = vec![body.len() as u8];
            framed.extend(body);
            out.extend(crate::crc32::hash(&framed).to_le_bytes());
            out.extend(framed);
            out.extend(payload);
        }
        let mut bytes = crate::rar5::SIGNATURE.to_vec();
        block(&mut bytes, &[1, 0, 0], &[]);
        for name in *b"ab" {
            let mut body = vec![2, 2, 1, 4, 1, 0x80, 0x03];
            body.extend(crate::crc32::hash(&[name]).to_le_bytes());
            body.extend([0, 1, 1, name]);
            block(&mut bytes, &body, &[name]);
        }
        block(&mut bytes, &[5, 0, 0], &[]);
        fs::write(path, bytes).unwrap();
    }
    fn options(path: &Path) -> Options {
        Options {
            mode: crate::extract::Mode::Extract,
            dest: path.into(),
            overwrite: Overwrite::Always,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        }
    }
    struct Fault {
        calls: u64,
        eof: bool,
    }
    impl RarExtractObserver for Fault {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            self.calls += 1;
            if self.calls == 1 && !self.eof || self.calls == 2 && self.eof {
                handles::CLOSE_ERROR.with(|s| s.set(Some(libc::EIO)));
            }
            if self.calls == 2 && self.eof {
                Err(RarDecisionError::EndOfInput)
            } else {
                Ok(RarOverwriteDecision::Replace)
            }
        }
        fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
    }
    #[test]
    fn decision_close_uncertainty_preserves_published_count_and_original_mute() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        fixture(&source);
        for name in ["a", "b"] {
            fs::write(d.path().join(name), b"old").unwrap();
        }
        let diagnostic = OpenOptions::new().append(true).open(d.path().join("a")).unwrap();
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c = RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Ask, RarExtractControlLimits::default());
        let f = s
            .extract_selected_controlled(
                &selected,
                &options(d.path()),
                RarDecodeLimits::default(),
                &mut c,
                &mut Fault { calls: 0, eof: false },
            )
            .finish();
        assert!(
            matches!(f.outcome,Err(RarExtractError::Control{partial,cause:RarExtractControlError::Limit{resource:RarResource::ExtractControlHandles,requested:2,allowed:1},..}) if partial.files==1&&partial.failed==0)
        );
        assert!(matches!(f.diagnostic_failure, Some(RarDiagnosticFailure::AliasTarget { ordinal: 0 })));
        assert_eq!(f.teardown.usage.decision_parents.uncertain, 1);
        assert_eq!(f.teardown.usage.decision_parents.close_attempts, 1);
        assert_eq!(fs::read(d.path().join("a")).unwrap(), b"a");
        assert_eq!(fs::read(d.path().join("b")).unwrap(), b"old");
        assert!(c.reset().is_err());
        assert!(c.reset().is_err());
    }
    #[test]
    fn pending_eof_is_not_replaced_by_close_aftermath() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        fixture(&source);
        for name in ["a", "b"] {
            fs::write(d.path().join(name), b"old").unwrap();
        }
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        let f = s
            .extract_selected_controlled(
                &selected,
                &options(d.path()),
                RarDecodeLimits::default(),
                &mut c,
                &mut Fault { calls: 0, eof: true },
            )
            .finish();
        assert!(
            matches!(f.outcome,Err(RarExtractError::Decision{partial,cause:RarDecisionError::EndOfInput,..}) if partial.files==1&&partial.failed==0)
        );
        assert_eq!(f.teardown.usage.decision_parents.confirmed_closed, 1);
        assert_eq!(f.teardown.usage.decision_parents.uncertain, 1);
    }
    #[test]
    fn owned_native_allocation_failure_does_not_allocate_a_failure_arc() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        fixture(&source);
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
        let opts = options(d.path());
        crate::test_alloc::DENY_LAYOUT.with(|s| s.set(Some((1, 1))));
        let report = s.extract_selected_controlled(
            &selected,
            &opts,
            RarDecodeLimits::default(),
            &mut c,
            &mut Fault { calls: 0, eof: false },
        );
        crate::test_alloc::DENY_LAYOUT.with(|s| s.set(None));
        assert!(
            matches!(report.outcome(),Err(RarExtractError::Control{partial,entry:None,cause:RarExtractControlError::Allocation(_)}) if partial.failed==0&&partial.files==0)
        );
    }

    #[test]
    fn new_open_failures_have_no_close_ticket_and_interrupted_retries_are_counted() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        fixture(&source);
        let run = |error: Option<i32>| {
            for name in ["a", "b"] {
                fs::write(d.path().join(name), b"old").unwrap();
            }
            let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
            let selected = session.select(|_| true).unwrap();
            let mut c = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
            handles::OPEN_ERROR.with(|s| s.set(error));
            session
                .extract_selected_controlled(
                    &selected,
                    &options(d.path()),
                    RarDecodeLimits::default(),
                    &mut c,
                    &mut Fault { calls: 0, eof: false },
                )
                .finish()
        };
        let baseline = run(None);
        let retry = run(Some(libc::EINTR));
        assert!(retry.outcome.is_ok());
        assert_eq!(retry.usage.io_attempts, baseline.usage.io_attempts + 1);
        for errno in [libc::EMFILE, libc::ENFILE] {
            let failed = run(Some(errno));
            assert!(
                matches!(failed.outcome,Err(RarExtractError::Native(error)) if matches!(error.failure.as_ref(),RarFailure::Output{operation:IoOperation::Open,source,..} if source.raw_os_error()==Some(errno)))
            );
            assert_eq!(failed.teardown.usage.decision_parents.successful_acquires, 0);
            assert_eq!(failed.teardown.usage.decision_parents.close_attempts, 0);
        }
    }
    #[test]
    fn optional_open_failure_mutes_without_spending_native_handle_slots() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        fixture(&source);
        let log = d.path().join("log");
        fs::write(&log, b"").unwrap();
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c = RarExtractControl::new(
            Some(OpenOptions::new().append(true).open(log).unwrap()),
            RarOverwriteMode::Always,
            RarExtractControlLimits::default(),
        );
        handles::OPEN_ERROR.with(|s| s.set(Some(libc::EMFILE)));
        let f = s
            .extract_selected_controlled(
                &selected,
                &options(d.path()),
                RarDecodeLimits::default(),
                &mut c,
                &mut Fault { calls: 0, eof: false },
            )
            .finish();
        assert_eq!(f.outcome.unwrap().files, 2);
        assert!(
            matches!(f.diagnostic_failure,Some(RarDiagnosticFailure::Metadata{operation:IoOperation::Open,source}) if source.raw_os_error()==Some(libc::EMFILE))
        );
        assert_eq!(f.teardown.usage.guards.successful_acquires, 0);
        assert_eq!(f.teardown.usage.guards.close_attempts, 0);
    }
}

#[cfg(test)]
mod directory_fault_tests {
    use super::*;
    fn vint(mut n: u64, out: &mut Vec<u8>) {
        loop {
            let next = (n & 127) as u8;
            n >>= 7;
            out.push(next | if n == 0 { 0 } else { 128 });
            if n == 0 {
                break;
            }
        }
    }
    fn block(out: &mut Vec<u8>, body: &[u8], payload: &[u8]) {
        let mut framed = Vec::new();
        vint(body.len() as u64, &mut framed);
        framed.extend(body);
        out.extend(crate::crc32::hash(&framed).to_le_bytes());
        out.extend(framed);
        out.extend(payload);
    }
    struct Deny;
    impl RarExtractObserver for Deny {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!()
        }
        fn entry(&mut self, e: &RarEntryOutcome, _: RarDiagnostic<'_>) {
            if e.entry.order == 1 {
                crate::test_alloc::DENY_LAYOUT.with(|s| s.set(Some((200, 1))));
            }
        }
    }
    #[test]
    fn allocation_refusal_after_two_directory_commits_still_drains_before_report() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        let out = d.path().join("out");
        let long = "x".repeat(200);
        let mut bytes = crate::rar5::SIGNATURE.to_vec();
        block(&mut bytes, &[1, 0, 0], &[]);
        for (name, dir, mode, payload) in [
            ("parent", true, 0o711, b"".as_slice()),
            ("parent/child", true, 0o710, b"".as_slice()),
            (long.as_str(), false, 0o600, b"A".as_slice()),
        ] {
            let mut body = vec![2, 2, payload.len() as u8, if dir { 5 } else { 4 }, payload.len() as u8];
            vint(mode, &mut body);
            body.extend(crate::crc32::hash(payload).to_le_bytes());
            body.extend([0, 1]);
            vint(name.len() as u64, &mut body);
            body.extend(name.as_bytes());
            block(&mut bytes, &body, payload);
        }
        block(&mut bytes, &[5, 0, 0], &[]);
        fs::write(&source, bytes).unwrap();
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let opts = Options {
            mode: crate::extract::Mode::Extract,
            dest: out.clone(),
            overwrite: Overwrite::Always,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
        let report = s.extract_selected_controlled(&selected, &opts, RarDecodeLimits::default(), &mut c, &mut Deny);
        crate::test_alloc::DENY_LAYOUT.with(|s| s.set(None));
        assert!(
            matches!(report.outcome(),Err(RarExtractError::Control{partial,cause:RarExtractControlError::Allocation(_),..}) if partial.dirs==2&&partial.failed==0)
        );
        assert_eq!(fs::metadata(out.join("parent")).unwrap().permissions().mode() & 0o777, 0o711);
        assert_eq!(fs::metadata(out.join("parent/child")).unwrap().permissions().mode() & 0o777, 0o710);
    }
}

#[cfg(test)]
mod trailing_directory_tests {
    use super::*;
    struct Observe;
    impl RarExtractObserver for Observe {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!()
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            if let Some(writer) = diagnostic.writer() {
                use std::io::Write;
                writer.write_all(b"entry\n").unwrap();
            }
        }
    }
    fn run(hook: impl FnMut(IoOperation, &Path) -> io::Result<()> + 'static) -> RarExtractFinished {
        run_with_cancel(hook, crate::extract::Cancellation::default())
    }
    fn run_with_cancel(
        hook: impl FnMut(IoOperation, &Path) -> io::Result<()> + 'static,
        cancel: crate::extract::Cancellation,
    ) -> RarExtractFinished {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                DIRECTORY_HOOK.with_borrow_mut(|h| *h = None);
            }
        }
        let _clear = Clear;
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        let out = d.path().join("out");
        let hex =
            "526172211a070100c51a333203010000aec4aed5150202000500ed830100000000000106656d7074792f19b23a3503050000";
        let bytes: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        fs::write(&source, bytes).unwrap();
        let diagnostic = OpenOptions::new().create_new(true).append(true).open(d.path().join("log")).unwrap();
        let mut s = RarSession::open(&source, None, RarSessionOptions { cancel, ..Default::default() }).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c =
            RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
        let opts = Options {
            mode: crate::extract::Mode::Extract,
            dest: out.clone(),
            overwrite: Overwrite::Always,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        DIRECTORY_HOOK.with_borrow_mut(|h| *h = Some(Box::new(hook)));
        let result =
            s.extract_selected_controlled(&selected, &opts, RarDecodeLimits::default(), &mut c, &mut Observe).finish();
        crate::test_alloc::DENY_LAYOUT.with(|s| s.set(None));
        if out.exists() {
            assert!(out.join("empty").exists());
        }
        result
    }
    #[test]
    fn trailing_directory_interrupted_metadata_and_mkdir_attempts_are_charged() {
        let baseline = run(|_, _| Ok(()));
        for operation in [IoOperation::Metadata, IoOperation::CreateDirectory] {
            let mut interrupted = false;
            let result = run(move |op, _| {
                if op == operation && !interrupted {
                    interrupted = true;
                    return Err(io::Error::from_raw_os_error(libc::EINTR));
                }
                Ok(())
            });
            assert_eq!(result.outcome.unwrap().failed, 1);
            assert_eq!(result.usage.io_attempts, baseline.usage.io_attempts + 1);
            assert!(result.diagnostic_failure.is_none());
        }
    }
    #[test]
    fn trailing_directory_unrelated_mkdir_failure_remains_terminal() {
        let result =
            run(
                |op, _| {
                    if op == IoOperation::CreateDirectory {
                        Err(io::Error::from_raw_os_error(libc::EIO))
                    } else {
                        Ok(())
                    }
                },
            );
        assert!(
            matches!(result.outcome, Err(RarExtractError::Native(error)) if error.partial.failed == 1 && error.partial.dirs == 0 && matches!(error.failure.as_ref(), RarFailure::Output { operation: IoOperation::CreateDirectory, source, .. } if source.raw_os_error() == Some(libc::EIO)))
        );
        assert!(result.diagnostic_failure.is_none());
    }
    #[test]
    fn trailing_directory_success_after_concurrent_removal_revokes_old_created_proof() {
        let result = run(|op, target| {
            if op == IoOperation::CreateDirectory {
                fs::remove_dir(target)?;
            }
            Ok(())
        });
        assert!(
            matches!(result.outcome, Err(RarExtractError::Native(error)) if error.partial.failed == 1 && error.partial.dirs == 0 && matches!(error.failure.as_ref(), RarFailure::Internal(crate::error::RarInternal::Invariant(_))))
        );
        assert!(matches!(result.diagnostic_failure, Some(RarDiagnosticFailure::BindingChanged { .. })));
    }
    #[test]
    fn trailing_directory_swap_to_private_symlink_never_adopts_foreign_identity() {
        let result = run(|op, target| {
            if op == IoOperation::CreateDirectory {
                let held = target.with_file_name("held");
                fs::rename(target, &held)?;
                std::os::unix::fs::symlink(held, target)?;
            }
            Ok(())
        });
        assert!(
            matches!(result.outcome, Err(RarExtractError::Native(error)) if error.partial.failed == 1 && error.partial.dirs == 0 && matches!(error.failure.as_ref(), RarFailure::Internal(crate::error::RarInternal::Invariant(_))))
        );
        assert!(matches!(result.diagnostic_failure, Some(RarDiagnosticFailure::BindingChanged { .. })));
    }
    #[test]
    fn trailing_directory_source_swap_during_final_mkdir_is_terminal() {
        let result = run(|op, target| {
            if op == IoOperation::CreateDirectory {
                fs::write(target.parent().unwrap().parent().unwrap().join("source.rar"), b"changed")?;
            }
            Ok(())
        });
        assert!(
            matches!(result.outcome, Err(RarExtractError::Native(error)) if error.partial.failed == 1 && error.partial.dirs == 0 && matches!(error.failure.as_ref(), RarFailure::SourceChanged { .. }))
        );
    }
    #[test]
    fn trailing_directory_enotdir_metadata_is_not_an_absent_ancestor() {
        let result =
            run(
                |op, _| {
                    if op == IoOperation::Metadata { Err(io::Error::from_raw_os_error(libc::ENOTDIR)) } else { Ok(()) }
                },
            );
        assert!(
            matches!(result.outcome, Err(RarExtractError::Native(error)) if error.partial.failed == 1 && matches!(error.failure.as_ref(), RarFailure::Output { operation: IoOperation::Metadata, source, .. } if source.raw_os_error() == Some(libc::ENOTDIR)))
        );
    }
    #[test]
    fn trailing_directory_error_path_allocation_is_admitted_after_the_failed_attempt() {
        let result = run(|op, target| {
            if op == IoOperation::CreateDirectory {
                crate::test_alloc::DENY_LAYOUT.with(|s| s.set(Some((target.as_os_str().len(), 1))));
            }
            Ok(())
        });
        assert!(
            matches!(result.outcome, Err(RarExtractError::Control { partial, cause: RarExtractControlError::Allocation(_), .. }) if partial.failed == 0 && partial.dirs == 0)
        );
    }
    #[test]
    fn trailing_directory_cancel_during_final_attempt_retains_terminal_classification() {
        let cancel = crate::extract::Cancellation::default();
        let signal = cancel.clone();
        let result = run_with_cancel(
            move |op, _| {
                if op == IoOperation::CreateDirectory {
                    signal.cancel();
                }
                Ok(())
            },
            cancel,
        );
        assert!(
            matches!(result.outcome, Err(RarExtractError::Native(error)) if error.partial.failed == 1 && error.partial.dirs == 0 && matches!(error.failure.as_ref(), RarFailure::Canceled))
        );
    }
}
