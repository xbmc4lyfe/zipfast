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

//! Source-aware borrowed diagnostic scopes and nonrecursive stop evidence.
use super::shared::{LedgerAccess, LedgerIdentity};
use super::*;
use crate::extract::Options;
use crate::zip::{ZipEntry, session::SourceBinding};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
mod listing;
mod terminal;
mod writer;
pub(crate) use terminal::terminal;
pub use writer::{ZipDiagnosticUsage, ZipDiagnosticWriter};

pub type ZipDiagnosticResult<T> = Result<T, ZipDiagnosticStop>;
pub type ZipObserverResult<T> = Result<T, ZipObserverFault>;
#[derive(Debug)]
pub enum ZipObserverFault {
    Caller(ZipSinkFault),
    Recorded(ZipDiagnosticStop),
}
impl From<ZipSinkFault> for ZipObserverFault {
    fn from(f: ZipSinkFault) -> Self {
        Self::Caller(f)
    }
}
impl From<ZipDiagnosticStop> for ZipObserverFault {
    fn from(f: ZipDiagnosticStop) -> Self {
        Self::Recorded(f)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Token {
    action: Option<LedgerIdentity>,
    serial: u64,
}
#[derive(Debug)]
pub struct ZipDiagnosticStop {
    token: Token,
}
#[derive(Clone, Copy, Debug)]
pub enum ZipDiagnosticSink {
    Stdout,
    Stderr,
}
impl ZipDiagnosticSink {
    fn index(self) -> usize {
        match self {
            Self::Stdout => 0,
            Self::Stderr => 1,
        }
    }
}
/// Source/admission observations made before this very rendering invocation.
pub struct ZipDiagnosticStatus<'a> {
    source: Option<&'a io::SourceCheckError>,
    boundary: Option<&'a DiagnosticBoundaryFault>,
}
impl ZipDiagnosticStatus<'_> {
    pub fn source_fault(&self) -> Option<&CheckedSourceFault> {
        match self.source {
            Some(io::SourceCheckError::Source(f)) => Some(f),
            _ => None,
        }
    }
    pub fn admission_fault(&self) -> Option<&ReadFault> {
        match self.source {
            Some(io::SourceCheckError::Admission(f)) => Some(f),
            _ => None,
        }
    }
    pub fn boundary_fault(&self) -> Option<&DiagnosticBoundaryFault> {
        self.boundary
    }
    pub fn is_fatal(&self) -> bool {
        self.source.is_some() || self.boundary.is_some()
    }
}
/// Synchronous observer for the qualified macOS/Linux checked runner.
///
/// Raw one-argument closures retain responsibility for their own diagnostic I/O.
/// A structured observer admits the actually used held descriptors in `prepare`,
/// then calls `emit` for each visible event. Suppressed events perform no diagnostic I/O.
/// A render/write failure, post-render boundary fault, or invalid observer token
/// stops every later callback, including `RunEnded`. A pre-write source fault may
/// still be rendered once to an independently admitted safe sink.
/// Legacy/non-ZIP events carry no checked ZIP source capability.
///
/// ```
/// use zipfast::zip::{ZipRunEvent,ZipRunObserver};
/// fn accepts(_:impl ZipRunObserver) {}
/// accepts(|_:ZipRunEvent<'_>|Ok(()));
/// ```
pub trait ZipRunObserver {
    fn prepare(&mut self, _io: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
        Ok(())
    }
    fn observe(&mut self, event: ZipRunEvent<'_>, io: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()>;
}
impl<F> ZipRunObserver for F
where
    F: for<'e> FnMut(ZipRunEvent<'e>) -> ZipSinkResult<()>,
{
    fn observe(&mut self, event: ZipRunEvent<'_>, _: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
        self(event).map_err(ZipObserverFault::Caller)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Descriptor {
    fd: i32,
    dev: u64,
    ino: u64,
    kind: u32,
    safe: bool,
}
#[derive(Default)]
pub(super) struct DiagnosticState {
    sinks: [Option<Descriptor>; 2],
    serial: u64,
    prepared: bool,
    pub(super) usage: ZipDiagnosticUsage,
    pub(super) attempted: bool,
    pub(super) cwd: Option<policy::OwnedMetadata<u8>>,
}
#[derive(Default)]
pub(crate) struct Evidence {
    // Callback disposition is independent of source/boundary/write priority.
    stop_callbacks: bool,
    source: Option<io::SourceCheckError>,
    boundary: Option<DiagnosticBoundaryFault>,
    write: Option<ZipSinkFault>,
    cwd: Option<policy::cwd::CwdFailure>,
}
impl Evidence {
    pub(crate) fn failed(&self) -> bool {
        self.source.is_some() || self.boundary.is_some() || self.write.is_some() || self.cwd.is_some()
    }
    pub(crate) fn observer_failed(&self) -> bool {
        self.stop_callbacks || self.write.is_some()
    }
    pub(crate) fn merge(self, mut error: ZipReadError) -> ZipReadError {
        if let Some(cwd) = self.cwd {
            error = cwd.merge(error);
        }
        if let Some(boundary) = self.boundary {
            error = error.merge_diagnostic_boundary(boundary);
        }
        if let Some(write) = self.write {
            error = error.merge_diagnostic(write);
        }
        match self.source {
            Some(io::SourceCheckError::Source(f)) => error.merge_source(f),
            Some(io::SourceCheckError::Admission(f)) => projected::merge_source_admission(error, f),
            None => error,
        }
    }
}
/// Ephemeral disjoint access to the original source and once-bound diagnostic policy.
pub struct ZipDiagnosticScope<'a> {
    inner: ScopeInner<'a>,
}
enum ScopeInner<'a> {
    Bound(BoundScope<'a>),
    Legacy(Evidence),
}
impl<'a> ZipDiagnosticScope<'a> {
    pub(super) fn new(
        owner: &'a mut projected::ProjectedOwner,
        options: &'a Options,
        context: &'a mut EncryptedReadContext,
        state: &'a mut DiagnosticState,
        cancel: &'a Cancellation,
        ordinal: Option<usize>,
    ) -> Result<Self, ReadFault> {
        BoundScope::new(owner, options, context, state, cancel, ordinal)
            .map(|inner| Self { inner: ScopeInner::Bound(inner) })
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_parts(
        file: &'a File,
        source: &'a mut Result<SourceBinding, io::SourceCheckError>,
        entries: &'a [ZipEntry],
        options: &'a Options,
        context: &'a mut EncryptedReadContext,
        state: &'a mut DiagnosticState,
        cancel: &'a Cancellation,
        ordinal: Option<usize>,
    ) -> Result<Self, ReadFault> {
        BoundScope::from_parts(file, source, entries, options, context, state, cancel, ordinal)
            .map(|inner| Self { inner: ScopeInner::Bound(inner) })
    }
    pub(super) fn retired(
        retired: &'a mut RetiredSource,
        entries: &'a [ZipEntry],
        options: &'a Options,
        context: &'a mut EncryptedReadContext,
        state: &'a mut DiagnosticState,
        cancel: &'a Cancellation,
    ) -> Result<Self, ReadFault> {
        state.serial = state.serial.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let token = Token { action: Some(context.ledger.identity()), serial: state.serial };
        Ok(Self {
            inner: ScopeInner::Bound(BoundScope {
                source: SourceParts::Retired(retired),
                entries,
                options,
                context,
                state,
                cancel,
                ordinal: None,
                evidence: Evidence::default(),
                token,
                emission_allowed: true,
                emitted: false,
            }),
        })
    }
    pub(crate) fn legacy() -> Self {
        Self { inner: ScopeInner::Legacy(Evidence::default()) }
    }
    pub fn admit_sinks(&mut self, stdout: Option<&dyn AsFd>, stderr: Option<&dyn AsFd>) -> ZipDiagnosticResult<()> {
        match &mut self.inner {
            ScopeInner::Bound(inner) => inner.admit_sinks(stdout, stderr),
            ScopeInner::Legacy(e) => {
                e.stop_callbacks = true;
                e.boundary = Some(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
                Err(ZipDiagnosticStop { token: Token { action: None, serial: 0 } })
            }
        }
    }
    /// Legacy/non-ZIP dispatch has no checked ZIP source capability.
    pub fn emit<W, F>(&mut self, which: ZipDiagnosticSink, out: &mut W, render: F) -> ZipDiagnosticResult<u128>
    where
        W: Write + AsFd,
        F: FnOnce(ZipDiagnosticStatus<'_>, &mut ZipDiagnosticWriter<'_, W>) -> ZipDiagnosticResult<()>,
    {
        match &mut self.inner {
            ScopeInner::Bound(inner) => inner.emit(which, out, render),
            ScopeInner::Legacy(e) => {
                e.stop_callbacks = true;
                e.boundary = Some(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
                Err(ZipDiagnosticStop { token: Token { action: None, serial: 0 } })
            }
        }
    }
    pub(crate) fn finish(self, result: ZipObserverResult<()>) -> Evidence {
        match self.inner {
            ScopeInner::Bound(inner) => inner.finish(result),
            ScopeInner::Legacy(mut e) => {
                match result {
                    Ok(()) => {}
                    Err(ZipObserverFault::Caller(f)) => e.write = Some(f),
                    Err(ZipObserverFault::Recorded(_)) => {
                        e.stop_callbacks = true;
                        e.boundary = Some(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan))
                    }
                }
                e
            }
        }
    }
}
pub(super) struct RetiredSource {
    pub(super) binding: Result<SourceBinding, io::SourceCheckError>,
    pub(super) owner: u64,
    pub(super) action: LedgerIdentity,
    pub(super) safe_only: bool,
    pub(super) confirmed_close: bool,
}
enum SourceParts<'a> {
    Held { file: &'a File, binding: &'a mut Result<SourceBinding, io::SourceCheckError> },
    Retired(&'a mut RetiredSource),
}
struct BoundScope<'a> {
    source: SourceParts<'a>,
    entries: &'a [ZipEntry],
    options: &'a Options,
    context: &'a mut EncryptedReadContext,
    state: &'a mut DiagnosticState,
    cancel: &'a Cancellation,
    ordinal: Option<usize>,
    evidence: Evidence,
    token: Token,
    emission_allowed: bool,
    emitted: bool,
}
impl<'a> BoundScope<'a> {
    pub(super) fn new(
        owner: &'a mut projected::ProjectedOwner,
        options: &'a Options,
        context: &'a mut EncryptedReadContext,
        state: &'a mut DiagnosticState,
        cancel: &'a Cancellation,
        ordinal: Option<usize>,
    ) -> Result<Self, ReadFault> {
        let projected::ProjectedOwner { file, source, entries, .. } = owner;
        state.serial = state.serial.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let token = Token { action: Some(context.ledger.identity()), serial: state.serial };
        Ok(Self {
            source: SourceParts::Held { file, binding: source },
            entries,
            options,
            context,
            state,
            cancel,
            ordinal,
            evidence: Evidence::default(),
            token,
            emission_allowed: false,
            emitted: false,
        })
    }
    #[allow(clippy::too_many_arguments)] // The disjoint original borrows are the capability boundary.
    pub(super) fn from_parts(
        file: &'a File,
        source: &'a mut Result<SourceBinding, io::SourceCheckError>,
        entries: &'a [ZipEntry],
        options: &'a Options,
        context: &'a mut EncryptedReadContext,
        state: &'a mut DiagnosticState,
        cancel: &'a Cancellation,
        ordinal: Option<usize>,
    ) -> Result<Self, ReadFault> {
        state.serial = state.serial.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let token = Token { action: Some(context.ledger.identity()), serial: state.serial };
        Ok(Self {
            source: SourceParts::Held { file, binding: source },
            entries,
            options,
            context,
            state,
            cancel,
            ordinal,
            evidence: Evidence::default(),
            token,
            emission_allowed: true,
            emitted: false,
        })
    }
    fn stop(&self) -> ZipDiagnosticStop {
        ZipDiagnosticStop { token: self.token }
    }
    fn observe_source(&mut self) {
        if self.evidence.source.is_some() {
            return;
        }
        let file = match &self.source {
            SourceParts::Held { file, .. } => Some(*file),
            SourceParts::Retired(_) => None,
        };
        let binding = match &mut self.source {
            SourceParts::Held { binding, .. } => &mut **binding,
            SourceParts::Retired(retired) => &mut retired.binding,
        };
        let result = match binding {
            Ok(binding) => self
                .context
                .ledger
                .with_state(|s| s.charge_category(RunCategory::DiagnosticSourceGroups, 1))
                .map_err(io::SourceCheckError::Admission)
                .and_then(|()| {
                    let mut observe =
                        |stage, call: &mut dyn FnMut() -> std::io::Result<crate::zip::session::SourceStamp>| {
                            self.context.source_stat(stage, || {
                                self.state.usage.metadata(0)?;
                                call()
                            })
                        };
                    match file {
                        Some(file) => binding.verify_with(file, &mut observe),
                        None => binding.verify_retired_path(&mut observe),
                    }
                }),
            Err(io::SourceCheckError::Source(f)) => {
                let (code, raw_os_error) = f.invalidation();
                Err(io::SourceCheckError::Source(CheckedSourceFault::PreviouslyInvalidated { code, raw_os_error }))
            }
            Err(io::SourceCheckError::Admission(_)) => Err(io::SourceCheckError::Admission(ReadFault::InvalidPlan)),
        };
        if let Err(error) = result {
            self.evidence.source = Some(error);
        }
    }
    fn boundary(&mut self, fault: DiagnosticBoundaryFault) {
        if self.evidence.boundary.is_none() {
            self.evidence.boundary = Some(fault);
        }
    }
    fn classify(&mut self, fd: i32) -> Result<Descriptor, DiagnosticBoundaryFault> {
        classify(fd, |operation, call| {
            io::operation(
                &self.context.ledger,
                false,
                RunCategory::DiagnosticAdmissionOperations,
                IoStage::ExternalOutput,
                operation,
                Some(self.cancel),
                || {
                    self.state.usage.metadata(1)?;
                    call()
                },
            )
        })
    }
    fn aliases_source(&self, d: Descriptor) -> bool {
        let binding = match &self.source {
            SourceParts::Held { binding, .. } => &**binding,
            SourceParts::Retired(retired) => &retired.binding,
        };
        binding.as_ref().is_ok_and(|s| s.stamp.dev == d.dev && s.stamp.ino == d.ino)
    }
    fn inspect_path(
        &mut self,
        path: &Path,
        sinks: &[Option<Descriptor>; 2],
        current: bool,
    ) -> Result<(), DiagnosticBoundaryFault> {
        let absolute = if path.is_relative() {
            let cwd = if let Some(policy) = self.context.action.as_ref().and_then(|a| a.policy.as_ref()) {
                policy.cwd()
            } else if let Some(cwd) = &self.state.cwd {
                Path::new(std::ffi::OsStr::from_bytes(&cwd[..cwd.len() - 1]))
            } else {
                return Err(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
            };
            Some(
                policy::PolicyPath::joined(&self.context.ledger, cwd, path)
                    .map_err(DiagnosticBoundaryFault::Admission)?,
            )
        } else {
            None
        };
        let result = self.inspect_absolute(absolute.as_ref().map_or(path, policy::PolicyPath::path), sinks, current);
        match absolute {
            Some(absolute) => {
                result.and(absolute.finish(&self.context.ledger).map_err(DiagnosticBoundaryFault::Admission))
            }
            None => result,
        }
    }
    #[allow(clippy::unnecessary_cast)] // Native dev/ino widths differ between qualified Unix ABIs.
    fn inspect_absolute(
        &mut self,
        path: &Path,
        sinks: &[Option<Descriptor>; 2],
        current: bool,
    ) -> Result<(), DiagnosticBoundaryFault> {
        let ledger = self.context.ledger.view();
        let mut bytes = policy::MetadataLease::zeroed(
            ledger,
            budget::PolicyComponent::Caller,
            path.as_os_str()
                .len()
                .checked_add(1)
                .ok_or(DiagnosticBoundaryFault::Admission(ReadFault::CounterOverflow))?,
        )
        .map_err(DiagnosticBoundaryFault::Admission)?;
        bytes[..path.as_os_str().len()].copy_from_slice(path.as_os_str().as_bytes());
        let name = std::ffi::CStr::from_bytes_with_nul(&bytes)
            .map_err(|_| DiagnosticBoundaryFault::Refused { reason: "diagnostic target contains NUL" })?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let mut observe = |follow| -> Result<Option<libc::stat>, DiagnosticBoundaryFault> {
            let result = io::operation(
                &self.context.ledger,
                false,
                RunCategory::DiagnosticAdmissionOperations,
                IoStage::ExternalOutput,
                ReadIoOperation::Stat,
                Some(self.cancel),
                || {
                    self.state.usage.metadata(2)?;
                    let r = unsafe {
                        if follow {
                            libc::stat(name.as_ptr(), stat.as_mut_ptr())
                        } else {
                            libc::lstat(name.as_ptr(), stat.as_mut_ptr())
                        }
                    };
                    if r == 0 {
                        Ok(Some(unsafe { stat.assume_init() }))
                    } else {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error() == Some(libc::ENOENT) { Ok(None) } else { Err(error) }
                    }
                },
            );
            result.map_err(DiagnosticBoundaryFault::Admission)
        };
        let mut actual = observe(current)?;
        if !current && actual.as_ref().is_some_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFLNK) {
            actual = observe(true)?;
        }
        if let Some(actual) = actual
            && sinks.iter().flatten().any(|d| !d.safe && d.dev == actual.st_dev as u64 && d.ino == actual.st_ino as u64)
        {
            return Err(DiagnosticBoundaryFault::Refused {
                reason: "diagnostic aliases an output or protected target",
            });
        }
        Ok(())
    }
    fn inspect_entry(
        &mut self,
        ordinal: usize,
        current: bool,
        sinks: &[Option<Descriptor>; 2],
    ) -> Result<(), DiagnosticBoundaryFault> {
        let e = &self.entries[ordinal];
        let relative = match policy::PolicyPath::normalized(&self.context.ledger, &e.name, e.host != 3, self.cancel) {
            Ok(p) => p,
            Err(policy::PathFailure::Unsafe) => return Ok(()),
            Err(policy::PathFailure::Fault(f)) => return Err(DiagnosticBoundaryFault::Admission(f)),
        };
        let operational = if self.options.flatten {
            Path::new(relative.path().file_name().unwrap_or_default())
        } else {
            relative.path()
        };
        let target = policy::PolicyPath::joined(&self.context.ledger, &self.options.dest, operational)
            .map_err(DiagnosticBoundaryFault::Admission);
        let result = match target {
            Ok(target) => {
                let result = self.inspect_path(target.path(), sinks, current);
                let release = target.finish(&self.context.ledger).map_err(DiagnosticBoundaryFault::Admission);
                result.and(release)
            }
            Err(e) => Err(e),
        };
        result.and(relative.finish(&self.context.ledger).map_err(DiagnosticBoundaryFault::Admission))
    }
    #[allow(clippy::result_large_err)] // The prepare-only CWD carrier has two fixed owned cleanup slots.
    fn capture_cwd(&mut self) -> Result<policy::OwnedMetadata<u8>, policy::cwd::CwdFailure> {
        let ledger = self.context.ledger.view();
        let mut scratch = policy::PolicyScratch::new(ledger).map_err(policy::cwd::CwdFailure::from)?;
        policy::cwd::capture(ledger, &mut scratch, self.cancel, &mut || self.state.usage.metadata(3))
            .map(policy::MetadataLease::into_owned)
    }
    pub fn admit_sinks(&mut self, stdout: Option<&dyn AsFd>, stderr: Option<&dyn AsFd>) -> ZipDiagnosticResult<()> {
        if self.emission_allowed {
            self.evidence.stop_callbacks = true;
            self.boundary(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
            return Err(self.stop());
        }
        if self.state.prepared {
            self.evidence.stop_callbacks = true;
            self.boundary(DiagnosticBoundaryFault::Refused { reason: "diagnostic sinks already prepared" });
            return Err(self.stop());
        }
        self.state.prepared = true;
        if stdout.is_none() && stderr.is_none() {
            return Ok(());
        }
        self.observe_source();
        for (i, sink) in [stdout, stderr].into_iter().enumerate() {
            if let Some(sink) = sink {
                match self.classify(sink.as_fd().as_raw_fd()) {
                    Ok(d) => {
                        self.state.sinks[i] = Some(d);
                        if !d.safe && self.aliases_source(d) {
                            self.boundary(DiagnosticBoundaryFault::Refused { reason: "diagnostic aliases ZIP source" });
                        }
                    }
                    Err(f) => self.boundary(f),
                }
            }
        }
        if self.state.sinks.iter().flatten().any(|d| !d.safe)
            && self.evidence.boundary.is_none()
            && self.evidence.source.is_none()
        {
            if self.options.mode == crate::extract::Mode::Test
                && self.options.protected_paths.iter().any(|p| p.is_relative())
            {
                let capture = self.capture_cwd();
                match capture {
                    Ok(cwd) => self.state.cwd = Some(cwd),
                    Err(failure) => self.evidence.cwd = Some(failure),
                }
            }
            let sinks = self.state.sinks;
            for path in &self.options.protected_paths {
                if self.evidence.cwd.is_some() {
                    break;
                }
                if let Err(f) = self.inspect_path(path, &sinks, false) {
                    self.boundary(f);
                    break;
                }
            }
            if self.options.mode == crate::extract::Mode::Extract
                && self.evidence.boundary.is_none()
                && self.evidence.cwd.is_none()
            {
                for (ordinal, _entry) in self.entries.iter().enumerate() {
                    if self.cancel.is_canceled() {
                        self.boundary(DiagnosticBoundaryFault::Admission(ReadFault::Cancelled));
                        break;
                    }
                    if let Err(f) = self.inspect_entry(ordinal, false, &sinks) {
                        self.boundary(f);
                        break;
                    }
                }
            }
        }
        self.observe_source();
        if self.evidence.failed() {
            for sink in &mut self.state.sinks {
                if sink.is_some_and(|d| !d.safe) {
                    *sink = None;
                }
            }
        }
        self.context.ledger.with_state(|s| {
            s.diagnostic_identities = self.state.sinks.map(|d| d.filter(|d| !d.safe).map(|d| (d.dev, d.ino)))
        });
        if self.evidence.failed() { Err(self.stop()) } else { Ok(()) }
    }
    pub fn emit<W, F>(&mut self, which: ZipDiagnosticSink, out: &mut W, render: F) -> ZipDiagnosticResult<u128>
    where
        W: Write + AsFd,
        F: FnOnce(ZipDiagnosticStatus<'_>, &mut ZipDiagnosticWriter<'_, W>) -> ZipDiagnosticResult<()>,
    {
        if self.evidence.write.is_some() || self.evidence.boundary.is_some() {
            return Err(self.stop());
        }
        if !self.emission_allowed || self.emitted {
            self.evidence.stop_callbacks = true;
            self.boundary(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
            return Err(self.stop());
        }
        self.emitted = true;
        if let SourceParts::Retired(retired) = &self.source
            && (retired.action != self.context.ledger.identity()
                || self.context.verify_identity(retired.owner).is_err())
        {
            self.evidence.stop_callbacks = true;
            self.boundary(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
            return Err(self.stop());
        }
        let prepared = self.state.sinks[which.index()];
        if prepared.is_none() {
            self.boundary(DiagnosticBoundaryFault::Refused { reason: "diagnostic sink was not admitted" });
            return Err(self.stop());
        }
        self.observe_source();
        let actual = self.classify(out.as_fd().as_raw_fd());
        let safe = actual.as_ref().is_ok_and(|d| d.safe);
        match actual {
            Ok(d) if Some(d) == prepared => {}
            Ok(_) => self.boundary(DiagnosticBoundaryFault::DescriptorChanged),
            Err(f) => self.boundary(f),
        }
        if let Some(ordinal) = self.ordinal
            && self.options.mode == crate::extract::Mode::Extract
            && self.evidence.boundary.is_none()
            && prepared.is_some_and(|d| !d.safe)
        {
            let sinks = self.state.sinks;
            if let Err(f) = self.inspect_entry(ordinal, true, &sinks) {
                self.boundary(f);
            }
        }
        let retired_safe_only =
            matches!(&self.source,SourceParts::Retired(retired)if retired.safe_only||!retired.confirmed_close);
        if self.evidence.boundary.is_some() || (self.evidence.source.is_some() || retired_safe_only) && !safe {
            if retired_safe_only && self.evidence.source.is_none() {
                self.boundary(DiagnosticBoundaryFault::Refused {
                    reason: "uncertain source retirement requires a safe diagnostic sink",
                });
            }
            return Err(self.stop());
        }
        if !safe && prepared.is_some_and(|d| self.aliases_source(d)) {
            self.boundary(DiagnosticBoundaryFault::Refused { reason: "diagnostic aliases retired original source" });
            return Err(self.stop());
        }
        let before = self.state.usage.accepted_bytes;
        let result = {
            let status = ZipDiagnosticStatus {
                source: self.evidence.source.as_ref(),
                boundary: self.evidence.boundary.as_ref(),
            };
            let mut writer = ZipDiagnosticWriter {
                out,
                usage: &mut self.state.usage,
                fault: &mut self.evidence.write,
                cancel: self.cancel,
                retries: self.context.options.limits.interrupted_retries,
                token: self.token,
                remaining: 1,
                attempted: &mut self.state.attempted,
            };
            render(status, &mut writer)
        };
        if let Err(stop) = result
            && (stop.token != self.token || !self.evidence.failed())
        {
            self.evidence.stop_callbacks = true;
            self.boundary(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
        }
        self.observe_source();
        match self.classify(out.as_fd().as_raw_fd()) {
            Ok(d) if Some(d) == prepared => {}
            Ok(_) => self.boundary(DiagnosticBoundaryFault::DescriptorChanged),
            Err(f) => self.boundary(f),
        }
        if let Some(ordinal) = self.ordinal
            && self.options.mode == crate::extract::Mode::Extract
            && prepared.is_some_and(|d| !d.safe)
        {
            let sinks = self.state.sinks;
            if let Err(f) = self.inspect_entry(ordinal, true, &sinks) {
                self.boundary(f);
            }
        }
        if self.evidence.failed() {
            // A render has occurred. Its provisional output and post-render
            // evidence are terminal: never call another observer or fallback.
            self.evidence.stop_callbacks = true;
            Err(self.stop())
        } else {
            Ok(self.state.usage.accepted_bytes - before)
        }
    }
    pub(super) fn finish(mut self, result: ZipObserverResult<()>) -> Evidence {
        match result {
            Ok(()) => {}
            Err(ZipObserverFault::Caller(f)) => self.evidence.write = Some(f),
            Err(ZipObserverFault::Recorded(stop)) if stop.token == self.token && self.evidence.failed() => {}
            Err(ZipObserverFault::Recorded(_)) => {
                self.evidence.stop_callbacks = true;
                self.boundary(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan));
            }
        }
        self.evidence
    }
}
#[cfg(test)]
thread_local! { pub(super) static DESCRIPTOR_STAT_FAULT: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) }; }
#[allow(clippy::unnecessary_cast)]
fn classify(
    fd: i32,
    mut operation: impl FnMut(
        ReadIoOperation,
        &mut dyn FnMut() -> std::io::Result<libc::stat>,
    ) -> Result<libc::stat, ReadFault>,
) -> Result<Descriptor, DiagnosticBoundaryFault> {
    let stat = operation(ReadIoOperation::Stat, &mut || {
        #[cfg(test)]
        if let Some(code) = DESCRIPTOR_STAT_FAULT.with(|fault| fault.take()) {
            return Err(std::io::Error::from_raw_os_error(code));
        }
        let mut s = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstat(fd, s.as_mut_ptr()) } == 0 {
            Ok(unsafe { s.assume_init() })
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
    .map_err(DiagnosticBoundaryFault::Admission)?;
    let kind = stat.st_mode & libc::S_IFMT;
    let safe = match kind {
        libc::S_IFIFO | libc::S_IFSOCK => true,
        libc::S_IFREG => false,
        libc::S_IFCHR => {
            operation(ReadIoOperation::DescriptorMode, &mut || {
                let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
                #[cfg(target_os = "macos")]
                let request = libc::TIOCGETA;
                #[cfg(not(target_os = "macos"))]
                let request = libc::TCGETS;
                if unsafe { libc::ioctl(fd, request, termios.as_mut_ptr()) } == 0 {
                    Ok(stat)
                } else {
                    Err(std::io::Error::last_os_error())
                }
            })
            .map_err(DiagnosticBoundaryFault::Admission)?;
            true
        }
        _ => return Err(DiagnosticBoundaryFault::Refused { reason: "unsupported diagnostic descriptor" }),
    };
    Ok(Descriptor { fd, dev: stat.st_dev as u64, ino: stat.st_ino as u64, kind: kind as u32, safe })
}

#[cfg(test)]
pub(super) fn protocol_test_token(action: LedgerIdentity, serial: u64) -> ZipDiagnosticStop {
    ZipDiagnosticStop { token: Token { action: Some(action), serial } }
}
