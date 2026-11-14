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

//! Finite selected-extraction control and lazy diagnostic capabilities.
use super::*;
use std::collections::TryReserveError;
mod execution;
mod guard;
mod handles;
use guard::Guard;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarOverwriteMode {
    Skip,
    Always,
    Ask,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarOverwriteDecision {
    Replace,
    Skip,
}
#[derive(Clone, Copy, Debug)]
pub struct RarExtractControlLimits {
    pub capacity: u64,
    pub work: u64,
    pub decisions: u64,
    pub io_attempts: u64,
    pub diagnostics: RarDiagnosticLimits,
}
impl Default for RarExtractControlLimits {
    fn default() -> Self {
        Self {
            capacity: 128 << 20,
            work: 1 << 32,
            decisions: 1_000_000,
            io_attempts: 1 << 32,
            diagnostics: RarDiagnosticLimits::default(),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct RarDiagnosticLimits {
    pub targets: u64,
    pub parents: u64,
    pub capacity: u64,
    pub open_handles: u64,
    pub work: u64,
    pub io_attempts: u64,
    pub checkpoint_attempts: u64,
}
impl Default for RarDiagnosticLimits {
    fn default() -> Self {
        Self {
            targets: 65536,
            parents: 131072,
            capacity: 64 << 20,
            open_handles: 8,
            work: 1 << 30,
            io_attempts: 1 << 24,
            checkpoint_attempts: 1 << 20,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarExtractControlPhase {
    #[default]
    Ready,
    Extracting,
    Terminal,
    Closed,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RarExtractControlUsage {
    pub phase: RarExtractControlPhase,
    pub capacity: u64,
    pub capacity_peak: u64,
    pub work: u64,
    pub decision_calls: u64,
    pub io_attempts: u64,
    pub diagnostic_files: u64,
    pub decision_parent_handles: u64,
    pub decision_parent_handles_peak: u64,
    pub diagnostics: RarDiagnosticUsage,
    pub teardown: RarTeardownUsage,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RarDiagnosticUsage {
    pub targets: u64,
    pub parents: u64,
    pub capacity: u64,
    pub capacity_peak: u64,
    pub work: u64,
    pub io_attempts: u64,
    pub checkpoints: u64,
    pub writer_requests: u64,
    pub checkpoint_attempts_peak: u64,
    pub open_handles: u64,
    pub open_handles_peak: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarControlHandleKind {
    Guard,
    DecisionParent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarTeardownFailure {
    Close { kind: RarControlHandleKind, raw_os_error: i32 },
    AccountingOverflow,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RarCloseUsage {
    pub successful_acquires: u64,
    pub close_attempts: u64,
    pub confirmed_closed: u64,
    pub uncertain: u64,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RarTeardownUsage {
    pub guards: RarCloseUsage,
    pub decision_parents: RarCloseUsage,
    pub accounting_poisoned: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RarTeardownSnapshot {
    pub usage: RarTeardownUsage,
    pub first_failure: Option<RarTeardownFailure>,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum RarDecisionError {
    EndOfInput,
    Read(io::Error),
    Quit,
    Canceled,
    Limit(RarDecisionLimit),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarDecisionLimit {
    InputBytes,
    IoAttempts,
    Work,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum RarExtractControlError {
    Limit { resource: RarResource, requested: u64, allowed: u64 },
    Allocation(TryReserveError),
    CounterOverflow,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum RarExtractError {
    Native(RarRunError),
    ControlNotReset { partial: RarRunSummary },
    Control { partial: RarRunSummary, entry: Option<RarEntryIdentity>, cause: RarExtractControlError },
    Decision { partial: RarRunSummary, entry: RarEntryIdentity, cause: RarDecisionError },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarDiagnosticFailureKind {
    NoDescriptor,
    UnsupportedKind,
    AliasInput,
    AliasTarget,
    AliasAncestor,
    ProjectionUnavailable,
    BindingChanged,
    PublicationUnverified,
    Metadata,
    Allocation,
    CounterOverflow,
    TeardownUncertain,
    Limit,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarDiagnosticLimit {
    Targets,
    Parents,
    Capacity,
    OpenHandles,
    Work,
    IoAttempts,
    CheckpointAttempts,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum RarDiagnosticFailure {
    NoDescriptor,
    UnsupportedKind,
    AliasInput { volume: u64 },
    AliasTarget { ordinal: u64 },
    AliasAncestor { ordinal: Option<u64> },
    ProjectionUnavailable { ordinal: u64 },
    BindingChanged { ordinal: Option<u64> },
    PublicationUnverified { ordinal: u64 },
    Metadata { operation: IoOperation, source: io::Error },
    Allocation(TryReserveError),
    CounterOverflow,
    TeardownUncertain,
    Limit(RarDiagnosticLimit),
}
impl RarDiagnosticFailure {
    fn kind(&self) -> RarDiagnosticFailureKind {
        use RarDiagnosticFailureKind as K;
        match self {
            Self::NoDescriptor => K::NoDescriptor,
            Self::UnsupportedKind => K::UnsupportedKind,
            Self::AliasInput { .. } => K::AliasInput,
            Self::AliasTarget { .. } => K::AliasTarget,
            Self::AliasAncestor { .. } => K::AliasAncestor,
            Self::ProjectionUnavailable { .. } => K::ProjectionUnavailable,
            Self::BindingChanged { .. } => K::BindingChanged,
            Self::PublicationUnverified { .. } => K::PublicationUnverified,
            Self::Metadata { .. } => K::Metadata,
            Self::Allocation(_) => K::Allocation,
            Self::CounterOverflow => K::CounterOverflow,
            Self::TeardownUncertain => K::TeardownUncertain,
            Self::Limit(_) => K::Limit,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarDiagnosticState {
    PendingTargets,
    AllowedByKind,
    AllowedByBindings,
    Muted(RarDiagnosticFailureKind),
    Closed,
}
#[derive(Clone, Copy, Debug)]
pub struct RarDiagnosticSnapshot {
    pub state: RarDiagnosticState,
    pub checkpoint: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct RarTargetSnapshot {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub modified: (i64, i64),
    pub changed: (i64, i64),
}
impl From<SourceStamp> for RarTargetSnapshot {
    fn from(s: SourceStamp) -> Self {
        Self { device: s.device, inode: s.inode, bytes: s.len, modified: s.mtime, changed: s.ctime }
    }
}
pub struct RarOverwriteConflict<'a> {
    pub entry: &'a RarEntryIdentity,
    pub target: &'a Path,
    pub existing: RarTargetSnapshot,
}
pub trait RarExtractObserver {
    fn overwrite(
        &mut self,
        conflict: &RarOverwriteConflict<'_>,
        diagnostic: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError>;
    fn entry(&mut self, entry: &RarEntryOutcome, diagnostic: RarDiagnostic<'_>);
}
#[derive(Debug)]
pub struct RarExtractAftermath {
    pub last_diagnostic: RarDiagnosticSnapshot,
    pub diagnostic_failure: Option<RarDiagnosticFailure>,
    pub usage: RarExtractControlUsage,
    pub teardown: RarTeardownSnapshot,
}
#[derive(Debug)]
pub struct RarResetError {
    pub usage: RarExtractControlUsage,
    pub teardown: RarTeardownSnapshot,
}
#[derive(Debug)]
pub struct RarDiagnosticRecovery {
    pub diagnostic: Option<File>,
    pub aftermath: RarExtractAftermath,
}
#[derive(Debug)]
pub struct RarExtractFinished {
    pub outcome: Result<RarRunSummary, RarExtractError>,
    pub last_diagnostic: RarDiagnosticSnapshot,
    pub diagnostic_failure: Option<RarDiagnosticFailure>,
    pub usage: RarExtractControlUsage,
    pub teardown: RarTeardownSnapshot,
}

/// One explicit control epoch. The supplied File is retained exactly, without cloning.
pub struct RarExtractControl {
    diagnostic: Option<File>,
    overwrite: RarOverwriteMode,
    limits: RarExtractControlLimits,
    usage: RarExtractControlUsage,
    state: RarDiagnosticState,
    failure: Option<RarDiagnosticFailure>,
    teardown_failure: Option<RarTeardownFailure>,
    guard: Guard,
    decision_parent: Option<File>,
}
impl RarExtractControl {
    pub fn new(diagnostic: Option<File>, overwrite: RarOverwriteMode, limits: RarExtractControlLimits) -> Self {
        Self {
            usage: RarExtractControlUsage { diagnostic_files: u64::from(diagnostic.is_some()), ..Default::default() },
            diagnostic,
            overwrite,
            limits,
            state: RarDiagnosticState::PendingTargets,
            failure: None,
            teardown_failure: None,
            guard: Guard::default(),
            decision_parent: None,
        }
    }
    pub fn early_diagnostic(&mut self) -> RarDiagnostic<'_> {
        RarDiagnostic { control: self, sources: None }
    }
    pub fn usage(&self) -> RarExtractControlUsage {
        self.usage
    }
    pub fn diagnostic_failure(&self) -> Option<&RarDiagnosticFailure> {
        self.failure.as_ref()
    }
    pub fn teardown(&self) -> RarTeardownSnapshot {
        RarTeardownSnapshot { usage: self.usage.teardown, first_failure: self.teardown_failure }
    }
    #[allow(
        clippy::result_large_err,
        reason = "the required scalar aftermath is owned and must not allocate on refusal"
    )]
    pub fn reset(&mut self) -> Result<RarExtractAftermath, RarResetError> {
        let last = self.snapshot();
        self.cleanup();
        if self.usage.teardown.accounting_poisoned
            || self.usage.teardown.guards.uncertain != 0
            || self.usage.teardown.decision_parents.uncertain != 0
        {
            return Err(RarResetError { usage: self.usage, teardown: self.teardown() });
        }
        let aftermath = self.aftermath(last);
        self.usage =
            RarExtractControlUsage { diagnostic_files: u64::from(self.diagnostic.is_some()), ..Default::default() };
        self.state = RarDiagnosticState::PendingTargets;
        self.teardown_failure = None;
        Ok(aftermath)
    }
    pub fn into_diagnostic(mut self) -> RarDiagnosticRecovery {
        let last = self.snapshot();
        self.cleanup();
        let aftermath = self.aftermath(last);
        RarDiagnosticRecovery { diagnostic: self.diagnostic.take(), aftermath }
    }
    fn aftermath(&mut self, last: RarDiagnosticSnapshot) -> RarExtractAftermath {
        RarExtractAftermath {
            last_diagnostic: last,
            diagnostic_failure: self.failure.take(),
            usage: self.usage,
            teardown: self.teardown(),
        }
    }
    fn snapshot(&self) -> RarDiagnosticSnapshot {
        RarDiagnosticSnapshot { state: self.state, checkpoint: self.usage.diagnostics.checkpoints }
    }
    fn mute(&mut self, failure: RarDiagnosticFailure) {
        if self.failure.is_none() {
            self.state = RarDiagnosticState::Muted(failure.kind());
            self.failure = Some(failure);
        }
        self.release_guard();
    }
    fn cleanup(&mut self) {
        self.close_parent();
        self.release_guard();
        self.usage.capacity = 0;
        self.usage.phase = RarExtractControlPhase::Closed;
        self.state = RarDiagnosticState::Closed;
    }
    fn native_charge(&mut self, resource: RarResource, count: u64) -> Result<(), RarExtractControlError> {
        let (current, allowed) = match resource {
            RarResource::ExtractControlWork => (&mut self.usage.work, self.limits.work),
            RarResource::ExtractControlIoAttempts => (&mut self.usage.io_attempts, self.limits.io_attempts),
            RarResource::ExtractDecisionCalls => (&mut self.usage.decision_calls, self.limits.decisions),
            _ => unreachable!(),
        };
        let requested = current.checked_add(count).ok_or(RarExtractControlError::CounterOverflow)?;
        if requested > allowed {
            return Err(RarExtractControlError::Limit { resource, requested, allowed });
        }
        *current = requested;
        Ok(())
    }
    fn check_capacity(&self, value: u64) -> Result<(), RarExtractControlError> {
        if value > self.limits.capacity {
            return Err(RarExtractControlError::Limit {
                resource: RarResource::ExtractControlCapacity,
                requested: value,
                allowed: self.limits.capacity,
            });
        }
        Ok(())
    }
    fn capacity(&mut self, value: u64) -> Result<(), RarExtractControlError> {
        self.check_capacity(value)?;
        self.usage.capacity = value;
        self.usage.capacity_peak = self.usage.capacity_peak.max(value);
        Ok(())
    }
}
impl Drop for RarExtractControl {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Lazy historical view. End each File borrow before waiting or retrying.
/// Never clone, swap, replace, move out, close or substitute the lent File.
pub struct RarDiagnostic<'a> {
    control: &'a mut RarExtractControl,
    sources: Option<&'a [HeldVolume]>,
}
impl RarDiagnostic<'_> {
    pub fn snapshot(&self) -> RarDiagnosticSnapshot {
        self.control.snapshot()
    }
    /// Refresh before every bounded, no-wait emission; reacquire after every wait.
    pub fn writer(&mut self) -> Option<&mut File> {
        let c = &mut *self.control;
        let Some(requests) = c.usage.diagnostics.writer_requests.checked_add(1) else {
            c.mute(RarDiagnosticFailure::CounterOverflow);
            return None;
        };
        c.usage.diagnostics.writer_requests = requests;
        if matches!(c.state, RarDiagnosticState::Muted(_) | RarDiagnosticState::Closed) {
            return None;
        }
        if let Err(f) = c.refresh(self.sources) {
            c.mute(f);
            return None;
        }
        if matches!(c.state, RarDiagnosticState::AllowedByKind | RarDiagnosticState::AllowedByBindings) {
            c.diagnostic.as_mut()
        } else {
            None
        }
    }
}
/// Terminal historical outcome borrowing only source capabilities and control.
pub struct RarControlledExtractReport<'a> {
    outcome: Option<Result<RarRunSummary, RarExtractError>>,
    sources: &'a [HeldVolume],
    control: &'a mut RarExtractControl,
}
impl RarControlledExtractReport<'_> {
    pub fn outcome(&self) -> &Result<RarRunSummary, RarExtractError> {
        self.outcome.as_ref().expect("live report")
    }
    pub fn diagnostic(&mut self) -> RarDiagnostic<'_> {
        RarDiagnostic { control: self.control, sources: Some(self.sources) }
    }
    pub fn diagnostic_failure(&self) -> Option<&RarDiagnosticFailure> {
        self.control.diagnostic_failure()
    }
    pub fn usage(&self) -> RarExtractControlUsage {
        self.control.usage()
    }
    pub fn teardown(&self) -> RarTeardownSnapshot {
        self.control.teardown()
    }
    pub fn finish(mut self) -> RarExtractFinished {
        let last = self.control.snapshot();
        self.control.cleanup();
        RarExtractFinished {
            outcome: self.outcome.take().expect("live report"),
            last_diagnostic: last,
            diagnostic_failure: self.control.failure.take(),
            usage: self.control.usage(),
            teardown: self.control.teardown(),
        }
    }
}
impl Drop for RarControlledExtractReport<'_> {
    fn drop(&mut self) {
        self.control.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_counter_overflows_preserve_values_without_allocating_error_payloads() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.usage.work = u64::MAX;
        c.usage.io_attempts = u64::MAX;
        c.usage.decision_calls = u64::MAX;
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(true));
        for resource in
            [RarResource::ExtractControlWork, RarResource::ExtractControlIoAttempts, RarResource::ExtractDecisionCalls]
        {
            assert!(matches!(c.native_charge(resource, 1), Err(RarExtractControlError::CounterOverflow)));
        }
        let recovery = c.into_diagnostic();
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(false));
        assert_eq!(recovery.aftermath.usage.work, u64::MAX);
    }
}
