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

use std::fmt;
use std::sync::Arc;

use crate::error::{Error, RarFailure, RarFault, RarIntegrityReason, RarPasswordEvidence, RarScope};

use super::{Mode, Summary};

/// One completion reported by a RAR bulk run.
#[derive(Debug)]
#[non_exhaustive]
pub struct RarEntryOutcome {
    pub entry: RarEntryIdentity,
    /// Raw compression method bits from this member's initial header.
    pub method: u8,
    pub outcome: RarOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RarEntryIdentity {
    /// Zero-based listing index, absent for a continuation without its initial header.
    pub index: Option<u64>,
    /// Zero-based reporting order, including orphan continuations.
    pub order: u64,
    /// Stored member name, before output path policy.
    pub name: String,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RarOutcome {
    /// Complete framing and all available final checks passed.
    Verified {
        bytes: u64,
        checks: RarVerification,
        output: RarOutput,
    },
    Directory,
    Skipped(RarSkipReason),
    Failed(Arc<RarFailure>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarSkipReason {
    ExistingTarget,
    OlderVersion(u64),
    MissingStart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarOutput {
    Tested,
    /// Output was finished and published. No durability guarantee is implied.
    Written,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RarVerification {
    pub size_checked: bool,
    pub crc32_checked: bool,
    pub blake2sp_checked: bool,
    pub password: RarPasswordEvidence,
}

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct RarRunSummary {
    pub encountered: u64,
    pub matched: u64,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub failed: u64,
    /// Successfully opened volumes, including those opened before a terminal failure.
    pub volumes: u64,
    pub match_state: RarMatchState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum RarMatchState {
    #[default]
    NoMatch,
    Matched,
}

/// Terminal failure, with the completions reported before the run returned.
#[derive(Debug)]
#[non_exhaustive]
pub struct RarRunError {
    pub partial: RarRunSummary,
    pub entry: Option<RarEntryIdentity>,
    pub failure: Arc<RarFailure>,
}

impl fmt::Display for RarRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(entry) = &self.entry {
            write!(f, "{}: ", entry.name)?;
        }
        self.failure.fmt(f)
    }
}

impl std::error::Error for RarRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.failure.as_ref())
    }
}

#[derive(Clone)]
pub(crate) struct EntryContext {
    pub(crate) entry: RarEntryIdentity,
    pub(crate) method: u8,
    pub(crate) password: RarPasswordEvidence,
}

impl EntryContext {
    pub(crate) fn scope(&self) -> RarScope {
        RarScope::Member { index: self.entry.index }
    }

    pub(crate) fn integrity(&self, reason: RarIntegrityReason, plaintext_dependent: bool) -> RarFailure {
        RarFailure::integrity(self.scope(), reason, self.password, plaintext_dependent)
    }

    pub(crate) fn event(&self, outcome: RarOutcome) -> RarEntryOutcome {
        RarEntryOutcome { entry: self.entry.clone(), method: self.method, outcome }
    }

    pub(crate) fn checks(&self, size_checked: bool, crc32_checked: bool, blake2sp_checked: bool) -> RarVerification {
        RarVerification { size_checked, crc32_checked, blake2sp_checked, password: self.password }
    }
}

pub(crate) type RunResult<T> = Result<T, RunFault>;

#[derive(Debug)]
pub(crate) enum RunFault {
    Fault(RarFault),
    Reported { entry: RarEntryIdentity, failure: Arc<RarFailure> },
}

impl From<RarFault> for RunFault {
    fn from(fault: RarFault) -> Self {
        Self::Fault(fault)
    }
}

impl RunFault {
    pub(super) fn into_legacy(self) -> Error {
        match self {
            Self::Fault(fault) => fault.into_legacy(),
            Self::Reported { .. } => unreachable!("only typed runs report terminal events"),
        }
    }

    pub(super) fn into_public(self, partial: RarRunSummary) -> RarRunError {
        let (entry, failure) = match self {
            Self::Fault(fault) => (None, Arc::from(fault.failure)),
            Self::Reported { entry, failure } => (Some(entry), failure),
        };
        RarRunError { partial, entry, failure }
    }
}

pub(super) enum Reports<'a> {
    Legacy { summary: Summary, callback: &'a mut dyn FnMut(&str) },
    Typed { summary: RarRunSummary, callback: &'a mut dyn FnMut(&RarEntryOutcome) },
}

impl Reports<'_> {
    pub(super) fn typed(&self) -> bool {
        matches!(self, Self::Typed { .. })
    }

    pub(super) fn encounter(
        &mut self,
        normal: bool,
        order: &mut u64,
        name: String,
        method: u8,
    ) -> RunResult<EntryContext> {
        let position = *order;
        add(order, 1)?;
        let index = match self {
            Self::Typed { summary, .. } if normal => {
                let index = summary.encountered;
                add(&mut summary.encountered, 1)?;
                summary.matched = summary.encountered;
                summary.match_state = RarMatchState::Matched;
                Some(index)
            }
            _ => None,
        };
        let entry = RarEntryIdentity { index, order: position, name };
        Ok(EntryContext { entry, method, password: RarPasswordEvidence::NotEncrypted })
    }

    pub(super) fn volume(&mut self) -> RunResult<()> {
        match self {
            Self::Legacy { summary, .. } => add(&mut summary.volumes, 1),
            Self::Typed { summary, .. } => add(&mut summary.volumes, 1),
        }
    }

    pub(super) fn verified(
        &mut self,
        ctx: &EntryContext,
        bytes: u64,
        checks: RarVerification,
        mode: Mode,
    ) -> RunResult<()> {
        match self {
            Self::Legacy { summary, .. } => complete_file(&mut summary.files, &mut summary.bytes, bytes),
            Self::Typed { summary, callback } => {
                complete_file(&mut summary.files, &mut summary.bytes, bytes)?;
                let output = match mode {
                    Mode::Test => RarOutput::Tested,
                    Mode::Extract => RarOutput::Written,
                };
                callback(&ctx.event(RarOutcome::Verified { bytes, checks, output }));
                Ok(())
            }
        }
    }

    pub(super) fn directory(&mut self, ctx: &EntryContext) -> RunResult<()> {
        match self {
            Self::Legacy { summary, .. } => add(&mut summary.dirs, 1),
            Self::Typed { summary, callback } => {
                add(&mut summary.dirs, 1)?;
                callback(&ctx.event(RarOutcome::Directory));
                Ok(())
            }
        }
    }

    pub(super) fn skipped(&mut self, ctx: &EntryContext, reason: RarSkipReason) -> RunResult<()> {
        match self {
            Self::Legacy { summary, callback } => {
                match reason {
                    RarSkipReason::ExistingTarget => callback(&format!("{}: exists, skipped", ctx.entry.name)),
                    RarSkipReason::OlderVersion(v) => {
                        callback(&format!("{}: older version {v}, skipped", ctx.entry.name))
                    }
                    RarSkipReason::MissingStart => {}
                }
                add(&mut summary.skipped, 1)
            }
            Self::Typed { summary, callback } => {
                add(&mut summary.skipped, 1)?;
                callback(&ctx.event(RarOutcome::Skipped(reason)));
                Ok(())
            }
        }
    }

    pub(super) fn failed(
        &mut self,
        ctx: &EntryContext,
        failure: Arc<RarFailure>,
        legacy: impl fmt::Display,
    ) -> RunResult<()> {
        match self {
            Self::Legacy { summary, callback } => {
                let line = format!("{}: {legacy}", ctx.entry.name);
                callback(&line);
                summary.errors.push(line);
                Ok(())
            }
            Self::Typed { summary, callback } => {
                add(&mut summary.failed, 1)?;
                callback(&ctx.event(RarOutcome::Failed(failure)));
                Ok(())
            }
        }
    }

    pub(super) fn terminal(&mut self, ctx: &EntryContext, fault: RarFault) -> RunFault {
        if !self.typed() {
            return fault.into();
        }
        let failure: Arc<RarFailure> = Arc::from(fault.failure);
        match self.failed(ctx, Arc::clone(&failure), "") {
            Ok(()) => RunFault::Reported { entry: ctx.entry.clone(), failure },
            Err(limit) => limit,
        }
    }
}

fn complete_file(files: &mut u64, bytes: &mut u64, size: u64) -> RunResult<()> {
    let files_after = files.checked_add(1).ok_or_else(RarFault::counter_limit)?;
    let bytes_after = bytes.checked_add(size).ok_or_else(RarFault::counter_limit)?;
    *files = files_after;
    *bytes = bytes_after;
    Ok(())
}

fn add(counter: &mut u64, value: u64) -> RunResult<()> {
    *counter = counter.checked_add(value).ok_or_else(RarFault::counter_limit)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_reporter_releases_failures_and_does_not_format_legacy_messages() {
        struct LegacyMessage;
        impl fmt::Display for LegacyMessage {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                panic!("typed reporter formatted a legacy message");
            }
        }

        let mut seen = 0;
        let mut callback = |event: &RarEntryOutcome| {
            assert_eq!(event.entry.order, seen);
            seen += 1;
        };
        let mut reports = Reports::Typed { summary: RarRunSummary::default(), callback: &mut callback };
        let mut order = 0;
        for _ in 0..1300 {
            let ctx = reports.encounter(true, &mut order, "file".into(), 0).unwrap();
            let failure = Arc::new(ctx.integrity(RarIntegrityReason::TruncatedData, false));
            let weak = Arc::downgrade(&failure);
            reports.failed(&ctx, failure, LegacyMessage).unwrap();
            assert!(weak.upgrade().is_none());
        }
        let Reports::Typed { summary, .. } = reports else { unreachable!() };
        assert_eq!((summary.failed, seen), (1300, 1300));
    }

    #[test]
    fn typed_counts_reject_overflow_without_emitting_or_counting_the_entry() {
        let mut callback = |_: &RarEntryOutcome| panic!("overflow emitted a completion");
        let mut reports = Reports::Typed {
            summary: RarRunSummary { files: 42, bytes: u64::MAX, ..RarRunSummary::default() },
            callback: &mut callback,
        };
        let mut order = 0;
        let ctx = reports.encounter(true, &mut order, "file".into(), 0).unwrap();
        let error = reports.verified(&ctx, 1, ctx.checks(true, false, false), Mode::Test).unwrap_err();
        let RunFault::Fault(fault) = error else { panic!("overflow was attached to an event") };
        assert!(matches!(
            fault.failure.as_ref(),
            RarFailure::Limit { resource: crate::error::RarResource::Counter, .. }
        ));
        let Reports::Typed { summary, .. } = reports else { unreachable!() };
        assert_eq!((summary.files, summary.bytes), (42, u64::MAX));
    }
}
