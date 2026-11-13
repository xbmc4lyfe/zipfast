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
use crate::zip::recovery::{MemberRecovery, RecoveryEntry, RecoveryOptions, RecoveryOutcome, RecoveryReport};
use layout::recovery::{DescriptorRepair, RecoveryOutcome as Candidate, RecoveryUsage, recover_member};

/// A held-source recovery plan and a separately anchored, absent destination.
pub struct RecoveryPlan {
    source: RewritePlan,
    destination: Parent,
}

struct Prepared {
    output: preflight::Prepared,
    repairs: Vec<Option<DescriptorRepair>>,
}

impl RecoveryPlan {
    /// Open the original without following its final symlink, snapshot its
    /// central directory and bind a distinct, absent output name. No writes.
    pub fn open(source: &Path, destination: &Path, options: RecoveryOptions) -> Result<Self> {
        let mut rewrite = RewriteOptions::new(Replacement::LastWriterWins);
        rewrite.verification = Verification::Full;
        rewrite.limits = options.limits;
        rewrite.durability = options.durability;
        rewrite.output_permissions = Some(options.output_permissions);
        rewrite.cancel = options.cancel;
        let mut source = RewritePlan::open(source, rewrite)?;
        let limits = source.options.limits.common;
        let attempts = Attempts::with_limits(&source.options.cancel, limits.transaction_attempts, &source.attempts);
        let remaining = limits
            .plan_capacity
            .checked_sub(source.fixed_capacity()?)
            .ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?;
        let destination = Parent::bind(destination, &attempts, remaining)?;
        if destination.lookup(&destination.leaf, &attempts)?.is_some() {
            return Err(CreateError::Conflict.into());
        }
        let capacity = add(source.fixed_capacity()?, destination.capacity())?;
        limit(capacity, limits.plan_capacity, CreateLimit::PlanCapacity)?;
        source.usage.common.plan.capacity = source.usage.common.plan.capacity.max(capacity);
        check_source(&source.parent, &source.file, source.stamp, &attempts)?;
        Ok(Self { source, destination })
    }

    pub fn metadata(&self) -> Arc<Metadata> {
        self.source.metadata()
    }
    pub fn usage(&self) -> RewriteUsage {
        self.source.usage()
    }

    /// Assess all candidates in central order, then publish the verified
    /// survivors. If none survive, leave the destination absent.
    pub fn recover(mut self) -> RecoveryReport {
        let mut entries = Vec::new();
        let outcome = match self.prepare(&mut entries) {
            Err(cause) => {
                Err(self.source.failure(RewriteStage::Planning, cause, Publication::NotPublished, CleanupState::Clean))
            }
            Ok(_) if self.source.usage.common.plan.entries == 0 => {
                Ok(RecoveryOutcome::NoMembers { usage: self.usage() })
            }
            Ok(prepared) => self.publish(prepared),
        };
        RecoveryReport { entries, outcome }
    }

    fn prepare(&mut self, entries: &mut Vec<RecoveryEntry>) -> Result<Prepared> {
        let source = &mut self.source;
        let limits = source.options.limits;
        let count = source.metadata.len();
        let fixed = add(source.fixed_capacity()?, self.destination.capacity())?;
        let per_member = size_of::<Member>()
            + size_of::<usize>()
            + size_of::<u64>()
            + size_of::<Option<DescriptorRepair>>()
            + size_of::<WrittenEntry>()
            + size_of::<EntryVerification>()
            + size_of::<RecoveryEntry>();
        let minimum = add(fixed, (count as u64).checked_mul(per_member as u64).ok_or(CreateError::Overflow)?)?;
        limit(minimum, limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
        let mut members = Vec::new();
        let mut order = Vec::new();
        let mut boundaries = Vec::new();
        let mut repairs = Vec::new();
        let mut written = Vec::new();
        members.try_reserve_exact(count)?;
        order.try_reserve_exact(count)?;
        boundaries.try_reserve_exact(count)?;
        repairs.try_reserve_exact(count)?;
        written.try_reserve_exact(count)?;
        entries.try_reserve_exact(count)?;
        let outcomes = VerificationSummary::reserve(count)?;
        let capacities = [
            bytes_for::<Member>(members.capacity())?,
            bytes_for::<usize>(order.capacity())?,
            bytes_for::<u64>(boundaries.capacity())?,
            bytes_for::<Option<DescriptorRepair>>(repairs.capacity())?,
            bytes_for::<WrittenEntry>(written.capacity())?,
            bytes_for::<EntryVerification>(outcomes.entries.capacity())?,
            bytes_for::<RecoveryEntry>(entries.capacity())?,
        ];
        let actual = capacities.into_iter().try_fold(fixed, add)?;
        limit(actual, limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
        source.usage.common.plan.capacity = source.usage.common.plan.capacity.max(actual);
        members.resize(count, Member::default());
        boundaries.resize(count, 0);
        repairs.resize(count, None);
        order.extend(0..count);
        let at = |ordinal| source.metadata.view(ordinal).physical_local_header_offset();
        sort_indices(&mut order, |a, b| {
            work(&source.options, &mut source.usage, 1)?;
            Ok(at(a).cmp(&at(b)))
        })?;
        let central = source.metadata.directory_range().start;
        for (position, &ordinal) in order.iter().enumerate() {
            work(&source.options, &mut source.usage, 1)?;
            let end = order.get(position + 1).map_or(central, |&next| at(next));
            if at(ordinal) >= end || end > central {
                return Err(RewriteError::UnsupportedLayout("ambiguous recovery local offsets"));
            }
            boundaries[ordinal] = end;
        }
        let attempts =
            Attempts::with_limits(&source.options.cancel, limits.common.transaction_attempts, &source.attempts);
        check_source(&source.parent, &source.file, source.stamp, &attempts)?;
        self.destination.check(&attempts)?;
        let prefix = order.first().map_or(central, |&ordinal| at(ordinal));
        layout::prefix(
            &mut Reader {
                file: &source.file,
                attempts: &attempts,
                bytes: &mut source.usage.layout_read_bytes,
                max: limits.layout_read_bytes,
                exhausted: ReadLimit::Rewrite(RewriteLimit::LayoutReadBytes),
            },
            prefix,
            limits.prefix_bytes,
        )?;
        let mut recovery_usage =
            RecoveryUsage { layout_read_bytes: source.usage.layout_read_bytes, payload: source.usage.source_payload };
        let mut survivors = 0;
        for ordinal in 0..count {
            work(&source.options, &mut source.usage, 1)?;
            let result = recover_member(
                &mut source.file,
                source.metadata.view(ordinal),
                boundaries[ordinal],
                limits,
                &attempts,
                &mut recovery_usage,
            );
            source.usage.layout_read_bytes = recovery_usage.layout_read_bytes;
            source.usage.source_payload = recovery_usage.payload;
            let outcome = match result? {
                Candidate::Verified(member) => {
                    members[ordinal] = member.framing;
                    repairs[ordinal] = member.descriptor;
                    survivors += 1;
                    MemberRecovery::Verified { descriptor_repaired: member.descriptor.is_some() }
                }
                Candidate::Omitted(issue) => {
                    source.actions[ordinal] = Action::Remove;
                    MemberRecovery::Omitted(issue)
                }
            };
            entries.push(RecoveryEntry { source_ordinal: ordinal, outcome });
        }
        check_source(&source.parent, &source.file, source.stamp, &attempts)?;
        source.usage.common.plan.entries = survivors;
        if survivors != 0 {
            output_count(survivors, limits.common)?;
            let mut feasibility = preflight::Feasibility::new(source, prefix, true);
            let mut packed = 0;
            for (ordinal, member) in members.iter().enumerate() {
                if matches!(source.actions[ordinal], Action::Keep) {
                    let entry = source.metadata.view(ordinal);
                    feasibility.preserved(
                        raw_entry(&source.metadata, *member, ordinal),
                        entry.raw_unicode_path().map_or(0, |name| name.len() as u64),
                    )?;
                    packed = add(packed, entry.packed_size())?;
                }
            }
            feasibility.finish(survivors, source.attempts.get(), packed)?;
        }
        Ok(Prepared { output: preflight::Prepared { prefix, members, outcomes, written }, repairs })
    }

    fn publish(mut self, mut prepared: Prepared) -> std::result::Result<RecoveryOutcome, RewriteFailure> {
        let source = &mut self.source;
        let attempts = Attempts::with_limits(
            &source.options.cancel,
            source.options.limits.common.transaction_attempts,
            &source.attempts,
        );
        let stage = Stage::create(&self.destination, &attempts, &mut source.usage.common.stage_attempts);
        let mut stage = match stage {
            Ok(stage) => stage,
            Err(error) => {
                return Err(source.failure(
                    RewriteStage::StageCreate,
                    error.into(),
                    Publication::NotPublished,
                    CleanupState::Clean,
                ));
            }
        };
        let result = self.execute(&mut stage, &mut prepared);
        let publication = result.as_ref().map_or_else(|stop| stop.publication, |_| Publication::Published);
        let reserve_count = Cell::new(0);
        let reserve = Attempts::finalization(&reserve_count);
        let recovery = match &result {
            Err(stop) if publication == Publication::Unknown => stop.stage_identity.map(|identity| {
                let observed = self
                    .destination
                    .check(&reserve)
                    .and_then(|()| self.destination.lookup(&self.destination.leaf, &reserve));
                let destination = match observed {
                    Ok(None) => DestinationObservation::Missing,
                    Ok(Some(NameState::Regular(stamp))) => DestinationObservation::Regular(file_identity(stamp)),
                    Ok(Some(NameState::Other)) => DestinationObservation::Other,
                    Err(error) => DestinationObservation::Unavailable(error),
                };
                Box::new(Recovery { stage_identity: identity, destination })
            }),
            _ => None,
        };
        let aftermath = cleanup(&self.destination, &stage, publication, &reserve);
        let clean = matches!(aftermath, Aftermath::Clean);
        let cleanup = aftermath.into_public(stage);
        self.source.usage.common.finalization_attempts = reserve_count.get();
        let verification = match result {
            Ok(verification) => verification,
            Err(stop) => {
                let mut failure = self.source.failure(stop.stage, stop.cause, publication, cleanup);
                failure.recovery = recovery;
                return Err(failure);
            }
        };
        let durability = if self.source.options.durability == Durability::SyncFileAndDirectory {
            let synced = after_commit_sync(&self.destination.file, &reserve);
            self.source.usage.common.finalization_attempts = reserve_count.get();
            if let Err(error) = synced {
                let mut failure = self.source.failure(RewriteStage::DirectorySync, error.into(), publication, cleanup);
                failure.verification = Some(Box::new(verification));
                return Err(failure);
            }
            DurabilityState::Synced
        } else {
            DurabilityState::NotRequested
        };
        if !clean || self.source.options.cancel.is_canceled() {
            let cause = if clean { CreateError::Canceled } else { CreateError::CleanupIncomplete };
            let mut failure = self.source.failure(RewriteStage::Cleanup, cause.into(), publication, cleanup);
            failure.verification = Some(Box::new(verification));
            failure.durability = durability;
            return Err(failure);
        }
        let usage = self.usage();
        Ok(RecoveryOutcome::Published(RewrittenArchive {
            destination: self.destination.destination,
            verification,
            publication,
            durability,
            cleanup,
            usage,
        }))
    }

    fn execute(
        &mut self,
        stage: &mut Stage,
        prepared: &mut Prepared,
    ) -> std::result::Result<VerificationSummary, Stop> {
        let source = &mut self.source;
        let options = &source.options;
        let attempts =
            Attempts::with_limits(&options.cancel, options.limits.common.transaction_attempts, &source.attempts);
        let original = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::StageCreate)?;
        check_source(&source.parent, &source.file, source.stamp, &attempts).at(RewriteStage::SourceRead)?;
        if original.identity == source.stamp.identity {
            return Err(Stop::at(RewriteStage::SourceRead, CreateError::StageChanged));
        }
        let output = OutputPlan {
            metadata: &source.metadata,
            options,
            source: &source.file,
            source_stamp: source.stamp,
            inputs: &[],
            actions: &source.actions,
            appends: &[],
            repairs: Some(&prepared.repairs),
        };
        let summary = output.write_stage(stage, original, &mut prepared.output, attempts, &mut source.usage)?;
        let finalized = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Finish)?;
        #[cfg(test)]
        super::super::test_event(super::super::Event::AfterFinish, Some(stage.path())).at(RewriteStage::Finish)?;
        check_source(&source.parent, &source.file, source.stamp, &attempts).at(RewriteStage::Verify)?;
        let manifest = Manifest {
            metadata: &source.metadata,
            members: &prepared.output.members,
            inputs: &[],
            actions: &source.actions,
            appends: &[],
            entries: &prepared.output.written,
            prefix: prepared.output.prefix,
            summary,
            repairs: Some(&prepared.repairs),
        };
        let outcomes = std::mem::take(&mut prepared.output.outcomes);
        let verification = manifest
            .verify(&source.file, &mut stage.file, options, &attempts, &mut source.usage, outcomes)
            .at(RewriteStage::Verify)?;
        check_source(&source.parent, &source.file, source.stamp, &attempts).at(RewriteStage::Verify)?;
        #[cfg(test)]
        super::super::test_event(super::super::Event::AfterVerify, Some(stage.path())).at(RewriteStage::Verify)?;
        if unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Permissions)? != finalized {
            return Err(Stop::at(RewriteStage::Permissions, CreateError::StageChanged));
        }
        let mode = options.output_permissions.expect("recovery has explicit output permissions");
        unix::chmod(&stage.file, mode, &attempts).at(RewriteStage::Permissions)?;
        let ready = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Permissions)?;
        if !ready.same_payload(finalized) || ready.mode != mode {
            return Err(Stop::at(RewriteStage::Permissions, CreateError::StageChanged));
        }
        if options.durability == Durability::SyncFileAndDirectory {
            #[cfg(test)]
            super::super::test_event(super::super::Event::FileSync, Some(stage.path())).at(RewriteStage::FileSync)?;
            unix::sync_stage(&stage.file, &attempts).at(RewriteStage::FileSync)?;
        }
        #[cfg(test)]
        super::super::test_event(super::super::Event::BeforeFinalCheck, Some(stage.path()))
            .at(RewriteStage::Precommit)?;
        check_source(&source.parent, &source.file, source.stamp, &attempts).at(RewriteStage::Precommit)?;
        self.destination.check(&attempts).at(RewriteStage::Precommit)?;
        let held = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Precommit)?;
        let named = self.destination.lookup(stage.name(), &attempts).at(RewriteStage::Precommit)?;
        if held != ready || !matches!(named, Some(NameState::Regular(stamp)) if stamp == held) {
            return Err(Stop::at(RewriteStage::Precommit, CreateError::StageChanged));
        }
        #[cfg(test)]
        super::super::test_event(super::super::Event::AfterFinalCheck, Some(stage.path()))
            .at(RewriteStage::Precommit)?;
        self.destination.publish_noreplace(stage.name(), &attempts).map_err(|error| Stop {
            stage: RewriteStage::Publish,
            publication: match error {
                PublishError::Definite(_) => Publication::NotPublished,
                PublishError::Uncertain(_) => Publication::Unknown,
            },
            cause: error.into_cause().into(),
            stage_identity: Some(file_identity(held)),
        })?;
        #[cfg(test)]
        let _ = super::super::test_event(super::super::Event::AfterCommit, Some(stage.path()));
        Ok(verification)
    }
}
