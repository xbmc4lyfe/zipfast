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

use std::{cell::Cell, fs::File, io, mem::size_of, os::unix::fs::FileExt, path::Path, sync::Arc};

use zip_container::CentralRecord;

pub(super) use crate::zip::create::native::unix;
use crate::zip::create::native::{
    Attempts, PlannedEntry, add, capture, input_cost, limit, name_bytes, prepare_input, sort_indices,
    transaction::{Aftermath, RawIo, SourceInput, cleanup, writer_error},
    validate_input, writer_limit,
};
use crate::zip::create::{self, CollisionPath, CreateEntryId, CreateLimit};
use crate::zip::write::raw::PreparedRaw;
use crate::zip::write::{
    EntryName, EntryOptions, EntryWritten, InputLength, IoStage, WriteSummary, WriterOptions, ZipWriter,
};
use crate::zip::{EntryId, FLAG_ENCRYPTED, FLAG_UTF8, METHOD_DEFLATE, METHOD_STORED, Metadata};

use super::layout::{self, DirectoryBudget, Member, ReadLimit, Reader};
use super::verify::{Manifest, WrittenEntry, declared_payload};
use super::*;
use unix::{NameState, Parent, PublishError, Stage, Stamp};

mod names;
mod preflight;
pub(in crate::zip) mod recovery;

#[derive(Clone, Copy, Debug)]
pub(super) enum Action {
    Keep,
    Remove,
    Replace(usize),
}

/// A read-only plan against the originally opened archive. Admitting edits
/// takes no staging or publication actions.
pub struct RewritePlan {
    parent: Parent,
    file: File,
    stamp: Stamp,
    metadata: Arc<Metadata>,
    actions: Vec<Action>,
    inputs: Vec<PlannedEntry>,
    appends: Vec<usize>,
    names: names::Exact,
    variable_capacity: u64,
    options: RewriteOptions,
    usage: RewriteUsage,
    attempts: Cell<u64>,
}

impl RewritePlan {
    /// Open an existing regular archive through its held parent, without
    /// following a symlink in the destination's final component.
    pub fn open(path: &Path, options: RewriteOptions) -> Result<Self> {
        Self::open_source(path, options, false, None)
    }

    /// Opens a rewrite plan with central extended Unix timestamps (UT) for
    /// callers comparing source freshness.
    ///
    /// [`EntryMetadata::raw_mtime_override()`](crate::zip::EntryMetadata::raw_mtime_override)
    /// reports the mtime from the last complete central UT field, if that
    /// field contains a usable mtime. Local extras and NTFS are ignored.
    /// If an extra overruns its block, the scan stops before that field.
    /// [`EntryMetadata::modified()`](crate::zip::EntryMetadata::modified)
    /// uses that UTC timestamp or interprets the DOS timestamp as UTC.
    /// Use [`EntryMetadata::header()`](crate::zip::EntryMetadata::header)
    /// to read the raw DOS fields for local wall-clock comparisons.
    pub fn open_with_central_ut(path: &Path, options: RewriteOptions) -> Result<Self> {
        Self::open_source(path, options, true, None)
    }

    fn open_source(path: &Path, options: RewriteOptions, central_ut_only: bool, output: Option<&File>) -> Result<Self> {
        if options.output_permissions.is_some_and(|mode| mode > 0o777) {
            return Err(CreateError::InvalidOptions("invalid output permission bits").into());
        }
        let attempts = Cell::new(0);
        let common = options.limits.common;
        let budget = Attempts::with_limits(&options.cancel, common.transaction_attempts, &attempts);
        let parent = Parent::bind(path, &budget, common.plan_capacity)?;
        let (file, stamp) = parent.open_existing_regular(&budget)?;
        if let Some(output) = output {
            check_output_identity(stamp, output, &budget)?;
        }
        check_source(&parent, &file, stamp, &budget)?;
        let limits = options.limits;
        let mut usage = RewriteUsage::default();
        let mut source_reads = 0;
        let directory = layout::directory(
            &mut Reader {
                file: &file,
                attempts: &budget,
                bytes: &mut source_reads,
                max: limits.source_directory.fetched_bytes,
                exhausted: ReadLimit::Parser,
            },
            stamp.len,
            None,
            central_ut_only,
            DirectoryBudget {
                core: limits.source_directory,
                scratch: limits.source_scratch,
                records: limits.source_records,
                metadata: limits.source_metadata,
                record_size: size_of::<CentralRecord>().max(Metadata::RECORD_BYTES),
            },
            &mut usage.source,
        )?;
        usage.source.read_bytes = source_reads;
        let records = directory.entries.len();
        let source_peak = add(usage.source.record_capacity, bytes_for::<MetadataRecord>(records)?)?;
        if source_peak > limits.source_records {
            return Err(RewriteError::Limit(RewriteLimit::SourceRecords));
        }
        let mut actions = Vec::new();
        let minimum = add(parent.capacity(), bytes_for::<Action>(records)?)?;
        limit(minimum, common.plan_capacity, CreateLimit::PlanCapacity)?;
        actions.try_reserve_exact(records)?;
        actions.resize(records, Action::Keep);
        let (metadata, capacity, decoded) =
            Metadata::from_directory_accounted(directory, &options.cancel).map_err(RewriteError::Metadata)?;
        usage.source_projection_capacity = capacity;
        usage.source_projection_bytes = decoded;
        let fixed = add(parent.capacity(), bytes_for::<Action>(actions.capacity())?)?;
        let names = names::Exact::new(&metadata, &options, &mut usage, fixed)?;
        check_source(&parent, &file, stamp, &budget)?;
        usage.common.plan.entries = records as u64;
        Ok(Self {
            parent,
            file,
            stamp,
            metadata: Arc::new(metadata),
            actions,
            inputs: Vec::new(),
            appends: Vec::new(),
            names,
            variable_capacity: 0,
            options,
            usage,
            attempts,
        })
    }

    /// The canonical snapshot from the held original ZIP.
    pub fn metadata(&self) -> Arc<Metadata> {
        Arc::clone(&self.metadata)
    }

    /// Admit a path input. Its descriptor is closed until execution.
    pub fn add_file(
        &mut self,
        at: Placement,
        source: &Path,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<()> {
        self.admit(at, metadata, keys, Some((source, None, false)))
    }

    /// Admit a caller-provided file whose path binds the same regular inode.
    pub fn add_open_file(
        &mut self,
        at: Placement,
        source: &Path,
        file: File,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<()> {
        self.admit(at, metadata, keys, Some((source, Some(file), false)))
    }

    /// Admit an explicit directory entry.
    pub fn add_directory(
        &mut self,
        at: Placement,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<()> {
        self.admit(at, metadata, keys, None)
    }

    /// Remove exactly this occurrence. Each source ID admits one edit.
    pub fn remove(&mut self, old: &EntryId) -> Result<()> {
        let ordinal = self.unedited(old)?;
        work(&self.options, &mut self.usage, 1)?;
        self.names.remove(ordinal);
        self.actions[ordinal] = Action::Remove;
        self.usage.common.plan.entries -= 1;
        Ok(())
    }

    /// Current accounting, including work consumed by failed admission.
    pub fn usage(&self) -> RewriteUsage {
        let mut usage = self.usage;
        usage.common.transaction_attempts = self.attempts.get();
        usage
    }

    /// Admit directory metadata bound to the source path.
    ///
    /// The plan snapshots the directory at admission and writes the supplied
    /// metadata. Callers that sampled metadata earlier must ensure it still
    /// describes the same directory when this call returns.
    pub fn add_directory_from_path(
        &mut self,
        at: Placement,
        source: &Path,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<()> {
        self.admit(at, metadata, keys, Some((source, None, true)))
    }

    /// Admit directory metadata bound to a held handle and its path.
    ///
    /// The supplied metadata is used as is. See [Self::add_directory_from_path]
    /// for the source snapshot contract.
    pub fn add_open_directory(
        &mut self,
        at: Placement,
        source: &Path,
        file: File,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<()> {
        self.admit(at, metadata, keys, Some((source, Some(file), true)))
    }

    fn unedited(&self, id: &EntryId) -> Result<usize> {
        let ordinal = self.metadata.ordinal(id).map_err(|_| RewriteError::ForeignEntryId)?;
        if !matches!(self.actions[ordinal], Action::Keep) {
            return Err(RewriteError::DuplicateEdit);
        }
        Ok(ordinal)
    }

    fn admit(
        &mut self,
        at: Placement,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
        source: Option<(&Path, Option<File>, bool)>,
    ) -> Result<()> {
        let ordinal = match at {
            Placement::Append => None,
            Placement::Replace(id) => Some(self.unedited(&id)?),
        };
        let options = &self.options;
        let common = options.limits.common;
        let (scan, minimum_metadata) = input_cost(metadata, keys, source.as_ref().map(|(path, _, _)| *path))?;
        work(options, &mut self.usage, scan)?;
        validate_input(metadata, keys, source.as_ref().is_none_or(|source| source.2), options.collisions)?;
        let raw = name_bytes(metadata.name);
        if let Some(ordinal) = ordinal {
            let original = self.metadata.view(ordinal);
            let efs = original.header().flags & FLAG_UTF8 != 0;
            if raw != original.raw_name() || matches!(metadata.name, EntryName::Utf8(_)) != efs {
                return Err(RewriteError::ReplacementName);
            }
        } else {
            self.names.check_append(raw, &self.metadata, &self.inputs, options, &mut self.usage)?;
        }
        let held = source.as_ref().is_some_and(|(_, file, _)| file.is_some());
        let retained = add(self.usage.common.plan.retained_handles, u64::from(held))?;
        limit(retained, common.retained_handles, CreateLimit::RetainedHandles)?;
        let entries = add(self.usage.common.plan.entries, u64::from(ordinal.is_none()))?;
        if ordinal.is_none() {
            output_count(entries, common)?;
        }
        let fixed = self.fixed_capacity()?;
        let next = add(fixed, minimum_metadata)?;
        let remaining = common.plan_capacity.checked_sub(next).ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?;
        let index = self.inputs.len();
        let attempts = Attempts::with_limits(&options.cancel, common.transaction_attempts, &self.attempts);
        let input = prepare_input(metadata, keys, source, CreateEntryId(index), remaining, &attempts)
            .map_err(|error| input_error(error, index))?;
        if input.source.as_ref().is_some_and(|source| source.stamp.identity == self.stamp.identity) {
            return Err(RewriteError::InputAliasesArchive { input: index });
        }
        let variable = add(self.variable_capacity, input.variable_capacity())?;
        let added = add(input.variable_capacity(), fixed)?;
        self.usage.common.plan.capacity = self.usage.common.plan.capacity.max(added);
        reserve_push(&mut self.inputs, options, added)?;
        let fixed = add(self.fixed_capacity()?, input.variable_capacity())?;
        self.usage.common.plan.capacity = self.usage.common.plan.capacity.max(fixed);
        if ordinal.is_none() {
            reserve_push(&mut self.appends, options, fixed)?;
            let fixed = add(self.fixed_capacity()?, input.variable_capacity())?;
            self.usage.common.plan.capacity = self.usage.common.plan.capacity.max(fixed);
            self.names.insert_append(raw, index, &self.inputs, options, &mut self.usage, fixed)?;
        }
        self.inputs.push(input);
        if let Some(ordinal) = ordinal {
            self.actions[ordinal] = Action::Replace(index);
        } else {
            self.appends.push(index);
        }
        self.variable_capacity = variable;
        self.usage.common.plan.retained_handles = retained;
        self.usage.common.plan.entries = entries;
        let capacity = self.fixed_capacity()?;
        self.usage.common.plan.capacity = self.usage.common.plan.capacity.max(capacity);
        Ok(())
    }

    fn fixed_capacity(&self) -> Result<u64> {
        let mut total = add(self.parent.capacity(), self.variable_capacity)?;
        total = add(total, self.names.capacity()?)?;
        total = add(total, bytes_for::<Action>(self.actions.capacity())?)?;
        total = add(total, bytes_for::<PlannedEntry>(self.inputs.capacity())?)?;
        Ok(add(total, bytes_for::<usize>(self.appends.capacity())?)?)
    }

    /// Verify and publish the plan. All layout and known feasibility checks
    /// run before stage creation. An empty edit plan checks the original
    /// in place and returns without publication or synchronization.
    pub fn publish(self) -> std::result::Result<RewriteOutcome, RewriteFailure> {
        self.publish_inner(None, None)
    }

    /// Publish with actual write receipts for new and replaced members.
    /// Receipt capacity is charged to the plan budget before staging.
    /// See [`RewriteReport`] for when receipts are available.
    pub fn publish_with_receipts(self) -> RewriteReport {
        let mut written = Vec::new();
        let outcome = self.publish_inner(Some(&mut written), None);
        RewriteReport { outcome, written }
    }

    /// Publish with write receipts and a held binding to the verified output.
    /// No binding is returned for an unchanged archive or when the published
    /// destination could not be proved stable through finalization.
    pub fn publish_with_bound_receipts(self) -> (RewriteReport, Option<PublishedArchiveBinding>) {
        let mut written = Vec::new();
        let mut binding = None;
        let outcome = self.publish_inner(Some(&mut written), Some(&mut binding));
        (RewriteReport { outcome, written }, binding)
    }

    fn publish_inner(
        mut self,
        mut receipts: Option<&mut Vec<EntryWritten>>,
        binding: Option<&mut Option<PublishedArchiveBinding>>,
    ) -> std::result::Result<RewriteOutcome, RewriteFailure> {
        let plan = self.preflight(receipts.as_deref_mut()).map_err(|cause| {
            self.failure(RewriteStage::Planning, cause, Publication::NotPublished, CleanupState::Clean)
        })?;
        if self.inputs.is_empty()
            && self.appends.is_empty()
            && self.actions.iter().all(|action| matches!(action, Action::Keep))
        {
            let verification = self.verify_unchanged(plan).map_err(|cause| {
                self.failure(RewriteStage::Verify, cause, Publication::NotPublished, CleanupState::Clean)
            })?;
            let usage = self.usage();
            return Ok(RewriteOutcome::Unchanged { source: self.parent.destination, verification, usage });
        }
        self.publish_staged(plan, receipts, binding)
    }

    fn failure(
        &self,
        stage: RewriteStage,
        cause: RewriteError,
        publication: Publication,
        cleanup: CleanupState,
    ) -> RewriteFailure {
        let durability = if self.options.durability == Durability::VisibilityOnly {
            DurabilityState::NotRequested
        } else {
            DurabilityState::Unconfirmed
        };
        RewriteFailure {
            stage,
            cause,
            publication,
            durability,
            cleanup,
            usage: Box::new(self.usage()),
            verification: None,
            recovery: None,
        }
    }

    fn verify_unchanged(&mut self, plan: preflight::Prepared) -> Result<VerificationSummary> {
        use crate::zip::create::native::verify::Reader as PayloadReader;
        let options = &self.options;
        let attempts =
            Attempts::with_limits(&options.cancel, options.limits.common.transaction_attempts, &self.attempts);
        check_source(&self.parent, &self.file, self.stamp, &attempts)?;
        let mut outcomes = plan.outcomes;
        let mut buffer = [0; layout::BUFFER];
        for (ordinal, member) in plan.members.iter().enumerate() {
            attempts.check_cancel()?;
            let result = if member.directory {
                EntryVerification::RetainedDirectoryVerified
            } else if options.verification == Verification::Full {
                let entry = self.metadata.view(ordinal);
                let mut reader = PayloadReader::new(
                    &mut self.file,
                    options.limits.common,
                    &attempts,
                    &mut self.usage.source_payload,
                );
                reader.check_payload(member.payload_at, declared_payload(entry), &mut buffer)?;
                EntryVerification::RetainedPayloadVerified
            } else {
                EntryVerification::PreservedStructurally
            };
            outcomes.record(result, &mut self.usage);
        }
        check_source(&self.parent, &self.file, self.stamp, &attempts)?;
        Ok(outcomes)
    }

    fn publish_staged(
        mut self,
        mut prepared: preflight::Prepared,
        receipts: Option<&mut Vec<EntryWritten>>,
        binding: Option<&mut Option<PublishedArchiveBinding>>,
    ) -> std::result::Result<RewriteOutcome, RewriteFailure> {
        let attempts = Attempts::with_limits(
            &self.options.cancel,
            self.options.limits.common.transaction_attempts,
            &self.attempts,
        );
        super::super::create::native::check_directories(&self.inputs, None, &attempts).map_err(|error| {
            self.failure(
                RewriteStage::Precommit,
                directory_input_error(error),
                Publication::NotPublished,
                CleanupState::Clean,
            )
        })?;
        let mut stage = match Stage::create(&self.parent, &attempts, &mut self.usage.common.stage_attempts) {
            Ok(stage) => stage,
            Err(error) => {
                return Err(self.failure(
                    RewriteStage::StageCreate,
                    error.into(),
                    Publication::NotPublished,
                    CleanupState::Clean,
                ));
            }
        };
        let final_count = Cell::new(0);
        let finalization = Attempts::finalization(&final_count);
        let binding_count = Cell::new(0);
        let binding_budget = Attempts::finalization(&binding_count);
        let result = self.execute(&mut stage, &mut prepared, binding.as_ref().map(|_| &binding_budget));
        let publication = result.as_ref().map_or_else(|stopped| stopped.publication, |_| Publication::Published);
        let recovery = match &result {
            Err(stop) if publication == Publication::Unknown => stop.stage_identity.map(|identity| {
                let observed = self
                    .parent
                    .check(&finalization)
                    .and_then(|()| self.parent.lookup(&self.parent.leaf, &finalization));
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
        let aftermath = cleanup(&self.parent, &stage, publication, &finalization);
        let clean = matches!(aftermath, Aftermath::Clean);
        self.usage.common.finalization_attempts = final_count.get() + binding_count.get();
        let (verification, publication_stamp) = match result {
            Ok(verified) => verified,
            Err(stop) => {
                let cleanup = aftermath.into_public(stage);
                let mut failure = self.failure(stop.stage, stop.cause, stop.publication, cleanup);
                failure.recovery = recovery;
                return Err(failure);
            }
        };
        if let Some(receipts) = receipts {
            receipts.extend(prepared.written.iter().filter_map(|entry| match entry {
                WrittenEntry::New { receipt, .. } => Some(*receipt),
                WrittenEntry::Preserved(_) => None,
            }));
        }
        let durability = if self.options.durability == Durability::SyncFileAndDirectory {
            let synced = after_commit_sync(&self.parent.file, &finalization);
            self.usage.common.finalization_attempts = final_count.get() + binding_count.get();
            if let Err(error) = synced {
                let cleanup = aftermath.into_public(stage);
                let mut failure =
                    self.failure(RewriteStage::DirectorySync, error.into(), Publication::Published, cleanup);
                failure.verification = Some(Box::new(verification));
                return Err(failure);
            }
            DurabilityState::Synced
        } else {
            DurabilityState::NotRequested
        };
        if !clean || self.options.cancel.is_canceled() {
            let cleanup = aftermath.into_public(stage);
            let cause = if clean { CreateError::Canceled } else { CreateError::CleanupIncomplete };
            let mut failure = self.failure(RewriteStage::Cleanup, cause.into(), Publication::Published, cleanup);
            failure.durability = durability;
            failure.verification = Some(Box::new(verification));
            return Err(failure);
        }
        if let (Some(binding), Some(stamp)) = (binding, publication_stamp) {
            *binding = unix::bound_publication(&self.parent, &stage, stamp, &binding_budget);
            self.usage.common.finalization_attempts = final_count.get() + binding_count.get();
        }
        let cleanup = aftermath.into_public(stage);
        let usage = self.usage();
        Ok(RewriteOutcome::Replaced(RewrittenArchive {
            destination: self.parent.destination,
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
        plan: &mut preflight::Prepared,
        binding: Option<&Attempts<'_>>,
    ) -> std::result::Result<(VerificationSummary, Option<Stamp>), Stop> {
        let options = &self.options;
        let attempts =
            Attempts::with_limits(&options.cancel, options.limits.common.transaction_attempts, &self.attempts);
        let parent_stamp = super::super::create::native::stage_parent_stamp(&self.inputs, &self.parent, &attempts)
            .map_err(directory_input_error)
            .at(RewriteStage::Precommit)?;
        let original = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::StageCreate)?;
        check_source(&self.parent, &self.file, self.stamp, &attempts).at(RewriteStage::SourceRead)?;
        let output = OutputPlan {
            metadata: &self.metadata,
            options,
            source: &self.file,
            source_stamp: self.stamp,
            inputs: &self.inputs,
            actions: &self.actions,
            appends: &self.appends,
            repairs: None,
        };
        let summary = output.write_stage(stage, original, plan, attempts, &mut self.usage)?;
        let finalized = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Finish)?;
        #[cfg(test)]
        super::test_event(super::Event::AfterFinish, Some(stage.path())).at(RewriteStage::Finish)?;
        check_source(&self.parent, &self.file, self.stamp, &attempts).at(RewriteStage::Verify)?;
        let manifest = Manifest {
            metadata: &self.metadata,
            members: &plan.members,
            inputs: &self.inputs,
            actions: &self.actions,
            appends: &self.appends,
            entries: &plan.written,
            prefix: plan.prefix,
            summary,
            repairs: None,
        };
        let outcomes = std::mem::take(&mut plan.outcomes);
        let verification = manifest
            .verify(&self.file, &mut stage.file, options, &attempts, &mut self.usage, outcomes)
            .at(RewriteStage::Verify)?;
        check_source(&self.parent, &self.file, self.stamp, &attempts).at(RewriteStage::Verify)?;
        #[cfg(test)]
        super::test_event(super::Event::AfterVerify, Some(stage.path())).at(RewriteStage::Verify)?;
        if unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Permissions)? != finalized {
            return Err(Stop::at(RewriteStage::Permissions, CreateError::StageChanged));
        }
        let mode = options.output_permissions.unwrap_or(self.stamp.mode & 0o777);
        unix::chmod(&stage.file, mode, &attempts).at(RewriteStage::Permissions)?;
        let ready = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Permissions)?;
        if !ready.same_payload(finalized) || ready.mode != mode {
            return Err(Stop::at(RewriteStage::Permissions, CreateError::StageChanged));
        }
        if options.durability == Durability::SyncFileAndDirectory {
            #[cfg(test)]
            super::test_event(super::Event::FileSync, Some(stage.path())).at(RewriteStage::FileSync)?;
            unix::sync_stage(&stage.file, &attempts).at(RewriteStage::FileSync)?;
        }
        #[cfg(test)]
        super::test_event(super::Event::BeforeFinalCheck, Some(stage.path())).at(RewriteStage::Precommit)?;
        super::super::create::native::check_directories(&self.inputs, parent_stamp, &attempts)
            .map_err(directory_input_error)
            .at(RewriteStage::Precommit)?;
        for (index, entry) in self.inputs.iter().enumerate() {
            if let Some(source) = entry.payload_source() {
                let path = unix::path_stamp(&source.path, &attempts)
                    .map_err(|error| input_error(error, index))
                    .at(RewriteStage::Precommit)?;
                if path != source.stamp
                    || source
                        .file
                        .as_ref()
                        .map(|file| unix::file_stamp(file, &attempts))
                        .transpose()
                        .at(RewriteStage::Precommit)?
                        .is_some_and(|stamp| stamp != source.stamp)
                {
                    return Err(Stop::at(RewriteStage::Precommit, RewriteError::InputChanged { input: index }));
                }
            }
        }
        check_source(&self.parent, &self.file, self.stamp, &attempts).at(RewriteStage::Precommit)?;
        let held = unix::file_stamp(&stage.file, &attempts).at(RewriteStage::Precommit)?;
        let named = self.parent.lookup(stage.name(), &attempts).at(RewriteStage::Precommit)?;
        if held != ready || !matches!(named, Some(NameState::Regular(stamp)) if stamp == held) {
            return Err(Stop::at(RewriteStage::Precommit, CreateError::StageChanged));
        }
        #[cfg(test)]
        super::test_event(super::Event::AfterFinalCheck, Some(stage.path())).at(RewriteStage::Precommit)?;
        match options.replacement {
            Replacement::LastWriterWins => self.parent.publish_replace(stage.name(), &attempts),
        }
        .map_err(|error| Stop {
            stage: RewriteStage::Publish,
            publication: match error {
                PublishError::Definite(_) => Publication::NotPublished,
                PublishError::Uncertain(_) => Publication::Unknown,
            },
            cause: error.into_cause().into(),
            stage_identity: Some(file_identity(held)),
        })?;
        let bound = binding.and_then(|budget| unix::publication_stamp(stage, held, budget));
        #[cfg(test)]
        let _ = super::test_event(super::Event::AfterCommit, Some(stage.path()));
        Ok((verification, bound))
    }
}

type MetadataRecord = [u8; Metadata::RECORD_BYTES];

fn after_commit_sync(file: &File, attempts: &Attempts<'_>) -> create::Result<()> {
    #[cfg(test)]
    super::test_event(super::Event::DirectorySync, None)?;
    unix::sync_directory(file, attempts)
}

fn file_identity(stamp: Stamp) -> FileIdentity {
    FileIdentity { device: stamp.identity.0, inode: stamp.identity.1 }
}

fn check_output_identity(stamp: Stamp, output: &File, attempts: &Attempts<'_>) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = attempts.run(|| output.metadata())?;
    if unix::Identity(metadata.dev(), metadata.ino()) == stamp.identity {
        return Err(RewriteError::OutputAliasesArchive);
    }
    Ok(())
}

fn check_source(parent: &Parent, file: &File, stamp: Stamp, attempts: &Attempts<'_>) -> Result<()> {
    parent.check(attempts)?;
    let held = unix::file_stamp(file, attempts)?;
    let named = parent.lookup(&parent.leaf, attempts)?;
    if held != stamp
        || !matches!(named, Some(NameState::Regular(observed)) if stamp == observed)
        || unix::file_stamp(file, attempts)? != stamp
    {
        return Err(RewriteError::SourceChanged);
    }
    Ok(())
}

fn input_error(error: CreateError, index: usize) -> RewriteError {
    match error {
        CreateError::SourceChanged(_) | CreateError::SourceNotRegular => RewriteError::InputChanged { input: index },
        CreateError::Io(ref error)
            if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ELOOP | libc::ENOTDIR)) =>
        {
            RewriteError::InputChanged { input: index }
        }
        error => error.into(),
    }
}

fn bytes_for<T>(count: usize) -> create::Result<u64> {
    (count as u64).checked_mul(size_of::<T>() as u64).ok_or(CreateError::Overflow)
}

fn reserve_push<T>(vec: &mut Vec<T>, options: &RewriteOptions, allocated: u64) -> Result<()> {
    if vec.len() < vec.capacity() {
        return Ok(());
    }
    let size = size_of::<T>() as u64;
    let available = options
        .limits
        .common
        .plan_capacity
        .checked_sub(allocated)
        .ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?
        / size;
    let growth = (vec.capacity() as u64).max(1).min(available);
    limit(1, growth, CreateLimit::PlanCapacity)?;
    let old = vec.capacity();
    vec.try_reserve_exact(growth as usize)?;
    let actual = add(allocated, bytes_for::<T>(vec.capacity() - old)?)?;
    limit(actual, options.limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
    Ok(())
}

fn work(options: &RewriteOptions, usage: &mut RewriteUsage, units: u64) -> create::Result<()> {
    if options.cancel.is_canceled() {
        return Err(CreateError::Canceled);
    }
    let plan = &mut usage.common.plan;
    let next = add(plan.work, units)?;
    limit(next, options.limits.common.plan_work, CreateLimit::PlanWork)?;
    plan.work = next;
    Ok(())
}

fn output_count(count: u64, limits: CreateLimits) -> Result<()> {
    limit(count, limits.entries.min(limits.directory.entries), CreateLimit::Entries)?;
    writer_limit(count, limits.writer.entries, crate::zip::write::Limit::Entries)?;
    limit(count, limits.verification_records / size_of::<CentralRecord>() as u64, CreateLimit::VerificationRecords)?;
    Ok(())
}

fn raw_entry(metadata: &Metadata, member: Member, ordinal: usize) -> PreparedRaw {
    let old = metadata.view(ordinal);
    PreparedRaw {
        source_ordinal: ordinal,
        local: member.local_at..member.end,
        central: old.source().raw_range(),
        extra_at: old.source().extra_range().start,
        central_header: old.header(),
        local_version: member.local_version,
        zip64_extra: member.central_zip64.map(|extra| (extra.at, extra.size)),
        wide_sizes: member.wide_sizes,
        packed: old.packed_size(),
        decoded: old.size(),
    }
}

struct OutputPlan<'a> {
    metadata: &'a Metadata,
    options: &'a RewriteOptions,
    source: &'a File,
    source_stamp: Stamp,
    inputs: &'a [PlannedEntry],
    actions: &'a [Action],
    appends: &'a [usize],
    repairs: Option<&'a [Option<layout::recovery::DescriptorRepair>]>,
}

impl OutputPlan<'_> {
    fn write_stage(
        &self,
        stage: &Stage,
        stage_stamp: Stamp,
        prepared: &mut preflight::Prepared,
        attempts: Attempts<'_>,
        usage: &mut RewriteUsage,
    ) -> std::result::Result<WriteSummary, Stop> {
        let options = WriterOptions {
            comment: self.metadata.raw_comment(),
            limits: self.options.limits.common.writer,
            cancel: Some(self.options.cancel.clone()),
        };
        let sink = RawIo::new(&stage.file, attempts);
        #[cfg(test)]
        let sink = sink.with_rewrite_hooks();
        let mut writer = match ZipWriter::new_accounted(sink, options) {
            Ok(writer) => writer,
            Err((error, partial)) => {
                usage.common.writer = partial;
                return Err(Stop::at(RewriteStage::Write, rewrite_writer_error(error)));
            }
        };
        let active_repair: Cell<Option<layout::recovery::DescriptorRepair>> = Cell::new(None);
        let mut source = |at: u64, bytes: &mut [u8]| {
            let used = &mut usage.raw_copy_bytes;
            if add(*used, bytes.len() as u64).map_err(io::Error::other)? > self.options.limits.raw_copy_bytes {
                return Err(io::Error::other(RewriteError::Limit(RewriteLimit::RawCopyBytes)));
            }
            attempts.charge().map_err(io::Error::other)?;
            #[cfg(test)]
            let bytes = {
                let size = bytes.len().min(super::test_source_read_cap());
                &mut bytes[..size]
            };
            let read = self.source.read_at(bytes, at)?;
            *used += read as u64;
            if let Some(repair) = active_repair.get() {
                let start = at.max(repair.offset);
                let end =
                    add(at, read as u64).map_err(io::Error::other)?.min(repair.offset + repair.bytes().len() as u64);
                if start < end {
                    bytes[(start - at) as usize..(end - at) as usize].copy_from_slice(
                        &repair.bytes()[(start - repair.offset) as usize..(end - repair.offset) as usize],
                    );
                }
            }
            Ok(read)
        };
        let prefix = writer.write_prefix(prepared.prefix, &mut source);
        usage.common.writer = writer.usage();
        prefix.map_err(rewrite_writer_error).at(RewriteStage::Write)?;
        let edits = self.actions.iter().copied().chain(self.appends.iter().map(|&index| Action::Replace(index)));
        for (ordinal, action) in edits.enumerate() {
            attempts.check_cancel().at(RewriteStage::Write)?;
            let written = match action {
                Action::Remove => continue,
                Action::Keep => {
                    active_repair.set(self.repairs.and_then(|repairs| repairs[ordinal]));
                    let raw = raw_entry(self.metadata, prepared.members[ordinal], ordinal);
                    writer
                        .add_preserved(&raw, &mut source)
                        .map(WrittenEntry::Preserved)
                        .map_err(rewrite_writer_error)
                        .at(RewriteStage::Write)
                }
                Action::Replace(input) => self
                    .write_input(&mut writer, input, stage_stamp, attempts)
                    .map(|receipt| WrittenEntry::New { input, receipt }),
            };
            usage.common.writer = writer.usage();
            prepared.written.push(written?);
        }
        #[cfg(test)]
        super::test_event(super::Event::BeforeFinish, Some(stage.path())).at(RewriteStage::Finish)?;
        match writer.finish_accounted() {
            Ok(finished) => {
                usage.common.writer = finished.summary.usage;
                Ok(finished.summary)
            }
            Err((error, partial)) => {
                usage.common.writer = partial;
                Err(Stop::at(RewriteStage::Finish, rewrite_writer_error(error)))
            }
        }
    }

    fn write_input<W: io::Write + io::Seek>(
        &self,
        writer: &mut ZipWriter<W>,
        index: usize,
        stage: Stamp,
        attempts: Attempts<'_>,
    ) -> std::result::Result<EntryWritten, Stop> {
        let entry = &self.inputs[index];
        let Some(source) = entry.payload_source() else {
            return writer.add_directory(entry.options()).map_err(rewrite_writer_error).at(RewriteStage::Write);
        };
        let reopened = if source.file.is_none() {
            Some(
                unix::open_source(&source.path, &attempts)
                    .map_err(|error| input_error(error, index))
                    .at(RewriteStage::SourceRead)?,
            )
        } else {
            None
        };
        let file = source.file.as_ref().or(reopened.as_ref()).expect("planned source handle");
        let checked = || {
            capture(file, &source.path, CreateEntryId(index), &attempts)
                .map_err(|error| input_error(error, index))
                .at(RewriteStage::SourceRead)
        };
        let before = checked()?;
        if before.identity == stage.identity {
            return Err(Stop::at(RewriteStage::SourceRead, RewriteError::InputAliasesStage { input: index }));
        }
        if before.identity == self.source_stamp.identity {
            return Err(Stop::at(RewriteStage::SourceRead, RewriteError::InputAliasesArchive { input: index }));
        }
        if before != source.stamp {
            return Err(Stop::at(RewriteStage::SourceRead, RewriteError::InputChanged { input: index }));
        }
        #[cfg(test)]
        super::test_event(super::Event::BeforeInputRead, Some(&source.path)).at(RewriteStage::SourceRead)?;
        let mut input = SourceInput::new(file, attempts);
        let receipt =
            writer.add_file(entry.options(), &mut input, InputLength::Exact(source.stamp.len)).map_err(|error| {
                let stage = match error {
                    WriteError::Io { stage: IoStage::SourceRead, .. }
                    | WriteError::SizeUnderrun { .. }
                    | WriteError::SizeOverrun { .. } => RewriteStage::SourceRead,
                    _ => RewriteStage::Write,
                };
                Stop::at(stage, rewrite_writer_error(error))
            })?;
        if checked()? != source.stamp {
            return Err(Stop::at(RewriteStage::SourceRead, RewriteError::InputChanged { input: index }));
        }
        Ok(receipt)
    }
}

fn rewrite_writer_error(error: WriteError) -> RewriteError {
    if let WriteError::Io { source, .. } = &error
        && let Some(RewriteError::Limit(limit)) =
            source.get_ref().and_then(|cause| cause.downcast_ref::<RewriteError>())
    {
        return RewriteError::Limit(*limit);
    }
    match writer_error(error) {
        CreateError::Writer(error) => RewriteError::Writer(error),
        error => error.into(),
    }
}

struct Stop {
    stage: RewriteStage,
    cause: RewriteError,
    publication: Publication,
    stage_identity: Option<FileIdentity>,
}

impl Stop {
    fn at(stage: RewriteStage, cause: impl Into<RewriteError>) -> Self {
        Self { stage, cause: cause.into(), publication: Publication::NotPublished, stage_identity: None }
    }
}

trait At<T> {
    fn at(self, stage: RewriteStage) -> std::result::Result<T, Stop>;
}

impl<T, E: Into<RewriteError>> At<T> for std::result::Result<T, E> {
    fn at(self, stage: RewriteStage) -> std::result::Result<T, Stop> {
        self.map_err(|error| Stop::at(stage, error))
    }
}

fn directory_input_error(error: CreateError) -> RewriteError {
    match error {
        CreateError::SourceChanged(id) => RewriteError::InputChanged { input: id.ordinal() },
        other => other.into(),
    }
}
