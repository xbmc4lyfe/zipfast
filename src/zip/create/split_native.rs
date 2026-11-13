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

//! Native ownership and publication of a verified physical split set.
use super::*;
use crate::zip::write::split::{self as wire, VolumeProvider, ZipSplitWriter};
use crate::zip::write::{InputLength, WriterOptions};
use std::{
    cell::RefCell,
    ffi::CStr,
    fs::Metadata,
    io::{Seek, SeekFrom, Write},
    os::unix::ffi::OsStrExt,
    sync::Arc,
};
use unix::split::Probe;
use unix::{Identity, NameState, PublishError};

type Checked<T> = std::result::Result<T, SplitCreateError>;
const STAGE_NAME: usize = 43;

pub(in crate::zip::create) struct Evidence {
    owner: Owner,
    _parent: Parent,
    pub(in crate::zip::create) receipts: Vec<wire::EntryWritten>,
}
impl Evidence {
    pub(in crate::zip::create) fn matches(&self, disk: u32, metadata: &Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.owner
            .slots
            .get(disk as usize)
            .and_then(|s| s.terminal.or(s.stamp))
            .is_some_and(|s| s.identity == Identity(metadata.dev(), metadata.ino()))
    }
}
struct Slot {
    file: Option<File>,
    stamp: Option<Stamp>,
    verified: Option<Stamp>,
    terminal: Option<Stamp>,
    name: [u8; STAGE_NAME],
    leaf: Vec<u8>,
    final_path: PathBuf,
    stage_path: PathBuf,
}
impl Slot {
    fn name(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.name).expect("prepared stage name")
    }
    fn leaf(&self) -> &CStr {
        CStr::from_bytes_with_nul(&self.leaf).expect("validated final leaf")
    }
}
struct Owner {
    slots: Vec<Slot>,
    opened: usize,
}
impl split_verify::HeldVolumes for Owner {
    fn len(&self) -> usize {
        self.opened
    }
    fn get(&self, disk: usize) -> Option<(&File, Stamp)> {
        let slot = self.slots.get(disk)?;
        Some((slot.file.as_ref()?, slot.stamp?))
    }
}
#[derive(Default)]
struct Counters {
    accepted: Cell<u64>,
    opens: Cell<u64>,
    writer: Cell<bool>,
}
struct Handles {
    live: Cell<u64>,
    peak: Cell<u64>,
    max: u64,
}
impl Handles {
    fn room(&self, count: u64) -> Checked<()> {
        bound(add(self.live.get(), count)?, self.max, SplitCreateLimit::OpenHandles)
    }
    fn opened(&self) {
        let n = self.live.get() + 1;
        self.live.set(n);
        self.peak.set(self.peak.get().max(n));
    }
    fn closed(&self) {
        self.live.set(self.live.get() - 1);
    }
}
struct Counted<'a> {
    file: Option<File>,
    handles: &'a Handles,
}
impl Drop for Counted<'_> {
    fn drop(&mut self) {
        drop(self.file.take());
        self.handles.closed();
    }
}
struct Context<'a> {
    parent: &'a Parent,
    entries: &'a [PlannedEntry],
    probes: &'a [Option<Probe>],
    original_parent: &'a Probe,
    real_parent: &'a Probe,
    baseline: Cell<Option<Stamp>>,
    namespace_valid: Cell<bool>,
    attempts: Attempts<'a>,
    handles: &'a Handles,
}
impl Context<'_> {
    fn parent(&self, budget: &Attempts<'_>) -> Result<()> {
        for (probe, follow) in [(self.original_parent, true), (self.real_parent, false)] {
            if probe.stamp(true, follow, budget)?.identity != self.parent.identity {
                return Err(CreateError::ParentChanged);
            }
        }
        Ok(())
    }
    fn mutation_before(&self, budget: &Attempts<'_>) -> Result<()> {
        if !self.namespace_valid.get() {
            return Err(CreateError::ParentChanged);
        }
        self.parent(budget)?;
        if let Some(expected) = self.baseline.get() {
            let current = unix::directory_stamp(&budget.run(|| self.parent.file.metadata())?)?;
            if current != expected {
                self.namespace_valid.set(false);
                return Err(CreateError::ParentChanged);
            }
        }
        Ok(())
    }
    fn mutation_after(&self, budget: &Attempts<'_>) -> Result<()> {
        if let Some(expected) = self.baseline.get() {
            let result = (|| {
                let current = unix::directory_stamp(&budget.run(|| self.parent.file.metadata())?)?;
                if current.identity != expected.identity || current.mode != expected.mode {
                    return Err(CreateError::ParentChanged);
                }
                self.baseline.set(Some(current));
                Ok(())
            })();
            if result.is_err() {
                self.namespace_valid.set(false);
            }
            result
        } else {
            Ok(())
        }
    }
    fn sources(&self, budget: &Attempts<'_>) -> Result<()> {
        self.parent(budget)?;
        for (index, entry) in self.entries.iter().enumerate() {
            if let Some(source) = &entry.source {
                let id = CreateEntryId(index);
                let expected = self
                    .baseline
                    .get()
                    .filter(|s| source.directory && s.identity == source.stamp.identity)
                    .unwrap_or(source.stamp);
                let current =
                    self.probes[index].as_ref().expect("source probe").stamp(source.directory, false, budget)?;
                if current != expected {
                    return Err(CreateError::SourceChanged(id));
                }
                if let Some(file) = &source.file {
                    let metadata = budget.run(|| file.metadata())?;
                    let current =
                        if source.directory { unix::directory_stamp(&metadata)? } else { Stamp::regular(&metadata)? };
                    if current != expected {
                        return Err(CreateError::SourceChanged(id));
                    }
                }
            }
        }
        Ok(())
    }
    fn capture(&self, index: usize, file: &File) -> Result<()> {
        let source = self.entries[index].source.as_ref().expect("payload source");
        let first = unix::file_stamp(file, &self.attempts)?;
        let named = self.probes[index].as_ref().expect("source probe").stamp(false, false, &self.attempts)?;
        let last = unix::file_stamp(file, &self.attempts)?;
        if first != source.stamp || named != first || last != first {
            return Err(CreateError::SourceChanged(CreateEntryId(index)));
        }
        Ok(())
    }
}
struct Prepared {
    owner: Owner,
    counters: Vec<Counters>,
    probes: Vec<Option<Probe>>,
    original_parent: Probe,
    real_parent: Probe,
    scratch: split_verify::Scratch,
    receipts: Vec<wire::EntryWritten>,
}
fn bound(value: u64, max: u64, limit: SplitCreateLimit) -> Checked<()> {
    if value > max { Err(SplitCreateError::Limit(limit)) } else { Ok(()) }
}
fn reserve<T>(n: usize) -> Checked<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(n)?;
    Ok(v)
}
fn path_buffer(n: usize) -> Checked<PathBuf> {
    let mut p = PathBuf::new();
    p.try_reserve_exact(n)?;
    Ok(p)
}
fn capacity<T>(v: &Vec<T>) -> u64 {
    v.capacity() as u64 * size_of::<T>() as u64
}
fn empty_row(disk: u32, data_sync: SplitBarrierState) -> SplitVolumeReport {
    let name = SplitNameObservation { state: SplitNameState::NotChecked, identity: None, regular: None };
    SplitVolumeReport {
        disk,
        role: SplitVolumeRole::Unassigned,
        final_path: None,
        stage_path: None,
        stage_created: false,
        writer_opened: false,
        accepted_bytes: 0,
        stage_open_attempts: 0,
        verified: None,
        terminal_held: None,
        stage_name: name,
        final_name: name,
        publication: SplitVolumePublication::NotAttempted,
        cleanup: SplitVolumeCleanup::NotNeeded,
        data_sync,
    }
}
impl CreatePlan {
    /// Write and independently verify clear split volumes, then publish numbered parts before the final ZIP.
    /// Publication is per-name and no-clobber. Inspect commit, visibility and durability separately on failure.
    pub fn publish_split_with_receipts(mut self, options: SplitCreateOptions) -> SplitCreateReport {
        let (durability, pending_sync) = match self.options.durability {
            Durability::VisibilityOnly => (DurabilityState::NotRequested, SplitBarrierState::NotRequested),
            Durability::SyncFileAndDirectory => (DurabilityState::Unconfirmed, SplitBarrierState::NotAttempted),
        };
        let mut report = SplitCreateReport {
            outcome: Ok(SplitCreatedArchive { volume_count: 0, physical_bytes: 0 }),
            destination: PathBuf::new(),
            commit: SplitCommitState::NonePublished,
            visibility: SplitVisibility::NotChecked,
            durability,
            barriers: SplitBarrierReport {
                prefix_parent: pending_sync,
                final_parent: pending_sync,
                aftermath_parent: SplitBarrierState::NotRequested,
            },
            volumes: Vec::new(),
            written: Vec::new(),
            summary: SplitCreateUsage::default(),
            additional_problems: Vec::new(),
            writer_failure: None,
            reconciliation: None,
        };
        let prepared = self.prepare_split(&options, &mut report);
        match prepared {
            Err(cause) => {
                report.volumes.clear();
                problem(&mut report, SplitCreateStage::Planning, None, cause);
            }
            Ok(mut prepared) => {
                let held =
                    self.entries.iter().filter_map(|e| e.source.as_ref()).filter(|s| s.file.is_some()).count() as u64;
                let handles =
                    Handles { live: Cell::new(held + 1), peak: Cell::new(held + 1), max: options.limits.open_handles };
                let final_count = Cell::new(0);
                let final_budget = Attempts::split_finalization(&final_count, report.summary.finalization_reserve);
                let ctx = Context {
                    parent: &self.parent,
                    entries: &self.entries,
                    probes: &prepared.probes,
                    original_parent: &prepared.original_parent,
                    real_parent: &prepared.real_parent,
                    baseline: Cell::new(
                        self.entries
                            .iter()
                            .filter_map(|e| e.source.as_ref())
                            .find(|s| s.directory && s.stamp.identity == self.parent.identity)
                            .map(|s| s.stamp),
                    ),
                    namespace_valid: Cell::new(true),
                    attempts: Attempts::new(&self.options, &self.attempts),
                    handles: &handles,
                };
                let result = execute(
                    &ctx,
                    &self.options,
                    &options,
                    &mut prepared.owner,
                    &prepared.counters,
                    &mut prepared.receipts,
                    &mut prepared.scratch,
                    &mut report,
                    &final_budget,
                );
                if let Err((stage, at, cause)) = result
                    && report.outcome.is_ok()
                {
                    problem(&mut report, stage, at, cause);
                }
                finalize(&ctx, &mut prepared.owner, &mut report, &final_budget);
                report.summary.finalization_attempts = final_count.get();
                report.summary.open_handles_peak = handles.peak.get();
                for (row, counter) in report.volumes.iter_mut().zip(&prepared.counters) {
                    row.accepted_bytes = counter.accepted.get();
                    row.stage_open_attempts = counter.opens.get();
                    row.writer_opened = counter.writer.get();
                    report.summary.stage_open_attempts += row.stage_open_attempts;
                    report.summary.stage_files_created += u64::from(row.stage_created);
                }
                report.volumes.truncate(
                    prepared
                        .owner
                        .opened
                        .max(report.volumes.iter().rposition(|r| r.stage_path.is_some()).map_or(0, |i| i + 1)),
                );
                if report.commit == SplitCommitState::Complete {
                    report.written = std::mem::take(&mut prepared.receipts);
                }
                let retain = report.commit == SplitCommitState::Unknown
                    || report.volumes.iter().any(|r| {
                        matches!(
                            r.cleanup,
                            SplitVolumeCleanup::Retained
                                | SplitVolumeCleanup::ForeignPreserved
                                | SplitVolumeCleanup::Unresolved(_)
                        )
                    });
                if retain {
                    report.summary.reconciliation_handles =
                        prepared.owner.slots.iter().filter(|s| s.file.is_some()).count() as u64 + 1;
                    report.reconciliation = Some(SplitReconciliation {
                        inner: Evidence { owner: prepared.owner, _parent: self.parent, receipts: prepared.receipts },
                    });
                    report.summary.native_attempts = self.attempts.get();
                    report.summary.plan = self.usage.plan;
                    return report;
                }
            }
        }
        if report.destination.as_os_str().is_empty() {
            report.destination = std::mem::take(&mut self.parent.destination);
        }
        report.summary.native_attempts = self.attempts.get();
        report.summary.plan = self.usage.plan;
        report
    }

    fn prepare_split(&mut self, options: &SplitCreateOptions, report: &mut SplitCreateReport) -> Checked<Prepared> {
        work(&self.options, &mut self.usage.plan, 0)?;
        if options.limits.volumes == 0 || options.limits.stage_attempts_per_volume == 0 || options.volume_bytes < 4 {
            return Err(SplitCreateError::InvalidOptions(
                "nonzero volume and stage limits and at least four bytes per volume required",
            ));
        }
        let leaf = self.parent.leaf.as_bytes();
        if leaf.len() < 4 || !leaf[leaf.len() - 4..].eq_ignore_ascii_case(b".zip") {
            return Err(SplitCreateError::InvalidFinalLeaf);
        }
        report.summary.finalization_reserve = u64::from(options.limits.volumes)
            .checked_add(1)
            .and_then(|n| n.checked_mul(64))
            .and_then(|n| {
                n.checked_add(if self.options.durability == Durability::SyncFileAndDirectory { 2 } else { 0 })
            })
            .ok_or(SplitCreateError::Overflow)?;
        let held = self.entries.iter().filter_map(|e| e.source.as_ref()).filter(|s| s.file.is_some()).count() as u64;
        let transient = self.entries.iter().any(|e| e.payload_source().is_some_and(|s| s.file.is_none()));
        bound(held + 3 + u64::from(transient), options.limits.open_handles, SplitCreateLimit::OpenHandles)?;
        let mut decoded = 0;
        for entry in &self.entries {
            work(&self.options, &mut self.usage.plan, 1)?;
            if let Some(source) = entry.payload_source() {
                let size = source.stamp.len;
                writer_limit(
                    size,
                    self.options.limits.writer.entry_decoded_bytes,
                    crate::zip::write::Limit::EntryDecodedBytes,
                )?;
                limit(size, self.options.limits.verification_entry_bytes, CreateLimit::VerificationEntryBytes)?;
                decoded = add(decoded, size)?;
                writer_limit(
                    add(decoded, 1)?,
                    self.options.limits.writer.source_bytes,
                    crate::zip::write::Limit::SourceBytes,
                )?;
                limit(decoded, self.options.limits.verification_decoded_bytes, CreateLimit::VerificationDecodedBytes)?;
            }
        }
        bound(
            split_verify::Scratch::minimum_capacity(),
            options.limits.verification_scratch,
            SplitCreateLimit::VerificationScratch,
        )?;
        let e = self.entries.len();
        let need = (e as u64)
            .checked_mul((size_of::<wire::EntryWritten>() + size_of::<usize>()) as u64)
            .ok_or(SplitCreateError::Overflow)?;
        limit(add(self.usage.plan.capacity, need)?, self.options.limits.plan_capacity, CreateLimit::PlanCapacity)?;
        let receipts = reserve::<wire::EntryWritten>(e)?;
        let mut indices = reserve::<usize>(e)?;
        indices.extend(0..e);
        self.usage.plan.capacity = add(self.usage.plan.capacity, add(capacity(&receipts), capacity(&indices))?)?;
        limit(self.usage.plan.capacity, self.options.limits.plan_capacity, CreateLimit::PlanCapacity)?;
        check_hierarchy(&self.entries, &mut indices, &self.options, &mut self.usage.plan, false)?;
        if self.options.collisions == CollisionPolicy::CallerKeys {
            check_hierarchy(&self.entries, &mut indices, &self.options, &mut self.usage.plan, true)?;
        }
        let v = usize::try_from(options.limits.volumes).map_err(|_| SplitCreateError::Overflow)?;
        let problems = v.checked_mul(16).and_then(|x| x.checked_add(16)).ok_or(SplitCreateError::Overflow)?;
        let digits = (options.limits.volumes - 1).max(1).ilog10() as usize + 1;
        let max_leaf = leaf.len().max(leaf.len() - 4 + 2 + digits.max(2));
        let parent_len = self.parent.real_path.as_os_str().len() + 1;
        let per = size_of::<Slot>()
            + size_of::<SplitVolumeReport>()
            + size_of::<Counters>()
            + 16 * size_of::<SplitProblem>()
            + max_leaf
            + 1
            + parent_len
            + max_leaf
            + parent_len
            + STAGE_NAME;
        let mut minimum = (v as u64).checked_mul(per as u64).ok_or(SplitCreateError::Overflow)?;
        minimum = add(minimum, 16 * size_of::<SplitProblem>() as u64)?;
        minimum = add(minimum, self.parent.destination.as_os_str().len() as u64)?;
        minimum = add(
            minimum,
            self.parent.destination.parent().ok_or(CreateError::InvalidDestination)?.as_os_str().len() as u64 + 1,
        )?;
        minimum = add(minimum, self.parent.real_path.as_os_str().len() as u64 + 1)?;
        minimum =
            add(minimum, (e as u64).checked_mul(size_of::<Option<Probe>>() as u64).ok_or(SplitCreateError::Overflow)?)?;
        minimum = add(minimum, split_verify::Scratch::minimum_capacity())?;
        for entry in &self.entries {
            work(&self.options, &mut self.usage.plan, 1)?;
            if let Some(source) = &entry.source {
                minimum = add(minimum, source.path.as_os_str().len() as u64 + 1)?;
            }
        }
        bound(minimum, options.limits.native_capacity, SplitCreateLimit::NativeCapacity)?;
        let mut slots = reserve::<Slot>(v)?;
        let mut counters = reserve::<Counters>(v)?;
        report.volumes = reserve::<SplitVolumeReport>(v)?;
        report.additional_problems = reserve::<SplitProblem>(problems)?;
        let mut charged =
            capacity(&slots) + capacity(&counters) + capacity(&report.volumes) + capacity(&report.additional_problems);
        report.summary.preparation_capacity = charged;
        for disk in 0..v {
            work(&self.options, &mut self.usage.plan, 1)?;
            let leaf = reserve::<u8>(max_leaf + 1)?;
            let final_path = path_buffer(parent_len + max_leaf)?;
            let stage_path = path_buffer(parent_len + STAGE_NAME)?;
            charged =
                add(charged, leaf.capacity() as u64 + final_path.capacity() as u64 + stage_path.capacity() as u64)?;
            report.summary.preparation_capacity = charged;
            report.summary.preparation_capacity = charged;
            bound(charged, options.limits.native_capacity, SplitCreateLimit::NativeCapacity)?;
            slots.push(Slot {
                file: None,
                stamp: None,
                verified: None,
                terminal: None,
                name: [0; STAGE_NAME],
                leaf,
                final_path,
                stage_path,
            });
            counters.push(Counters::default());
            report.volumes.push(empty_row(disk as u32, report.barriers.prefix_parent));
        }
        report.destination = path_buffer(self.parent.destination.as_os_str().len())?;
        report.destination.push(&self.parent.destination);
        charged = add(charged, report.destination.capacity() as u64)?;
        report.summary.preparation_capacity = charged;
        let original_parent = Probe::new(self.parent.destination.parent().ok_or(CreateError::InvalidDestination)?)?;
        let real_parent = Probe::new(&self.parent.real_path)?;
        charged = add(charged, original_parent.capacity() + real_parent.capacity())?;
        report.summary.preparation_capacity = charged;
        let mut probes = reserve::<Option<Probe>>(e)?;
        charged = add(charged, capacity(&probes))?;
        report.summary.preparation_capacity = charged;
        for entry in &self.entries {
            work(&self.options, &mut self.usage.plan, 1)?;
            let probe = entry.source.as_ref().map(|s| Probe::new(&s.path)).transpose()?;
            charged = add(charged, probe.as_ref().map_or(0, Probe::capacity))?;
            report.summary.preparation_capacity = charged;
            report.summary.preparation_capacity = charged;
            bound(charged, options.limits.native_capacity, SplitCreateLimit::NativeCapacity)?;
            probes.push(probe);
        }
        let scratch = split_verify::Scratch::new(options.limits.verification_scratch).map_err(|e| match e {
            CreateError::Limit(CreateLimit::VerificationScratch) => {
                SplitCreateError::Limit(SplitCreateLimit::VerificationScratch)
            }
            e => e.into(),
        })?;
        charged = add(charged, scratch.capacity())?;
        report.summary.preparation_capacity = charged;
        bound(charged, options.limits.native_capacity, SplitCreateLimit::NativeCapacity)?;
        report.summary.preparation_capacity = charged;
        Ok(Prepared {
            owner: Owner { slots, opened: 0 },
            counters,
            probes,
            original_parent,
            real_parent,
            scratch,
            receipts,
        })
    }
}

struct Provider<'a, 'b> {
    owner: &'a mut Owner,
    rows: &'a mut [SplitVolumeReport],
    counters: &'b [Counters],
    ctx: &'b Context<'b>,
    failure: &'b RefCell<Option<SplitProblem>>,
    max_attempts: u32,
}
struct Sink<'a> {
    file: Counted<'a>,
    counter: &'a Counters,
    attempts: Attempts<'a>,
    failure: &'a RefCell<Option<SplitProblem>>,
}
fn bridge(slot: &RefCell<Option<SplitProblem>>, error: SplitCreateError, stage: SplitCreateStage) -> std::io::Error {
    let mut first = slot.borrow_mut();
    if first.is_none() {
        *first = Some(SplitProblem { stage, at: None, cause: error });
    }
    std::io::Error::from_raw_os_error(libc::EIO)
}
impl Write for Sink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let n = self
            .attempts
            .run(|| self.file.file.as_ref().expect("active clone").write(bytes))
            .map_err(|e| bridge(self.failure, e.into(), SplitCreateStage::Write))?;
        self.counter.accepted.set(
            self.counter
                .accepted
                .get()
                .checked_add(n as u64)
                .ok_or_else(|| bridge(self.failure, SplitCreateError::Overflow, SplitCreateStage::Write))?,
        );
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.attempts
            .run(|| self.file.file.as_ref().expect("active clone").flush())
            .map_err(|e| bridge(self.failure, e.into(), SplitCreateStage::Write))
    }
}
impl<'a, 'b> VolumeProvider for Provider<'a, 'b> {
    type Sink = Sink<'b>;
    fn open(&mut self, disk: u32) -> std::io::Result<Self::Sink> {
        let result = (|| -> Checked<Sink<'b>> {
            self.ctx.handles.room(2)?;
            let slot =
                self.owner.slots.get_mut(disk as usize).ok_or(SplitCreateError::Limit(SplitCreateLimit::Volumes))?;
            let row = &mut self.rows[disk as usize];
            let counter = &self.counters[disk as usize];
            let ctx = self.ctx;
            for _ in 0..self.max_attempts {
                ctx.mutation_before(&ctx.attempts)?;
                let mut random = [0u8; 16];
                getrandom::fill(&mut random)
                    .map_err(|_| CreateError::Io(std::io::Error::from_raw_os_error(libc::EIO)))?;
                slot.name[..10].copy_from_slice(if ctx.parent.leaf.as_bytes().contains(&b'~') {
                    b".zipfast-@"
                } else {
                    b".zipfast-~"
                });
                for (i, b) in random.iter().enumerate() {
                    slot.name[10 + 2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                    slot.name[11 + 2 * i] = b"0123456789abcdef"[(b & 15) as usize];
                }
                slot.name[STAGE_NAME - 1] = 0;
                slot.stage_path.clear();
                slot.stage_path.push(&ctx.parent.real_path);
                slot.stage_path.push(std::ffi::OsStr::from_bytes(&slot.name[..STAGE_NAME - 1]));
                ctx.handles.room(1)?;
                match unix::split::create(ctx.parent, slot.name(), &ctx.attempts, &counter.opens) {
                    Ok(file) => {
                        slot.file = Some(file);
                        ctx.handles.opened();
                        row.stage_created = true;
                        self.owner.opened = disk as usize + 1;
                        break;
                    }
                    Err(CreateError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => {
                        row.stage_path = Some(std::mem::take(&mut slot.stage_path));
                        if let CreateError::Io(io) = &e
                            && !matches!(
                                io.raw_os_error(),
                                Some(
                                    libc::EACCES
                                        | libc::EPERM
                                        | libc::EROFS
                                        | libc::ENOENT
                                        | libc::ENOTDIR
                                        | libc::ENAMETOOLONG
                                        | libc::ENOSPC
                                        | libc::EDQUOT
                                        | libc::ELOOP
                                )
                            )
                        {
                            ctx.namespace_valid.set(false);
                            row.stage_name = unresolved(SplitProblemRef::Primary);
                            row.cleanup = SplitVolumeCleanup::Unresolved(SplitProblemRef::Primary);
                        }
                        return Err(e.into());
                    }
                }
            }
            if slot.file.is_none() {
                return Err(SplitCreateError::Limit(SplitCreateLimit::StageNameAttempts));
            }
            row.stage_path = Some(std::mem::take(&mut slot.stage_path));
            ctx.mutation_after(&ctx.attempts)?;
            let file = slot.file.as_ref().expect("owned stage");
            #[cfg(test)]
            tests::event(tests::Event::SplitStageStat, row.stage_path.as_deref())?;
            let stamp = unix::file_stamp(file, &ctx.attempts)?;
            slot.stamp = Some(stamp);
            if stamp.len != 0 {
                return Err(CreateError::StageChanged.into());
            }
            ctx.handles.room(1)?;
            #[cfg(test)]
            tests::event(tests::Event::SplitStageClone, row.stage_path.as_deref())?;
            let clone = ctx.attempts.run(|| file.try_clone())?;
            ctx.handles.opened();
            counter.writer.set(true);
            Ok(Sink {
                file: Counted { file: Some(clone), handles: ctx.handles },
                counter,
                attempts: ctx.attempts,
                failure: self.failure,
            })
        })();
        result.map_err(|e| bridge(self.failure, e, SplitCreateStage::StageCreate))
    }
}

type Stopped = (SplitCreateStage, Option<wire::Location>, SplitCreateError);
trait At<T> {
    fn at(self, stage: SplitCreateStage) -> std::result::Result<T, Stopped>;
}
impl<T, E: Into<SplitCreateError>> At<T> for std::result::Result<T, E> {
    fn at(self, stage: SplitCreateStage) -> std::result::Result<T, Stopped> {
        self.map_err(|e| (stage, None, e.into()))
    }
}
fn writer_failure(
    error: Arc<wire::Error>,
    first: &RefCell<Option<SplitProblem>>,
    report: &mut SplitCreateReport,
) -> Stopped {
    report.summary.transport = error.usage;
    report.summary.writer = error.writer;
    let at = Some(error.at);
    let origin = first.borrow_mut().take();
    let stage = origin.as_ref().map_or(
        match error.stage {
            wire::Stage::Open => SplitCreateStage::StageCreate,
            wire::Stage::Finish => SplitCreateStage::Finish,
            _ => SplitCreateStage::Write,
        },
        |p| p.stage,
    );
    let cause = origin.map(|p| p.cause).unwrap_or_else(|| match error.kind {
        wire::ErrorKind::Canceled | wire::ErrorKind::Writer(WriteError::Canceled) => CreateError::Canceled.into(),
        wire::ErrorKind::Writer(WriteError::Overflow) => CreateError::Overflow.into(),
        wire::ErrorKind::Limit(wire::Limit::Disks) => SplitCreateError::Limit(SplitCreateLimit::Volumes),
        wire::ErrorKind::Limit(wire::Limit::Attempts) => SplitCreateError::Limit(SplitCreateLimit::TransportAttempts),
        _ => project_source_error(&error).unwrap_or_else(|| SplitCreateError::Write(Arc::clone(&error))),
    });
    report.writer_failure = Some(error);
    (stage, at, cause)
}
#[allow(clippy::too_many_arguments)]
fn execute(
    ctx: &Context<'_>,
    create: &CreateOptions,
    options: &SplitCreateOptions,
    owner: &mut Owner,
    counters: &[Counters],
    receipts: &mut Vec<wire::EntryWritten>,
    scratch: &mut split_verify::Scratch,
    report: &mut SplitCreateReport,
    final_budget: &Attempts<'_>,
) -> std::result::Result<(), Stopped> {
    ctx.sources(&ctx.attempts).at(SplitCreateStage::SourceRead)?;
    let failure = RefCell::new(None);
    let provider = Provider {
        owner,
        rows: &mut report.volumes,
        counters,
        ctx,
        failure: &failure,
        max_attempts: options.limits.stage_attempts_per_volume,
    };
    let wire_options = wire::Options {
        volume_bytes: options.volume_bytes,
        volumes: options.limits.volumes,
        transport_attempts: options.limits.transport_attempts,
        writer: WriterOptions {
            comment: &create.archive_comment,
            limits: create.limits.writer,
            cancel: Some(create.cancel.clone()),
        },
    };
    let mut writer = match ZipSplitWriter::new(provider, wire_options) {
        Ok(w) => w,
        Err(e) => return Err(writer_failure(e, &failure, report)),
    };
    let written = (|| -> std::result::Result<(), Stopped> {
        for (index, entry) in ctx.entries.iter().enumerate() {
            let result = if let Some(source) = entry.payload_source() {
                let reopened = if source.file.is_none() {
                    ctx.handles.room(1).at(SplitCreateStage::SourceRead)?;
                    let file = unix::open_source(&source.path, &ctx.attempts).at(SplitCreateStage::SourceRead)?;
                    ctx.handles.opened();
                    Some(Counted { file: Some(file), handles: ctx.handles })
                } else {
                    None
                };
                let file = source
                    .file
                    .as_ref()
                    .or_else(|| reopened.as_ref().and_then(|f| f.file.as_ref()))
                    .expect("source file");
                ctx.capture(index, file).at(SplitCreateStage::SourceRead)?;
                ctx.attempts.run(|| (&*file).seek(SeekFrom::Start(0))).at(SplitCreateStage::SourceRead)?;
                let mut input = transaction::SourceInput::new(file, ctx.attempts);
                let result = writer.add_file(entry.options(), &mut input, InputLength::Exact(source.stamp.len));
                if result.is_ok() {
                    ctx.capture(index, file).at(SplitCreateStage::SourceRead)?;
                }
                result
            } else {
                writer.add_directory(entry.options())
            };
            match result {
                Ok(r) => receipts.push(r),
                Err(e) => return Err((SplitCreateStage::Write, Some(e.at), SplitCreateError::Write(e))),
            }
        }
        Ok(())
    })();
    if let Err(stop) = written {
        let (transport, usage) = writer.usage();
        drop(writer);
        report.summary.transport = transport;
        report.summary.writer = usage;
        return Err(match stop {
            (_, _, SplitCreateError::Write(e)) => writer_failure(e, &failure, report),
            other => other,
        });
    }
    let finished = match writer.finish() {
        Ok(f) => f,
        Err(e) => return Err(writer_failure(e, &failure, report)),
    };
    let layout = split_verify::Layout {
        volume_bytes: options.volume_bytes,
        transport: finished.usage,
        writer: finished.writer,
        central_start: finished.central_start,
        zip64: finished.zip64,
    };
    // End the provider's mutable owner/report borrows before verification.
    report.summary.transport = layout.transport;
    report.summary.writer = layout.writer;
    for slot in owner.slots.iter_mut().take(owner.opened) {
        slot.stamp =
            Some(unix::file_stamp(slot.file.as_ref().expect("stage"), &ctx.attempts).at(SplitCreateStage::Verify)?);
    }
    let mut usage = VerificationUsage::default();
    let verified =
        split_verify::verify(owner, (ctx.entries, receipts), layout, create, &ctx.attempts, scratch, &mut usage);
    report.summary.verification = SplitVerificationUsage {
        read_bytes: usage.read_bytes,
        decoded_bytes: usage.decoded_bytes,
        members: usage.payloads,
        central_rows: usage.entries,
        raw_metadata_bytes: usage.metadata_bytes,
        metadata_work: usage.directory.work_units,
        record_capacity: usage.record_capacity,
        scratch_capacity: usage.scratch_capacity,
    };
    verified.map_err(verification_error).at(SplitCreateStage::Verify)?;
    for (disk, slot) in owner.slots.iter_mut().take(owner.opened).enumerate() {
        slot.verified = slot.stamp;
        report.volumes[disk].verified = slot.verified.map(snapshot);
    }
    #[cfg(test)]
    tests::event(tests::Event::AfterVerify, report.volumes.first().and_then(|r| r.stage_path.as_deref()))
        .at(SplitCreateStage::Verify)?;
    for (disk, slot) in owner.slots.iter_mut().take(owner.opened).enumerate() {
        let file = slot.file.as_ref().expect("stage");
        let before = slot.stamp.expect("verified stamp");
        report.volumes[disk].verified = Some(snapshot(before));
        if unix::file_stamp(file, &ctx.attempts).at(SplitCreateStage::Permissions)? != before {
            return Err((SplitCreateStage::Permissions, None, CreateError::StageChanged.into()));
        }
        unix::chmod(file, create.output_permissions, &ctx.attempts).at(SplitCreateStage::Permissions)?;
        let after = unix::file_stamp(file, &ctx.attempts).at(SplitCreateStage::Permissions)?;
        if !before.same_payload(after) || after.mode != create.output_permissions {
            return Err((SplitCreateStage::Permissions, None, CreateError::StageChanged.into()));
        }
        slot.stamp = Some(after);
        if create.durability == Durability::SyncFileAndDirectory {
            report.volumes[disk].data_sync = SplitBarrierState::NotAttempted;
            if let Err(cause) = unix::sync_stage(file, &ctx.attempts) {
                let r = problem(report, SplitCreateStage::FileSync, None, cause.into());
                report.volumes[disk].data_sync = SplitBarrierState::Failed(r);
                return Err((SplitCreateStage::FileSync, None, CreateError::CleanupIncomplete.into()));
            }
            report.volumes[disk].data_sync = SplitBarrierState::Complete;
        }
    }
    actual_names(ctx, owner, report).at(SplitCreateStage::NamePreflight)?;
    ctx.sources(&ctx.attempts).at(SplitCreateStage::SourceRead)?;
    #[cfg(test)]
    tests::event(tests::Event::BeforeCommit, report.volumes.first().and_then(|r| r.stage_path.as_deref()))
        .at(SplitCreateStage::NamePreflight)?;
    for disk in 0..owner.opened {
        let last = disk + 1 == owner.opened;
        if last {
            if create.durability == Durability::SyncFileAndDirectory {
                report.barriers.prefix_parent = SplitBarrierState::NotAttempted;
                if let Err(cause) = unix::sync_directory(&ctx.parent.file, final_budget) {
                    let r = problem(report, SplitCreateStage::PreFinalSync, None, cause.into());
                    report.barriers.prefix_parent = SplitBarrierState::Failed(r);
                    return Err((SplitCreateStage::PreFinalSync, None, CreateError::CleanupIncomplete.into()));
                }
                report.barriers.prefix_parent = SplitBarrierState::Complete;
            }
            ctx.sources(&ctx.attempts).at(SplitCreateStage::SourceRead)?;
            for (n, slot) in owner.slots.iter().take(owner.opened).enumerate() {
                check_slot(ctx, slot, n < disk, &ctx.attempts).at(SplitCreateStage::Verify)?;
            }
        }
        let stage = if last { SplitCreateStage::FinalPublish } else { SplitCreateStage::NumberedPublish };
        let slot = &mut owner.slots[disk];
        ctx.mutation_before(&ctx.attempts).at(stage)?;
        check_slot(ctx, slot, false, &ctx.attempts).at(stage)?;
        let row = &mut report.volumes[disk];
        match ctx.parent.publish_noreplace_leaf(slot.name(), slot.leaf(), &ctx.attempts) {
            Ok(()) => {
                row.publication = SplitVolumePublication::Published;
                report.commit = if last { SplitCommitState::Complete } else { SplitCommitState::PrefixPublished };
            }
            Err(PublishError::Definite(e)) => {
                row.publication = SplitVolumePublication::NotPublished;
                return Err((stage, Some(wire::Location { disk: disk as u32, offset: 0 }), e.into()));
            }
            Err(PublishError::Uncertain(e)) => {
                row.publication = SplitVolumePublication::Unknown;
                report.commit = SplitCommitState::Unknown;
                ctx.namespace_valid.set(false);
                return Err((stage, Some(wire::Location { disk: disk as u32, offset: 0 }), e.into()));
            }
        }
        ctx.mutation_after(&ctx.attempts).at(stage)?;
        #[cfg(test)]
        tests::event(tests::Event::AfterCommit, report.volumes[disk].final_path.as_deref()).at(stage)?;
        let current = unix::file_stamp(slot.file.as_ref().expect("stage"), &ctx.attempts).at(stage)?;
        let old = slot.stamp.expect("verified");
        if !current.same_payload(old) || current.mode != old.mode {
            return Err((stage, None, CreateError::StageChanged.into()));
        }
        slot.stamp = Some(current);
    }
    report.outcome =
        Ok(SplitCreatedArchive { volume_count: owner.opened as u32, physical_bytes: layout.transport.bytes });
    if create.durability == Durability::SyncFileAndDirectory {
        report.barriers.final_parent = SplitBarrierState::NotAttempted;
        if let Err(cause) = unix::sync_directory(&ctx.parent.file, final_budget) {
            let r = problem(report, SplitCreateStage::DirectorySync, None, cause.into());
            report.barriers.final_parent = SplitBarrierState::Failed(r);
            return Err((SplitCreateStage::DirectorySync, None, CreateError::CleanupIncomplete.into()));
        }
        report.barriers.final_parent = SplitBarrierState::Complete;
        report.durability = DurabilityState::Synced;
    }
    Ok(())
}

fn actual_names(ctx: &Context<'_>, owner: &mut Owner, report: &mut SplitCreateReport) -> Checked<()> {
    let maximum = unix::split::component_limit(ctx.parent, &ctx.attempts)?;
    let raw = ctx.parent.leaf.as_bytes();
    let stem = &raw[..raw.len() - 4];
    for (disk, slot) in owner.slots.iter_mut().take(owner.opened).enumerate() {
        slot.leaf.clear();
        let last = disk + 1 == owner.opened;
        if last {
            slot.leaf.extend_from_slice(raw);
        } else {
            slot.leaf.extend_from_slice(stem);
            slot.leaf.extend_from_slice(b".z");
            let mut digits = [b'0'; 10];
            let mut n = disk + 1;
            let mut at = digits.len();
            while n != 0 {
                at -= 1;
                digits[at] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            if digits.len() - at < 2 {
                at -= 1;
            }
            slot.leaf.extend_from_slice(&digits[at..]);
        }
        let bytes = slot.leaf.len() as u64;
        if maximum.is_some_and(|m| bytes > m) {
            slot.leaf.clear();
            return Err(SplitCreateError::NameTooLong { disk: disk as u32, bytes, maximum });
        }
        slot.final_path.push(&ctx.parent.real_path);
        slot.final_path.push(std::ffi::OsStr::from_bytes(&slot.leaf));
        slot.leaf.push(0);
        let row = &mut report.volumes[disk];
        row.role = if last { SplitVolumeRole::FinalZip } else { SplitVolumeRole::Numbered };
        row.final_path = Some(std::mem::take(&mut slot.final_path));
    }
    ctx.parent(&ctx.attempts)?;
    for slot in owner.slots.iter().take(owner.opened) {
        if ctx.parent.lookup(slot.leaf(), &ctx.attempts)?.is_some() {
            return Err(CreateError::Conflict.into());
        }
    }
    Ok(())
}
fn check_slot(ctx: &Context<'_>, slot: &Slot, published: bool, budget: &Attempts<'_>) -> Result<()> {
    let expected = slot.stamp.ok_or(CreateError::StageChanged)?;
    let held = unix::file_stamp(slot.file.as_ref().ok_or(CreateError::StageChanged)?, budget)?;
    let named = ctx.parent.lookup(if published { slot.leaf() } else { slot.name() }, budget)?;
    if held != expected || !matches!(named,Some(NameState::Regular(stamp)) if stamp==held) {
        return Err(CreateError::StageChanged);
    }
    Ok(())
}
fn snapshot(stamp: Stamp) -> SplitFileSnapshot {
    SplitFileSnapshot {
        identity: SplitFileIdentity { device: stamp.identity.0, inode: stamp.identity.1 },
        bytes: stamp.len,
        modified: stamp.modified,
        changed: stamp.changed,
        permissions: stamp.mode,
    }
}
fn observation(value: Option<NameState>, held: Stamp, expected: Option<Stamp>) -> SplitNameObservation {
    match value {
        None => SplitNameObservation { state: SplitNameState::Absent, identity: None, regular: None },
        Some(NameState::Other) => {
            SplitNameObservation { state: SplitNameState::Foreign, identity: None, regular: None }
        }
        Some(NameState::Regular(named)) => {
            let state = if named.identity != held.identity {
                SplitNameState::Foreign
            } else if named != held || expected.is_some_and(|s| s != held) {
                SplitNameState::ChangedHeld
            } else {
                SplitNameState::MatchesHeld
            };
            SplitNameObservation { state, identity: Some(snapshot(named).identity), regular: Some(snapshot(named)) }
        }
    }
}
fn problem(
    report: &mut SplitCreateReport,
    stage: SplitCreateStage,
    at: Option<wire::Location>,
    cause: SplitCreateError,
) -> SplitProblemRef {
    if report.outcome.is_ok() {
        report.outcome = Err(SplitCreateFailure { stage, at, cause });
        SplitProblemRef::Primary
    } else {
        let index = report.additional_problems.len();
        assert!(index < report.additional_problems.capacity(), "pre-reserved split aftermath bound");
        report.additional_problems.push(SplitProblem { stage, at, cause });
        SplitProblemRef::Additional(index as u64)
    }
}
fn unresolved(reference: SplitProblemRef) -> SplitNameObservation {
    SplitNameObservation { state: SplitNameState::Unresolved(reference), identity: None, regular: None }
}
fn finalize(ctx: &Context<'_>, owner: &mut Owner, report: &mut SplitCreateReport, budget: &Attempts<'_>) {
    // A main-budget probe may fail after the confirmed final rename. The
    // reserved parent barrier still runs once, independently of that failure.
    if report.commit == SplitCommitState::Complete
        && report.durability != DurabilityState::NotRequested
        && matches!(report.barriers.final_parent, SplitBarrierState::NotRequested | SplitBarrierState::NotAttempted)
    {
        report.barriers.final_parent = match unix::sync_directory(&ctx.parent.file, budget) {
            Ok(()) => SplitBarrierState::Complete,
            Err(error) => {
                SplitBarrierState::Failed(problem(report, SplitCreateStage::DirectorySync, None, error.into()))
            }
        };
        if report.barriers.prefix_parent == SplitBarrierState::Complete
            && report.barriers.final_parent == SplitBarrierState::Complete
            && report.volumes.iter().take(owner.opened).all(|v| v.data_sync == SplitBarrierState::Complete)
        {
            report.durability = DurabilityState::Synced;
        }
    }
    let cleanup = !matches!(report.commit, SplitCommitState::Complete | SplitCommitState::Unknown);
    let parent_problem = ctx.parent(budget).err().map(|e| problem(report, SplitCreateStage::Reconcile, None, e.into()));
    let mut mutated = false;
    for disk in 0..owner.opened {
        let slot = &mut owner.slots[disk];
        let location = Some(wire::Location { disk: disk as u32, offset: 0 });
        let Some(file) = &slot.file else { continue };
        let held = match unix::file_stamp(file, budget) {
            Ok(stamp) => stamp,
            Err(e) => {
                let r = problem(report, SplitCreateStage::Reconcile, location, e.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(r);
                report.volumes[disk].stage_name = unresolved(r);
                report.volumes[disk].final_name = unresolved(r);
                continue;
            }
        };
        slot.terminal = Some(held);
        report.volumes[disk].terminal_held = Some(snapshot(held));
        if let Some(reference) = parent_problem {
            report.volumes[disk].stage_name = unresolved(reference);
            report.volumes[disk].final_name = unresolved(reference);
            report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(reference);
            continue;
        }
        let expected = report.volumes[disk].verified.and(slot.stamp);
        let stage_name = ctx.parent.lookup(slot.name(), budget);
        report.volumes[disk].stage_name = match stage_name {
            Ok(v) => observation(v, held, expected),
            Err(e) => {
                let r = problem(report, SplitCreateStage::Reconcile, location, e.into());
                unresolved(r)
            }
        };
        if !slot.leaf.is_empty() {
            report.volumes[disk].final_name = match ctx.parent.lookup(slot.leaf(), budget) {
                Ok(v) => observation(v, held, expected),
                Err(e) => {
                    let r = problem(report, SplitCreateStage::Reconcile, location, e.into());
                    unresolved(r)
                }
            };
        }
        if !cleanup {
            report.volumes[disk].cleanup = if report.commit == SplitCommitState::Unknown {
                SplitVolumeCleanup::Retained
            } else {
                SplitVolumeCleanup::NotNeeded
            };
            if report.commit == SplitCommitState::Complete
                && !matches!(report.volumes[disk].final_name.state, SplitNameState::MatchesHeld)
            {
                problem(report, SplitCreateStage::Reconcile, location, CreateError::StageChanged.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::Retained;
            }
            continue;
        }
        let published = report.volumes[disk].publication == SplitVolumePublication::Published;
        let leaf = if published { slot.leaf() } else { slot.name() };
        let removed = (|| -> Result<bool> {
            ctx.mutation_before(budget)?;
            let before = unix::file_stamp(file, budget)?;
            match ctx.parent.lookup(leaf, budget)? {
                None => return Err(CreateError::CleanupIncomplete),
                Some(NameState::Regular(named)) if named == before => {}
                _ => return Err(CreateError::StageChanged),
            }
            if let Err(error) = ctx.parent.unlink(leaf, budget) {
                // An unsuccessful mutation is never retried. Keep the remaining
                // namespace untouched when its effect cannot be established.
                if matches!(&error,CreateError::Io(io) if !matches!(io.raw_os_error(),Some(libc::EACCES|libc::EPERM|libc::EROFS|libc::ENOENT|libc::ENOTDIR)))
                {
                    ctx.namespace_valid.set(false);
                }
                return Err(error);
            }
            mutated = true;
            ctx.mutation_after(budget)?;
            if ctx.parent.lookup(leaf, budget)?.is_some() {
                return Err(CreateError::CleanupIncomplete);
            }
            Ok(true)
        })();
        match removed {
            Ok(was_removed) => {
                report.volumes[disk].cleanup =
                    if was_removed { SplitVolumeCleanup::Removed } else { SplitVolumeCleanup::NotNeeded };
                let absent = SplitNameObservation { state: SplitNameState::Absent, identity: None, regular: None };
                if published {
                    report.volumes[disk].final_name = absent;
                } else {
                    report.volumes[disk].stage_name = absent;
                }
            }
            Err(CreateError::StageChanged) => {
                problem(report, SplitCreateStage::Cleanup, location, CreateError::StageChanged.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::ForeignPreserved;
            }
            Err(e) => {
                let r = problem(report, SplitCreateStage::Cleanup, location, e.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(r);
            }
        }
    }
    if cleanup && mutated && report.durability != DurabilityState::NotRequested {
        report.barriers.aftermath_parent = match unix::sync_directory(&ctx.parent.file, budget) {
            Ok(()) => SplitBarrierState::Complete,
            Err(e) => SplitBarrierState::Failed(problem(report, SplitCreateStage::DirectorySync, None, e.into())),
        };
    }
    // Second and final observation pass follows all owned namespace mutations.
    let terminal_parent =
        ctx.parent(budget).err().map(|e| problem(report, SplitCreateStage::Reconcile, None, e.into()));
    for disk in 0..owner.opened {
        let slot = &mut owner.slots[disk];
        let at = Some(wire::Location { disk: disk as u32, offset: 0 });
        let held = match unix::file_stamp(slot.file.as_ref().expect("owned stage"), budget) {
            Ok(stamp) => stamp,
            Err(e) => {
                let r = problem(report, SplitCreateStage::Reconcile, at, e.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(r);
                report.volumes[disk].stage_name = unresolved(r);
                report.volumes[disk].final_name = unresolved(r);
                continue;
            }
        };
        slot.terminal = Some(held);
        report.volumes[disk].terminal_held = Some(snapshot(held));
        if let Some(r) = terminal_parent {
            report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(r);
            report.volumes[disk].stage_name = unresolved(r);
            report.volumes[disk].final_name = unresolved(r);
            continue;
        }
        let expected = if matches!(report.volumes[disk].cleanup, SplitVolumeCleanup::Removed) {
            None
        } else {
            report.volumes[disk].verified.and(slot.stamp)
        };
        report.volumes[disk].stage_name = match ctx.parent.lookup(slot.name(), budget) {
            Ok(v) => observation(v, held, expected),
            Err(e) => {
                let r = problem(report, SplitCreateStage::Reconcile, at, e.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(r);
                unresolved(r)
            }
        };
        if report.volumes[disk].final_path.is_some() {
            report.volumes[disk].final_name = match ctx.parent.lookup(slot.leaf(), budget) {
                Ok(v) => observation(v, held, expected),
                Err(e) => {
                    let r = problem(report, SplitCreateStage::Reconcile, at, e.into());
                    report.volumes[disk].cleanup = SplitVolumeCleanup::Unresolved(r);
                    unresolved(r)
                }
            };
            if report.commit == SplitCommitState::Complete
                && !matches!(report.volumes[disk].final_name.state, SplitNameState::MatchesHeld)
            {
                problem(report, SplitCreateStage::Reconcile, at, CreateError::StageChanged.into());
                report.volumes[disk].cleanup = SplitVolumeCleanup::Retained;
            }
        }
    }
    let mut observed = 0;
    let mut matches = 0;
    let mut unknown = false;
    for row in report.volumes.iter().take(owner.opened).filter(|r| r.final_path.is_some()) {
        observed += 1;
        match row.final_name.state {
            SplitNameState::MatchesHeld | SplitNameState::ChangedHeld => matches += 1,
            SplitNameState::NotChecked | SplitNameState::Unresolved(_) => unknown = true,
            _ => {}
        }
    }
    report.visibility = if unknown {
        SplitVisibility::Unresolved
    } else if observed == 0 {
        SplitVisibility::NotChecked
    } else if matches == 0 {
        SplitVisibility::NoneMatch
    } else if matches == observed {
        SplitVisibility::AllMatch
    } else {
        SplitVisibility::PartialMatch
    };
}
fn verification_error(error: split_verify::Error) -> SplitCreateError {
    match error {
        split_verify::Error::Native(e) => e.into(),
        split_verify::Error::Invalid { at, kind, member } => {
            use split_verify::Problem as P;
            let kind = match kind {
                P::VolumeCount => SplitVerificationError::VolumeCount,
                P::VolumeLength => SplitVerificationError::VolumeLength,
                P::Marker => SplitVerificationError::Marker,
                P::Receipt => SplitVerificationError::Receipt,
                P::Placement => SplitVerificationError::PackedExtent,
                P::LocalHeader => SplitVerificationError::LocalHeader,
                P::CentralHeader => SplitVerificationError::CentralHeader,
                P::Extras => SplitVerificationError::Extras,
                P::Descriptor => SplitVerificationError::Descriptor,
                P::EndGroup => SplitVerificationError::EndGroup,
                P::Checksum => SplitVerificationError::Checksum,
                P::PackedExtent => SplitVerificationError::PackedExtent,
                P::CodecCompletion => SplitVerificationError::CodecCompletion,
                P::DecodedLength => SplitVerificationError::DecodedLength,
            };
            SplitCreateError::Verification { disk: Some(at.disk), member, kind }
        }
    }
}

fn project_source_error(error: &wire::Error) -> Option<SplitCreateError> {
    if let wire::ErrorKind::Writer(WriteError::Io { source, .. }) = &error.kind
        && let Some(native) = source.get_ref().and_then(|e| e.downcast_ref::<CreateError>())
    {
        return match native {
            CreateError::Canceled => Some(CreateError::Canceled.into()),
            CreateError::Overflow => Some(CreateError::Overflow.into()),
            CreateError::Limit(k) => Some(CreateError::Limit(*k).into()),
            _ => None,
        };
    }
    None
}
