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

use crate::zip::write::{Limit as W, exact_member_geometry};

use super::*;

pub(super) struct Prepared {
    pub(super) prefix: u64,
    pub(super) members: Vec<Member>,
    pub(super) outcomes: VerificationSummary,
    pub(super) written: Vec<WrittenEntry>,
}

impl RewritePlan {
    pub(super) fn preflight(&mut self) -> Result<Prepared> {
        let options = &self.options;
        let limits = options.limits;
        let changed = !self.inputs.is_empty() || self.actions.iter().any(|action| matches!(action, Action::Remove));
        let entries = self.usage.common.plan.entries;
        let count = usize::try_from(entries).map_err(|_| CreateError::Overflow)?;
        if changed {
            output_count(entries, limits.common)?
        }
        let old = self.metadata.len();
        let index_count = old.max(count).max(self.inputs.len());
        let mut members = Vec::new();
        let mut order = Vec::new();
        let mut written = Vec::new();
        let fixed = self.fixed_capacity()?;
        let overhead = add(bytes_for::<Member>(old)?, bytes_for::<usize>(index_count)?)?;
        let outcome_bytes = bytes_for::<EntryVerification>(count)?;
        let receipt_bytes = if changed { bytes_for::<WrittenEntry>(count)? } else { 0 };
        let total = add(add(fixed, overhead)?, add(outcome_bytes, receipt_bytes)?)?;
        limit(total, limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
        members.try_reserve_exact(old)?;
        members.resize(old, Member::default());
        order.try_reserve_exact(index_count)?;
        if changed {
            written.try_reserve_exact(count)?
        }
        let outcomes = VerificationSummary::reserve(count)?;
        let overhead = add(bytes_for::<Member>(members.capacity())?, bytes_for::<usize>(order.capacity())?)?;
        let actual = add(
            add(fixed, overhead)?,
            add(
                bytes_for::<EntryVerification>(outcomes.entries.capacity())?,
                bytes_for::<WrittenEntry>(written.capacity())?,
            )?,
        )?;
        limit(actual, limits.common.plan_capacity, CreateLimit::PlanCapacity)?;
        self.usage.common.plan.capacity = self.usage.common.plan.capacity.max(actual);

        let attempts = Attempts::with_limits(&options.cancel, limits.common.transaction_attempts, &self.attempts);
        check_source(&self.parent, &self.file, self.stamp, &attempts)?;
        order.extend(0..old);
        let at = |ordinal| self.metadata.view(ordinal).physical_local_header_offset();
        sort_indices(&mut order, |a, b| {
            work(options, &mut self.usage, 1)?;
            Ok(at(a).cmp(&at(b)))
        })?;
        work(options, &mut self.usage, old as u64)?;
        let before = self.usage.layout_read_bytes;
        let work_left = limits.common.plan_work - self.usage.common.plan.work;
        let work_read_max = add(before, work_left)?;
        let (maximum, exhausted) = if work_read_max < limits.layout_read_bytes {
            (work_read_max, ReadLimit::Create(CreateLimit::PlanWork))
        } else {
            (limits.layout_read_bytes, ReadLimit::Rewrite(RewriteLimit::LayoutReadBytes))
        };
        let layout = layout::members(
            &mut Reader {
                file: &self.file,
                attempts: &attempts,
                bytes: &mut self.usage.layout_read_bytes,
                max: maximum,
                exhausted,
            },
            &self.metadata,
            &order,
            &mut members,
            limits.prefix_bytes,
        );
        let layout_work = self.usage.layout_read_bytes - before;
        // The reader reserved the planning budget before every range read.
        self.usage.common.plan.work += layout_work;
        let prefix = layout?;
        check_source(&self.parent, &self.file, self.stamp, &attempts)?;
        if changed {
            // Borrow the plan's names and edit indices while charging the
            // reusable sorting scratch independently.
            let mut name_usage = self.usage;
            let names = names::validate(self, &mut name_usage, &mut order);
            self.usage = name_usage;
            names?;
        }
        let mut feasibility = Feasibility::new(self, prefix, changed);
        let mut verify_total = 0;
        let mut full_packed = 0;
        let edited = self.actions.iter().copied().chain(self.appends.iter().map(|&input| Action::Replace(input)));
        let mut loop_usage = self.usage;
        let result = (|| {
            for (ordinal, action) in edited.enumerate() {
                work(options, &mut loop_usage, 1)?;
                match action {
                    Action::Keep => {
                        let old = self.metadata.view(ordinal);
                        if options.verification == Verification::Full {
                            if !matches!(old.header().method, METHOD_STORED | METHOD_DEFLATE)
                                || old.header().flags & FLAG_ENCRYPTED != 0
                            {
                                return Err(RewriteError::CannotFullyVerify { source_ordinal: ordinal });
                            }
                            verify_total = decoded(verify_total, old.size(), limits.common)?;
                            full_packed = add(full_packed, old.packed_size())?;
                        }
                        if changed {
                            let projection = old.raw_unicode_path().map_or(0, |name| name.len() as u64);
                            feasibility.preserved(raw_entry(&self.metadata, members[ordinal], ordinal), projection)?;
                        }
                    }
                    Action::Replace(input) => {
                        let entry = &self.inputs[input];
                        let size = entry.source.as_ref().map_or(0, |source| source.stamp.len);
                        verify_total = decoded(verify_total, size, limits.common)?;
                        feasibility.new_input(entry, size)?;
                    }
                    Action::Remove => {}
                }
            }
            limit(full_packed, limits.common.verification_read_bytes, CreateLimit::VerificationReadBytes)?;
            feasibility.finish(entries, self.attempts.get(), full_packed)
        })();
        self.usage = loop_usage;
        result?;
        Ok(Prepared { prefix, members, written, outcomes })
    }
}

fn decoded(total: u64, size: u64, limits: CreateLimits) -> Result<u64> {
    limit(size, limits.verification_entry_bytes, CreateLimit::VerificationEntryBytes)?;
    let total = add(total, size)?;
    limit(total, limits.verification_decoded_bytes, CreateLimit::VerificationDecodedBytes)?;
    Ok(total)
}

struct Feasibility<'a> {
    limits: &'a RewriteLimits,
    changed: bool,
    local: u64,
    central: u64,
    comment: u64,
    names: u64,
    comments: u64,
    copy: u64,
    comparison: u64,
    extra: u64,
    extra_projection: u64,
    packed_for_verification: u64,
    patch_bytes: u64,
    decoded: u64,
    packed: u64,
    new_source: u64,
    input_attempts: u64,
    wide: bool,
    exact_offset: bool,
}

impl<'a> Feasibility<'a> {
    fn new(plan: &'a RewritePlan, prefix: u64, changed: bool) -> Self {
        let comment = plan.metadata.raw_comment().len() as u64;
        Self {
            limits: &plan.options.limits,
            changed,
            local: prefix,
            central: 0,
            comment,
            names: 0,
            comments: comment,
            copy: prefix,
            comparison: prefix + comment,
            extra: 0,
            extra_projection: 0,
            packed_for_verification: 0,
            patch_bytes: 0,
            decoded: 0,
            packed: 0,
            new_source: 0,
            input_attempts: 0,
            wide: false,
            exact_offset: true,
        }
    }

    fn preserved(&mut self, entry: PreparedRaw, projection: u64) -> Result<()> {
        let proof = entry.proof(self.local).map_err(rewrite_writer_error)?;
        let central = entry.output_central_len(proof).map_err(rewrite_writer_error)?;
        let local = entry.local.end - entry.local.start;
        let offset_was_wide = entry.central_header.local_header_offset == u32::MAX;
        let old_central = entry.central.end - entry.central.start;
        let max_skipped = if offset_was_wide {
            12
        } else if self.exact_offset && !proof.widened {
            4
        } else {
            4 + 2 * u64::from(entry.local_version < 45)
                + 2 * u64::from(entry.central_header.version_needed < 45)
                + 2
                + 2 * u64::from(entry.zip64_extra.is_some())
        };
        let read = add(local, old_central)?.checked_sub(max_skipped).ok_or(CreateError::Overflow)?;
        self.copy = add(self.copy, read)?;
        self.comparison = add(self.comparison, read)?;
        self.wide |= entry.wide_sizes || proof.offset64_at.is_some() || entry.central_header.disk_start == u16::MAX;
        self.names = add(self.names, u64::from(entry.central_header.name_len))?;
        self.comments = add(self.comments, u64::from(entry.central_header.comment_len))?;
        self.extra = add(self.extra, u64::from(entry.central_header.extra_len) + u64::from(proof.extra_growth))?;
        self.extra_projection = add(self.extra_projection, projection)?;
        self.local = add(self.local, local)?;
        self.central = add(self.central, central)?;
        self.decoded = add(self.decoded, entry.decoded)?;
        self.packed = add(self.packed, entry.packed)?;
        Ok(())
    }

    fn new_input(&mut self, entry: &PlannedEntry, size: u64) -> Result<()> {
        let options = entry.options();
        let limits = self.limits.common;
        let geometry =
            exact_member_geometry(options, size, entry.source.is_none(), self.local).map_err(rewrite_writer_error)?;
        let name = entry.name.len() as u64;
        let comment = entry.comment.len() as u64;
        let central_extra = geometry.central_bytes - 46 - name - comment;
        let payload = if geometry.deflate { 1 } else { size };
        if entry.source.is_some() {
            self.new_source = add(self.new_source, size)?;
            writer_limit(add(self.new_source, 1)?, limits.writer.source_bytes, W::SourceBytes)?;
            writer_limit(size, limits.writer.entry_decoded_bytes, W::EntryDecodedBytes)?;
            // Three identity reads before and after streaming and at least
            // one source EOF probe, plus the positive payload reads.
            self.input_attempts = add(self.input_attempts, 7 + size.div_ceil(layout::BUFFER as u64))?;
        }
        self.patch_bytes = add(self.patch_bytes, geometry.patch_bytes)?;
        self.wide |= geometry.wide;
        self.exact_offset &= !geometry.deflate;
        self.local = add(self.local, add(geometry.local_bytes, payload)?)?;
        self.central = add(self.central, geometry.central_bytes)?;
        self.names = add(self.names, name)?;
        self.comments = add(self.comments, comment)?;
        self.extra = add(self.extra, central_extra)?;
        self.decoded = add(self.decoded, size)?;
        self.packed = add(self.packed, payload)?;
        self.packed_for_verification = add(self.packed_for_verification, payload)?;
        Ok(())
    }

    fn finish(&self, entries: u64, attempts: u64, full_packed: u64) -> Result<()> {
        if !self.changed {
            return Ok(());
        }
        let common = self.limits.common;
        if self.copy > self.limits.raw_copy_bytes {
            return Err(RewriteError::Limit(RewriteLimit::RawCopyBytes));
        }
        if self.comparison > self.limits.raw_copy_bytes {
            return Err(RewriteError::Limit(RewriteLimit::RetainedComparisonBytes));
        }
        let wide =
            self.wide || entries >= u16::MAX as u64 || self.local >= u32::MAX as u64 || self.central >= u32::MAX as u64;
        let extent = add(add(self.local, self.central)?, 22 + self.comment + 76 * u64::from(wide))?;
        writer_limit(common.writer.central_bytes, isize::MAX as u64, W::CentralBytes)?;
        writer_limit(common.writer.metadata_capacity, isize::MAX as u64, W::MetadataCapacity)?;
        writer_limit(self.central, common.writer.central_bytes, W::CentralBytes)?;
        writer_limit(add(self.central, self.comment)?, common.writer.metadata_capacity, W::MetadataCapacity)?;
        writer_limit(extent, common.writer.archive_extent, W::ArchiveExtent)?;
        writer_limit(add(extent, self.patch_bytes)?, common.writer.output_bytes, W::OutputBytes)?;
        let metadata = add(add(self.names, self.comments)?, add(self.extra, self.extra_projection)?)?;
        limit(metadata, common.verification_metadata, CreateLimit::VerificationMetadata)?;
        let tail = extent.min(create::native::verify::DISCOVERY_TAIL_BYTES);
        limit(tail, common.verification_scratch, CreateLimit::VerificationScratch)?;
        let parser_reads = tail * 3;
        if parser_reads > common.directory.fetched_bytes {
            return Err(DirectoryError::Limit(zip_container::LimitKind::FetchedBytes).into());
        }
        let minimum_reads = add(add(self.comparison, add(self.packed_for_verification, full_packed)?)?, parser_reads)?;
        let writer_io = add(self.copy.div_ceil(layout::BUFFER as u64), extent.div_ceil(layout::BUFFER as u64))?;
        writer_limit(add(writer_io, 4)?, common.writer.io_attempts, W::IoAttempts)?;
        let transaction_io = add(add(writer_io, 7)?, self.input_attempts)?;
        limit(add(attempts, transaction_io)?, common.transaction_attempts, CreateLimit::TransactionAttempts)?;
        limit(minimum_reads, common.verification_read_bytes, CreateLimit::VerificationReadBytes)?;
        for (value, max, kind) in [
            (self.central, common.directory.directory_bytes, zip_container::LimitKind::DirectoryBytes),
            (self.names, common.directory.name_bytes, zip_container::LimitKind::NameBytes),
            (self.comments, common.directory.comment_bytes, zip_container::LimitKind::CommentBytes),
            (self.extra_projection, common.directory.extra_bytes, zip_container::LimitKind::ExtraBytes),
        ] {
            if value > max {
                return Err(DirectoryError::Limit(kind).into());
            }
        }
        Ok(())
    }
}
