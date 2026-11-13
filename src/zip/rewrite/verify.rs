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

use std::{fs::File, ops::Range};

use zip_container::CentralRecord;

use crate::zip::create::native::{
    Attempts, PlannedEntry, add,
    verify::{Payload, Reader as PayloadReader, check_directory},
};
use crate::zip::create::{CreateError, CreateLimit};
use crate::zip::write::raw::{Proof, RawWritten};
use crate::zip::write::{EntryWritten, WriteSummary};
use crate::zip::{EntryMetadata, Metadata};

use super::layout::{self, BUFFER, DirectoryBudget, Member, ReadLimit, Reader};
use super::{
    EntryVerification, Result, RewriteError, RewriteLimit, RewriteOptions, RewriteUsage, Verification,
    VerificationSummary,
};

#[derive(Clone, Copy)]
pub(super) enum WrittenEntry {
    New { input: usize, receipt: EntryWritten },
    Preserved(RawWritten),
}

impl WrittenEntry {
    fn offset(&self) -> u64 {
        match self {
            Self::New { receipt, .. } => receipt.local_offset,
            Self::Preserved(receipt) => receipt.local_offset,
        }
    }
}

pub(super) struct Manifest<'a> {
    pub(super) metadata: &'a Metadata,
    pub(super) members: &'a [Member],
    pub(super) inputs: &'a [PlannedEntry],
    pub(super) actions: &'a [super::native::Action],
    pub(super) appends: &'a [usize],
    pub(super) entries: &'a [WrittenEntry],
    pub(super) prefix: u64,
    pub(super) summary: WriteSummary,
}

impl Manifest<'_> {
    pub(super) fn verify(
        &self,
        old: &File,
        stage: &mut File,
        options: &RewriteOptions,
        attempts: &Attempts<'_>,
        usage: &mut RewriteUsage,
        mut outcomes: VerificationSummary,
    ) -> Result<VerificationSummary> {
        let limits = options.limits.common;
        let stage_stamp = super::native::unix::file_stamp(stage, attempts)?;
        check(stage_stamp.len == self.summary.usage.archive_extent, "wrong staged extent")?;
        let comment = self.metadata.raw_comment();
        let expected_eocd = stage_stamp
            .len
            .checked_sub(22 + comment.len() as u64)
            .ok_or(RewriteError::Verification("staged end record is too short"))?;
        let mut stage_bytes = usage.common.verification.read_bytes;
        let directory = layout::directory(
            &mut Reader {
                file: stage,
                attempts,
                bytes: &mut stage_bytes,
                max: limits.verification_read_bytes,
                exhausted: ReadLimit::Create(CreateLimit::VerificationReadBytes),
            },
            stage_stamp.len,
            Some(expected_eocd),
            false,
            DirectoryBudget {
                core: limits.directory,
                scratch: limits.verification_scratch,
                records: limits.verification_records,
                metadata: limits.verification_metadata,
                record_size: std::mem::size_of::<CentralRecord>(),
            },
            &mut usage.common.verification,
        );
        usage.common.verification.read_bytes = stage_bytes;
        let directory = directory?;
        check_directory(&directory, self.entries.len(), self.summary, comment)?;
        let mut buffers = [[0; BUFFER]; 2];
        {
            let mut comparison = Comparison::new(old, stage, options, attempts, usage, &mut buffers);
            comparison.copy(0..self.prefix, 0)?;
            comparison.copy(self.metadata.comment_range(), directory.comment_range.start)?;
        }

        let mut local_at = self.prefix;
        let mut central_at = directory.directory_range.start;
        let mut wide = false;
        use super::native::Action;
        let expected = self
            .actions
            .iter()
            .copied()
            .chain(self.appends.iter().map(|&input| Action::Replace(input)))
            .enumerate()
            .filter(|(_, action)| !matches!(action, Action::Remove));
        for (ordinal, ((central, entry), (source_ordinal, action))) in
            directory.entries.iter().zip(self.entries).zip(expected).enumerate()
        {
            attempts.check_cancel()?;
            let next = self.entries.get(ordinal + 1).map_or(directory.directory_range.start, WrittenEntry::offset);
            check(
                entry.offset() == local_at
                    && central.source.raw_range().start == central_at
                    && central.resolved.local_header_offset == local_at,
                "staged order or member offset differs",
            )?;
            let verified = match (entry, action) {
                (WrittenEntry::New { input, receipt }, Action::Replace(expected)) if *input == expected => {
                    check(receipt.ordinal == ordinal as u64, "new receipt has the wrong ordinal")?;
                    let mut reader = PayloadReader::new(stage, limits, attempts, &mut usage.common.verification);
                    wide |= reader.check_new(central, &self.inputs[*input], receipt, next, &mut buffers[0])?;
                    EntryVerification::NewVerified
                }
                (WrittenEntry::Preserved(raw), Action::Keep) => {
                    check(
                        raw.ordinal == ordinal as u64 && raw.source_ordinal == source_ordinal,
                        "retained receipt has the wrong ordinal",
                    )?;
                    let source = self.metadata.view(raw.source_ordinal);
                    let member = self.members[raw.source_ordinal];
                    let mut comparison = Comparison::new(old, stage, options, attempts, usage, &mut buffers);
                    wide |= verify_retained(&mut comparison, source, member, central, *raw, next)?;
                    if member.directory {
                        EntryVerification::RetainedDirectoryVerified
                    } else if options.verification == Verification::Full {
                        let at = add(local_at, member.payload_at - member.local_at)?;
                        let mut reader = PayloadReader::new(stage, limits, attempts, &mut usage.common.verification);
                        reader.check_payload(at, declared_payload(source), &mut buffers[0])?;
                        EntryVerification::RetainedPayloadVerified
                    } else {
                        EntryVerification::PreservedStructurally
                    }
                }
                _ => return Err(RewriteError::Verification("entry receipt disagrees with the edit plan")),
            };
            outcomes.record(verified, usage);
            usage.common.verification.entries += 1;
            local_at = next;
            central_at = central.source.raw_range().end;
        }
        let declaration = directory.declaration;
        let wide = wide
            || declaration.entries >= u16::MAX as u64
            || declaration.offset >= u32::MAX as u64
            || declaration.size >= u32::MAX as u64;
        check(
            outcomes.entries.len() == self.entries.len()
                && local_at == directory.directory_range.start
                && central_at == directory.directory_range.end
                && self.summary.zip64 == wide,
            "staged ZIP64 end policy or final boundary differs",
        )?;
        if super::native::unix::file_stamp(stage, attempts)? != stage_stamp {
            return Err(CreateError::StageChanged.into());
        }
        Ok(outcomes)
    }
}

pub(super) fn declared_payload(source: EntryMetadata<'_>) -> Payload {
    Payload {
        method: source.header().method,
        packed_size: source.packed_size(),
        decoded_size: source.size(),
        crc32: source.raw_crc32(),
    }
}

impl VerificationSummary {
    pub(super) fn reserve(count: usize) -> Result<Self> {
        let mut entries = Vec::new();
        entries.try_reserve_exact(count)?;
        Ok(Self { entries, ..Self::default() })
    }

    pub(super) fn record(&mut self, result: EntryVerification, usage: &mut RewriteUsage) {
        match result {
            EntryVerification::NewVerified => self.new_verified += 1,
            EntryVerification::RetainedPayloadVerified => {
                self.retained_payload_verified += 1;
                usage.retained_payload_verified += 1;
            }
            EntryVerification::RetainedDirectoryVerified => self.retained_directories_verified += 1,
            EntryVerification::PreservedStructurally => {
                self.retained_structural_only += 1;
                usage.retained_structural_only += 1;
            }
        }
        self.entries.push(result);
    }
}

fn check(condition: bool, reason: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(RewriteError::Verification(reason)) }
}

struct Comparison<'a, 'b> {
    source: Reader<'a, 'b, 'a>,
    stage: Reader<'a, 'b, 'a>,
    buffers: &'a mut [[u8; BUFFER]; 2],
}

impl<'a, 'b> Comparison<'a, 'b> {
    fn new(
        source: &'a File,
        stage: &'a File,
        options: &RewriteOptions,
        attempts: &'a Attempts<'b>,
        usage: &'a mut RewriteUsage,
        buffers: &'a mut [[u8; BUFFER]; 2],
    ) -> Self {
        Self {
            source: Reader {
                file: source,
                attempts,
                bytes: &mut usage.retained_comparison_bytes,
                max: options.limits.raw_copy_bytes,
                exhausted: ReadLimit::Rewrite(RewriteLimit::RetainedComparisonBytes),
            },
            stage: Reader {
                file: stage,
                attempts,
                bytes: &mut usage.common.verification.read_bytes,
                max: options.limits.common.verification_read_bytes,
                exhausted: ReadLimit::Create(CreateLimit::VerificationReadBytes),
            },
            buffers,
        }
    }

    fn copy(&mut self, range: Range<u64>, mut target: u64) -> Result<()> {
        let mut at = range.start;
        let [expected, actual] = self.buffers;
        while at < range.end {
            let size = (range.end - at).min(BUFFER as u64) as usize;
            self.source.read(at, &mut expected[..size])?;
            self.stage.read(target, &mut actual[..size])?;
            check(expected[..size] == actual[..size], "retained bytes differ")?;
            at += size as u64;
            target = add(target, size as u64)?;
        }
        Ok(())
    }

    fn literal(&mut self, at: u64, expected: &[u8]) -> Result<()> {
        let actual = &mut self.buffers[0][..expected.len()];
        self.stage.read(at, actual)?;
        check(actual == expected, "retained patch bytes differ")
    }
}

struct Segments<'a, 'b, 'c> {
    compare: &'a mut Comparison<'b, 'c>,
    source: u64,
    output: u64,
}

impl Segments<'_, '_, '_> {
    fn copy_to(&mut self, at: u64) -> Result<()> {
        let len = at.checked_sub(self.source).ok_or(RewriteError::Verification("unordered patch proof"))?;
        self.compare.copy(self.source..at, self.output)?;
        self.source = at;
        self.output = add(self.output, len)?;
        Ok(())
    }

    fn literal(&mut self, at: u64, replaced: u64, bytes: &[u8]) -> Result<()> {
        self.copy_to(at)?;
        self.compare.literal(self.output, bytes)?;
        self.source = add(at, replaced)?;
        self.output = add(self.output, bytes.len() as u64)?;
        Ok(())
    }
}

fn verify_retained(
    comparison: &mut Comparison<'_, '_>,
    source: EntryMetadata<'_>,
    member: Member,
    central: &CentralRecord,
    receipt: RawWritten,
    boundary: u64,
) -> Result<bool> {
    let old = source.header();
    let old_central = source.source();
    let new_offset = central.resolved.local_header_offset;
    let was_wide = old.local_header_offset == u32::MAX;
    let needs_wide = new_offset >= u64::from(u32::MAX);
    let widen = needs_wide && !was_wide;
    let extra = member.central_zip64;
    let old_extra = old_central.extra_range();
    // Determine the insertion point independently of the writer. Sizes are
    // selected from their sentinel fields, so the offset always comes after
    // their values, regardless of the disk-start representation.
    let size_values = u64::from(old.packed_size == u32::MAX) + u64::from(old.unpacked_size == u32::MAX);
    let offset_at = if was_wide || needs_wide {
        Some(extra.map_or(old_extra.end, |extra| old_extra.start + u64::from(extra.at) + 4 + 8 * size_values))
    } else {
        None
    };
    let growth = if widen { if extra.is_some() { 8 } else { 12 } } else { 0 };
    let proof = Proof { widened: widen, offset64_at: offset_at, extra_growth: growth };
    check(
        receipt.proof == proof
            && receipt.local_offset == new_offset
            && receipt.local_len == member.end - member.local_at
            && receipt.packed == source.packed_size()
            && receipt.decoded == source.size()
            && receipt.method == old.method
            && receipt.crc == old.crc32
            && add(receipt.local_offset, receipt.local_len)? == boundary,
        "retained receipt or patch proof differs",
    )?;

    let mut local = Segments { compare: comparison, source: member.local_at, output: new_offset };
    if widen && member.local_version < 45 {
        local.literal(member.local_at + 4, 2, &45_u16.to_le_bytes())?;
    }
    local.copy_to(member.end)?;
    check(local.output == boundary, "retained local span differs")?;

    let old_raw = old_central.raw_range();
    let new_raw = central.source.raw_range();
    let mut directory = Segments { compare: comparison, source: old_raw.start, output: new_raw.start };
    if widen && old.version_needed < 45 {
        directory.literal(old_raw.start + 6, 2, &45_u16.to_le_bytes())?;
    }
    if widen {
        let len = old.extra_len.checked_add(growth).ok_or(RewriteError::Verification("oversized relocated extra"))?;
        directory.literal(old_raw.start + 30, 2, &len.to_le_bytes())?;
    }
    let offset32 = if was_wide || needs_wide { u32::MAX } else { new_offset as u32 };
    directory.literal(old_raw.start + 42, 4, &offset32.to_le_bytes())?;
    if let Some(at) = offset_at {
        match (widen, extra) {
            (false, _) => directory.literal(at, 8, &new_offset.to_le_bytes())?,
            (true, Some(zip64)) => {
                directory.literal(old_extra.start + u64::from(zip64.at) + 2, 2, &(zip64.size + 8).to_le_bytes())?;
                directory.literal(at, 0, &new_offset.to_le_bytes())?;
            }
            (true, None) => {
                let mut literal = [1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                literal[4..].copy_from_slice(&new_offset.to_le_bytes());
                directory.literal(at, 0, &literal)?;
            }
        }
    }
    directory.copy_to(old_raw.end)?;
    check(directory.output == new_raw.end, "retained central span differs")?;
    Ok(member.wide_sizes || offset_at.is_some() || old.disk_start == u16::MAX)
}
