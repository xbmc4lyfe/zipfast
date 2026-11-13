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

use std::{fs::File, io, mem::size_of, ops::Range, os::unix::fs::FileExt};

use zip_container::{
    AesFields, AesView, CentralHeader, Directory, DirectoryError, DirectoryParser, EndDiscovery, ExtraIter,
    LOCAL_HEADER_LEN, Limits, LocalHeader, Profile, local_layout,
};

use crate::zip::create::native::{Attempts, add};
use crate::zip::create::{CreateError, CreateLimit, VerificationUsage};
use crate::zip::{FLAG_ENCRYPTED, Metadata};

use super::{Result, RewriteError, RewriteLimit};

pub(super) const BUFFER: usize = 64 << 10;
const EOCD_WINDOW: usize = 22 + u16::MAX as usize;
const LOCATOR_LEN: usize = 20;
pub(super) const CLASSIC_SENTINEL: u32 = u32::MAX;
const DESC_SIGNATURE: u32 = 0x0807_4b50;
const DESCRIPTOR: u16 = 8;
// Bit 4 denotes enhanced deflation. Bits 5, 6 and 13 denote patching,
// strong encryption and masked local fields. Reserved flags fail closed.
const ALLOWED_FLAGS: u16 = 0x080f;

pub(super) struct Reader<'a, 'b, 'c> {
    pub(super) file: &'a File,
    pub(super) attempts: &'a Attempts<'b>,
    pub(super) bytes: &'c mut u64,
    pub(super) max: u64,
    pub(super) exhausted: ReadLimit,
}

#[derive(Clone, Copy)]
pub(super) enum ReadLimit {
    Rewrite(RewriteLimit),
    Create(CreateLimit),
    Parser,
}

impl Reader<'_, '_, '_> {
    pub(super) fn read(&mut self, mut at: u64, mut out: &mut [u8]) -> Result<()> {
        let next = add(*self.bytes, out.len() as u64)?;
        if next > self.max {
            return Err(match self.exhausted {
                ReadLimit::Rewrite(kind) => RewriteError::Limit(kind),
                ReadLimit::Create(kind) => CreateError::Limit(kind).into(),
                ReadLimit::Parser => DirectoryError::Limit(zip_container::LimitKind::FetchedBytes).into(),
            });
        }
        while !out.is_empty() {
            let count = self.attempts.run(|| {
                #[cfg(test)]
                if matches!(self.exhausted, ReadLimit::Create(CreateLimit::VerificationReadBytes)) {
                    super::test_event(super::Event::StageVerifyRead, None)?;
                }
                self.file.read_at(out, at)
            })?;
            if count == 0 {
                return Err(CreateError::from(io::Error::from(io::ErrorKind::UnexpectedEof)).into());
            }
            *self.bytes = add(*self.bytes, count as u64)?;
            at = add(at, count as u64)?;
            out = &mut out[count..];
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct DirectoryBudget {
    pub(super) core: Limits,
    pub(super) scratch: u64,
    pub(super) records: u64,
    pub(super) metadata: u64,
    pub(super) record_size: usize,
}

pub(super) fn directory(
    reader: &mut Reader<'_, '_, '_>,
    len: u64,
    expected_eocd: Option<u64>,
    central_ut_only: bool,
    budget: DirectoryBudget,
    usage: &mut VerificationUsage,
) -> Result<Directory> {
    let mut core = budget.core;
    core.entries = core.entries.min(budget.records / budget.record_size as u64);
    core.directory_bytes = core.directory_bytes.min(budget.metadata.saturating_add(core.entries.saturating_mul(46)));
    core.name_bytes = core.name_bytes.min(budget.metadata);
    core.extra_bytes = core.extra_bytes.min(budget.metadata);
    core.comment_bytes = core.comment_bytes.min(budget.metadata);
    let scratch = usize::try_from(budget.scratch).unwrap_or(usize::MAX);
    let mut buffer = [0; BUFFER];
    let mut ordinary = [None, None];
    for (profile, slot) in [Profile::Zipfast, Profile::Zipview].into_iter().zip(&mut ordinary) {
        let baseline_bytes = usage.discovery_bytes;
        let baseline_work = usage.discovery_work;
        let classify = |error| match error {
            DirectoryError::Limit(_) | DirectoryError::Allocation => RewriteError::Directory(error),
            DirectoryError::UnsupportedDisk => RewriteError::UnsupportedLayout("multiple ZIP disks"),
            _ => RewriteError::AmbiguousDirectory { profile },
        };
        let mut discovery = EndDiscovery::new_with_scratch_limit(len, profile, core, scratch).map_err(classify)?;
        let mut observe = |discovery: &EndDiscovery| -> Result<()> {
            let parsed = discovery.usage();
            usage.discovery_bytes = add(baseline_bytes, parsed.fetched_bytes)?;
            usage.discovery_work = add(baseline_work, parsed.work_units)?;
            usage.scratch_capacity = usage.scratch_capacity.max(discovery.buffer_usage().capacity_bytes as u64);
            Ok(())
        };
        loop {
            reader.attempts.check_cancel()?;
            let request = discovery.next_read();
            observe(&discovery)?;
            let Some(range) = request.map_err(classify)? else { break };
            let chunk = parser_chunk(&range, len, &mut buffer)?;
            reader.read(range.start, chunk)?;
            let supplied = discovery.supply(range.start, chunk);
            observe(&discovery)?;
            supplied.map_err(classify)?;
        }
        let located = discovery.finish().map_err(classify)?;
        *slot = Some(crate::zip::create::native::verify::Geometry::from_location(&located));
        let spent = located.usage();
        core.fetched_bytes = core.fetched_bytes.checked_sub(spent.fetched_bytes).ok_or(CreateError::Overflow)?;
        core.work_units = core.work_units.checked_sub(spent.work_units).ok_or(CreateError::Overflow)?;
    }

    let [Some(zipfast), Some(zipview)] = ordinary else { unreachable!("both discovery profiles run") };
    let eocd = expected_eocd.unwrap_or_else(|| zipfast.eocd());
    for (profile, geometry) in [(Profile::Zipfast, &zipfast), (Profile::Zipview, &zipview)] {
        if geometry.eocd() != eocd || geometry != &zipfast || geometry.comment_end() != len {
            return Err(RewriteError::AmbiguousDirectory { profile });
        }
    }

    let alternative =
        expected_eocd.is_none() && has_alternative_end(reader, len, eocd, &mut core, budget, usage, &mut buffer)?;
    let wire_metadata =
        zipfast.metadata_wire_bytes().ok_or(RewriteError::UnsupportedLayout("central declaration is too short"))?;
    core.extra_bytes = core
        .extra_bytes
        .min(budget.metadata.checked_sub(wire_metadata).ok_or(RewriteError::Limit(RewriteLimit::SourceMetadata))?);
    let parser = if central_ut_only {
        DirectoryParser::at_eocd_with_central_ut(len, eocd, core, scratch)
    } else {
        DirectoryParser::at_eocd_with_scratch_limit(len, eocd, core, scratch)
    }
    .map_err(layout_error)?;
    let parsed = read_anchored(reader, len, parser, usage, &mut buffer)?;
    ensure(usage.record_capacity <= budget.records, "central record capacity")?;
    if !zipfast.agrees(&parsed) || (expected_eocd.is_some() && parsed.prefix_shift != 0) {
        return Err(RewriteError::AmbiguousDirectory { profile: Profile::Zipfast });
    }
    envelope(&parsed)?;
    if alternative {
        return Err(RewriteError::AmbiguousDirectory { profile: Profile::Zipfast });
    }
    usage.metadata_bytes = budget_metadata(&parsed)?;
    if usage.metadata_bytes > budget.metadata {
        return Err(RewriteError::Limit(RewriteLimit::SourceMetadata));
    }
    Ok(parsed)
}

fn read_anchored<T>(
    reader: &mut Reader<'_, '_, '_>,
    len: u64,
    mut parser: DirectoryParser<T>,
    usage: &mut VerificationUsage,
    buffer: &mut [u8],
) -> Result<Directory<T>> {
    let mut observe = |parser: &DirectoryParser<T>| {
        usage.directory = parser.usage();
        usage.scratch_capacity = usage.scratch_capacity.max(parser.buffer_usage().capacity_bytes as u64);
    };
    loop {
        reader.attempts.check_cancel()?;
        let request = parser.next_read();
        observe(&parser);
        let Some(range) = request.map_err(layout_error)? else { break };
        let chunk = parser_chunk(&range, len, buffer)?;
        reader.read(range.start, chunk)?;
        let supplied = parser.supply(range.start, chunk);
        observe(&parser);
        supplied.map_err(layout_error)?;
    }
    let parsed = parser.finish().map_err(layout_error)?;
    usage.directory = parsed.usage;
    let capacity =
        (parsed.entries.capacity() as u64).checked_mul(size_of::<T>() as u64).ok_or(CreateError::Overflow)?;
    usage.record_capacity = usage.record_capacity.max(capacity);
    Ok(parsed)
}

// The ordinary profiles can agree on a later valid EOCD even when another
// valid EOCD treats it as part of its comment. Enumerate only complete EOF
// candidates in the standard tail and validate each with the anchored parser.
// Alternatives are dropped before materializing the selected directory.
fn has_alternative_end(
    reader: &mut Reader<'_, '_, '_>,
    len: u64,
    selected: u64,
    core: &mut Limits,
    budget: DirectoryBudget,
    usage: &mut VerificationUsage,
    buffer: &mut [u8],
) -> Result<bool> {
    let size = len.min((EOCD_WINDOW + LOCATOR_LEN) as u64);
    let start = len - size;
    let scan_start = len.saturating_sub(EOCD_WINDOW as u64) - start;
    let mut tail = [0; EOCD_WINDOW + LOCATOR_LEN];
    let tail = &mut tail[..size as usize];
    charge_discovery(core, usage, size, size)?;
    reader.read(start, tail)?;
    for (index, fixed) in tail.windows(22).enumerate().skip(scan_start as usize) {
        if index & 1023 == 0 {
            reader.attempts.check_cancel()?;
        }
        let at = start + index as u64;
        let field16 = |offset| u16::from_le_bytes([fixed[offset], fixed[offset + 1]]);
        if at == selected
            || le32(fixed, 0) != 0x0605_4b50
            || u64::from(field16(20)) != len - at - 22
            || field16(4) != 0
            || field16(6) != 0
        {
            continue;
        }
        let count = u64::from(field16(10));
        let size = u64::from(le32(fixed, 12));
        let offset = u64::from(le32(fixed, 16));
        let wide = field16(8) == u16::MAX
            || count == u16::MAX as u64
            || size == u32::MAX as u64
            || offset == u32::MAX as u64
            || index.checked_sub(LOCATOR_LEN).is_some_and(|i| le32(&tail[i..index], 0) == 0x0706_4b50);
        if !wide
            && (u64::from(field16(8)) != count
                || offset > at
                || size > at - offset
                || (count == 0 && size != 0)
                || size < count * 46)
        {
            continue;
        }
        let mut alternative = VerificationUsage::default();
        let scratch = usize::try_from(budget.scratch).unwrap_or(usize::MAX);
        let parsed = DirectoryParser::validate_at_eocd_with_scratch_limit(len, at, *core, scratch)
            .map_err(layout_error)
            .and_then(|parser| read_anchored(reader, len, parser, &mut alternative, buffer));
        charge_discovery(core, usage, alternative.directory.fetched_bytes, alternative.directory.work_units)?;
        usage.scratch_capacity = usage.scratch_capacity.max(alternative.scratch_capacity);
        usage.record_capacity = usage.record_capacity.max(alternative.record_capacity);
        match parsed {
            Ok(parsed) if envelope(&parsed).is_ok() => {
                if budget_metadata(&parsed)? > budget.metadata {
                    return Err(RewriteError::Limit(RewriteLimit::SourceMetadata));
                }
                return Ok(true);
            }
            Ok(_) | Err(RewriteError::UnsupportedLayout(_)) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn charge_discovery(core: &mut Limits, usage: &mut VerificationUsage, bytes: u64, work: u64) -> Result<()> {
    core.fetched_bytes =
        core.fetched_bytes.checked_sub(bytes).ok_or(DirectoryError::Limit(zip_container::LimitKind::FetchedBytes))?;
    core.work_units =
        core.work_units.checked_sub(work).ok_or(DirectoryError::Limit(zip_container::LimitKind::WorkUnits))?;
    usage.discovery_bytes = add(usage.discovery_bytes, bytes)?;
    usage.discovery_work = add(usage.discovery_work, work)?;
    Ok(())
}

fn parser_chunk<'a>(range: &Range<u64>, len: u64, buffer: &'a mut [u8]) -> Result<&'a mut [u8]> {
    ensure(range.start < range.end && range.end <= len, "directory parser requested invalid range")?;
    Ok(&mut buffer[..(range.end - range.start).min(BUFFER as u64) as usize])
}

fn budget_metadata<T>(directory: &Directory<T>) -> Result<u64> {
    // Actual on-wire names, raw extras and comments plus any retained
    // variable-length projection (currently the selected Unicode-path field).
    let fixed = directory.declaration.entries.checked_mul(46).ok_or(CreateError::Overflow)?;
    let variable = directory.declaration.size.checked_sub(fixed).ok_or(CreateError::Overflow)?;
    Ok(add(
        add(variable, directory.comment_range.end - directory.comment_range.start)?,
        directory.usage.owned.extra_bytes as u64,
    )?)
}

fn envelope<T>(dir: &Directory<T>) -> Result<()> {
    let end = &dir.end_record;
    ensure(
        end.disk == 0
            && end.directory_disk == 0
            && end.source.end == dir.comment_range.start
            && dir.comment_range.end == dir.archive_len
            && dir.comment_range.end - dir.comment_range.start == u64::from(end.comment_len)
            && dir.observed_range == dir.directory_range
            && dir.logical_range == dir.directory_range
            && dir.declaration.entries == dir.entries.len() as u64
            && add(dir.declaration.offset, dir.prefix_shift)? == dir.directory_range.start
            && add(dir.directory_range.start, dir.declaration.size)? == dir.directory_range.end,
        "incomplete or noncontiguous ZIP directory",
    )?;
    match (&dir.zip64_end, &dir.zip64_locator) {
        (None, None) => ensure(
            dir.directory_range.end == end.source.start && end.disk_entries == end.entries,
            "unowned ZIP tail bytes or inconsistent disk count",
        ),
        (Some(wide), Some(locator)) => {
            let classic16 = |n: u16, expected| n == u16::MAX || u64::from(n) == expected;
            let classic32 = |n: u32, expected| n == u32::MAX || u64::from(n) == expected;
            ensure(
                wide.extension.is_empty()
                    && wide.source.start == dir.directory_range.end
                    && wide.source.end == locator.source.start
                    && locator.source.end == end.source.start
                    && wide.disk == 0
                    && wide.directory_disk == 0
                    && locator.disk == 0
                    && locator.total_disks == 1
                    && wide.disk_entries == dir.declaration.entries
                    && classic16(end.disk_entries, wide.disk_entries)
                    && classic16(end.entries, dir.declaration.entries)
                    && classic32(end.size, dir.declaration.size)
                    && classic32(end.offset, dir.declaration.offset)
                    && add(locator.record_offset, dir.prefix_shift)? == wide.source.start,
                "unsupported ZIP64 tail geometry",
            )
        }
        _ => Err(RewriteError::UnsupportedLayout("incomplete ZIP64 tail")),
    }
}

fn layout_error(error: DirectoryError) -> RewriteError {
    match error {
        DirectoryError::Limit(_) | DirectoryError::Allocation => RewriteError::Directory(error),
        DirectoryError::UnsupportedDisk => RewriteError::UnsupportedLayout("multiple ZIP disks"),
        _ => RewriteError::UnsupportedLayout("malformed or unsupported central directory"),
    }
}

pub(super) fn ensure(condition: bool, reason: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(RewriteError::UnsupportedLayout(reason)) }
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Member {
    pub(super) local_at: u64,
    pub(super) end: u64,
    pub(super) payload_at: u64,
    pub(super) local_version: u16,
    pub(super) central_zip64: Option<Zip64Extra>,
    pub(super) wide_sizes: bool,
    pub(super) directory: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Zip64Extra {
    /// Offset within the central extra block, including its TLV header.
    pub(super) at: u16,
    pub(super) size: u16,
}

#[derive(Default)]
struct Extras {
    zip64: Option<Zip64Extra>,
    decoded: Option<u64>,
    packed: Option<u64>,
    offset: Option<u64>,
    disk: Option<u32>,
    aes: Option<AesFields>,
}

fn extras(bytes: &[u8], decoded: bool, packed: bool, offset: bool, disk: bool) -> Result<Extras> {
    let mut result = Extras::default();
    for item in ExtraIter::new(bytes, 0).map_err(|_| RewriteError::UnsupportedLayout("invalid extra range"))? {
        let extra = item.map_err(|_| RewriteError::UnsupportedLayout("malformed extra field"))?;
        match extra.id {
            0x000f | 0x0016 | 0x0017 | 0xa11e | 0xd935 => {
                return Err(RewriteError::UnsupportedLayout("relocation-sensitive member extra"));
            }
            0x0001 => {
                let width =
                    8 * (usize::from(decoded) + usize::from(packed) + usize::from(offset)) + 4 * usize::from(disk);
                ensure(result.zip64.is_none() && width != 0 && extra.body.len() == width, "ambiguous ZIP64 extra")?;
                result.zip64 = Some(Zip64Extra { at: extra.range.start as u16, size: width as u16 });
                let mut values = extra.body.chunks(8);
                let mut u64_field =
                    || values.next().map(|value| u64::from_le_bytes(value.try_into().expect("validated ZIP64 width")));
                result.decoded = if decoded { u64_field() } else { None };
                result.packed = if packed { u64_field() } else { None };
                result.offset = if offset { u64_field() } else { None };
                if disk {
                    result.disk = Some(le32(extra.body, width - 4));
                }
            }
            0x9901 => {
                ensure(result.aes.is_none() && extra.body.len() == 7, "ambiguous AES extra")?;
                result.aes = Some(AesView::parse(extra.body).expect("validated AES width").fields());
            }
            _ => {}
        }
    }
    let required = decoded || packed || offset || disk;
    ensure(!required || result.zip64.is_some(), "missing ZIP64 extra")?;
    Ok(result)
}

pub(super) fn u32_size(value: u32, wide: Option<u64>) -> u64 {
    wide.unwrap_or(u64::from(value))
}

pub(super) fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("validated field extent"))
}

fn descriptor(
    reader: &mut Reader<'_, '_, '_>,
    at: u64,
    end: u64,
    central: CentralHeader,
    sizes: (u64, u64),
    wide: bool,
    recover_signed: bool,
) -> Result<Option<recovery::DescriptorRepair>> {
    let length = end.checked_sub(at).ok_or(RewriteError::UnsupportedLayout("overlapping local records"))?;
    let mut bytes = [0; 24];
    let body = if wide { 20 } else { 12 };
    ensure(length == body || length == body + 4, "descriptor does not end at the next boundary")?;
    reader.read(at, &mut bytes[..length as usize])?;
    let mut matches = 0;
    for signed in [false, true] {
        let prefix = if signed { 4 } else { 0 };
        if length != body + prefix || (signed && le32(&bytes, 0) != DESC_SIGNATURE) {
            continue;
        }
        let at = prefix as usize;
        let packed = if wide {
            u64::from_le_bytes(bytes[at + 4..at + 12].try_into().expect("ZIP64 packed descriptor size"))
        } else {
            u64::from(le32(&bytes, at + 4))
        };
        let decoded = if wide {
            u64::from_le_bytes(bytes[at + 12..at + 20].try_into().expect("ZIP64 decoded descriptor size"))
        } else {
            u64::from(le32(&bytes, at + 8))
        };
        if le32(&bytes, at) == central.crc32 && (packed, decoded) == sizes {
            matches += 1;
        }
    }
    if matches == 1 {
        return Ok(None);
    }
    ensure(
        recover_signed && length == body + 4 && le32(&bytes, 0) == DESC_SIGNATURE,
        "no unique matching data descriptor",
    )?;
    ensure(
        wide || (sizes.0 < u64::from(CLASSIC_SENTINEL) && sizes.1 < u64::from(CLASSIC_SENTINEL)),
        "classic descriptor sizes require ZIP64",
    )?;
    bytes[4..8].copy_from_slice(&central.crc32.to_le_bytes());
    if wide {
        bytes[8..16].copy_from_slice(&sizes.0.to_le_bytes());
        bytes[16..24].copy_from_slice(&sizes.1.to_le_bytes());
    } else {
        bytes[8..12].copy_from_slice(&(sizes.0 as u32).to_le_bytes());
        bytes[12..16].copy_from_slice(&(sizes.1 as u32).to_le_bytes());
    }
    Ok(Some(recovery::DescriptorRepair { offset: at, data: bytes, len: length as u8 }))
}

pub(super) fn member(
    reader: &mut Reader<'_, '_, '_>,
    central: crate::zip::EntryMetadata<'_>,
    end: u64,
    scratch: &mut [u8; BUFFER],
) -> Result<Member> {
    framed_member(reader, central, end, scratch, false).map(|(member, _)| member)
}

fn framed_member(
    reader: &mut Reader<'_, '_, '_>,
    central: crate::zip::EntryMetadata<'_>,
    end: u64,
    scratch: &mut [u8; BUFFER],
    recover_signed: bool,
) -> Result<(Member, Option<recovery::DescriptorRepair>)> {
    let local_at = central.physical_local_header_offset();
    let header = central.header();
    let resolved = central.resolved();
    ensure(resolved.disk_start == 0, "member starts on another ZIP disk")?;
    ensure(header.flags & !ALLOWED_FLAGS == 0, "unsupported ZIP member flags")?;
    let mut fixed = [0; LOCAL_HEADER_LEN];
    ensure(add(local_at, fixed.len() as u64)? <= end, "overlapping local records")?;
    reader.read(local_at, &mut fixed)?;
    let local = LocalHeader::parse(&fixed).map_err(|_| RewriteError::UnsupportedLayout("invalid local header"))?;
    let layout = local_layout(local, local_at, end)
        .map_err(|_| RewriteError::UnsupportedLayout("local header exceeds its boundary"))?;
    ensure(
        local.name_len == header.name_len
            && local.method == header.method
            && local.flags == header.flags
            && local.mod_time == header.mod_time
            && local.mod_date == header.mod_date,
        "local and central metadata disagree",
    )?;
    let name = &mut scratch[..usize::from(local.name_len)];
    reader.read(layout.name_range().start, name)?;
    ensure(name == central.raw_name(), "local and central raw names disagree")?;

    let local_packed = local.packed_size == CLASSIC_SENTINEL;
    let local_decoded = local.unpacked_size == CLASSIC_SENTINEL;
    let local_extra = &mut scratch[..usize::from(local.extra_len)];
    reader.read(layout.extra_range().start, local_extra)?;
    let local_extras = extras(local_extra, local_decoded, local_packed, false, false)?;

    let central_packed = header.packed_size == CLASSIC_SENTINEL;
    let central_decoded = header.unpacked_size == CLASSIC_SENTINEL;
    let wide_offset = header.local_header_offset == CLASSIC_SENTINEL;
    let wide_disk = header.disk_start == u16::MAX;
    let central_extra = &mut scratch[..usize::from(header.extra_len)];
    reader.read(central.source().extra_range().start, central_extra)?;
    let central_extras = extras(central_extra, central_decoded, central_packed, wide_offset, wide_disk)?;
    ensure(
        u32_size(header.packed_size, central_extras.packed) == resolved.packed_size
            && u32_size(header.unpacked_size, central_extras.decoded) == resolved.unpacked_size
            && u32_size(header.local_header_offset, central_extras.offset) == resolved.local_header_offset
            && central_extras.disk.unwrap_or(u32::from(header.disk_start)) == resolved.disk_start,
        "unresolved central ZIP64 values",
    )?;
    let sizes = (resolved.packed_size, resolved.unpacked_size);
    let directory = raw_directory(central);
    if directory {
        ensure(
            sizes == (0, 0) && header.crc32 == 0 && header.method == 0 && header.flags & FLAG_ENCRYPTED == 0,
            "directory entry is not structurally empty",
        )?;
    }
    encryption(header, local_extras.aes, central_extras.aes, sizes.0)?;
    let has_descriptor = header.flags & DESCRIPTOR != 0;
    let local_sizes =
        (u32_size(local.packed_size, local_extras.packed), u32_size(local.unpacked_size, local_extras.decoded));
    let consistent = |local, central| local == central || (has_descriptor && local == 0);
    ensure(
        consistent(u64::from(local.crc32), u64::from(header.crc32))
            && consistent(local_sizes.0, sizes.0)
            && consistent(local_sizes.1, sizes.1),
        "local and central CRC or sizes disagree",
    )?;
    let payload = layout
        .payload_range(sizes.0, end)
        .map_err(|_| RewriteError::UnsupportedLayout("packed data exceeds its boundary"))?;
    let wide_sizes = local_packed || local_decoded || central_packed || central_decoded;
    let repair = if has_descriptor {
        descriptor(reader, payload.end, end, header, sizes, wide_sizes, recover_signed)?
    } else {
        ensure(payload.end == end, "unowned bytes between local records and directory")?;
        None
    };
    Ok((
        Member {
            local_at,
            end,
            payload_at: payload.start,
            local_version: local.version_needed,
            central_zip64: central_extras.zip64,
            wide_sizes,
            directory,
        },
        repair,
    ))
}

pub(super) fn raw_directory(entry: crate::zip::EntryMetadata<'_>) -> bool {
    entry.raw_name().ends_with(b"/") || crate::zip::is_dir("", entry.creator_host(), entry.header().external_attributes)
}

fn encryption(header: CentralHeader, local: Option<AesFields>, central: Option<AesFields>, packed: u64) -> Result<()> {
    let encrypted = header.flags & FLAG_ENCRYPTED != 0;
    if header.method != 99 && local.is_none() && central.is_none() {
        return ensure(!encrypted || packed >= 12, "truncated traditional encryption header");
    }
    let Some(aes) = central else { return Err(RewriteError::UnsupportedLayout("missing AES metadata")) };
    ensure(
        encrypted
            && header.method == 99
            && local == central
            && aes.vendor_id == *b"AE"
            && matches!(aes.vendor_version, 1 | 2)
            && (aes.vendor_version != 2 || header.crc32 == 0)
            && aes.method != 99
            && match aes.strength {
                1 => packed >= 20,
                2 => packed >= 24,
                3 => packed >= 28,
                _ => false,
            },
        "unsupported AES framing",
    )
}

pub(super) fn prefix(reader: &mut Reader<'_, '_, '_>, end: u64, max: u64) -> Result<()> {
    if end > max {
        return Err(RewriteError::Limit(RewriteLimit::PrefixBytes));
    }
    if end >= 8 {
        let mut bytes = [0; LOCAL_HEADER_LEN];
        let len = end.min(LOCAL_HEADER_LEN as u64) as usize;
        reader.read(0, &mut bytes[..len])?;
        match le32(&bytes, 0) {
            0x0806_4b50 if 8 + u64::from(le32(&bytes, 4)) <= end => {
                return Err(RewriteError::UnsupportedLayout("leading archive extra data record"));
            }
            0x0403_4b50 if len == LOCAL_HEADER_LEN => {
                let header = LocalHeader::parse(&bytes).expect("complete local signature and fixed header");
                if let Ok(layout) = local_layout(header, 0, end)
                    && layout.payload_range(u64::from(header.packed_size), end).is_ok()
                {
                    return Err(RewriteError::UnsupportedLayout("leading unreferenced local record"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn members(
    reader: &mut Reader<'_, '_, '_>,
    metadata: &Metadata,
    order: &[usize],
    members: &mut [Member],
    max_prefix: u64,
) -> Result<u64> {
    let central = metadata.directory_range().start;
    let position = |&index: &usize| metadata.view(index).physical_local_header_offset();
    let prefix_end = order.first().map_or(central, position);
    prefix(reader, prefix_end, max_prefix)?;
    let mut scratch = [0; BUFFER];
    for (i, &ordinal) in order.iter().enumerate() {
        reader.attempts.check_cancel()?;
        let next = order.get(i + 1).map_or(central, position);
        members[ordinal] = member(reader, metadata.view(ordinal), next, &mut scratch)?;
    }
    Ok(prefix_end)
}

#[cfg(test)]
mod recovery_tests;

// The central-directed transaction will consume this independently reviewed seam.
#[allow(dead_code)]
pub(in crate::zip) mod recovery;
