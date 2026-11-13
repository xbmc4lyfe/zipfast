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

// Private checkpoint. Native publication must supply the held set and its
// stamps; no ordinary discovery profile is broadened to accept split framing.
use super::*;
use crate::crc32::Hasher;
use crate::zip::write::{
    WriteUsage,
    split::{EntryWritten, Location, Usage},
};
use crate::zip::{FLAG_DESCRIPTOR, FLAG_UTF8, HOST_UNIX, METHOD_DEFLATE, METHOD_STORED, S_IFDIR};
use std::io;
use std::os::unix::fs::FileExt;
use zip_container::{CentralHeader, ExtraIter, LimitKind, LocalHeader};

const BUFFER: usize = 64 << 10;
const FIXED: usize = 98;
const SIZE: u64 = u32::MAX as u64;
const COUNT: u64 = u16::MAX as u64;

pub(super) trait HeldVolumes {
    fn len(&self) -> usize;
    fn get(&self, disk: usize) -> Option<(&File, Stamp)>;
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Layout {
    pub volume_bytes: u64,
    pub transport: Usage,
    pub writer: WriteUsage,
    pub central_start: Location,
    pub zip64: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Problem {
    VolumeCount,
    VolumeLength,
    Marker,
    Receipt,
    Placement,
    LocalHeader,
    CentralHeader,
    Extras,
    Descriptor,
    EndGroup,
    Checksum,
}

#[derive(Debug)]
pub(super) enum Error {
    Native(CreateError),
    Invalid { at: Location, kind: Problem },
}
impl From<CreateError> for Error {
    fn from(error: CreateError) -> Self {
        Self::Native(error)
    }
}
type Checked<T> = std::result::Result<T, Error>;

pub(super) struct Scratch {
    input: Vec<u8>,
    output: Vec<u8>,
    fixed: [u8; FIXED],
}
impl Scratch {
    pub(super) fn new(maximum: u64) -> Result<Self> {
        limit((2 * BUFFER + FIXED) as u64, maximum, CreateLimit::VerificationScratch)?;
        let mut input = Vec::new();
        let mut output = Vec::new();
        input.try_reserve_exact(BUFFER)?;
        output.try_reserve_exact(BUFFER)?;
        limit(
            add(add(input.capacity() as u64, output.capacity() as u64)?, FIXED as u64)?,
            maximum,
            CreateLimit::VerificationScratch,
        )?;
        input.resize(BUFFER, 0);
        output.resize(BUFFER, 0);
        Ok(Self { input, output, fixed: [0; FIXED] })
    }
    fn capacity(&self) -> u64 {
        self.input.capacity() as u64 + self.output.capacity() as u64 + FIXED as u64
    }
}

#[derive(Clone, Copy)]
struct Framing {
    method: u16,
    version: u16,
    flags: u16,
    wide_sizes: bool,
    wide_offset: bool,
    wide_disk: bool,
    descriptor: bool,
}
impl Framing {
    fn new(entry: &PlannedEntry, receipt: &EntryWritten) -> Checked<Self> {
        let decoded = entry.payload_source().map_or(0, |s| s.stamp.len);
        let method = if decoded == 0 { Method::Stored } else { entry.method };
        let valid = receipt.method == method
            && receipt.decoded_size == decoded
            && (decoded != 0 || (receipt.packed_size == 0 && receipt.crc32 == 0))
            && (method != Method::Stored || receipt.packed_size == decoded);
        check(valid, receipt.local, Problem::Receipt)?;
        let wide_sizes = decoded != 0 && (method != Method::Stored || decoded >= SIZE);
        let wide_offset = receipt.local.offset >= SIZE;
        let wide_disk = u64::from(receipt.local.disk) >= COUNT;
        Ok(Self {
            method: if method == Method::Stored { METHOD_STORED } else { METHOD_DEFLATE },
            version: if wide_sizes || wide_offset || wide_disk { 45 } else { 20 },
            flags: if entry.utf8 { FLAG_UTF8 } else { 0 } | if decoded != 0 { FLAG_DESCRIPTOR } else { 0 },
            wide_sizes,
            wide_offset,
            wide_disk,
            descriptor: decoded != 0,
        })
    }
    fn extra_len(self, entry: &PlannedEntry, central: bool) -> u64 {
        let wide = 16 * u64::from(self.wide_sizes)
            + 8 * u64::from(central && self.wide_offset)
            + 4 * u64::from(central && self.wide_disk);
        wide + 4 * u64::from(wide != 0) + 9 * u64::from(entry.extended_mtime.is_some())
    }
    fn size32(self, value: u64) -> u32 {
        if self.wide_sizes { u32::MAX } else { value as u32 }
    }
}

pub(super) fn verify(
    held: &impl HeldVolumes,
    members: (&[PlannedEntry], &[EntryWritten]),
    layout: Layout,
    options: &CreateOptions,
    attempts: &Attempts<'_>,
    scratch: &mut Scratch,
    usage: &mut VerificationUsage,
) -> Checked<()> {
    let (entries, receipts) = members;
    attempts.check_cancel()?;
    check(
        held.len() != 0
            && held.len() as u64 == u64::from(layout.transport.disks)
            && held.len() as u64 <= u32::MAX as u64,
        Location::default(),
        Problem::VolumeCount,
    )?;
    check(
        layout.volume_bytes >= 4 && entries.len() == receipts.len() && entries.len() as u64 == layout.writer.entries,
        Location::default(),
        Problem::Receipt,
    )?;
    limit(entries.len() as u64, options.limits.directory_entries(), CreateLimit::VerificationRecords)?;
    limit(scratch.capacity(), options.limits.verification_scratch, CreateLimit::VerificationScratch)?;
    usage.scratch_capacity = scratch.capacity();
    let mut physical = 0;
    for disk in 0..held.len() {
        attempts.check_cancel()?;
        let (file, stamp) = held
            .get(disk)
            .ok_or(Error::Invalid { at: Location { disk: disk as u32, offset: 0 }, kind: Problem::VolumeCount })?;
        if unix::file_stamp(file, attempts)? != stamp {
            return Err(CreateError::StageChanged.into());
        }
        check(
            stamp.len != 0 && stamp.len <= layout.volume_bytes,
            Location { disk: disk as u32, offset: 0 },
            Problem::VolumeLength,
        )?;
        physical = add(physical, stamp.len)?;
    }
    check(
        physical == layout.transport.bytes
            && physical == layout.writer.archive_extent
            && physical == layout.writer.output_bytes,
        Location::default(),
        Problem::VolumeLength,
    )?;
    let mut reader = Reader { held, capacity: layout.volume_bytes, at: Location::default(), options, attempts, usage };
    reader.place(4)?;
    reader.bytes(&mut scratch.fixed[..4], true)?;
    check(scratch.fixed[..4] == [0x50, 0x4b, 7, 8], Location::default(), Problem::Marker)?;
    let mut central_bytes = 0;
    let mut decoded = 0;
    let mut packed = 0;
    let mut wide = false;
    for (ordinal, (entry, receipt)) in entries.iter().zip(receipts).enumerate() {
        reader.work(1)?;
        check(receipt.ordinal == ordinal as u64, reader.at, Problem::Receipt)?;
        let framing = Framing::new(entry, receipt)?;
        wide |= framing.version == 45;
        reader.local(entry, receipt, framing, scratch)?;
        central_bytes = add(
            central_bytes,
            46 + entry.name.len() as u64 + entry.comment.len() as u64 + framing.extra_len(entry, true),
        )?;
        decoded = add(decoded, receipt.decoded_size)?;
        packed = add(packed, receipt.packed_size)?;
    }
    check(
        central_bytes == layout.writer.central_bytes
            && decoded == layout.writer.decoded_bytes
            && packed == layout.writer.packed_bytes,
        reader.at,
        Problem::Receipt,
    )?;
    directory_limit(central_bytes, options.limits.directory.directory_bytes, LimitKind::DirectoryBytes)?;
    wide |= entries.len() as u64 >= COUNT || central_bytes >= SIZE;
    let mut start = None;
    let mut current_disk = reader.at.disk;
    let mut on_disk = 0;
    let mut paired = false;
    for (ordinal, (entry, receipt)) in entries.iter().zip(receipts).enumerate() {
        let framing = Framing::new(entry, receipt)?;
        let len = 46 + entry.name.len() as u64 + entry.comment.len() as u64 + framing.extra_len(entry, true);
        let last = ordinal + 1 == entries.len();
        let placement = loop {
            let combined = add(len, end_len(wide, options.archive_comment.len())?)?;
            paired = last && combined <= reader.capacity;
            let placement = reader.preview(if paired { combined } else { len })?;
            if !wide && (u64::from(placement.disk) >= COUNT || placement.offset >= SIZE) {
                wide = true;
                continue;
            }
            reader.place(if paired { combined } else { len })?;
            break placement;
        };
        if placement.disk != current_disk {
            current_disk = placement.disk;
            on_disk = 0
        }
        on_disk = add(on_disk, 1)?;
        start.get_or_insert(placement);
        reader.central(entry, receipt, framing, scratch)?;
        reader.usage.directory.directory_bytes = add(reader.usage.directory.directory_bytes, len)?;
        reader.usage.directory.owned.entries += 1;
        reader.usage.entries = add(reader.usage.entries, 1)?;
    }
    let end = if paired {
        reader.at
    } else {
        let mut at = reader.preview(end_len(wide, options.archive_comment.len())?)?;
        if u64::from(at.disk) >= COUNT || at.offset >= SIZE {
            wide = true;
            at = reader.preview(end_len(wide, options.archive_comment.len())?)?;
        }
        reader.place(end_len(wide, options.archive_comment.len())?)?;
        at
    };
    let central = *start.get_or_insert(end);
    check(central == layout.central_start && wide == layout.zip64, end, Problem::EndGroup)?;
    let on_disk = if current_disk == end.disk { on_disk } else { 0 };
    reader.end(
        EndExpectation { at: end, central, entries: entries.len() as u64, on_disk, size: central_bytes, wide },
        scratch,
    )?;
    check(
        reader.at.disk as usize + 1 == held.len() && reader.at.offset == reader.stamp()?.len,
        reader.at,
        Problem::VolumeLength,
    )?;
    for disk in 0..held.len() {
        let (file, stamp) = held.get(disk).ok_or(Error::Invalid { at: reader.at, kind: Problem::VolumeCount })?;
        if unix::file_stamp(file, attempts)? != stamp {
            return Err(CreateError::StageChanged.into());
        }
    }
    Ok(())
}

struct Reader<'a, 'b, V> {
    held: &'a V,
    capacity: u64,
    at: Location,
    options: &'a CreateOptions,
    attempts: &'a Attempts<'b>,
    usage: &'a mut VerificationUsage,
}
impl<V: HeldVolumes> Reader<'_, '_, V> {
    fn stamp(&self) -> Checked<Stamp> {
        self.held
            .get(self.at.disk as usize)
            .map(|(_, stamp)| stamp)
            .ok_or(Error::Invalid { at: self.at, kind: Problem::VolumeCount })
    }
    fn preview(&self, len: u64) -> Checked<Location> {
        check(len <= self.capacity && self.at.offset <= self.capacity, self.at, Problem::Placement)?;
        if len > self.capacity - self.at.offset {
            Ok(Location { disk: self.at.disk.checked_add(1).ok_or(CreateError::Overflow)?, offset: 0 })
        } else {
            Ok(self.at)
        }
    }
    fn next(&mut self) -> Checked<()> {
        check(self.at.offset == self.stamp()?.len, self.at, Problem::Placement)?;
        self.at = Location { disk: self.at.disk.checked_add(1).ok_or(CreateError::Overflow)?, offset: 0 };
        self.stamp()?;
        Ok(())
    }
    fn place(&mut self, len: u64) -> Checked<Location> {
        let at = self.preview(len)?;
        if at.disk != self.at.disk {
            self.next()?;
        }
        check(add(at.offset, len)? <= self.stamp()?.len, at, Problem::Placement)?;
        Ok(at)
    }
    fn work(&mut self, units: u64) -> Checked<()> {
        self.attempts.check_cancel()?;
        let work = add(self.usage.directory.work_units, units)?;
        directory_limit(work, self.options.limits.directory.work_units, LimitKind::WorkUnits)?;
        self.usage.directory.work_units = work;
        Ok(())
    }
    fn bytes(&mut self, mut bytes: &mut [u8], metadata: bool) -> Checked<()> {
        limit(
            add(self.usage.read_bytes, bytes.len() as u64)?,
            self.options.limits.verification_read_bytes,
            CreateLimit::VerificationReadBytes,
        )?;
        check(add(self.at.offset, bytes.len() as u64)? <= self.stamp()?.len, self.at, Problem::Placement)?;
        while !bytes.is_empty() {
            let mut size =
                bytes.len().min(usize::try_from(self.options.limits.directory.range_bytes).unwrap_or(usize::MAX));
            directory_limit(1, size as u64, LimitKind::RangeBytes)?;
            #[cfg(test)]
            {
                size = size.min(super::tests::verify_read_cap());
            }
            if metadata {
                self.work(size as u64)?;
                directory_limit(
                    add(self.usage.directory.fetched_bytes, size as u64)?,
                    self.options.limits.directory.fetched_bytes,
                    LimitKind::FetchedBytes,
                )?;
            }
            let (file, _) = self
                .held
                .get(self.at.disk as usize)
                .ok_or(Error::Invalid { at: self.at, kind: Problem::VolumeCount })?;
            let count = self.attempts.run(|| {
                #[cfg(test)]
                super::tests::event_io(super::tests::Event::VerifyRead, None)?;
                file.read_at(&mut bytes[..size], self.at.offset)
            })?;
            if count == 0 {
                return Err(CreateError::from(io::Error::from(io::ErrorKind::UnexpectedEof)).into());
            }
            self.usage.read_bytes = add(self.usage.read_bytes, count as u64)?;
            if metadata {
                self.usage.directory.fetched_bytes = add(self.usage.directory.fetched_bytes, count as u64)?;
            }
            self.at.offset = add(self.at.offset, count as u64)?;
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
    fn variable(&mut self, expected: &[u8], scratch: &mut [u8], kind: Problem) -> Checked<()> {
        let total = add(self.usage.metadata_bytes, expected.len() as u64)?;
        limit(total, self.options.limits.verification_metadata, CreateLimit::VerificationMetadata)?;
        for part in expected.chunks(scratch.len()) {
            self.bytes(&mut scratch[..part.len()], true)?;
            check(&scratch[..part.len()] == part, self.at, kind)?;
        }
        self.usage.metadata_bytes = total;
        Ok(())
    }
    fn extras(
        &mut self,
        entry: &PlannedEntry,
        receipt: &EntryWritten,
        framing: Framing,
        central: bool,
        scratch: &mut Scratch,
    ) -> Checked<()> {
        let len = framing.extra_len(entry, central) as usize;
        let total = add(self.usage.metadata_bytes, len as u64)?;
        limit(total, self.options.limits.verification_metadata, CreateLimit::VerificationMetadata)?;
        let at = self.at;
        self.bytes(&mut scratch.fixed[..len], true)?;
        let mut fields = ExtraIter::new(&scratch.fixed[..len], at.offset)
            .map_err(|_| Error::Invalid { at, kind: Problem::Extras })?;
        let offset = central && framing.wide_offset;
        let disk = central && framing.wide_disk;
        if framing.wide_sizes || offset || disk {
            let field = fields
                .next()
                .transpose()
                .map_err(|_| Error::Invalid { at, kind: Problem::Extras })?
                .ok_or(Error::Invalid { at, kind: Problem::Extras })?;
            check(field.id == 1, at, Problem::Extras)?;
            let mut body = field.body;
            if framing.wide_sizes {
                qword(&mut body, if central { receipt.decoded_size } else { 0 }, at)?;
                qword(&mut body, if central { receipt.packed_size } else { 0 }, at)?;
            }
            if offset {
                qword(&mut body, receipt.local.offset, at)?;
            }
            if disk {
                dword(&mut body, receipt.local.disk, at)?;
            }
            check(body.is_empty(), at, Problem::Extras)?;
        }
        if let Some(mtime) = entry.extended_mtime {
            let field = fields
                .next()
                .transpose()
                .map_err(|_| Error::Invalid { at, kind: Problem::Extras })?
                .ok_or(Error::Invalid { at, kind: Problem::Extras })?;
            check(
                field.id == 0x5455
                    && field.body.len() == 5
                    && field.body[0] == 1
                    && field.body[1..] == mtime.to_le_bytes(),
                at,
                Problem::Extras,
            )?;
        }
        check(fields.next().is_none(), at, Problem::Extras)?;
        self.usage.metadata_bytes = total;
        Ok(())
    }
    fn local(
        &mut self,
        entry: &PlannedEntry,
        receipt: &EntryWritten,
        f: Framing,
        scratch: &mut Scratch,
    ) -> Checked<()> {
        self.work(1)?;
        let at = self.place(30 + entry.name.len() as u64 + f.extra_len(entry, false))?;
        check(at == receipt.local, at, Problem::Receipt)?;
        self.bytes(&mut scratch.fixed[..30], true)?;
        let header =
            LocalHeader::parse(&scratch.fixed[..30]).map_err(|_| Error::Invalid { at, kind: Problem::LocalHeader })?;
        check(
            header.version_needed == f.version
                && header.flags == f.flags
                && header.method == f.method
                && (header.mod_time, header.mod_date) == entry.modified.wire_fields()
                && header.crc32 == 0
                && header.packed_size == f.size32(0)
                && header.unpacked_size == f.size32(0)
                && header.name_len as usize == entry.name.len()
                && u64::from(header.extra_len) == f.extra_len(entry, false),
            at,
            Problem::LocalHeader,
        )?;
        self.variable(&entry.name, &mut scratch.input, Problem::LocalHeader)?;
        self.extras(entry, receipt, f, false, scratch)?;
        if entry.payload_source().is_some() {
            let payload = verify::Payload {
                method: f.method,
                packed_size: receipt.packed_size,
                decoded_size: receipt.decoded_size,
                crc32: receipt.crc32,
            };
            let (decoded, crc) =
                verify::pump_payload(self, payload, receipt.packed_size, &mut scratch.input, &mut scratch.output)?;
            check(decoded == receipt.decoded_size && crc == receipt.crc32, self.at, Problem::Checksum)?;
            self.usage.payloads = add(self.usage.payloads, 1)?;
        }
        if f.descriptor {
            let len = if f.wide_sizes { 24 } else { 16 };
            self.place(len)?;
            let at = self.at;
            self.bytes(&mut scratch.fixed[..len as usize], true)?;
            check(
                crate::zip::descriptor_matches(
                    &scratch.fixed[..len as usize],
                    f.wide_sizes,
                    true,
                    receipt.crc32,
                    (receipt.packed_size, receipt.decoded_size),
                ),
                at,
                Problem::Descriptor,
            )?;
        }
        Ok(())
    }
    fn central(
        &mut self,
        entry: &PlannedEntry,
        receipt: &EntryWritten,
        f: Framing,
        scratch: &mut Scratch,
    ) -> Checked<()> {
        self.work(1)?;
        let at = self.at;
        self.bytes(&mut scratch.fixed[..46], true)?;
        let header = CentralHeader::parse(&scratch.fixed[..46])
            .map_err(|_| Error::Invalid { at, kind: Problem::CentralHeader })?;
        let (kind, dos) = if entry.payload_source().is_some() { (0o100000, 0) } else { (S_IFDIR, 0x10) };
        check(
            header.version_made_by == (u16::from(HOST_UNIX) << 8 | f.version)
                && header.version_needed == f.version
                && header.flags == f.flags
                && header.method == f.method
                && (header.mod_time, header.mod_date) == entry.modified.wire_fields()
                && header.crc32 == receipt.crc32
                && header.packed_size == f.size32(receipt.packed_size)
                && header.unpacked_size == f.size32(receipt.decoded_size)
                && header.name_len as usize == entry.name.len()
                && u64::from(header.extra_len) == f.extra_len(entry, true)
                && header.comment_len as usize == entry.comment.len()
                && header.disk_start == if f.wide_disk { u16::MAX } else { receipt.local.disk as u16 }
                && header.local_header_offset == if f.wide_offset { u32::MAX } else { receipt.local.offset as u32 }
                && header.internal_attributes == 0
                && header.external_attributes == ((kind | u32::from(entry.permissions.bits())) << 16 | dos),
            at,
            Problem::CentralHeader,
        )?;
        let names = add(self.usage.directory.owned.name_bytes as u64, entry.name.len() as u64)?;
        let comments = add(self.usage.directory.owned.comment_bytes as u64, entry.comment.len() as u64)?;
        directory_limit(names, self.options.limits.directory.name_bytes, LimitKind::NameBytes)?;
        directory_limit(comments, self.options.limits.directory.comment_bytes, LimitKind::CommentBytes)?;
        self.variable(&entry.name, &mut scratch.input, Problem::CentralHeader)?;
        self.extras(entry, receipt, f, true, scratch)?;
        self.variable(&entry.comment, &mut scratch.input, Problem::CentralHeader)?;
        self.usage.directory.owned.name_bytes = usize::try_from(names).map_err(|_| CreateError::Overflow)?;
        self.usage.directory.owned.comment_bytes = usize::try_from(comments).map_err(|_| CreateError::Overflow)?;
        Ok(())
    }
    fn end(&mut self, expected: EndExpectation, scratch: &mut Scratch) -> Checked<()> {
        self.work(1)?;
        let len = if expected.wide { 98 } else { 22 };
        self.bytes(&mut scratch.fixed[..len], true)?;
        check_end(&scratch.fixed[..len], expected, self.options.archive_comment.len())?;
        let comments = add(self.usage.directory.owned.comment_bytes as u64, self.options.archive_comment.len() as u64)?;
        directory_limit(comments, self.options.limits.directory.comment_bytes, LimitKind::CommentBytes)?;
        self.variable(&self.options.archive_comment, &mut scratch.input, Problem::EndGroup)?;
        self.usage.directory.owned.comment_bytes = usize::try_from(comments).map_err(|_| CreateError::Overflow)?;
        Ok(())
    }
}

impl<V: HeldVolumes> verify::PayloadInput for Reader<'_, '_, V> {
    fn read_chunk(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        while !bytes.is_empty() {
            if self.at.offset == self.capacity {
                self.next().map_err(native_payload_error)?;
            }
            // Bound in u64 first. The result is at most bytes.len(), so the
            // final conversion fits usize even when capacity exceeds 4 GiB.
            let size = (self.capacity - self.at.offset).min(bytes.len() as u64) as usize;
            self.bytes(&mut bytes[..size], false).map_err(native_payload_error)?;
            bytes = &mut bytes[size..];
        }
        Ok(())
    }
    fn step(&mut self) -> Result<()> {
        self.attempts.charge()
    }
    fn decoded(&mut self, crc: &mut Hasher, member: &mut u64, receipt: verify::Payload, bytes: &[u8]) -> Result<()> {
        *member = add(*member, bytes.len() as u64)?;
        let aggregate = add(self.usage.decoded_bytes, bytes.len() as u64)?;
        limit(*member, self.options.limits.verification_entry_bytes, CreateLimit::VerificationEntryBytes)?;
        limit(aggregate, self.options.limits.verification_decoded_bytes, CreateLimit::VerificationDecodedBytes)?;
        if *member > receipt.decoded_size {
            return Err(CreateError::Verification("payload exceeds the declared decoded length"));
        }
        self.usage.decoded_bytes = aggregate;
        crc.update(bytes);
        Ok(())
    }
}
fn native_payload_error(error: Error) -> CreateError {
    match error {
        Error::Native(error) => error,
        Error::Invalid { .. } => CreateError::Verification("split payload crosses an invalid physical boundary"),
    }
}

#[derive(Clone, Copy)]
pub(super) struct EndExpectation {
    pub at: Location,
    pub central: Location,
    pub entries: u64,
    pub on_disk: u64,
    pub size: u64,
    pub wide: bool,
}
pub(super) fn check_end(bytes: &[u8], e: EndExpectation, comment: usize) -> Checked<()> {
    check(bytes.len() == if e.wide { 98 } else { 22 }, e.at, Problem::EndGroup)?;
    let classic = if e.wide {
        check(
            u32le(bytes, 0) == 0x06064b50
                && u64le(bytes, 4) == 44
                && u16le(bytes, 12) == 0x032d
                && u16le(bytes, 14) == 45
                && u32le(bytes, 16) == e.at.disk
                && u32le(bytes, 20) == e.central.disk
                && u64le(bytes, 24) == e.on_disk
                && u64le(bytes, 32) == e.entries
                && u64le(bytes, 40) == e.size
                && u64le(bytes, 48) == e.central.offset
                && u32le(bytes, 56) == 0x07064b50
                && u32le(bytes, 60) == e.at.disk
                && u64le(bytes, 64) == e.at.offset
                && u64::from(u32le(bytes, 72)) == u64::from(e.at.disk) + 1,
            e.at,
            Problem::EndGroup,
        )?;
        &bytes[76..]
    } else {
        bytes
    };
    check(
        comment <= u16::MAX as usize
            && u32le(classic, 0) == 0x06054b50
            && u64::from(u16le(classic, 4)) == u64::from(e.at.disk).min(COUNT)
            && u64::from(u16le(classic, 6)) == u64::from(e.central.disk).min(COUNT)
            && u64::from(u16le(classic, 8)) == e.on_disk.min(COUNT)
            && u64::from(u16le(classic, 10)) == e.entries.min(COUNT)
            && u64::from(u32le(classic, 12)) == e.size.min(SIZE)
            && u64::from(u32le(classic, 16)) == e.central.offset.min(SIZE)
            && u16le(classic, 20) as usize == comment,
        e.at,
        Problem::EndGroup,
    )
}
fn end_len(wide: bool, comment: usize) -> Result<u64> {
    add(if wide { 98 } else { 22 }, comment as u64)
}
fn check(valid: bool, at: Location, kind: Problem) -> Checked<()> {
    if valid { Ok(()) } else { Err(Error::Invalid { at, kind }) }
}
fn directory_limit(value: u64, maximum: u64, kind: LimitKind) -> Result<()> {
    if value > maximum { Err(CreateError::Directory(zip_container::DirectoryError::Limit(kind))) } else { Ok(()) }
}
fn qword(bytes: &mut &[u8], value: u64, at: Location) -> Checked<()> {
    let (field, rest) = bytes.split_at_checked(8).ok_or(Error::Invalid { at, kind: Problem::Extras })?;
    check(field == value.to_le_bytes(), at, Problem::Extras)?;
    *bytes = rest;
    Ok(())
}
fn dword(bytes: &mut &[u8], value: u32, at: Location) -> Checked<()> {
    let (field, rest) = bytes.split_at_checked(4).ok_or(Error::Invalid { at, kind: Problem::Extras })?;
    check(field == value.to_le_bytes(), at, Problem::Extras)?;
    *bytes = rest;
    Ok(())
}
fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod geometry_tests {
    use super::*;
    use crate::zip::write::{DosDateTime, Permissions};
    use std::os::unix::fs::FileExt;

    fn planned(root: &Path) -> CreatePlan {
        let source = root.join("source");
        std::fs::write(&source, b"x").unwrap();
        let mut plan = CreatePlan::new(&root.join("out.zip"), CreateOptions::default()).unwrap();
        plan.add_file(
            &source,
            EntryOptions {
                name: EntryName::Raw(b"x"),
                method: Method::Stored,
                modified: DosDateTime::default(),
                extended_mtime: Some(1234),
                permissions: Permissions::new(0o640).unwrap(),
                comment: b"",
            },
            None,
        )
        .unwrap();
        plan
    }

    #[test]
    fn split_verifier_promotes_local_sizes_central_offsets_and_disks_independently() {
        let root = tempfile::tempdir().unwrap();
        let mut plan = planned(root.path());
        let entry = &mut plan.entries[0];
        for (size, offset, disk, want_sizes, want_offset, want_disk, extra) in [
            (4294967294, 4294967294, 65534, false, false, false, 9),
            (4294967295, 4, 0, true, false, false, 29),
            (1, 4294967295, 0, false, true, false, 21),
            (1, 4, 65535, false, false, true, 17),
            (4294967296, 4294967296, 65536, true, true, true, 41),
        ] {
            entry.source.as_mut().unwrap().stamp.len = size;
            let receipt = EntryWritten {
                ordinal: 0,
                method: Method::Stored,
                crc32: 1,
                decoded_size: size,
                packed_size: size,
                local: Location { disk, offset },
            };
            let framing = Framing::new(entry, &receipt).unwrap();
            assert_eq!(
                (framing.wide_sizes, framing.wide_offset, framing.wide_disk),
                (want_sizes, want_offset, want_disk)
            );
            assert_eq!(framing.extra_len(entry, true), extra);
            assert_eq!(framing.extra_len(entry, false), if want_sizes { 29 } else { 9 });
        }
    }

    #[test]
    fn split_verifier_parses_disk_offset_and_size_extras_without_width_coupling() {
        struct One(File, Stamp);
        impl HeldVolumes for One {
            fn len(&self) -> usize {
                1
            }
            fn get(&self, disk: usize) -> Option<(&File, Stamp)> {
                (disk == 0).then_some((&self.0, self.1))
            }
        }
        let root = tempfile::tempdir().unwrap();
        let mut plan = planned(root.path());
        plan.entries[0].source.as_mut().unwrap().stamp.len = 4294967295;
        let entry = &plan.entries[0];
        let receipt = EntryWritten {
            ordinal: 0,
            method: Method::Stored,
            crc32: 1,
            decoded_size: 4294967295,
            packed_size: 4294967295,
            local: Location { disk: 65535, offset: 4294967295 },
        };
        let framing = Framing::new(entry, &receipt).unwrap();
        // ZIP64: decoded, packed, local offset, disk; then UT mtime.
        let bytes = [
            1, 0, 28, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0,
            0, 255, 255, 0, 0, 0x55, 0x54, 5, 0, 1, 0xd2, 4, 0, 0,
        ];
        for mutation in [None, Some(2), Some(4), Some(12), Some(20), Some(28), Some(32), Some(36), Some(37)] {
            let mut data = bytes;
            if let Some(index) = mutation {
                data[index] ^= 1
            }
            let file = tempfile::tempfile().unwrap();
            file.write_all_at(&data, 0).unwrap();
            let attempts = Attempts::new(&plan.options, &plan.attempts);
            let stamp = unix::file_stamp(&file, &attempts).unwrap();
            let held = One(file, stamp);
            let mut usage = VerificationUsage::default();
            let mut scratch = Scratch::new(1 << 20).unwrap();
            let mut reader = Reader {
                held: &held,
                capacity: 256,
                at: Location::default(),
                options: &plan.options,
                attempts: &attempts,
                usage: &mut usage,
            };
            assert_eq!(reader.extras(entry, &receipt, framing, true, &mut scratch).is_ok(), mutation.is_none());
        }
    }
}
