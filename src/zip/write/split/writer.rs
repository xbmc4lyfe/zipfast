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

use std::io::{self, Read, Write};
use std::sync::Arc;

use super::{Error, ErrorKind, Limits, Location, Result, Stage, Transport, Usage, VolumeProvider};
use crate::zip::FLAG_DESCRIPTOR;
use crate::zip::write::records::{Member, Record};
use crate::zip::write::{
    BUFFER, EntryOptions, FileInput, InputLength, Limit, Method, Output, Work, WriteError, WriteUsage, WriterOptions,
    add, archive_comment_len, bound, prepare_member, reserve_central,
};

/// Split output limits and ordinary source, metadata and encoding limits.
pub struct Options<'a> {
    /// Capacity of each volume. Every complete record must fit.
    pub volume_bytes: u64,
    /// Maximum number of volumes, including the final volume.
    pub volumes: u32,
    /// Aggregate provider calls and physical write and flush attempts.
    pub transport_attempts: u64,
    /// Existing source, encoding, metadata and logical I/O ceilings.
    pub writer: WriterOptions<'a>,
}

impl Default for Options<'_> {
    fn default() -> Self {
        Self {
            volume_bytes: 64 << 20,
            volumes: 1_000_000,
            transport_attempts: 1 << 32,
            writer: WriterOptions::default(),
        }
    }
}

/// Actual member framing with a disk-relative local header location.
#[derive(Clone, Copy, Debug)]
pub struct EntryWritten {
    pub ordinal: u64,
    pub method: Method,
    pub crc32: u32,
    pub decoded_size: u64,
    pub packed_size: u64,
    pub local: Location,
}

/// Successfully flushed provisional volumes. The provider owns their storage.
pub struct Finished<P> {
    pub provider: P,
    pub usage: Usage,
    pub writer: WriteUsage,
    pub central_start: Location,
    pub zip64: bool,
}

/// Streams a fresh clear ZIP across caller-provided numbered sinks.
///
/// Local and central records, descriptors and the final end group are intact.
/// The final central record shares a volume with the end group when both
/// fit together. A separate intact end group is also supported.
/// Sinks remain provisional until finish succeeds. There is no path publication.
/// Provider errors and failures after admission poison the writer.
pub struct ZipSplitWriter<P: VolumeProvider> {
    transport: Transport<P>,
    work: Work,
    central: Vec<u8>,
    lengths: Vec<usize>,
    comment: Vec<u8>,
    wide: bool,
    failed: Option<Arc<Error>>,
}

impl<P: VolumeProvider> ZipSplitWriter<P> {
    /// Opens the first sink and emits the spanning marker once at disk zero.
    pub fn new(provider: P, options: Options<'_>) -> Result<Self> {
        let writer = options.writer;
        let validate = || -> std::result::Result<Vec<u8>, WriteError> {
            let len = archive_comment_len(&writer)?;
            bound(u64::from(len), writer.limits.metadata_capacity, Limit::MetadataCapacity)?;
            let mut comment = Vec::new();
            comment.try_reserve_exact(usize::from(len)).map_err(WriteError::Allocation)?;
            bound(comment.capacity() as u64, writer.limits.metadata_capacity, Limit::MetadataCapacity)?;
            comment.extend_from_slice(writer.comment);
            Ok(comment)
        };
        let comment = validate().map_err(|cause| {
            Arc::new(Error {
                stage: Stage::Reserve,
                at: Location::default(),
                kind: ErrorKind::Writer(cause),
                usage: Usage::default(),
                writer: WriteUsage::default(),
            })
        })?;
        let end = end_len(false, comment.len());
        let output_limit = writer.limits.archive_extent.min(writer.limits.output_bytes);
        let refusal = if end > options.volume_bytes {
            Some(ErrorKind::RecordTooLarge { requested: end, capacity: options.volume_bytes })
        } else if 4 + end > output_limit {
            Some(ErrorKind::Limit(super::Limit::OutputBytes))
        } else {
            None
        };
        if let Some(kind) = refusal {
            return Err(Arc::new(Error {
                stage: Stage::Reserve,
                at: Location::default(),
                kind,
                usage: Usage::default(),
                writer: WriteUsage::default(),
            }));
        }
        let transport = Transport::new(
            provider,
            Limits {
                disk_bytes: options.volume_bytes,
                disks: options.volumes,
                output_bytes: writer.limits.archive_extent.min(writer.limits.output_bytes),
                attempts: options.transport_attempts,
            },
            writer.cancel.clone(),
        )?;
        let mut result = Self {
            transport,
            work: Work { limits: writer.limits, cancel: writer.cancel, usage: WriteUsage::default() },
            central: Vec::new(),
            lengths: Vec::new(),
            comment,
            wide: false,
            failed: None,
        };
        result.check_tail_size(false, 0)?;
        Ok(result)
    }

    /// Complete-member totals plus all provisional source and output work.
    pub fn usage(&self) -> (Usage, WriteUsage) {
        let mut writer = self.work.usage;
        writer.central_bytes = self.central.len() as u64;
        writer.metadata_capacity = self.central.capacity() as u64
            + self.comment.capacity() as u64
            + (self.lengths.capacity() * std::mem::size_of::<usize>()) as u64;
        writer.output_bytes = self.transport.usage.bytes;
        writer.archive_extent = writer.output_bytes;
        (self.transport.usage, writer)
    }

    /// Admits and streams a regular file. Exact lengths include an EOF probe.
    pub fn add_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        input: &mut R,
        length: InputLength,
    ) -> Result<EntryWritten> {
        let member = self.prepare(options, length, false)?;
        let result = self.write_file(options, member, FileInput { input, length, decoded: 0 });
        self.remember(result)
    }

    /// Admits one clear Stored directory record.
    pub fn add_directory(&mut self, options: EntryOptions<'_>) -> Result<EntryWritten> {
        let member = self.prepare(options, InputLength::Exact(0), true)?;
        let result = (|| {
            self.local(&member, options.name.bytes())?;
            self.complete(options, member, 0, 0, 0)
        })();
        self.remember(result)
    }

    fn prepare(&mut self, options: EntryOptions<'_>, length: InputLength, directory: bool) -> Result<Member> {
        self.active()?;
        let result = (|| -> std::result::Result<Member, WriteError> {
            let mut member = prepare_member(options, length, directory, self.transport.position.offset)?;
            let entries = add(self.work.usage.entries, 1)?;
            bound(entries, self.work.limits.entries, Limit::Entries)?;
            let payload = if directory { 0 } else { self.work.payload_min(length, member.method)? };
            // Local extra width depends only on sizes. Disk/offset width is
            // fixed after choosing the intact local record's destination.
            let placement = self.transport.placement(member.local_len()).map_err(transport_io)?;
            member.relocate(placement.disk, placement.offset);
            let central = add(self.central.len() as u64, member.central_len())?;
            bound(central, self.work.limits.central_bytes, Limit::CentralBytes)?;
            let descriptor = if !directory && length != InputLength::Exact(0) { member.descriptor_len() } else { 0 };
            let wide = self.wide || member.width.is_wide() || entries >= u16::MAX as u64 || central >= u32::MAX as u64;
            let tail = end_len(wide, self.comment.len());
            let minimum = add(add(add(add(member.local_len(), payload)?, descriptor)?, central)?, tail)?;
            self.transport.validate_output(minimum, Stage::Reserve).map_err(transport_io)?;
            self.transport.validate_record(member.central_len()).map_err(transport_io)?;
            self.transport.validate_record(tail).map_err(transport_io)?;
            let index = add(self.lengths.len() as u64, 1)?
                .checked_mul(std::mem::size_of::<usize>() as u64)
                .ok_or(WriteError::Overflow)?;
            let max = self
                .work
                .limits
                .metadata_capacity
                .checked_sub(self.comment.capacity() as u64)
                .and_then(|n| n.checked_sub(index))
                .ok_or(WriteError::Limit(Limit::MetadataCapacity))?;
            reserve_central(&mut self.central, central, max)?;
            self.lengths.try_reserve_exact(1).map_err(WriteError::Allocation)?;
            bound(self.usage().1.metadata_capacity, self.work.limits.metadata_capacity, Limit::MetadataCapacity)?;
            Ok(member)
        })();
        let member = result.map_err(|cause| self.error(Stage::Member, cause))?;
        self.check_tail_size(self.wide || member.width.is_wide(), member.central_len())?;
        Ok(member)
    }

    fn write_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        mut member: Member,
        mut file: FileInput<'_, R>,
    ) -> Result<EntryWritten> {
        let mut input = [0; BUFFER];
        let first = file.read(&mut self.work, &mut input).map_err(|cause| self.error(Stage::Member, cause))?;
        if first == 0 {
            member = prepare_member(options, InputLength::Exact(0), false, member.local_at)
                .map_err(|cause| self.error(Stage::Member, cause))?;
            let at = self.transport.placement(member.local_len()).map_err(|error| self.enrich(error))?;
            member.relocate(at.disk, at.offset);
            self.local(&member, options.name.bytes())?;
            return self.complete(options, member, 0, 0, 0);
        }
        member.flags |= FLAG_DESCRIPTOR;
        self.local(&member, options.name.bytes())?;
        let at = self.transport.usage.bytes;
        let mut output = Output { sink: Payload(&mut self.transport), work: self.work.clone(), position: at };
        output.work.usage.output_bytes = at;
        output.work.usage.archive_extent = at;
        let result = output.write_payload(member.method, &mut file, &mut input, first, None);
        self.work = output.work;
        let (crc, packed) = result.map_err(|cause| self.error(Stage::Member, cause))?;
        let decoded = file.decoded;
        let descriptor = member.descriptor(crc, decoded, packed).map_err(|cause| self.error(Stage::Member, cause))?;
        self.record(&[descriptor.as_bytes()])?;
        self.complete(options, member, crc, decoded, packed)
    }

    fn local(&mut self, member: &Member, name: &[u8]) -> Result<()> {
        self.record(&[member.local().as_bytes(), name, member.local_extra().as_bytes()])?;
        Ok(())
    }

    fn record(&mut self, parts: &[&[u8]]) -> Result<Location> {
        let size = parts
            .iter()
            .try_fold(0u64, |sum, part| add(sum, part.len() as u64))
            .map_err(|cause| self.error(Stage::Reserve, cause))?;
        let result = (|| {
            let mut reserved = self.transport.reserve_record(size)?;
            let at = reserved.location();
            for part in parts {
                reserved.write(part)?;
            }
            Ok(at)
        })();
        result.map_err(|error| self.enrich(error))
    }

    fn complete(
        &mut self,
        options: EntryOptions<'_>,
        member: Member,
        crc: u32,
        decoded: u64,
        packed: u64,
    ) -> Result<EntryWritten> {
        let result = (|| -> std::result::Result<EntryWritten, WriteError> {
            self.work.check_canceled()?;
            let central = member.central(crc, decoded, packed)?;
            let extra = member.central_extra(decoded, packed);
            let length = member.central_len() as usize;
            self.central.extend_from_slice(central.as_bytes());
            self.central.extend_from_slice(options.name.bytes());
            self.central.extend_from_slice(extra.as_bytes());
            self.central.extend_from_slice(options.comment);
            self.lengths.push(length);
            let usage = &mut self.work.usage;
            let ordinal = usage.entries;
            usage.entries += 1;
            usage.decoded_bytes = add(usage.decoded_bytes, decoded)?;
            usage.packed_bytes = add(usage.packed_bytes, packed)?;
            self.wide |= member.width.is_wide();
            Ok(EntryWritten {
                ordinal,
                method: member.method,
                crc32: crc,
                decoded_size: decoded,
                packed_size: packed,
                local: Location { disk: member.local_disk, offset: member.local_at },
            })
        })();
        result.map_err(|cause| self.error(Stage::Member, cause))
    }

    fn check_tail_size(&mut self, wide: bool, central: u64) -> Result<()> {
        let tail = end_len(wide, self.comment.len());
        self.transport.validate_record(central).map_err(|error| self.enrich(error))?;
        self.transport.validate_record(tail).map_err(|error| self.enrich(error))
    }

    fn active(&self) -> Result<()> {
        if let Some(error) = &self.failed {
            return Err(Arc::clone(error));
        }
        Ok(())
    }

    fn enrich(&self, error: Arc<Error>) -> Arc<Error> {
        let mut error = (*error).clone();
        error.writer = self.usage().1;
        Arc::new(error)
    }

    fn error(&self, stage: Stage, cause: WriteError) -> Arc<Error> {
        // A read-only preflight may carry a transport refusal without poisoning it.
        if let WriteError::Io { source, .. } = &cause
            && let Some(error) = source.get_ref().and_then(|error| error.downcast_ref::<Arc<Error>>())
        {
            return self.enrich(Arc::clone(error));
        }
        // Unwrap a transport failure carried through the shared encoder sink.
        if let Some(error) = &self.transport.failed {
            return self.enrich(Arc::clone(error));
        }
        Arc::new(Error {
            stage,
            at: self.transport.position(),
            kind: ErrorKind::Writer(cause),
            usage: self.transport.usage,
            writer: self.usage().1,
        })
    }

    fn remember<T>(&mut self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            self.failed = Some(Arc::clone(error));
        }
        result
    }

    /// Writes each central record and the final intact end group, then flushes.
    pub fn finish(mut self) -> Result<Finished<P>> {
        self.active()?;
        let (central_start, zip64) = self.finish_records()?;
        let writer = self.usage().1;
        let (provider, usage) = self.transport.finish().map_err(|mut error| {
            Arc::make_mut(&mut error).writer = writer;
            error
        })?;
        Ok(Finished { provider, usage, writer, central_start, zip64 })
    }

    fn finish_records(&mut self) -> Result<(Location, bool)> {
        let mut wide =
            self.wide || self.work.usage.entries >= u16::MAX as u64 || self.central.len() as u64 >= u32::MAX as u64;
        let mut start = None;
        let mut at = 0;
        let mut current_disk = self.transport.position.disk;
        let mut on_disk = 0;
        let mut paired = false;
        for index in 0..self.lengths.len() {
            let size = self.lengths[index];
            let last = index + 1 == self.lengths.len();
            let (destination, together) = self.central_placement(size as u64, last, &mut wide)?;
            if destination.disk != current_disk {
                current_disk = destination.disk;
                on_disk = 0;
            }
            let central_start = *start.get_or_insert(destination);
            on_disk += 1;
            let tail = if together {
                paired = true;
                Some(
                    EndGroup {
                        at: Location { disk: destination.disk, offset: destination.offset + size as u64 },
                        central: central_start,
                        entries: self.work.usage.entries,
                        on_disk,
                        size: self.central.len() as u64,
                        wide,
                        comment: &self.comment,
                    }
                    .record()
                    .map_err(|cause| self.error(Stage::Finish, cause))?,
                )
            } else {
                None
            };
            let total =
                size as u64 + tail.as_ref().map_or(0, |tail| tail.as_bytes().len() as u64 + self.comment.len() as u64);
            let result = (|| {
                let mut record = self.transport.reserve_record(total)?;
                record.write(&self.central[at..at + size])?;
                if let Some(tail) = tail.as_ref() {
                    record.write(tail.as_bytes())?;
                    record.write(&self.comment)?;
                }
                Ok(())
            })();
            result.map_err(|error| self.enrich(error))?;
            at += size;
        }
        if !paired {
            let mut at =
                self.transport.placement(end_len(wide, self.comment.len())).map_err(|error| self.enrich(error))?;
            wide |= at.disk >= u16::MAX as u32 || at.offset >= u32::MAX as u64;
            at = self.transport.placement(end_len(wide, self.comment.len())).map_err(|error| self.enrich(error))?;
            let central_start = *start.get_or_insert(at);
            let tail = EndGroup {
                at,
                central: central_start,
                entries: self.work.usage.entries,
                on_disk: if at.disk == current_disk { on_disk } else { 0 },
                size: self.central.len() as u64,
                wide,
                comment: &self.comment,
            }
            .record()
            .map_err(|cause| self.error(Stage::Finish, cause))?;
            let result = (|| {
                let mut record =
                    self.transport.reserve_record(tail.as_bytes().len() as u64 + self.comment.len() as u64)?;
                record.write(tail.as_bytes())?;
                record.write(&self.comment)
            })();
            result.map_err(|error| self.enrich(error))?;
        }
        Ok((start.unwrap(), wide))
    }

    fn central_placement(&mut self, size: u64, last: bool, wide: &mut bool) -> Result<(Location, bool)> {
        let combined =
            add(size, end_len(*wide, self.comment.len())).map_err(|cause| self.error(Stage::Finish, cause))?;
        let paired = last && combined <= self.transport.limits.disk_bytes;
        let at = self.transport.placement(if paired { combined } else { size }).map_err(|error| self.enrich(error))?;
        if !*wide && (at.disk >= u16::MAX as u32 || at.offset >= u32::MAX as u64) {
            *wide = true;
            // Promotion changes the end-group length and can change placement.
            return self.central_placement(size, last, wide);
        }
        Ok((at, paired))
    }
}

struct Payload<'a, P: VolumeProvider>(&'a mut Transport<P>);
impl<P: VolumeProvider> Write for Payload<'_, P> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write_payload(bytes).map_err(io::Error::other)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush().map_err(io::Error::other)
    }
}
fn transport_io(error: Arc<Error>) -> WriteError {
    WriteError::io(crate::zip::write::IoStage::LocalHeader, io::Error::other(error))
}
fn end_len(wide: bool, comment: usize) -> u64 {
    22 + 76 * u64::from(wide) + comment as u64
}

struct EndGroup<'a> {
    at: Location,
    central: Location,
    entries: u64,
    on_disk: u64,
    size: u64,
    wide: bool,
    comment: &'a [u8],
}
impl EndGroup<'_> {
    fn record(&self) -> std::result::Result<Record<98>, WriteError> {
        let needs_wide = self.at.disk >= u16::MAX as u32
            || self.central.disk >= u16::MAX as u32
            || self.entries >= u16::MAX as u64
            || self.on_disk >= u16::MAX as u64
            || self.size >= u32::MAX as u64
            || self.central.offset >= u32::MAX as u64;
        if needs_wide && !self.wide {
            return Err(WriteError::Overflow);
        }
        let mut record = Record::new();
        if self.wide {
            record.u32(0x0606_4b50);
            record.u64(44);
            record.u16(0x032d);
            record.u16(45);
            record.u32(self.at.disk);
            record.u32(self.central.disk);
            for value in [self.on_disk, self.entries, self.size, self.central.offset] {
                record.u64(value);
            }
            record.u32(0x0706_4b50);
            record.u32(self.at.disk);
            record.u64(self.at.offset);
            record.u32(self.at.disk.checked_add(1).ok_or(WriteError::Overflow)?);
        }
        record.u32(0x0605_4b50);
        for value in [self.at.disk as u64, self.central.disk as u64, self.on_disk, self.entries] {
            record.u16(value.min(u16::MAX as u64) as u16);
        }
        for value in [self.size, self.central.offset] {
            record.u32(value.min(u32::MAX as u64) as u32);
        }
        record.u16(self.comment.len() as u16);
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read16(b: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
    }
    fn read32(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn read64(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn disk_and_offset_promotion_preserve_descriptor_width_and_extra_order() {
        let options = EntryOptions {
            name: super::super::super::EntryName::Raw(b"a"),
            method: Method::Stored,
            modified: super::super::super::DosDateTime::default(),
            extended_mtime: Some(1),
            permissions: super::super::super::Permissions::new(0o644).unwrap(),
            comment: b"",
        };
        for disk in [65534, 65535, 65536] {
            for offset in [0, u32::MAX as u64 - 1, u32::MAX as u64, u32::MAX as u64 + 1] {
                for size in [3, u32::MAX as u64 - 1, u32::MAX as u64, u32::MAX as u64 + 1] {
                    let mut member = prepare_member(options, InputLength::Exact(size), false, 0).unwrap();
                    member.relocate(disk, offset);
                    let wide_size = size >= u32::MAX as u64;
                    assert_eq!(member.descriptor_len(), if wide_size { 24 } else { 16 });
                    let central = member.central(1, size, size).unwrap();
                    let b = central.as_bytes();
                    assert_eq!(read16(b, 34), disk.min(u16::MAX as u32) as u16);
                    assert_eq!(read32(b, 42), offset.min(u32::MAX as u64) as u32);
                    let extras = member.central_extra(size, size);
                    let e = extras.as_bytes();
                    let length = 16 * usize::from(wide_size)
                        + 8 * usize::from(offset >= u32::MAX as u64)
                        + 4 * usize::from(disk >= 65535);
                    let mut at = 0;
                    if length != 0 {
                        assert_eq!((read16(e, 0), read16(e, 2)), (1, length as u16));
                        at = 4;
                        if wide_size {
                            assert_eq!(read64(e, at), size);
                            assert_eq!(read64(e, at + 8), size);
                            at += 16;
                        }
                        if offset >= u32::MAX as u64 {
                            assert_eq!(read64(e, at), offset);
                            at += 8;
                        }
                        if disk >= 65535 {
                            assert_eq!(read32(e, at), disk);
                            at += 4;
                        }
                    }
                    assert_eq!(read16(e, at), 0x5455);
                }
            }
        }
    }

    #[test]
    fn end_group_has_independent_disk_counts_and_locator_position() {
        for disk in [65534, 65535, 65536] {
            for entries in [65534, 65535, 65536] {
                for size in [3, u32::MAX as u64 - 1, u32::MAX as u64, u32::MAX as u64 + 1] {
                    let at = Location { disk, offset: 999 };
                    let central = Location { disk: disk - 2, offset: 123 };
                    let end =
                        EndGroup { at, central, entries, on_disk: 7, size, wide: true, comment: b"" }.record().unwrap();
                    let b = end.as_bytes();
                    assert_eq!(b.len(), 98);
                    assert_eq!(read32(b, 16), disk);
                    assert_eq!(read32(b, 20), disk - 2);
                    assert_eq!(read64(b, 24), 7);
                    assert_eq!(read64(b, 32), entries);
                    assert_eq!(read64(b, 40), size);
                    assert_eq!(read64(b, 48), 123);
                    assert_eq!(read32(b, 60), disk);
                    assert_eq!(read64(b, 64), 999);
                    assert_eq!(read32(b, 72), disk + 1);
                    assert_eq!(read16(b, 80), disk.min(65535) as u16);
                    assert_eq!(read16(b, 84), 7);
                    assert_eq!(read16(b, 86), entries.min(65535) as u16);
                }
            }
        }
        assert!(
            EndGroup {
                at: Location { disk: u32::MAX, offset: 0 },
                central: Location::default(),
                entries: 0,
                on_disk: 0,
                size: 0,
                wide: true,
                comment: b""
            }
            .record()
            .is_err()
        );
    }
}
