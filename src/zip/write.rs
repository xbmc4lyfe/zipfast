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

//! Creates fresh ZIP archives with a seekable [`ZipWriter`] or a forward-only
//! [`ZipStreamWriter`].
//!
//! Call the writer's finish method to write the central directory and flush the sink.
//! Dropping the writer leaves any provisional bytes in place. A generic sink
//! cannot prevent other handles from changing it. Finishing provides no
//! filesystem durability guarantee.
//!
//! Names are ZIP metadata and can contain raw bytes. Apply any filesystem path
//! policy before treating these bytes as paths.
//!
//! ```
//! use std::io::Cursor;
//! use zipfast::zip::write::{
//!     DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions, WriterOptions, ZipWriter,
//! };
//!
//! let sink = Cursor::new(Vec::new());
//! let mut zip = ZipWriter::new(sink, WriterOptions::default())?;
//! let text = b"hello\n";
//! let options = EntryOptions {
//!     name: EntryName::Utf8("hello.txt"),
//!     method: Method::Stored,
//!     modified: DosDateTime::default(),
//!     extended_mtime: None,
//!     permissions: Permissions::new(0o644)?,
//!     comment: b"",
//! };
//! zip.add_file(options, &mut text.as_slice(), InputLength::Exact(text.len() as u64))?;
//! let archive = zip.finish()?.sink.into_inner();
//! assert!(archive.starts_with(b"PK"));
//! # Ok::<(), zipfast::zip::write::WriteError>(())
//! ```

use std::collections::TryReserveError;
use std::fmt;
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use flate2::{Compress, Compression, FlushCompress, Status};

use crate::crc32::Hasher;
use crate::extract::Cancellation;
use crate::zip::{FLAG_UTF8, S_IFDIR};

use records::{End, Member, Width};

mod records;
mod stream;
pub use stream::ZipStreamWriter;
#[cfg(test)]
mod tests;

/// Supported member compression methods. Empty members use Stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Stored,
    Deflate(DeflateLevel),
}

/// A raw Deflate compression level from 1 through 9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeflateLevel(u32);

/// How the source stream is framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputLength {
    /// Read exactly this many bytes, then require EOF on a one-byte probe.
    Exact(u64),
    /// Read until EOF. The writer conservatively reserves ZIP64 record space
    /// before reading even when the input eventually proves empty.
    Unknown,
}

/// A DOS civil timestamp. The default is 1980-01-01 at midnight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DosDateTime {
    time: u16,
    date: u16,
}

impl Default for DosDateTime {
    fn default() -> Self {
        Self { time: 0, date: 0x21 }
    }
}

/// Writer failures. Metadata and feasibility errors during preflight leave the
/// writer available for another entry. A failure after admission makes future
/// entry operations and finish return [`WriteError::Failed`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum WriteError {
    InvalidMetadata(&'static str),
    NonEmptySink {
        position: u64,
        extent: u64,
    },
    SizeUnderrun {
        expected: u64,
        actual: u64,
    },
    SizeOverrun {
        expected: u64,
    },
    Limit(Limit),
    Allocation(TryReserveError),
    Overflow,
    Canceled,
    Io {
        stage: IoStage,
        source: Arc<io::Error>,
    },
    Compression(flate2::CompressError),
    EncoderStalled,
    /// A previous admitted entry failed. The cause is retained in full.
    Failed(Arc<WriteError>),
}

/// A length-delimited member name of up to 65,535 bytes.
#[derive(Clone, Copy, Debug)]
pub enum EntryName<'a> {
    /// Set the UTF-8 flag and require a valid UTF-8 member comment.
    Utf8(&'a str),
    /// Preserve bytes, including control bytes, and clear the UTF-8 flag.
    Raw(&'a [u8]),
}

/// Unix rwx bits, excluding file type and special permission bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u16);

impl Permissions {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn bits(self) -> u16 {
        self.0
    }

    /// Validates a Unix permission mode in 0o000..=0o777.
    pub fn new(mode: u16) -> Result<Self, WriteError> {
        if mode > 0o777 {
            return Err(WriteError::InvalidMetadata("permissions must contain only rwx bits"));
        }
        Ok(Self(mode))
    }
}

impl DeflateLevel {
    /// Validates a raw Deflate compression level.
    pub fn new(level: u32) -> Result<Self, WriteError> {
        if !(1..=9).contains(&level) {
            return Err(WriteError::InvalidMetadata("Deflate level must be in 1..=9"));
        }
        Ok(Self(level))
    }
}

impl DosDateTime {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn wire_fields(self) -> (u16, u16) {
        (self.time, self.date)
    }

    /// Validates a Gregorian date in 1980 through 2107 and a civil time.
    /// Odd seconds round down to the previous two-second tick. The writer
    /// applies no timezone conversion.
    pub fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Result<Self, WriteError> {
        let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => 28 + u8::from(leap),
            _ => 0,
        };
        if !(1980..=2107).contains(&year) || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
            return Err(WriteError::InvalidMetadata("invalid DOS civil date or time"));
        }
        Ok(Self {
            time: (u16::from(hour) << 11) | (u16::from(minute) << 5) | u16::from(second / 2),
            date: ((year - 1980) << 9) | (u16::from(month) << 5) | u16::from(day),
        })
    }
}

/// Metadata for one file or directory.
#[derive(Clone, Copy, Debug)]
pub struct EntryOptions<'a> {
    pub name: EntryName<'a>,
    pub method: Method,
    pub modified: DosDateTime,
    /// Optional extended modification time in signed Unix seconds.
    pub extended_mtime: Option<i32>,
    pub permissions: Permissions,
    /// A member comment of up to 65,535 bytes, with encoding set by the name.
    pub comment: &'a [u8],
}

/// Finite component ceilings. Metadata capacity includes the archive comment
/// and the central-directory buffer. It excludes allocator overhead, codec
/// allocations, and I/O buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteLimits {
    /// Member count, including directories.
    pub entries: u64,
    /// Serialized central-directory bytes.
    pub central_bytes: u64,
    /// Combined capacity of the central-directory and archive comment buffers.
    pub metadata_capacity: u64,
    /// Decoded payload bytes per member.
    pub entry_decoded_bytes: u64,
    /// Bytes read across all sources. EOF probes require available budget and
    /// only charge bytes when the source returns them.
    pub source_bytes: u64,
    /// Maximum physical extent of the completed archive.
    pub archive_extent: u64,
    /// Cumulative bytes written, including backpatches.
    pub output_bytes: u64,
    /// Read, write, seek, flush and codec attempts, including retries.
    pub io_attempts: u64,
}

impl Default for WriteLimits {
    fn default() -> Self {
        Self {
            entries: 1_000_000,
            central_bytes: 128 << 20,
            metadata_capacity: 129 << 20,
            entry_decoded_bytes: 1 << 40,
            source_bytes: 2 << 40,
            archive_extent: 3 << 40,
            output_bytes: 4 << 40,
            io_attempts: 1 << 32,
        }
    }
}

/// Archive-level options.
#[derive(Clone, Default)]
pub struct WriterOptions<'a> {
    /// Archive comment of up to 65,535 arbitrary bytes.
    pub comment: &'a [u8],
    pub limits: WriteLimits,
    /// Cooperative cancellation. A blocking I/O or codec call runs until it
    /// returns control to the writer.
    pub cancel: Option<Cancellation>,
}

/// Current accounting for the writer's resource ceilings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteUsage {
    pub entries: u64,
    pub central_bytes: u64,
    pub metadata_capacity: u64,
    pub decoded_bytes: u64,
    pub packed_bytes: u64,
    pub source_bytes: u64,
    pub archive_extent: u64,
    pub output_bytes: u64,
    pub io_attempts: u64,
}

/// Component reported by [`WriteError::Limit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    Entries,
    CentralBytes,
    MetadataCapacity,
    EntryDecodedBytes,
    SourceBytes,
    ArchiveExtent,
    OutputBytes,
    IoAttempts,
}

/// Operation reported by an I/O failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IoStage {
    SinkPosition,
    SinkExtent,
    SinkRestore,
    SourceRead,
    LocalHeader,
    Payload,
    DataDescriptor,
    BackpatchSeek,
    BackpatchWrite,
    BackpatchRestore,
    CentralDirectory,
    EndRecord,
    Flush,
}

/// Values for a successfully written member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryWritten {
    /// Zero-based ordinal in central-directory order.
    pub ordinal: u64,
    pub method: Method,
    pub crc32: u32,
    pub decoded_size: u64,
    pub packed_size: u64,
    pub local_offset: u64,
}

/// Archive-level accounting after a successful finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteSummary {
    pub usage: WriteUsage,
    pub central_offset: u64,
    pub zip64: bool,
}

/// The flushed sink and its archive summary.
#[derive(Debug)]
pub struct Finished<W> {
    pub sink: W,
    pub summary: WriteSummary,
}

/// A fresh ZIP archive in progress. The sink may be owned or borrowed.
pub struct ZipWriter<W> {
    output: Output<W>,
    central: Vec<u8>,
    comment: Vec<u8>,
    comment_len: u16,
    wide_member: bool,
    failed: Option<Arc<WriteError>>,
}

impl<W: Write + Seek> ZipWriter<W> {
    /// Checks that the sink starts at position zero and has zero extent.
    ///
    /// A successfully probed sink is restored to its original position.
    /// On error, an owned sink is dropped. Pass a mutable reference to keep
    /// access to the sink if the probe or subsequent writing fails.
    pub fn new(sink: W, options: WriterOptions<'_>) -> Result<Self, WriteError> {
        Self::new_accounted(sink, options).map_err(|(error, _)| error)
    }

    pub(super) fn new_accounted(sink: W, options: WriterOptions<'_>) -> Result<Self, (WriteError, WriteUsage)> {
        let before_io = |error| (error, WriteUsage::default());
        let comment_len = archive_comment_len(&options).map_err(before_io)?;

        let mut writer = Self {
            output: Output::new(sink, options.limits, options.cancel),
            central: Vec::new(),
            comment: Vec::new(),
            comment_len,
            wide_member: false,
            failed: None,
        };
        match writer.initialize(options.comment) {
            Ok(()) => Ok(writer),
            Err(error) => Err((error, writer.usage())),
        }
    }

    fn initialize(&mut self, comment: &[u8]) -> Result<(), WriteError> {
        let comment_len = self.comment_len;
        let metadata_capacity = self.output.work.limits.metadata_capacity;
        self.output.check_tail(End::new(0, 0, 0, false, comment_len), 0)?;
        bound(u64::from(comment_len), metadata_capacity, Limit::MetadataCapacity)?;
        self.comment.try_reserve_exact(usize::from(comment_len)).map_err(WriteError::Allocation)?;
        bound(self.comment.capacity() as u64, metadata_capacity, Limit::MetadataCapacity)?;
        self.comment.extend_from_slice(comment);

        let output = &mut self.output;
        let position = output.seek(SeekFrom::Current(0), IoStage::SinkPosition)?;
        let extent = output.seek(SeekFrom::End(0), IoStage::SinkExtent)?;
        output.seek_to(position, IoStage::SinkRestore)?;
        if position != 0 || extent != 0 {
            return Err(WriteError::NonEmptySink { position, extent });
        }
        Ok(())
    }

    /// Streams a regular file. Exact lengths require a one-byte EOF probe,
    /// including when the declared length is zero. A surplus probe byte is
    /// consumed and charged to the source budget. Supply a bounded reader if
    /// the member occupies only one frame in a longer input stream.
    pub fn add_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        input: &mut R,
        length: InputLength,
    ) -> Result<EntryWritten, WriteError> {
        let (member, entries) = self.prepare(options, length, false)?;
        let result = self.write_file(options, member, entries, FileInput { input, length, decoded: 0 });
        self.remember_failure(result)
    }

    /// Appends an explicit Stored directory whose name has one trailing slash.
    pub fn add_directory(&mut self, options: EntryOptions<'_>) -> Result<EntryWritten, WriteError> {
        let (member, entries) = self.prepare(options, InputLength::Exact(0), true)?;
        let result = self
            .output
            .write_local(&member, options.name.bytes())
            .and_then(|()| self.complete(options, &member, entries, 0, 0, 0));
        self.remember_failure(result)
    }

    /// Returns current accounting, including positive I/O on an incomplete
    /// member. Entry count and decoded and packed totals cover complete members.
    pub fn usage(&self) -> WriteUsage {
        WriteUsage {
            central_bytes: self.central.len() as u64,
            metadata_capacity: self.central.capacity() as u64 + self.comment.capacity() as u64,
            ..self.output.work.usage
        }
    }

    /// Writes the directory and end records, then flushes. On success the
    /// returned sink is positioned at the end of the archive. Discard the
    /// partial archive on error, even if all bytes were written before flush.
    pub fn finish(self) -> Result<Finished<W>, WriteError> {
        self.finish_accounted().map_err(|(error, _)| error)
    }

    pub(super) fn finish_accounted(mut self) -> Result<Finished<W>, (WriteError, WriteUsage)> {
        match self.finish_records() {
            Ok(summary) => Ok(Finished { sink: self.output.sink, summary }),
            Err(error) => Err((error, self.usage())),
        }
    }

    fn finish_records(&mut self) -> Result<WriteSummary, WriteError> {
        self.check_failed()?;
        let usage = self.usage();
        let central_offset = self.output.position;
        let end = End::new(usage.entries, usage.central_bytes, central_offset, self.wide_member, self.comment_len);
        self.output.check_tail(end, 0)?;
        self.output.write_tail(end, &self.central, &self.comment)?;
        Ok(WriteSummary { usage: self.usage(), central_offset, zip64: end.is_wide() })
    }

    fn check_failed(&self) -> Result<(), WriteError> {
        match &self.failed {
            Some(error) => Err(WriteError::Failed(Arc::clone(error))),
            None => Ok(()),
        }
    }

    fn remember_failure<T>(&mut self, result: Result<T, WriteError>) -> Result<T, WriteError> {
        if let Err(error) = &result {
            self.failed = Some(Arc::new(error.clone()));
        }
        result
    }

    fn prepare(
        &mut self,
        options: EntryOptions<'_>,
        length: InputLength,
        directory: bool,
    ) -> Result<(Member, u64), WriteError> {
        self.check_failed()?;
        let local_at = self.output.position;
        let member = prepare_member(options, length, directory, local_at)?;
        let empty = matches!(length, InputLength::Exact(0));

        let usage = self.output.work.usage;
        let limits = self.output.work.limits;
        let entries = add(usage.entries, 1)?;
        bound(entries, limits.entries, Limit::Entries)?;
        let central = add(self.central.len() as u64, member.central_len())?;
        bound(central, limits.central_bytes, Limit::CentralBytes)?;
        let payload_min = if directory { 0 } else { self.output.work.payload_min(length, member.method)? };
        let local_and_payload = add(member.local_len(), payload_min)?;
        let payload_end = add(local_at, local_and_payload)?;
        let end = End::new(entries, central, payload_end, self.wide_member || member.width.is_wide(), self.comment_len);
        let patch = if empty { 0 } else { member.patch_len() };
        self.output.check_tail(end, add(local_and_payload, patch)?)?;
        self.output.work.check_canceled()?;
        self.reserve_central(central)?;
        Ok((member, entries))
    }

    fn reserve_central(&mut self, needed: u64) -> Result<(), WriteError> {
        let max = self.output.work.limits.metadata_capacity - self.comment.capacity() as u64;
        reserve_central(&mut self.central, needed, max)
    }

    fn write_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        mut member: Member,
        entries: u64,
        mut file: FileInput<'_, R>,
    ) -> Result<EntryWritten, WriteError> {
        let mut input = [0; BUFFER];
        let first = file.read(&mut self.output.work, &mut input)?;
        if first == 0 {
            member.method = Method::Stored;
            member.width = Width::new(Method::Stored, InputLength::Exact(0), member.local_at, true);
            self.output.write_local(&member, options.name.bytes())?;
            return self.complete(options, &member, entries, 0, 0, 0);
        }

        self.output.write_local(&member, options.name.bytes())?;
        let (crc, packed) = self.output.write_payload(member.method, &mut file, &mut input, first)?;
        let payload_end = self.output.position;
        let decoded = file.decoded;

        let central = add(self.central.len() as u64, member.central_len())?;
        let end = End::new(entries, central, payload_end, self.wide_member || member.width.is_wide(), self.comment_len);
        self.output.check_tail(end, member.patch_len())?;

        let patch = member.patch(crc, decoded, packed)?;
        self.output.seek_to(member.crc_at()?, IoStage::BackpatchSeek)?;
        self.output.write(patch.as_bytes(), IoStage::BackpatchWrite)?;
        if member.width.sizes {
            let mut sizes = [0; 16];
            sizes[..8].copy_from_slice(&decoded.to_le_bytes());
            sizes[8..].copy_from_slice(&packed.to_le_bytes());
            self.output.seek_to(member.zip64_sizes_at()?, IoStage::BackpatchSeek)?;
            self.output.write(&sizes, IoStage::BackpatchWrite)?;
        }
        self.output.seek_to(payload_end, IoStage::BackpatchRestore)?;
        self.complete(options, &member, entries, crc, decoded, packed)
    }

    fn complete(
        &mut self,
        options: EntryOptions<'_>,
        member: &Member,
        entries: u64,
        crc: u32,
        decoded: u64,
        packed: u64,
    ) -> Result<EntryWritten, WriteError> {
        self.output.work.check_canceled()?;
        let header = member.central(crc, decoded, packed)?;
        let usage = &mut self.output.work.usage;
        let total_decoded = add(usage.decoded_bytes, decoded)?;
        let total_packed = add(usage.packed_bytes, packed)?;
        self.central.extend_from_slice(header.as_bytes());
        self.central.extend_from_slice(options.name.bytes());
        self.central.extend_from_slice(member.central_extra(decoded, packed).as_bytes());
        self.central.extend_from_slice(options.comment);
        self.wide_member |= member.width.is_wide();
        usage.entries = entries;
        usage.decoded_bytes = total_decoded;
        usage.packed_bytes = total_packed;
        Ok(EntryWritten {
            ordinal: entries - 1,
            method: member.method,
            crc32: crc,
            decoded_size: decoded,
            packed_size: packed,
            local_offset: member.local_at,
        })
    }
}

fn archive_comment_len(options: &WriterOptions<'_>) -> Result<u16, WriteError> {
    let len = metadata_len(options.comment, "archive comment exceeds 65,535 bytes")?;
    let max_buffer = isize::MAX as u64;
    bound(options.limits.central_bytes, max_buffer, Limit::CentralBytes)?;
    bound(options.limits.metadata_capacity, max_buffer, Limit::MetadataCapacity)?;
    Ok(len)
}

fn prepare_member(
    options: EntryOptions<'_>,
    length: InputLength,
    directory: bool,
    local_at: u64,
) -> Result<Member, WriteError> {
    let name = options.name.bytes();
    let name_len = metadata_len(name, "entry name exceeds 65,535 bytes")?;
    let comment_len = metadata_len(options.comment, "entry comment exceeds 65,535 bytes")?;
    let flags = if matches!(options.name, EntryName::Utf8(_)) {
        if std::str::from_utf8(options.comment).is_err() {
            return Err(WriteError::InvalidMetadata("UTF-8 entry requires a UTF-8 comment"));
        }
        FLAG_UTF8
    } else {
        0
    };
    let slash = name.ends_with(b"/");
    if directory {
        if !slash || name.ends_with(b"//") || options.method != Method::Stored {
            return Err(WriteError::InvalidMetadata("directory requires Stored and exactly one terminal slash"));
        }
    } else if slash {
        return Err(WriteError::InvalidMetadata("file name ends with slash"));
    }
    let empty = matches!(length, InputLength::Exact(0));
    let method = if empty { Method::Stored } else { options.method };
    let (type_bits, dos_attributes) = if directory { (S_IFDIR, 0x10) } else { (0o100000, 0) };
    Ok(Member {
        width: Width::new(method, length, local_at, empty),
        method,
        flags,
        dos: options.modified,
        name_len,
        comment_len,
        external: ((type_bits | u32::from(options.permissions.0)) << 16) | dos_attributes,
        mtime: options.extended_mtime,
        local_at,
    })
}

fn reserve_central(central: &mut Vec<u8>, needed: u64, max: u64) -> Result<(), WriteError> {
    bound(needed, max, Limit::MetadataCapacity)?;
    let needed = usize::try_from(needed).map_err(|_| WriteError::Overflow)?;
    let capacity = central.capacity();
    if needed > capacity {
        let new_capacity = needed.max(capacity.saturating_mul(2)).min(max as usize);
        central.try_reserve_exact(new_capacity - central.len()).map_err(WriteError::Allocation)?;
        bound(central.capacity() as u64, max, Limit::MetadataCapacity)?;
    }
    Ok(())
}

const BUFFER: usize = 64 << 10;

impl<'a> EntryName<'a> {
    fn bytes(self) -> &'a [u8] {
        match self {
            Self::Utf8(name) => name.as_bytes(),
            Self::Raw(name) => name,
        }
    }
}

fn metadata_len(bytes: &[u8], message: &'static str) -> Result<u16, WriteError> {
    u16::try_from(bytes.len()).map_err(|_| WriteError::InvalidMetadata(message))
}

fn add(a: u64, b: u64) -> Result<u64, WriteError> {
    a.checked_add(b).ok_or(WriteError::Overflow)
}

fn bound(value: u64, max: u64, limit: Limit) -> Result<(), WriteError> {
    if value > max { Err(WriteError::Limit(limit)) } else { Ok(()) }
}

struct Work {
    limits: WriteLimits,
    usage: WriteUsage,
    cancel: Option<Cancellation>,
}

impl Work {
    fn payload_min(&self, length: InputLength, method: Method) -> Result<u64, WriteError> {
        let usage = self.usage;
        let limits = self.limits;
        Ok(match length {
            InputLength::Exact(size) => {
                bound(size, limits.entry_decoded_bytes, Limit::EntryDecodedBytes)?;
                bound(add(add(usage.source_bytes, size)?, 1)?, limits.source_bytes, Limit::SourceBytes)?;
                if method == Method::Stored { size } else { 0 }
            }
            InputLength::Unknown => {
                bound(add(usage.source_bytes, 1)?, limits.source_bytes, Limit::SourceBytes)?;
                0
            }
        })
    }

    fn check_canceled(&self) -> Result<(), WriteError> {
        if self.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
            return Err(WriteError::Canceled);
        }
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<(), WriteError> {
        self.check_canceled()?;
        if self.usage.io_attempts == self.limits.io_attempts {
            return Err(WriteError::Limit(Limit::IoAttempts));
        }
        self.usage.io_attempts += 1;
        Ok(())
    }

    fn io<T>(&mut self, stage: IoStage, mut op: impl FnMut() -> io::Result<T>) -> Result<T, WriteError> {
        loop {
            self.checkpoint()?;
            match op() {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(WriteError::io(stage, error)),
            }
        }
    }
}

struct FileInput<'a, R: ?Sized> {
    input: &'a mut R,
    length: InputLength,
    decoded: u64,
}

impl<R: Read + ?Sized> FileInput<'_, R> {
    fn read(&mut self, work: &mut Work, buffer: &mut [u8; BUFFER]) -> Result<usize, WriteError> {
        let remaining = match self.length {
            InputLength::Exact(expected) => expected - self.decoded,
            InputLength::Unknown => work.limits.entry_decoded_bytes - self.decoded,
        };
        let source_left = work.limits.source_bytes - work.usage.source_bytes;
        let len = remaining.max(1).min(source_left).min(BUFFER as u64) as usize;
        if len == 0 {
            return Err(WriteError::Limit(Limit::SourceBytes));
        }
        let n = work.io(IoStage::SourceRead, || self.input.read(&mut buffer[..len]))?;
        if n > len {
            return Err(WriteError::io(
                IoStage::SourceRead,
                io::Error::new(ErrorKind::InvalidData, "invalid read count"),
            ));
        }
        work.usage.source_bytes = add(work.usage.source_bytes, n as u64)?;
        match self.length {
            InputLength::Exact(expected) if n == 0 && remaining != 0 => {
                return Err(WriteError::SizeUnderrun { expected, actual: self.decoded });
            }
            InputLength::Exact(expected) if n as u64 > remaining => return Err(WriteError::SizeOverrun { expected }),
            InputLength::Unknown if n as u64 > remaining => return Err(WriteError::Limit(Limit::EntryDecodedBytes)),
            _ => {}
        }
        self.decoded = add(self.decoded, n as u64)?;
        Ok(n)
    }
}

struct Output<W> {
    sink: W,
    work: Work,
    position: u64,
}

impl<W: Write> Output<W> {
    fn new(sink: W, limits: WriteLimits, cancel: Option<Cancellation>) -> Self {
        Self { sink, work: Work { limits, cancel, usage: WriteUsage::default() }, position: 0 }
    }

    fn check_tail(&self, end: End, before_tail: u64) -> Result<(), WriteError> {
        bound(end.archive_extent()?, self.work.limits.archive_extent, Limit::ArchiveExtent)?;
        let output_bytes = add(add(self.work.usage.output_bytes, before_tail)?, end.trailer_len()?)?;
        bound(output_bytes, self.work.limits.output_bytes, Limit::OutputBytes)
    }

    fn write(&mut self, mut bytes: &[u8], stage: IoStage) -> Result<(), WriteError> {
        let end = add(self.position, bytes.len() as u64)?;
        bound(end, self.work.limits.archive_extent, Limit::ArchiveExtent)?;
        let output = add(self.work.usage.output_bytes, bytes.len() as u64)?;
        bound(output, self.work.limits.output_bytes, Limit::OutputBytes)?;
        while !bytes.is_empty() {
            let n = self.work.io(stage, || self.sink.write(bytes))?;
            if n == 0 {
                return Err(WriteError::io(stage, ErrorKind::WriteZero.into()));
            }
            if n > bytes.len() {
                return Err(WriteError::io(stage, io::Error::new(ErrorKind::InvalidData, "invalid write count")));
            }
            // The total for this slice was checked before writing the first byte.
            self.position += n as u64;
            self.work.usage.archive_extent = self.work.usage.archive_extent.max(self.position);
            self.work.usage.output_bytes += n as u64;
            bytes = &bytes[n..];
        }
        Ok(())
    }

    fn deflate(
        &mut self,
        encoder: &mut Compress,
        mut input: &[u8],
        output: &mut [u8; BUFFER],
        flush: FlushCompress,
    ) -> Result<(), WriteError> {
        loop {
            self.work.checkpoint()?;
            let previous_in = encoder.total_in();
            let previous_out = encoder.total_out();
            let status = encoder.compress(input, output, flush).map_err(WriteError::Compression)?;
            let consumed = encoder_delta(previous_in, encoder.total_in(), input.len())?;
            let produced = encoder_delta(previous_out, encoder.total_out(), output.len())?;
            self.write(&output[..produced], IoStage::Payload)?;
            input = &input[consumed..];
            match status {
                Status::StreamEnd if flush == FlushCompress::Finish => return Ok(()),
                Status::StreamEnd => return Err(WriteError::EncoderStalled),
                _ if consumed == 0 && produced == 0 => return Err(WriteError::EncoderStalled),
                _ if input.is_empty() && flush == FlushCompress::None => return Ok(()),
                _ => {}
            }
        }
    }

    fn write_local(&mut self, member: &Member, name: &[u8]) -> Result<(), WriteError> {
        self.write(member.local().as_bytes(), IoStage::LocalHeader)?;
        self.write(name, IoStage::LocalHeader)?;
        self.write(member.local_extra().as_bytes(), IoStage::LocalHeader)
    }

    fn write_payload<R: Read + ?Sized>(
        &mut self,
        method: Method,
        file: &mut FileInput<'_, R>,
        input: &mut [u8; BUFFER],
        first: usize,
    ) -> Result<(u32, u64), WriteError> {
        let payload_at = self.position;
        let mut crc = Hasher::new();
        let mut chunk = first;
        let mut encoder = match method {
            Method::Stored => None,
            Method::Deflate(level) => Some(Compress::new(Compression::new(level.0), false)),
        };
        let mut compressed = [0; BUFFER];
        while chunk != 0 {
            let bytes = &input[..chunk];
            crc.update(bytes);
            if let Some(encoder) = &mut encoder {
                self.deflate(encoder, bytes, &mut compressed, FlushCompress::None)?;
            } else {
                self.write(bytes, IoStage::Payload)?;
            }
            chunk = file.read(&mut self.work, input)?;
        }
        if let Some(encoder) = &mut encoder {
            self.deflate(encoder, &[], &mut compressed, FlushCompress::Finish)?;
        }
        let payload_end = self.position;
        let packed = payload_end.checked_sub(payload_at).ok_or(WriteError::Overflow)?;
        Ok((crc.finalize(), packed))
    }

    fn write_tail(&mut self, end: End, central: &[u8], comment: &[u8]) -> Result<(), WriteError> {
        let record = end.record()?;
        for chunk in central.chunks(BUFFER) {
            self.write(chunk, IoStage::CentralDirectory)?;
        }
        self.write(record.as_bytes(), IoStage::EndRecord)?;
        self.write(comment, IoStage::EndRecord)?;
        self.flush()?;
        self.work.check_canceled()?;
        Ok(())
    }

    fn flush(&mut self) -> Result<(), WriteError> {
        self.work.io(IoStage::Flush, || self.sink.flush())
    }
}

impl<W: Write + Seek> Output<W> {
    fn seek(&mut self, from: SeekFrom, stage: IoStage) -> Result<u64, WriteError> {
        let position = self.work.io(stage, || self.sink.seek(from))?;
        self.position = position;
        Ok(position)
    }

    fn seek_to(&mut self, position: u64, stage: IoStage) -> Result<(), WriteError> {
        if self.seek(SeekFrom::Start(position), stage)? != position {
            return Err(WriteError::io(
                stage,
                io::Error::new(ErrorKind::InvalidData, "seek returned an unexpected position"),
            ));
        }
        Ok(())
    }
}

fn encoder_delta(previous: u64, total: u64, available: usize) -> Result<usize, WriteError> {
    let delta = total.checked_sub(previous).ok_or(WriteError::Overflow)?;
    if delta > available as u64 {
        return Err(WriteError::EncoderStalled);
    }
    Ok(delta as usize)
}

impl WriteError {
    fn io(stage: IoStage, source: io::Error) -> Self {
        Self::Io { stage, source: Arc::new(source) }
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetadata(message) => write!(f, "invalid ZIP metadata: {message}"),
            Self::NonEmptySink { position, extent } => {
                write!(f, "ZIP sink starts at position {position} with extent {extent}")
            }
            Self::SizeUnderrun { expected, actual } => write!(f, "expected {expected} source bytes, found {actual}"),
            Self::SizeOverrun { expected } => write!(f, "source exceeds its declared length of {expected} bytes"),
            Self::Limit(limit) => write!(f, "ZIP writer exceeded the {limit:?} limit"),
            Self::Allocation(error) => write!(f, "could not allocate ZIP metadata: {error}"),
            Self::Overflow => f.write_str("ZIP writer arithmetic overflow"),
            Self::Canceled => f.write_str("ZIP writing canceled"),
            Self::Io { stage, source } => write!(f, "ZIP writer {stage:?}: {source}"),
            Self::Compression(error) => write!(f, "ZIP writer Deflate: {error}"),
            Self::EncoderStalled => f.write_str("ZIP writer Deflate made no usable progress"),
            Self::Failed(cause) => write!(f, "ZIP writer failed earlier: {cause}"),
        }
    }
}

impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source.as_ref()),
            Self::Allocation(error) => Some(error),
            Self::Compression(error) => Some(error),
            Self::Failed(cause) => Some(cause.as_ref()),
            _ => None,
        }
    }
}
