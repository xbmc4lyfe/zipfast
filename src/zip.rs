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

//! ZIP archives, read from PKWARE's published APPNOTE: the end of central directory record (and its ZIP64 form),
//! the central directory, and each entry's local header. Entries are stored, deflated, or compressed with bzip2,
//! LZMA, xz or zstd.

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::{Decompress, FlushDecompress, Status};
use zip_container::{
    Directory, DirectoryError, DirectoryParser, LOCAL_HEADER_LEN, Limits, LocalHeader, OwnershipError, ParseError,
    Profile, ReducedCentralRecord, local_layout,
};

use crate::error::{Error, Result};
use crate::extract::{
    Cancellation, Entry, Meta, Mode, Options, Summary, Target, finish_dirs, finish_file, make_dirs, open_target,
};
use crate::path::sanitize;
use crate::rar5::Redirection;
use crate::stream::{LZMA_MEMORY_LIMIT, zstd_decoder};

pub mod create;
pub mod recovery;
pub mod rewrite;
mod session;
pub mod write;

pub(crate) use session::InspectionSource;
pub use session::{
    EntryId, EntryMetadata, Metadata, ReadSession, SelectedZipEntry, SessionError, SessionResult, SourceChange,
};
pub use zip_container::{
    AesFields, CentralHeader, CentralLocation, DirectoryDeclaration, EndRecord, ExtraMtime, ResolvedFields, Usage,
    Zip64End, Zip64Fields, Zip64Locator,
};

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_UTF8: u16 = 0x0800;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_BZIP2: u16 = 12;
const METHOD_LZMA: u16 = 14;
const METHOD_ZSTD: u16 = 93;
const METHOD_XZ: u16 = 95;
/// An LZMA entry ends with an end marker instead of at its stated size.
const FLAG_LZMA_EOS: u16 = 0x0002;

/// Whether entries compressed with `method` can be read.
fn supported(method: u16) -> bool {
    matches!(method, METHOD_STORED | METHOD_DEFLATE | METHOD_BZIP2 | METHOD_LZMA | METHOD_ZSTD | METHOD_XZ)
}

const HOST_UNIX: u8 = 3;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

const BUF: usize = 1 << 20;
const ENCRYPTED_PACKED_LIMIT: u64 = 128 << 20;
// A cancelable parse polls between bounded reads and parser supplies. The
// shared parser also bounds the tail it may consume from cache in one poll.
const CANCELABLE_DIRECTORY_CHUNK: usize = 64 << 10;

/// Whether the file starts the way a ZIP archive does.
pub fn sniff(head: &[u8]) -> bool {
    head.len() >= 4 && head[..2] == *b"PK" && matches!(head[2..4], [3, 4] | [5, 6] | [7, 8])
}

/// One central directory entry.
#[derive(Clone, Debug, Default)]
pub struct ZipEntry {
    pub name: String,
    pub flags: u16,
    pub method: u16,
    pub host: u8,
    pub crc32: u32,
    pub packed: u64,
    pub size: u64,
    pub local_at: u64,
    pub external: u32,
    pub mtime: Option<i64>,
    pub nanos: u32,
    pub aes_info: Option<(u8, u16, u16)>,
}

impl ZipEntry {
    pub fn unix_mode(&self) -> Option<u32> {
        extraction_unix_mode(self.host, self.external)
    }

    pub fn is_dir(&self) -> bool {
        is_dir(&self.name, self.host, self.external)
    }

    pub fn is_link(&self) -> bool {
        is_link(self.host, self.external)
    }

    pub fn encrypted(&self) -> bool {
        self.read_description().encrypted()
    }

    pub fn effective_method(&self) -> u16 {
        self.read_description().effective_method()
    }

    fn read_description(&self) -> ReadDescription<'_> {
        ReadDescription {
            name: &self.name,
            flags: self.flags,
            method: self.method,
            crc32: self.crc32,
            packed: self.packed,
            size: self.size,
            local_at: self.local_at,
            aes_info: self.aes_info,
        }
    }

    fn meta(&self) -> Meta {
        Meta { mtime: self.mtime, nanos: self.nanos, mode: self.unix_mode() }
    }
}

fn extraction_unix_mode(host: u8, external: u32) -> Option<u32> {
    (host == HOST_UNIX && external >> 16 != 0).then_some(external >> 16)
}

fn is_dir(name: &str, host: u8, external: u32) -> bool {
    name.ends_with('/')
        || extraction_unix_mode(host, external).is_some_and(|mode| mode & S_IFMT == S_IFDIR)
        || (host != HOST_UNIX && external & 0x10 != 0)
}

fn is_link(host: u8, external: u32) -> bool {
    extraction_unix_mode(host, external).is_some_and(|mode| mode & S_IFMT == S_IFLNK)
}

struct ReadDescription<'a> {
    name: &'a str,
    flags: u16,
    method: u16,
    crc32: u32,
    packed: u64,
    size: u64,
    local_at: u64,
    aes_info: Option<(u8, u16, u16)>,
}

impl ReadDescription<'_> {
    fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0 || self.method == 99 || self.aes_info.is_some()
    }

    fn effective_method(&self) -> u16 {
        if self.method == 99 { self.aes_info.map_or(self.method, |(_, _, m)| m) } else { self.method }
    }
}

fn check_selection(is_dir: bool, is_link: bool, packed: u64, size: u64, limit: u64) -> Result<()> {
    if is_dir || is_link {
        return Err(Error::Unsupported("the selected ZIP entry is not a regular file".into()));
    }
    if packed > limit || size > limit {
        return Err(Error::Unsupported("the selected ZIP entry exceeds the byte limit".into()));
    }
    Ok(())
}

fn read_local_header(file: &mut (impl Read + Seek), at: u64) -> Result<[u8; LOCAL_HEADER_LEN]> {
    file.seek(SeekFrom::Start(at))?;
    let mut buf = [0; LOCAL_HEADER_LEN];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn directory_error(error: DirectoryError) -> Error {
    match error {
        DirectoryError::NotZip => Error::NotAnArchive,
        DirectoryError::MalformedEnd => Error::Corrupt("central directory size or offset"),
        DirectoryError::MalformedZip64 => Error::Corrupt("ZIP64 metadata"),
        DirectoryError::EntryCount { .. } => Error::Corrupt("central directory entry count"),
        DirectoryError::InvalidLocalOffset => Error::Corrupt("local header offset"),
        DirectoryError::UnsupportedDisk => Error::Unsupported("split ZIP archives (.z01 and on)".into()),
        DirectoryError::Limit(_)
        | DirectoryError::Ownership(OwnershipError::CounterOverflow { .. } | OwnershipError::LimitExceeded { .. }) => {
            Error::Unsupported("ZIP directory exceeds the listing limit".into())
        }
        DirectoryError::Allocation | DirectoryError::Ownership(OwnershipError::Allocation { .. }) => {
            Error::Unsupported("cannot allocate ZIP directory metadata".into())
        }
        DirectoryError::Supply(_) => Error::Corrupt("ZIP directory source range"),
        DirectoryError::Incomplete => Error::Truncated,
        DirectoryError::Parse(_) => Error::Corrupt("central directory record"),
    }
}

fn check_cancel(cancel: Option<&Cancellation>) -> Result<()> {
    Ok(cancel.map_or(Ok(()), Cancellation::check_io)?)
}

fn read_directory<T>(
    file: &mut (impl Read + Seek),
    len: u64,
    mut parser: DirectoryParser<T>,
    cancel: Option<&Cancellation>,
) -> Result<Directory<T>> {
    let mut buf = Vec::new();
    let mut file_at = None;
    loop {
        check_cancel(cancel)?;
        let Some(range) = parser.next_read().map_err(directory_error)? else { break };
        // DirectoryParser checks each pending range and cumulative source
        // usage against Limits before issuing a request.
        let size = range
            .end
            .checked_sub(range.start)
            .filter(|&size| size != 0 && range.end <= len)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(Error::Corrupt("ZIP directory source range"))?;
        let chunk_size = if cancel.is_some() { size.min(CANCELABLE_DIRECTORY_CHUNK) } else { size };
        if chunk_size > buf.len() {
            buf.try_reserve_exact(chunk_size - buf.len()).map_err(|_| directory_error(DirectoryError::Allocation))?;
            buf.resize(chunk_size, 0);
        }
        check_cancel(cancel)?;
        if file_at != Some(range.start) {
            file.seek(SeekFrom::Start(range.start))?;
        }
        file.read_exact(&mut buf[..chunk_size])?;
        file_at = Some(range.start + chunk_size as u64);
        check_cancel(cancel)?;
        parser.supply(range.start, &buf[..chunk_size]).map_err(directory_error)?;
        // A strict walk can finish at a noncentral trailer before the end
        // of a pending range. Poll again before reading any remainder.
    }
    check_cancel(cancel)?;
    parser.finish().map_err(directory_error)
}

/// An open archive: the file and its central directory.
pub struct Archive {
    file: File,
    len: u64,
    pub entries: Vec<ZipEntry>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Archive> {
        Self::open_cancelable(path, None)
    }

    pub(crate) fn open_cancelable(path: &Path, cancel: Option<&Cancellation>) -> Result<Archive> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        check_cancel(cancel)?;
        let parser = DirectoryParser::with_projection_and_name_crc32(
            len,
            Profile::Zipfast,
            Limits::default(),
            crate::crc32::hash,
            project_record,
        )
        .map_err(directory_error)?;
        let directory = read_directory(&mut file, len, parser, cancel)?;
        let mut entries = directory.entries;
        if directory.prefix_shift != 0 {
            for entry in &mut entries {
                check_cancel(cancel)?;
                entry.local_at = entry
                    .local_at
                    .checked_add(directory.prefix_shift)
                    .filter(|&at| at < len)
                    .ok_or(Error::Corrupt("local header offset"))?;
            }
        }
        check_cancel(cancel)?;
        Ok(Archive { file, len, entries })
    }

    /// Decodes the entry at a zero-based index and checks its integrity.
    ///
    /// Both its packed and unpacked sizes must be at most `max_bytes`.
    /// The sink receives provisional data. Only publish it after success.
    pub fn read_at(
        &mut self,
        index: usize,
        password: Option<&str>,
        max_bytes: u64,
        sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.read_at_cancelable(index, password, max_bytes, None, sink)
    }

    pub(crate) fn selected_entry(&self, index: usize, limit: u64) -> Result<&ZipEntry> {
        let entry = self.entries.get(index).ok_or_else(|| Error::Unsupported("entry index is out of range".into()))?;
        check_selection(entry.is_dir(), entry.is_link(), entry.packed, entry.size, limit)?;
        Ok(entry)
    }

    pub(crate) fn read_at_cancelable(
        &mut self,
        index: usize,
        password: Option<&str>,
        limit: u64,
        cancel: Option<&Cancellation>,
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.selected_entry(index, limit)?;
        let entry = self.entries[index].read_description();
        let mut buffer = vec![0; BUF];
        read_entry(&mut self.file, self.len, &entry, password, &mut buffer, &mut sink, cancel)
    }
}

/// Where an entry's data starts, from its local header.
fn data_at(file: &mut (impl Read + Seek), len: u64, e: &ReadDescription<'_>) -> Result<u64> {
    if e.local_at.checked_add(LOCAL_HEADER_LEN as u64).is_none_or(|end| end > len) {
        return Err(Error::Truncated);
    }
    let head = read_local_header(file, e.local_at)?;
    let header = LocalHeader::parse(&head).map_err(|error| match error {
        ParseError::BadSignature { .. } => Error::Corrupt("local header signature"),
        _ => Error::Truncated,
    })?;
    let layout = local_layout(header, e.local_at, len).map_err(|_| Error::Truncated)?;
    Ok(layout.payload_range(e.packed, len).map_err(|_| Error::Truncated)?.start)
}

/// Reads an entry's data, decompressed, into `sink`, and checks its size and CRC.
fn read_entry(
    file: &mut (impl Read + Seek),
    len: u64,
    e: &ReadDescription<'_>,
    password: Option<&str>,
    buf: &mut [u8],
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    cancel: Option<&Cancellation>,
) -> Result<()> {
    let check = || cancel.map_or(Ok(()), Cancellation::check_io);
    check()?;
    let at = data_at(file, len, e)?;
    file.seek(SeekFrom::Start(at))?;
    let mut crc = crate::crc32::Hasher::new();
    let mut size = 0u64;
    let mut emit = |chunk: &[u8]| -> Result<()> {
        size += chunk.len() as u64;
        if size > e.size {
            return Err(Error::Corrupt("more data than the directory says"));
        }
        crc.update(chunk);
        check()?;
        sink(chunk)
    };
    if e.encrypted() {
        if e.packed > ENCRYPTED_PACKED_LIMIT {
            return Err(Error::Unsupported("encrypted ZIP entry exceeds the 128 MiB packed limit".into()));
        }
        let pw = password
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Unsupported("encrypted (password required)".into()))?;
        let packed_len = usize::try_from(e.packed).map_err(|_| Error::Corrupt("encrypted entry too large"))?;
        let mut raw = vec![0u8; packed_len];
        if cancel.is_some() {
            for chunk in raw.chunks_mut(buf.len()) {
                check()?;
                file.read_exact(chunk)?;
            }
            check()?;
        } else {
            file.read_exact(&mut raw)?;
        }
        let mut skip_crc = false;
        let decrypted = if e.method == 99 || e.aes_info.is_some() {
            let (strength, vendor, _) = e.aes_info.ok_or(Error::Corrupt("missing WinZip AES extra field"))?;
            if vendor == 2 {
                skip_crc = true;
            }
            crate::crypto::decrypt_winzip_aes(pw, strength, &raw, Some(e.packed))
                .ok_or(Error::Corrupt("wrong password or damaged AES stream"))?
        } else {
            let check = if e.flags & 0x0008 != 0 {
                let head = read_local_header(file, e.local_at)?;
                head[11]
            } else {
                (e.crc32 >> 24) as u8
            };
            crate::crypto::decrypt_zipcrypto(pw, check, &raw).ok_or(Error::Corrupt("wrong password"))?
        };
        let method = e.effective_method();
        match method {
            METHOD_STORED => {
                if decrypted.len() as u64 != e.size {
                    return Err(Error::Corrupt("stored entry's sizes differ"));
                }
                if cancel.is_some() {
                    for chunk in decrypted.chunks(buf.len()) {
                        check()?;
                        emit(chunk)?;
                    }
                } else {
                    emit(&decrypted)?;
                }
            }
            METHOD_DEFLATE => {
                let mut z = Decompress::new(false);
                let mut out = vec![0u8; BUF];
                let mut input = decrypted.as_slice();
                loop {
                    check()?;
                    let (before_in, before_out) = (z.total_in(), z.total_out());
                    let status = z
                        .decompress(input, &mut out, FlushDecompress::None)
                        .map_err(|_| Error::Corrupt("deflate data"))?;
                    let used = (z.total_in() - before_in) as usize;
                    let made = (z.total_out() - before_out) as usize;
                    input = &input[used..];
                    emit(&out[..made])?;
                    if status == Status::StreamEnd {
                        break;
                    }
                    if made == out.len() {
                        continue;
                    }
                    if input.is_empty() || (used == 0 && made == 0) {
                        return Err(Error::Corrupt("deflate data"));
                    }
                }
            }
            METHOD_BZIP2 | METHOD_LZMA | METHOD_ZSTD | METHOD_XZ => {
                let mut dec = stream_decoder(e, method, BufReader::new(Cursor::new(&decrypted)))?;
                loop {
                    check()?;
                    let n = dec.read(buf).map_err(|_| Error::Corrupt("compressed data is damaged"))?;
                    if n == 0 {
                        break;
                    }
                    emit(&buf[..n])?;
                }
            }
            m => return Err(Error::Unsupported(format!("compression method {m}"))),
        }
        if size != e.size {
            return Err(Error::Corrupt("less data than the directory says"));
        }
        if !skip_crc && crc.finalize() != e.crc32 {
            return Err(Error::BadChecksum(e.name.to_owned()));
        }
        return Ok(());
    }
    let mut left = e.packed;
    match e.method {
        METHOD_STORED => {
            if e.packed != e.size {
                return Err(Error::Corrupt("stored entry's sizes differ"));
            }
            while left > 0 {
                check()?;
                let n = (left.min(buf.len() as u64)) as usize;
                file.read_exact(&mut buf[..n])?;
                emit(&buf[..n])?;
                left -= n as u64;
            }
        }
        METHOD_DEFLATE => {
            let mut z = Decompress::new(false);
            let mut out = vec![0u8; BUF];
            let mut done = false;
            while !done {
                let n = (left.min(buf.len() as u64)) as usize;
                file.read_exact(&mut buf[..n])?;
                left -= n as u64;
                let mut input = &buf[..n];
                loop {
                    check()?;
                    let (before_in, before_out) = (z.total_in(), z.total_out());
                    let status = z
                        .decompress(input, &mut out, FlushDecompress::None)
                        .map_err(|_| Error::Corrupt("deflate data"))?;
                    let used = (z.total_in() - before_in) as usize;
                    let made = (z.total_out() - before_out) as usize;
                    input = &input[used..];
                    emit(&out[..made])?;
                    if status == Status::StreamEnd {
                        done = true;
                        break;
                    }
                    // a full output buffer means there may be more to come from the same input
                    if made == out.len() {
                        continue;
                    }
                    if input.is_empty() {
                        if left == 0 {
                            return Err(Error::Corrupt("deflate data ends early"));
                        }
                        break;
                    }
                    if used == 0 && made == 0 {
                        return Err(Error::Corrupt("deflate data"));
                    }
                }
            }
        }
        METHOD_BZIP2 | METHOD_LZMA | METHOD_ZSTD | METHOD_XZ => {
            let packed = BufReader::with_capacity(1 << 20, CheckedInput { input: file.take(e.packed), cancel });
            let mut dec = stream_decoder(e, e.method, packed)?;
            loop {
                check()?;
                let decoded = dec.read(buf);
                check()?;
                let n = match decoded {
                    Ok(n) => n,
                    Err(io) if io.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Error::Truncated),
                    Err(io) if io.raw_os_error().is_some() => return Err(Error::Io(io)),
                    Err(_) => return Err(Error::Corrupt("compressed data is damaged")),
                };
                if n == 0 {
                    break;
                }
                emit(&buf[..n])?;
            }
        }
        m => return Err(Error::Unsupported(format!("compression method {m}"))),
    }
    if size != e.size {
        return Err(Error::Corrupt("less data than the directory says"));
    }
    if crc.finalize() != e.crc32 {
        return Err(Error::BadChecksum(e.name.to_owned()));
    }
    Ok(())
}

// The buffered codecs may consume several input windows before producing
// output. Poll at the source as well as between decoder output chunks.
struct CheckedInput<'a, R> {
    input: R,
    cancel: Option<&'a Cancellation>,
}

impl<R: Read> Read for CheckedInput<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(cancel) = self.cancel {
            cancel.check_io()?;
        }
        self.input.read(buffer)
    }
}

/// A reader of an entry's data for the methods that have a stream decoder.
fn stream_decoder<'a>(e: &ReadDescription<'_>, method: u16, packed: impl BufRead + 'a) -> Result<Box<dyn Read + 'a>> {
    Ok(match method {
        METHOD_BZIP2 => Box::new(bzip2::bufread::MultiBzDecoder::new(packed)),
        METHOD_ZSTD => Box::new(zstd_decoder(packed)?),
        METHOD_XZ => {
            let stream = liblzma::stream::Stream::new_stream_decoder(LZMA_MEMORY_LIMIT, liblzma::stream::CONCATENATED)
                .map_err(|_| Error::Corrupt("xz data"))?;
            Box::new(liblzma::bufread::XzDecoder::new_stream(packed, stream))
        }
        _ => {
            // APPNOTE 5.8.8: a version, the length of the properties, then the properties and the raw LZMA data.
            // Put back together with the size as the classic .lzma header, it reads with the stock decoder.
            let mut packed = packed;
            let mut head = [0u8; 4];
            packed.read_exact(&mut head)?;
            let props_len = u16::from_le_bytes([head[2], head[3]]) as usize;
            if props_len != 5 {
                return Err(Error::Corrupt("LZMA properties"));
            }
            let mut alone = vec![0u8; 13];
            packed.read_exact(&mut alone[..5])?;
            let size = if e.flags & FLAG_LZMA_EOS != 0 { u64::MAX } else { e.size };
            alone[5..].copy_from_slice(&size.to_le_bytes());
            let stream = liblzma::stream::Stream::new_lzma_decoder(LZMA_MEMORY_LIMIT)
                .map_err(|_| Error::Corrupt("LZMA data"))?;
            Box::new(liblzma::bufread::XzDecoder::new_stream(BufReader::new(Cursor::new(alone).chain(packed)), stream))
        }
    })
}

fn project_record(record: ReducedCentralRecord<'_>) -> std::result::Result<ZipEntry, DirectoryError> {
    let view = record.view();
    let known = record.known();
    project_entry(
        view.header(),
        record.resolved(),
        view.raw_name(),
        known.unicode_path.map(|path| path.path_bytes()),
        known.mtime_override,
        known.aes,
    )
}

fn project_entry(
    header: CentralHeader,
    resolved: ResolvedFields,
    raw_name: &[u8],
    unicode_path: Option<&[u8]>,
    mtime_override: Option<ExtraMtime>,
    aes: Option<AesFields>,
) -> std::result::Result<ZipEntry, DirectoryError> {
    let (mtime, nanos) = project_mtime(header, mtime_override);
    Ok(ZipEntry {
        name: decode_name(unicode_path.unwrap_or(raw_name), unicode_path.is_some() || header.flags & FLAG_UTF8 != 0)?,
        flags: header.flags,
        method: header.method,
        host: (header.version_made_by >> 8) as u8,
        crc32: header.crc32,
        packed: resolved.packed_size,
        size: resolved.unpacked_size,
        local_at: resolved.local_header_offset,
        external: header.external_attributes,
        mtime,
        nanos,
        aes_info: project_aes(aes),
    })
}

fn project_mtime(header: CentralHeader, mtime_override: Option<ExtraMtime>) -> (Option<i64>, u32) {
    match mtime_override {
        Some(ExtraMtime::NtfsFiletime(ticks)) => {
            (Some((ticks / 10_000_000) as i64 - 11_644_473_600), ((ticks % 10_000_000) * 100) as u32)
        }
        Some(ExtraMtime::UnixSeconds(seconds)) => (Some(i64::from(seconds)), 0),
        None => (dos_time(header.mod_time, header.mod_date), 0),
    }
}

fn project_aes(aes: Option<AesFields>) -> Option<(u8, u16, u16)> {
    aes.filter(|fields| (1..=3).contains(&fields.strength))
        .map(|fields| (fields.strength, fields.vendor_version, fields.method))
}

/// MS-DOS date and time, which carry no time zone: read as UTC.
fn dos_time(time: u16, date: u16) -> Option<i64> {
    let (year, month, day) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 15), i64::from(date & 31));
    let (hour, min, sec) = (i64::from(time >> 11), i64::from((time >> 5) & 63), i64::from(time & 31) * 2);
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    // days since 1970 for a civil date (proleptic Gregorian)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// The high half of code page 437, the encoding of names without the UTF-8 flag.
const CP437_HIGH: [char; 128] = [
    'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û',
    'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡',
    '«', '»', '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─',
    '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█',
    '▄', '▌', '▐', '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', '≡', '±', '≥',
    '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
];

fn cp437(byte: u8) -> char {
    if byte < 0x80 { byte as char } else { CP437_HIGH[usize::from(byte - 0x80)] }
}

fn decode_name(raw: &[u8], utf8: bool) -> std::result::Result<String, DirectoryError> {
    // Many tools write valid UTF-8 without setting the flag.
    if let Ok(valid) = std::str::from_utf8(raw) {
        let mut name = String::new();
        name.try_reserve_exact(valid.len()).map_err(|_| DirectoryError::Allocation)?;
        name.push_str(valid);
        return Ok(name);
    }
    decode_invalid_name(raw, utf8, |_| Ok(()))
}

// Charge the exact additional allocation before reserving a decoded name.
// Raw names and Unicode extra bodies are bounded by wire u16 lengths.
fn decode_invalid_name(
    raw: &[u8],
    utf8: bool,
    charge: impl FnOnce(usize) -> std::result::Result<(), DirectoryError>,
) -> std::result::Result<String, DirectoryError> {
    let len = if utf8 {
        // Utf8Chunks reproduces from_utf8_lossy's replacement boundaries.
        raw.utf8_chunks().map(|chunk| chunk.valid().len() + 3 * usize::from(!chunk.invalid().is_empty())).sum()
    } else {
        raw.iter().copied().map(|byte| cp437(byte).len_utf8()).sum()
    };
    charge(len)?;
    let mut name = String::new();
    name.try_reserve_exact(len).map_err(|_| DirectoryError::Allocation)?;
    if utf8 {
        for chunk in raw.utf8_chunks() {
            name.push_str(chunk.valid());
            if !chunk.invalid().is_empty() {
                name.push('\u{fffd}');
            }
        }
    } else {
        name.extend(raw.iter().copied().map(cp437));
    }
    Ok(name)
}

pub fn list(path: &Path) -> Result<Vec<Entry>> {
    let archive = Archive::open(path)?;
    Ok(archive
        .entries
        .iter()
        .map(|e| Entry {
            name: e.name.clone(),
            size: e.size,
            packed: e.packed,
            mtime: e.mtime,
            crc32: (!e.is_dir()).then_some(e.crc32),
            method: e.method.min(255) as u8,
            dir: e.is_dir(),
            encrypted: e.encrypted(),
            solid: false,
            link: e.is_link().then(|| Redirection::UnixSymlink(String::new())),
        })
        .collect())
}

pub fn run(path: &Path, opts: &Options, report: impl FnMut(&str)) -> Result<Summary> {
    run_with_password(path, opts, None, report)
}

pub fn run_with_password(
    path: &Path,
    opts: &Options,
    password: Option<&str>,
    mut report: impl FnMut(&str),
) -> Result<Summary> {
    let mut archive = Archive::open(path)?;
    let opts = &*opts.protecting(path)?;
    let mut summary = Summary { volumes: 1, ..Summary::default() };
    let mut buf = vec![0u8; BUF];
    let entries = std::mem::take(&mut archive.entries);
    let password = password.filter(|s| !s.is_empty());
    fn fail(summary: &mut Summary, report: &mut impl FnMut(&str), name: &str, why: &str) {
        let line = format!("{name}: {why}");
        report(&line);
        summary.errors.push(line);
    }
    for e in &entries {
        let rel = match sanitize(&e.name, e.host != HOST_UNIX) {
            Ok(rel) => rel,
            Err(err) => {
                fail(&mut summary, &mut report, &e.name, &err.to_string());
                continue;
            }
        };
        let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        if e.is_dir() {
            if opts.mode == Mode::Extract && !opts.flatten {
                make_dirs(&opts.dest, &rel)?;
                summary.dir_meta.push((opts.dest.join(&rel), e.meta()));
            }
            summary.dirs += 1;
            continue;
        }
        let eff_method = e.effective_method();
        let refuse = if e.encrypted() && password.is_none() {
            Some("encrypted (password required)".to_string())
        } else if !supported(eff_method) {
            Some(format!("compression method {} is not supported yet", eff_method))
        } else if e.is_link() {
            Some("links are not supported yet".to_string())
        } else {
            None
        };
        if let Some(why) = refuse {
            fail(&mut summary, &mut report, &e.name, &why);
            continue;
        }
        let mut target = None;
        if opts.mode == Mode::Extract {
            match open_target(opts, &rel, Some(e.size))? {
                Target::Write(out) => target = Some(out),
                Target::Exists => {
                    report(&format!("{}: exists, skipped", e.name));
                    summary.skipped += 1;
                    continue;
                }
                Target::Blocked(why) => {
                    fail(&mut summary, &mut report, &e.name, why);
                    continue;
                }
            }
        }
        let entry = e.read_description();
        let read = match target.as_mut() {
            Some(out) => read_entry(
                &mut archive.file,
                archive.len,
                &entry,
                password,
                &mut buf,
                &mut |chunk| Ok(out.write(chunk)?),
                None,
            ),
            None => read_entry(&mut archive.file, archive.len, &entry, password, &mut buf, &mut |_| Ok(()), None),
        };
        match read {
            Ok(()) => {
                if let Some(out) = target
                    && let Err(io) = out.finish(|file| finish_file(file, &e.meta()))
                {
                    finish_dirs(&mut summary);
                    return Err(Error::Io(io));
                }
                summary.files += 1;
                summary.bytes += e.size;
            }
            Err(err) => {
                drop(target);
                match err {
                    // a failure writing out stops the run; anything about this entry's data fails only the entry
                    Error::Io(io) if io.kind() != std::io::ErrorKind::UnexpectedEof => {
                        finish_dirs(&mut summary);
                        return Err(Error::Io(io));
                    }
                    Error::Io(_) => fail(&mut summary, &mut report, &e.name, &Error::Truncated.to_string()),
                    other => fail(&mut summary, &mut report, &e.name, &other.to_string()),
                }
            }
        }
    }
    finish_dirs(&mut summary);
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{self, Write};
    use std::ops::Range;

    fn sparse_directory(entries: u16, comment_len: u16, directory_size: u32) -> (tempfile::NamedTempFile, u64) {
        let mut archive = tempfile::NamedTempFile::new().unwrap();
        let mut central = [0; 50];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[28..30].copy_from_slice(&4u16.to_le_bytes());
        central[32..34].copy_from_slice(&comment_len.to_le_bytes());
        central[46..].copy_from_slice(b"item");
        for ordinal in 0..u64::from(entries) {
            let at = 30 + ordinal * (50 + u64::from(comment_len));
            archive.seek(SeekFrom::Start(at)).unwrap();
            archive.write_all(&central).unwrap();
        }

        let mut end = [0; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8..10].copy_from_slice(&entries.to_le_bytes());
        end[10..12].copy_from_slice(&entries.to_le_bytes());
        end[12..16].copy_from_slice(&directory_size.to_le_bytes());
        end[16..20].copy_from_slice(&30u32.to_le_bytes());
        archive.seek(SeekFrom::Start(30 + u64::from(directory_size))).unwrap();
        archive.write_all(&end).unwrap();
        (archive, 30 + u64::from(directory_size) + 22)
    }

    #[derive(Default)]
    struct ReadTrace {
        at: u64,
        ranges: Vec<Range<u64>>,
    }

    struct TracedFile<'a> {
        file: File,
        trace: ReadTrace,
        cancel_on_read_at: Option<(u64, &'a Cancellation)>,
    }

    impl Read for TracedFile<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.file.read(buf)?;
            let at = self.trace.at;
            self.trace.at += n as u64;
            self.trace.ranges.push(at..self.trace.at);
            if let Some((target, cancel)) = self.cancel_on_read_at
                && at == target
            {
                cancel.cancel();
            }
            Ok(n)
        }
    }

    impl Seek for TracedFile<'_> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.trace.at = self.file.seek(pos)?;
            Ok(self.trace.at)
        }
    }

    fn read_traced_directory(
        file: &mut TracedFile<'_>,
        len: u64,
        cancel: Option<&Cancellation>,
    ) -> Result<Directory<ZipEntry>> {
        let parser = DirectoryParser::with_projection_and_name_crc32(
            len,
            Profile::Zipfast,
            Limits::default(),
            crate::crc32::hash,
            project_record,
        )
        .unwrap();
        read_directory(file, len, parser, cancel)
    }

    #[test]
    fn cancelable_open_accepts_a_large_directory_with_a_noncentral_trailer() {
        let (file, _) = sparse_directory(2, 0, 128 << 20);
        let cancel = Cancellation::default();
        let archive = Archive::open_cancelable(file.path(), Some(&cancel)).unwrap();
        assert_eq!(archive.entries.len(), 2);
        assert!(archive.entries.iter().all(|entry| entry.name == "item"));
    }

    #[test]
    fn directory_driver_bounds_source_requests_and_avoids_local_payloads() {
        const COUNT: u16 = 260;
        let (file, len) = sparse_directory(COUNT, u16::MAX, u32::from(COUNT) * (50 + u32::from(u16::MAX)));
        let mut file =
            TracedFile { file: file.reopen().unwrap(), trace: ReadTrace::default(), cancel_on_read_at: None };
        let parsed = read_traced_directory(&mut file, len, None).unwrap();
        assert_eq!(parsed.entries.len(), usize::from(COUNT));
        let sizes = file.trace.ranges.iter().map(|r| r.end - r.start);
        assert!(sizes.clone().max().unwrap() <= 16 << 20);
        assert!(file.trace.ranges.iter().all(|r| r.start >= 30 && r.end <= len));
        assert_eq!(sizes.sum::<u64>(), parsed.usage.fetched_bytes);
        assert!((16 << 20..=129 << 20).contains(&parsed.usage.fetched_bytes));
    }

    #[test]
    fn directory_byte_limit_stops_before_reading_the_sparse_directory() {
        let (file, len) = sparse_directory(2, 0, (128 << 20) + 1);
        let mut file =
            TracedFile { file: file.reopen().unwrap(), trace: ReadTrace::default(), cancel_on_read_at: None };
        assert!(matches!(read_traced_directory(&mut file, len, None), Err(Error::Unsupported(_))));
        assert_eq!(file.trace.ranges, vec![len - 65_633..len]);
    }

    #[test]
    fn directory_driver_stops_at_the_first_canceled_chunk() {
        let (file, len) = sparse_directory(2, 0, 128 << 20);
        let cancel = Cancellation::default();
        let mut file = TracedFile {
            file: file.reopen().unwrap(),
            trace: ReadTrace::default(),
            cancel_on_read_at: Some((76, &cancel)),
        };
        assert!(matches!(
            read_traced_directory(&mut file, len, Some(&cancel)),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::ConnectionAborted
        ));
        assert_eq!(file.trace.ranges.last(), Some(&(76..76 + (64 << 10))));
    }

    #[test]
    fn canceled_open_does_not_read_directory_metadata() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), [0; 22]).unwrap();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            Archive::open_cancelable(file.path(), Some(&cancel)),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::ConnectionAborted
        ));
    }

    #[test]
    fn dos_times() {
        // 2024-02-29 13:37:58
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = (13 << 11) | (37 << 5) | 29;
        assert_eq!(dos_time(time, date), Some(1_709_213_878));
        assert_eq!(dos_time(0, 0), None);
    }

    #[test]
    fn names() {
        assert_eq!(decode_name(b"caf\x82", false).unwrap(), "café");
        assert_eq!(decode_name("café".as_bytes(), false).unwrap(), "café");
        assert_eq!(decode_name(b"a\xffb", true).unwrap(), "a\u{fffd}b");
    }
}
