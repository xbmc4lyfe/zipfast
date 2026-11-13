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

#[cfg(test)]
#[path = "verify/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "verify/aes_tests.rs"]
mod aes_tests;

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use flate2::{Decompress, FlushDecompress, Status};
use zip_container::{
    CentralRecord, Directory, DirectoryDeclaration, DirectoryError, DirectoryLocation, DirectoryParser, EndDiscovery,
    EndRecord, ExtraIter, LOCAL_HEADER_LEN, LocalHeader, Profile, Zip64End, Zip64Locator, local_layout,
};

use crate::crc32::Hasher;
use crate::crypto::{WinZipAesEncryptor, ZipCrypto};
use crate::zip::{FLAG_DESCRIPTOR, FLAG_ENCRYPTED, FLAG_UTF8, HOST_UNIX, METHOD_DEFLATE, METHOD_STORED, S_IFDIR};

use super::{
    Attempts, CreateError, CreateLimit, CreateLimits, CreateOptions, PlannedEntry, Result, Stamp, VerificationUsage,
    add, limit, unix,
};
use crate::zip::write::{AesStrength, AesVariant, EntryWritten, InputLength, Method, WinZipAesRequest, WriteSummary};

const BUFFER: usize = 64 << 10;
pub(in crate::zip) const DISCOVERY_TAIL_BYTES: u64 = 22 + u16::MAX as u64 + 56 + 20;
const MAX_EXTRA: usize = 48;
const ZIPCRYPTO_HEADER: u64 = 12;
const SIZE_SENTINEL: u64 = u32::MAX as u64;

#[derive(Debug)]
pub(super) struct VerifiedCreation {
    pub(super) stamp: Stamp,
}

#[derive(Clone, Copy)]
pub(super) struct ZipCryptoExpectation<'a> {
    pub(super) password: &'a str,
    pub(super) length: InputLength,
}

#[derive(Clone, Copy)]
pub(super) struct AesExpectation<'a> {
    pub(super) request: &'a WinZipAesRequest<'a>,
    pub(super) length: InputLength,
    pub(super) plaintext_crc32: u32,
}

#[derive(Clone, Copy)]
pub(super) enum EncryptionExpectation<'a> {
    ZipCrypto(ZipCryptoExpectation<'a>),
    Aes(AesExpectation<'a>),
}

impl<'a> From<ZipCryptoExpectation<'a>> for EncryptionExpectation<'a> {
    fn from(value: ZipCryptoExpectation<'a>) -> Self {
        Self::ZipCrypto(value)
    }
}

impl<'a> From<AesExpectation<'a>> for EncryptionExpectation<'a> {
    fn from(value: AesExpectation<'a>) -> Self {
        Self::Aes(value)
    }
}

impl EncryptionExpectation<'_> {
    fn length(self) -> InputLength {
        match self {
            Self::ZipCrypto(mode) => mode.length,
            Self::Aes(mode) => mode.length,
        }
    }
    fn aes(self) -> Option<(AesStrength, AesVariant)> {
        match self {
            Self::ZipCrypto(_) => None,
            Self::Aes(mode) => {
                let (_, strength, variant) = mode.request.parameters();
                Some((strength, variant))
            }
        }
    }
    fn overhead(self) -> u64 {
        match self {
            Self::ZipCrypto(_) => ZIPCRYPTO_HEADER,
            Self::Aes(_) => self.aes().expect("AES mode").0.overhead(),
        }
    }
}

pub(super) fn verify_created<'a>(
    file: &mut File,
    members: (&[PlannedEntry], &[EntryWritten]),
    options: &CreateOptions,
    summary: WriteSummary,
    attempts: &Attempts<'_>,
    usage: &mut VerificationUsage,
    mut encryption: impl FnMut(usize) -> Option<EncryptionExpectation<'a>>,
) -> Result<VerifiedCreation> {
    let (entries, receipts) = members;
    let stamp = unix::file_stamp(file, attempts)?;
    ensure(
        stamp.len == summary.usage.archive_extent
            && entries.len() == receipts.len()
            && entries.len() as u64 == summary.usage.entries,
        "wrong created archive length or receipt count",
    )?;
    let mut reader =
        Reader { file, limits: options.limits, archive_comment: &options.archive_comment, attempts, usage };
    let mut input = [0; BUFFER];
    // Drop each default discovery's buffers and raw comment before
    // materializing the strict directory. Keep only its checked geometry.
    let ordinary = [
        reader.discover(stamp.len, Profile::Zipfast, &mut input)?,
        reader.discover(stamp.len, Profile::Zipview, &mut input)?,
    ];
    let directory = reader.read_directory(stamp.len, entries, &mut input)?;
    check_directory(&directory, receipts.len(), summary, &options.archive_comment)?;
    for (profile, observed) in [Profile::Zipfast, Profile::Zipview].into_iter().zip(ordinary) {
        if !observed.agrees(&directory) || directory.prefix_shift != 0 {
            return Err(CreateError::AmbiguousDirectory { profile });
        }
    }
    reader.usage.metadata_bytes = options.archive_comment.len() as u64;

    let mut local_at = 0;
    let mut central_at = directory.directory_range.start;
    let mut wide_entry = false;
    for (ordinal, ((central, expected), receipt)) in directory.entries.iter().zip(entries).zip(receipts).enumerate() {
        ensure(
            receipt.ordinal == ordinal as u64
                && receipt.local_offset == local_at
                && central.source.raw_range().start == central_at
                && central.source.raw_range() == central.source.declared_range(),
            "entry order, offset or extent differs from the plan",
        )?;
        let metadata = u64::from(central.header.name_len)
            + u64::from(central.header.comment_len)
            + u64::from(central.header.extra_len);
        reader.usage.metadata_bytes = add(reader.usage.metadata_bytes, metadata)?;
        limit(reader.usage.metadata_bytes, options.limits.verification_metadata, CreateLimit::VerificationMetadata)?;
        let next = receipts.get(ordinal + 1).map_or(directory.directory_range.start, |next| next.local_offset);
        ensure(next <= directory.directory_range.start, "local records overlap the central directory")?;
        wide_entry |= reader.check_member(central, expected, receipt, next, &mut input, encryption(ordinal))?;
        local_at = next;
        central_at = central.source.raw_range().end;
        reader.usage.entries += 1;
    }
    let expected_wide = wide_entry
        || receipts.len() >= u16::MAX as usize
        || directory.declaration.size >= SIZE_SENTINEL
        || directory.declaration.offset >= SIZE_SENTINEL;
    ensure(
        local_at == directory.directory_range.start
            && central_at == directory.directory_range.end
            && summary.zip64 == expected_wide,
        "gap in local or central records or wrong ZIP64 end policy",
    )?;
    if unix::file_stamp(reader.file, reader.attempts)? != stamp {
        return Err(CreateError::StageChanged);
    }
    Ok(VerifiedCreation { stamp })
}

pub(in crate::zip) fn check_directory(
    directory: &Directory,
    entries: usize,
    summary: WriteSummary,
    expected_comment: &[u8],
) -> Result<()> {
    let end = &directory.end_record;
    let declared = directory.declaration;
    let central = &directory.directory_range;
    ensure(
        directory.prefix_shift == 0
            && directory.entries.len() == entries
            && declared.entries == entries as u64
            && declared.size == summary.usage.central_bytes
            && declared.offset == summary.central_offset
            && central.start == declared.offset
            && central.end == add(declared.offset, declared.size)?
            && directory.observed_range == *central
            && directory.logical_range == *central
            && end.disk == 0
            && end.directory_disk == 0
            && end.comment_len as usize == expected_comment.len()
            && directory.raw_comment == expected_comment
            && directory.comment_range.start == end.source.end
            && directory.comment_range.end == directory.archive_len,
        "wrong central directory, end record or archive comment",
    )?;
    if summary.zip64 {
        let wide = directory.zip64_end.as_ref().ok_or(CreateError::Verification("missing ZIP64 end"))?;
        let locator = directory.zip64_locator.as_ref().ok_or(CreateError::Verification("missing ZIP64 locator"))?;
        ensure(
            end.entries == u16::MAX
                && end.disk_entries == u16::MAX
                && end.size == u32::MAX
                && end.offset == u32::MAX
                && wide.source.start == central.end
                && wide.source.end == locator.source.start
                && locator.source.end == end.source.start
                && wide.body_size == 44
                && wide.extension.is_empty()
                && wide.version_made_by == (u16::from(HOST_UNIX) << 8 | 45)
                && wide.version_needed == 45
                && wide.disk == 0
                && wide.directory_disk == 0
                && wide.disk_entries == declared.entries
                && wide.declaration == declared
                && locator.disk == 0
                && locator.total_disks == 1
                && locator.record_offset == wide.source.start,
            "wrong ZIP64 end framing",
        )
    } else {
        ensure(
            directory.zip64_end.is_none()
                && directory.zip64_locator.is_none()
                && end.source.start == central.end
                && u64::from(end.entries) == declared.entries
                && u64::from(end.disk_entries) == declared.entries
                && u64::from(end.size) == declared.size
                && u64::from(end.offset) == declared.offset,
            "wrong classic end framing",
        )
    }
}

#[derive(PartialEq, Eq)]
pub(in crate::zip) struct Geometry {
    end: EndRecord,
    zip64_end: Option<Zip64End>,
    locator: Option<Zip64Locator>,
    declaration: DirectoryDeclaration,
    directory: std::ops::Range<u64>,
    prefix_shift: u64,
    comment: std::ops::Range<u64>,
}

impl Geometry {
    pub(in crate::zip) fn from_location(located: &DirectoryLocation) -> Self {
        Self {
            end: located.end_record().clone(),
            zip64_end: located.zip64_end().cloned(),
            locator: located.zip64_locator().cloned(),
            declaration: located.declaration(),
            directory: located.directory_range(),
            prefix_shift: located.prefix_shift(),
            comment: located.comment_range(),
        }
    }

    pub(in crate::zip) fn eocd(&self) -> u64 {
        self.end.source.start
    }
    pub(in crate::zip) fn comment_end(&self) -> u64 {
        self.comment.end
    }
    pub(in crate::zip) fn metadata_wire_bytes(&self) -> Option<u64> {
        self.declaration
            .size
            .checked_sub(self.declaration.entries.checked_mul(46)?)?
            .checked_add(u64::from(self.end.comment_len))
    }

    pub(in crate::zip) fn agrees(&self, strict: &Directory) -> bool {
        self.end == strict.end_record
            && self.zip64_end == strict.zip64_end
            && self.locator == strict.zip64_locator
            && self.declaration == strict.declaration
            && self.directory == strict.directory_range
            && self.prefix_shift == strict.prefix_shift
            && self.comment == strict.comment_range
    }
}

struct Framing {
    method: u16,
    outer_method: u16,
    aes: Option<(AesStrength, AesVariant)>,
    version: u16,
    flags: u16,
    dos: (u16, u16),
    attributes: u32,
    wide_sizes: bool,
    wide_offset: bool,
    encrypted: bool,
}

impl Framing {
    fn new(
        entry: &PlannedEntry,
        receipt: &EntryWritten,
        encryption: Option<EncryptionExpectation<'_>>,
    ) -> Result<Self> {
        let source = entry.payload_source();
        let decoded = source.map_or(0, |source| source.stamp.len);
        if let Some(encryption) = encryption {
            ensure(source.is_some(), "a directory cannot have encrypted framing")?;
            if let InputLength::Exact(size) = encryption.length() {
                ensure(size == decoded, "encrypted writer length differs from the source")?;
            }
        }
        let overhead = encryption.map_or(0, EncryptionExpectation::overhead);
        let aes = encryption.and_then(EncryptionExpectation::aes);
        let plaintext_crc32 = match encryption {
            Some(EncryptionExpectation::Aes(mode)) => mode.plaintext_crc32,
            _ => receipt.crc32,
        };
        ensure(
            receipt.crc32 == aes.map_or(plaintext_crc32, |(_, variant)| variant.wire_crc(plaintext_crc32)),
            "wire CRC differs from the encryption policy",
        )?;
        let expected_method = if decoded == 0 { Method::Stored } else { entry.method };
        ensure(
            receipt.decoded_size == decoded
                && receipt.method == expected_method
                && (decoded != 0 || (plaintext_crc32 == 0 && receipt.packed_size == overhead))
                && receipt.packed_size >= overhead,
            "writer receipt differs from the expected source framing",
        )?;
        let method = match receipt.method {
            Method::Stored => {
                ensure(receipt.packed_size == add(decoded, overhead)?, "Stored payload sizes differ")?;
                METHOD_STORED
            }
            Method::Deflate(_) => METHOD_DEFLATE,
        };
        let wide_sizes = method == METHOD_DEFLATE
            || receipt.packed_size >= SIZE_SENTINEL
            || (decoded != 0 && encryption.is_some_and(|mode| mode.length() == InputLength::Unknown));
        let wide_offset = receipt.local_offset >= SIZE_SENTINEL;
        let (kind, dos_attributes) = if entry.payload_source().is_some() { (0o100000, 0) } else { (S_IFDIR, 0x10) };
        Ok(Self {
            method,
            outer_method: if aes.is_some() { 99 } else { method },
            aes,
            version: if wide_sizes || wide_offset { 45 } else { 20 },
            flags: (if entry.utf8 { FLAG_UTF8 } else { 0 })
                | (if encryption.is_some() { FLAG_DESCRIPTOR | FLAG_ENCRYPTED } else { 0 }),
            dos: entry.modified.wire_fields(),
            attributes: ((kind | u32::from(entry.permissions.bits())) << 16) | dos_attributes,
            wide_sizes,
            wide_offset,
            encrypted: encryption.is_some(),
        })
    }

    fn size_field(&self, size: u64) -> u32 {
        if self.wide_sizes { u32::MAX } else { size as u32 }
    }

    fn valid_flags(&self, flags: u16) -> bool {
        // Bit 1/2 may indicate a Deflate level hint. The plan selects EFS
        // and whether encrypted descriptor framing is required.
        let hints = if self.method == METHOD_DEFLATE { 0b110 } else { 0 };
        flags & !hints == self.flags
    }
}

struct Member<'a> {
    central: &'a CentralRecord,
    expected: &'a PlannedEntry,
    receipt: &'a EntryWritten,
    framing: Framing,
}

impl Member<'_> {
    fn check_central(&self, reader: &mut Reader<'_, '_>) -> Result<()> {
        let header = self.central.header;
        let resolved = self.central.resolved;
        let expected = self.expected;
        let receipt = self.receipt;
        let framing = &self.framing;
        ensure(
            self.central.raw_name.as_ref() == expected.name
                && self.central.raw_comment.as_ref() == expected.comment
                && header.name_len as usize == expected.name.len()
                && header.comment_len as usize == expected.comment.len()
                && framing.valid_flags(header.flags)
                && header.method == framing.outer_method
                && (header.mod_time, header.mod_date) == framing.dos
                && header.version_needed == framing.version
                && header.version_made_by == (u16::from(HOST_UNIX) << 8 | framing.version)
                && header.crc32 == receipt.crc32
                && header.packed_size == framing.size_field(receipt.packed_size)
                && header.unpacked_size == framing.size_field(receipt.decoded_size)
                && header.local_header_offset
                    == if framing.wide_offset { u32::MAX } else { receipt.local_offset as u32 }
                && header.disk_start == 0
                && header.internal_attributes == 0
                && header.external_attributes == framing.attributes
                && resolved.unresolved == zip_container::Zip64Fields::default()
                && resolved.packed_size == receipt.packed_size
                && resolved.unpacked_size == receipt.decoded_size
                && resolved.local_header_offset == receipt.local_offset
                && resolved.disk_start == 0,
            "central header or metadata differs from the plan and receipt",
        )?;
        let extra_at = self.central.source.extra_range().start;
        if header.extra_len != 0 {
            reader.seek(extra_at)?;
        }
        self.check_extras(reader, header.extra_len, extra_at, true)
    }

    fn check_local(&self, reader: &mut Reader<'_, '_>, boundary: u64, buffer: &mut [u8]) -> Result<u64> {
        let receipt = self.receipt;
        let framing = &self.framing;
        let offset = receipt.local_offset;
        ensure(add(offset, LOCAL_HEADER_LEN as u64)? <= boundary, "local header overlaps the next record")?;
        reader.seek(offset)?;
        let mut fixed = [0; LOCAL_HEADER_LEN];
        reader.read_exact(&mut fixed)?;
        let local = LocalHeader::parse(&fixed).map_err(|error| CreateError::Directory(error.into()))?;
        let layout = local_layout(local, offset, boundary).map_err(|error| CreateError::Directory(error.into()))?;
        let local_crc = if framing.encrypted { 0 } else { receipt.crc32 };
        let (local_packed, local_decoded) =
            if framing.encrypted { (0, 0) } else { (receipt.packed_size, receipt.decoded_size) };
        ensure(
            local.version_needed == framing.version
                && local.flags == self.central.header.flags
                && local.method == framing.outer_method
                && (local.mod_time, local.mod_date) == framing.dos
                && local.crc32 == local_crc
                && local.packed_size == framing.size_field(local_packed)
                && local.unpacked_size == framing.size_field(local_decoded)
                && local.name_len as usize == self.expected.name.len(),
            "local header differs from the central header",
        )?;
        let payload = layout
            .payload_range(receipt.packed_size, boundary)
            .map_err(|error| CreateError::Directory(error.into()))?;
        let name = &mut buffer[..self.expected.name.len()];
        reader.read_exact(name)?;
        ensure(name == self.expected.name, "local name differs from the central name")?;
        self.check_extras(reader, local.extra_len, layout.extra_range().start, false)?;
        Ok(payload.end)
    }

    fn check_extras(&self, reader: &mut Reader<'_, '_>, len: u16, at: u64, central: bool) -> Result<()> {
        let mut data = [0; MAX_EXTRA];
        let data = data.get_mut(..usize::from(len)).ok_or(CreateError::Verification("unexpected extra fields"))?;
        reader.read_exact(data)?;
        let mut fields = ExtraIter::new(data, at).map_err(|error| CreateError::Directory(error.into()))?;
        let offset = central && self.framing.wide_offset;
        if self.framing.wide_sizes || offset {
            let field = fields
                .next()
                .transpose()
                .map_err(|error| CreateError::Directory(error.into()))?
                .ok_or(CreateError::Verification("missing ZIP64 extra"))?;
            let mut body = field.body;
            ensure(field.id == 1, "unexpected ZIP64 extra ID")?;
            if self.framing.wide_sizes {
                let provisional = self.framing.encrypted && !central;
                expect_qword(&mut body, if provisional { 0 } else { self.receipt.decoded_size })?;
                expect_qword(&mut body, if provisional { 0 } else { self.receipt.packed_size })?;
            }
            if offset {
                expect_qword(&mut body, self.receipt.local_offset)?;
            }
            ensure(body.is_empty(), "unexpected ZIP64 extra bytes")?;
        }
        if let Some(mtime) = self.expected.extended_mtime {
            let field = fields
                .next()
                .transpose()
                .map_err(|error| CreateError::Directory(error.into()))?
                .ok_or(CreateError::Verification("missing modification-time extra"))?;
            ensure(
                field.id == 0x5455
                    && field.body.len() == 5
                    && field.body[0] == 1
                    && field.body[1..] == mtime.to_le_bytes(),
                "wrong modification-time extra",
            )?;
        }
        if let Some((strength, variant)) = self.framing.aes {
            let field = fields
                .next()
                .transpose()
                .map_err(|error| CreateError::Directory(error.into()))?
                .ok_or(CreateError::Verification("missing AES extra"))?;
            let mut expected = [0; 7];
            expected[..2].copy_from_slice(&variant.wire().to_le_bytes());
            expected[2..4].copy_from_slice(b"AE");
            expected[4] = strength.wire();
            expected[5..].copy_from_slice(&self.framing.method.to_le_bytes());
            ensure(field.id == 0x9901 && field.body == expected, "AES extra differs from the request")?;
        }
        ensure(fields.next().is_none(), "unexpected or duplicate extra field")
    }
}

fn expect_qword(bytes: &mut &[u8], expected: u64) -> Result<()> {
    let (field, rest) = bytes.split_at_checked(8).ok_or(CreateError::Verification("short ZIP64 extra"))?;
    *bytes = rest;
    ensure(field == expected.to_le_bytes(), "wrong ZIP64 extra value")
}

pub(in crate::zip) struct Reader<'a, 'b> {
    file: &'a mut File,
    limits: CreateLimits,
    archive_comment: &'a [u8],
    attempts: &'a Attempts<'b>,
    usage: &'a mut VerificationUsage,
}

#[derive(Clone, Copy)]
pub(in crate::zip) struct Payload {
    pub(crate) method: u16,
    pub(crate) packed_size: u64,
    pub(crate) decoded_size: u64,
    pub(crate) crc32: u32,
}

impl From<EntryWritten> for Payload {
    fn from(receipt: EntryWritten) -> Self {
        let method = match receipt.method {
            Method::Stored => METHOD_STORED,
            Method::Deflate(_) => METHOD_DEFLATE,
        };
        Self { method, packed_size: receipt.packed_size, decoded_size: receipt.decoded_size, crc32: receipt.crc32 }
    }
}

impl<'a, 'b> Reader<'a, 'b> {
    pub(in crate::zip) fn new(
        file: &'a mut File,
        limits: CreateLimits,
        attempts: &'a Attempts<'b>,
        usage: &'a mut VerificationUsage,
    ) -> Self {
        Self { file, limits, archive_comment: &[], attempts, usage }
    }

    pub(in crate::zip) fn check_new(
        &mut self,
        central: &CentralRecord,
        expected: &PlannedEntry,
        receipt: &EntryWritten,
        boundary: u64,
        buffer: &mut [u8],
    ) -> Result<bool> {
        self.check_member(central, expected, receipt, boundary, buffer, None)
    }

    fn check_member(
        &mut self,
        central: &CentralRecord,
        expected: &PlannedEntry,
        receipt: &EntryWritten,
        boundary: u64,
        buffer: &mut [u8],
        encryption: Option<EncryptionExpectation<'_>>,
    ) -> Result<bool> {
        let framing = Framing::new(expected, receipt, encryption)?;
        let record = Member { central, expected, receipt, framing };
        record.check_central(self)?;
        let payload_end = record.check_local(self, boundary, buffer)?;
        let wide = record.framing.wide_sizes;
        let descriptor_len = if encryption.is_some() { if wide { 24 } else { 16 } } else { 0 };
        ensure(add(payload_end, descriptor_len)? == boundary, "new entry leaves a gap or overlaps the next record")?;
        if expected.payload_source().is_some() {
            let mut payload = Payload::from(*receipt);
            if let Some(EncryptionExpectation::Aes(mode)) = encryption {
                payload.crc32 = mode.plaintext_crc32;
            }
            self.verify_payload(payload, buffer, encryption, (record.framing.dos.0 >> 8) as u8)?;
            if encryption.is_some() {
                let mut descriptor = [0; 24];
                let descriptor = &mut descriptor[..descriptor_len as usize];
                self.read_exact(descriptor)?;
                ensure(
                    crate::zip::descriptor_matches(
                        descriptor,
                        wide,
                        true,
                        receipt.crc32,
                        (receipt.packed_size, receipt.decoded_size),
                    ),
                    "signed data descriptor differs from the receipt",
                )?;
            }
            self.usage.payloads += 1;
        }
        Ok(record.framing.version == 45)
    }

    pub(in crate::zip) fn check_payload(&mut self, at: u64, payload: Payload, buffer: &mut [u8]) -> Result<()> {
        self.seek(at)?;
        self.verify_payload(payload, buffer, None, 0)?;
        self.usage.payloads += 1;
        Ok(())
    }

    fn seek(&mut self, at: u64) -> Result<()> {
        let actual = self.attempts.run(|| {
            #[cfg(test)]
            super::tests::event_io(super::tests::Event::VerifySeek, None)?;
            self.file.seek(SeekFrom::Start(at))
        })?;
        ensure(actual == at, "stage seek reached the wrong offset")
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        let maximum = self.limits.verification_read_bytes;
        limit(add(self.usage.read_bytes, bytes.len() as u64)?, maximum, CreateLimit::VerificationReadBytes)?;
        while !bytes.is_empty() {
            let count = self.attempts.run(|| {
                #[cfg(test)]
                super::tests::event_io(super::tests::Event::VerifyRead, None)?;
                #[cfg(test)]
                let size = bytes.len().min(super::tests::verify_read_cap());
                #[cfg(not(test))]
                let size = bytes.len();
                self.file.read(&mut bytes[..size])
            })?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            self.usage.read_bytes = add(self.usage.read_bytes, count as u64)?;
            bytes = &mut bytes[count..];
        }
        Ok(())
    }

    fn read_directory(&mut self, len: u64, entries: &[PlannedEntry], buffer: &mut [u8]) -> Result<Directory> {
        let limits = self.limits;
        let comment = self.archive_comment;
        let mut parser_limits = self.parser_budget()?;
        parser_limits.entries = parser_limits.entries.min(limits.directory_entries()).min(entries.len() as u64);
        // Only the exact expected raw name and comment totals may be owned.
        // The admitted extra types use scalar projections, with no owned
        // variable-length Unicode path or other variable-length summary.
        let mut names = 0;
        let mut comments = comment.len() as u64;
        for entry in entries {
            self.attempts.check_cancel()?;
            names = add(names, entry.name.len() as u64)?;
            comments = add(comments, entry.comment.len() as u64)?;
        }
        parser_limits.name_bytes = parser_limits.name_bytes.min(names);
        parser_limits.comment_bytes = parser_limits.comment_bytes.min(comments);
        parser_limits.extra_bytes = 0;
        let eocd = len
            .checked_sub(22 + comment.len() as u64)
            .ok_or(CreateError::Verification("archive is too short for the expected end and comment"))?;
        let mut parser = DirectoryParser::at_eocd_with_scratch_limit(len, eocd, parser_limits, self.scratch_limit())
            .map_err(parser_error)?;
        let mut at = None;
        loop {
            self.check_parser(&parser)?;
            let request = parser.next_read();
            self.check_parser(&parser)?;
            let Some(range) = request.map_err(parser_error)? else { break };
            let size = (range.end - range.start).min(buffer.len() as u64) as usize;
            ensure(size != 0 && range.end <= len, "parser requested invalid stage range")?;
            if at != Some(range.start) {
                self.seek(range.start)?;
            }
            self.read_exact(&mut buffer[..size])?;
            at = Some(range.start + size as u64);
            let supplied = parser.supply(range.start, &buffer[..size]);
            self.check_parser(&parser)?;
            supplied.map_err(parser_error)?;
        }
        let directory = parser.finish().map_err(parser_error)?;
        self.usage.record_capacity = directory.entries.capacity() as u64 * size_of::<CentralRecord>() as u64;
        limit(self.usage.record_capacity, limits.verification_records, CreateLimit::VerificationRecords)?;
        Ok(directory)
    }

    fn parser_budget(&self) -> Result<zip_container::Limits> {
        let mut limits = self.limits.directory;
        limits.fetched_bytes =
            limits.fetched_bytes.checked_sub(self.usage.discovery_bytes).ok_or(CreateError::Overflow)?;
        limits.work_units = limits.work_units.checked_sub(self.usage.discovery_work).ok_or(CreateError::Overflow)?;
        Ok(limits)
    }

    fn discover(&mut self, len: u64, profile: Profile, buffer: &mut [u8]) -> Result<Geometry> {
        let mut limits = self.parser_budget()?;
        limits.comment_bytes = limits.comment_bytes.min(self.archive_comment.len() as u64);
        let baseline_bytes = self.usage.discovery_bytes;
        let baseline_work = self.usage.discovery_work;
        let ambiguity = || CreateError::AmbiguousDirectory { profile };
        let classify = |error| match error {
            DirectoryError::Limit(_) | DirectoryError::Allocation => parser_error(error),
            _ => ambiguity(),
        };
        let mut discovery =
            EndDiscovery::new_with_scratch_limit(len, profile, limits, self.scratch_limit()).map_err(classify)?;
        loop {
            self.attempts.check_cancel()?;
            let request = discovery.next_read();
            let usage = discovery.usage();
            self.usage.discovery_bytes = add(baseline_bytes, usage.fetched_bytes)?;
            self.usage.discovery_work = add(baseline_work, usage.work_units)?;
            self.observe_scratch(discovery.buffer_usage().capacity_bytes);
            let Some(range) = request.map_err(classify)? else { break };
            let size = (range.end - range.start).min(buffer.len() as u64) as usize;
            ensure(size != 0 && range.end <= len, "discovery requested invalid stage range")?;
            self.seek(range.start)?;
            self.read_exact(&mut buffer[..size])?;
            let supplied = discovery.supply(range.start, &buffer[..size]);
            let usage = discovery.usage();
            self.usage.discovery_bytes = add(baseline_bytes, usage.fetched_bytes)?;
            self.usage.discovery_work = add(baseline_work, usage.work_units)?;
            self.observe_scratch(discovery.buffer_usage().capacity_bytes);
            supplied.map_err(classify)?;
        }
        let located = discovery.finish().map_err(classify)?;
        if located.raw_comment() != self.archive_comment {
            return Err(ambiguity());
        }
        Ok(Geometry::from_location(&located))
    }

    fn check_parser(&mut self, parser: &DirectoryParser) -> Result<()> {
        self.attempts.check_cancel()?;
        self.usage.directory = parser.usage();
        self.observe_scratch(parser.buffer_usage().capacity_bytes);
        Ok(())
    }

    fn scratch_limit(&self) -> usize {
        usize::try_from(self.limits.verification_scratch).unwrap_or(usize::MAX)
    }

    fn observe_scratch(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.scratch_limit());
        self.usage.scratch_capacity = self.usage.scratch_capacity.max(bytes as u64);
    }

    fn verify_payload(
        &mut self,
        receipt: Payload,
        buffer: &mut [u8],
        encryption: Option<EncryptionExpectation<'_>>,
        password_check: u8,
    ) -> Result<()> {
        let mut remaining = receipt.packed_size;
        let mut cipher = if let Some(EncryptionExpectation::ZipCrypto(mode)) = encryption {
            remaining =
                remaining.checked_sub(ZIPCRYPTO_HEADER).ok_or(CreateError::Verification("short ZipCrypto header"))?;
            let mut header = [0; ZIPCRYPTO_HEADER as usize];
            self.read_exact(&mut header)?;
            let mut cipher = ZipCrypto::new(mode.password);
            cipher.decrypt(&mut header);
            ensure(header[11] == password_check, "ZipCrypto password hint differs")?;
            Some(PayloadCipher::ZipCrypto(cipher))
        } else if let Some(EncryptionExpectation::Aes(mode)) = encryption {
            let (password, strength, _) = mode.request.parameters();
            remaining =
                remaining.checked_sub(strength.overhead()).ok_or(CreateError::Verification("short AES payload"))?;
            let mut header = [0; 18];
            let salt_len = strength.salt_bytes();
            self.read_exact(&mut header[..salt_len + 2])?;
            self.attempts.check_cancel()?;
            let cipher = WinZipAesEncryptor::new(password.as_bytes(), &header[..salt_len], strength.key_bytes())
                .ok_or(CreateError::Verification("invalid AES parameters"))?;
            self.attempts.check_cancel()?;
            use subtle::ConstantTimeEq;
            ensure(
                bool::from(cipher.verifier().ct_eq(&header[salt_len..salt_len + 2])),
                "AES password verifier differs",
            )?;
            Some(PayloadCipher::Aes(cipher))
        } else {
            None
        };
        let mut decoded = 0;
        let mut crc = Hasher::new();
        if receipt.method == METHOD_STORED {
            while remaining != 0 {
                let len = remaining.min(buffer.len() as u64) as usize;
                self.read_packed(&mut buffer[..len], &mut cipher)?;
                self.decoded(&mut crc, &mut decoded, receipt, &buffer[..len])?;
                remaining -= len as u64;
            }
        } else {
            ensure(receipt.method == METHOD_DEFLATE, "unsupported strict payload verification method")?;
            let mut inflate = Decompress::new(false);
            let mut output = [0; BUFFER];
            let mut current = 0..0;
            loop {
                if current.is_empty() && remaining != 0 {
                    let len = remaining.min(buffer.len() as u64) as usize;
                    self.read_packed(&mut buffer[..len], &mut cipher)?;
                    remaining -= len as u64;
                    current = 0..len;
                }
                self.attempts.charge()?;
                let (before_in, before_out) = (inflate.total_in(), inflate.total_out());
                let status = inflate
                    .decompress(&buffer[current.clone()], &mut output, FlushDecompress::None)
                    .map_err(|_| CreateError::Verification("invalid raw Deflate payload"))?;
                let used = codec_delta(inflate.total_in(), before_in, current.len())?;
                let made = codec_delta(inflate.total_out(), before_out, output.len())?;
                current.start += used;
                self.decoded(&mut crc, &mut decoded, receipt, &output[..made])?;
                if status == Status::StreamEnd {
                    ensure(current.is_empty() && remaining == 0, "trailing bytes in packed Deflate range")?;
                    break;
                }
                ensure(used != 0 || made != 0, "truncated or stalled raw Deflate payload")?;
            }
        }
        if let Some(PayloadCipher::Aes(cipher)) = cipher {
            let mut tag = [0; 10];
            self.read_exact(&mut tag)?;
            use subtle::ConstantTimeEq;
            ensure(bool::from(cipher.tag().ct_eq(&tag)), "AES authentication tag differs")?;
        }
        ensure(decoded == receipt.decoded_size && crc.finalize() == receipt.crc32, "decoded length or CRC differs")
    }

    fn read_packed(&mut self, buffer: &mut [u8], cipher: &mut Option<PayloadCipher>) -> Result<()> {
        self.read_exact(buffer)?;
        if let Some(cipher) = cipher {
            match cipher {
                PayloadCipher::ZipCrypto(cipher) => cipher.decrypt(buffer),
                PayloadCipher::Aes(cipher) => {
                    cipher.decrypt(buffer).ok_or(CreateError::Overflow)?;
                }
            }
        }
        Ok(())
    }

    fn decoded(&mut self, crc: &mut Hasher, member: &mut u64, receipt: Payload, bytes: &[u8]) -> Result<()> {
        *member = add(*member, bytes.len() as u64)?;
        let aggregate = add(self.usage.decoded_bytes, bytes.len() as u64)?;
        limit(*member, self.limits.verification_entry_bytes, CreateLimit::VerificationEntryBytes)?;
        limit(aggregate, self.limits.verification_decoded_bytes, CreateLimit::VerificationDecodedBytes)?;
        ensure(*member <= receipt.decoded_size, "payload exceeds the declared decoded length")?;
        self.usage.decoded_bytes = aggregate;
        crc.update(bytes);
        Ok(())
    }
}

#[allow(clippy::large_enum_variant, reason = "fixed-size cipher state stays on the stack without an allocation")]
enum PayloadCipher {
    ZipCrypto(ZipCrypto),
    Aes(WinZipAesEncryptor),
}

fn parser_error(error: DirectoryError) -> CreateError {
    if error == DirectoryError::Limit(zip_container::LimitKind::ScratchBytes) {
        CreateError::Limit(CreateLimit::VerificationScratch)
    } else {
        CreateError::Directory(error)
    }
}

fn codec_delta(total: u64, previous: u64, maximum: usize) -> Result<usize> {
    total
        .checked_sub(previous)
        .filter(|&delta| delta <= maximum as u64)
        .map(|delta| delta as usize)
        .ok_or(CreateError::Verification("invalid decoder progress counters"))
}

fn ensure(condition: bool, reason: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(CreateError::Verification(reason)) }
}
