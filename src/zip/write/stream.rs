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

use crate::crypto::ZipCrypto;
use crate::zip::FLAG_ENCRYPTED;

use super::records::{End, Member, Width};
use super::{
    BUFFER, EntryOptions, EntryWritten, FileInput, Finished, InputLength, IoStage, Limit, Method, Output, WriteError,
    WriteSummary, WriteUsage, WriterOptions, add, archive_comment_len, bound, prepare_member, reserve_central,
};

const FLAG_DESCRIPTOR: u16 = 1 << 3;
const ZIPCRYPTO_HEADER: u64 = 12;

/// A fresh ZIP archive written forward to an owned or borrowed sink.
///
/// Nonempty files and ZipCrypto files have a signed data descriptor after
/// the payload. Clear empty files and directories use Stored without a descriptor. Call
/// [Self::finish] to write the central directory and flush the sink. Dropping
/// this writer leaves any provisional bytes in place.
pub struct ZipStreamWriter<W> {
    output: Output<W>,
    central: Vec<u8>,
    comment: Vec<u8>,
    comment_len: u16,
    wide_member: bool,
    failed: Option<Arc<WriteError>>,
}

impl<W: Write> ZipStreamWriter<W> {
    /// Starts at logical offset zero without calling the sink.
    ///
    /// The caller supplies a fresh logical stream. A file sink must be empty
    /// and positioned at zero. Existing bytes or position cannot be checked
    /// through [Write]. Pass a mutable reference to retain the sink on error.
    pub fn new(sink: W, options: WriterOptions<'_>) -> Result<Self, WriteError> {
        let comment_len = archive_comment_len(&options)?;
        let output = Output::new(sink, options.limits, options.cancel);
        output.check_tail(End::new(0, 0, 0, false, comment_len), 0)?;
        output.work.check_canceled()?;

        let mut comment = Vec::new();
        let metadata_capacity = options.limits.metadata_capacity;
        bound(u64::from(comment_len), metadata_capacity, Limit::MetadataCapacity)?;
        comment.try_reserve_exact(usize::from(comment_len)).map_err(WriteError::Allocation)?;
        bound(comment.capacity() as u64, metadata_capacity, Limit::MetadataCapacity)?;
        comment.extend_from_slice(options.comment);
        Ok(Self { output, central: Vec::new(), comment, comment_len, wide_member: false, failed: None })
    }

    /// Streams a regular file. Exact lengths require a one-byte EOF probe,
    /// including when the declared length is zero. A surplus probe byte is
    /// consumed and charged to the source budget. After preflight succeeds,
    /// any failure poisons the writer, even before the local header.
    pub fn add_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        input: &mut R,
        length: InputLength,
    ) -> Result<EntryWritten, WriteError> {
        let (member, entries) = self.prepare(options, length, false, false)?;
        let result = self.write_file(options, member, entries, FileInput { input, length, decoded: 0 }, None);
        self.remember_failure(result)
    }

    /// Streams a regular file using traditional ZIP encryption for legacy
    /// interoperability. ZipCrypto does not authenticate content.
    ///
    /// The password uses its UTF-8 bytes and must be nonempty and contain
    /// no NUL bytes. Supply fresh operating-system cryptographic randomness
    /// for all eleven bytes on each call. A failed entropy callback leaves
    /// the writer reusable, with the attempt charged to the I/O budget.
    /// An error after entropy succeeds and the entry is admitted poisons
    /// the writer. Password and cipher state live only for this call.
    pub fn add_zipcrypto_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        input: &mut R,
        length: InputLength,
        password: &str,
        entropy: impl FnOnce(&mut [u8; 11]) -> io::Result<()>,
    ) -> Result<EntryWritten, WriteError> {
        self.check_failed()?;
        if password.is_empty() || password.as_bytes().contains(&0) {
            return Err(WriteError::InvalidMetadata("ZIP password must be nonempty and contain no NUL bytes"));
        }
        let (member, entries) = self.prepare(options, length, false, true)?;
        let mut random = [0; 11];
        self.output.work.checkpoint()?;
        entropy(&mut random).map_err(|error| WriteError::io(IoStage::EncryptionEntropy, error))?;
        let result = self.write_file(
            options,
            member,
            entries,
            FileInput { input, length, decoded: 0 },
            Some((ZipCrypto::new(password), random)),
        );
        self.remember_failure(result)
    }

    /// Appends an explicit Stored directory whose name has one trailing slash.
    pub fn add_directory(&mut self, options: EntryOptions<'_>) -> Result<EntryWritten, WriteError> {
        let (member, entries) = self.prepare(options, InputLength::Exact(0), true, false)?;
        let result = self
            .output
            .write_local(&member, options.name.bytes())
            .and_then(|()| self.complete(options, &member, entries, 0, 0, 0));
        self.remember_failure(result)
    }

    /// Returns current accounting, including positive I/O on an incomplete
    /// member. Entry count and decoded and packed totals cover complete members.
    /// Physical extent and output bytes both include any descriptor bytes.
    pub fn usage(&self) -> WriteUsage {
        WriteUsage {
            central_bytes: self.central.len() as u64,
            metadata_capacity: self.central.capacity() as u64 + self.comment.capacity() as u64,
            ..self.output.work.usage
        }
    }

    /// Writes the directory, end records and archive comment, then flushes.
    /// Returns the sink only after a successful flush and cancellation check.
    /// On error, any bytes already delivered to the sink are provisional.
    pub fn finish(mut self) -> Result<Finished<W>, WriteError> {
        self.check_failed()?;
        let usage = self.usage();
        let central_offset = self.output.position;
        let end = End::new(usage.entries, usage.central_bytes, central_offset, self.wide_member, self.comment_len);
        self.output.check_tail(end, 0)?;
        self.output.write_tail(end, &self.central, &self.comment)?;
        let summary = WriteSummary { usage: self.usage(), central_offset, zip64: end.is_wide() };
        Ok(Finished { sink: self.output.sink, summary })
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
        encrypted: bool,
    ) -> Result<(Member, u64), WriteError> {
        self.check_failed()?;
        let local_at = self.output.position;
        let mut member = prepare_member(options, length, directory, local_at)?;
        let overhead = if encrypted { ZIPCRYPTO_HEADER } else { 0 };
        if encrypted {
            member.flags |= FLAG_DESCRIPTOR | FLAG_ENCRYPTED;
            if member.method == Method::Stored
                && let InputLength::Exact(size) = length
            {
                member.width = Width::new(Method::Stored, InputLength::Exact(add(size, overhead)?), local_at, false);
            }
        }
        let work = &self.output.work;
        let limits = work.limits;
        let entries = add(work.usage.entries, 1)?;
        bound(entries, limits.entries, Limit::Entries)?;
        let central = add(self.central.len() as u64, member.central_len())?;
        bound(central, limits.central_bytes, Limit::CentralBytes)?;
        let payload_min = if directory { 0 } else { add(work.payload_min(length, member.method)?, overhead)? };
        let descriptor = if encrypted || length != InputLength::Exact(0) { member.descriptor_len() } else { 0 };
        let before_tail = add(add(member.local_len(), payload_min)?, descriptor)?;
        let central_at = add(local_at, before_tail)?;
        let end = End::new(entries, central, central_at, self.wide_member || member.width.is_wide(), self.comment_len);
        self.output.check_tail(end, before_tail)?;
        if encrypted {
            // Entropy, an input read, the fixed local record and name, the
            // encryption header and a descriptor are mandatory.
            bound(add(work.usage.io_attempts, 6)?, limits.io_attempts, Limit::IoAttempts)?;
        }
        work.check_canceled()?;
        let max_capacity = limits.metadata_capacity - self.comment.capacity() as u64;
        reserve_central(&mut self.central, central, max_capacity)?;
        Ok((member, entries))
    }

    fn write_file<R: Read + ?Sized>(
        &mut self,
        options: EntryOptions<'_>,
        mut member: Member,
        entries: u64,
        mut file: FileInput<'_, R>,
        encryption: Option<(ZipCrypto, [u8; 11])>,
    ) -> Result<EntryWritten, WriteError> {
        let mut input = [0; BUFFER];
        let first = file.read(&mut self.output.work, &mut input)?;
        if first == 0 {
            member.method = Method::Stored;
            member.width = Width::new(Method::Stored, InputLength::Exact(0), member.local_at, true);
            if encryption.is_none() {
                self.output.write_local(&member, options.name.bytes())?;
                return self.complete(options, &member, entries, 0, 0, 0);
            }
        }

        member.flags |= FLAG_DESCRIPTOR;
        self.output.write_local(&member, options.name.bytes())?;
        let (cipher, overhead) = if let Some((mut cipher, random)) = encryption {
            let mut header = [0; ZIPCRYPTO_HEADER as usize];
            header[..11].copy_from_slice(&random);
            header[11] = (member.dos.time >> 8) as u8;
            cipher.encrypt(&mut header);
            self.output.write(&header, IoStage::EncryptionHeader)?;
            (Some(cipher), ZIPCRYPTO_HEADER)
        } else {
            (None, 0)
        };
        let (crc, payload) = self.output.write_payload(member.method, &mut file, &mut input, first, cipher)?;
        let packed = add(payload, overhead)?;
        let decoded = file.decoded;

        let descriptor_len = member.descriptor_len();
        let central_at = add(self.output.position, descriptor_len)?;
        let central = add(self.central.len() as u64, member.central_len())?;
        let end = End::new(entries, central, central_at, self.wide_member || member.width.is_wide(), self.comment_len);
        self.output.check_tail(end, descriptor_len)?;

        let descriptor = member.descriptor(crc, decoded, packed)?;
        self.output.write(descriptor.as_bytes(), IoStage::DataDescriptor)?;
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

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::zip::write::{DosDateTime, EntryName, Permissions, WriteLimits};

    fn stored() -> EntryOptions<'static> {
        EntryOptions {
            name: EntryName::Utf8("x"),
            method: Method::Stored,
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o644).unwrap(),
            comment: b"",
        }
    }

    #[test]
    fn descriptor_sizes_follow_local_size_width_and_reject_classic_sentinels() {
        let sentinel = u64::from(u32::MAX);
        for size in [sentinel - 1, sentinel, sentinel + 1] {
            let narrow = prepare_member(stored(), InputLength::Exact(1), false, sentinel).unwrap();
            assert!(narrow.width.is_wide());
            assert!(!narrow.width.sizes);
            assert_eq!(narrow.descriptor_len(), 16);
            for (decoded, packed) in [(size, 17), (19, size)] {
                let record = narrow.descriptor(0x0123_4567, decoded, packed);
                if size < sentinel {
                    let record = record.unwrap();
                    let bytes = record.as_bytes();
                    assert_eq!(bytes.len(), 16);
                    assert_eq!(&bytes[..8], b"PK\x07\x08\x67\x45\x23\x01");
                    assert_eq!(&bytes[8..12], &(packed as u32).to_le_bytes());
                    assert_eq!(&bytes[12..16], &(decoded as u32).to_le_bytes());
                } else {
                    assert!(matches!(record, Err(WriteError::Overflow)));
                }
                let wide = prepare_member(stored(), InputLength::Unknown, false, 0).unwrap();
                let record = wide.descriptor(0x0123_4567, decoded, packed).unwrap();
                let bytes = record.as_bytes();
                assert_eq!(wide.descriptor_len(), 24);
                assert_eq!(bytes.len(), 24);
                assert_eq!(&bytes[..8], b"PK\x07\x08\x67\x45\x23\x01");
                assert_eq!(&bytes[8..16], &packed.to_le_bytes());
                assert_eq!(&bytes[16..24], &decoded.to_le_bytes());
            }
            let exact = prepare_member(stored(), InputLength::Exact(size), false, 0).unwrap();
            assert_eq!(exact.descriptor_len(), if size >= sentinel { 24 } else { 16 });
        }
    }

    // This harness checks arithmetic without constructing a physical archive.
    #[test]
    fn descriptor_alone_crosses_the_central_offset_sentinel() {
        let sentinel = u64::from(u32::MAX);
        for central_at in [sentinel - 1, sentinel, sentinel + 1] {
            let mut writer = ZipStreamWriter::new(io::sink(), WriterOptions::default()).unwrap();
            // 31 bytes of local header, one payload byte, 16 descriptor bytes.
            writer.output.position = central_at - 48;
            writer.output.work.usage.output_bytes = writer.output.position;
            writer.output.work.usage.archive_extent = writer.output.position;
            let first = writer.add_file(stored(), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
            assert_eq!(first.local_offset, central_at - 48);
            let summary = writer.finish().unwrap().summary;
            assert_eq!(summary.central_offset, central_at);
            assert_eq!(summary.zip64, central_at >= sentinel);
            let tail = if central_at >= sentinel { 98 } else { 22 };
            assert_eq!(summary.usage.archive_extent, central_at + 47 + tail);
            assert_eq!(summary.usage.output_bytes, summary.usage.archive_extent);
        }
    }

    #[test]
    fn zipcrypto_header_crosses_size_and_offset_sentinels() {
        let sentinel = u64::from(u32::MAX);
        for (size, wide) in [(sentinel - 13, false), (sentinel - 12, true)] {
            let mut writer = ZipStreamWriter::new(io::sink(), WriterOptions::default()).unwrap();
            let (member, _) = writer.prepare(stored(), InputLength::Exact(size), false, true).unwrap();
            assert_eq!(member.width.sizes, wide);
            let descriptor = member.descriptor(0, size, size + ZIPCRYPTO_HEADER).unwrap();
            assert_eq!(descriptor.as_bytes().len(), if wide { 24 } else { 16 });
        }
        for central_at in [sentinel - 1, sentinel] {
            let mut writer = ZipStreamWriter::new(io::sink(), WriterOptions::default()).unwrap();
            writer.output.position = central_at - 60;
            let receipt = writer
                .add_zipcrypto_file(stored(), &mut b"x".as_slice(), InputLength::Exact(1), "pass", |random| {
                    *random = [1; 11];
                    Ok(())
                })
                .unwrap();
            assert_eq!(receipt.packed_size, 13);
            let summary = writer.finish().unwrap().summary;
            assert_eq!(summary.central_offset, central_at);
            assert_eq!(summary.zip64, central_at == sentinel);
        }
    }

    #[test]
    fn descriptor_and_tail_arithmetic_detects_u64_overflow_before_reading() {
        let limits = WriteLimits { archive_extent: u64::MAX, output_bytes: u64::MAX, ..WriteLimits::default() };
        let mut writer =
            ZipStreamWriter::new(io::sink(), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
        for position in [u64::MAX - 47, u64::MAX - 48] {
            writer.output.position = position;
            writer.output.work.usage.output_bytes = position;
            writer.output.work.usage.archive_extent = position;
            let mut source = b"y".as_slice();
            assert!(matches!(writer.add_file(stored(), &mut source, InputLength::Exact(1)), Err(WriteError::Overflow)));
            assert_eq!(source, b"y");
            assert_eq!(writer.usage().io_attempts, 0);
        }
    }
}
