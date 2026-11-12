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

use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

use zip_container::{Limits, LocalHeader, Profile, local_layout, parse_slice};
use zipfast::extract::Cancellation;
use zipfast::zip::Archive;
use zipfast::zip::write::{
    DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, IoStage, Limit, Method, Permissions, WriteError,
    WriteLimits, WriterOptions, ZipWriter,
};
use zipview::ZipReader;

fn deflate(level: u32) -> Method {
    Method::Deflate(DeflateLevel::new(level).unwrap())
}

fn entry(name: &str, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"",
    }
}

fn n16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn n32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn n64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn verify_payloads(bytes: &[u8], wanted: &[(&str, Option<&[u8]>)]) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    let mut root = Archive::open(file.path()).unwrap();
    let view = ZipReader::new(bytes).unwrap();
    assert_eq!(root.entries.len(), wanted.len());
    assert_eq!(view.entries().len(), wanted.len());
    for (idx, (name, data)) in wanted.iter().enumerate() {
        let root_entry = &root.entries[idx];
        let view_entry = view.by_index(idx).unwrap();
        assert_eq!(&root_entry.name, name);
        assert_eq!(view_entry.name(), *name);
        assert_eq!(root_entry.is_dir(), data.is_none());
        assert_eq!(view_entry.is_dir(), data.is_none());
        if let Some(data) = data {
            let crc = crc32fast::hash(data);
            assert_eq!(root_entry.crc32, crc);
            assert_eq!(view_entry.crc32(), crc);
            assert_eq!(view.read_entry(view_entry).unwrap(), *data);
            let mut output = Vec::new();
            root.read_at(idx, None, data.len() as u64 + 4096, |chunk| {
                output.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
            assert_eq!(output, *data);
        }
    }
}

#[test]
fn empty_archive_has_exact_classic_record() {
    let mut sink = Cursor::new(Vec::new());
    let finished = ZipWriter::new(&mut sink, WriterOptions::default()).unwrap().finish().unwrap();
    assert_eq!(finished.summary.usage.entries, 0);
    assert_eq!(finished.sink.position(), 22);
    assert_eq!(sink.into_inner(), b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
}

#[test]
fn rejects_nonempty_or_positioned_sinks_and_restores_the_cursor() {
    for (bytes, at) in [(vec![1], 0), (Vec::new(), 2), (vec![1, 2, 3], 1)] {
        let mut sink = Cursor::new(bytes.clone());
        sink.set_position(at);
        assert!(matches!(ZipWriter::new(&mut sink, WriterOptions::default()), Err(WriteError::NonEmptySink { .. })));
        assert_eq!(sink.position(), at);
        assert_eq!(sink.into_inner(), bytes);
    }
}

#[test]
fn streams_all_methods_and_preserves_directory_and_duplicate_order() {
    let mut random = vec![0; 192 * 1024 + 11];
    let mut state = 0x12345678u32;
    for b in &mut random {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *b = state as u8;
    }
    let compressible = vec![b'Z'; 300_011];
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
    let mut dir = entry("nested/", Method::Stored);
    dir.permissions = Permissions::new(0o755).unwrap();
    writer.add_directory(dir).unwrap();
    let mut wanted = vec![("nested/", None)];
    for (name, method, data, length) in [
        ("nested/file", Method::Stored, b"\0\xff\x01".as_slice(), InputLength::Exact(3)),
        ("nested/file", deflate(1), compressible.as_slice(), InputLength::Exact(300_011)),
        ("nested/工具", deflate(6), random.as_slice(), InputLength::Unknown),
        ("nested/last", deflate(9), compressible.as_slice(), InputLength::Unknown),
        ("empty", deflate(6), b"", InputLength::Exact(0)),
        ("also-empty", deflate(6), b"", InputLength::Unknown),
    ] {
        let written = writer.add_file(entry(name, method), &mut &*data, length).unwrap();
        assert_eq!(written.ordinal, wanted.len() as u64);
        assert_eq!(written.method, if data.is_empty() { Method::Stored } else { method });
        assert_eq!(written.decoded_size, data.len() as u64);
        if name == "nested/工具" {
            assert!(written.packed_size > written.decoded_size);
        }
        wanted.push((name, Some(data)));
    }
    let finished = writer.finish().unwrap();
    assert_eq!(finished.summary.usage.entries, 7);
    assert_eq!(finished.sink.position(), finished.sink.get_ref().len() as u64);
    verify_payloads(finished.sink.get_ref(), &wanted);
}

#[test]
fn forced_zip64_sets_exact_tail_and_both_readers_agree() {
    let payload = b"tiny forced ZIP64 member";
    for (method, length) in [
        (deflate(6), InputLength::Exact(24)),
        (deflate(6), InputLength::Unknown),
        (Method::Stored, InputLength::Unknown),
    ] {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
        writer.add_file(entry("tiny", method), &mut payload.as_slice(), length).unwrap();
        let finished = writer.finish().unwrap();
        let bytes = finished.sink.into_inner();
        let classic = bytes.len() - 22;
        let zip64 = classic - 76;
        assert_eq!(&bytes[classic..classic + 8], b"PK\x05\x06\0\0\0\0");
        assert_eq!(&bytes[classic + 8..classic + 20], &[255; 12]);
        assert_eq!(&bytes[zip64..zip64 + 4], b"PK\x06\x06");
        assert_eq!(n64(&bytes, zip64 + 4), 44);
        assert_eq!(&bytes[zip64 + 16..zip64 + 24], &[0; 8]);
        assert_eq!(n64(&bytes, zip64 + 24), 1);
        assert_eq!(n64(&bytes, zip64 + 32), 1);
        let directory = n64(&bytes, zip64 + 48);
        let directory_size = n64(&bytes, zip64 + 40);
        assert_eq!(directory_size, 70);
        assert_eq!(directory + directory_size, zip64 as u64);
        assert_eq!(&bytes[classic - 20..classic - 12], b"PK\x06\x07\0\0\0\0");
        assert_eq!(n64(&bytes, classic - 12), zip64 as u64);
        assert_eq!(n32(&bytes, classic - 4), 1);
        assert_eq!(n16(&bytes, 4), 45);
        assert_eq!(&bytes[18..26], &[255; 8]);
        assert_eq!(n16(&bytes, 28), 20);
        assert_eq!(&bytes[34..38], b"\x01\x00\x10\x00");
        assert_eq!(n64(&bytes, 38), 24);
        assert_eq!(n64(&bytes, 46) + 54, directory);

        for profile in [Profile::Zipfast, Profile::Zipview] {
            let parsed = parse_slice(&bytes, profile, Limits::default()).unwrap();
            assert!(parsed.zip64_end.is_some());
            assert_eq!(parsed.prefix_shift, 0);
            assert_eq!(parsed.directory_range, directory..zip64 as u64);
            assert_eq!(parsed.physical_local_header_offset(0), Some(0));
            let central = &parsed.entries[0];
            assert_eq!(central.resolved.packed_size, directory - 54);
            assert_eq!(central.resolved.unpacked_size, 24);
            assert_eq!(central.header.crc32, n32(&bytes, 14));
            assert_eq!(central.header.version_needed, 45);
            let layout = local_layout(LocalHeader::parse(&bytes).unwrap(), 0, directory).unwrap();
            assert_eq!(layout.payload_range(central.resolved.packed_size, directory).unwrap(), 54..directory);
        }
        verify_payloads(&bytes, &[("tiny", Some(payload))]);
    }
}

#[test]
fn raw_bytes_and_unix_metadata_round_trip_on_wire() {
    let raw = b"raw\x82\x00\x01\x7f";
    let mut writer = ZipWriter::new(
        Cursor::new(Vec::new()),
        WriterOptions { comment: b"archive\xff\0", ..WriterOptions::default() },
    )
    .unwrap();
    let mut raw_opts = entry("replaced", Method::Stored);
    raw_opts.name = EntryName::Raw(raw);
    raw_opts.comment = b"raw\xff\x00";
    raw_opts.modified = DosDateTime::new(2000, 2, 29, 23, 59, 59).unwrap();
    raw_opts.extended_mtime = Some(i32::MIN);
    raw_opts.permissions = Permissions::new(0o751).unwrap();
    writer.add_file(raw_opts, &mut b"x".as_slice(), InputLength::Exact(1)).unwrap();
    let mut utf8 = entry("é\u{1}", Method::Stored);
    utf8.comment = "té".as_bytes();
    utf8.extended_mtime = Some(i32::MAX);
    writer.add_file(utf8, &mut b"".as_slice(), InputLength::Unknown).unwrap();
    let mut dir = entry("nested/", Method::Stored);
    dir.permissions = Permissions::new(0o755).unwrap();
    writer.add_directory(dir).unwrap();

    let bytes = writer.finish().unwrap().sink.into_inner();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let mut root = Archive::open(file.path()).unwrap();
    assert_eq!(root.entries[0].name, "rawé\0\u{1}\u{7f}");
    assert_eq!(root.entries[0].mtime, Some(i64::from(i32::MIN)));
    assert_eq!(root.entries[0].unix_mode(), Some(0o100751));
    root.read_at(0, None, 1, |chunk| {
        assert_eq!(chunk, b"x");
        Ok(())
    })
    .unwrap();
    let view = ZipReader::new(&bytes).unwrap();
    let first = view.by_index(0).unwrap();
    assert_eq!(first.name(), "raw�\0\u{1}\u{7f}");
    assert_eq!(first.unix_mode(), Some(0o100751));
    let dos = first.last_modified().unwrap();
    assert_eq!((dos.year(), dos.month(), dos.day(), dos.hour(), dos.minute(), dos.second()), (2000, 2, 29, 23, 59, 58));
    assert_eq!(view.read_entry(first).unwrap(), b"x");

    for profile in [Profile::Zipfast, Profile::Zipview] {
        let parsed = parse_slice(&bytes, profile, Limits::default()).unwrap();
        assert_eq!(parsed.raw_comment, b"archive\xff\0");
        for (idx, name, comment, flags, attributes, mtime) in [
            (0, raw.as_slice(), raw_opts.comment, 0, 0o100751 << 16, Some(i32::MIN)),
            (1, "é\u{1}".as_bytes(), utf8.comment, 0x800, 0o100644 << 16, Some(i32::MAX)),
            (2, b"nested/".as_slice(), b"".as_slice(), 0x800, (0o040755 << 16) | 0x10, None),
        ] {
            let rec = &parsed.entries[idx];
            assert_eq!(&*rec.raw_name, name);
            assert_eq!(&*rec.raw_comment, comment);
            assert_eq!(rec.header.flags, flags);
            assert_eq!(rec.header.external_attributes, attributes);
            assert_eq!(rec.known.mtime_override, mtime.map(zip_container::ExtraMtime::UnixSeconds));
            let start = parsed.physical_local_header_offset(idx).unwrap();
            let local = LocalHeader::parse(&bytes[start as usize..]).unwrap();
            let ranges = local_layout(local, start, bytes.len() as u64).unwrap();
            assert_eq!(&bytes[ranges.name_range().start as usize..ranges.name_range().end as usize], name);
            assert_eq!(local.flags, flags);
            assert_eq!(local.method, rec.header.method);
            assert_eq!(local.crc32, rec.header.crc32);
            assert_eq!(local.packed_size, rec.header.packed_size);
            assert_eq!(local.unpacked_size, rec.header.unpacked_size);
            assert_eq!(local.mod_time, rec.header.mod_time);
            assert_eq!(local.mod_date, rec.header.mod_date);
            if let Some(mtime) = mtime {
                let extra = ranges.extra_range();
                let expected = [b"UT\x05\0\x01".as_slice(), &mtime.to_le_bytes()].concat();
                assert_eq!(&bytes[extra.start as usize..extra.end as usize], expected);
            }
        }
        assert_eq!(parsed.entries[0].header.mod_date, (20 << 9) | (2 << 5) | 29);
        assert_eq!(parsed.entries[0].header.mod_time, (23 << 11) | (59 << 5) | 29);
    }
}

#[test]
fn metadata_preflight_is_recoverable() {
    for (year, month, day, h, m, s) in [
        (1979, 12, 31, 0, 0, 0),
        (2108, 1, 1, 0, 0, 0),
        (2100, 2, 29, 0, 0, 0),
        (2024, 4, 31, 0, 0, 0),
        (2024, 0, 1, 0, 0, 0),
        (2024, 1, 1, 24, 0, 0),
        (2024, 1, 1, 0, 60, 0),
        (2024, 1, 1, 0, 0, 60),
    ] {
        assert!(DosDateTime::new(year, month, day, h, m, s).is_err());
    }
    assert!(DosDateTime::new(2107, 12, 31, 23, 59, 59).is_ok());
    assert!(DeflateLevel::new(0).is_err());
    assert!(DeflateLevel::new(10).is_err());
    assert!(Permissions::new(0o1000).is_err());
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
    let mut bad_comment = entry("ok", Method::Stored);
    bad_comment.comment = b"\xff";
    for invalid in [entry("bad/", Method::Stored), bad_comment] {
        assert!(matches!(
            writer.add_file(invalid, &mut NeverRead, InputLength::Exact(0)),
            Err(WriteError::InvalidMetadata(_))
        ));
    }
    for invalid in [entry("bad", Method::Stored), entry("bad//", Method::Stored), entry("bad/", deflate(6))] {
        assert!(matches!(writer.add_directory(invalid), Err(WriteError::InvalidMetadata(_))));
    }
    writer.add_file(entry("ok", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
    verify_payloads(writer.finish().unwrap().sink.get_ref(), &[("ok", Some(b"y"))]);
}

#[test]
fn length_delimited_metadata_accepts_65535_and_rejects_65536() {
    let long = vec![b'x'; 65_536];
    let max = &long[..65_535];
    assert!(matches!(
        ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { comment: &long, ..WriterOptions::default() }),
        Err(WriteError::InvalidMetadata(_))
    ));
    let mut writer =
        ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { comment: max, ..WriterOptions::default() }).unwrap();
    let mut opts = entry("replace", Method::Stored);
    opts.name = EntryName::Raw(&long);
    assert!(matches!(
        writer.add_file(opts, &mut NeverRead, InputLength::Exact(0)),
        Err(WriteError::InvalidMetadata(_))
    ));
    opts.name = EntryName::Raw(max);
    opts.comment = &long;
    assert!(matches!(
        writer.add_file(opts, &mut NeverRead, InputLength::Exact(0)),
        Err(WriteError::InvalidMetadata(_))
    ));
    opts.comment = max;
    writer.add_file(opts, &mut b"".as_slice(), InputLength::Exact(0)).unwrap();
    let finished = writer.finish().unwrap();
    assert!(!finished.summary.zip64);
    let bytes = finished.sink.into_inner();
    let dir_at = 30 + 65_535;
    assert_eq!(n16(&bytes, 26), 65_535);
    assert_eq!(n16(&bytes, dir_at + 28), 65_535);
    assert_eq!(n16(&bytes, dir_at + 32), 65_535);
    assert_eq!(n16(&bytes, bytes.len() - 65_535 - 2), 65_535);
    for profile in [Profile::Zipfast, Profile::Zipview] {
        let parsed = parse_slice(&bytes, profile, Limits::default()).unwrap();
        assert_eq!(parsed.raw_comment, max);
        assert_eq!(&*parsed.entries[0].raw_name, max);
        assert_eq!(&*parsed.entries[0].raw_comment, max);
    }
}

struct NeverRead;

impl Read for NeverRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("source consumed before admission");
    }
}

#[test]
fn admitted_size_mismatches_poison_and_never_finish() {
    for (data, declared, overrun, consumed) in [
        (b"".as_slice(), 1, false, 0),
        (b"q".as_slice(), 2, false, 1),
        (b"q".as_slice(), 0, true, 1),
        (b"qrs".as_slice(), 1, true, 2),
    ] {
        let mut input = Cursor::new(data);
        let mut sink = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut sink, WriterOptions::default()).unwrap();
        let error = writer.add_file(entry("x", Method::Stored), &mut input, InputLength::Exact(declared)).unwrap_err();
        if overrun {
            assert!(matches!(error, WriteError::SizeOverrun { expected } if expected == declared));
        } else {
            assert!(
                matches!(error, WriteError::SizeUnderrun { expected, actual } if expected == declared && actual == consumed)
            );
        }
        assert_eq!(input.position(), consumed);
        assert_eq!(writer.usage().source_bytes, consumed);
        assert!(matches!(writer.add_directory(entry("later/", Method::Stored)), Err(WriteError::Failed(_))));
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
        assert!(!sink.get_ref().windows(4).any(|x| x == b"PK\x05\x06"));
    }
}

#[test]
fn each_byte_and_entry_limit_has_independent_equality_and_plus_one() {
    let baseline = WriteLimits::default();
    for (limit, configure, max) in [
        (Limit::Entries, (|limits: &mut WriteLimits, n| limits.entries = n) as fn(&mut WriteLimits, u64), 1),
        (Limit::CentralBytes, |limits: &mut WriteLimits, n| limits.central_bytes = n, 47),
        (Limit::MetadataCapacity, |limits: &mut WriteLimits, n| limits.metadata_capacity = n, 47),
        (Limit::EntryDecodedBytes, |limits: &mut WriteLimits, n| limits.entry_decoded_bytes = n, 1),
        (Limit::SourceBytes, |limits: &mut WriteLimits, n| limits.source_bytes = n, 2),
        (Limit::ArchiveExtent, |limits: &mut WriteLimits, n| limits.archive_extent = n, 101),
        (Limit::OutputBytes, |limits: &mut WriteLimits, n| limits.output_bytes = n, 113),
    ] {
        let mut limits = baseline;
        configure(&mut limits, max - 1);
        let mut writer =
            ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
        let result = writer.add_file(entry("x", Method::Stored), &mut NeverRead, InputLength::Exact(1));
        assert!(matches!(result, Err(WriteError::Limit(actual)) if actual == limit), "{result:?}");
        assert_eq!(writer.finish().unwrap().sink.get_ref().len(), 22);

        configure(&mut limits, max);
        let mut writer =
            ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
        let finished = writer.finish().unwrap();
        assert_eq!(finished.summary.usage.archive_extent, 101);
        assert_eq!(finished.summary.usage.output_bytes, 113);
        assert_eq!(finished.summary.usage.source_bytes, 1);
        assert_eq!(finished.summary.usage.central_bytes, 47);
        assert!(finished.summary.usage.metadata_capacity <= limits.metadata_capacity);
    }
}

#[test]
fn unknown_limit_equality_requires_a_real_eof() {
    let limits = WriteLimits { entry_decoded_bytes: 4, source_bytes: 5, ..WriteLimits::default() };
    let options = WriterOptions { limits, ..WriterOptions::default() };
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()), options.clone()).unwrap();
    writer.add_file(entry("x", Method::Stored), &mut b"1234".as_slice(), InputLength::Unknown).unwrap();
    assert!(writer.finish().is_ok());

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()), options).unwrap();
    let result = writer.add_file(entry("x", Method::Stored), &mut io::repeat(b'x'), InputLength::Unknown);
    assert!(matches!(result, Err(WriteError::Limit(Limit::EntryDecodedBytes))));
    assert_eq!(writer.usage().source_bytes, 5);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));

    let limits = WriteLimits { source_bytes: 4, ..limits };
    let mut writer =
        ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
    let result = writer.add_file(entry("x", Method::Stored), &mut b"1234".as_slice(), InputLength::Unknown);
    assert!(matches!(result, Err(WriteError::Limit(Limit::SourceBytes))));
}

#[test]
fn no_drop_finish_writes_no_central_or_end_records() {
    let mut sink = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut sink, WriterOptions::default()).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
    }
    let bytes = sink.into_inner();
    assert_eq!(bytes.len(), 32);
    assert_eq!(n32(&bytes, 14), crc32fast::hash(b"y"));
    assert_eq!(n32(&bytes, 18), 1);
    assert_eq!(&bytes[30..], b"xy");
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    Short,
    Zero,
    InterruptOnce,
    InterruptAlways,
    SeekTo(u64),
    WriteAt(u64),
    WritePrefix([u8; 4]),
    Flush,
}

struct FaultSink {
    cursor: Cursor<Vec<u8>>,
    fault: Fault,
}

impl FaultSink {
    fn new(fault: Fault) -> Self {
        Self { cursor: Cursor::new(Vec::new()), fault }
    }
}

impl Seek for FaultSink {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        if matches!(self.fault, Fault::SeekTo(at) if from == SeekFrom::Start(at)) {
            return Err(io::Error::other("injected seek"));
        }
        self.cursor.seek(from)
    }
}

impl Write for FaultSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.fault {
            Fault::Short => self.cursor.write(&bytes[..bytes.len().min(2)]),
            Fault::Zero => Ok(0),
            Fault::InterruptAlways => Err(io::ErrorKind::Interrupted.into()),
            Fault::InterruptOnce => {
                self.fault = Fault::None;
                Err(io::ErrorKind::Interrupted.into())
            }
            Fault::WriteAt(at) if self.cursor.position() == at => Err(io::Error::other("injected write")),
            Fault::WritePrefix(prefix) if bytes.starts_with(&prefix) => Err(io::Error::other("injected write")),
            _ => self.cursor.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if matches!(self.fault, Fault::Flush) {
            return Err(io::Error::other("injected flush"));
        }
        Ok(())
    }
}

#[test]
fn short_and_interrupted_writes_preserve_bytes_and_charge_attempts() {
    let mut attempts = Vec::new();
    for fault in [Fault::None, Fault::Short, Fault::InterruptOnce] {
        let mut writer = ZipWriter::new(FaultSink::new(fault), WriterOptions::default()).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
        let finished = writer.finish().unwrap();
        assert_eq!(finished.summary.usage.output_bytes, 113);
        attempts.push(finished.summary.usage.io_attempts);
        verify_payloads(finished.sink.cursor.get_ref(), &[("x", Some(b"y"))]);
    }
    assert!(attempts[1] > attempts[0]);
    assert_eq!(attempts[2], attempts[0] + 1);
}

#[test]
fn local_payload_backpatch_and_restore_failures_poison_with_the_original_io_error() {
    for (fault, stage, kind) in [
        (Fault::Zero, IoStage::LocalHeader, io::ErrorKind::WriteZero),
        (Fault::WriteAt(31), IoStage::Payload, io::ErrorKind::Other),
        (Fault::SeekTo(14), IoStage::BackpatchSeek, io::ErrorKind::Other),
        (Fault::WriteAt(14), IoStage::BackpatchWrite, io::ErrorKind::Other),
        (Fault::SeekTo(32), IoStage::BackpatchRestore, io::ErrorKind::Other),
    ] {
        let mut sink = FaultSink::new(fault);
        let mut writer = ZipWriter::new(&mut sink, WriterOptions::default()).unwrap();
        let error =
            writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap_err();
        let WriteError::Io { stage: actual, source } = error else { panic!("{error:?}") };
        assert_eq!(actual, stage);
        assert_eq!(source.kind(), kind);
        let Err(WriteError::Failed(cause)) = writer.finish() else {
            panic!("poisoned writer returned a different result")
        };
        let WriteError::Io { source: original, .. } = &*cause else { panic!("{cause:?}") };
        assert!(std::sync::Arc::ptr_eq(&source, original));
        assert!(!sink.cursor.get_ref().windows(4).any(|x| x == b"PK\x05\x06"));
    }
}

#[test]
fn central_end_and_flush_errors_never_return_the_finished_sink() {
    for (fault, stage, final_len) in [
        (Fault::WritePrefix(*b"PK\x01\x02"), IoStage::CentralDirectory, 32),
        (Fault::WritePrefix(*b"PK\x05\x06"), IoStage::EndRecord, 79),
        (Fault::Flush, IoStage::Flush, 101),
    ] {
        let mut sink = FaultSink::new(fault);
        let mut writer = ZipWriter::new(&mut sink, WriterOptions::default()).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
        assert!(matches!(writer.finish(), Err(WriteError::Io { stage: actual, .. }) if actual == stage));
        assert_eq!(sink.cursor.get_ref().len(), final_len);
    }
}

struct ReadFailure {
    error: io::ErrorKind,
    initial: bool,
}

impl Read for ReadFailure {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.initial {
            self.initial = false;
            bytes[0] = b'x';
            return Ok(1);
        }
        Err(self.error.into())
    }
}

#[test]
fn read_errors_poison_before_or_after_a_local_header() {
    for initial in [false, true] {
        let mut sink = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(&mut sink, WriterOptions::default()).unwrap();
        let mut input = ReadFailure { error: io::ErrorKind::ConnectionReset, initial };
        let result = writer.add_file(entry("x", Method::Stored), &mut input, InputLength::Unknown);
        assert!(matches!(result, Err(WriteError::Io { stage: IoStage::SourceRead, .. })));
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
        assert_eq!(sink.into_inner().len(), if initial { 52 } else { 0 });
    }
}

#[test]
fn attempt_cap_stops_interrupted_io_and_counts_exact_success_boundary() {
    let limit = |io_attempts| WriterOptions {
        limits: WriteLimits { io_attempts, ..WriteLimits::default() },
        ..WriterOptions::default()
    };
    let mut writer = ZipWriter::new(FaultSink::new(Fault::InterruptAlways), limit(7)).unwrap();
    let result = writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1));
    assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!(writer.usage().io_attempts, 7);

    let mut writer = ZipWriter::new(FaultSink::new(Fault::None), limit(7)).unwrap();
    let mut input = ReadFailure { error: io::ErrorKind::Interrupted, initial: false };
    let result = writer.add_file(entry("x", Method::Stored), &mut input, InputLength::Unknown);
    assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!(writer.usage().io_attempts, 7);

    for attempts in [13, 14] {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()), limit(attempts)).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
        match writer.finish() {
            Err(WriteError::Limit(Limit::IoAttempts)) => assert_eq!(attempts, 13),
            Ok(finished) => {
                assert_eq!(attempts, 14);
                assert_eq!(finished.summary.usage.io_attempts, attempts);
            }
            Err(other) => panic!("{other:?}"),
        }
    }
}

struct CancelOnRead(Cancellation);

impl Read for CancelOnRead {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        bytes[0] = 1;
        self.0.cancel();
        Ok(1)
    }
}

#[test]
fn cancellation_after_admission_stops_before_the_next_io() {
    let cancel = Cancellation::default();
    let mut sink = Cursor::new(Vec::new());
    let options = WriterOptions { cancel: Some(cancel.clone()), ..WriterOptions::default() };
    let mut writer = ZipWriter::new(&mut sink, options).unwrap();
    let result = writer.add_file(entry("x", deflate(6)), &mut CancelOnRead(cancel), InputLength::Unknown);
    assert!(matches!(result, Err(WriteError::Canceled)));
    assert_eq!(writer.usage().source_bytes, 1);
    assert_eq!(writer.usage().io_attempts, 4);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    assert!(sink.into_inner().is_empty());
}

#[test]
fn an_adjacent_locator_without_classic_sentinels_has_profile_specific_selection() {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
    writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Unknown).unwrap();
    let mut bytes = writer.finish().unwrap().sink.into_inner();
    let classic = bytes.len() - 22;
    // Keep the same ZIP64 tail. The single member has a 51-byte local header,
    // one byte of payload, and a 67-byte central record.
    bytes[classic + 8..classic + 20].copy_from_slice(b"\x01\0\x01\0\x43\0\0\0\x34\0\0\0");
    let root = parse_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap();
    let view = parse_slice(&bytes, Profile::Zipview, Limits::default()).unwrap();
    assert!(root.zip64_end.is_some());
    assert!(view.zip64_end.is_none());
    assert_eq!(root.prefix_shift, 0);
    assert_eq!(view.prefix_shift, 0);
    assert_eq!(root.directory_range, 52..119);
    assert_eq!(view.directory_range, 52..119);
}

#[test]
fn actual_entry_counts_cross_classic_sentinel() {
    for count in [65_534u64, 65_535, 65_536] {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()), WriterOptions::default()).unwrap();
        for ordinal in 0..count {
            assert_eq!(writer.add_directory(entry("d/", Method::Stored)).unwrap().ordinal, ordinal);
        }
        let finished = writer.finish().unwrap();
        assert_eq!(finished.summary.usage.entries, count);
        assert_eq!(finished.summary.central_offset, 32 * count);
        assert_eq!(finished.summary.usage.central_bytes, 48 * count);
        assert_eq!(finished.summary.zip64, count >= 65_535);
        let bytes = finished.sink.get_ref();
        assert_eq!(n16(bytes, bytes.len() - 12), count.min(65_535) as u16);
        if count >= 65_535 {
            assert_eq!(n64(bytes, bytes.len() - 98 + 32), count);
        }
        let view = ZipReader::new(bytes).unwrap();
        assert_eq!(view.entries().len(), count as usize);
        assert_eq!(view.by_index(count as usize - 1).unwrap().name(), "d/");
    }
}

#[test]
fn enormous_declared_length_overflow_is_recoverable() {
    let limits = WriteLimits {
        entry_decoded_bytes: u64::MAX,
        source_bytes: u64::MAX,
        archive_extent: u64::MAX,
        output_bytes: u64::MAX,
        ..WriteLimits::default()
    };
    let mut writer =
        ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
    for size in [u64::MAX, u64::MAX - 1] {
        let error = writer.add_file(entry("x", Method::Stored), &mut NeverRead, InputLength::Exact(size));
        assert!(matches!(error, Err(WriteError::Overflow)));
    }
    assert!(writer.finish().is_ok());
}

#[test]
#[ignore = "writes and reads a generated >4 GiB archive"]
fn streamed_member_crosses_four_gib_and_next_entry_has_offset_only_zip64() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = std::env::var_os("ZIPFAST_WRITER_REFERENCE_DIR")
        .map_or_else(|| temporary.path().to_path_buf(), std::path::PathBuf::from);
    let path = directory.join("large.zip");
    let mut file = std::fs::File::create(&path).unwrap();
    let mut writer = ZipWriter::new(&mut file, WriterOptions::default()).unwrap();
    let size = (1u64 << 32) + 4096;
    let first = writer
        .add_file(entry("zeros", Method::Stored), &mut io::repeat(0).take(size), InputLength::Exact(size))
        .unwrap();
    let second =
        writer.add_file(entry("after", Method::Stored), &mut b"tail".as_slice(), InputLength::Exact(4)).unwrap();
    let finished = writer.finish().unwrap();
    assert_eq!(first.packed_size, size);
    assert_eq!(first.decoded_size, size);
    assert_eq!(second.local_offset, 55 + size);
    assert_eq!(finished.summary.usage.packed_bytes, size + 4);
    assert_eq!(finished.summary.usage.decoded_bytes, size + 4);
    assert_eq!(finished.summary.usage.source_bytes, size + 4);
    assert!(finished.summary.zip64);

    let mut file = std::fs::File::open(&path).unwrap();
    file.seek(SeekFrom::Start(second.local_offset)).unwrap();
    let mut local = [0; 35];
    file.read_exact(&mut local).unwrap();
    assert_eq!(&local[..4], b"PK\x03\x04");
    assert_eq!(n16(&local, 4), 45);
    assert_eq!(n16(&local, 28), 0);
    assert_eq!(&local[30..], b"after");
    file.seek(SeekFrom::Start(finished.summary.central_offset)).unwrap();
    let mut central = [0; 134];
    file.read_exact(&mut central).unwrap();
    let second_central = &central[71..];
    assert_eq!(n16(second_central, 6), 45);
    assert_eq!(n32(second_central, 20), 4);
    assert_eq!(n32(second_central, 24), 4);
    assert_eq!(n32(second_central, 42), u32::MAX);
    assert_eq!(&second_central[51..55], b"\x01\0\x08\0");
    assert_eq!(n64(second_central, 55), second.local_offset);

    let mut root = Archive::open(&path).unwrap();
    assert_eq!(root.entries[0].size, size);
    assert_eq!(root.entries[1].local_at, second.local_offset);
    let mut checked = 0;
    root.read_at(0, None, size, |chunk| {
        assert!(chunk.iter().all(|&byte| byte == 0));
        checked += chunk.len() as u64;
        Ok(())
    })
    .unwrap();
    assert_eq!(checked, size);
    root.read_at(1, None, 4, |chunk| {
        assert_eq!(chunk, b"tail");
        Ok(())
    })
    .unwrap();
}

#[test]
#[ignore = "exports fixtures to ZIPFAST_WRITER_REFERENCE_DIR for pinned external tools"]
fn write_reference_fixtures() {
    let directory = std::path::PathBuf::from(std::env::var_os("ZIPFAST_WRITER_REFERENCE_DIR").unwrap());
    let payload = b"tiny forced ZIP64 member";
    std::fs::write(directory.join("tiny.expected"), payload).unwrap();
    for (name, method, length) in [
        ("known-deflate.zip", deflate(6), InputLength::Exact(24)),
        ("unknown-deflate.zip", deflate(6), InputLength::Unknown),
        ("unknown-stored.zip", Method::Stored, InputLength::Unknown),
    ] {
        let mut writer =
            ZipWriter::new(std::fs::File::create(directory.join(name)).unwrap(), WriterOptions::default()).unwrap();
        writer.add_file(entry("tiny", method), &mut payload.as_slice(), length).unwrap();
        writer.finish().unwrap();
    }
    ZipWriter::new(std::fs::File::create(directory.join("empty.zip")).unwrap(), WriterOptions::default())
        .unwrap()
        .finish()
        .unwrap();

    let mut writer = ZipWriter::new(
        std::fs::File::create(directory.join("metadata.zip")).unwrap(),
        WriterOptions { comment: b"archive comment", ..WriterOptions::default() },
    )
    .unwrap();
    let mut dir = entry("nested/", Method::Stored);
    dir.permissions = Permissions::new(0o755).unwrap();
    dir.modified = DosDateTime::new(2020, 1, 2, 3, 4, 7).unwrap();
    writer.add_directory(dir).unwrap();
    let mut tool = entry("nested/tool", Method::Stored);
    tool.permissions = Permissions::new(0o751).unwrap();
    tool.modified = dir.modified;
    tool.extended_mtime = Some(1_577_934_247);
    tool.comment = b"member comment";
    writer.add_file(tool, &mut payload.as_slice(), InputLength::Exact(24)).unwrap();
    writer.add_file(entry("empty", deflate(9)), &mut b"".as_slice(), InputLength::Exact(0)).unwrap();
    writer.finish().unwrap();

    let mut writer =
        ZipWriter::new(std::fs::File::create(directory.join("raw.zip")).unwrap(), WriterOptions::default()).unwrap();
    let mut raw = entry("", Method::Stored);
    raw.name = EntryName::Raw(b"raw\x82\0\x01\x7f");
    raw.comment = b"raw\0\xff";
    writer.add_file(raw, &mut payload.as_slice(), InputLength::Exact(24)).unwrap();
    writer.finish().unwrap();
}

#[test]
fn encoder_iteration_obeys_the_same_attempt_cap_as_io() {
    let limits = WriteLimits { io_attempts: 7, ..WriteLimits::default() };
    let mut writer =
        ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
    let result = writer.add_file(entry("x", deflate(6)), &mut b"y".as_slice(), InputLength::Exact(1));
    assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
    // Three constructor seeks, one source read and three local header writes.
    // No attempt remains for the first codec call.
    assert_eq!(writer.usage().io_attempts, 7);
    assert_eq!(writer.usage().archive_extent, 51);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
}

#[test]
fn unknown_empty_reserves_worst_case_before_admission_but_only_serializes_actual_metadata() {
    for (limit, limits) in [
        (Limit::CentralBytes, WriteLimits { central_bytes: 66, ..WriteLimits::default() }),
        (Limit::MetadataCapacity, WriteLimits { metadata_capacity: 69, ..WriteLimits::default() }),
    ] {
        let options = WriterOptions { comment: b"abc", limits, ..WriterOptions::default() };
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()), options).unwrap();
        let rejected = writer.add_file(entry("x", Method::Stored), &mut NeverRead, InputLength::Unknown);
        assert!(matches!(rejected, Err(WriteError::Limit(actual)) if actual == limit));
        writer.add_file(entry("x", Method::Stored), &mut b"".as_slice(), InputLength::Exact(0)).unwrap();
        assert!(writer.finish().is_ok());
    }

    let options = WriterOptions {
        comment: b"abc",
        limits: WriteLimits { central_bytes: 67, metadata_capacity: 70, ..WriteLimits::default() },
        ..WriterOptions::default()
    };
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()), options).unwrap();
    writer.add_file(entry("x", Method::Stored), &mut b"".as_slice(), InputLength::Unknown).unwrap();
    let usage = writer.usage();
    assert_eq!(usage.central_bytes, 47);
    assert_eq!(usage.metadata_capacity, 70);
    let finished = writer.finish().unwrap();
    assert!(!finished.summary.zip64);
    assert!(finished.sink.get_ref().ends_with(b"abc"));
}

#[test]
fn late_output_and_extent_limits_poison_before_any_tail() {
    for (limit, limits) in [
        (Limit::ArchiveExtent, WriteLimits { archive_extent: 216, ..WriteLimits::default() }),
        (Limit::OutputBytes, WriteLimits { output_bytes: 236, ..WriteLimits::default() }),
    ] {
        let mut sink = Cursor::new(Vec::new());
        let options = WriterOptions { limits, ..WriterOptions::default() };
        let mut writer = ZipWriter::new(&mut sink, options).unwrap();
        let rejected = writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Unknown);
        assert!(matches!(rejected, Err(WriteError::Limit(actual)) if actual == limit));
        assert_eq!(writer.usage().source_bytes, 1);
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
        assert_eq!(sink.into_inner().len(), 52);
    }
}
