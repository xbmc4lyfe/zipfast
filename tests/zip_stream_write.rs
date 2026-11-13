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

use zip_container::{Limits, Profile, parse_slice};
use zipfast::extract::Cancellation;
use zipfast::zip::Archive;
use zipfast::zip::write::{
    DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, IoStage, Limit, Method, Permissions, WriteError,
    WriteLimits, WriterOptions, ZipStreamWriter,
};
use zipview::ZipReader;

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

fn deflate(level: u32) -> Method {
    Method::Deflate(DeflateLevel::new(level).unwrap())
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

struct WriteOnly<W>(W);

impl<W: Write> Write for WriteOnly<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.write(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

fn read_at<R: Read + Seek, const N: usize>(archive: &mut R, offset: u64) -> [u8; N] {
    archive.seek(SeekFrom::Start(offset)).unwrap();
    let mut bytes = [0; N];
    archive.read_exact(&mut bytes).unwrap();
    bytes
}

struct Tail {
    count: u64,
    central: u64,
    size: u64,
    wide: bool,
}

fn tail<R: Read + Seek>(archive: &mut R, comment: &[u8]) -> Tail {
    let extent = archive.seek(SeekFrom::End(0)).unwrap();
    let classic_at = extent - 22 - comment.len() as u64;
    let classic: [u8; 22] = read_at(archive, classic_at);
    assert_eq!(&classic[..8], b"PK\x05\x06\0\0\0\0");
    assert_eq!(n16(&classic, 20) as usize, comment.len());
    let mut actual_comment = vec![0; comment.len()];
    archive.read_exact(&mut actual_comment).unwrap();
    assert_eq!(actual_comment, comment);
    let count = n16(&classic, 8);
    assert_eq!(count, n16(&classic, 10));
    let result = if count == u16::MAX {
        assert_eq!(&classic[8..20], &[0xff; 12]);
        let zip64_at = classic_at - 76;
        let end: [u8; 76] = read_at(archive, zip64_at);
        assert_eq!(&end[..4], b"PK\x06\x06");
        assert_eq!(n64(&end, 4), 44);
        assert_eq!(n16(&end, 12), 0x032d);
        assert_eq!(n16(&end, 14), 45);
        assert_eq!(&end[16..24], &[0; 8]);
        assert_eq!(n64(&end, 24), n64(&end, 32));
        assert_eq!(&end[56..64], b"PK\x06\x07\0\0\0\0");
        assert_eq!(n64(&end, 64), zip64_at);
        assert_eq!(n32(&end, 72), 1);
        Tail { count: n64(&end, 24), central: n64(&end, 48), size: n64(&end, 40), wide: true }
    } else {
        Tail { count: count.into(), central: n32(&classic, 16).into(), size: n32(&classic, 12).into(), wide: false }
    };
    assert_eq!(result.central + result.size, classic_at - if result.wide { 76 } else { 0 });
    result
}

#[derive(Clone, Copy)]
struct WireMember<'a> {
    name: &'a [u8],
    comment: &'a [u8],
    method: u16,
    crc: u32,
    decoded: u64,
    descriptor: u64,
    offset_wide: bool,
    utf8: bool,
    dos: (u16, u16),
    mtime: Option<i32>,
    external: u32,
}

impl<'a> WireMember<'a> {
    fn new(name: &'a str, data: &[u8], method: u16, descriptor: u64) -> Self {
        Self {
            name: name.as_bytes(),
            comment: b"",
            method,
            crc: crc32fast::hash(data),
            decoded: data.len() as u64,
            descriptor,
            offset_wide: false,
            utf8: true,
            dos: (0, 0x21),
            mtime: None,
            external: if name.ends_with('/') { 0x41a4_0010 } else { 0x81a4_0000 },
        }
    }
}

fn descriptor_matches<R: Read + Seek>(
    archive: &mut R,
    start: u64,
    end: u64,
    descriptor_len: u64,
    crc: u32,
    packed: u64,
    decoded: u64,
) -> bool {
    if end.checked_sub(start) != Some(descriptor_len) {
        return false;
    }
    match descriptor_len {
        0 => true,
        16 => {
            let bytes: [u8; 16] = read_at(archive, start);
            n32(&bytes, 0) == 0x0807_4b50
                && n32(&bytes, 4) == crc
                && u64::from(n32(&bytes, 8)) == packed
                && u64::from(n32(&bytes, 12)) == decoded
        }
        24 => {
            let bytes: [u8; 24] = read_at(archive, start);
            n32(&bytes, 0) == 0x0807_4b50
                && n32(&bytes, 4) == crc
                && n64(&bytes, 8) == packed
                && n64(&bytes, 16) == decoded
        }
        _ => panic!("bad test descriptor width"),
    }
}

fn check_wire<R: Read + Seek>(archive: &mut R, comment: &[u8], members: &[WireMember<'_>]) -> bool {
    let end = tail(archive, comment);
    assert_eq!(end.count, members.len() as u64);
    assert_eq!(end.wide, end.count >= 65_535 || members.iter().any(|m| m.descriptor == 24 || m.offset_wide));
    let mut central_at = end.central;
    let mut local_at = 0;
    let mut preceding = None;
    let mut valid_descriptors = true;
    for &member in members {
        let c: [u8; 46] = read_at(archive, central_at);
        assert_eq!(&c[..4], b"PK\x01\x02");
        let size_wide = member.descriptor == 24;
        let version = if size_wide || member.offset_wide { 45 } else { 20 };
        let flags = if member.utf8 { 0x800 } else { 0 } | if member.descriptor != 0 { 8 } else { 0 };
        assert_eq!(n16(&c, 4), 0x300 | version);
        assert_eq!(n16(&c, 6), version);
        assert_eq!(n16(&c, 8), flags);
        assert_eq!(n16(&c, 10), member.method);
        assert_eq!((n16(&c, 12), n16(&c, 14)), member.dos);
        assert_eq!(n32(&c, 16), member.crc);
        assert_eq!(n16(&c, 28) as usize, member.name.len());
        assert_eq!(n16(&c, 32) as usize, member.comment.len());
        assert_eq!(&c[34..38], &[0; 4]);
        assert_eq!(n32(&c, 38), member.external);
        let mut name = vec![0; member.name.len()];
        archive.read_exact(&mut name).unwrap();
        assert_eq!(name, member.name);
        let mut extra = vec![0; n16(&c, 30) as usize];
        archive.read_exact(&mut extra).unwrap();
        let mut comment = vec![0; member.comment.len()];
        archive.read_exact(&mut comment).unwrap();
        assert_eq!(comment, member.comment);
        central_at = archive.stream_position().unwrap();

        let (mut decoded, mut packed) = (u64::from(n32(&c, 24)), u64::from(n32(&c, 20)));
        let mut offset = u64::from(n32(&c, 42));
        let mut local_extra = Vec::new();
        let zip64_len = 16 * usize::from(size_wide) + 8 * usize::from(member.offset_wide);
        let mut extra_at = 0;
        if zip64_len != 0 {
            assert_eq!((n16(&extra, 0), n16(&extra, 2) as usize), (1, zip64_len));
            extra_at = 4;
            if size_wide {
                assert_eq!((decoded, packed), (u32::MAX.into(), u32::MAX.into()));
                (decoded, packed) = (n64(&extra, extra_at), n64(&extra, extra_at + 8));
                extra_at += 16;
                local_extra.extend_from_slice(b"\x01\0\x10\0");
                local_extra.extend_from_slice(&[0; 16]);
            }
            if member.offset_wide {
                assert_eq!(offset, u64::from(u32::MAX));
                offset = n64(&extra, extra_at);
                assert!(offset >= u64::from(u32::MAX));
                extra_at += 8;
            }
        }
        if let Some(mtime) = member.mtime {
            let mut field = b"UT\x05\0\x01".to_vec();
            field.extend_from_slice(&mtime.to_le_bytes());
            assert_eq!(&extra[extra_at..], field);
            local_extra.extend_from_slice(&field);
            extra_at += field.len();
        }
        assert_eq!(extra_at, extra.len());
        assert_eq!(decoded, member.decoded);
        if member.method == 0 {
            assert_eq!(packed, decoded);
        }

        if let Some((payload_end, width, crc, preceding_packed, preceding_decoded)) = preceding {
            valid_descriptors &=
                descriptor_matches(archive, payload_end, offset, width, crc, preceding_packed, preceding_decoded);
        } else {
            assert_eq!(offset, local_at);
        }
        local_at = offset;
        let l: [u8; 30] = read_at(archive, local_at);
        assert_eq!(&l[..4], b"PK\x03\x04");
        assert_eq!(&l[4..14], &c[6..16]);
        assert_eq!(n32(&l, 14), 0);
        let classic_size = if size_wide { u32::MAX } else { 0 };
        assert_eq!((n32(&l, 18), n32(&l, 22)), (classic_size, classic_size));
        assert_eq!(n16(&l, 26) as usize, member.name.len());
        assert_eq!(n16(&l, 28) as usize, local_extra.len());
        archive.read_exact(&mut name).unwrap();
        assert_eq!(name, member.name);
        let mut extra = vec![0; local_extra.len()];
        archive.read_exact(&mut extra).unwrap();
        assert_eq!(extra, local_extra);
        preceding = Some((archive.stream_position().unwrap() + packed, member.descriptor, member.crc, packed, decoded));
    }
    if let Some((payload_end, width, crc, packed, decoded)) = preceding {
        valid_descriptors &= descriptor_matches(archive, payload_end, end.central, width, crc, packed, decoded);
    } else {
        assert_eq!(end.central, 0);
    }
    assert_eq!(central_at, end.central + end.size);
    valid_descriptors
}

fn check_readers(bytes: &[u8], members: &[(&str, Option<&[u8]>)], comment: &[u8]) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    let mut root = Archive::open(file.path()).unwrap();
    let view = ZipReader::new(bytes).unwrap();
    assert_eq!(root.entries.len(), members.len());
    assert_eq!(view.entries().len(), members.len());
    let end = tail(&mut Cursor::new(bytes), comment);
    for profile in [Profile::Zipfast, Profile::Zipview] {
        let parsed = parse_slice(bytes, profile, Limits::default()).unwrap();
        assert_eq!(parsed.zip64_end.is_some(), end.wide);
        assert_eq!(parsed.prefix_shift, 0);
        assert_eq!(parsed.directory_range, end.central..end.central + end.size);
    }
    for (idx, (name, data)) in members.iter().enumerate() {
        let view_entry = view.by_index(idx).unwrap();
        assert_eq!(&root.entries[idx].name, name);
        assert_eq!(view_entry.name(), *name);
        assert_eq!(root.entries[idx].is_dir(), data.is_none());
        assert_eq!(view_entry.is_dir(), data.is_none());
        if let Some(data) = data {
            let crc = crc32fast::hash(data);
            assert_eq!(root.entries[idx].crc32, crc);
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
fn mixed_width_records_use_payload_positions_even_with_embedded_signatures() {
    let fake = b"PK\x03\x04PK\x07\x08PK\x01\x02PK\x05\x06PK\x06\x06PK\x06\x07";
    let crc_marker = b"\xac\x0a\x7a\xd5";
    assert_eq!(crc32fast::hash(crc_marker), 0x0807_4b50);
    let comment = b"a\0\xffPK\x05\x06";
    let mut sink = WriteOnly(Vec::new());
    let mut writer = ZipStreamWriter::new(&mut sink, WriterOptions { comment, ..WriterOptions::default() }).unwrap();
    assert_eq!(writer.usage().io_attempts, 0);
    let cases = [
        ("duplicate", Method::Stored, &fake[..], InputLength::Exact(fake.len() as u64), 0, 16),
        ("tiny1", deflate(1), &b"exact deflate"[..], InputLength::Exact(13), 8, 24),
        ("tiny6", deflate(6), &b"unknown deflate"[..], InputLength::Unknown, 8, 24),
        ("tiny9", deflate(9), &b"another level"[..], InputLength::Exact(13), 8, 24),
        ("unknown", Method::Stored, &b"unknown stored"[..], InputLength::Unknown, 0, 24),
        ("duplicate", Method::Stored, &crc_marker[..], InputLength::Exact(4), 0, 16),
        ("empty-exact", deflate(1), &b""[..], InputLength::Exact(0), 0, 0),
        ("empty-unknown", deflate(6), &b""[..], InputLength::Unknown, 0, 0),
    ];
    let mut wire = Vec::new();
    let mut expected = Vec::new();
    for (name, method, data, length, method_code, descriptor) in cases {
        let result = writer.add_file(entry(name, method), &mut &*data, length).unwrap();
        assert_eq!(result.ordinal, expected.len() as u64);
        assert_eq!(result.crc32, crc32fast::hash(data));
        assert_eq!(result.decoded_size, data.len() as u64);
        assert_eq!(result.method, if data.is_empty() { Method::Stored } else { method });
        wire.push(WireMember::new(name, data, method_code, descriptor));
        expected.push((name, Some(data)));
    }
    writer.add_directory(entry("nested/", Method::Stored)).unwrap();
    wire.push(WireMember::new("nested/", b"", 0, 0));
    expected.push(("nested/", None));
    let finished = writer.finish().unwrap();
    let bytes = &finished.sink.0;
    let end = tail(&mut Cursor::new(bytes), comment);
    assert_eq!(finished.summary.central_offset, end.central);
    assert_eq!(finished.summary.usage.central_bytes, end.size);
    assert_eq!(finished.summary.usage.entries, end.count);
    assert_eq!(finished.summary.usage.output_bytes, bytes.len() as u64);
    assert_eq!(finished.summary.usage.archive_extent, bytes.len() as u64);
    assert!(check_wire(&mut Cursor::new(bytes), comment, &wire));
    check_readers(bytes, &expected, comment);
}

#[test]
fn malformed_descriptors_fail_positional_framing_even_if_readers_decode() {
    let data = b"data";
    let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
    writer.add_file(entry("x", Method::Stored), &mut data.as_slice(), InputLength::Exact(4)).unwrap();
    let bytes = writer.finish().unwrap().sink.0;
    let wire = [WireMember::new("x", data, 0, 16)];
    let descriptor = 30 + 1 + data.len();
    assert!(check_wire(&mut Cursor::new(&bytes), b"", &wire));
    for index in [0, 4, 8, 12] {
        let mut corrupted = bytes.clone();
        corrupted[descriptor + index] ^= 1;
        assert!(!check_wire(&mut Cursor::new(&corrupted), b"", &wire));
        check_readers(&corrupted, &[("x", Some(data))], b"");
    }
    // Retain a coherent classic end record while shortening or widening
    // only the space between the payload and central directory.
    for delta in [-1isize, 8] {
        let mut corrupted = bytes.clone();
        let old_central = descriptor + 16;
        if delta < 0 {
            corrupted.remove(old_central - 1);
        } else {
            corrupted.splice(old_central..old_central, [0; 8]);
        }
        let at = corrupted.len() - 6;
        let central = (old_central as u32).wrapping_add_signed(delta as i32);
        corrupted[at..at + 4].copy_from_slice(&central.to_le_bytes());
        assert!(!check_wire(&mut Cursor::new(&corrupted), b"", &wire));
        check_readers(&corrupted, &[("x", Some(data))], b"");
    }
}

#[test]
fn descriptor_bytes_count_in_both_preflight_and_late_tail_checks() {
    // x has a 31-byte local header, one byte of payload, a 16-byte
    // descriptor, 47 central bytes and a 22-byte end record.
    for limit in [Limit::ArchiveExtent, Limit::OutputBytes] {
        for max in [116, 117] {
            let mut limits = WriteLimits::default();
            match limit {
                Limit::ArchiveExtent => limits.archive_extent = max,
                Limit::OutputBytes => limits.output_bytes = max,
                _ => unreachable!(),
            }
            let mut writer =
                ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions { limits, ..WriterOptions::default() })
                    .unwrap();
            let mut source = b"y".as_slice();
            let result = writer.add_file(entry("x", Method::Stored), &mut source, InputLength::Exact(1));
            if max == 117 {
                result.unwrap();
                assert_eq!(writer.finish().unwrap().summary.usage.output_bytes, 117);
            } else {
                assert!(matches!(result, Err(WriteError::Limit(actual)) if actual == limit));
                assert_eq!(source, b"y");
                assert_eq!(writer.usage().output_bytes, 0);
                assert!(writer.finish().is_ok());
            }
        }

        // Wide prospective cost is 51 + 24 + 67 + 98. The first payload
        // byte fits itself but leaves the complete descriptor/tail infeasible.
        let mut limits = WriteLimits::default();
        match limit {
            Limit::ArchiveExtent => limits.archive_extent = 240,
            Limit::OutputBytes => limits.output_bytes = 240,
            _ => unreachable!(),
        }
        let mut writer =
            ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
        let result = writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Unknown);
        assert!(matches!(result, Err(WriteError::Limit(actual)) if actual == limit));
        assert_eq!(writer.usage().source_bytes, 1);
        assert_eq!(writer.usage().output_bytes, 52);
        assert_eq!(writer.usage().entries, 0);
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    }
}

struct CancelOnFlush(Cancellation);

impl Write for CancelOnFlush {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.cancel();
        Ok(())
    }
}

#[test]
fn final_flush_cancellation_never_returns_the_sink_as_finished() {
    let cancel = Cancellation::default();
    let options = WriterOptions { cancel: Some(cancel.clone()), ..WriterOptions::default() };
    let writer = ZipStreamWriter::new(CancelOnFlush(cancel), options).unwrap();
    assert!(matches!(writer.finish(), Err(WriteError::Canceled)));
}

struct DescriptorError {
    accepted: usize,
}

impl Write for DescriptorError {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.accepted == 33 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "descriptor failure"));
        }
        let n = data.len().min(33 - self.accepted);
        self.accepted += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("poisoned finish must not flush");
    }
}

#[test]
fn a_partial_descriptor_preserves_the_io_cause_and_poisons() {
    let mut sink = DescriptorError { accepted: 0 };
    let mut writer = ZipStreamWriter::new(&mut sink, WriterOptions::default()).unwrap();
    let err = writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(1)).unwrap_err();
    let WriteError::Io { stage: IoStage::DataDescriptor, source } = err else {
        panic!("wrong error: {err:?}");
    };
    assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(writer.usage().output_bytes, 33);
    assert_eq!(writer.usage().entries, 0);
    let err = writer.add_directory(entry("dir/", Method::Stored)).unwrap_err();
    let WriteError::Failed(cause) = err else { panic!("wrong error: {err:?}") };
    let WriteError::Io { source: original, .. } = cause.as_ref() else { panic!("wrong cause: {cause:?}") };
    assert!(std::sync::Arc::ptr_eq(original, &source));
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    assert_eq!(sink.accepted, 33);
}

const LARGE_BYTES: u64 = (1 << 32) + 4096;
const LARGE_VALUE: u8 = b'Z';

fn reference_dir(temporary: &tempfile::TempDir) -> std::path::PathBuf {
    std::env::var_os("ZIPFAST_STREAM_REFERENCE_DIR")
        .map_or_else(|| temporary.path().to_path_buf(), std::path::PathBuf::from)
}

fn check_large_stream(method: Method, filename: &str) {
    let temporary = tempfile::tempdir().unwrap();
    let path = reference_dir(&temporary).join(filename);
    let file = WriteOnly(std::fs::File::create(&path).unwrap());
    let mut zip = ZipStreamWriter::new(file, WriterOptions::default()).unwrap();
    let first = zip
        .add_file(entry("large", method), &mut io::repeat(LARGE_VALUE).take(LARGE_BYTES), InputLength::Unknown)
        .unwrap();
    assert_eq!(first.decoded_size, LARGE_BYTES);
    assert_eq!(first.packed_size == LARGE_BYTES, method == Method::Stored);

    let after = zip.add_file(entry("after", Method::Stored), &mut b"tail".as_slice(), InputLength::Exact(4)).unwrap();
    let empty = zip.add_file(entry("empty", deflate(9)), &mut b"".as_slice(), InputLength::Unknown).unwrap();
    let mut options = entry("dir/", Method::Stored);
    options.permissions = Permissions::new(0o755).unwrap();
    let directory = zip.add_directory(options).unwrap();
    let result = zip.finish().unwrap();
    let summary = result.summary;
    let extent = result.sink.0.metadata().unwrap().len();
    drop(result);
    assert!(summary.zip64);
    assert_eq!(after.local_offset, 55 + first.packed_size + 24);
    assert_eq!(empty.local_offset, after.local_offset + 35 + 4 + 16);
    assert_eq!(directory.local_offset, empty.local_offset + 35);
    assert_eq!(summary.central_offset, directory.local_offset + 34);
    assert_eq!(summary.usage.archive_extent, extent);
    assert_eq!(summary.usage.output_bytes, extent);
    assert_eq!(summary.usage.decoded_bytes, LARGE_BYTES + 4);
    assert_eq!(summary.usage.packed_bytes, first.packed_size + 4);
    assert_eq!(summary.usage.source_bytes, LARGE_BYTES + 4);
    eprintln!("{filename}: {summary:?}; first={first:?}");

    let mut file = std::fs::File::open(&path).unwrap();
    let mut root = Archive::open(&path).unwrap();
    assert_eq!(root.entries[0].size, LARGE_BYTES);
    assert_eq!(root.entries[1].local_at, after.local_offset);
    let mut checked = 0;
    let mut independent_crc = crc32fast::Hasher::new();
    root.read_at(0, None, LARGE_BYTES, |chunk| {
        assert!(chunk.iter().all(|&byte| byte == LARGE_VALUE));
        independent_crc.update(chunk);
        checked += chunk.len() as u64;
        Ok(())
    })
    .unwrap();
    assert_eq!(checked, LARGE_BYTES);
    let crc = independent_crc.finalize();
    assert_eq!(first.crc32, crc);
    assert_eq!(root.entries[0].crc32, crc);
    root.read_at(1, None, 4, |chunk| {
        assert_eq!(chunk, b"tail");
        Ok(())
    })
    .unwrap();
    root.read_at(2, None, 1, |_| panic!("empty payload")).unwrap();

    let offset_wide = method == Method::Stored;
    let expected = [
        WireMember { crc, decoded: LARGE_BYTES, ..WireMember::new("large", b"", if offset_wide { 0 } else { 8 }, 24) },
        WireMember { offset_wide, ..WireMember::new("after", b"tail", 0, 16) },
        WireMember { offset_wide, ..WireMember::new("empty", b"", 0, 0) },
        WireMember { offset_wide, external: 0x41ed_0010, ..WireMember::new("dir/", b"", 0, 0) },
    ];
    assert!(check_wire(&mut file, b"", &expected));

    let view = zipview::ZipIndex::open::<io::Error>(extent, |offset, buf| {
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(buf)
    })
    .unwrap();
    assert_eq!(view.entries().len(), expected.len());
    let large = view.by_index(0).unwrap();
    assert_eq!(large.name(), "large");
    assert_eq!(large.size(), LARGE_BYTES);
    assert_eq!(large.compressed_size(), first.packed_size);
    assert_eq!(large.crc32(), crc);
    for (idx, data) in [(1, &b"tail"[..]), (2, &b""[..])] {
        let entry = view.by_index(idx).unwrap();
        let header = view.header_range(entry).unwrap();
        let range = view.entry_range(entry, &read_at::<_, 30>(&mut file, header.start)).unwrap();
        file.seek(SeekFrom::Start(range.start)).unwrap();
        let mut bytes = vec![0; (range.end - range.start) as usize];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(view.read_entry(entry, &bytes).unwrap(), data);
        assert_eq!(entry.crc32(), crc32fast::hash(data));
    }
    assert!(view.by_index(3).unwrap().is_dir());
}

#[test]
#[ignore = "streams and verifies a physical archive above 4 GiB"]
fn unknown_stored_above_four_gib_has_an_offset_only_narrow_descriptor() {
    check_large_stream(Method::Stored, "large-stored.zip");
}

#[test]
#[ignore = "streams and verifies more than 4 GiB of decoded Deflate"]
fn deflate_stream_above_four_gib_decoded() {
    check_large_stream(deflate(1), "large-deflate.zip");
}

#[test]
#[ignore = "exports small fixtures for pinned external readers"]
fn export_stream_reference_fixtures() {
    let directory = std::path::PathBuf::from(std::env::var_os("ZIPFAST_STREAM_REFERENCE_DIR").unwrap());
    let payload = b"tiny forced ZIP64 member";
    std::fs::write(directory.join("tiny.expected"), payload).unwrap();
    std::fs::write(directory.join("after.expected"), b"tail").unwrap();
    for (name, method, length, descriptor, method_code) in [
        ("narrow-stored", Method::Stored, InputLength::Exact(24), 16, 0),
        ("known-deflate", deflate(6), InputLength::Exact(24), 24, 8),
        ("unknown-deflate", deflate(6), InputLength::Unknown, 24, 8),
        ("unknown-stored", Method::Stored, InputLength::Unknown, 24, 0),
    ] {
        let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
        writer.add_file(entry("tiny", method), &mut payload.as_slice(), length).unwrap();
        let bytes = writer.finish().unwrap().sink.0;
        assert!(check_wire(
            &mut Cursor::new(&bytes),
            b"",
            &[WireMember::new("tiny", payload, method_code, descriptor)]
        ));
        std::fs::write(directory.join(format!("{name}.zip")), bytes).unwrap();
    }
    let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
    writer.add_file(entry("tiny", Method::Stored), &mut payload.as_slice(), InputLength::Unknown).unwrap();
    writer.add_file(entry("after", Method::Stored), &mut b"tail".as_slice(), InputLength::Exact(4)).unwrap();
    let bytes = writer.finish().unwrap().sink.0;
    assert!(check_wire(
        &mut Cursor::new(&bytes),
        b"",
        &[WireMember::new("tiny", payload, 0, 24), WireMember::new("after", b"tail", 0, 16)]
    ));
    std::fs::write(directory.join("mixed.zip"), bytes).unwrap();

    let writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
    let bytes = writer.finish().unwrap().sink.0;
    assert!(check_wire(&mut Cursor::new(&bytes), b"", &[]));
    std::fs::write(directory.join("empty.zip"), bytes).unwrap();

    let comment = b"archive comment";
    let mut writer =
        ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions { comment, ..WriterOptions::default() }).unwrap();
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
    let bytes = writer.finish().unwrap().sink.0;
    let dos = (0x1883, 0x5022);
    let wire = [
        WireMember { dos, external: 0x41ed_0010, ..WireMember::new("nested/", b"", 0, 0) },
        WireMember {
            dos,
            comment: tool.comment,
            mtime: tool.extended_mtime,
            external: 0x81e9_0000,
            ..WireMember::new("nested/tool", payload, 0, 16)
        },
        WireMember::new("empty", b"", 0, 0),
    ];
    assert!(check_wire(&mut Cursor::new(&bytes), comment, &wire));
    check_readers(&bytes, &[("nested/", None), ("nested/tool", Some(payload)), ("empty", Some(b""))], comment);
    std::fs::write(directory.join("metadata.zip"), bytes).unwrap();

    let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
    let mut raw = entry("", Method::Stored);
    raw.name = EntryName::Raw(b"raw\x82\0\x01\x7f");
    raw.comment = b"raw\0\xff";
    writer.add_file(raw, &mut payload.as_slice(), InputLength::Exact(24)).unwrap();
    let bytes = writer.finish().unwrap().sink.0;
    let wire = [WireMember {
        name: b"raw\x82\0\x01\x7f",
        comment: raw.comment,
        utf8: false,
        ..WireMember::new("", payload, 0, 16)
    }];
    assert!(check_wire(&mut Cursor::new(&bytes), b"", &wire));
    std::fs::write(directory.join("raw.zip"), bytes).unwrap();
}

#[derive(Clone, Copy, Debug)]
enum Call {
    Read(usize),
    Write { position: usize, accepted: usize },
    Flush,
}

#[derive(Clone, Copy)]
enum Fault {
    Fail,
    Interrupt,
    Zero,
    Oversized,
    Cancel,
}

#[derive(Default)]
struct Script {
    calls: std::cell::RefCell<Vec<Call>>,
    fault: Option<(usize, Fault)>,
    cancel: Cancellation,
}

impl Script {
    fn record(&self, call: Call) -> Option<Fault> {
        let mut calls = self.calls.borrow_mut();
        let index = calls.len();
        calls.push(call);
        match self.fault {
            Some((at, action)) if at == index => {
                if matches!(action, Fault::Cancel) {
                    self.cancel.cancel();
                }
                Some(action)
            }
            _ => None,
        }
    }
}

struct ScriptSink<'a> {
    script: &'a Script,
    bytes: Vec<u8>,
    chunk: usize,
}

fn injected() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "script failure")
}

impl Write for ScriptSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = bytes.len().min(self.chunk);
        match self.script.record(Call::Write { position: self.bytes.len(), accepted: n }) {
            Some(Fault::Fail) => Err(injected()),
            Some(Fault::Interrupt) => Err(io::ErrorKind::Interrupted.into()),
            Some(Fault::Zero) => Ok(0),
            Some(Fault::Oversized) => Ok(bytes.len() + 1),
            _ => {
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.script.record(Call::Flush) {
            Some(Fault::Fail) => Err(injected()),
            Some(Fault::Interrupt) => Err(io::ErrorKind::Interrupted.into()),
            _ => Ok(()),
        }
    }
}

struct ScriptSource<'a> {
    script: &'a Script,
    data: &'a [u8],
    chunk: usize,
}

impl Read for ScriptSource<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let n = output.len().min(self.data.len()).min(self.chunk);
        match self.script.record(Call::Read(n)) {
            Some(Fault::Fail) => Err(injected()),
            Some(Fault::Interrupt) => Err(io::ErrorKind::Interrupted.into()),
            Some(Fault::Oversized) => Ok(output.len() + 1),
            _ => self.data.read(&mut output[..n]),
        }
    }
}

const SCRIPT_BYTES: &[u8] = b"0123456789abcdefg";
const SCRIPT_COMMENT: &[u8] = b"comment";

#[derive(Clone, Copy)]
struct ScriptCase {
    length: InputLength,
    payload_at: usize,
    descriptor_at: usize,
    central_at: usize,
    end_at: usize,
}

impl ScriptCase {
    fn new(wide: bool) -> Self {
        let length = if wide { InputLength::Unknown } else { InputLength::Exact(17) };
        // local: 30 + 1 name + 9 mtime + optional 20 size extra
        let payload_at = if wide { 60 } else { 40 };
        let descriptor_at = payload_at + SCRIPT_BYTES.len();
        let central_at = descriptor_at + if wide { 24 } else { 16 };
        // central: 46 + 1 name + 9 mtime + optional 20 size extra
        let end_at = central_at + if wide { 76 } else { 56 };
        Self { length, payload_at, descriptor_at, central_at, end_at }
    }

    fn stage(self, call: Call) -> IoStage {
        match call {
            Call::Read(_) => IoStage::SourceRead,
            Call::Flush => IoStage::Flush,
            Call::Write { position, .. } if position < self.payload_at => IoStage::LocalHeader,
            Call::Write { position, .. } if position < self.descriptor_at => IoStage::Payload,
            Call::Write { position, .. } if position < self.central_at => IoStage::DataDescriptor,
            Call::Write { position, .. } if position < self.end_at => IoStage::CentralDirectory,
            Call::Write { .. } => IoStage::EndRecord,
        }
    }

    fn run(self, script: &Script, chunk: usize) -> Result<Vec<u8>, WriteError> {
        let mut sink = ScriptSink { script, bytes: Vec::new(), chunk };
        let mut source = ScriptSource { script, data: SCRIPT_BYTES, chunk: 7 };
        let options =
            WriterOptions { comment: SCRIPT_COMMENT, cancel: Some(script.cancel.clone()), ..WriterOptions::default() };
        let mut writer = ZipStreamWriter::new(&mut sink, options).unwrap();
        assert!(script.calls.borrow().is_empty());
        let mut options = entry("x", Method::Stored);
        options.extended_mtime = Some(0);
        let result = writer.add_file(options, &mut source, self.length);
        let usage = writer.usage();
        if let Err(error) = result {
            let calls = script.calls.borrow().len();
            let (index, fault) = script.fault.unwrap();
            assert_eq!(calls, index + 1);
            let logged = script.calls.borrow();
            let source_bytes = logged[..calls]
                .iter()
                .enumerate()
                .filter_map(|(i, call)| match call {
                    Call::Read(n) if i != index || matches!(fault, Fault::Cancel) => Some(*n as u64),
                    _ => None,
                })
                .sum::<u64>();
            let written = logged[..calls]
                .iter()
                .enumerate()
                .filter_map(|(i, call)| match call {
                    Call::Write { accepted, .. } if i != index || matches!(fault, Fault::Cancel) => {
                        Some(*accepted as u64)
                    }
                    _ => None,
                })
                .sum::<u64>();
            drop(logged);
            assert_eq!(usage.source_bytes, source_bytes);
            assert_eq!(usage.output_bytes, written);
            assert_eq!(usage.archive_extent, written);
            assert_eq!(usage.io_attempts, calls as u64);
            assert_eq!(usage.entries, 0);
            assert_eq!(usage.central_bytes, 0);
            assert_eq!(usage.decoded_bytes, 0);
            assert_eq!(usage.packed_bytes, 0);
            assert!(matches!(writer.add_file(options, &mut source, self.length), Err(WriteError::Failed(_))));
            assert!(matches!(writer.add_directory(entry("d/", Method::Stored)), Err(WriteError::Failed(_))));
            assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
            assert_eq!(script.calls.borrow().len(), calls);
            assert_eq!(sink.bytes.len() as u64, written);
            return Err(error);
        }
        assert_eq!(usage.entries, 1);
        assert_eq!(usage.source_bytes, SCRIPT_BYTES.len() as u64);
        assert_eq!(usage.output_bytes, self.central_at as u64);
        let finished = writer.finish()?;
        assert_eq!(finished.summary.usage.io_attempts, script.calls.borrow().len() as u64);
        Ok(sink.bytes)
    }
}

fn assert_stage(error: WriteError, expected_stage: IoStage, expected_kind: io::ErrorKind) {
    let WriteError::Io { stage, source } = error else { panic!("wrong error: {error:?}") };
    assert_eq!(stage, expected_stage);
    assert_eq!(source.kind(), expected_kind);
    if expected_kind == io::ErrorKind::BrokenPipe {
        assert_eq!(source.to_string(), "script failure");
    }
}

#[test]
fn fails_each_actual_read_write_and_flush_with_precise_stages() {
    for wide in [false, true] {
        let case = ScriptCase::new(wide);
        for chunk in [1, 7] {
            let success = Script::default();
            let _bytes = case.run(&success, chunk).unwrap();
            let calls = success.calls.into_inner();
            assert!(matches!(calls[0], Call::Read(7)));
            assert!(calls.iter().any(|call| matches!(call, Call::Read(0))));
            assert!(matches!(calls.last(), Some(Call::Flush)));
            let descriptor_calls = calls.iter().filter(|&&call| case.stage(call) == IoStage::DataDescriptor).count();
            assert_eq!(descriptor_calls, (case.central_at - case.descriptor_at).div_ceil(chunk));
            for (index, call) in calls.iter().copied().enumerate() {
                let stage = case.stage(call);
                let script = Script { fault: Some((index, Fault::Fail)), ..Script::default() };
                assert_stage(case.run(&script, chunk).unwrap_err(), stage, io::ErrorKind::BrokenPipe);
                assert_eq!(script.calls.borrow().len(), index + 1, "{stage:?} at call {index}");
            }
        }
    }
}

#[test]
fn retries_interrupted_descriptor_writes_and_rejects_invalid_counts() {
    for wide in [false, true] {
        let case = ScriptCase::new(wide);
        let success = Script::default();
        let bytes = case.run(&success, 7).unwrap();
        let calls = success.calls.into_inner();
        let first = calls.iter().position(|&call| case.stage(call) == IoStage::DataDescriptor).unwrap();
        for index in [first, first + 1] {
            let script = Script { fault: Some((index, Fault::Interrupt)), ..Script::default() };
            assert_eq!(case.run(&script, 7).unwrap(), bytes);
            assert_eq!(script.calls.borrow().len(), calls.len() + 1);
            for (fault, kind) in
                [(Fault::Zero, io::ErrorKind::WriteZero), (Fault::Oversized, io::ErrorKind::InvalidData)]
            {
                let script = Script { fault: Some((index, fault)), ..Script::default() };
                assert_stage(case.run(&script, 7).unwrap_err(), IoStage::DataDescriptor, kind);
            }
        }
    }
}

#[test]
fn cancellation_inside_calls_stops_at_the_next_checkpoint() {
    let case = ScriptCase::new(true);
    let success = Script::default();
    let _bytes = case.run(&success, 3).unwrap();
    let calls = success.calls.into_inner();
    let first_payload = calls.iter().position(|&call| case.stage(call) == IoStage::Payload).unwrap();
    let first_descriptor = calls.iter().position(|&call| case.stage(call) == IoStage::DataDescriptor).unwrap();
    let last_descriptor = calls.iter().rposition(|&call| case.stage(call) == IoStage::DataDescriptor).unwrap();
    let first_central = calls.iter().position(|&call| case.stage(call) == IoStage::CentralDirectory).unwrap();
    let last_end = calls.iter().rposition(|&call| case.stage(call) == IoStage::EndRecord).unwrap();
    for index in [0, first_payload, first_descriptor, last_descriptor, first_central, last_end, calls.len() - 1] {
        let script = Script { fault: Some((index, Fault::Cancel)), ..Script::default() };
        assert!(matches!(case.run(&script, 3), Err(WriteError::Canceled)));
        assert_eq!(script.calls.borrow().len(), index + 1);
    }
}

#[test]
fn construction_and_drop_never_call_the_sink() {
    let script = Script::default();
    let mut sink = ScriptSink { script: &script, bytes: Vec::new(), chunk: 7 };
    let writer = ZipStreamWriter::new(&mut sink, WriterOptions::default()).unwrap();
    assert!(script.calls.borrow().is_empty());
    drop(writer);
    assert!(script.calls.borrow().is_empty());

    let mut writer = ZipStreamWriter::new(&mut sink, WriterOptions::default()).unwrap();
    writer.add_directory(entry("d/", Method::Stored)).unwrap();
    let before_drop = script.calls.borrow().len();
    drop(writer);
    assert_eq!(script.calls.borrow().len(), before_drop);
    assert_eq!(sink.bytes.len(), 32);

    let cancel = Cancellation::default();
    cancel.cancel();
    let options = WriterOptions { cancel: Some(cancel), ..WriterOptions::default() };
    assert!(matches!(ZipStreamWriter::new(&mut sink, options), Err(WriteError::Canceled)));
    assert_eq!(script.calls.borrow().len(), before_drop);
}

#[test]
fn finite_entry_source_and_metadata_limits_accept_exact_boundaries() {
    // One narrow member named x with one payload byte; two-byte archive comment.
    for (limit, boundary) in [
        (Limit::Entries, 1),
        (Limit::CentralBytes, 47),
        (Limit::MetadataCapacity, 49),
        (Limit::EntryDecodedBytes, 1),
        (Limit::SourceBytes, 2),
    ] {
        for delta in [0, 1] {
            let mut limits = WriteLimits::default();
            let value = boundary - delta;
            match limit {
                Limit::Entries => limits.entries = value,
                Limit::CentralBytes => limits.central_bytes = value,
                Limit::MetadataCapacity => limits.metadata_capacity = value,
                Limit::EntryDecodedBytes => limits.entry_decoded_bytes = value,
                Limit::SourceBytes => limits.source_bytes = value,
                _ => unreachable!(),
            }
            let options = WriterOptions { comment: b"ok", limits, ..WriterOptions::default() };
            let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), options).unwrap();
            let mut source = b"y".as_slice();
            let result = writer.add_file(entry("x", Method::Stored), &mut source, InputLength::Exact(1));
            if delta == 0 {
                result.unwrap();
                assert_eq!(source, b"");
                let usage = writer.finish().unwrap().summary.usage;
                assert_eq!(usage.source_bytes, 1);
                assert_eq!(usage.central_bytes, 47);
                assert_eq!(usage.output_bytes, 119);
            } else {
                assert!(matches!(result, Err(WriteError::Limit(actual)) if actual == limit));
                assert_eq!(source, b"y");
                assert_eq!(writer.usage().output_bytes, 0);
                assert_eq!(writer.finish().unwrap().summary.usage.output_bytes, 24);
            }
        }
    }
}

#[test]
fn unknown_empty_reserves_the_prospective_descriptor_and_wide_tail() {
    for max in [239, 240] {
        let limits = WriteLimits { archive_extent: max, output_bytes: max, ..WriteLimits::default() };
        let mut writer =
            ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions { limits, ..WriterOptions::default() }).unwrap();
        let result = writer.add_file(entry("x", deflate(6)), &mut b"".as_slice(), InputLength::Unknown);
        if max == 239 {
            assert!(matches!(result, Err(WriteError::Limit(Limit::ArchiveExtent))));
            assert_eq!(writer.usage().io_attempts, 0);
            writer.add_file(entry("x", deflate(6)), &mut b"".as_slice(), InputLength::Exact(0)).unwrap();
        } else {
            assert_eq!(result.unwrap().method, Method::Stored);
        }
        let finished = writer.finish().unwrap();
        assert_eq!(finished.summary.usage.output_bytes, 100);
        assert!(!finished.summary.zip64);
        assert!(check_wire(&mut Cursor::new(finished.sink.0), b"", &[WireMember::new("x", b"", 0, 0)]));
    }
}

#[test]
fn exact_lengths_probe_eof_and_charge_surplus_bytes() {
    for (size, data, accepted_source, header_payload) in
        [(0, &b"z"[..], 1, 0), (1, &b"yz"[..], 2, 32), (2, &b"y"[..], 1, 32)]
    {
        let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
        let mut input = data;
        let error = writer.add_file(entry("x", Method::Stored), &mut input, InputLength::Exact(size)).unwrap_err();
        if size <= 1 {
            assert!(matches!(error, WriteError::SizeOverrun { expected } if expected == size));
        } else {
            assert!(matches!(error, WriteError::SizeUnderrun { expected: 2, actual: 1 }));
        }
        assert_eq!(input, b"");
        assert_eq!(writer.usage().source_bytes, accepted_source);
        assert_eq!(writer.usage().output_bytes, header_payload);
        assert_eq!(writer.usage().entries, 0);
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    }
}

#[test]
fn progressing_unknown_input_stops_at_real_eof_or_byte_ceilings() {
    for (source, decoded, expected, charged) in [(3, 2, Limit::EntryDecodedBytes, 3), (2, 3, Limit::SourceBytes, 2)] {
        let limits = WriteLimits { source_bytes: source, entry_decoded_bytes: decoded, ..WriteLimits::default() };
        let options = WriterOptions { limits, ..WriterOptions::default() };
        let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), options.clone()).unwrap();
        let result = writer.add_file(entry("x", Method::Stored), &mut io::repeat(0), InputLength::Unknown);
        assert!(matches!(result, Err(WriteError::Limit(limit)) if limit == expected));
        assert_eq!(writer.usage().source_bytes, charged);
        assert_eq!(writer.usage().output_bytes, 53);
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));

        let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), options).unwrap();
        let result = writer.add_file(entry("x", Method::Stored), &mut b"zz".as_slice(), InputLength::Unknown);
        if source == 3 {
            assert_eq!(result.unwrap().decoded_size, 2);
            assert_eq!(writer.finish().unwrap().summary.usage.source_bytes, 2);
        } else {
            assert!(matches!(result, Err(WriteError::Limit(Limit::SourceBytes))));
            assert_eq!(writer.usage().source_bytes, 2);
        }
    }
}

#[derive(Default)]
struct InterruptingSink {
    write_interrupts: bool,
    writes: u64,
    flushes: u64,
}

impl Write for InterruptingSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.write_interrupts { Err(io::ErrorKind::Interrupted.into()) } else { Ok(data.len()) }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        Err(io::ErrorKind::Interrupted.into())
    }
}

#[test]
fn zipcrypto_entry_attempt_bound_accounts_for_an_empty_name() {
    let options =
        WriterOptions { limits: WriteLimits { io_attempts: 5, ..WriteLimits::default() }, ..WriterOptions::default() };
    let mut writer = ZipStreamWriter::new(io::sink(), options).unwrap();
    let result = writer
        .add_zipcrypto_file(
            entry("", Method::Stored),
            &mut io::empty(),
            InputLength::Exact(0),
            "zipfast-test-only",
            |random| {
                random.fill(9);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((result.decoded_size, result.packed_size), (0, 12));
    assert_eq!(writer.usage().io_attempts, 5);
    assert!(matches!(writer.finish(), Err(WriteError::Limit(Limit::IoAttempts))));
}

#[test]
fn retries_and_codec_iterations_consume_the_finite_attempt_budget() {
    let options = |io_attempts| WriterOptions {
        limits: WriteLimits { io_attempts, ..WriteLimits::default() },
        ..WriterOptions::default()
    };
    let mut reader_calls = 0;
    let mut interrupted = |_: &mut [u8]| -> io::Result<usize> {
        reader_calls += 1;
        Err(io::ErrorKind::Interrupted.into())
    };
    struct FunctionReader<F>(F);
    impl<F: FnMut(&mut [u8]) -> io::Result<usize>> Read for FunctionReader<F> {
        fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
            (self.0)(data)
        }
    }
    let mut writer = ZipStreamWriter::new(io::sink(), options(4)).unwrap();
    let result =
        writer.add_file(entry("x", Method::Stored), &mut FunctionReader(&mut interrupted), InputLength::Unknown);
    assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!(reader_calls, 4);
    assert_eq!(writer.usage().io_attempts, 4);
    assert_eq!(writer.usage().source_bytes, 0);
    assert_eq!(writer.usage().output_bytes, 0);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));

    let mut sink = InterruptingSink { write_interrupts: true, ..InterruptingSink::default() };
    let mut writer = ZipStreamWriter::new(&mut sink, options(4)).unwrap();
    let result = writer.add_file(entry("x", Method::Stored), &mut b"z".as_slice(), InputLength::Exact(1));
    assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!(writer.usage().io_attempts, 4);
    assert_eq!(writer.usage().source_bytes, 1);
    assert_eq!(writer.usage().output_bytes, 0);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    assert_eq!((sink.writes, sink.flushes), (3, 0));

    let mut sink = InterruptingSink::default();
    let writer = ZipStreamWriter::new(&mut sink, options(4)).unwrap();
    assert!(matches!(writer.finish(), Err(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!((sink.writes, sink.flushes), (1, 3));

    let mut writer = ZipStreamWriter::new(io::sink(), options(4)).unwrap();
    let result = writer.add_file(entry("x", deflate(6)), &mut b"z".as_slice(), InputLength::Exact(1));
    assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!(writer.usage().io_attempts, 4);
    assert_eq!(writer.usage().output_bytes, 51);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));

    for cap in [8, 9] {
        let mut writer = ZipStreamWriter::new(io::sink(), options(cap)).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"z".as_slice(), InputLength::Exact(1)).unwrap();
        assert_eq!(writer.usage().io_attempts, 6);
        let result = writer.finish();
        if cap == 9 {
            assert_eq!(result.unwrap().summary.usage.io_attempts, cap);
        } else {
            assert!(matches!(result, Err(WriteError::Limit(Limit::IoAttempts))));
        }
    }
}

#[test]
fn stored_and_expanding_deflate_stream_across_input_chunk_boundaries() {
    let mut state = 0x4321_8765u32;
    let data: Vec<u8> = (0..196_613)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    for chunk in [1, 7, 65_535, 65_536, 65_537] {
        let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
        let cases = [
            ("stored", Method::Stored, InputLength::Exact(data.len() as u64), 0, 16),
            ("deflate", deflate(6), InputLength::Unknown, 8, 24),
        ];
        let mut wire = Vec::new();
        let script = Script::default();
        for (name, method, length, code, descriptor) in cases {
            let mut source = ScriptSource { script: &script, data: &data, chunk };
            let written = writer.add_file(entry(name, method), &mut source, length).unwrap();
            assert_eq!(written.method, method);
            if method != Method::Stored {
                assert!(written.packed_size > written.decoded_size);
            }
            wire.push(WireMember::new(name, &data, code, descriptor));
        }
        let bytes = writer.finish().unwrap().sink.0;
        assert!(check_wire(&mut Cursor::new(&bytes), b"", &wire));
        check_readers(&bytes, &[("stored", Some(&data)), ("deflate", Some(&data))], b"");
    }
}

#[test]
fn count_only_zip64_keeps_earlier_descriptors_narrow() {
    for count in [65_534, 65_535, 65_536] {
        let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
        writer.add_file(entry("x", Method::Stored), &mut b"z".as_slice(), InputLength::Exact(1)).unwrap();
        for ordinal in 1..count {
            assert_eq!(writer.add_directory(entry("d/", Method::Stored)).unwrap().ordinal, ordinal);
        }
        let result = writer.finish().unwrap();
        let bytes = result.sink.0;
        assert_eq!(result.summary.usage.entries, count);
        assert_eq!(result.summary.central_offset, 48 + (count - 1) * 32);
        assert_eq!(result.summary.usage.central_bytes, 47 + (count - 1) * 48);
        let end = tail(&mut Cursor::new(&bytes), b"");
        assert_eq!(end.wide, count >= 65_535);
        assert_eq!(end.count, count);
        assert_eq!(&bytes[48..52], b"PK\x03\x04");
        assert_eq!(n16(&bytes, 4), 20);
        assert!(descriptor_matches(&mut Cursor::new(&bytes), 32, 48, 16, crc32fast::hash(b"z"), 1, 1));
        for profile in [Profile::Zipfast, Profile::Zipview] {
            let parsed = parse_slice(&bytes, profile, Limits::default()).unwrap();
            assert_eq!(parsed.entries.len() as u64, count);
            assert_eq!(parsed.zip64_end.is_some(), end.wide);
            assert_eq!(parsed.prefix_shift, 0);
            assert_eq!(parsed.directory_range, end.central..end.central + end.size);
        }
    }
}

#[test]
fn oversized_metadata_and_impossible_lengths_are_recoverable_preflight_failures() {
    let limits = WriteLimits {
        entry_decoded_bytes: u64::MAX,
        source_bytes: u64::MAX,
        archive_extent: u64::MAX,
        output_bytes: u64::MAX,
        ..WriteLimits::default()
    };
    let options = WriterOptions { limits, ..WriterOptions::default() };
    let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), options).unwrap();
    for length in [u64::MAX, u64::MAX - 1] {
        let result = writer.add_file(entry("x", Method::Stored), &mut b"y".as_slice(), InputLength::Exact(length));
        assert!(matches!(result, Err(WriteError::Overflow)));
    }
    let mut oversized = vec![b'a'; 65_536];
    oversized[0] = 0;
    let mut raw = entry("", Method::Stored);
    raw.name = EntryName::Raw(&oversized);
    let result = writer.add_file(raw, &mut b"y".as_slice(), InputLength::Exact(1));
    assert!(matches!(result, Err(WriteError::InvalidMetadata(_))));
    raw.name = EntryName::Utf8("ok");
    raw.comment = b"\xff";
    let result = writer.add_file(raw, &mut b"y".as_slice(), InputLength::Exact(1));
    assert!(matches!(result, Err(WriteError::InvalidMetadata(_))));
    assert_eq!(writer.usage().io_attempts, 0);
    let maximum = &oversized[..65_535];
    raw.name = EntryName::Raw(maximum);
    raw.comment = maximum;
    writer.add_file(raw, &mut b"y".as_slice(), InputLength::Exact(1)).unwrap();
    let bytes = writer.finish().unwrap().sink.0;
    let expected = WireMember { name: maximum, comment: maximum, utf8: false, ..WireMember::new("", b"y", 0, 16) };
    assert!(check_wire(&mut Cursor::new(bytes), b"", &[expected]));
}

#[test]
fn zipcrypto_stream_uses_time_checked_signed_descriptors_for_all_lengths() {
    const PASSWORD: &str = "zipfast-test-only";
    let payload: Vec<_> = (0..=255).cycle().take(65_792).collect();
    let mut writer = ZipStreamWriter::new(WriteOnly(Vec::new()), WriterOptions::default()).unwrap();
    let mut receipts = Vec::new();
    for (name, method, length, bytes) in [
        ("stored", Method::Stored, InputLength::Exact(payload.len() as u64), payload.as_slice()),
        ("deflated", deflate(6), InputLength::Unknown, payload.as_slice()),
        ("empty", deflate(9), InputLength::Exact(0), b"".as_slice()),
        ("empty-unknown", deflate(1), InputLength::Unknown, b"".as_slice()),
    ] {
        let mut options = entry(name, method);
        options.modified = DosDateTime::new(2024, 11, 12, 20, 32, 40).unwrap();
        options.extended_mtime = Some(1_700_000_000);
        options.comment = b"member";
        let mut input = bytes;
        let written = writer
            .add_zipcrypto_file(options, &mut input, length, PASSWORD, |random| {
                *random = [0x5a; 11];
                Ok(())
            })
            .unwrap();
        receipts.push((written, bytes));
    }
    writer.add_directory(entry("clear/", Method::Stored)).unwrap();
    writer.add_file(entry("clear/data", Method::Stored), &mut b"clear".as_slice(), InputLength::Exact(5)).unwrap();
    let finished = writer.finish().unwrap();
    let bytes = finished.sink.0;
    let reader = ZipReader::new(&bytes).unwrap();
    let mut expected_packed = 5;
    for (receipt, plain) in receipts {
        let at = receipt.local_offset as usize;
        assert_eq!(n16(&bytes, at + 6), 0x0809);
        assert_eq!(n32(&bytes, at + 14), 0);
        let data = at + 30 + usize::from(n16(&bytes, at + 26)) + usize::from(n16(&bytes, at + 28));
        let end = data + receipt.packed_size as usize;
        assert_eq!(n32(&bytes, end), 0x0807_4b50);
        assert_eq!(n32(&bytes, end + 4), crc32fast::hash(plain));
        let time_check = bytes[at + 11];
        assert_ne!(time_check, (receipt.crc32 >> 24) as u8);
        let decrypted = zipfast::crypto::decrypt_zipcrypto(PASSWORD, time_check, &bytes[data..end]).unwrap();
        assert_eq!(decrypted.len() as u64 + 12, receipt.packed_size);
        if receipt.method == Method::Stored {
            assert_eq!(decrypted, plain);
            assert_eq!(n32(&bytes, end + 8) as u64, receipt.packed_size);
            assert_eq!(n32(&bytes, end + 12) as u64, receipt.decoded_size);
        } else {
            assert_eq!(n64(&bytes, end + 8), receipt.packed_size);
            assert_eq!(n64(&bytes, end + 16), receipt.decoded_size);
        }
        assert_eq!(
            reader.read_entry_with_password(&reader.entries()[receipt.ordinal as usize], Some(PASSWORD)).unwrap(),
            plain
        );
        expected_packed += receipt.packed_size;
    }
    assert_eq!(finished.summary.usage.packed_bytes, expected_packed);
    assert_eq!(reader.read_by_name("clear/data").unwrap(), b"clear");
}

#[test]
fn zipcrypto_preflight_and_entropy_failure_leave_writer_reusable() {
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    for invalid in ["", "password\0tail"] {
        let error = writer
            .add_zipcrypto_file(
                entry("secret", Method::Stored),
                &mut io::empty(),
                InputLength::Exact(0),
                invalid,
                |_| panic!("invalid password requested entropy"),
            )
            .unwrap_err();
        assert!(matches!(error, WriteError::InvalidMetadata(_)));
    }
    let error = writer
        .add_zipcrypto_file(entry("secret", Method::Stored), &mut io::empty(), InputLength::Exact(0), "pass", |_| {
            Err(io::Error::other("entropy source"))
        })
        .unwrap_err();
    assert!(
        matches!(&error, WriteError::Io { stage: IoStage::EncryptionEntropy, source } if source.to_string() == "entropy source")
    );
    assert_eq!(writer.usage().output_bytes, 0);
    assert_eq!(writer.usage().source_bytes, 0);
    writer.add_file(entry("clear", Method::Stored), &mut io::empty(), InputLength::Exact(0)).unwrap();
    assert_eq!(writer.finish().unwrap().summary.usage.entries, 1);
}

#[test]
fn encrypted_empty_preflight_accounts_for_header_and_descriptor() {
    for (maximum, expected) in [(128, true), (127, false)] {
        let options = WriterOptions {
            limits: WriteLimits { archive_extent: maximum, output_bytes: maximum, ..WriteLimits::default() },
            ..WriterOptions::default()
        };
        let mut writer = ZipStreamWriter::new(Vec::new(), options).unwrap();
        let mut entropy = 0;
        let result = writer.add_zipcrypto_file(
            entry("x", Method::Stored),
            &mut io::empty(),
            InputLength::Exact(0),
            "pass",
            |random| {
                entropy += 1;
                *random = [7; 11];
                Ok(())
            },
        );
        if expected {
            assert_eq!(result.unwrap().packed_size, 12);
            assert_eq!(writer.finish().unwrap().sink.len(), 128);
        } else {
            assert!(matches!(result, Err(WriteError::Limit(Limit::ArchiveExtent))));
            assert_eq!(entropy, 0);
            assert_eq!(writer.usage().output_bytes, 0);
        }
    }
}

#[test]
fn zipcrypto_short_writes_do_not_encrypt_ciphertext_twice() {
    let plain = b"streamed compression".repeat(4000);
    let write = |chunk| {
        let script = Script::default();
        let sink = ScriptSink { script: &script, bytes: Vec::new(), chunk };
        let mut writer = ZipStreamWriter::new(sink, WriterOptions::default()).unwrap();
        for (name, method) in [("stored", Method::Stored), ("deflate", deflate(6))] {
            writer
                .add_zipcrypto_file(
                    entry(name, method),
                    &mut plain.as_slice(),
                    InputLength::Exact(plain.len() as u64),
                    "pass",
                    |bytes| {
                        *bytes = [1; 11];
                        Ok(())
                    },
                )
                .unwrap();
        }
        writer.finish().unwrap().sink.bytes
    };
    assert_eq!(write(usize::MAX), write(7));
}

#[test]
fn zipcrypto_admitted_input_and_header_failures_poison_the_writer() {
    for (fault, stage) in [(1, IoStage::SourceRead), (4, IoStage::EncryptionHeader)] {
        let script = Script { fault: Some((fault - 1, Fault::Fail)), ..Script::default() };
        let sink = ScriptSink { script: &script, bytes: Vec::new(), chunk: usize::MAX };
        let mut source = ScriptSource { script: &script, data: b"x", chunk: usize::MAX };
        let mut writer = ZipStreamWriter::new(sink, WriterOptions::default()).unwrap();
        let result = writer.add_zipcrypto_file(
            entry("x", Method::Stored),
            &mut source,
            InputLength::Exact(1),
            "pass",
            |bytes| {
                *bytes = [1; 11];
                Ok(())
            },
        );
        assert!(matches!(result, Err(WriteError::Io { stage: actual, .. }) if actual == stage), "{result:?}");
        assert!(matches!(
            writer.add_file(entry("later", Method::Stored), &mut io::empty(), InputLength::Exact(0)),
            Err(WriteError::Failed(_))
        ));
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    }
}

#[test]
#[ignore = "exports generated ZipCrypto streams for checksum-pinned reference readers"]
fn export_zipcrypto_reference_fixtures() {
    let folder = std::path::PathBuf::from(std::env::var_os("ZIPFAST_ZIPCRYPTO_REFERENCE_DIR").unwrap());
    let expected = folder.join("expected");
    std::fs::create_dir_all(&expected).unwrap();
    let cross: Vec<_> = (0..=255).cycle().take(65_792).collect();
    let text = b"line of text\n".repeat(6_000);
    let mut writer = ZipStreamWriter::new(
        std::fs::File::create(folder.join("mixed.zip")).unwrap(),
        WriterOptions { comment: b"zipcrypto fixtures", ..WriterOptions::default() },
    )
    .unwrap();
    for (index, (name, method, length, contents)) in [
        ("empty", deflate(1), InputLength::Exact(0), b"".as_slice()),
        ("empty-unknown", deflate(6), InputLength::Unknown, b"".as_slice()),
        ("one", Method::Stored, InputLength::Exact(1), b"x".as_slice()),
        ("cross", Method::Stored, InputLength::Unknown, cross.as_slice()),
        ("deflate1", deflate(1), InputLength::Exact(text.len() as u64), text.as_slice()),
        ("deflate6", deflate(6), InputLength::Unknown, text.as_slice()),
        ("deflate9", deflate(9), InputLength::Unknown, text.as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut options = entry(name, method);
        options.modified = DosDateTime::new(2023, 11, 14, 22, 13, 20).unwrap();
        options.extended_mtime = Some(1_700_000_000);
        options.comment = b"member comment";
        if index == 3 {
            options.name = EntryName::Raw(b"cross");
        }
        let mut input = contents;
        writer
            .add_zipcrypto_file(options, &mut input, length, "zipfast-test-only", |random| {
                // Deterministic bytes are for interoperability fixtures only.
                random.fill(index as u8);
                Ok(())
            })
            .unwrap();
        std::fs::write(expected.join(name), contents).unwrap();
    }
    writer.add_directory(entry("dir/", Method::Stored)).unwrap();
    writer.add_file(entry("dir/clear", Method::Stored), &mut b"clear".as_slice(), InputLength::Exact(5)).unwrap();
    std::fs::create_dir(expected.join("dir")).unwrap();
    std::fs::write(expected.join("dir/clear"), b"clear").unwrap();
    writer.finish().unwrap();
}
