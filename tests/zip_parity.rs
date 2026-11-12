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

//! Characterization before consolidating the ZIP parsers. See docs/zip-parser-parity.md.

#[path = "common/zip_parity_fixture.rs"]
mod fixture;

use std::io::Write;
use std::ops::Range;

use fixture::{Fixture, Member, build, extra};
use zipfast::{error::Error, zip::Archive};
use zipview::{PasswordCheck, ZipEntry, ZipIndex, ZipIndexOpener, ZipReadError, ZipReader};

#[derive(Debug, PartialEq, Eq)]
struct Read {
    offset: u64,
    length: usize,
    bytes: Vec<u8>,
}

struct RangeSource<'a> {
    archive: &'a [u8],
    reads: Vec<Read>,
}

impl<'a> RangeSource<'a> {
    fn new(archive: &'a [u8]) -> Self {
        Self { archive, reads: Vec::new() }
    }

    fn supply(&mut self, offset: u64, length: usize) -> &[u8] {
        assert!((1..=16 * 1024 * 1024).contains(&length));
        assert!(self.reads.len() < 32, "small fixture should need few ranges");
        let start = usize::try_from(offset).unwrap();
        let bytes = &self.archive[start..start + length];
        self.reads.push(Read { offset, length, bytes: bytes.to_vec() });
        bytes
    }

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), ZipReadError> {
        buf.copy_from_slice(self.supply(offset, buf.len()));
        Ok(())
    }
}

fn open_fast(bytes: &[u8]) -> Result<Archive, Error> {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    Archive::open(file.path())
}

fn open_incremental(source: &mut RangeSource<'_>) -> Result<ZipIndex, ZipReadError> {
    let mut opener = ZipIndexOpener::new(source.archive.len() as u64);
    while let Some(range) = opener.next_read()? {
        let bytes = source.supply(range.start, (range.end - range.start) as usize);
        opener.supply(range.start, bytes)?;
    }
    opener.finish()
}

fn open_indexes(bytes: &[u8]) -> ([Result<ZipIndex, ZipReadError>; 2], Vec<Read>) {
    let mut blocking = RangeSource::new(bytes);
    let index = ZipIndex::open(bytes.len() as u64, |at, buf| blocking.read(at, buf));
    let mut incremental = RangeSource::new(bytes);
    let opened = open_incremental(&mut incremental);
    assert_eq!(blocking.reads, incremental.reads);
    ([index, opened], blocking.reads)
}

fn open_view(fixture: &Fixture) -> (ZipReader<'_>, [ZipIndex; 2], Vec<Read>) {
    let reader = ZipReader::new(&fixture.bytes).unwrap();
    let (indexes, reads) = open_indexes(&fixture.bytes);
    let indexes = indexes.map(Result::unwrap);
    for index in &indexes {
        assert_eq!(index.archive_len(), fixture.bytes.len() as u64);
        assert_eq!(index.entries().len(), reader.entries().len());
        assert_eq!(index.comment(), reader.comment());
        for (range_entry, slice_entry) in index.entries().iter().zip(reader.entries()) {
            assert_view_entry(range_entry, slice_entry);
        }
    }
    (reader, indexes, reads)
}

fn assert_view_entry(actual: &ZipEntry, expected: &ZipEntry) {
    assert_eq!(actual.name(), expected.name());
    assert_eq!(actual.flags(), expected.flags());
    assert_eq!(actual.compression(), expected.compression());
    assert_eq!(actual.effective_compression(), expected.effective_compression());
    assert_eq!(actual.compression_name(), expected.compression_name());
    assert_eq!(actual.crc32(), expected.crc32());
    assert_eq!(actual.compressed_size(), expected.compressed_size());
    assert_eq!(actual.size(), expected.size());
    assert_eq!(actual.local_header_offset(), expected.local_header_offset());
    assert_eq!(actual.version_made_by(), expected.version_made_by());
    assert_eq!(actual.unix_mode(), expected.unix_mode());
    assert_eq!(actual.last_modified(), expected.last_modified());
    assert_eq!(actual.aes_info(), expected.aes_info());
    assert_eq!(actual.is_encrypted(), expected.is_encrypted());
    assert_eq!(actual.is_dir(), expected.is_dir());
}

fn assert_shared_metadata(fast: &zipfast::zip::ZipEntry, view: &ZipEntry) {
    assert_eq!(fast.flags, view.flags());
    assert_eq!(fast.method, view.compression());
    assert_eq!(fast.host, view.version_made_by().0);
    assert_eq!(fast.crc32, view.crc32());
    assert_eq!(fast.packed, view.compressed_size());
    assert_eq!(fast.size, view.size());
    assert_eq!(fast.effective_method(), view.effective_compression());
    assert_eq!(fast.aes_info.map(|(strength, _, method)| (strength, method)), view.aes_info());
}

fn read_fast(archive: &mut Archive, entry: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    archive.read_at(entry, None, 1_000, |chunk| {
        output.extend(chunk);
        Ok(())
    })?;
    Ok(output)
}

fn range_bytes(bytes: &[u8], range: Range<u64>) -> &[u8] {
    &bytes[range.start as usize..range.end as usize]
}

fn assert_payload(
    fixture: &Fixture,
    fast: &mut Archive,
    view: &ZipReader<'_>,
    indexes: &[ZipIndex; 2],
    central: usize,
    local: usize,
    expected: &[u8],
) {
    assert_eq!(read_fast(fast, central).unwrap(), expected);
    assert_eq!(view.read_entry(view.by_index(central).unwrap()).unwrap(), expected);
    let start = fixture.local[local] as u64;
    let payload_end = fixture.payload[local].end as u64;
    assert_eq!(fast.entries[central].local_at, start);
    for index in indexes {
        let entry = index.by_index(central).unwrap();
        let header = index.header_range(entry).unwrap();
        assert_eq!(header, start..start + 30);
        let span = index.entry_range(entry, range_bytes(&fixture.bytes, header.clone())).unwrap();
        assert_eq!(span, start..payload_end);
        assert_eq!(index.read_entry(entry, range_bytes(&fixture.bytes, span.clone())).unwrap(), expected);
        let mut source = RangeSource::new(&fixture.bytes);
        let output = index.fetch_entry(entry, None, |at, buf| source.read(at, buf)).unwrap();
        assert_eq!(output, expected);
        let expected_reads = [header, span].map(|range| {
            let bytes = range_bytes(&fixture.bytes, range.clone()).to_vec();
            Read { offset: range.start, length: bytes.len(), bytes }
        });
        assert_eq!(source.reads, expected_reads);
    }
}

#[test]
fn central_order_and_duplicate_lookup_use_central_order() {
    let fixture = build(
        &[
            Member::stored(b"same", b"local-first"),
            Member::stored(b"middle", b"middle"),
            Member::stored(b"same", b"central-first"),
        ],
        &[2, 1, 0],
        &[],
        &vec![b'c'; usize::from(u16::MAX)],
        false,
    );
    let mut fast = open_fast(&fixture.bytes).unwrap();
    let (view, indexes, reads) = open_view(&fixture);
    assert_eq!(reads.len(), 4, "the directory starts outside the tail and is probed before reading its body");
    assert_eq!(reads[0].offset + reads[0].length as u64, fixture.bytes.len() as u64);
    assert_eq!(reads[1].offset, fixture.central[0] as u64);

    let mut opener = ZipIndexOpener::new(fixture.bytes.len() as u64);
    let tail = opener.next_read().unwrap().unwrap();
    assert_eq!(opener.next_read().unwrap(), Some(tail.clone()));
    let split = tail.start + 27;
    let mut source = RangeSource::new(&fixture.bytes);
    let first = source.supply(tail.start, 27);
    opener.supply(tail.start, first).unwrap();
    assert_eq!(opener.next_read().unwrap(), Some(split..tail.end));
    while let Some(range) = opener.next_read().unwrap() {
        let bytes = source.supply(range.start, (range.end - range.start) as usize);
        opener.supply(range.start, bytes).unwrap();
    }
    let partial = opener.finish().unwrap();
    assert_eq!(partial.comment(), view.comment());
    assert_eq!(partial.len(), view.len());
    for (actual, expected) in partial.entries().iter().zip(view.entries()) {
        assert_view_entry(actual, expected);
    }

    for profile in [zip_container::Profile::Zipfast, zip_container::Profile::Zipview] {
        let parsed = shared_directory(&fixture.bytes, profile);
        assert_eq!(parsed.raw_comment.len(), usize::from(u16::MAX));
        assert_eq!(
            parsed.entries.iter().map(|entry| &*entry.raw_name).collect::<Vec<_>>(),
            [b"same".as_slice(), b"middle", b"same"]
        );
        assert_eq!(parsed.physical_local_header_offset(0), Some(fixture.local[2] as u64));
        assert_eq!(parsed.physical_local_header_offset(2), Some(fixture.local[0] as u64));
    }

    assert_eq!(view.comment().len(), usize::from(u16::MAX));
    assert!(view.comment().bytes().all(|b| b == b'c'));
    assert_eq!(fast.entries.len(), 3);
    assert_eq!(view.len(), 3);
    for (i, (name, local, payload)) in [
        ("same", 2, b"central-first".as_slice()),
        ("middle", 1, b"middle".as_slice()),
        ("same", 0, b"local-first".as_slice()),
    ]
    .into_iter()
    .enumerate()
    {
        let fast_entry = &fast.entries[i];
        let entry = view.by_index(i).unwrap();
        assert_eq!(fast_entry.name, name);
        assert_eq!(entry.name(), name);
        assert_eq!(entry.local_header_offset(), fixture.local[local] as u64);
        assert_eq!(entry.version_made_by(), (3, 20));
        assert_eq!(fast_entry.external, 0o100644 << 16);
        assert_eq!(entry.unix_mode(), Some(0o100644));
        assert_eq!(fast_entry.unix_mode(), Some(0o100644));
        assert_eq!(entry.crc32(), crc32fast::hash(payload));
        assert_eq!(entry.size(), payload.len() as u64);
        assert_eq!(entry.compressed_size(), payload.len() as u64);
        assert_eq!(entry.flags(), 0);
        assert_eq!(entry.compression_name(), "Stored");
        assert!(!entry.is_encrypted());
        assert!(!fast_entry.encrypted());
        assert!(!entry.is_dir());
        assert!(!fast_entry.is_dir());
        assert!(!fast_entry.is_link());
        assert_shared_metadata(fast_entry, entry);
        assert_payload(&fixture, &mut fast, &view, &indexes, i, local, payload);
    }
    assert_eq!(view.read_by_name("same").unwrap(), b"central-first");
    assert!(view.contains("same"));
    assert!(!view.contains("Same"));
    assert!(view.by_index(3).is_none());
    for index in &indexes {
        assert!(index.contains("same"));
        assert!(!index.contains("Same"));
        assert!(index.by_index(3).is_none());
        let entry = index.by_name("same").unwrap();
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)).unwrap(), b"central-first");
    }
}

#[test]
fn filename_decoding_and_unicode_path_extras() {
    let legacy = b"caf\x82.txt";
    let unicode = "別名.txt";
    let mut unicode_body = vec![1];
    unicode_body.extend(crc32fast::hash(legacy).to_le_bytes());
    unicode_body.extend(unicode.as_bytes());
    let valid = extra(0x7075, &unicode_body);
    unicode_body[1] ^= 1;
    let wrong_crc = extra(0x7075, &unicode_body);

    let fixture = build(
        &[
            Member { flags: 0x800, ..Member::stored("é.txt".as_bytes(), b"a") },
            Member::stored("é.txt".as_bytes(), b"b"),
            Member::stored(legacy, b"c"),
            Member { flags: 0x800, ..Member::stored(b"bad\xff", b"d") },
            Member { central_extra: &valid, comment: b"entry\xffcomment", ..Member::stored(legacy, b"e") },
            Member { central_extra: &wrong_crc, ..Member::stored(legacy, b"f") },
        ],
        &[0, 1, 2, 3, 4, 5],
        &[],
        b"archive\xffcomment",
        false,
    );
    let mut fast = open_fast(&fixture.bytes).unwrap();
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(view.comment(), "archive�comment");
    for (i, (fast_name, view_name, payload)) in [
        ("é.txt", "é.txt", b"a"),
        ("é.txt", "é.txt", b"b"),
        ("café.txt", "caf�.txt", b"c"),
        ("bad�", "bad�", b"d"),
        (unicode, "caf�.txt", b"e"),
        ("café.txt", "caf�.txt", b"f"),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(fast.entries[i].name, fast_name);
        assert_eq!(view.entries()[i].name(), view_name, "central index {i}");
        assert_shared_metadata(&fast.entries[i], &view.entries()[i]);
        assert_payload(&fixture, &mut fast, &view, &indexes, i, i, payload);
    }
    let name_at = fixture.central[4] + 46;
    assert_eq!(&fixture.bytes[name_at..name_at + legacy.len()], legacy);
    let comment_at = name_at + legacy.len() + valid.len();
    assert_eq!(&fixture.bytes[comment_at..fixture.central[5]], b"entry\xffcomment");
}

#[test]
fn eocd_signature_in_comment_keeps_the_framed_end_record() {
    let mut comment = b"start\xff".to_vec();
    comment.extend(0x06054b50u32.to_le_bytes());
    comment.extend([0; 18]); // false zero-entry EOCD, whose comment ends early
    comment.extend(b"end");
    let fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], &comment, false);
    assert_eq!(&fixture.bytes[fixture.eocd + 22..], &comment);

    let mut fast = open_fast(&fixture.bytes).unwrap();
    assert_eq!(read_fast(&mut fast, 0).unwrap(), b"data");
    let (view, indexes, _) = open_view(&fixture);
    for profile in [zip_container::Profile::Zipfast, zip_container::Profile::Zipview] {
        let parsed = shared_directory(&fixture.bytes, profile);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(&*parsed.entries[0].raw_name, b"item");
        assert_eq!(parsed.raw_comment, comment);
    }
    assert_eq!(view.comment(), "start�PK\x05\x06".to_owned() + &"\0".repeat(18) + "end");
    assert_payload(&fixture, &mut fast, &view, &indexes, 0, 0, b"data");
}

#[test]
fn dos_extended_and_ntfs_timestamps() {
    let mut ut = vec![1];
    ut.extend((-123i32).to_le_bytes());
    let extended = extra(0x5455, &ut);
    let mut ntfs = vec![0, 0, 0, 0, 1, 0, 24, 0];
    ntfs.extend(116_444_736_421_234_567u64.to_le_bytes());
    ntfs.extend([0; 16]);
    let ntfs = extra(0x000a, &ntfs);
    let mut mixed = ntfs.clone();
    mixed.extend(&extended);
    let fixture = build(
        &[
            Member::stored(b"dos", b""),
            Member { central_extra: &extended, ..Member::stored(b"ut", b"") },
            Member { central_extra: &ntfs, ..Member::stored(b"ntfs", b"") },
            Member { central_extra: &mixed, ..Member::stored(b"both", b"") },
            Member { dos_date: 0, dos_time: 0, ..Member::stored(b"none", b"") },
            Member { dos_date: 1, dos_time: 0, ..Member::stored(b"invalid", b"") },
        ],
        &[0, 1, 2, 3, 4, 5],
        &[],
        &[],
        false,
    );
    let fast = open_fast(&fixture.bytes).unwrap();
    let (view, _, _) = open_view(&fixture);
    for (i, (mtime, nanos, dos)) in [
        (Some(1_577_934_246), 0, Some((2020, 1, 2, 3, 4, 6))),
        (Some(-123), 0, Some((2020, 1, 2, 3, 4, 6))),
        (Some(42), 123_456_700, Some((2020, 1, 2, 3, 4, 6))),
        (Some(-123), 0, Some((2020, 1, 2, 3, 4, 6))),
        (None, 0, None),
        (None, 0, Some((1980, 0, 1, 0, 0, 0))),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!((fast.entries[i].mtime, fast.entries[i].nanos), (mtime, nanos));
        assert_eq!(
            view.entries()[i].last_modified().map(|d| (d.year(), d.month(), d.day(), d.hour(), d.minute(), d.second())),
            dos
        );
    }
}

#[test]
fn host_attributes_and_directory_classification() {
    let fixture = build(
        &[
            Member { external: 0o040755 << 16, ..Member::stored(b"unix-dir", b"") },
            Member { external: 0o120777 << 16, ..Member::stored(b"unix-link", b"target") },
            Member { made_by: 0x1314, external: 0o100600 << 16, ..Member::stored(b"mac-mode", b"") },
            Member { external: 0, ..Member::stored(b"zero-mode", b"") },
            Member { made_by: 0x0014, external: 0x10, ..Member::stored(b"dos-dir", b"") },
            Member::stored(b"slash/", b""),
            Member::stored(b"backslash\\", b""),
        ],
        &[0, 1, 2, 3, 4, 5, 6],
        &[],
        &[],
        false,
    );
    let fast = open_fast(&fixture.bytes).unwrap();
    let (view, _, _) = open_view(&fixture);
    for (i, (external, mode_fast, mode_view, fast_dir, view_dir, link)) in [
        (0o040755 << 16, Some(0o040755), Some(0o040755), true, false, false),
        (0o120777 << 16, Some(0o120777), Some(0o120777), false, false, true),
        (0o100600 << 16, None, Some(0o100600), false, false, false),
        (0, None, Some(0), false, false, false),
        (0x10, None, None, true, false, false),
        (0o100644 << 16, Some(0o100644), Some(0o100644), true, true, false),
        (0o100644 << 16, Some(0o100644), Some(0o100644), false, true, false),
    ]
    .into_iter()
    .enumerate()
    {
        let f = &fast.entries[i];
        let v = &view.entries()[i];
        assert_shared_metadata(f, v);
        assert_eq!(f.external, external);
        assert_eq!((f.unix_mode(), v.unix_mode()), (mode_fast, mode_view));
        assert_eq!((f.is_dir(), v.is_dir(), f.is_link()), (fast_dir, view_dir, link));
    }
}

#[test]
fn aes_fields_use_central_metadata_but_password_check_uses_local_strength() {
    let aes = extra(0x9901, &[2, 0, b'A', b'E', 1, 8, 0]);
    let local_aes = extra(0x9901, &[1, 0, b'A', b'E', 3, 0, 0]);
    // Header-only characterization with a synthetic salt, verifier and tag.
    let data = b"12345678\x12\x34abcdefghij";
    let fixture = build(
        &[Member {
            flags: 1,
            method: 99,
            crc: Some(0),
            central_extra: &aes,
            local_extra: &local_aes,
            ..Member::stored(b"aes", data)
        }],
        &[0],
        &[],
        &[],
        false,
    );
    let mut fast = open_fast(&fixture.bytes).unwrap();
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(fast.entries[0].aes_info, Some((1, 2, 8)));
    assert!(fast.entries[0].encrypted());
    assert!(matches!(read_fast(&mut fast, 0), Err(Error::Unsupported(_))));
    let entry = view.by_index(0).unwrap();
    assert_shared_metadata(&fast.entries[0], entry);
    assert_eq!(entry.flags(), 1);
    assert_eq!(entry.compression(), 99);
    assert_eq!(entry.effective_compression(), 8);
    assert_eq!(entry.aes_info(), Some((1, 8)));
    assert!(entry.is_encrypted());
    assert_eq!(entry.crc32(), 0);
    assert_eq!(entry.compressed_size(), 20);
    assert_eq!(view.read_entry(entry), Err(ZipReadError::Encrypted));
    // The probe reads the local strength and therefore consumes a different prefix.
    let expected = Some(PasswordCheck::Aes { strength: 3, salt: *b"12345678\x12\x34abcdef", verifier: *b"gh" });
    assert_eq!(view.password_check(entry), expected);
    for index in &indexes {
        let entry = index.by_index(0).unwrap();
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_password_check(entry, |at, buf| source.read(at, buf)).unwrap(), expected);
        let end = fixture.payload[0].start + 18;
        assert_eq!(
            source.reads,
            [
                Read { offset: 0, length: 30, bytes: fixture.bytes[..30].to_vec() },
                Read { offset: 0, length: end, bytes: fixture.bytes[..end].to_vec() }
            ]
        );
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)), Err(ZipReadError::Encrypted));
    }
}

#[test]
fn zip64_size_offset_and_counts_with_optional_prefix() {
    let packed = b"\x2b\x29\xcf\x07\x00"; // raw DEFLATE of "two"
    let members =
        [Member::stored(b"first", b"one"), Member { zip64: true, ..Member::deflated(b"wide", packed, b"two") }];
    let prefix = b"MZ synthetic prefix".as_slice();
    for (prefix, zip64_end) in [(b"".as_slice(), true), (prefix, false), (prefix, true)] {
        let fixture = build(&members, &[0, 1], prefix, b"", zip64_end);
        let mut fast = open_fast(&fixture.bytes).unwrap();
        assert_eq!(fast.entries.len(), 2);
        assert_eq!(fast.entries[1].name, "wide");
        assert_eq!(fast.entries[1].size, 3);
        assert_eq!(fast.entries[1].packed, 5);
        assert_eq!(&fixture.bytes[fixture.payload[1].clone()], packed);
        assert_eq!(fast.entries[1].local_at, fixture.local[1] as u64);
        assert_eq!(read_fast(&mut fast, 1).unwrap(), b"two");
        for profile in [zip_container::Profile::Zipfast, zip_container::Profile::Zipview] {
            let parsed = shared_directory(&fixture.bytes, profile);
            assert_eq!(parsed.entries.len(), 2);
            assert_eq!(parsed.prefix_shift, prefix.len() as u64);
            assert_eq!(parsed.physical_local_header_offset(1), Some(fixture.local[1] as u64));
            assert_eq!((parsed.entries[1].resolved.unpacked_size, parsed.entries[1].resolved.packed_size), (3, 5));
        }
        let (view, indexes, _) = open_view(&fixture);
        assert_eq!(view.len(), 2);
        assert_eq!(view.entries()[1].local_header_offset(), 38);
        assert_shared_metadata(&fast.entries[1], &view.entries()[1]);
        assert_payload(&fixture, &mut fast, &view, &indexes, 0, 0, b"one");
        assert_payload(&fixture, &mut fast, &view, &indexes, 1, 1, b"two");
    }
}

#[test]
fn prefixed_extensible_zip64_resolves_local_addresses() {
    let prefix = b"MZ synthetic prefix";
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], prefix, b"", true);
    let locator = fixture.eocd - 20;
    let record = locator - 56;
    fixture.bytes[record + 4..record + 12].copy_from_slice(&53u64.to_le_bytes());
    fixture.bytes.splice(locator..locator, [0x5a; 9]);
    fixture.eocd += 9;

    assert!(matches!(open_fast(&fixture.bytes), Err(Error::Corrupt("ZIP64 end record"))));
    let (view, indexes, _) = open_view(&fixture);
    let parsed = shared_directory(&fixture.bytes, zip_container::Profile::Zipview);
    assert_eq!(parsed.zip64_end.unwrap().extension, locator as u64..(locator + 9) as u64);
    assert_eq!(view.by_index(0).unwrap().local_header_offset(), 0);
    assert_eq!(view.read_by_name("item").unwrap(), b"data");
    for index in indexes {
        let entry = index.by_index(0).unwrap();
        assert_eq!(index.header_range(entry).unwrap().start, prefix.len() as u64);
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)).unwrap(), b"data");
    }
}

#[test]
fn directory_count_budget_rejects_an_over_limit_zip64_declaration() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], &[], true);
    let record = fixture.eocd - 76;
    let count = 1_000_001u64.to_le_bytes();
    fixture.bytes[record + 24..record + 32].copy_from_slice(&count);
    fixture.bytes[record + 32..record + 40].copy_from_slice(&count);
    assert_eq!(ZipReader::new(&fixture.bytes).unwrap_err(), ZipReadError::BadOffset);
    let (indexes, reads) = open_indexes(&fixture.bytes);
    assert_eq!(reads.len(), 1);
    for index in indexes {
        assert_eq!(index.unwrap_err(), ZipReadError::BadOffset);
    }
}

#[test]
fn short_local_header_preserves_signature_and_clipping_precedence() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], b"junk", false);
    let len = fixture.bytes.len() as u32;
    let central = fixture.central[0];
    for (offset, expected_range, expected) in [
        (len - 4, Some(u64::from(len - 4)..u64::from(len)), ZipReadError::BadSignature),
        (len - 3, Some(u64::from(len - 3)..u64::from(len)), ZipReadError::Truncated),
        (len, Some(u64::from(len)..u64::from(len)), ZipReadError::Truncated),
        (len + 1, None, ZipReadError::BadOffset),
    ] {
        fixture.bytes[central + 42..central + 46].copy_from_slice(&offset.to_le_bytes());
        let (view, indexes, _) = open_view(&fixture);
        assert_eq!(view.read_by_name("item"), Err(expected.clone()));
        for index in indexes {
            let entry = index.by_index(0).unwrap();
            assert_eq!(index.header_range(entry).ok(), expected_range);
            assert_eq!(
                index.fetch_entry(entry, None, |at, buf| {
                    buf.copy_from_slice(&fixture.bytes[at as usize..at as usize + buf.len()]);
                    Ok::<(), ZipReadError>(())
                }),
                Err(expected.clone())
            );
        }
    }
}

#[test]
fn local_variable_fields_locate_payload_and_descriptor_stays_outside() {
    let unknown = extra(0xbeef, b"opaque local bytes");
    let packed = b"\x2b\x2e\xc9\x2f\x4a\x4d\x01\x00"; // raw DEFLATE of "stored"
    let fixture = build(
        &[Member {
            flags: 8,
            local_name: Some(b"different-local-name"),
            local_extra: &unknown,
            ..Member::deflated(b"central", packed, b"stored")
        }],
        &[0],
        &[],
        &[],
        false,
    );
    assert_eq!(&fixture.bytes[fixture.payload[0].clone()], packed);
    let descriptor = &fixture.bytes[fixture.payload[0].end..fixture.central[0]];
    assert_eq!(&descriptor[..4], b"PK\x07\x08");
    assert_eq!(&descriptor[8..16], &[8, 0, 0, 0, 6, 0, 0, 0]);
    let mut fast = open_fast(&fixture.bytes).unwrap();
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(fast.entries[0].name, "central");
    assert_eq!(view.entries()[0].name(), "central");
    assert_eq!(view.entries()[0].flags(), 8);
    assert_eq!(view.entries()[0].compressed_size(), 8);
    assert_eq!(view.entries()[0].size(), 6);
    assert_shared_metadata(&fast.entries[0], &view.entries()[0]);
    assert_payload(&fixture, &mut fast, &view, &indexes, 0, 0, b"stored");

    // Contradict the central flags, method, CRC and sizes. The local name
    // and extra lengths still identify the same compressed payload.
    let mut conflicting = fixture;
    conflicting.bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
    conflicting.bytes[8..10].copy_from_slice(&0u16.to_le_bytes());
    conflicting.bytes[14..26].fill(0xff);
    let mut fast = open_fast(&conflicting.bytes).unwrap();
    let (view, indexes, _) = open_view(&conflicting);
    assert_eq!(fast.entries[0].flags, 8);
    assert_eq!(view.entries()[0].compression(), 8);
    assert_payload(&conflicting, &mut fast, &view, &indexes, 0, 0, b"stored");
}

#[test]
fn eocd_comment_truncation_trailing_bytes_and_empty_archive() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], b"comment", false);
    fixture.bytes.extend(b"trailer");
    let mut fast = open_fast(&fixture.bytes).unwrap();
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(view.comment(), "comment");
    assert_payload(&fixture, &mut fast, &view, &indexes, 0, 0, b"data");

    fixture.bytes.truncate(fixture.eocd + 22 + 3);
    assert!(matches!(open_fast(&fixture.bytes), Err(Error::NotAnArchive)));
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(view.comment(), "com");
    assert_eq!(view.read_by_name("item").unwrap(), b"data");
    for index in indexes {
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(
            index.fetch_entry(index.by_index(0).unwrap(), None, |at, buf| source.read(at, buf)).unwrap(),
            b"data"
        );
    }

    let empty = build(&[], &[], &[], b"empty", false);
    let (view, indexes, _) = open_view(&empty);
    assert!(open_fast(&empty.bytes).unwrap().entries.is_empty());
    assert!(view.is_empty());
    assert_eq!(view.comment(), "empty");
    assert!(indexes.iter().all(ZipIndex::is_empty));
}

#[test]
fn directory_count_mismatches_expose_strict_and_listing_policies() {
    for (count, parsed) in [(1u16, 1), (3, 2)] {
        let mut fixture = build(&[Member::stored(b"a", b"A"), Member::stored(b"b", b"B")], &[0, 1], &[], &[], false);
        fixture.bytes[fixture.eocd + 8..fixture.eocd + 10].copy_from_slice(&count.to_le_bytes());
        fixture.bytes[fixture.eocd + 10..fixture.eocd + 12].copy_from_slice(&count.to_le_bytes());
        assert!(matches!(open_fast(&fixture.bytes), Err(Error::Corrupt("central directory entry count"))));
        let (view, _, _) = open_view(&fixture);
        assert_eq!(view.len(), parsed);
        assert_eq!(view.by_index(0).unwrap().name(), "a");
    }
}

#[test]
fn zip64_count_overrides_classic_sentinel() {
    let mut fixture =
        build(&[Member::stored(b"first", b"A"), Member::stored(b"second", b"B")], &[0, 1], &[], &[], true);
    let record = fixture.eocd - 20 - 56; // locator, then the fixed ZIP64 EOCD
    assert_eq!(&fixture.bytes[record..record + 4], b"PK\x06\x06");
    assert_eq!(&fixture.bytes[fixture.eocd + 8..fixture.eocd + 12], &[0xff; 4]);
    fixture.bytes[record + 24..record + 32].copy_from_slice(&1u64.to_le_bytes());
    fixture.bytes[record + 32..record + 40].copy_from_slice(&1u64.to_le_bytes());

    assert!(matches!(open_fast(&fixture.bytes), Err(Error::Corrupt("central directory entry count"))));
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(view.len(), 1);
    assert_eq!(view.by_index(0).unwrap().name(), "first");
    assert!(!view.contains("second"));
    for index in indexes {
        assert_eq!(index.len(), 1);
        assert_eq!(index.by_index(0).unwrap().name(), "first");
        assert!(!index.contains("second"));
    }
}

#[test]
fn truncated_central_name_and_comment_have_distinct_baselines() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], &[], false);
    let central = fixture.central[0];
    fixture.bytes[central + 28..central + 30].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(open_fast(&fixture.bytes), Err(Error::Corrupt("central directory record"))));
    assert_eq!(ZipReader::new(&fixture.bytes).unwrap_err(), ZipReadError::Truncated);
    for index in open_indexes(&fixture.bytes).0 {
        assert_eq!(index.unwrap_err(), ZipReadError::Truncated);
    }

    fixture.bytes[central + 28..central + 30].copy_from_slice(&4u16.to_le_bytes());
    fixture.bytes[central + 32..central + 34].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(open_fast(&fixture.bytes), Err(Error::Corrupt("central directory record"))));
    let (view, _, _) = open_view(&fixture);
    assert_eq!(view.len(), 1);
    assert_eq!(view.read_by_name("item").unwrap(), b"data");
}

#[test]
fn short_zip64_extra_leaves_a_sentinel_only_in_zipview() {
    let zip64 = extra(1, &4u64.to_le_bytes()); // supplies uncompressed size only
    let mut fixture =
        build(&[Member { central_extra: &zip64, ..Member::stored(b"item", b"data") }], &[0], &[], &[], false);
    let central = fixture.central[0];
    fixture.bytes[central + 20..central + 28].fill(0xff);
    assert!(matches!(open_fast(&fixture.bytes), Err(Error::Corrupt("ZIP64 extra field"))));
    let (view, indexes, _) = open_view(&fixture);
    let entry = view.by_index(0).unwrap();
    assert_eq!(entry.size(), 4);
    assert_eq!(entry.compressed_size(), u64::from(u32::MAX));
    assert_eq!(view.read_entry(entry), Err(ZipReadError::Truncated));
    for index in indexes {
        let mut source = RangeSource::new(&fixture.bytes);
        let entry = index.by_index(0).unwrap();
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)), Err(ZipReadError::Truncated));
    }
}

#[test]
fn unresolved_packed_size_blocks_payload_reads_but_preserves_password_preview() {
    let payload = b"abcdefghijkl";
    let mut fixture = build(&[Member { flags: 1, ..Member::stored(b"item", payload) }], &[0], &[], &[], false);
    let central = fixture.central[0];
    fixture.bytes[central + 20..central + 24].fill(0xff);
    let (view, indexes, _) = open_view(&fixture);
    let expected = Some(PasswordCheck::Crypto { header: *payload, check: (crc32fast::hash(payload) >> 24) as u8 });
    assert_eq!(view.password_check(view.by_index(0).unwrap()), expected);
    assert_eq!(view.read_by_name("item"), Err(ZipReadError::Truncated));
    for index in indexes {
        let entry = index.by_index(0).unwrap();
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_password_check(entry, |at, buf| source.read(at, buf)).unwrap(), expected);
        assert_eq!(source.reads.len(), 2);
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)), Err(ZipReadError::Truncated));
        assert!(source.reads.is_empty());
    }
}

#[test]
fn split_disk_metadata_can_be_listed_but_cannot_address_local_data() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], &[], false);
    fixture.bytes[fixture.eocd + 4..fixture.eocd + 6].copy_from_slice(&1u16.to_le_bytes());
    let parsed = shared_directory(&fixture.bytes, zip_container::Profile::Zipview);
    assert_eq!(parsed.end_record.disk, 1);
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.physical_local_header_offset(0), None);
    assert!(matches!(open_fast(&fixture.bytes), Err(Error::Unsupported(_))));
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(view.by_index(0).unwrap().local_header_offset(), 0);
    assert_eq!(view.read_by_name("item"), Err(ZipReadError::BadOffset));
    for index in indexes {
        let entry = index.by_index(0).unwrap();
        assert_eq!(index.header_range(entry), Err(ZipReadError::BadOffset));
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)), Err(ZipReadError::BadOffset));
        assert!(source.reads.is_empty());
        assert_eq!(index.read_entry(entry, &fixture.bytes), Err(ZipReadError::BadOffset));
    }
}

#[test]
fn unresolved_zip64_local_offset_is_visible_but_cannot_address_local_data() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], &[], false);
    let central = fixture.central[0];
    fixture.bytes[central + 42..central + 46].fill(0xff);
    let (view, indexes, _) = open_view(&fixture);
    assert_eq!(view.by_index(0).unwrap().local_header_offset(), u64::from(u32::MAX));
    assert_eq!(view.read_by_name("item"), Err(ZipReadError::BadOffset));
    for index in indexes {
        let entry = index.by_index(0).unwrap();
        // The direct range reader must enforce address validity, even when
        // handed bytes from a real local header without calling header_range.
        assert_eq!(index.read_entry(entry, &fixture.bytes), Err(ZipReadError::BadOffset));
        let mut source = RangeSource::new(&fixture.bytes);
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)), Err(ZipReadError::BadOffset));
        assert!(source.reads.is_empty());
    }
}

#[test]
fn local_extra_past_end_is_rejected_on_payload_read() {
    let mut fixture = build(&[Member::stored(b"item", b"data")], &[0], &[], &[], false);
    fixture.bytes[28..30].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut fast = open_fast(&fixture.bytes).unwrap();
    let (view, indexes, _) = open_view(&fixture);
    assert!(matches!(read_fast(&mut fast, 0), Err(Error::Truncated)));
    assert_eq!(view.read_by_name("item"), Err(ZipReadError::Truncated));
    for index in indexes {
        let mut source = RangeSource::new(&fixture.bytes);
        let entry = index.by_index(0).unwrap();
        assert_eq!(index.fetch_entry(entry, None, |at, buf| source.read(at, buf)), Err(ZipReadError::Truncated));
    }
}

#[test]
fn encryption_classification_preserves_raw_flags_and_aes_extra() {
    let aes = extra(0x9901, &[1, 0, b'A', b'E', 2, 0, 0]);
    let invalid = extra(0x9901, &[1, 0, b'A', b'E', 4, 0, 0]);
    let fixture = build(
        &[
            Member { flags: 1, ..Member::stored(b"traditional", b"") },
            Member { flags: 0x40, ..Member::stored(b"strong-bit-only", b"") },
            Member { flags: 0x2000, ..Member::stored(b"masked-bit-only", b"") },
            Member { central_extra: &aes, ..Member::stored(b"aes-extra-only", b"") },
            Member { method: 99, central_extra: &invalid, ..Member::stored(b"invalid-strength", b"") },
            Member { method: 99, local_extra: &aes, ..Member::stored(b"local-aes-only", b"") },
        ],
        &[0, 1, 2, 3, 4, 5],
        &[],
        &[],
        false,
    );
    let fast = open_fast(&fixture.bytes).unwrap();
    let (view, _, _) = open_view(&fixture);
    for (i, (flags, method, aes, fast_encrypted, view_encrypted)) in [
        (1, 0, None, true, true),
        (0x40, 0, None, false, true),
        (0x2000, 0, None, false, true),
        (0, 0, Some((2, 1, 0)), true, false),
        (0, 99, None, true, true),
        (0, 99, None, true, true),
    ]
    .into_iter()
    .enumerate()
    {
        let f = &fast.entries[i];
        let v = &view.entries()[i];
        assert_shared_metadata(f, v);
        assert_eq!((f.flags, f.method, f.aes_info), (flags, method, aes));
        assert_eq!((f.encrypted(), v.is_encrypted()), (fast_encrypted, view_encrypted));
    }
}

fn shared_directory(bytes: &[u8], profile: zip_container::Profile) -> zip_container::Directory {
    use zip_container::{DirectoryParser, Limits, parse_slice};

    let limits = Limits::default();
    let slice = parse_slice(bytes, profile, limits).unwrap();
    for chunks in [&[usize::MAX][..], &[1], &[3, 27, 16, 1, 4, 7, 13, 2]] {
        let mut parser = DirectoryParser::new(bytes.len() as u64, profile, limits).unwrap();
        let mut chunk = 0;
        while let Some(range) = parser.next_read().unwrap() {
            let start = range.start as usize;
            let end = (range.end as usize).min(start.saturating_add(chunks[chunk % chunks.len()]));
            parser.supply(range.start, &bytes[start..end]).unwrap();
            chunk += 1;
        }
        let mut ranged = parser.finish().unwrap();
        assert_eq!(ranged.usage.owned, slice.usage.owned);
        ranged.usage = slice.usage;
        assert_eq!(ranged, slice);
    }
    slice
}

#[test]
fn shared_directory_retains_raw_generated_fixture_metadata() {
    use zip_container::{AesFields, ExtraIter, ExtraMtime, LocalHeader, Profile, local_layout};

    let prefix = b"MZ synthetic prefix";
    let local_extra = extra(0xfedc, b"local only");
    let opaque = extra(0xfedc, b"central only");
    let aes = extra(0x9901, &[2, 0, b'A', b'E', 3, 8, 0]);
    let timestamp = extra(0x5455, &[1, 0xfe, 0xff, 0xff, 0xff]);
    let raw_name = b"same\x82";
    let mut unicode = vec![1];
    unicode.extend(crc32fast::hash(raw_name).to_le_bytes());
    unicode.extend(b"override\xff");
    let extras = [opaque.as_slice(), &aes, &timestamp, &extra(0x7075, &unicode)].concat();
    let packed = b"\x2b\x29\xcf\x07\x00";
    let members = [
        Member::stored(raw_name, b"stored payload"),
        Member {
            zip64: true,
            flags: 0x801,
            method: 99,
            made_by: 0x033f,
            external: 0x1234_5678,
            dos_time: 0x7182,
            dos_date: 0x3421,
            local_name: Some(b"separate local"),
            local_extra: &local_extra,
            central_extra: &extras,
            comment: b"entry\xffcomment",
            ..Member::deflated(raw_name, packed, b"two")
        },
    ];
    let fixture = build(&members, &[1, 0], prefix, b"archive\xff", true);
    let expected_name = fixture.central[0] + 46;
    let expected_extra = expected_name + raw_name.len();
    let expected_comment = expected_extra + extras.len() + 28;
    let anchor = fixture.eocd - 20 - 56;
    for profile in [Profile::Zipfast, Profile::Zipview] {
        let parsed = shared_directory(&fixture.bytes, profile);
        assert_eq!(parsed.archive_len, fixture.bytes.len() as u64);
        assert_eq!(parsed.prefix_shift, prefix.len() as u64);
        assert_eq!(parsed.directory_range, fixture.central[0] as u64..anchor as u64);
        assert_eq!(parsed.observed_range, parsed.directory_range);
        assert_eq!(parsed.logical_range, parsed.directory_range);
        assert_eq!(parsed.declaration.entries, 2);
        assert_eq!(parsed.declaration.size, (anchor - fixture.central[0]) as u64);
        assert_eq!(parsed.declaration.offset, (fixture.central[0] - prefix.len()) as u64);
        assert_eq!(parsed.end_record.entries, u16::MAX);
        assert_eq!(parsed.zip64_end.as_ref().unwrap().source, anchor as u64..(anchor + 56) as u64);
        assert_eq!(parsed.zip64_locator.as_ref().unwrap().record_offset, (anchor - prefix.len()) as u64);
        assert_eq!(parsed.raw_comment, b"archive\xff");
        assert_eq!(range_bytes(&fixture.bytes, parsed.comment_range.clone()), b"archive\xff");
        let first = &parsed.entries[0];
        assert_eq!(&*first.raw_name, raw_name);
        assert_eq!(&*parsed.entries[1].raw_name, raw_name);
        assert_eq!(&*first.raw_comment, b"entry\xffcomment");
        assert_eq!(first.source.raw_range(), fixture.central[0] as u64..fixture.central[1] as u64);
        assert_eq!(first.source.name_range(), expected_name as u64..expected_extra as u64);
        assert_eq!(first.source.extra_range(), expected_extra as u64..expected_comment as u64);
        assert_eq!(first.source.comment_range(), expected_comment as u64..fixture.central[1] as u64);
        assert_eq!(first.header.version_made_by, 0x033f);
        assert_eq!(first.header.version_needed, 45);
        assert_eq!(first.header.flags, 0x801);
        assert_eq!(first.header.method, 99);
        assert_eq!(first.header.mod_time, 0x7182);
        assert_eq!(first.header.mod_date, 0x3421);
        assert_eq!(first.header.crc32, crc32fast::hash(b"two"));
        assert_eq!(first.header.packed_size, u32::MAX);
        assert_eq!(first.header.unpacked_size, u32::MAX);
        assert_eq!(first.header.name_len, raw_name.len() as u16);
        assert_eq!(first.header.extra_len, (extras.len() + 28) as u16);
        assert_eq!(first.header.comment_len, 13);
        assert_eq!(first.header.disk_start, 0);
        assert_eq!(first.header.internal_attributes, 0);
        assert_eq!(first.header.external_attributes, 0x1234_5678);
        assert_eq!(first.header.local_header_offset, u32::MAX);
        assert_eq!((first.resolved.unpacked_size, first.resolved.packed_size), (3, 5));
        assert_eq!(first.resolved.local_header_offset, (fixture.local[1] - prefix.len()) as u64);
        assert_eq!(parsed.physical_local_header_offset(0), Some(fixture.local[1] as u64));
        assert_eq!(parsed.physical_local_header_offset(1), Some(fixture.local[0] as u64));
        assert_eq!(first.known.aes, Some(AesFields { vendor_version: 2, vendor_id: *b"AE", strength: 3, method: 8 }));
        assert_eq!(first.known.mtime_override, Some(ExtraMtime::UnixSeconds(-2)));
        assert_eq!(first.known.unicode_path.as_deref(), (profile == Profile::Zipfast).then_some(&b"override\xff"[..]));
        let extra_range = first.source.extra_range();
        let mut extra = ExtraIter::new(range_bytes(&fixture.bytes, extra_range.clone()), extra_range.start).unwrap();
        assert_eq!(extra.next().unwrap().unwrap().body, b"central only");
        let local = parsed.physical_local_header_offset(0).unwrap();
        let header = LocalHeader::parse(&fixture.bytes[local as usize..]).unwrap();
        let layout = local_layout(header, local, parsed.archive_len).unwrap();
        assert_eq!(range_bytes(&fixture.bytes, layout.name_range()), b"separate local");
        assert!(range_bytes(&fixture.bytes, layout.extra_range()).starts_with(&local_extra));
        assert_eq!(
            range_bytes(&fixture.bytes, layout.payload_range(first.resolved.packed_size, parsed.archive_len).unwrap()),
            packed
        );
    }
}

#[test]
fn shared_directory_skips_an_overclaimed_aes_extra_that_legacy_root_accepted() {
    use zip_container::Profile;

    let mut aes = extra(0x9901, &[2, 0, b'A', b'E', 1, 8, 0]);
    aes[2..4].copy_from_slice(&20u16.to_le_bytes());
    let fixture = build(
        &[Member { flags: 1, method: 99, central_extra: &aes, ..Member::stored(b"file", b"") }],
        &[0],
        &[],
        &[],
        false,
    );
    assert_eq!(open_fast(&fixture.bytes).unwrap().entries[0].aes_info, Some((1, 2, 8)));
    let (view, _, _) = open_view(&fixture);
    assert_eq!(view.by_index(0).unwrap().aes_info(), None);
    for profile in [Profile::Zipfast, Profile::Zipview] {
        let parsed = shared_directory(&fixture.bytes, profile);
        assert_eq!(parsed.entries[0].known.aes, None);
        assert_eq!(range_bytes(&fixture.bytes, parsed.entries[0].source.extra_range()), aes);
    }
}
