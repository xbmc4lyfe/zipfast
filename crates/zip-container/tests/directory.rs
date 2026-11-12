// zip-container -- checked ZIP metadata primitives
// Copyright (C) 2026 zipview contributors
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

use std::{
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use zip_container::{
    AesFields, Directory, DirectoryError, DirectoryParser, ExtraIter, ExtraMtime, LimitKind, Limits, OwnershipError,
    OwnershipKind, Profile, SupplyError, discover_slice, parse_slice,
};

const PROFILES: [Profile; 2] = [Profile::Zipfast, Profile::Zipview];
const TAIL: u64 = 65_633;

fn field(id: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = id.to_le_bytes().to_vec();
    bytes.extend(u16::try_from(body.len()).unwrap().to_le_bytes());
    bytes.extend(body);
    bytes
}

fn record(name: &[u8], extra: &[u8], comment: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 46];
    bytes[..4].copy_from_slice(b"PK\x01\x02");
    for (at, len) in [(28, name.len()), (30, extra.len()), (32, comment.len())] {
        bytes[at..at + 2].copy_from_slice(&u16::try_from(len).unwrap().to_le_bytes());
    }
    bytes.extend(name);
    bytes.extend(extra);
    bytes.extend(comment);
    bytes
}

fn end(start: u32, size: u32, count: u16, comment: &[u8]) -> Vec<u8> {
    let mut bytes = b"PK\x05\x06".to_vec();
    bytes.extend([0; 4]);
    bytes.extend(count.to_le_bytes());
    bytes.extend(count.to_le_bytes());
    bytes.extend(size.to_le_bytes());
    bytes.extend(start.to_le_bytes());
    bytes.extend(u16::try_from(comment.len()).unwrap().to_le_bytes());
    bytes.extend(comment);
    bytes
}

fn archive(directory: &[u8], count: u16, comment: &[u8]) -> Vec<u8> {
    let mut bytes = directory.to_vec();
    bytes.extend(end(0, directory.len().try_into().unwrap(), count, comment));
    bytes
}

fn drive(bytes: &[u8], mut parser: DirectoryParser, schedule: &[usize]) -> Result<Directory, DirectoryError> {
    let mut i = 0;
    while let Some(read) = parser.next_read()? {
        let usage = parser.usage();
        let buffers = parser.buffer_usage();
        assert_eq!(parser.next_read(), Ok(Some(read.clone())));
        assert_eq!(parser.usage(), usage);
        assert_eq!(parser.buffer_usage(), buffers);
        let start = read.start as usize;
        let end = (read.end as usize).min(start.saturating_add(schedule[i % schedule.len()]));
        parser.supply(read.start, &bytes[start..end])?;
        i += 1;
    }
    assert_eq!(parser.buffer_usage().live_bytes, 0);
    assert_eq!(parser.buffer_usage().capacity_bytes, 0);
    parser.finish()
}

fn across_schedules(bytes: &[u8], profile: Profile) -> Result<Directory, DirectoryError> {
    let expected = parse_slice(bytes, profile, Limits::default());
    for schedule in [&[usize::MAX][..], &[1], &[3, 43, 1, 2, 7, 8, 15, 39]] {
        let ranged =
            drive(bytes, DirectoryParser::new(bytes.len() as u64, profile, Limits::default()).unwrap(), schedule);
        match (&expected, ranged) {
            (Ok(expected), Ok(mut ranged)) => {
                assert_eq!(ranged.usage.owned, expected.usage.owned);
                // Fragmented input can require scratch copies or stop a pending range early.
                ranged.usage = expected.usage;
                assert_eq!(&ranged, expected);
            }
            (Err(expected), Err(ranged)) => assert_eq!(*expected, ranged),
            (left, right) => panic!("slice and range outcomes differ: {left:?} / {right:?}"),
        }
    }
    expected
}

#[test]
fn exact_root_count_allows_a_noncentral_trailer_including_zero_entries() {
    for count in [0, 1] {
        let mut cd = if count == 0 { vec![] } else { record(b"name", &[], &[]) };
        let observed_end = cd.len() as u64;
        // A signature deeper in the opaque trailer is irrelevant.
        cd.extend(b"tailPK\x01\x02");
        let bytes = archive(&cd, count, b"archive comment");
        let location = discover_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap();
        assert_eq!(location.directory_range(), 0..cd.len() as u64);
        for profile in PROFILES {
            let parsed = across_schedules(&bytes, profile).unwrap();
            assert_eq!(parsed.entries.len(), count as usize);
            assert_eq!(parsed.observed_range, 0..observed_end);
            assert_eq!(parsed.raw_comment, b"archive comment");
        }
    }
}

#[test]
fn strict_counts_check_the_immediately_following_signature() {
    let first = record(b"a", &[], &[]);
    let mut cd = first.clone();
    cd.extend(b"PK\x01\x02"); // The signature alone establishes a count error.
    for (bytes, count) in [(archive(&cd, 1, &[]), 1), (archive(&first, 0, &[]), 0)] {
        assert!(matches!(across_schedules(&bytes, Profile::Zipfast), Err(DirectoryError::EntryCount { .. })));
        assert_eq!(across_schedules(&bytes, Profile::Zipview).unwrap().entries.len(), count);
    }

    let bytes = archive(&first, 2, &[]);
    assert!(matches!(across_schedules(&bytes, Profile::Zipfast), Err(DirectoryError::EntryCount { .. })));
    assert_eq!(across_schedules(&bytes, Profile::Zipview).unwrap().entries.len(), 1);
}

#[test]
fn zipview_tracks_clipped_and_undersold_directory_extents() {
    let mut cd = record(b"raw", &field(0xaaaa, b"unknown"), &[]);
    cd[32..34].copy_from_slice(&100u16.to_le_bytes());
    let mut bytes = cd.clone();
    bytes.extend(end(0, 1, 1, &[]));
    let parsed = across_schedules(&bytes, Profile::Zipview).unwrap();
    assert_eq!(parsed.directory_range, 0..1);
    assert_eq!(parsed.observed_range, 0..bytes.len() as u64);
    assert_eq!(parsed.logical_range, 0..cd.len() as u64 + 100);
    let entry = &parsed.entries[0];
    assert_eq!(entry.source.name_range(), 46..49);
    assert_eq!(entry.source.extra_range(), 49..60);
    assert_eq!(entry.source.declared_comment_len(), 100);
    assert_eq!(entry.source.available_comment_len(), 22);
    assert_eq!(&*entry.raw_comment, &bytes[cd.len()..]);
    let exact = parsed.logical_range.end;
    let limits = Limits { directory_bytes: exact, ..Limits::default() };
    assert!(parse_slice(&bytes, Profile::Zipview, limits).is_ok());
    let limits = Limits { directory_bytes: exact - 1, ..limits };
    assert_eq!(parse_slice(&bytes, Profile::Zipview, limits), Err(DirectoryError::Limit(LimitKind::DirectoryBytes)));

    for at in [28, 30] {
        let mut malformed = bytes.clone();
        malformed[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(across_schedules(&malformed, Profile::Zipview), Err(DirectoryError::Parse(_))));
    }
    let bytes = archive(&cd, 2, &[]);
    assert!(matches!(across_schedules(&bytes, Profile::Zipview), Err(DirectoryError::Parse(_))));
    assert!(matches!(across_schedules(&bytes, Profile::Zipfast), Err(DirectoryError::Parse(_))));
}

#[test]
fn zip64_duplicates_and_disk_sentinel_preserve_profile_rules() {
    let first: Vec<_> = [u64::from(u32::MAX), 7, 0].into_iter().flat_map(u64::to_le_bytes).collect();
    let second = 31u64.to_le_bytes();
    let extras = [field(1, &first), field(1, &second)].concat();
    let mut cd = record(b"file", &extras, &[]);
    cd[20..28].fill(0xff);
    cd[34..36].fill(0xff);
    cd[42..46].fill(0xff);
    let bytes = archive(&cd, 1, &[]);
    for profile in PROFILES {
        let parsed = across_schedules(&bytes, profile).unwrap();
        let resolved = parsed.entries[0].resolved;
        assert_eq!(resolved.unpacked_size, u64::from(u32::MAX));
        assert_eq!(resolved.packed_size, 7);
        assert_eq!(resolved.local_header_offset, 0);
        assert!(!resolved.unresolved.unpacked_size);
        assert!(resolved.unresolved.disk_start);
        assert_eq!(parsed.physical_local_header_offset(0), (profile == Profile::Zipfast).then_some(0));
    }

    let mut complete = first;
    complete.extend(3u32.to_le_bytes());
    let mut cd = record(b"file", &field(1, &complete), &[]);
    cd[20..28].fill(0xff);
    cd[34..36].fill(0xff);
    cd[42..46].fill(0xff);
    let bytes = archive(&cd, 1, &[]);
    let view = across_schedules(&bytes, Profile::Zipview).unwrap();
    assert_eq!(view.entries[0].resolved.disk_start, 3);
    assert!(!view.entries[0].resolved.unresolved.disk_start);
    assert_eq!(view.physical_local_header_offset(0), None);
    let root = across_schedules(&bytes, Profile::Zipfast).unwrap();
    assert_eq!(root.entries[0].resolved.disk_start, u32::from(u16::MAX));
    assert_eq!(root.physical_local_header_offset(0), Some(0));

    let mut partial = record(b"file", &[field(1, &17u64.to_le_bytes()), field(1, &29u64.to_le_bytes())].concat(), &[]);
    partial[20..28].fill(0xff);
    let bytes = archive(&partial, 1, &[]);
    assert!(matches!(across_schedules(&bytes, Profile::Zipfast), Err(DirectoryError::MalformedZip64)));
    let resolved = across_schedules(&bytes, Profile::Zipview).unwrap().entries[0].resolved;
    assert_eq!(resolved.unpacked_size, 17);
    assert!(resolved.unresolved.packed_size);
}

#[test]
fn unresolved_local_sentinel_is_never_a_physical_address_in_a_sparse_archive() {
    let mut cd = record(b"large sparse archive", &[], &[]);
    cd[42..46].fill(0xff);
    let start = u64::from(u32::MAX) - 31;
    let mut suffix = cd.clone();
    suffix.extend(end(start as u32, cd.len() as u32, 1, &[]));
    let len = start + suffix.len() as u64;
    assert!(len > u64::from(u32::MAX));
    for profile in PROFILES {
        let mut parser = DirectoryParser::new(len, profile, Limits::default()).unwrap();
        let result = (|| {
            while let Some(read) = parser.next_read()? {
                assert!(read.start >= len - TAIL);
                let mut window = vec![0; (read.end - read.start) as usize];
                let overlap = read.start.max(start)..read.end.min(len);
                if !overlap.is_empty() {
                    let into = (overlap.start - read.start) as usize..(overlap.end - read.start) as usize;
                    let from = (overlap.start - start) as usize..(overlap.end - start) as usize;
                    window[into].copy_from_slice(&suffix[from]);
                }
                parser.supply(read.start, &window)?;
            }
            parser.finish()
        })();
        if profile == Profile::Zipfast {
            assert_eq!(result, Err(DirectoryError::InvalidLocalOffset));
        } else {
            let parsed = result.unwrap();
            assert!(parsed.entries[0].resolved.unresolved.local_header_offset);
            assert_eq!(parsed.physical_local_header_offset(0), None);
        }
    }
}

fn unicode(version: u8, crc: u32, name: &[u8]) -> Vec<u8> {
    let mut body = vec![version];
    body.extend(crc.to_le_bytes());
    body.extend(name);
    field(0x7075, &body)
}

#[test]
fn known_extras_reduce_once_in_wire_order_inside_their_advertised_bounds() {
    let crc = 0xcbf4_3926; // IEEE CRC-32 of the standard "123456789" vector.
    let unknown = field(0xdada, b"opaque");
    let ntfs = field(
        0x000a,
        &[0, 0, 0, 0, 1, 0, 24, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    );
    let extended = field(0x5455, &[1, 0xfe, 0xff, 0xff, 0xff]);
    let short_aes = field(0x9901, &[2, 0, b'X']);
    let invalid_aes = field(0x9901, &[4, 0, b'X', b'Y', 9, 8, 0]);
    let valid_aes = field(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let malformed = [0x34, 0x12, 0xff, 0xff];
    let first = [
        unknown.as_slice(),
        &short_aes,
        &invalid_aes,
        &valid_aes,
        &ntfs,
        &extended,
        &unicode(1, crc, b"first"),
        &unicode(1, crc ^ 1, b"bad"),
        &unicode(1, crc, b"winner\xff"),
        &malformed,
        &unicode(1, crc, b"unreachable"),
    ]
    .concat();
    let second =
        [invalid_aes.as_slice(), &valid_aes, &extended, &ntfs, &field(0x5455, &[0]), &unicode(2, crc, b"bad version")]
            .concat();
    let mut cd = record(b"123456789", &first, b"raw\xff");
    cd.extend(record(b"123456789", &second, &[]));
    let bytes = archive(&cd, 2, b"archive\xff");
    for profile in PROFILES {
        let parsed = across_schedules(&bytes, profile).unwrap();
        let first = &parsed.entries[0];
        let second = &parsed.entries[1];
        let invalid = Some(AesFields { vendor_version: 4, vendor_id: *b"XY", strength: 9, method: 8 });
        assert_eq!(first.known.aes, if profile == Profile::Zipfast { invalid } else { None });
        assert_eq!(second.known.aes, invalid);
        assert_eq!(first.known.mtime_override, Some(ExtraMtime::UnixSeconds(-2)));
        assert_eq!(second.known.mtime_override, Some(ExtraMtime::NtfsFiletime(9)));
        assert_eq!(first.known.unicode_path.as_deref(), (profile == Profile::Zipfast).then_some(&b"winner\xff"[..]));
        assert_eq!(second.known.unicode_path, None);
        assert_eq!(&*first.raw_comment, b"raw\xff");
        let range = first.source.extra_range();
        let mut extras = ExtraIter::new(&bytes[range.start as usize..range.end as usize], range.start).unwrap();
        let opaque = extras.next().unwrap().unwrap();
        assert_eq!(opaque.id, 0xdada);
        assert_eq!(opaque.range, 55..65);
        assert_eq!(opaque.body, b"opaque");
        assert!(extras.last().unwrap().is_err());
    }

    // A following framed unknown extra must never supply missing AES bytes.
    let malformed_aes = [field(0x9901, &[]), field(0x4541, &[1, 8, 0]), valid_aes].concat();
    let bytes = archive(&record(b"file", &malformed_aes, &[]), 1, &[]);
    assert_eq!(across_schedules(&bytes, Profile::Zipview).unwrap().entries[0].known.aes, None);
    let selected = across_schedules(&bytes, Profile::Zipfast).unwrap().entries[0].known.aes.unwrap();
    assert_eq!((selected.vendor_version, selected.vendor_id, selected.strength, selected.method), (2, *b"AE", 1, 0));

    // Legacy zipfast accepts the prefix even when the full advertised body is missing.
    let mut overclaimed = field(0x9901, &[2, 0, b'A', b'E', 1, 8, 0]);
    overclaimed[2..4].copy_from_slice(&20u16.to_le_bytes());
    let bytes = archive(&record(b"file", &overclaimed, &[]), 1, &[]);
    for profile in PROFILES {
        let directory = across_schedules(&bytes, profile).unwrap();
        assert_eq!(directory.entries[0].known.aes, None);
        assert_eq!(directory.entries[0].source.extra_range(), 50..61);
    }
}

#[test]
fn unicode_crc_override_is_lazy_once_per_name_and_keeps_work_deterministic() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn hash(bytes: &[u8]) -> u32 {
        assert_eq!(bytes, b"123456789");
        CALLS.fetch_add(1, Ordering::Relaxed);
        0xcbf4_3926
    }
    let crc = 0xcbf4_3926;
    let mut cd = record(b"unused", &unicode(2, crc, b"ignore"), &[]);
    cd.extend(record(b"123456789", &[unicode(1, crc ^ 1, b"bad"), unicode(1, crc, b"good")].concat(), &[]));
    let bytes = archive(&cd, 2, &[]);
    let limits = Limits::default();
    let default = parse_slice(&bytes, Profile::Zipfast, limits).unwrap();
    let custom = DirectoryParser::with_name_crc32(bytes.len() as u64, Profile::Zipfast, limits, hash).unwrap();
    assert_eq!(drive(&bytes, custom, &[usize::MAX]).unwrap(), default);
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    let custom_view = DirectoryParser::with_name_crc32(bytes.len() as u64, Profile::Zipview, limits, hash).unwrap();
    let view = drive(&bytes, custom_view, &[usize::MAX]).unwrap();
    assert_eq!(view.entries[1].known.unicode_path, None);
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
}

#[test]
fn component_budgets_carry_archive_comment_and_discovery_work_into_the_walk() {
    let cd = record(b"123456789", &unicode(1, 0xcbf4_3926, b"utf"), b"entry");
    let bytes = archive(&cd, 1, b"archive");
    let baseline = parse_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap();
    let exact = Limits {
        directory_bytes: cd.len() as u64,
        entries: 1,
        fetched_bytes: bytes.len() as u64,
        range_bytes: bytes.len() as u64,
        work_units: baseline.usage.work_units,
        name_bytes: 9,
        extra_bytes: 3,
        comment_bytes: 12,
    };
    assert_eq!(parse_slice(&bytes, Profile::Zipfast, exact).unwrap(), baseline);
    for (limits, expected) in [
        (
            Limits { directory_bytes: exact.directory_bytes - 1, ..exact },
            DirectoryError::Limit(LimitKind::DirectoryBytes),
        ),
        (Limits { entries: 0, ..exact }, DirectoryError::Limit(LimitKind::Entries)),
        (Limits { fetched_bytes: exact.fetched_bytes - 1, ..exact }, DirectoryError::Limit(LimitKind::FetchedBytes)),
        (Limits { range_bytes: 0, ..exact }, DirectoryError::Limit(LimitKind::RangeBytes)),
        (Limits { work_units: exact.work_units - 1, ..exact }, DirectoryError::Limit(LimitKind::WorkUnits)),
        (
            Limits { name_bytes: 8, ..exact },
            DirectoryError::Ownership(OwnershipError::LimitExceeded {
                kind: OwnershipKind::NameBytes,
                needed: 9,
                limit: 8,
            }),
        ),
        (
            Limits { extra_bytes: 2, ..exact },
            DirectoryError::Ownership(OwnershipError::LimitExceeded {
                kind: OwnershipKind::ExtraBytes,
                needed: 3,
                limit: 2,
            }),
        ),
        (
            Limits { comment_bytes: 11, ..exact },
            DirectoryError::Ownership(OwnershipError::LimitExceeded {
                kind: OwnershipKind::CommentBytes,
                needed: 12,
                limit: 11,
            }),
        ),
    ] {
        let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, limits).unwrap();
        let error = loop {
            match parser.next_read() {
                Ok(Some(read)) => {
                    if let Err(error) = parser.supply(read.start, &bytes[read.start as usize..read.end as usize]) {
                        break error;
                    }
                }
                Err(error) => break error,
                Ok(None) => panic!("an exceeded budget completed"),
            }
        };
        assert_eq!(error, expected);
        let stopped = (parser.usage(), parser.buffer_usage());
        assert_eq!(parser.next_read(), Err(expected));
        assert_eq!(parser.next_read(), Err(expected));
        assert_eq!((parser.usage(), parser.buffer_usage()), stopped);
        assert_eq!(parser.finish(), Err(expected));
    }
    let split = Limits { range_bytes: 1, work_units: Limits::default().work_units, ..exact };
    assert_eq!(parse_slice(&bytes, Profile::Zipfast, split).unwrap().entries, baseline.entries);
}

#[test]
fn maximum_record_is_assembled_once_with_bounded_scratch_and_transactional_supply() {
    let count = usize::from(u16::MAX);
    let cd = record(&vec![b'n'; count], &field(0xf00d, &vec![0; count - 4]), &vec![b'c'; count]);
    assert_eq!(cd.len(), 196_651);
    let bytes = archive(&cd, 1, &[]);
    let limits = Limits { range_bytes: 16 * 1024, ..Limits::default() };
    let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, limits).unwrap();
    assert_eq!(parser.supply(0, b"X"), Err(DirectoryError::Supply(SupplyError::Unsolicited)));
    let mut peak = (0, 0);
    let mut seen = vec![false; bytes.len()];
    while let Some(read) = parser.next_read().unwrap() {
        assert!(read.end - read.start <= limits.range_bytes);
        let start = read.start as usize;
        let stop = (read.end as usize).min(start + 7);
        let usage = parser.usage();
        let buffers = parser.buffer_usage();
        if read.start == (bytes.len() as u64 - TAIL) || read.start == 46 {
            assert_eq!(parser.supply(read.start + 1, b"X"), Err(DirectoryError::Supply(SupplyError::UnexpectedOffset)));
            assert_eq!(
                parser.supply(read.start, &vec![0; 1 + (read.end - read.start) as usize]),
                Err(DirectoryError::Supply(SupplyError::Overlong))
            );
        }
        parser.supply(read.start, &[]).unwrap();
        assert_eq!(parser.usage(), usage);
        assert_eq!(parser.buffer_usage(), buffers);
        assert_eq!(parser.next_read().unwrap(), Some(read.clone()));
        for hit in &mut seen[start..stop] {
            assert!(!*hit, "a discovered header or tail byte was fetched again");
            *hit = true;
        }
        parser.supply(read.start, &bytes[start..stop]).unwrap();
        if read.start == 46 {
            let usage = parser.usage();
            assert_eq!(
                parser.supply(read.start, &bytes[start..stop]),
                Err(DirectoryError::Supply(SupplyError::UnexpectedOffset))
            );
            assert_eq!(parser.usage(), usage);
            assert_eq!(parser.next_read().unwrap(), Some(stop as u64..read.end));
        }
        let buffers = parser.buffer_usage();
        peak.0 = peak.0.max(buffers.live_bytes);
        peak.1 = peak.1.max(buffers.capacity_bytes);
    }
    assert!(seen.into_iter().all(|hit| hit));
    assert!(peak.0 > count);
    assert!(peak.1 <= TAIL as usize + 196_651 + 111);
    assert_eq!(parser.buffer_usage().capacity_bytes, 0);
    assert_eq!(parser.supply(bytes.len() as u64, b"X"), Err(DirectoryError::Supply(SupplyError::OutOfBounds)));
    let parsed = parser.finish().unwrap();
    let full = parse_slice(&bytes, Profile::Zipfast, limits).unwrap();
    assert_eq!(parsed, full);
    assert_eq!(parsed.entries[0].source.raw_range(), 0..196_651);
    assert_eq!(parsed.entries[0].raw_name.len(), count);
    assert_eq!(parsed.entries[0].raw_comment.len(), count);
    assert!(parsed.usage.work_units < 5 * bytes.len() as u64);
    eprintln!(
        "maximum record: scratch live/capacity={peak:?}, output count/capacity={}/{}, usage={:?}",
        parsed.entries.len(),
        parsed.entries.capacity(),
        parsed.usage
    );
}

#[test]
fn sixty_thousand_fragmented_entries_do_not_buffer_the_directory_or_fetch_payloads() {
    let cd = record(b"ab", &field(0x9898, b"unknown"), b"file comment").repeat(60_000);
    let prefix = 70_000;
    let mut bytes = vec![0; prefix];
    bytes.extend(&cd);
    bytes.extend(end(prefix as u32, cd.len() as u32, 60_000, &[]));
    let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
    let mut reads: Vec<Range<u64>> = Vec::new();
    let mut peak = (0, 0);
    while let Some(read) = parser.next_read().unwrap() {
        assert!(read.start >= prefix as u64, "a request reached into local data");
        let stop = read.end.min(read.start + 97);
        if let Some(previous) = reads.last_mut().filter(|previous| previous.end == read.start) {
            previous.end = stop;
        } else {
            reads.push(read.start..stop);
        }
        parser.supply(read.start, &bytes[read.start as usize..stop as usize]).unwrap();
        let buffers = parser.buffer_usage();
        peak.0 = peak.0.max(buffers.live_bytes);
        peak.1 = peak.1.max(buffers.capacity_bytes);
    }
    assert!(peak.0 <= TAIL as usize + 46);
    assert!(peak.1 <= TAIL as usize + 46 + 111);
    assert_eq!(parser.buffer_usage().capacity_bytes, 0);
    assert_eq!(reads.iter().map(|range| range.end - range.start).sum::<u64>(), bytes.len() as u64 - prefix as u64);
    let directory = parser.finish().unwrap();
    assert_eq!(directory.entries.len(), 60_000);
    assert_eq!(directory.usage.owned.name_bytes, 120_000);
    assert_eq!(directory.usage.owned.extra_bytes, 0);
    assert_eq!(directory.usage.owned.comment_bytes, 720_000);
    assert_eq!(directory.usage.fetched_bytes, bytes.len() as u64 - prefix as u64);
    assert!(directory.usage.work_units < 5 * cd.len() as u64);
    eprintln!(
        "60k records: scratch live/capacity={peak:?}, output count/capacity={}/{}, entry size={}, usage={:?}",
        directory.entries.len(),
        directory.entries.capacity(),
        std::mem::size_of::<zip_container::CentralRecord>(),
        directory.usage
    );
}

#[test]
fn known_large_body_fails_work_preflight_before_a_new_request_or_scratch_reservation() {
    let name = vec![b'x'; usize::from(u16::MAX)];
    let cd = record(&name, &[], &vec![b'c'; usize::from(u16::MAX)]);
    let bytes = archive(&cd, 1, &[]);
    let discovery = discover_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap().usage();
    let limits = Limits {
        // Enough to fetch all metadata, but too little to examine the full
        // known body, much less own the name and comment.
        work_units: discovery.work_units + (bytes.len() as u64 - discovery.fetched_bytes),
        ..Limits::default()
    };
    let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, limits).unwrap();
    while parser.usage().fetched_bytes < discovery.fetched_bytes {
        let read = parser.next_read().unwrap().unwrap();
        parser.supply(read.start, &bytes[read.start as usize..read.end as usize]).unwrap();
    }
    assert_eq!(parser.next_read(), Err(DirectoryError::Limit(LimitKind::WorkUnits)));
    assert_eq!(parser.usage().fetched_bytes, discovery.fetched_bytes);
    assert_eq!(parser.buffer_usage().capacity_bytes, 0);
}

#[test]
fn known_large_body_fails_fetched_preflight_before_a_new_request() {
    let cd = record(&vec![b'x'; usize::from(u16::MAX)], &[], &vec![b'c'; usize::from(u16::MAX)]);
    let bytes = archive(&cd, 1, &[]);
    let discovery = discover_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap().usage();
    let limits = Limits { fetched_bytes: bytes.len() as u64 - 1, ..Limits::default() };
    let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, limits).unwrap();
    while parser.usage().fetched_bytes < discovery.fetched_bytes {
        let read = parser.next_read().unwrap().unwrap();
        parser.supply(read.start, &bytes[read.start as usize..read.end as usize]).unwrap();
    }
    assert_eq!(parser.next_read(), Err(DirectoryError::Limit(LimitKind::FetchedBytes)));
    assert_eq!(parser.usage().fetched_bytes, discovery.fetched_bytes);
    assert_eq!(parser.buffer_usage().capacity_bytes, 0);
}

#[test]
fn incremental_output_reservation_is_capped_by_declared_and_plausible_counts() {
    let single = archive(&record(b"item", &[], &[]), 1, &[]);
    for profile in PROFILES {
        let parsed = parse_slice(&single, profile, Limits { entries: 1, ..Limits::default() }).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries.capacity(), 1);
    }

    let two = archive(&record(b"a", &[], &[]).repeat(2), 60_000, &[]);
    let parsed = parse_slice(&two, Profile::Zipview, Limits::default()).unwrap();
    assert_eq!(parsed.entries.len(), 2);
    assert_eq!(parsed.entries.capacity(), 2);
}

#[test]
fn first_body_request_continues_through_the_external_directory_window() {
    let entry = record(b"dup", &field(0x9898, b"unknown"), b"file");
    assert_eq!(entry.len(), 64);
    let bytes = archive(&entry.repeat(2_000), 2_000, b"end");
    let len = bytes.len() as u64;
    let tail = len - TAIL;
    let discovery_reads = [tail..len, 0..4, 4..46];

    for profile in PROFILES {
        let expected = parse_slice(&bytes, profile, Limits::default()).unwrap();
        let limits = Limits {
            fetched_bytes: len,
            range_bytes: TAIL,
            work_units: expected.usage.work_units,
            directory_bytes: 128_000,
            entries: 2_000,
            name_bytes: 6_000,
            extra_bytes: 0,
            comment_bytes: 8_003,
        };
        let mut parser = DirectoryParser::new(len, profile, limits).unwrap();
        for read in &discovery_reads {
            assert_eq!(parser.next_read().unwrap().as_ref(), Some(read));
            parser.supply(read.start, &bytes[read.start as usize..read.end as usize]).unwrap();
        }
        assert_eq!(parser.next_read().unwrap(), Some(46..tail));
        let before = parser.usage();
        assert_eq!(parser.next_read().unwrap(), Some(46..tail));
        assert_eq!(parser.usage(), before);
        assert_eq!(before.directory_bytes, tail);

        // Supply the first body and a complete following record. The next
        // poll can be cancelled and does not charge work for the window suffix.
        parser.supply(46, &bytes[46..128]).unwrap();
        let checkpoint = parser.usage();
        assert_eq!(checkpoint.fetched_bytes, before.fetched_bytes + 82);
        assert_eq!(checkpoint.work_units, before.work_units + 82 + 128 + 2 * (16 + 3 + 4));
        assert_eq!(checkpoint.owned.entries, 2);
        assert_eq!(checkpoint.owned.name_bytes, 6);
        assert_eq!(checkpoint.owned.extra_bytes, 0);
        assert_eq!(checkpoint.owned.comment_bytes, 11);
        assert_eq!(parser.next_read().unwrap(), Some(128..tail));
        assert_eq!(parser.usage(), checkpoint);
        parser.supply(128, &bytes[128..tail as usize]).unwrap();
        assert_eq!(parser.next_read().unwrap(), None);
        let result = parser.finish().unwrap();
        assert_eq!(result, expected);
        assert_eq!(result.usage.fetched_bytes, len);
        assert_eq!(result.entries[1].source.extra_range(), 113..124);
        assert_eq!(&*result.entries[1].raw_name, b"dup");
        assert_eq!(&*result.entries[1].raw_comment, b"file");

        let fragment_limits = Limits { work_units: Limits::default().work_units, ..limits };
        let fragmented =
            drive(&bytes, DirectoryParser::new(len, profile, fragment_limits).unwrap(), &[3, 43, 1, 2, 7, 8, 15, 39])
                .unwrap();
        assert_eq!(fragmented.entries, expected.entries);
        assert_eq!(fragmented.usage.owned, expected.usage.owned);
        assert_eq!(fragmented.usage.fetched_bytes, len);
        assert!(fragmented.usage.work_units > expected.usage.work_units);

        let discovery = discover_slice(&bytes, profile, limits).unwrap();
        let limited = Limits { work_units: discovery.usage().work_units + 115, ..limits };
        let mut parser = DirectoryParser::new(len, profile, limited).unwrap();
        for read in &discovery_reads {
            assert_eq!(parser.next_read().unwrap().as_ref(), Some(read));
            parser.supply(read.start, &bytes[read.start as usize..read.end as usize]).unwrap();
        }
        // Preflight holds back the first name and comment's ownership work.
        assert_eq!(parser.next_read().unwrap(), Some(46..154));
        assert_eq!(parser.usage().work_units, discovery.usage().work_units);
        assert_eq!(parser.finish(), Err(DirectoryError::Incomplete));
    }
}

#[test]
fn contiguous_and_split_headers_fail_ownership_before_the_body() {
    let first = record(b"first", &[], &[]);
    let mut cd = first.clone();
    cd.extend(record(&vec![b'n'; usize::from(u16::MAX)], &[], &vec![b'c'; usize::from(u16::MAX)]));
    let bytes = archive(&cd, 2, &[]);
    let len = bytes.len() as u64;
    let tail = len - TAIL;
    let body = first.len() as u64 + 46;
    let limits = Limits { name_bytes: 5, ..Limits::default() };

    for profile in PROFILES {
        let mut failures = Vec::new();
        for cuts in [&[46, body][..], &[46, first.len() as u64, first.len() as u64 + 4, body]] {
            let mut parser = DirectoryParser::new(len, profile, limits).unwrap();
            for read in [tail..len, 0..4, 4..46] {
                assert_eq!(parser.next_read().unwrap(), Some(read.clone()));
                parser.supply(read.start, &bytes[read.start as usize..read.end as usize]).unwrap();
            }
            assert_eq!(parser.next_read().unwrap(), Some(46..tail));
            let discovery = parser.usage();
            for (index, cut) in cuts.windows(2).enumerate() {
                let (start, end) = (cut[0], cut[1]);
                assert_eq!(parser.next_read().unwrap(), Some(start..tail));
                let result = parser.supply(start, &bytes[start as usize..end as usize]);
                if index < cuts.len() - 2 {
                    assert_eq!(result, Ok(()));
                } else {
                    let error = DirectoryError::Ownership(OwnershipError::LimitExceeded {
                        kind: OwnershipKind::NameBytes,
                        needed: 5 + usize::from(u16::MAX),
                        limit: 5,
                    });
                    assert_eq!(result, Err(error));
                    assert_eq!(parser.next_read(), Err(error));
                    assert_eq!(parser.buffer_usage().capacity_bytes, 0);
                    let usage = parser.usage();
                    assert_eq!(usage.fetched_bytes, discovery.fetched_bytes + body - 46);
                    assert_eq!(usage.work_units, discovery.work_units + body - 46 + 5 + 128);
                    assert_eq!(usage.owned.entries, 1);
                    assert_eq!(usage.owned.name_bytes, 5);
                    failures.push(usage);
                }
            }
        }
        assert_eq!(failures[0], failures[1]);
    }
}

#[test]
fn strict_trailer_reads_only_the_next_signature_outside_the_cached_tail() {
    for count in [0, 1] {
        let mut cd = if count == 0 { vec![] } else { record(b"file", &[], &[]) };
        let observed_end = cd.len() as u64;
        cd.extend(b"tail");
        cd.resize(200_000, 0);
        let bytes = archive(&cd, count, &[]);
        let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
        let mut after_tail = Vec::new();
        while let Some(read) = parser.next_read().unwrap() {
            if read.start < bytes.len() as u64 - TAIL {
                after_tail.push(read.clone());
            }
            parser.supply(read.start, &bytes[read.start as usize..read.end as usize]).unwrap();
        }
        if count == 0 {
            assert_eq!(after_tail.as_slice(), std::slice::from_ref(&(0..4)));
        } else {
            assert_eq!(after_tail, [0..4, 4..46, 46..50, 50..54]);
        }
        let result = parser.finish().unwrap();
        assert_eq!(result.observed_range, 0..observed_end);
        assert_eq!(result.usage.directory_bytes, observed_end + 4);
    }
}

#[test]
fn local_address_requires_in_file_start_and_preserves_view_listing() {
    let mut cd = record(b"file", &[], &[]);
    let len = (cd.len() + 22) as u32;
    for local_offset in [len - 1, len] {
        cd[42..46].copy_from_slice(&local_offset.to_le_bytes());
        let bytes = archive(&cd, 1, &[]);
        let view = across_schedules(&bytes, Profile::Zipview).unwrap();
        assert_eq!(view.entries[0].resolved.local_header_offset, u64::from(local_offset));
        let root = across_schedules(&bytes, Profile::Zipfast);
        if local_offset < len {
            assert_eq!(view.physical_local_header_offset(0), Some(u64::from(local_offset)));
            assert_eq!(root.unwrap().physical_local_header_offset(0), Some(u64::from(local_offset)));
        } else {
            assert_eq!(view.physical_local_header_offset(0), None);
            assert_eq!(root, Err(DirectoryError::InvalidLocalOffset));
        }
    }
}

#[test]
fn incomplete_parser_can_be_finished_or_dropped_between_requests() {
    let bytes = archive(&record(b"file", &[], &[]), 1, &[]);
    let mut parser = DirectoryParser::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
    let read = parser.next_read().unwrap().unwrap();
    parser.supply(read.start, &bytes[..1]).unwrap();
    assert_eq!(parser.next_read().unwrap(), Some(1..read.end));
    assert_eq!(parser.finish(), Err(DirectoryError::Incomplete));
}
