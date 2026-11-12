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

use std::ops::Range;

use crate::{
    Directory, DirectoryError, DirectoryLocation, DirectoryParser, EndDiscovery, LimitKind, Limits, Profile,
    SupplyError, discover_slice, parse_slice,
};

const TAIL: u64 = 65_633;
const WINDOW: u64 = 65_536;
const PROFILES: [Profile; 2] = [Profile::Zipfast, Profile::Zipview];

fn set16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn set32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn set64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn central() -> [u8; 46] {
    let mut bytes = [0; 46];
    bytes[..4].copy_from_slice(b"PK\x01\x02");
    bytes
}

fn end(count: u16, size: u32, offset: u32, comment: u16) -> [u8; 22] {
    let mut bytes = [0; 22];
    bytes[..4].copy_from_slice(b"PK\x05\x06");
    set16(&mut bytes, 8, count);
    set16(&mut bytes, 10, count);
    set32(&mut bytes, 12, size);
    set32(&mut bytes, 16, offset);
    set16(&mut bytes, 20, comment);
    bytes
}

fn zip64(body_size: u64, count: u64, size: u64, offset: u64) -> [u8; 56] {
    let mut bytes = [0; 56];
    bytes[..4].copy_from_slice(b"PK\x06\x06");
    set64(&mut bytes, 4, body_size);
    set16(&mut bytes, 12, 45);
    set16(&mut bytes, 14, 45);
    set64(&mut bytes, 24, count);
    set64(&mut bytes, 32, count);
    set64(&mut bytes, 40, size);
    set64(&mut bytes, 48, offset);
    bytes
}

fn locator(offset: u64) -> [u8; 20] {
    let mut bytes = [0; 20];
    bytes[..4].copy_from_slice(b"PK\x06\x07");
    set64(&mut bytes, 8, offset);
    set32(&mut bytes, 16, 1);
    bytes
}

fn classic(prefix: usize, comment: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xA5; prefix];
    bytes.extend(central());
    bytes.extend(end(1, 46, 0, comment.len() as u16));
    bytes.extend(comment);
    bytes
}

fn extended(prefix: usize, extension: usize, recorded: u64, saturated: bool) -> Vec<u8> {
    let mut bytes = vec![0xA5; prefix];
    bytes.extend(central());
    bytes.extend(zip64(44 + extension as u64, 1, 46, 0));
    bytes.resize(bytes.len() + extension, 0xA5);
    bytes.extend(locator(recorded));
    bytes.extend(if saturated { end(u16::MAX, u32::MAX, u32::MAX, 0) } else { end(1, 46, 0, 0) });
    bytes
}

#[derive(Clone, Copy)]
enum Chunk {
    Full,
    Byte,
    Mixed,
}

fn drive(
    len: u64,
    profile: Profile,
    limits: Limits,
    chunk: Chunk,
    mut read: impl FnMut(Range<u64>) -> Vec<u8>,
) -> Result<DirectoryLocation, DirectoryError> {
    let mut parser = EndDiscovery::new(len, profile, limits)?;
    let mut part = 0;
    loop {
        let before = parser.usage();
        let range = parser.next_read()?;
        let after = parser.usage();
        assert_eq!(parser.next_read()?, range);
        assert_eq!(parser.usage(), after);
        assert_eq!(before.fetched_bytes, after.fetched_bytes);
        let Some(range) = range else {
            return parser.finish();
        };
        assert!(range.start < range.end && range.end <= len);
        assert!(range.end - range.start <= limits.range_bytes);
        assert!(range.end - range.start <= limits.fetched_bytes - after.fetched_bytes);
        let max = match chunk {
            Chunk::Full => u64::MAX,
            Chunk::Byte => 1,
            Chunk::Mixed => [5, 27, 2, 45, 56, 513, 65_503][part % 7],
        };
        part += 1;
        let take = (range.end - range.start).min(max);
        let bytes = read(range.start..range.start + take);
        assert_eq!(bytes.len() as u64, take);
        parser.supply(range.start, &bytes)?;
        assert_eq!(parser.usage().fetched_bytes, after.fetched_bytes + take);
    }
}

fn verify(
    bytes: &[u8],
    profile: Profile,
    limits: Limits,
    expected: impl FnOnce(Result<DirectoryLocation, DirectoryError>),
) {
    let slice = discover_slice(bytes, profile, limits);
    for chunk in [Chunk::Full, Chunk::Byte, Chunk::Mixed] {
        let ranged =
            drive(bytes.len() as u64, profile, limits, chunk, |r| bytes[r.start as usize..r.end as usize].to_vec());
        match (&slice, &ranged) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.end_record(), b.end_record());
                assert_eq!(a.zip64_locator(), b.zip64_locator());
                assert_eq!(a.zip64_end(), b.zip64_end());
                assert_eq!(a.declaration(), b.declaration());
                assert_eq!(a.directory_range(), b.directory_range());
                assert_eq!(a.prefix_shift(), b.prefix_shift());
                assert_eq!(a.raw_comment(), b.raw_comment());
                assert_eq!(a.comment_range(), b.comment_range());
                assert_eq!(a.usage().fetched_bytes, b.usage().fetched_bytes);
                assert_eq!(a.usage().owned, b.usage().owned);
                assert_eq!(a.first_header(), b.first_header());
                assert_eq!(a.usage(), b.usage());
            }
            (Err(a), Err(b)) => assert_eq!(a, b),
            (a, b) => panic!("slice and range disagreed: {a:?}, {b:?}"),
        }
    }
    expected(slice);
}

#[test]
fn classic_location_retains_wire_comment_and_prefixed_empty_geometry() {
    for profile in PROFILES {
        verify(&classic(9, b"\xffraw"), profile, Limits::default(), |location| {
            let location = location.unwrap();
            assert_eq!(location.end_record().source, 55..77);
            assert_eq!(location.declaration().offset, 0);
            assert_eq!(location.directory_range(), 9..55);
            assert_eq!(location.prefix_shift(), 9);
            assert_eq!(location.comment_range(), 77..81);
            assert_eq!(location.raw_comment(), b"\xffraw");
            assert_eq!(location.usage().owned.comment_bytes, 4);
        });
        let empty = end(0, 0, 0, 0);
        for prefix in [0, 7] {
            let mut bytes = vec![0xA5; prefix];
            bytes.extend(empty);
            verify(&bytes, profile, Limits::default(), |location| {
                let location = location.unwrap();
                assert_eq!(location.directory_range(), prefix as u64..prefix as u64);
                assert_eq!(location.prefix_shift(), prefix as u64);
            });
        }
    }
}

#[test]
fn exact_comment_outranks_trailing_fake_and_impossible_exact_candidate() {
    for profile in PROFILES {
        let mut comment = end(0, 0, 0, 0).to_vec();
        comment.extend(b"tail");
        let bytes = classic(0, &comment);
        verify(&bytes, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap().end_record().source, 46..68);
        });

        let bytes = classic(0, &end(0, 0, 500, 0));
        verify(&bytes, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap().end_record().source, 46..68);
        });

        // Two fully plausible exact-end candidates. Reverse order breaks the tie.
        let bytes = classic(0, &end(0, 0, 0, 0));
        verify(&bytes, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap().end_record().source, 68..90);
        });
    }
}

#[test]
fn trailing_and_clipped_comments_preserve_profile_selection() {
    for profile in PROFILES {
        let mut trailing = classic(0, b"abcd");
        trailing.extend(end(1, 46, 0, 99));
        verify(&trailing, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap().raw_comment(), b"abcd");
        });

        let mut clipped = classic(0, b"ab");
        set16(&mut clipped, 66, 4);
        verify(&clipped, profile, Limits::default(), |location| {
            if profile == Profile::Zipview {
                let location = location.unwrap();
                assert_eq!(location.raw_comment(), b"ab");
                assert_eq!(location.comment_range(), 68..70);
                assert_eq!(location.end_record().comment_len, 4);
            } else {
                assert_eq!(location.unwrap_err(), DirectoryError::NotZip);
            }
        });
    }
}

#[test]
fn maximum_comment_keeps_first_header_and_reuses_partial_tail() {
    let bytes = classic(0, &vec![0xFF; 65_535]);
    assert_eq!(bytes.len(), 65_603);
    for profile in PROFILES {
        verify(&bytes, profile, Limits::default(), |location| {
            let location = location.unwrap();
            assert_eq!(location.directory_range(), 0..46);
            assert_eq!(location.raw_comment().len(), 65_535);
            assert_eq!(location.usage().fetched_bytes, bytes.len() as u64);
        });
    }
}

#[test]
fn multiple_candidates_probe_only_fixed_bytes_then_resume_ranking() {
    let mut bytes = vec![0xA5; 100];
    bytes.extend(central());
    bytes.resize(241, 0xA5);
    bytes.extend(end(1, 141, 100, 65_535));
    bytes.extend(end(1, 243, 20, 65_513));
    bytes.resize(263 + 65_535, 0xFF);
    for profile in PROFILES {
        let mut reads = Vec::new();
        let location = drive(bytes.len() as u64, profile, Limits::default(), Chunk::Full, |range| {
            reads.push(range.clone());
            bytes[range.start as usize..range.end as usize].to_vec()
        })
        .unwrap();
        assert_eq!(location.end_record().source, 241..263);
        assert_eq!(location.directory_range(), 100..241);
        assert_eq!(reads[1].start, 20);
        assert_eq!(reads[2].start, 100);
        assert!(reads.iter().skip(1).all(|range| range.end - range.start <= 46));
        assert!(reads.iter().skip(1).all(|range| range.end <= reads[0].start));
    }
}

#[test]
fn zip64_retains_fixed_fields_and_extensible_source_ranges() {
    for profile in PROFILES {
        for (prefix, extension, pointer) in [(0, 0, 46), (11, 0, 46), (11, 7, 46), (11, 66_000, 46)] {
            let bytes = extended(prefix, extension, pointer, true);
            verify(&bytes, profile, Limits::default(), |location| {
                let location = location.unwrap();
                let record = location.zip64_end().unwrap();
                let locator = location.zip64_locator().unwrap();
                let start = prefix as u64 + 46;
                let end = start + 56 + extension as u64;
                assert_eq!(record.source, start..end);
                assert_eq!(record.extension, start + 56..end);
                assert_eq!(record.body_size, 44 + extension as u64);
                assert_eq!(locator.source, end..end + 20);
                assert_eq!(locator.record_offset, 46);
                assert_eq!(location.declaration().entries, 1);
                assert_eq!(location.directory_range(), prefix as u64..start);
                assert_eq!(location.prefix_shift(), prefix as u64);
            });
        }
    }
}

#[test]
fn zip64_correct_long_pointer_skips_the_opaque_middle() {
    let bytes = extended(11, 200_000, 57, true);
    for profile in PROFILES {
        let mut reads = Vec::new();
        let location = drive(bytes.len() as u64, profile, Limits::default(), Chunk::Full, |range| {
            reads.push(range.clone());
            bytes[range.start as usize..range.end as usize].to_vec()
        })
        .unwrap();
        assert_eq!(location.directory_range(), 11..57);
        assert_eq!(reads[1], 57..113);
        assert!(reads.iter().skip(1).all(|range| range.end <= 113));
        assert!(location.usage().fetched_bytes <= TAIL + 56 + 46 + 4);
    }
}

#[test]
fn zip64_recovery_handles_fixed_prefix_crossing_two_window_edges() {
    for gap in [7, 54, WINDOW + 7, WINDOW + 54] {
        // The record starts gap bytes below the retained tail.
        let extension = (TAIL - 98 + gap) as usize;
        let bytes = extended(100, extension, 46, true);
        for profile in PROFILES {
            verify(&bytes, profile, Limits::default(), |location| {
                let location = location.unwrap();
                assert_eq!(location.zip64_end().unwrap().source.start, 146);
                assert_eq!(location.directory_range(), 100..146);
                assert!(location.buffer_usage().live_bytes <= TAIL as usize + 46);
                assert!(location.buffer_usage().capacity_bytes <= TAIL as usize + 56);
            });

            // Lockstep driving compares the pending range and cumulative work
            // after every partial supply, including the recovery windows.
            for step in [usize::MAX, 1, 17] {
                let len = bytes.len() as u64;
                let limits = Limits::default();
                let mut raw = DirectoryParser::new(len, profile, limits).unwrap();
                let mut projected =
                    DirectoryParser::with_projection(len, profile, limits, |record| Ok(record.view().location()))
                        .unwrap();
                loop {
                    let pending = raw.next_read();
                    assert_eq!(projected.next_read(), pending);
                    assert_eq!(projected.usage(), raw.usage());
                    let Some(read) = pending.unwrap() else { break };
                    let start = read.start as usize;
                    let end = (read.end as usize).min(start.saturating_add(step));
                    let part = &bytes[start..end];
                    raw.supply(read.start, part).unwrap();
                    projected.supply(read.start, part).unwrap();
                }
                let raw = raw.finish().unwrap();
                let projected = projected.finish().unwrap();
                assert_eq!(projected.zip64_end, raw.zip64_end);
                assert_eq!(projected.directory_range, raw.directory_range);
                assert_eq!(projected.prefix_shift, raw.prefix_shift);
                assert_eq!(projected.entries, [raw.entries[0].source]);
                assert_eq!(projected.usage, raw.usage);
            }
        }
    }
}

#[test]
fn nonsaturated_locator_and_disk_fields_preserve_profile_policy() {
    let bytes = extended(0, 0, 46, false);
    verify(&bytes, Profile::Zipfast, Limits::default(), |location| {
        assert!(location.unwrap().zip64_end().is_some());
    });
    verify(&bytes, Profile::Zipview, Limits::default(), |location| {
        let location = location.unwrap();
        assert!(location.zip64_end().is_none());
        assert!(location.zip64_locator().is_none());
        assert_eq!(location.directory_range(), 0..46);
    });

    let mut bytes = classic(0, b"");
    set16(&mut bytes, 50, 2);
    verify(&bytes, Profile::Zipfast, Limits::default(), |location| {
        assert_eq!(location.unwrap_err(), DirectoryError::UnsupportedDisk);
    });
    verify(&bytes, Profile::Zipview, Limits::default(), |location| {
        assert_eq!(location.unwrap().end_record().disk, 2);
    });
}

#[test]
fn bad_zip64_framing_and_unresolved_offset_are_structural_errors() {
    for bad_body in [43, 45, u64::MAX] {
        let mut bytes = extended(0, 0, 46, true);
        set64(&mut bytes, 50, bad_body);
        for profile in PROFILES {
            verify(&bytes, profile, Limits::default(), |location| {
                assert_eq!(location.unwrap_err(), DirectoryError::MalformedZip64);
            });
        }
    }

    let mut bytes = classic(0, b"");
    set32(&mut bytes, 62, u32::MAX);
    for profile in PROFILES {
        verify(&bytes, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap_err(), DirectoryError::MalformedZip64);
        });
    }

    set32(&mut bytes, 62, 0);
    set16(&mut bytes, 56, u16::MAX);
    verify(&bytes, Profile::Zipview, Limits::default(), |location| {
        assert_eq!(location.unwrap().declaration().entries, 65_535);
    });
}

#[test]
fn framed_zip64_contradiction_and_disk_failure_are_not_candidate_fallbacks() {
    for profile in PROFILES {
        let mut bytes = extended(22, 0, 68, true);
        // An older empty EOCD remains plausible. The exact-end candidate has
        // valid ZIP64 framing, but its central size exceeds the record anchor.
        bytes[..22].copy_from_slice(&end(0, 0, 0, 0));
        set64(&mut bytes, 108, 69);
        set64(&mut bytes, 116, 10);
        verify(&bytes, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap_err(), DirectoryError::MalformedZip64);
        });
    }

    let mut bytes = extended(0, 0, 46, true);
    set32(&mut bytes, 118, 2);
    verify(&bytes, Profile::Zipfast, Limits::default(), |location| {
        assert_eq!(location.unwrap_err(), DirectoryError::UnsupportedDisk);
    });
    verify(&bytes, Profile::Zipview, Limits::default(), |location| {
        assert_eq!(location.unwrap().zip64_locator().unwrap().total_disks, 2);
    });
}

#[test]
fn zipview_declared_offset_wins_and_record_shift_is_independent() {
    let mut bytes = extended(11, 0, 46, true);
    set64(&mut bytes, 105, 11);
    for profile in PROFILES {
        verify(&bytes, profile, Limits::default(), |location| {
            let location = location.unwrap();
            assert_eq!(location.zip64_end().unwrap().source.start, 57);
            assert_eq!(location.directory_range(), 11..57);
            assert_eq!(location.prefix_shift(), 0);
        });
    }

    let mut bytes = classic(0, b"");
    set32(&mut bytes, 58, 0); // The size understates the nonempty directory.
    verify(&bytes, Profile::Zipview, Limits::default(), |location| {
        let location = location.unwrap();
        assert_eq!(location.declaration().size, 0);
        assert_eq!(location.directory_range(), 0..0);
    });
    verify(&bytes, Profile::Zipfast, Limits::default(), |location| {
        assert_eq!(location.unwrap_err(), DirectoryError::MalformedEnd);
    });

    let mut bytes = classic(0, b"");
    set32(&mut bytes, 62, 1); // Anchor-based start would require a negative shift.
    for profile in PROFILES {
        verify(&bytes, profile, Limits::default(), |location| {
            assert_eq!(location.unwrap_err(), DirectoryError::MalformedEnd);
        });
    }
}

#[test]
fn supply_rejections_preserve_pending_suffix_usage_and_completed_result() {
    let bytes = classic(0, b"raw");
    let mut parser = EndDiscovery::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
    assert_eq!(parser.supply(0, b"P"), Err(DirectoryError::Supply(SupplyError::Unsolicited)));
    assert_eq!(parser.next_read().unwrap(), Some(0..71));
    parser.supply(0, &bytes[..5]).unwrap();
    let before = parser.usage();
    for (at, supplied, expected) in [
        (0, &bytes[..5], SupplyError::UnexpectedOffset),
        (4, &bytes[4..6], SupplyError::UnexpectedOffset),
        (6, &bytes[6..7], SupplyError::UnexpectedOffset),
        (71, b"P", SupplyError::OutOfBounds),
        (u64::MAX, b"P", SupplyError::OutOfBounds),
    ] {
        assert_eq!(parser.supply(at, supplied), Err(DirectoryError::Supply(expected)));
        assert_eq!(parser.usage(), before);
        assert_eq!(parser.next_read().unwrap(), Some(5..71));
    }
    parser.supply(71, b"").unwrap();
    parser.supply(5, &bytes[5..]).unwrap();
    assert_eq!(parser.next_read().unwrap(), None);
    assert_eq!(parser.supply(71, b"P"), Err(DirectoryError::Supply(SupplyError::OutOfBounds)));
    assert_eq!(parser.finish().unwrap().raw_comment(), b"raw");

    let mut parser = EndDiscovery::new(71, Profile::Zipfast, Limits { range_bytes: 5, ..Limits::default() }).unwrap();
    assert_eq!(parser.next_read().unwrap(), Some(0..5));
    assert_eq!(parser.supply(0, &bytes[..6]), Err(DirectoryError::Supply(SupplyError::Overlong)));
    assert_eq!(parser.next_read().unwrap(), Some(0..5));
    assert_eq!(parser.finish().unwrap_err(), DirectoryError::Incomplete);
}

#[test]
fn discovery_enforces_exact_fetched_work_and_ownership_boundaries() {
    let bytes = classic(0, b"raw");
    let exact = discover_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap().usage();
    let limits = Limits {
        directory_bytes: 46,
        entries: 1,
        fetched_bytes: 71,
        range_bytes: 1,
        comment_bytes: 3,
        work_units: exact.work_units,
        ..Limits::default()
    };
    verify(&bytes, Profile::Zipfast, limits, |location| {
        assert_eq!(location.unwrap().usage(), exact);
    });

    for (limits, kind) in [
        (Limits { directory_bytes: 45, ..limits }, LimitKind::DirectoryBytes),
        (Limits { entries: 0, ..limits }, LimitKind::Entries),
        (Limits { fetched_bytes: 70, ..limits }, LimitKind::FetchedBytes),
        (Limits { range_bytes: 0, ..limits }, LimitKind::RangeBytes),
        (Limits { comment_bytes: 2, ..limits }, LimitKind::CommentBytes),
        (Limits { work_units: exact.work_units - 1, ..limits }, LimitKind::WorkUnits),
    ] {
        verify(&bytes, Profile::Zipfast, limits, |location| {
            assert_eq!(location.unwrap_err(), DirectoryError::Limit(kind));
        });
    }

    for (limits, kind) in [
        (Limits { fetched_bytes: 70, ..limits }, LimitKind::FetchedBytes),
        (Limits { range_bytes: 0, ..limits }, LimitKind::RangeBytes),
        (Limits { work_units: 70, ..limits }, LimitKind::WorkUnits),
    ] {
        let mut parser = EndDiscovery::new(71, Profile::Zipfast, limits).unwrap();
        let before = parser.buffer_usage();
        assert_eq!(parser.next_read(), Err(DirectoryError::Limit(kind)));
        assert_eq!(parser.next_read(), Err(DirectoryError::Limit(kind)));
        assert_eq!(parser.buffer_usage(), before);
        assert_eq!(parser.usage().fetched_bytes, 0);
        assert_eq!(parser.finish().unwrap_err(), DirectoryError::Limit(kind));
    }
}

#[test]
fn recovery_consumes_remaining_allowance_then_stops_before_fetching_more() {
    let bytes = extended(100_000, 100_000, 46, true);
    let limits = Limits { fetched_bytes: TAIL + 56 + 19, range_bytes: 1024, ..Limits::default() };
    let mut parser = EndDiscovery::new(bytes.len() as u64, Profile::Zipfast, limits).unwrap();
    let mut last = None;
    loop {
        match parser.next_read() {
            Ok(Some(range)) => {
                parser.supply(range.start, &bytes[range.start as usize..range.end as usize]).unwrap();
                last = Some(range);
            }
            Err(DirectoryError::Limit(LimitKind::FetchedBytes)) => break,
            other => panic!("unexpected discovery result {other:?}"),
        }
    }
    let last = last.unwrap();
    assert_eq!(last.end - last.start, 19);
    let usage = parser.usage();
    assert_eq!(usage.fetched_bytes, limits.fetched_bytes);
    assert_eq!(parser.next_read(), Err(DirectoryError::Limit(LimitKind::FetchedBytes)));
    assert_eq!(parser.usage(), usage);
}

#[test]
fn sparse_high_offsets_do_not_overflow_end_or_directory_geometry() {
    let len = u64::MAX;
    let central_at = len - 144;
    let zip64_at = len - 98;
    let tail_at = len - TAIL;
    for profile in PROFILES {
        let location = drive(len, profile, Limits::default(), Chunk::Mixed, |range| {
            assert!(range.start >= tail_at);
            let mut bytes = vec![0; (range.end - range.start) as usize];
            for (start, data) in [
                (central_at, central().to_vec()),
                (zip64_at, zip64(44, 1, 46, central_at).to_vec()),
                (len - 42, locator(zip64_at).to_vec()),
                (len - 22, end(u16::MAX, u32::MAX, u32::MAX, u16::MAX).to_vec()),
            ] {
                let from = range.start.max(start);
                let to = range.end.min(start + data.len() as u64);
                if from < to {
                    bytes[(from - range.start) as usize..(to - range.start) as usize]
                        .copy_from_slice(&data[(from - start) as usize..(to - start) as usize]);
                }
            }
            bytes
        });
        if profile == Profile::Zipview {
            let location = location.unwrap();
            assert_eq!(location.directory_range(), central_at..zip64_at);
            assert_eq!(location.comment_range(), len..len);
            assert_eq!(location.prefix_shift(), 0);
        } else {
            assert_eq!(location.unwrap_err(), DirectoryError::NotZip);
        }
    }
}

#[test]
fn first_external_recovery_window_has_overlap_with_max_comment() {
    let mut bytes = extended(100, 7, 46, true);
    let end_at = bytes.len() - 22;
    set16(&mut bytes, end_at + 20, u16::MAX);
    bytes.resize(bytes.len() + 65_535, 0xFF);
    for profile in PROFILES {
        verify(&bytes, profile, Limits::default(), |location| {
            let location = location.unwrap();
            assert_eq!(location.zip64_end().unwrap().source, 146..209);
            assert_eq!(location.raw_comment().len(), 65_535);
        });
    }
}

#[test]
fn recovery_uses_same_work_budget_for_full_and_fragmented_input() {
    let bytes = extended(100, 66_000, 46, true);
    for profile in PROFILES {
        let exact = discover_slice(&bytes, profile, Limits::default()).unwrap().usage();
        let limits = Limits { work_units: exact.work_units, ..Limits::default() };
        verify(&bytes, profile, limits, |location| {
            assert_eq!(location.unwrap().usage(), exact);
        });
        let limits = Limits { work_units: exact.work_units - 1, ..limits };
        verify(&bytes, profile, limits, |location| {
            assert_eq!(location.unwrap_err(), DirectoryError::Limit(LimitKind::WorkUnits));
        });
    }
}

#[test]
fn borrowed_recovery_uses_no_window_buffer_and_fragmented_recovery_uses_one() {
    let bytes = extended(100_000, 180_000, 46, true);
    for fragmented in [false, true] {
        let mut parser = EndDiscovery::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
        let mut searched = false;
        while let Some(range) = parser.next_read().unwrap() {
            let complete = range.end - range.start == WINDOW;
            if complete && fragmented {
                parser.supply(range.start, &bytes[range.start as usize..range.start as usize + 1]).unwrap();
                assert_eq!(parser.next_read().unwrap(), Some(range.start + 1..range.end));
                let buffers = parser.buffer_usage();
                assert!(buffers.live_bytes <= TAIL as usize + 56 + 55 + 1);
                assert!(buffers.capacity_bytes <= (TAIL + WINDOW) as usize + 56 + 55);
            }
            let start = range.start + u64::from(complete && fragmented);
            parser.supply(start, &bytes[start as usize..range.end as usize]).unwrap();
            if complete {
                searched = true;
                if !fragmented {
                    assert!(parser.buffer_usage().capacity_bytes <= TAIL as usize + 56 + 55);
                }
            }
        }
        assert!(searched);
        let location = parser.finish().unwrap();
        assert_eq!(location.directory_range(), 100_000..100_046);
        assert!(location.buffer_usage().capacity_bytes <= TAIL as usize + 56);
    }
}

#[test]
fn plausible_classic_candidates_cannot_escape_declaration_limits_or_disk_policy() {
    let mut bytes = end(0, 0, 0, 0).to_vec();
    bytes.extend(classic(0, b"raw"));
    let last = 22 + 46;
    set32(&mut bytes, last + 16, 22);
    let limits = Limits { entries: 0, ..Limits::default() };
    for profile in PROFILES {
        verify(&bytes, profile, limits, |location| {
            assert_eq!(location.unwrap_err(), DirectoryError::Limit(LimitKind::Entries));
        });
    }
    set16(&mut bytes, last + 4, 1);
    verify(&bytes, Profile::Zipfast, Limits::default(), |location| {
        assert_eq!(location.unwrap_err(), DirectoryError::UnsupportedDisk);
    });
}

#[test]
fn first_header_reuses_overlapping_declared_offset_probe() {
    let mut bytes = vec![0xA5];
    bytes.extend(central());
    bytes.resize(101, 0xA5);
    bytes.extend(end(1, 100, 0, u16::MAX));
    bytes.resize(bytes.len() + 65_535, 0xFF);
    let mut reads = Vec::new();
    let location = drive(bytes.len() as u64, Profile::Zipview, Limits::default(), Chunk::Full, |range| {
        reads.push(range.clone());
        bytes[range.start as usize..range.end as usize].to_vec()
    })
    .unwrap();
    assert_eq!(location.directory_range(), 1..101);
    assert_eq!(location.prefix_shift(), 1);
    assert_eq!(reads[1..], [0..4, 4..5, 5..25]);
}

#[test]
fn deterministic_mutations_match_between_slice_and_fragmented_sources() {
    let cases = [classic(3, b"data"), extended(11, 7, 46, true)];
    for source in cases {
        for at in 0..source.len() {
            for mask in [0x01, 0x80, 0xFF] {
                let mut bytes = source.clone();
                bytes[at] ^= mask;
                for profile in PROFILES {
                    verify(&bytes, profile, Limits::default(), |_| {});
                }
            }
        }
    }
}

#[test]
fn zero_count_keeps_checked_noncentral_directory_trailer() {
    let mut bytes = b"prefixtrailer".to_vec();
    bytes.extend(end(0, 7, 0, 0));
    for profile in PROFILES {
        let location = discover_slice(&bytes, profile, Limits::default()).unwrap();
        assert_eq!(location.directory_range(), 6..13);
        assert_eq!(location.prefix_shift(), 6);
        assert_eq!(location.first_header(), None);
    }
}

#[test]
fn walk_rejects_logical_comment_end_overflow_at_a_sparse_u64_source_end() {
    use crate::{DirectoryParser, ParseError};

    let len = u64::MAX;
    let central_at = len - 144;
    let zip64_at = len - 98;
    let mut record = central();
    set16(&mut record, 32, u16::MAX);
    let suffix =
        [record.as_slice(), &zip64(44, 1, 46, central_at), &locator(zip64_at), &end(u16::MAX, u32::MAX, u32::MAX, 0)]
            .concat();
    for profile in PROFILES {
        let mut parser = DirectoryParser::new(len, profile, Limits::default()).unwrap();
        let read = parser.next_read().unwrap().unwrap();
        assert_eq!(read, len - TAIL..len);
        let mut tail = vec![0; TAIL as usize];
        tail[TAIL as usize - suffix.len()..].copy_from_slice(&suffix);
        parser.supply(read.start, &tail).unwrap();
        let error = Err(DirectoryError::Parse(ParseError::OffsetOverflow));
        assert_eq!(parser.next_read(), error);
        assert_eq!(parser.next_read(), error);
        assert_eq!(parser.usage().owned.entries, 0);
    }
}

#[test]
fn cloned_partial_tail_keeps_the_bounded_discovery_reservation() {
    let bytes = classic(80_000, b"archive");
    let mut original = EndDiscovery::new(bytes.len() as u64, Profile::Zipfast, Limits::default()).unwrap();
    let read = original.next_read().unwrap().unwrap();
    let split = read.start + 40 * 1024;
    original.supply(read.start, &bytes[read.start as usize..split as usize]).unwrap();
    let checkpoint = original.usage();
    let mut clone = original.clone();
    assert_eq!(clone.next_read(), Ok(Some(split..read.end)));
    assert_eq!(clone.usage(), checkpoint);
    for parser in [&mut clone, &mut original] {
        parser.supply(split, &bytes[split as usize..read.end as usize]).unwrap();
    }
    assert_eq!(clone.usage(), original.usage());
    assert_eq!(clone.buffer_usage().live_bytes, original.buffer_usage().live_bytes);
    assert!(clone.buffer_usage().capacity_bytes <= original.buffer_usage().capacity_bytes);
    let cloned = clone.finish().unwrap();
    let original = original.finish().unwrap();
    assert_eq!(cloned.directory_range(), original.directory_range());
    assert_eq!(cloned.raw_comment(), original.raw_comment());
}

fn parse_anchored(bytes: &[u8], offset: u64, limits: Limits, fragment: usize) -> Result<Directory, DirectoryError> {
    let mut parser = DirectoryParser::at_eocd(bytes.len() as u64, offset, limits)?;
    while let Some(range) = parser.next_read()? {
        assert_eq!(parser.next_read()?, Some(range.clone()));
        let start = range.start as usize;
        let end = (range.end as usize).min(start + fragment);
        parser.supply(range.start, &bytes[start..end])?;
    }
    parser.finish()
}

#[test]
fn anchored_directory_keeps_the_real_eocd_and_full_binary_comment() {
    let mut comment = vec![0xA5; u16::MAX as usize];
    let fake = end(0, 0, 0, 0);
    let fake_at = comment.len() - fake.len();
    comment[fake_at..].copy_from_slice(&fake);
    let bytes = classic(30, &comment);
    let actual_at = 30 + 46;
    let default = parse_slice(&bytes, Profile::Zipfast, Limits::default()).unwrap();
    assert_eq!(default.end_record.source.start, (bytes.len() - fake.len()) as u64);
    assert!(default.entries.is_empty());

    let baseline = parse_anchored(&bytes, actual_at, Limits::default(), usize::MAX / 2).unwrap();
    assert_eq!(baseline.end_record.source.start, actual_at);
    assert_eq!(baseline.raw_comment, comment);
    assert_eq!(baseline.entries.len(), 1);
    for fragment in [1, 17, 64 * 1024] {
        let parsed = parse_anchored(&bytes, actual_at, Limits::default(), fragment).unwrap();
        assert_eq!(parsed, baseline);
    }
}

#[test]
fn invalid_eocd_anchor_never_uses_a_valid_neighbor() {
    let bytes = classic(30, b"binary\0comment");
    for anchor in [0, 75, 77, bytes.len() as u64, u64::MAX] {
        assert_eq!(parse_anchored(&bytes, anchor, Limits::default(), 17).unwrap_err(), DirectoryError::MalformedEnd,);
    }
    let mut malformed = bytes.clone();
    malformed.extend(end(1, 1024, 0, 0));
    let real_comment_len = (malformed.len() - (76 + 22)) as u16;
    set16(&mut malformed, 76 + 20, real_comment_len);
    assert_eq!(
        parse_anchored(&malformed, bytes.len() as u64, Limits::default(), 1).unwrap_err(),
        DirectoryError::MalformedEnd,
    );
    let mut inexact = bytes;
    inexact.push(0);
    assert_eq!(parse_anchored(&inexact, 76, Limits::default(), 17).unwrap_err(), DirectoryError::MalformedEnd,);
}

#[test]
fn anchored_zip64_preserves_validation_and_budgets() {
    let bytes = extended(30, 0, 76, true);
    let anchor = (bytes.len() - 22) as u64;
    let baseline = parse_anchored(&bytes, anchor, Limits::default(), 1).unwrap();
    assert_eq!(baseline.directory_range, 30..76);
    assert_eq!(baseline.zip64_locator.as_ref().unwrap().record_offset, 76);
    assert_eq!(baseline.zip64_end.as_ref().unwrap().source, 76..132);
    let limits = Limits {
        directory_bytes: 46,
        entries: 1,
        fetched_bytes: baseline.usage.fetched_bytes,
        work_units: baseline.usage.work_units,
        range_bytes: 1,
        ..Limits::default()
    };
    assert_eq!(parse_anchored(&bytes, anchor, limits, 1).unwrap(), baseline);
    for (limits, error) in [
        (Limits { fetched_bytes: limits.fetched_bytes - 1, ..limits }, LimitKind::FetchedBytes),
        (Limits { work_units: limits.work_units - 1, ..limits }, LimitKind::WorkUnits),
        (Limits { directory_bytes: limits.directory_bytes - 1, ..limits }, LimitKind::DirectoryBytes),
        (Limits { entries: 0, ..limits }, LimitKind::Entries),
        (Limits { range_bytes: 0, ..limits }, LimitKind::RangeBytes),
    ] {
        assert_eq!(parse_anchored(&bytes, anchor, limits, 1).unwrap_err(), DirectoryError::Limit(error));
    }
    let mut corrupt = bytes;
    corrupt[76] ^= 1;
    assert_eq!(parse_anchored(&corrupt, anchor, Limits::default(), 1).unwrap_err(), DirectoryError::MalformedZip64,);
}

#[test]
fn discovery_scratch_limit_counts_inline_tail_and_fragmented_recovery() {
    let bytes = extended(100_000, 180_000, 46, true);
    let inline = 56 + 55;
    let tail = TAIL as usize;
    let window = WINDOW as usize;
    let limit_error = DirectoryError::Limit(LimitKind::ScratchBytes);
    for profile in PROFILES {
        assert_eq!(
            EndDiscovery::new_with_scratch_limit(bytes.len() as u64, profile, Limits::default(), inline - 1)
                .unwrap_err(),
            limit_error,
        );
        for (cap, fragmented, succeeds) in [
            (tail + inline - 1, false, false),
            (tail + inline, false, true),
            (tail + inline + window - 1, true, false),
            (tail + inline + window, true, true),
        ] {
            let mut discovery =
                EndDiscovery::new_with_scratch_limit(bytes.len() as u64, profile, Limits::default(), cap).unwrap();
            let mut saw_recovery = false;
            while let Some(range) = discovery.next_read().unwrap() {
                let is_recovery = range.end - range.start == WINDOW;
                saw_recovery |= is_recovery;
                let start = range.start as usize;
                let end = if is_recovery && fragmented { start + 1 } else { range.end as usize };
                let mut cloned = (is_recovery && fragmented).then(|| discovery.clone());
                let result = discovery.supply(range.start, &bytes[start..end]);
                assert!(discovery.buffer_usage().capacity_bytes <= cap);
                if let Some(cloned) = &mut cloned {
                    assert_eq!(cloned.supply(range.start, &bytes[start..end]), result);
                    assert!(cloned.buffer_usage().capacity_bytes <= cap);
                }
                if let Err(error) = result {
                    assert!(!succeeds);
                    assert_eq!(error, limit_error);
                    assert_eq!(discovery.next_read(), Err(limit_error));
                    assert_eq!(discovery.clone().next_read(), Err(limit_error));
                    break;
                }
            }
            assert_eq!(saw_recovery, cap >= tail + inline);
            if succeeds {
                assert_eq!(discovery.finish().unwrap().directory_range(), 100_000..100_046);
            } else {
                assert_eq!(discovery.finish().unwrap_err(), limit_error);
            }
        }
    }
}

#[test]
fn anchored_scratch_limit_precedes_fragmented_body_reservation_even_for_corrupted_lengths() {
    let name = usize::from(u16::MAX);
    let body = 2 * name;
    let central_at = 30;
    let eocd = central_at + 46 + body;
    let required = TAIL as usize + body;
    for corrupt in [false, true] {
        let mut bytes = vec![0xA5; central_at];
        let mut header = central();
        set16(&mut header, 28, u16::MAX);
        set16(&mut header, 30, u16::from(corrupt));
        set16(&mut header, 32, u16::MAX - u16::from(corrupt));
        bytes.extend(header);
        bytes.resize(eocd, b'a');
        bytes.extend(end(1, (46 + body) as u32, central_at as u32, 0));

        for (cap, admitted_body) in [(required - 1, false), (required, true)] {
            if corrupt && admitted_body {
                continue;
            }
            let mut parser =
                DirectoryParser::at_eocd_with_scratch_limit(bytes.len() as u64, eocd as u64, Limits::default(), cap)
                    .unwrap();
            let mut saw_full_reservation = false;
            while let Some(range) = parser.next_read().unwrap() {
                let start = range.start as usize;
                let end = (start + 64 * 1024).min(range.end as usize);
                let mut cloned = (start == central_at + 46).then(|| parser.clone());
                let result = parser.supply(range.start, &bytes[start..end]);
                if let Some(cloned) = &mut cloned {
                    assert_eq!(cloned.supply(range.start, &bytes[start..end]), result);
                    assert!(cloned.buffer_usage().capacity_bytes <= cap);
                }
                let scratch = parser.buffer_usage().capacity_bytes;
                assert!(scratch <= cap, "scratch capacity {scratch} exceeds {cap}");
                saw_full_reservation |= scratch == required;
                if let Err(error) = result {
                    assert_eq!(error, DirectoryError::Limit(LimitKind::ScratchBytes));
                    assert_eq!(parser.next_read(), Err(error));
                    assert_eq!(parser.clone().next_read(), Err(error));
                    break;
                }
            }
            assert_eq!(saw_full_reservation, admitted_body);
            if admitted_body {
                assert_eq!(parser.finish().unwrap().entries[0].raw_name.len(), name);
            } else {
                assert_eq!(parser.finish().unwrap_err(), DirectoryError::Limit(LimitKind::ScratchBytes));
            }
        }
    }
}
