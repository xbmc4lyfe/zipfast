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

//! Private experimental successor proof, never a product handoff API.

use super::*;
use std::io::Write;

type Member = (crate::rar5::FileHeader, &'static [u8], Vec<u8>);

fn members() -> (Member, Member) {
    let (first, packed, gold) = boundary::solid_first();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(boundary::SOLID).unwrap();
    let mut volume = crate::rar5::reader::Volume::open(file.path()).unwrap();
    let mut headers = Vec::new();
    while let Some(block) = volume.next_block().unwrap() {
        if let crate::rar5::reader::Block::File(header) = block {
            headers.push(header);
        }
    }
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].data_at, first.data_at);
    assert_eq!(headers[0].packed_size, first.packed_size);
    let second = headers.remove(1);
    assert_eq!(second.name, "b.txt");
    assert_eq!((second.packed_size, second.unpacked_size, second.dictionary), (37, 21003, 1048576));
    assert_eq!(second.crc32, Some(0x6b5eab7c));
    let raw = second.rar4.unwrap();
    assert_eq!((raw.flags, raw.unpack_version, raw.method), (0x8090, 29, 0x35));
    let start = usize::try_from(second.data_at).unwrap();
    let end = start.checked_add(usize::try_from(second.packed_size).unwrap()).unwrap();
    let second_packed = &boundary::SOLID[start..end];
    let mut second_gold = b"RAR4 archive compatibility.\n".repeat(750);
    second_gold.extend_from_slice(b"end");
    assert_eq!(second_gold.len() as u64, second.unpacked_size);
    assert_eq!(crate::crc32::hash(&second_gold), second.crc32.unwrap());
    assert_eq!(
        crate::crypto::sha256(&second_gold),
        [
            0x75, 0x50, 0xee, 0x05, 0xfc, 0x33, 0x75, 0x95, 0xe1, 0xb1, 0x8c, 0xc2, 0x9d, 0x94, 0xc0, 0x12, 0x56, 0x66,
            0x3e, 0xeb, 0x80, 0x1a, 0x7e, 0xe2, 0x84, 0xa9, 0x37, 0xfa, 0xf7, 0x7c, 0xff, 0x71,
        ]
    );
    ((first, packed, gold), (second, second_packed, second_gold))
}

#[test]
fn independent_empty_history_cannot_decode_the_successor() {
    let (_, (second, packed, gold)) = members();
    let mut d = Rar4Decoder::new(
        second.dictionary,
        second.packed_size,
        second.unpacked_size,
        second.dictionary,
        Cancellation::default(),
    )
    .unwrap();
    d.trace = Some(BoundaryTrace::default());
    let mut out = Vec::new();
    let result = d.feed(packed, &mut collect(&mut out));
    println!(
        "independent successor result={result:?} produced={} fed={} cursor={} tables={} trace={:?}",
        d.produced,
        d.fed,
        d.bits.bit_position(),
        d.table_builds,
        d.trace
    );
    assert!(matches!(result, Err(Rar4DecodeError::Unsupported(Rar4UnsupportedMode::Ppm))));
    assert_eq!((d.produced, d.fed, d.bits.bit_position(), d.table_builds), (0, 37, 1, 0));
    assert!(d.poisoned);
    assert_ne!(out, gold);
    assert!(d.finish(&mut collect(&mut out)).is_err());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    RepeatLast,
    Recent(usize),
    New,
    Short,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CrossMatch {
    at: u64,
    cumulative: u64,
    local: u64,
    distance: u64,
    length: u64,
    origin: Origin,
    ring_position: u64,
    table_builds: u64,
    state: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rar5::unpack::rar4) struct SuccessorTrace {
    start: u64,
    copies: u64,
    first_cross: Option<CrossMatch>,
}

// Semantic tables plus old lengths and recent/last/low state, fixed digest only.
// No dictionary or packed payload is copied; integer encoding is explicit.
fn retained_digest(d: &Rar4Decoder) -> u32 {
    let mut digest = crc32fast::Hasher::new();
    digest.update(&d.old);
    for table in &d.tables[1..] {
        for value in table.count {
            digest.update(&value.to_le_bytes());
        }
        for value in table.first {
            digest.update(&value.to_le_bytes());
        }
        for value in table.offset {
            digest.update(&(value as u64).to_le_bytes());
        }
        for value in &table.symbols[..table.used] {
            digest.update(&value.to_le_bytes());
        }
        digest.update(&(table.used as u64).to_le_bytes());
    }
    for value in d.recent.into_iter().chain([d.last_length, d.low]) {
        digest.update(&value.to_le_bytes());
    }
    digest.update(&[d.low_repeats]);
    digest.finalize()
}

impl Rar4Decoder {
    pub(in crate::rar5::unpack::rar4) fn observe_successor_match(&mut self, length: u64, distance: u64) {
        if let Some(trace) = &self.successor_trace {
            let local = self.produced.checked_sub(trace.start).unwrap();
            let event = if trace.first_cross.is_none() && distance > local {
                Some(CrossMatch {
                    at: self.bits.bit_position(),
                    cumulative: self.produced,
                    local,
                    distance,
                    length,
                    origin: match self.phase {
                        Phase::Token => Origin::RepeatLast,
                        Phase::LengthExtra { recent: Some(slot), .. } => Origin::Recent(slot),
                        Phase::Short { .. } => Origin::Short,
                        Phase::DistanceBits { .. } | Phase::Low { .. } => Origin::New,
                        _ => unreachable!("successor observation must originate at an original copy caller"),
                    },
                    ring_position: self.produced & (self.dictionary.len() as u64 - 1),
                    table_builds: self.table_builds,
                    state: retained_digest(self),
                })
            } else {
                None
            };
            let trace = self.successor_trace.as_mut().unwrap();
            trace.copies = trace.copies.checked_add(1).unwrap();
            if event.is_some() {
                trace.first_cross = event;
            }
        }
    }
}

// Explicit experimental exception for this ONE known poisoned sentinel probe.
// This is not a capability or a general recovery route for decoder failures.
fn begin_known_successor(
    d: &mut Rar4Decoder,
    error: &Rar4DecodeError,
    first_out: &[u8],
    first: &crate::rar5::FileHeader,
    second: &crate::rar5::FileHeader,
) -> Result<(), &'static str> {
    if !matches!(error, Rar4DecodeError::DecodedSize { expected: 19601, actual: 19600 }) {
        return Err("not the known sentinel error");
    }
    if first.unpacked_size != 19600
        || first.packed_size != 92
        || first.dictionary != 1048576
        || first.crc32 != Some(0x58a55c98)
        || !first.rar4.is_some_and(|r| (r.flags, r.unpack_version, r.method) == (0x8080, 29, 0x35))
        || second.unpacked_size != 21003
        || second.packed_size != 37
        || second.dictionary != first.dictionary
        || second.crc32 != Some(0x6b5eab7c)
        || !second.rar4.is_some_and(|r| (r.flags, r.unpack_version, r.method) == (0x8090, 29, 0x35))
    {
        return Err("unexpected parsed metadata");
    }
    if first_out.len() != 19600
        || !first_out.as_chunks::<28>().0.iter().all(|line| line == b"RAR4 archive compatibility.\n")
        || crate::crc32::hash(first_out) != 0x58a55c98
    {
        return Err("unverified first output");
    }
    let expected_events = [
        (TraceKind::Mode { ppm: false }, 1),
        (TraceKind::Retain { delta: false }, 2),
        (TraceKind::Tables, 275),
        (TraceKind::EndSymbol, 729),
        (TraceKind::EndBit { same_file: false }, 730),
        (TraceKind::EndHint { read_tables_next: false }, 731),
    ];
    let Some(trace) = &d.trace else { return Err("missing first boundary observation") };
    if trace.len != expected_events.len()
        || !trace.events[..trace.len]
            .iter()
            .zip(expected_events)
            .all(|(event, (kind, at))| event.is_some_and(|event| event.kind == kind && event.at == at))
    {
        return Err("wrong first boundary observation");
    }
    if d.produced != 19600
        || d.expected != 19601
        || d.packed != 92
        || d.fed != 92
        || d.bits.bit_position() != 731
        || d.bits.read_bytes != 92
        || d.bits.count != 5
        || !matches!(d.phase, Phase::EndHint)
        || !d.poisoned
        || d.finished
        || d.filled != 0
        || d.prefix != 0
        || d.depth != 0
        || d.table_builds != 1
        || d.tables[1].used == 0
        || retained_digest(d) != 0xd338df9e
        || d.dictionary.len() != 1048576
        || d.dictionary.capacity() != 1048576
    {
        return Err("unsafe experimental entry state");
    }
    d.work.check().map_err(|_| "canceled transition")?;
    let expected = d.produced.checked_add(second.unpacked_size).ok_or("cumulative size overflow")?;
    // Keep cumulative produced for the ORIGINAL ring/distance implementation.
    // Production must later separate member accounting from history accounting.
    d.expected = expected;
    d.packed = second.packed_size;
    d.fed = 0;
    d.bits = Bits::default();
    d.prefix = 0;
    d.depth = 0;
    d.phase = Phase::Token; // observed 00; source-derived retain-tables rule
    d.filled = 0; // original private drain already emptied predecessor output
    d.finished = false;
    d.poisoned = false; // ONLY the explicitly checked known-sentinel exception
    d.successor_trace = Some(SuccessorTrace { start: d.produced, copies: 0, first_cross: None });
    Ok(())
}

#[test]
fn retained_history_decodes_full_successor_in_original_machine() {
    let ((first, packed, gold), (second, next, next_gold)) = members();
    let (mut d, out, error) = boundary::probe(packed.len(), gold.len(), first.dictionary, [packed]);
    let before = retained_digest(&d);
    begin_known_successor(&mut d, &error, &out, &first, &second).unwrap();
    assert_eq!(retained_digest(&d), before);
    let mut successor = Vec::new();
    d.feed(next, &mut collect(&mut successor)).unwrap();
    d.finish(&mut collect(&mut successor)).unwrap();
    assert_eq!(successor, next_gold);
    assert_eq!(crate::crc32::hash(&successor), second.crc32.unwrap());
    assert_eq!((d.produced, d.expected, d.fed, d.packed, d.table_builds), (40603, 40603, 37, 37, 1));
    println!(
        "retained second offset={} bytes={} cursor={} read={} buffered={} before={before:08x} after={:08x} recent={:?} last={} low={} repeats={} work={} trace={:?}",
        second.data_at,
        successor.len(),
        d.bits.bit_position(),
        d.bits.read_bytes,
        d.bits.count,
        retained_digest(&d),
        d.recent,
        d.last_length,
        d.low,
        d.low_repeats,
        d.work.operations,
        d.successor_trace
    );
    assert_eq!((d.bits.bit_position(), d.bits.read_bytes, d.bits.count), (280, 35, 0));
    assert_eq!(
        d.successor_trace,
        Some(SuccessorTrace {
            start: 19600,
            copies: 90,
            first_cross: Some(CrossMatch {
                at: 12,
                cumulative: 19600,
                local: 0,
                distance: 28,
                length: 257,
                origin: Origin::New,
                ring_position: 19600,
                table_builds: 1,
                state: 0xd338df9e,
            }),
        })
    );
    assert_eq!(retained_digest(&d), 0x7b0ab764);
    assert!(d.finished && !d.poisoned);
    assert!(matches!(d.phase, Phase::Complete));
    // Size-first final completion has no second boundary observation.
    assert_eq!(d.trace.as_ref().unwrap().len, 6);
}

#[derive(Debug, PartialEq, Eq)]
struct FinalState {
    successor: Option<SuccessorTrace>,
    boundary: Option<BoundaryTrace>,
    produced: u64,
    fed: u64,
    cursor: u64,
    read_bytes: u64,
    buffered: u8,
    table_builds: u64,
    state: u32,
    history_crc: u32,
}

fn final_state(d: &Rar4Decoder) -> FinalState {
    assert!(d.finished && !d.poisoned && matches!(d.phase, Phase::Complete));
    FinalState {
        successor: d.successor_trace.clone(),
        boundary: d.trace.clone(),
        produced: d.produced,
        fed: d.fed,
        cursor: d.bits.bit_position(),
        read_bytes: d.bits.read_bytes,
        buffered: d.bits.count,
        table_builds: d.table_builds,
        state: retained_digest(d),
        // Fixed streaming digest checks identical final initialized history,
        // without cloning it into an observation snapshot.
        history_crc: crate::crc32::hash(&d.dictionary[..d.produced as usize]),
    }
}

#[test]
fn successor_splits_and_first_member_splits_never_replay() {
    let ((first, packed, gold), (second, next, next_gold)) = members();
    let run = |first_pieces: Vec<&[u8]>, second_pieces: Vec<&[u8]>| {
        let (mut d, out, error) = boundary::probe(packed.len(), gold.len(), first.dictionary, first_pieces);
        let pointer = d.dictionary.as_ptr();
        let work_before = d.work.operations;
        begin_known_successor(&mut d, &error, &out, &first, &second).unwrap();
        assert_eq!(d.dictionary.as_ptr(), pointer);
        assert_eq!(d.work.operations, work_before);
        let mut successor = Vec::new();
        for piece in second_pieces {
            d.feed(piece, &mut collect(&mut successor)).unwrap();
        }
        d.finish(&mut collect(&mut successor)).unwrap();
        assert_eq!(successor, next_gold);
        assert_eq!(crate::crc32::hash(&successor), 0x6b5eab7c);
        assert_eq!(d.dictionary.as_ptr(), pointer);
        (final_state(&d), d.work.operations)
    };
    let (whole, work) = run(vec![packed], vec![next]);
    for split in 0..=next.len() {
        let (state, operations) = run(vec![packed], vec![&[], &next[..split], &[], &next[split..], &[]]);
        assert_eq!(state, whole, "second split {split}");
        assert!(operations < work + 128);
    }
    let (state, operations) = run(vec![packed], next.chunks(1).flat_map(|b| [b, &[][..]]).collect());
    assert_eq!(state, whole);
    assert!(operations < work + next.len() as u64 * 12);
    // Linear campaigns: all first splits with second whole, no Cartesian run.
    for split in 0..=packed.len() {
        let (state, operations) = run(vec![&[], &packed[..split], &[], &packed[split..], &[]], vec![next]);
        assert_eq!(state, whole, "first split {split}");
        assert!(operations < work + 128);
    }
    let (state, operations) = run(packed.chunks(1).flat_map(|b| [b, &[][..]]).collect(), vec![next]);
    assert_eq!(state, whole);
    assert!(operations < work + packed.len() as u64 * 12);
    println!("split campaigns: second=38 first=93 one-byte+empty=2 whole=1 final={whole:?} work={work}");
}

#[test]
fn successor_proper_physical_prefixes_fail_and_stay_poisoned() {
    let ((first, packed, gold), (second, next, _)) = members();
    for end in 0..next.len() {
        let (mut d, out, error) = boundary::probe(packed.len(), gold.len(), first.dictionary, [packed]);
        begin_known_successor(&mut d, &error, &out, &first, &second).unwrap();
        let mut successor = Vec::new();
        d.feed(&next[..end], &mut collect(&mut successor)).unwrap();
        let error = d.finish(&mut collect(&mut successor)).unwrap_err();
        assert!(matches!(error, Rar4DecodeError::PackedSize { expected: 37, actual } if actual==end as u64));
        assert!(d.poisoned && !d.finished);
        assert!(d.bits.bit_position() <= end as u64 * 8);
        assert!(d.feed(&[], &mut collect(&mut successor)).is_err());
        assert!(d.finish(&mut collect(&mut successor)).is_err());
        if end >= 35 {
            assert_eq!(d.produced, 40603); // exact bytes still cannot waive physical extent
            assert_eq!(d.bits.bit_position(), 280);
        }
    }
    println!("all 37 proper second physical prefixes retain PackedSize failure and poison");
}

#[test]
fn missing_bad_or_unflushed_predecessor_cannot_enter_private_transition() {
    let ((first, packed, gold), (second, _, _)) = members();
    let (mut d, mut out, error) = boundary::probe(packed.len(), gold.len(), first.dictionary, [packed]);
    assert!(begin_known_successor(&mut d, &error, &out[..out.len() - 1], &first, &second).is_err());
    out[0] ^= 1;
    assert!(begin_known_successor(&mut d, &error, &out, &first, &second).is_err());
    out[0] ^= 1;
    let mut bad_header = first.clone();
    bad_header.crc32 = Some(first.crc32.unwrap() ^ 1);
    assert!(begin_known_successor(&mut d, &error, &out, &bad_header, &second).is_err());
    assert!(
        begin_known_successor(&mut d, &Rar4DecodeError::Malformed("arbitrary failure"), &out, &first, &second).is_err()
    );
    d.filled = 1;
    assert!(begin_known_successor(&mut d, &error, &out, &first, &second).is_err());
    d.filled = 0;
    d.fed -= 1;
    assert!(begin_known_successor(&mut d, &error, &out, &first, &second).is_err());
    d.fed += 1;
    let end = d.trace.as_mut().unwrap().events[5].as_mut().unwrap();
    end.kind = TraceKind::EndHint { read_tables_next: true };
    assert!(begin_known_successor(&mut d, &error, &out, &first, &second).is_err());
    d.trace.as_mut().unwrap().events[5].as_mut().unwrap().kind = TraceKind::EndHint { read_tables_next: false };
    d.work.cancel.as_ref().unwrap().cancel();
    assert!(begin_known_successor(&mut d, &error, &out, &first, &second).is_err());
    assert!(d.poisoned);
    assert_eq!((d.produced, d.expected, d.packed, d.fed), (19600, 19601, 92, 92));
    assert!(d.successor_trace.is_none());
    println!(
        "private transition refused missing/corrupt output, bad CRC header, arbitrary error, pending output, short extent, 01 and canceled state"
    );
}

#[test]
fn falsification_separates_history_ring_position_and_built_tables() {
    let ((first, packed, gold), (second, next, next_gold)) = members();
    for control in 0..4 {
        let (mut d, out, error) = boundary::probe(packed.len(), gold.len(), first.dictionary, [packed]);
        begin_known_successor(&mut d, &error, &out, &first, &second).unwrap();
        match control {
            0 => {
                d.produced = 0;
                d.expected = second.unpacked_size;
                d.successor_trace.as_mut().unwrap().start = 0;
            }
            1 => d.dictionary[..19600].fill(0),
            2 => {
                d.produced += 1;
                d.expected += 1;
                d.successor_trace.as_mut().unwrap().start += 1;
            }
            _ => d.tables[1] = Huff::empty(),
        }
        let mut out = Vec::new();
        let result = d.feed(next, &mut collect(&mut out));
        match control {
            0 => {
                assert!(matches!(
                    result,
                    Err(Rar4DecodeError::Malformed("match distance outside initialized history"))
                ));
                assert_eq!((d.produced, d.bits.bit_position()), (0, 12));
                assert!(d.poisoned);
            }
            1 | 2 => {
                result.unwrap();
                d.finish(&mut collect(&mut out)).unwrap();
                assert_ne!(out, next_gold);
                assert_ne!(crate::crc32::hash(&out), 0x6b5eab7c);
                println!(
                    "history control={control} output={} CRC={:08x} cursor={}",
                    out.len(),
                    crate::crc32::hash(&out),
                    d.bits.bit_position()
                );
            }
            _ => {
                assert!(matches!(result, Err(Rar4DecodeError::Malformed("empty Huffman table"))));
                assert_eq!((d.produced, d.bits.bit_position()), (19600, 0));
                assert!(d.poisoned);
            }
        }
        println!(
            "control={control} produced={} tables={} first_cross={:?} poison={}",
            d.produced, d.table_builds, d.successor_trace, d.poisoned
        );
    }
}

#[test]
fn successor_transition_and_decode_allocate_no_second_dictionary() {
    let ((first, packed, gold), (second, next, next_gold)) = members();
    let cancel = Cancellation::default();
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|c| c.set(true));
    let created =
        Rar4Decoder::new(first.dictionary, first.packed_size, first.unpacked_size + 1, first.dictionary, cancel);
    TRACK_ALLOC.with(|c| c.set(false));
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 1);
    let mut d = created.unwrap();
    d.trace = Some(BoundaryTrace::default());
    let pointer = d.dictionary.as_ptr();
    let mut out = Vec::with_capacity(gold.len());
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|c| c.set(true));
    let error = d.feed(packed, &mut collect(&mut out)).unwrap_err();
    d.flush(&mut collect(&mut out)).unwrap();
    let transition = begin_known_successor(&mut d, &error, &out, &first, &second);
    TRACK_ALLOC.with(|c| c.set(false));
    transition.unwrap();
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 0);
    let mut successor = Vec::with_capacity(next_gold.len());
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|c| c.set(true));
    let feed = d.feed(next, &mut collect(&mut successor));
    let finish = d.finish(&mut collect(&mut successor));
    TRACK_ALLOC.with(|c| c.set(false));
    feed.unwrap();
    finish.unwrap();
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 0);
    assert_eq!(successor, next_gold);
    assert_eq!(d.dictionary.as_ptr(), pointer);
    assert_eq!((d.dictionary.len(), d.dictionary.capacity()), (1048576, 1048576));
    println!(
        "successor decoder fixed={} dictionary len/cap=1048576 allocations construct=1 transition+first=0 second=0",
        std::mem::size_of::<Rar4Decoder>()
    );
    assert!(std::mem::size_of::<Rar4Decoder>() <= 48 * 1024);
}
