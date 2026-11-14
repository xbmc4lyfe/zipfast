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

//! First-member observation only: no solid decoder or successor handoff.

use super::*;
use std::io::Write;

// Byte-identical retained RARLAB solid fixture; provenance and hashes are in the
// first-boundary report. Keeping the whole archive lets the original parser
// derive payload position/extent rather than trusting a hand-selected offset.
const SOLID: &[u8] = &[
    0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0x3b, 0xd0, 0x73, 0x08, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xe5, 0x95, 0x74, 0x80, 0x80, 0x25, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x90, 0x4c, 0x00, 0x00, 0x03, 0x98, 0x5c,
    0xa5, 0x58, 0x84, 0x18, 0x22, 0x50, 0x1d, 0x35, 0x05, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x61, 0x2e, 0x74, 0x78, 0x74,
    0x09, 0x01, 0x41, 0x8c, 0xbd, 0x98, 0x0c, 0xef, 0x70, 0xa9, 0x81, 0x35, 0x38, 0x0b, 0x82, 0xcc, 0x0e, 0x31, 0x80,
    0xfc, 0x0f, 0xe4, 0x48, 0x20, 0xef, 0x69, 0xde, 0xc6, 0xfd, 0xd6, 0xf6, 0x93, 0xd5, 0xf5, 0x19, 0xf3, 0xcf, 0x96,
    0x5a, 0x7c, 0xd7, 0xb6, 0x3e, 0xed, 0x96, 0xbe, 0xbc, 0x7b, 0xd3, 0x7c, 0x74, 0xc7, 0x7c, 0x6f, 0xfb, 0x8f, 0x0b,
    0xeb, 0x02, 0x47, 0x7d, 0x60, 0x4f, 0xef, 0xac, 0x09, 0xfd, 0xf5, 0x81, 0x3f, 0xbe, 0xb0, 0x27, 0xf7, 0xd6, 0x04,
    0xfe, 0xfa, 0xc0, 0x9f, 0xdf, 0x58, 0x13, 0xfb, 0xeb, 0x02, 0x7f, 0x7d, 0x60, 0x4f, 0xff, 0x80, 0x22, 0xa5, 0x74,
    0x90, 0x80, 0x25, 0x00, 0x25, 0x00, 0x00, 0x00, 0x0b, 0x52, 0x00, 0x00, 0x03, 0x7c, 0xab, 0x5e, 0x6b, 0x84, 0x18,
    0x22, 0x50, 0x1d, 0x35, 0x05, 0x00, 0xa4, 0x81, 0x00, 0x00, 0x62, 0x2e, 0x74, 0x78, 0x74, 0xbe, 0xb0, 0x10, 0xaf,
    0xac, 0x04, 0x2b, 0xeb, 0x01, 0x0a, 0xfa, 0xc0, 0x42, 0xbe, 0xb0, 0x10, 0xaf, 0xac, 0x04, 0x2b, 0xeb, 0x01, 0x0a,
    0xfa, 0xc0, 0x42, 0xbe, 0xb0, 0x10, 0xaf, 0xac, 0x04, 0x2d, 0xbc, 0xf5, 0xfe, 0x80, 0xc4, 0x3d, 0x7b, 0x00, 0x40,
    0x07, 0x00,
];

fn solid_first() -> (crate::rar5::FileHeader, &'static [u8], Vec<u8>) {
    assert_eq!(SOLID.len(), 230);
    assert_eq!(
        crate::crypto::sha256(SOLID),
        [
            0x63, 0x44, 0x0b, 0x78, 0x3a, 0xa7, 0x2b, 0x24, 0xf2, 0xb5, 0xc4, 0x40, 0xdc, 0x58, 0x05, 0xf8, 0xc4, 0xe9,
            0x14, 0x2a, 0xab, 0x01, 0x09, 0x4c, 0x43, 0xb7, 0xec, 0xba, 0x7b, 0x63, 0xac, 0xe2,
        ]
    );
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(SOLID).unwrap();
    let mut volume = crate::rar5::reader::Volume::open(file.path()).unwrap();
    let first = loop {
        match volume.next_block().unwrap().unwrap() {
            crate::rar5::reader::Block::File(header) => break header,
            crate::rar5::reader::Block::Main(_) => {}
            _ => panic!("unexpected block before first member"),
        }
    };
    assert_eq!(first.name, "a.txt");
    assert_eq!(first.packed_size, 92);
    assert_eq!(first.unpacked_size, 19600);
    assert_eq!(first.dictionary, 1048576);
    assert_eq!(first.crc32, Some(0x58a55c98));
    let raw = first.rar4.unwrap();
    assert_eq!((raw.flags, raw.unpack_version, raw.method), (0x8080, 29, 0x35));
    let start = usize::try_from(first.data_at).unwrap();
    let end = start.checked_add(first.packed_size as usize).unwrap();
    let packed = &SOLID[start..end];
    let expected = b"RAR4 archive compatibility.\n".repeat(700);
    assert_eq!(expected.len() as u64, first.unpacked_size);
    assert_eq!(crate::crc32::hash(&expected), first.crc32.unwrap());
    (first, packed, expected)
}

// Declaring one extra byte is solely a test-driver escape from size-first
// completion. A real end must still fail with the original DecodedSize error;
// actual output is independently bounded and checked. Nothing becomes success.
fn probe<'a>(
    packed_len: usize,
    actual: usize,
    dictionary: u64,
    pieces: impl IntoIterator<Item = &'a [u8]>,
) -> (Rar4Decoder, Vec<u8>, Rar4DecodeError) {
    let mut d = Rar4Decoder::new(dictionary, packed_len as u64, actual as u64 + 1, dictionary, Cancellation::default())
        .unwrap();
    d.trace = Some(BoundaryTrace::default());
    let mut out = Vec::new();
    let mut error = None;
    for piece in pieces {
        let result = d.feed(piece, &mut |bytes: &[u8]| {
            if out.len() + bytes.len() > actual {
                return Err(crate::error::Error::Corrupt("boundary probe extra output"));
            }
            out.extend_from_slice(bytes);
            Ok(())
        });
        if d.produced > actual as u64 {
            error = Some(Rar4DecodeError::DecodedSize { expected: actual as u64, actual: d.produced });
            break;
        }
        if let Err(failure) = result {
            error = Some(failure);
            break;
        }
    }
    let error = error.unwrap_or_else(|| d.finish(&mut collect(&mut out)).unwrap_err());
    // Inspect the bounded provisional prefix after the intentional error. This
    // private drain neither calls finish successfully nor clears poison.
    if d.produced <= actual as u64 {
        d.flush(&mut collect(&mut out)).unwrap();
    }
    assert!(d.poisoned);
    assert!(d.feed(&[], &mut collect(&mut Vec::new())).is_err());
    assert!(d.finish(&mut collect(&mut Vec::new())).is_err());
    (d, out, error)
}

fn events(d: &Rar4Decoder) -> &[Option<TraceEvent>] {
    let trace = d.trace.as_ref().unwrap();
    &trace.events[..trace.len]
}

#[test]
fn first_member_requires_a_real_observed_end_hint() {
    let (first, packed, expected) = solid_first();
    let mut ordinary = Rar4Decoder::new(
        first.dictionary,
        first.packed_size,
        first.unpacked_size,
        first.dictionary,
        Cancellation::default(),
    )
    .unwrap();
    ordinary.trace = Some(BoundaryTrace::default());
    let mut out = Vec::new();
    ordinary.feed(packed, &mut collect(&mut out)).unwrap();
    assert_eq!(ordinary.produced, 19600);
    assert_eq!(out, expected);
    assert!(matches!(ordinary.phase, Phase::Complete));
    assert!(!events(&ordinary).iter().flatten().any(|e| matches!(e.kind, TraceKind::EndHint { .. })));
    assert_eq!(ordinary.bits.bit_position(), 722);
    println!("ordinary logical-output cursor={}", ordinary.bits.bit_position());
    ordinary.finish(&mut collect(&mut out)).unwrap();

    let (d, out, error) = probe(packed.len(), expected.len(), first.dictionary, [packed]);
    assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 19601, actual: 19600 }));
    assert_eq!(d.produced, 19600);
    assert_eq!(out, expected);
    assert_eq!(crate::crc32::hash(&out), 0x58a55c98);
    let kinds: Vec<_> = events(&d).iter().flatten().map(|e| (e.kind, e.at)).collect();
    assert_eq!(
        kinds,
        [
            (TraceKind::Mode { ppm: false }, 1),
            (TraceKind::Retain { delta: false }, 2),
            (TraceKind::Tables, 275),
            (TraceKind::EndSymbol, 729),
            (TraceKind::EndBit { same_file: false }, 730),
            (TraceKind::EndHint { read_tables_next: false }, 731),
        ]
    );
    let last = events(&d).last().unwrap().unwrap();
    assert_eq!((last.produced, last.ring_position, last.initialized), (19600, 19600, 19600));
    assert_eq!((last.recent, last.last_length, last.low, last.low_repeats), ([28; 4], 161, 0, 0));
    assert_eq!(d.bits.read_bytes, 92);
    assert_eq!(d.bits.count, 5);
    assert_eq!(d.table_builds, 1);
    assert_eq!(
        crate::crypto::sha256(&out),
        [
            0xe1, 0xd4, 0xe2, 0x28, 0xf6, 0xe8, 0x71, 0xa9, 0x91, 0x65, 0x01, 0xbc, 0xb6, 0x46, 0x04, 0xfb, 0x45, 0xe3,
            0x02, 0xbd, 0x4c, 0x1f, 0xf4, 0x73, 0xf6, 0x12, 0x57, 0xa7, 0x87, 0xb3, 0x5d, 0xed,
        ]
    );
    println!(
        "first payload offset={} packed={} produced={} position={} fed={} dictionary len={} cap={} fixed={}",
        first.data_at,
        packed.len(),
        d.produced,
        d.bits.bit_position(),
        d.fed,
        d.dictionary.len(),
        d.dictionary.capacity(),
        std::mem::size_of::<Rar4Decoder>()
    );
    println!("first trace {:#?}", events(&d));
}

#[test]
fn first_member_trace_is_stable_at_every_split_without_replay() {
    let (first, packed, expected) = solid_first();
    let (whole, out, error) = probe(packed.len(), expected.len(), first.dictionary, [packed]);
    assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 19601, actual: 19600 }));
    assert_eq!(out, expected);
    for split in 0..=packed.len() {
        let (d, out, error) = probe(
            packed.len(),
            expected.len(),
            first.dictionary,
            [&[][..], &packed[..split], &[][..], &packed[split..], &[][..]],
        );
        assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 19601, actual: 19600 }));
        assert_eq!(d.trace, whole.trace, "split {split}");
        assert_eq!(out, expected, "split {split}");
        assert_eq!(d.produced, 19600);
        assert_eq!(d.table_builds, 1);
        assert_eq!(d.bits.bit_position(), 731);
    }
    let pieces = packed.chunks(1).flat_map(|byte| [byte, &[][..]]);
    let (one, out, error) = probe(packed.len(), expected.len(), first.dictionary, pieces);
    assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 19601, actual: 19600 }));
    assert_eq!(one.trace, whole.trace);
    assert_eq!(out, expected);
    assert_eq!(one.bits.bit_position(), 731);
    assert_eq!(one.table_builds, 1);
    // No table or end event replays while waiting for bits. Feed bookkeeping
    // adds bounded call overhead; token work does not restart on split input.
    assert!(one.work.operations < whole.work.operations + packed.len() as u64 * 12);
}

#[test]
fn real_bit_position_survives_partial_reads_splits_and_alignment() {
    // Values/positions are hand specified for AB CD EF 12; no decoder-derived
    // codebook or input length is used as a substitute for consumed bits.
    let bytes = [0xab, 0xcd, 0xef, 0x12];
    for split in 0..=bytes.len() {
        let mut bits = Bits::default();
        let mut input = &bytes[..split];
        let requests = [(12, 0xabc, 12), (4, 0xd, 16), (3, 7, 19)];
        let mut index = 0;
        while index < requests.len() {
            let (width, value, position) = requests[index];
            let before = bits.bit_position();
            match bits.take(width, &mut input) {
                Some(actual) => {
                    assert_eq!(actual, value);
                    assert_eq!(bits.bit_position(), position);
                    index += 1;
                }
                None => {
                    assert_eq!(bits.bit_position(), before);
                    assert!(input.is_empty());
                    let loaded = bits.read_bytes;
                    assert_eq!(bits.take(width, &mut &[][..]), None);
                    assert_eq!(bits.read_bytes, loaded);
                    assert_eq!(bits.bit_position(), before);
                    input = &bytes[split..];
                }
            }
        }
        assert_eq!(bits.take(0, &mut &[][..]), Some(0));
        assert_eq!(bits.bit_position(), 19);
        bits.align();
        assert_eq!(bits.bit_position(), 24);
        // If the prefix supplied the first three bytes, use the untouched
        // fourth byte; otherwise the second slice still owns its tail.
        if input.is_empty() && split == 3 {
            input = &bytes[3..];
        }
        assert_eq!(bits.take(8, &mut input), Some(0x12));
        assert_eq!(bits.bit_position(), 32);
        assert_eq!(bits.read_bytes, 4);
        assert_eq!(bits.take(1, &mut &[][..]), None);
        assert_eq!(bits.bit_position(), 32);
    }
    // A partially assembled original Huffman symbol has already consumed real
    // bits; empty input cannot replay those bits or finish a fifteen-bit code.
    let mut d = decoder(2, 1);
    d.tables[1].build(&[15], &mut d.work).unwrap();
    assert_eq!(d.symbol(1, &mut &[0][..]).unwrap(), None);
    assert_eq!(d.bits.bit_position(), 8);
    assert_eq!(d.symbol(1, &mut &[][..]).unwrap(), None);
    assert_eq!(d.bits.bit_position(), 8);
    assert_eq!(d.symbol(1, &mut &[0][..]).unwrap(), Some(0));
    assert_eq!(d.bits.bit_position(), 15);
}

#[test]
fn independent_boundary_00_01_and_same_file_1_have_exact_offsets() {
    // Original fixed literal-a topology: 82 header +404 direct length bits,
    // A=0, EOB=1. Its terminal bits are A/EOB/00 at 486..490.
    let retain = fixture!("literal-a").as_slice();
    let mut read_next = retain.to_vec();
    read_next[489 / 8] |= 1 << (7 - 489 % 8);
    for (packed, next) in [(retain, false), (read_next.as_slice(), true)] {
        let (whole, out, error) = probe(packed.len(), 1, 65536, [packed]);
        assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 2, actual: 1 }));
        assert_eq!(out, b"A");
        assert_eq!(whole.bits.bit_position(), 490);
        assert_eq!(whole.table_builds, 1);
        let tail: Vec<_> = events(&whole)[3..].iter().flatten().map(|e| (e.kind, e.at)).collect();
        assert_eq!(
            tail,
            [
                (TraceKind::EndSymbol, 488),
                (TraceKind::EndBit { same_file: false }, 489),
                (TraceKind::EndHint { read_tables_next: next }, 490),
            ]
        );
        for split in 0..=packed.len() {
            let (d, out, error) = probe(packed.len(), 1, 65536, [&packed[..split], &[][..], &packed[split..]]);
            assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 2, actual: 1 }));
            assert_eq!(out, b"A");
            assert_eq!(d.trace, whole.trace, "00/01 split {split}");
        }
        let (d, out, _) = probe(packed.len(), 1, 65536, packed.chunks(1).flat_map(|b| [b, &[][..]]));
        assert_eq!(out, b"A");
        assert_eq!(d.trace, whole.trace);
    }
    // Existing independent table-reuse-delta control: 1 ends at 489, aligns
    // to 496; second mode/retain at 497/498. Table deltas retain old lengths.
    let packed = fixture!("table-reuse-delta").as_slice();
    let (whole, out, error) = probe(packed.len(), 2, 65536, [packed]);
    assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 3, actual: 2 }));
    assert_eq!(out, b"AA");
    assert_eq!(whole.table_builds, 2);
    let kinds: Vec<_> = events(&whole).iter().flatten().map(|e| (e.kind, e.at)).collect();
    assert_eq!(
        kinds,
        [
            (TraceKind::Mode { ppm: false }, 1),
            (TraceKind::Retain { delta: false }, 2),
            (TraceKind::Tables, 486),
            (TraceKind::EndSymbol, 488),
            (TraceKind::EndBit { same_file: true }, 489),
            (TraceKind::Mode { ppm: false }, 497),
            (TraceKind::Retain { delta: true }, 498),
            (TraceKind::Tables, 982),
            (TraceKind::EndSymbol, 984),
            (TraceKind::EndBit { same_file: false }, 985),
            (TraceKind::EndHint { read_tables_next: false }, 986),
        ]
    );
    assert_eq!(events(&whole)[2].unwrap().old_crc32, events(&whole)[7].unwrap().old_crc32);
    for split in 0..=packed.len() {
        let (d, out, error) = probe(packed.len(), 2, 65536, [&packed[..split], &[][..], &packed[split..]]);
        assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 3, actual: 2 }));
        assert_eq!(out, b"AA");
        assert_eq!(d.trace, whole.trace, "same-file split {split}");
    }
    let (d, out, _) = probe(packed.len(), 2, 65536, packed.chunks(1).flat_map(|b| [b, &[][..]]));
    assert_eq!(out, b"AA");
    assert_eq!(d.trace, whole.trace);
}

// Fixed-vector manipulation only, using the existing independent A/EOB codes
// and 486-bit table prefix. No token decoding or general source-data encoder.
fn literal_control(literals: usize, flags: &[bool]) -> Vec<u8> {
    let source = fixture!("literal-a");
    let mut bits: Vec<_> = (0..486).map(|i| source[i / 8] & (1 << (7 - i % 8)) != 0).collect();
    bits.extend(std::iter::repeat_n(false, literals));
    bits.push(true); // EOB
    bits.extend_from_slice(flags);
    let mut bytes = vec![0u8; bits.len().div_ceil(8)];
    for (i, bit) in bits.into_iter().enumerate() {
        if bit {
            bytes[i / 8] |= 1 << (7 - i % 8);
        }
    }
    bytes
}

#[test]
fn byte_aligned_missing_end_or_hint_bits_never_invent_a_boundary() {
    // Vary only the count of literal A=0 codes so each missing event begins
    // exactly at a physical byte edge. Cuts contain no fabricated padding.
    for (literals, phase, position) in [(2, 0, 488), (1, 1, 488), (0, 2, 488)] {
        let full = literal_control(literals, &[false, false]);
        let cut = &full[..61];
        let (whole, out, error) = probe(cut.len(), literals, 65536, [cut]);
        assert!(matches!(error,Rar4DecodeError::DecodedSize {actual,..} if actual == literals as u64));
        assert_eq!(out, vec![b'A'; literals]);
        assert_eq!(whole.bits.bit_position(), position);
        assert!(match phase {
            0 => matches!(whole.phase, Phase::Token),
            1 => matches!(whole.phase, Phase::End),
            _ => matches!(whole.phase, Phase::EndHint),
        });
        assert!(!events(&whole).iter().flatten().any(|e| matches!(e.kind, TraceKind::EndHint { .. })));
        for split in 0..=cut.len() {
            let (d, out, _) = probe(cut.len(), literals, 65536, [&cut[..split], &[][..], &cut[split..]]);
            assert_eq!(out, vec![b'A'; literals]);
            assert_eq!(d.trace, whole.trace);
            assert_eq!(d.bits.bit_position(), 488);
        }
        let (d, _, _) = probe(cut.len(), literals, 65536, cut.chunks(1).flat_map(|b| [b, &[][..]]));
        assert_eq!(d.trace, whole.trace);
    }
    let (_, packed, expected) = solid_first();
    for end in 0..packed.len() {
        let (d, _, _) = probe(end, expected.len(), 1048576, [&packed[..end]]);
        assert!(!events(&d).iter().flatten().any(|e| matches!(e.kind, TraceKind::EndHint { .. })), "prefix {end}");
        assert!(d.bits.bit_position() <= end as u64 * 8);
    }
}

#[test]
fn probe_rejects_extra_literal_or_match_before_any_end_hint() {
    let packed = fixture!("literal-a").as_slice();
    let (d, out, error) = probe(packed.len(), 0, 65536, [packed]);
    assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 0, actual: 1 }));
    assert!(out.is_empty());
    assert!(!events(&d).iter().flatten().any(|e| matches!(e.kind, TraceKind::EndHint { .. })));
    let packed = fixture!("new-match-repeat-last").as_slice();
    let (d, out, error) = probe(packed.len(), 1, 65536, [packed]);
    assert!(matches!(error, Rar4DecodeError::DecodedSize { expected: 2, actual: 4 }));
    assert_eq!(d.produced, 1);
    assert_eq!(out, b"A");
    assert!(!events(&d).iter().flatten().any(|e| matches!(e.kind, TraceKind::EndHint { .. })));
}

#[test]
fn enabled_observation_keeps_core_dynamic_storage_to_one_dictionary() {
    let (first, packed, expected) = solid_first();
    let cancel = Cancellation::default();
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|f| f.set(true));
    let created =
        Rar4Decoder::new(first.dictionary, first.packed_size, first.unpacked_size + 1, first.dictionary, cancel);
    TRACK_ALLOC.with(|f| f.set(false));
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 1);
    let mut d = created.unwrap();
    d.trace = Some(BoundaryTrace::default());
    let mut bytes = 0;
    let mut sink = |data: &[u8]| {
        bytes += data.len();
        Ok(())
    };
    ALLOC_REQUESTS.with(|c| c.set(0));
    TRACK_ALLOC.with(|f| f.set(true));
    let failure = d.feed(packed, &mut sink);
    let drain = d.flush(&mut sink);
    TRACK_ALLOC.with(|f| f.set(false));
    assert!(matches!(failure, Err(Rar4DecodeError::DecodedSize { expected: 19601, actual: 19600 })));
    drain.unwrap();
    assert_eq!(bytes, expected.len());
    assert_eq!(ALLOC_REQUESTS.with(|c| c.get()), 0);
    assert_eq!((d.dictionary.len(), d.dictionary.capacity()), (1048576, 1048576));
    assert!(std::mem::size_of::<Rar4Decoder>() <= 48 * 1024);
}

#[test]
fn probe_preserves_typed_ppm_and_vm_failure_observations() {
    let packed = fixture!("ppm-marker").as_slice();
    let (d, out, error) = probe(packed.len(), 2, 65536, [packed]);
    assert!(matches!(error, Rar4DecodeError::Unsupported(Rar4UnsupportedMode::Ppm)));
    assert!(out.is_empty());
    assert_eq!(events(&d).len(), 1);
    assert_eq!((events(&d)[0].unwrap().kind, events(&d)[0].unwrap().at), (TraceKind::Mode { ppm: true }, 1));
    let packed = fixture!("vm-marker-after-prefix").as_slice();
    let (d, out, error) = probe(packed.len(), 2, 65536, [packed]);
    assert!(matches!(error, Rar4DecodeError::Unsupported(Rar4UnsupportedMode::VmFilter)));
    assert_eq!(out, b"A");
    assert!(events(&d).iter().flatten().any(|e| e.kind == TraceKind::VmFilter));
    assert!(!events(&d).iter().flatten().any(|e| matches!(e.kind, TraceKind::EndHint { .. })));
}
