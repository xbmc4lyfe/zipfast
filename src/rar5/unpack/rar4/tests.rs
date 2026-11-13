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

use super::*;

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/", $name, ".packed"))
    };
}
const VECTORS: &[(&[u8], &[u8])] = &[
    (fixture!("literal-a"), b"A"),
    (fixture!("initial-delta-zero-baseline"), b"A"),
    (fixture!("table-reuse-delta"), b"AA"),
    (fixture!("code-length-nibble-zero-run"), b"A"),
    (fixture!("new-match-repeat-last"), b"AAAAAAA"),
    (fixture!("recent-distance-repeat"), b"AAAAAA"),
    (fixture!("short-distance-match"), b"AAA"),
    (fixture!("zero-length-runs"), b"A"),
    (fixture!("previous-length-runs"), b"AP"),
];
fn collect(out: &mut Vec<u8>) -> impl Sink + '_ {
    move |bytes: &[u8]| {
        out.extend_from_slice(bytes);
        Ok(())
    }
}
fn decoder(packed: usize, unpacked: usize) -> Rar4Decoder {
    Rar4Decoder::new(65536, packed as u64, unpacked as u64, 65536, Cancellation::default()).unwrap()
}

#[test]
fn every_split_one_byte_and_empty_feeds() {
    for &(packed, expected) in VECTORS {
        for split in 0..=packed.len() {
            let mut d = decoder(packed.len(), expected.len());
            let mut out = Vec::new();
            d.feed(&[], &mut collect(&mut out)).unwrap();
            d.feed(&packed[..split], &mut collect(&mut out)).unwrap();
            d.feed(&[], &mut collect(&mut out)).unwrap();
            d.feed(&packed[split..], &mut collect(&mut out)).unwrap();
            d.finish(&mut collect(&mut out)).unwrap();
            assert_eq!(out, expected, "split {split}");
        }
        let mut d = decoder(packed.len(), expected.len());
        let mut out = Vec::new();
        for byte in packed {
            d.feed(&[*byte], &mut collect(&mut out)).unwrap();
            d.feed(&[], &mut collect(&mut out)).unwrap();
        }
        d.finish(&mut collect(&mut out)).unwrap();
        assert_eq!(out, expected);
    }
}

#[test]
fn real_bits_and_expected_size_are_required() {
    let packed = fixture!("literal-a");
    for end in 0..packed.len() - 1 {
        let mut d = decoder(end, 1);
        let mut out = Vec::new();
        assert!(d.feed(&packed[..end], &mut collect(&mut out)).is_ok());
        assert!(d.finish(&mut collect(&mut out)).is_err(), "prefix {end}");
        assert!(out.is_empty());
    }
    let mut d = decoder(packed.len(), 2);
    let mut out = Vec::new();
    let result = d.feed(packed, &mut collect(&mut out));
    assert!(matches!(result, Err(Rar4DecodeError::DecodedSize { expected: 2, actual: 1 })));
    assert!(d.finish(&mut collect(&mut out)).is_err());
}

#[test]
fn typed_modes_poison_decoder_and_preserve_prefix() {
    for (packed, mode) in [
        (fixture!("ppm-marker").as_slice(), Rar4UnsupportedMode::Ppm),
        (fixture!("vm-marker-after-prefix").as_slice(), Rar4UnsupportedMode::VmFilter),
    ] {
        let mut d = decoder(packed.len(), 2);
        let mut out = Vec::new();
        assert!(
            matches!(d.feed(packed, &mut collect(&mut out)), Err(Rar4DecodeError::Unsupported(actual)) if actual == mode)
        );
        assert!(d.feed(&[], &mut collect(&mut out)).is_err());
        assert!(d.finish(&mut collect(&mut out)).is_err());
        // A core may retain a bounded provisional chunk until finish. No success or invented suffix is allowed.
        assert!(out.is_empty() || out == b"A");
    }
    let packed = fixture!("empty-initial-retained-table");
    assert!(matches!(
        decoder(packed.len(), 1).feed(packed, &mut collect(&mut Vec::new())),
        Err(Rar4DecodeError::Malformed(_))
    ));
}

#[test]
fn physical_counts_empty_policy_and_finalized_state() {
    let packed = fixture!("literal-a");
    let mut out = Vec::new();
    let mut d = decoder(packed.len() + 1, 1);
    d.feed(packed, &mut collect(&mut out)).unwrap();
    assert!(matches!(d.finish(&mut collect(&mut out)), Err(Rar4DecodeError::PackedSize { .. })));
    let mut d = decoder(packed.len() - 1, 1);
    assert!(matches!(d.feed(packed, &mut collect(&mut Vec::new())), Err(Rar4DecodeError::PackedSize { .. })));
    let mut d = decoder(1, 0);
    assert_eq!(d.feed(&[128], &mut collect(&mut Vec::new())).unwrap(), Rar4FeedState::Complete);
    d.finish(&mut collect(&mut Vec::new())).unwrap();
    assert!(d.finish(&mut collect(&mut Vec::new())).is_err());
    assert!(d.feed(&[], &mut collect(&mut Vec::new())).is_err());
}

#[test]
fn window_and_cancellation_are_typed() {
    assert!(matches!(
        Rar4Decoder::new(123, 0, 0, 65536, Cancellation::default()),
        Err(Rar4DecodeError::InvalidDictionary { requested: 123 })
    ));
    assert!(matches!(
        Rar4Decoder::new(65536, 0, 0, 65535, Cancellation::default()),
        Err(Rar4DecodeError::WindowLimit { .. })
    ));
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(matches!(Rar4Decoder::new(65536, 0, 0, 65536, cancel), Err(Rar4DecodeError::Canceled)));
    let cancel = Cancellation::default();
    let mut d = Rar4Decoder::new(65536, 0, 0, 65536, cancel.clone()).unwrap();
    cancel.cancel();
    assert!(matches!(d.feed(&[], &mut collect(&mut Vec::new())), Err(Rar4DecodeError::Canceled)));
}

thread_local! {
    static INIT_CANCEL: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static TRACK_ALLOC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static ALLOC_REQUESTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DENY_DICTIONARY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
pub(super) fn take_init_cancel() -> Option<u64> {
    INIT_CANCEL.with(|value| value.take())
}

struct FaultAllocator;
// SAFETY: All admitted requests are forwarded unchanged to System. The
// constant-initialized TLS flag performs no allocation and fails closed
// during thread teardown. Only this thread's 64 KiB test request is denied.
unsafe impl std::alloc::GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if TRACK_ALLOC.try_with(|flag| flag.get()).unwrap_or(false) {
            let _ = ALLOC_REQUESTS.try_with(|count| count.set(count.get() + 1));
        }
        if layout.size() == 65536
            && layout.align() == 1
            && DENY_DICTIONARY.try_with(|flag| flag.replace(false)).unwrap_or(false)
        {
            return std::ptr::null_mut();
        }
        // SAFETY: The allocator caller provides the original valid layout.
        unsafe { std::alloc::System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: Admitted allocations came from System with this layout.
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[test]
fn dictionary_allocation_and_initialization_refusal() {
    DENY_DICTIONARY.with(|flag| flag.set(true));
    let result = Rar4Decoder::new(65536, 0, 0, 65536, Cancellation::default());
    DENY_DICTIONARY.with(|flag| flag.set(false));
    assert!(matches!(result, Err(Rar4DecodeError::Allocation { requested: 65536 })));
    INIT_CANCEL.with(|value| value.set(Some(65536)));
    assert!(matches!(
        Rar4Decoder::new(4194304, 0, 0, 4194304, Cancellation::default()),
        Err(Rar4DecodeError::Canceled)
    ));
    let d = decoder(0, 0);
    assert_eq!(d.dictionary.capacity(), 65536);
}

#[test]
fn official_lz_control_wraps_dictionary_under_chunk_splits() {
    let mut expected = b"RAR4 bounded LZ control.\n".repeat(8000);
    expected.extend((0u8..=255).cycle().take(256 * 400));
    assert_eq!(expected.len(), 302400);
    for packed in [
        fixture!("official-lz-m1").as_slice(),
        fixture!("official-lz-m2").as_slice(),
        fixture!("official-lz-m3").as_slice(),
        fixture!("official-lz-m4").as_slice(),
        fixture!("official-lz-m5").as_slice(),
    ] {
        for chunk in [1, 2, 3, 7, 64, 65536] {
            let mut d = decoder(packed.len(), expected.len());
            let mut out = Vec::new();
            for piece in packed.chunks(chunk) {
                d.feed(piece, &mut collect(&mut out)).unwrap();
            }
            d.finish(&mut collect(&mut out)).unwrap();
            assert_eq!(out, expected, "chunk {chunk}");
        }
    }
}

#[test]
fn no_replay_table_work_and_cancellation_between_feeds() {
    let packed = fixture!("table-reuse-delta");
    let mut counts = Vec::new();
    for chunk in [1, packed.len()] {
        let mut d = decoder(packed.len(), 2);
        for piece in packed.chunks(chunk) {
            d.feed(piece, &mut collect(&mut Vec::new())).unwrap();
        }
        d.finish(&mut collect(&mut Vec::new())).unwrap();
        assert_eq!(d.table_builds, 2);
        counts.push(d.work.operations);
    }
    // A small constant overhead per input call, never repeated table builds.
    assert!(counts[0] < counts[1] + packed.len() as u64 * 5);
    let mut d = decoder(packed.len(), 2);
    d.work.cancel_at = Some(d.work.operations + 64);
    assert!(matches!(d.feed(packed, &mut collect(&mut Vec::new())), Err(Rar4DecodeError::Canceled)));
    assert_eq!(d.produced, 0);
    assert!(d.poisoned);
    let mut d = decoder(packed.len(), 2);
    d.feed(&packed[..1], &mut collect(&mut Vec::new())).unwrap();
    let previous = d.work.operations;
    d.work.cancel_at = Some(previous + 1);
    assert!(matches!(d.feed(&packed[1..], &mut collect(&mut Vec::new())), Err(Rar4DecodeError::Canceled)));
    assert!(d.work.operations > previous);
}

#[test]
fn sink_failure_is_typed_and_permanently_poisoned() {
    let packed = fixture!("literal-a");
    let mut d = decoder(packed.len(), 1);
    let mut sink = |_: &[u8]| Err(crate::error::Error::Corrupt("injected sink refusal"));
    assert!(matches!(
        d.feed(packed, &mut sink),
        Err(Rar4DecodeError::Sink(crate::error::Error::Corrupt("injected sink refusal")))
    ));
    assert!(d.feed(&[], &mut collect(&mut Vec::new())).is_err());
    assert!(d.finish(&mut collect(&mut Vec::new())).is_err());
}

#[test]
fn malformed_and_resource_fields_remain_available_without_strings() {
    let packed = fixture!("empty-initial-retained-table");
    assert!(matches!(
        decoder(packed.len(), 1).feed(packed, &mut collect(&mut Vec::new())),
        Err(Rar4DecodeError::Malformed("empty literal table"))
    ));
    assert!(matches!(
        Rar4Decoder::new(65536, 0, 0, 65535, Cancellation::default()),
        Err(Rar4DecodeError::WindowLimit { requested: 65536, allowed: 65535 })
    ));
    let mut d = decoder(1, 0);
    assert!(matches!(
        d.finish(&mut collect(&mut Vec::new())),
        Err(Rar4DecodeError::PackedSize { expected: 1, actual: 0 })
    ));
    let mut d = decoder(0, 0);
    d.work.operations = u64::MAX;
    assert!(matches!(d.feed(&[], &mut collect(&mut Vec::new())), Err(Rar4DecodeError::CounterOverflow)));
}

#[test]
fn high_distance_low_nibbles_and_length_thresholds() {
    for (packed, distance, dictionary) in [
        (fixture!("dd10-low").as_slice(), 33usize, 65536u64),
        (fixture!("threshold8191").as_slice(), 8191, 65536),
        (fixture!("threshold8192").as_slice(), 8192, 65536),
        (fixture!("threshold262143").as_slice(), 262143, 4194304),
        (fixture!("threshold262144").as_slice(), 262144, 4194304),
        (fixture!("dd59-reach4m").as_slice(), 4194304, 4194304),
    ] {
        let mut expected = vec![b'A'; distance];
        expected[0] = b'B';
        expected.push(b'B');
        expected.extend(std::iter::repeat_n(b'A', 2 + usize::from(distance >= 8192) + usize::from(distance >= 262144)));
        for chunk in [1, packed.len()] {
            let mut d = Rar4Decoder::new(
                dictionary,
                packed.len() as u64,
                expected.len() as u64,
                dictionary,
                Cancellation::default(),
            )
            .unwrap();
            let mut out = Vec::new();
            for piece in packed.chunks(chunk) {
                d.feed(piece, &mut collect(&mut out)).unwrap();
            }
            d.finish(&mut collect(&mut out)).unwrap();
            assert_eq!(out, expected, "distance {distance} chunk {chunk}");
        }
    }
}

#[test]
fn dictionary_distance_and_length_intervals_are_contiguous() {
    let mut end = 0u64;
    for index in 0..60 {
        let (base, bits) = Rar4Decoder::distance(index);
        assert_eq!(base, end);
        end += 1 << bits;
    }
    assert_eq!(end, 4194304);
    let mut end = 0;
    for index in 0..28 {
        let (base, bits) = Rar4Decoder::length(index);
        assert_eq!(base, end);
        end += 1 << bits;
    }
    assert_eq!(end, 256);
}

#[test]
fn low_distance_repeat_reset_and_all_recent_slots() {
    let packed = fixture!("low-repeat16");
    let expected = b"BAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAABAAAAAAAA";
    for split in 0..=packed.len() {
        let mut d = decoder(packed.len(), expected.len());
        let mut out = Vec::new();
        d.feed(&packed[..split], &mut collect(&mut out)).unwrap();
        d.feed(&packed[split..], &mut collect(&mut out)).unwrap();
        d.finish(&mut collect(&mut out)).unwrap();
        assert_eq!(out, expected, "low-repeat16 split {split}");
    }
    let packed = fixture!("low-reset-table");
    let expected = b"BAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAABAA";
    for split in 0..=packed.len() {
        let mut d = decoder(packed.len(), expected.len());
        let mut out = Vec::new();
        d.feed(&packed[..split], &mut collect(&mut out)).unwrap();
        d.feed(&packed[split..], &mut collect(&mut out)).unwrap();
        d.finish(&mut collect(&mut out)).unwrap();
        assert_eq!(out, expected, "low-reset-table split {split}");
    }
    let packed = fixture!("all-recent-slots");
    let expected = b"BAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for split in 0..=packed.len() {
        let mut d = decoder(packed.len(), expected.len());
        let mut out = Vec::new();
        d.feed(&packed[..split], &mut collect(&mut out)).unwrap();
        d.feed(&packed[split..], &mut collect(&mut out)).unwrap();
        d.finish(&mut collect(&mut out)).unwrap();
        assert_eq!(out, expected, "all-recent-slots split {split}");
    }
}

#[test]
fn pending_raw_fields_and_fifteen_bit_symbols_use_only_real_bits() {
    let mut bits = Bits::default();
    let mut first: &[u8] = &[0xab];
    assert_eq!(bits.take(12, &mut first), None);
    assert_eq!(bits.count, 8);
    let mut empty: &[u8] = &[];
    assert_eq!(bits.take(12, &mut empty), None);
    assert_eq!(bits.count, 8);
    let mut tail: &[u8] = &[0xcd];
    assert_eq!(bits.take(12, &mut tail), Some(0xabc));
    assert_eq!(bits.take(4, &mut tail), Some(0xd));
    assert_eq!(bits.take(1, &mut tail), None);
    let mut d = decoder(2, 1);
    d.tables[1].build(&[15], &mut d.work).unwrap();
    let mut first: &[u8] = &[0];
    assert_eq!(d.symbol(1, &mut first).unwrap(), None);
    assert_eq!(d.depth, 8);
    let mut empty: &[u8] = &[];
    assert_eq!(d.symbol(1, &mut empty).unwrap(), None);
    assert_eq!(d.depth, 8);
    let mut tail: &[u8] = &[0];
    assert_eq!(d.symbol(1, &mut tail).unwrap(), Some(0));
    assert_eq!(d.bits.count, 1);
    assert_eq!(d.depth, 0);
}

#[test]
fn malformed_tables_distances_and_size_overruns_are_bounded() {
    let mut d = decoder(0, 0);
    assert!(matches!(
        d.tables[0].build(&[1, 1, 1], &mut d.work),
        Err(Rar4DecodeError::Malformed("oversubscribed Huffman table"))
    ));
    assert!(matches!(d.tables[0].build(&[16], &mut d.work), Err(Rar4DecodeError::Malformed("code length"))));
    d.tables[1].build(&[1], &mut d.work).unwrap();
    let mut invalid: &[u8] = &[255, 255];
    assert!(matches!(d.symbol(1, &mut invalid), Err(Rar4DecodeError::Malformed("undefined Huffman code"))));
    let mut d = decoder(0, 10);
    assert!(matches!(
        d.start_copy(3, 1),
        Err(Rar4DecodeError::Malformed("match distance outside initialized history"))
    ));
    let packed = fixture!("new-match-repeat-last");
    let mut d = decoder(packed.len(), 3);
    let mut out = Vec::new();
    assert!(matches!(
        d.feed(packed, &mut collect(&mut out)),
        Err(Rar4DecodeError::DecodedSize { expected: 3, actual: 4 })
    ));
    assert_eq!(d.produced, 1);
    assert!(out.is_empty());
    let bytes = [0x3f, 0xff, 0xc0];
    assert!(matches!(
        decoder(bytes.len(), 1).feed(&bytes, &mut collect(&mut Vec::new())),
        Err(Rar4DecodeError::Malformed("BC run exceeds table"))
    ));
}

#[test]
fn cancellation_interrupts_table_build_copy_and_physical_tail() {
    let mut d = decoder(0, 0);
    d.work.cancel_at = Some(d.work.operations + 2);
    assert!(matches!(d.tables[1].build(&[1; 299], &mut d.work), Err(Rar4DecodeError::Canceled)));
    let packed = fixture!("official-lz-m3");
    let mut d = decoder(packed.len(), 302400);
    // Force cancellation after multiple output chunks during real overlapping copies.
    d.work.cancel_at = Some(d.work.operations + 100000);
    assert!(matches!(d.feed(packed, &mut collect(&mut Vec::new())), Err(Rar4DecodeError::Canceled)));
    assert!(d.produced > 0 && d.produced < 302400);
    let mut d = decoder(2, 0);
    d.feed(&[0], &mut collect(&mut Vec::new())).unwrap();
    d.work.cancel.cancel();
    assert!(matches!(d.feed(&[0], &mut collect(&mut Vec::new())), Err(Rar4DecodeError::Canceled)));
}

#[test]
fn fixed_core_storage_and_work_are_bounded() {
    let size = std::mem::size_of::<Rar4Decoder>();
    println!("RAR4 fixed decoder bytes {size}");
    assert!(size <= 48 * 1024);
    let packed = fixture!("table-reuse-delta");
    let mut d = decoder(packed.len(), 2);
    for byte in packed {
        d.feed(&[*byte], &mut collect(&mut Vec::new())).unwrap();
    }
    assert_eq!(d.table_builds, 2);
    assert!(d.work.operations < 65536 + size as u64 + 10000);
    assert_eq!(d.dictionary.len(), 65536);
    assert_eq!(d.dictionary.capacity(), 65536);
}

#[test]
fn negative_outcomes_are_stable_at_every_split() {
    for (packed, class) in [
        (fixture!("ppm-marker").as_slice(), 0),
        (fixture!("vm-marker-after-prefix").as_slice(), 1),
        (fixture!("empty-initial-retained-table").as_slice(), 2),
    ] {
        for split in 0..=packed.len() {
            let mut d = decoder(packed.len(), 2);
            let mut out = Vec::new();
            let first = d.feed(&packed[..split], &mut collect(&mut out));
            let error = match first {
                Err(error) => error,
                Ok(_) => d.feed(&packed[split..], &mut collect(&mut out)).err().unwrap(),
            };
            assert!(matches!(
                (class, error),
                (0, Rar4DecodeError::Unsupported(Rar4UnsupportedMode::Ppm))
                    | (1, Rar4DecodeError::Unsupported(Rar4UnsupportedMode::VmFilter))
                    | (2, Rar4DecodeError::Malformed(_))
            ));
            assert!(d.poisoned);
            assert!(d.finish(&mut collect(&mut out)).is_err());
            assert!(out.is_empty() || out == b"A");
        }
    }
}

#[test]
fn dictionary_is_the_only_dynamic_core_allocation() {
    let cancel = Cancellation::default();
    ALLOC_REQUESTS.with(|count| count.set(0));
    TRACK_ALLOC.with(|flag| flag.set(true));
    let rejected = Rar4Decoder::new(65536, 0, 0, 65535, cancel);
    TRACK_ALLOC.with(|flag| flag.set(false));
    assert!(matches!(rejected, Err(Rar4DecodeError::WindowLimit { .. })));
    assert_eq!(ALLOC_REQUESTS.with(|count| count.get()), 0);
    let packed = fixture!("table-reuse-delta");
    let cancel = Cancellation::default();
    ALLOC_REQUESTS.with(|count| count.set(0));
    TRACK_ALLOC.with(|flag| flag.set(true));
    let created = Rar4Decoder::new(65536, packed.len() as u64, 2, 65536, cancel);
    TRACK_ALLOC.with(|flag| flag.set(false));
    assert_eq!(ALLOC_REQUESTS.with(|count| count.get()), 1);
    let mut d = created.unwrap();
    let mut count = 0;
    let mut sink = |bytes: &[u8]| {
        count += bytes.len();
        Ok(())
    };
    ALLOC_REQUESTS.with(|count| count.set(0));
    TRACK_ALLOC.with(|flag| flag.set(true));
    let feed = d.feed(packed, &mut sink);
    let finish = d.finish(&mut sink);
    TRACK_ALLOC.with(|flag| flag.set(false));
    feed.unwrap();
    finish.unwrap();
    assert_eq!(count, 2);
    assert_eq!(ALLOC_REQUESTS.with(|count| count.get()), 0);
}

#[test]
fn cancellation_poll_detects_crossed_work_interval() {
    let mut d = decoder(0, 0);
    d.work.operations = 255;
    d.work.cancel_at = Some(256);
    assert!(matches!(d.work.tick(2), Err(Rar4DecodeError::Canceled)));
}

#[test]
fn logical_completion_accepts_real_terminal_prefix_and_physical_slack() {
    let packed = fixture!("literal-a");
    let mut shortened = decoder(packed.len() - 1, 1);
    let mut out = Vec::new();
    assert_eq!(shortened.feed(&packed[..packed.len() - 1], &mut collect(&mut out)).unwrap(), Rar4FeedState::Complete);
    shortened.finish(&mut collect(&mut out)).unwrap();
    assert_eq!(out, b"A");
    for tail in [0, 255] {
        let mut d = decoder(packed.len() + 1, 1);
        let mut out = Vec::new();
        assert_eq!(d.feed(packed, &mut collect(&mut out)).unwrap(), Rar4FeedState::Complete);
        assert_eq!(d.feed(&[tail], &mut collect(&mut out)).unwrap(), Rar4FeedState::Complete);
        d.finish(&mut collect(&mut out)).unwrap();
        assert_eq!(out, b"A");
    }
}
