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

use super::records::{End, Member, Width};
use super::*;

fn n16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn n32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn n64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[test]
fn stored_size_boundaries_saturate_both_size_fields() {
    for (size, wide) in [(4_294_967_294, false), (4_294_967_295, true), (4_294_967_296, true)] {
        let member = Member {
            width: Width::new(Method::Stored, InputLength::Exact(size), 0, false),
            method: Method::Stored,
            flags: 0,
            dos: DosDateTime::default(),
            name_len: 1,
            comment_len: 0,
            external: 0,
            mtime: None,
            local_at: 0,
        };
        let central = member.central(0x12345678, size, size).unwrap();
        let header = central.as_bytes();
        let extra = member.central_extra(size, size).as_bytes().to_vec();
        let local = member.local();
        assert_eq!(n16(local.as_bytes(), 4), if wide { 45 } else { 20 });
        assert_eq!(n32(header, 16), 0x12345678);
        for offset in [20, 24] {
            assert_eq!(n32(header, offset), if wide { 0xffffffff } else { 0xfffffffe });
        }
        if wide {
            assert_eq!(n32(local.as_bytes(), 18), 0xffffffff);
            assert_eq!(n32(local.as_bytes(), 22), 0xffffffff);
            assert_eq!(&extra[..4], b"\x01\x00\x10\x00");
            assert_eq!(n64(&extra, 4), size);
            assert_eq!(n64(&extra, 12), size);
        } else {
            assert!(extra.is_empty());
        }
    }
}

#[test]
fn offset_only_widening_keeps_local_sizes_narrow() {
    for (offset, wide) in [(4_294_967_294, false), (4_294_967_295, true), (4_294_967_296, true)] {
        let member = Member {
            width: Width::new(Method::Stored, InputLength::Exact(3), offset, false),
            method: Method::Stored,
            flags: 0,
            dos: DosDateTime::default(),
            name_len: 1,
            comment_len: 0,
            external: 0,
            mtime: None,
            local_at: offset,
        };
        let central = member.central(0, 3, 3).unwrap();
        assert_eq!(n32(central.as_bytes(), 20), 3);
        assert_eq!(n32(central.as_bytes(), 24), 3);
        assert_eq!(n32(central.as_bytes(), 42), if wide { 0xffffffff } else { 0xfffffffe });
        let local = member.local();
        assert_eq!(n16(local.as_bytes(), 4), if wide { 45 } else { 20 });
        assert_eq!(n16(local.as_bytes(), 28), 0);
        let extra = member.central_extra(3, 3);
        if wide {
            assert_eq!(&extra.as_bytes()[..4], b"\x01\x00\x08\x00");
            assert_eq!(n64(extra.as_bytes(), 4), offset);
        } else {
            assert!(extra.as_bytes().is_empty());
        }
    }
}

#[test]
fn zip64_tail_thresholds_use_all_classic_sentinels() {
    for (count, size, at, wide) in [
        (65_534, 4_294_967_294, 4_294_967_294, false),
        (65_535, 12, 50, true),
        (65_536, 12, 50, true),
        (3, 4_294_967_295, 50, true),
        (3, 4_294_967_296, 50, true),
        (3, 12, 4_294_967_295, true),
        (3, 12, 4_294_967_296, true),
    ] {
        let record = End::new(count, size, at, false, 2).record().unwrap();
        let bytes = record.as_bytes();
        let classic = if wide {
            assert_eq!(bytes.len(), 98);
            assert_eq!(&bytes[..4], b"PK\x06\x06");
            assert_eq!(n64(bytes, 4), 44);
            assert_eq!(&bytes[16..24], &[0; 8]);
            assert_eq!(n64(bytes, 24), count);
            assert_eq!(n64(bytes, 32), count);
            assert_eq!(n64(bytes, 40), size);
            assert_eq!(n64(bytes, 48), at);
            assert_eq!(&bytes[56..64], b"PK\x06\x07\0\0\0\0");
            assert_eq!(n64(bytes, 64), at + size);
            assert_eq!(n32(bytes, 72), 1);
            &bytes[76..]
        } else {
            bytes
        };
        assert_eq!(&classic[..8], b"PK\x05\x06\0\0\0\0");
        assert_eq!(n16(classic, 8), if wide { 0xffff } else { 65_534 });
        assert_eq!(n16(classic, 10), n16(classic, 8));
        assert_eq!(n32(classic, 12), if wide { 0xffffffff } else { 0xfffffffe });
        assert_eq!(n32(classic, 16), n32(classic, 12));
        assert_eq!(n16(classic, 20), 2);
    }
    assert!(matches!(End::new(1, 2, u64::MAX, false, 0).record(), Err(WriteError::Overflow)));
}

#[test]
fn stalled_encoder_returns_without_emitting_payload() {
    let sink = io::Cursor::new(Vec::new());
    let mut output = Output::new(sink, WriteLimits::default(), None);
    let mut encoder = Compress::new(Compression::new(6), false);
    let result = output.deflate(&mut encoder, b"", &mut [0; BUFFER], FlushCompress::None);
    assert!(matches!(result, Err(WriteError::EncoderStalled)));
    assert!(output.sink.into_inner().is_empty());
}

#[test]
fn encoder_failure_does_not_emit_more_bytes() {
    let sink = io::Cursor::new(Vec::new());
    let mut output = Output::new(sink, WriteLimits::default(), None);
    let mut encoder = Compress::new(Compression::new(6), false);
    let mut buffer = [0; BUFFER];
    // Feed a nonempty slice to an already finished native stream. zlib-rs
    // reports a stream error, while miniz reports a non-progress status.
    output.deflate(&mut encoder, b"", &mut buffer, FlushCompress::Finish).unwrap();
    let extent = output.work.usage.archive_extent;
    let result = output.deflate(&mut encoder, b"x", &mut buffer, FlushCompress::None);
    assert!(matches!(result, Err(WriteError::Compression(_) | WriteError::EncoderStalled)));
    assert_eq!(output.work.usage.archive_extent, extent);
}

#[cfg(target_pointer_width = "64")]
#[test]
#[ignore = "requests an intentionally impossible allocation from the system allocator"]
fn metadata_allocation_failure_leaves_writer_usable() {
    let limits = WriteLimits {
        central_bytes: isize::MAX as u64,
        metadata_capacity: isize::MAX as u64,
        ..WriteLimits::default()
    };
    let options = WriterOptions { limits, ..WriterOptions::default() };
    let mut writer = ZipWriter::new(io::Cursor::new(Vec::new()), options).unwrap();
    assert!(matches!(writer.reserve_central(isize::MAX as u64), Err(WriteError::Allocation(_))));
    assert_eq!(writer.usage().metadata_capacity, 0);
    assert_eq!(writer.finish().unwrap().sink.get_ref().len(), 22);
}
