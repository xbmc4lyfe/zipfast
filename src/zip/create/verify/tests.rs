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

use std::io::{Seek, SeekFrom, Write};

use super::super::tests::{metadata, test_dir};
use super::super::{Cell, CreatePlan, CreateUsage};
use super::*;
use crate::zip::write::{DeflateLevel, WriteUsage};

const CRC: u32 = 0x3524_41c2;

fn words(bytes: &mut Vec<u8>, words: &[u16]) {
    for word in words {
        bytes.extend(word.to_le_bytes());
    }
}

fn dwords(bytes: &mut Vec<u8>, words: &[u32]) {
    for word in words {
        bytes.extend(word.to_le_bytes());
    }
}

fn qwords(bytes: &mut Vec<u8>, words: &[u64]) {
    for word in words {
        bytes.extend(word.to_le_bytes());
    }
}

fn fixture(deflate: bool, packed: &[u8]) -> (Vec<u8>, EntryWritten, WriteSummary) {
    let version = if deflate { 45 } else { 20 };
    let method = if deflate { 8 } else { 0 };
    let sizes = if deflate { [u32::MAX; 2] } else { [packed.len() as u32, 3] };
    let extra_len = if deflate { 20 } else { 0 };
    let mut bytes = Vec::new();
    dwords(&mut bytes, &[0x0403_4b50]);
    words(&mut bytes, &[version, 0x800, method, 0, 0x21]);
    dwords(&mut bytes, &[CRC, sizes[0], sizes[1]]);
    words(&mut bytes, &[1, extra_len]);
    bytes.push(b'a');
    if deflate {
        words(&mut bytes, &[1, 16]);
        qwords(&mut bytes, &[3, packed.len() as u64]);
    }
    bytes.extend_from_slice(packed);
    let central_offset = bytes.len() as u64;
    dwords(&mut bytes, &[0x0201_4b50]);
    words(&mut bytes, &[0x300 | version, version, 0x800, method, 0, 0x21]);
    dwords(&mut bytes, &[CRC, sizes[0], sizes[1]]);
    words(&mut bytes, &[1, extra_len, 0, 0, 0]);
    dwords(&mut bytes, &[0o100640 << 16, 0]);
    bytes.push(b'a');
    if deflate {
        words(&mut bytes, &[1, 16]);
        qwords(&mut bytes, &[3, packed.len() as u64]);
    }
    let central_bytes = bytes.len() as u64 - central_offset;
    let zip64_at = bytes.len() as u64;
    if deflate {
        dwords(&mut bytes, &[0x0606_4b50]);
        qwords(&mut bytes, &[44]);
        words(&mut bytes, &[0x32d, 45]);
        dwords(&mut bytes, &[0, 0]);
        qwords(&mut bytes, &[1, 1, central_bytes, central_offset]);
        dwords(&mut bytes, &[0x0706_4b50, 0]);
        qwords(&mut bytes, &[zip64_at]);
        dwords(&mut bytes, &[1]);
    }
    dwords(&mut bytes, &[0x0605_4b50]);
    words(&mut bytes, &[0, 0, if deflate { u16::MAX } else { 1 }, if deflate { u16::MAX } else { 1 }]);
    dwords(&mut bytes, &if deflate { [u32::MAX; 2] } else { [central_bytes as u32, central_offset as u32] });
    words(&mut bytes, &[0]);

    let receipt = EntryWritten {
        ordinal: 0,
        method: if deflate { Method::Deflate(DeflateLevel::new(6).unwrap()) } else { Method::Stored },
        crc32: CRC,
        decoded_size: 3,
        packed_size: packed.len() as u64,
        local_offset: 0,
    };
    let summary = WriteSummary {
        usage: WriteUsage { entries: 1, archive_extent: bytes.len() as u64, central_bytes, ..WriteUsage::default() },
        central_offset,
        zip64: deflate,
    };
    (bytes, receipt, summary)
}

fn verify_fixture(file: &mut File, receipt: EntryWritten, summary: WriteSummary) -> Result<VerifiedCreation> {
    let temp = test_dir();
    let path = temp.path().join("source");
    std::fs::write(&path, b"abc").unwrap();
    let mut plan = CreatePlan::new(&temp.path().join("out.zip"), CreateOptions::default()).unwrap();
    let mut meta = metadata("a");
    meta.method = receipt.method;
    plan.add_file(&path, meta, None).unwrap();
    let mut usage = CreateUsage::default();
    let count = Cell::new(0);
    let budget = Attempts::new(&plan.options, &count);
    verify_created(file, &plan.entries, &[receipt], &plan.options, summary, &budget, &mut usage.verification)
}

#[test]
fn independent_fixtures_verify_and_deflate_must_consume_all_packed_bytes() {
    for (deflate, bytes, expected) in [
        (false, &b"abc"[..], true),
        (false, &b"abd"[..], false),
        (true, &[0x4b, 0x4c, 0x4a, 0x06, 0], true),
        (true, &[0x4b, 0x4c, 0x4a, 0x06, 0, 0x42], false),
        (true, &[0x4b, 0x4c, 0x4a, 0x06], false),
    ] {
        let (fixture, receipt, summary) = fixture(deflate, bytes);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&fixture).unwrap();
        let result = verify_fixture(&mut file, receipt, summary);
        assert_eq!(result.is_ok(), expected, "{bytes:?} {:?}", result.err());
    }
}

#[test]
fn detects_local_central_and_trailer_mutations() {
    let (original, receipt, summary) = fixture(false, b"abc");
    let central = summary.central_offset as usize;
    let end = original.len() - 22;
    for offset in [
        0,
        4,
        6,
        8,
        10,
        12,
        14,
        18,
        22,
        26,
        28,
        30,
        central,
        central + 4,
        central + 6,
        central + 8,
        central + 10,
        central + 12,
        central + 14,
        central + 16,
        central + 20,
        central + 24,
        central + 28,
        central + 30,
        central + 32,
        central + 34,
        central + 36,
        central + 38,
        central + 42,
        central + 46,
        end,
        end + 4,
        end + 8,
        end + 12,
        end + 16,
        end + 20,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        assert!(verify_fixture(&mut file, receipt, summary).is_err(), "mutation at {offset}");
    }
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&original).unwrap();
    file.write_all(b"trailer").unwrap();
    assert!(verify_fixture(&mut file, receipt, summary).is_err());
}

#[test]
fn verifies_held_file_after_name_replacement() {
    let dir = test_dir();
    let path = dir.path().join("stage");
    let mut file = File::options().read(true).write(true).create_new(true).open(&path).unwrap();
    let (bytes, receipt, summary) = fixture(false, b"abc");
    file.write_all(&bytes).unwrap();
    std::fs::rename(&path, dir.path().join("original")).unwrap();
    std::fs::write(&path, b"foreign").unwrap();
    assert!(verify_fixture(&mut file, receipt, summary).is_ok());
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
    file.seek(SeekFrom::Start(31)).unwrap();
    file.write_all(b"x").unwrap();
    assert!(verify_fixture(&mut file, receipt, summary).is_err());
}

#[test]
fn gaps_prefixes_and_zip64_end_mutations_fail() {
    let (mut gap, receipt, mut summary) = fixture(false, b"abc");
    gap.insert(summary.central_offset as usize, 0);
    summary.central_offset += 1;
    summary.usage.archive_extent += 1;
    let at = gap.len() - 6;
    gap[at..at + 4].copy_from_slice(&(summary.central_offset as u32).to_le_bytes());
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&gap).unwrap();
    assert!(verify_fixture(&mut file, receipt, summary).is_err());

    let (mut overlap, receipt, mut summary) = fixture(false, b"abc");
    overlap.remove(summary.central_offset as usize - 1);
    summary.central_offset -= 1;
    summary.usage.archive_extent -= 1;
    let at = overlap.len() - 6;
    overlap[at..at + 4].copy_from_slice(&(summary.central_offset as u32).to_le_bytes());
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&overlap).unwrap();
    assert!(verify_fixture(&mut file, receipt, summary).is_err());

    let (original, receipt, mut summary) = fixture(false, b"abc");
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"x").unwrap();
    file.write_all(&original).unwrap();
    summary.usage.archive_extent += 1;
    assert!(verify_fixture(&mut file, receipt, summary).is_err());

    let (original, receipt, summary) = fixture(true, &[0x4b, 0x4c, 0x4a, 0x06, 0]);
    let central = summary.central_offset as usize;
    let wide_end = central + summary.usage.central_bytes as usize;
    for offset in [
        31,
        33,
        35,
        43,
        central + 47,
        central + 51,
        wide_end,
        wide_end + 4,
        wide_end + 12,
        wide_end + 20,
        wide_end + 24,
        wide_end + 32,
        wide_end + 40,
        wide_end + 48,
        wide_end + 56,
        wide_end + 64,
        wide_end + 72,
        wide_end + 84,
        wide_end + 88,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        assert!(verify_fixture(&mut file, receipt, summary).is_err(), "mutation at {offset}");
    }
}

#[test]
fn agreeing_headers_still_have_to_match_the_plan_and_receipt_order() {
    let (mut bytes, mut receipt, summary) = fixture(false, b"abc");
    bytes[30] = b'b';
    bytes[summary.central_offset as usize + 46] = b'b';
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    assert!(matches!(verify_fixture(&mut file, receipt, summary), Err(CreateError::Verification(_))));

    let (bytes, _, _) = fixture(false, b"abc");
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    receipt.ordinal = 1;
    assert!(matches!(verify_fixture(&mut file, receipt, summary), Err(CreateError::Verification(_))));
}
