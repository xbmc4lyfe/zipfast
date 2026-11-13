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
    verify_created(file, (&plan.entries, &[receipt]), &plan.options, summary, &budget, &mut usage.verification, |_| {
        None
    })
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

#[test]
fn encrypted_descriptor_and_payload_are_verified_against_the_plan() {
    use crate::zip::write::{InputLength, WriterOptions, ZipStreamWriter};

    let temp = test_dir();
    let path = temp.path().join("source");
    std::fs::write(&path, b"abc").unwrap();
    let mut plan = CreatePlan::new(&temp.path().join("out.zip"), CreateOptions::default()).unwrap();
    let mut meta = metadata("a");
    meta.method = Method::Stored;
    plan.add_file(&path, meta, None).unwrap();

    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let receipt = writer
        .add_zipcrypto_file(meta, &mut b"abc".as_slice(), InputLength::Exact(3), "verify-test", |entropy| {
            entropy.fill(0x59);
            Ok(())
        })
        .unwrap();
    let finished = writer.finish().unwrap();
    assert_eq!(receipt.packed_size, 15);
    let encryption = ZipCryptoExpectation { password: "verify-test", length: InputLength::Exact(3) };
    let verify = |bytes: &[u8], encryption, limit| {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        let options = CreateOptions {
            limits: CreateLimits { verification_read_bytes: limit, ..CreateLimits::default() },
            ..CreateOptions::default()
        };
        let count = Cell::new(0);
        let budget = Attempts::new(&options, &count);
        let mut usage = VerificationUsage::default();
        verify_created(
            &mut file,
            (&plan.entries, &[receipt]),
            &options,
            finished.summary,
            &budget,
            &mut usage,
            |_| encryption,
        )?;
        assert_eq!((usage.payloads, usage.decoded_bytes), (1, 3));
        Ok::<_, CreateError>(usage.read_bytes)
    };

    let descriptor_at = finished.summary.central_offset as usize - 16;
    assert_eq!(
        &finished.sink[31..descriptor_at],
        &[0xa7, 0x21, 0x9a, 0xcd, 0x93, 0x13, 0x80, 0x42, 0x7a, 0x62, 0x8e, 0x58, 0x4d, 0x1a, 0x28],
    );
    let read_bytes = verify(&finished.sink, Some(encryption), u64::MAX).unwrap();
    assert!(verify(&finished.sink, None, u64::MAX).is_err());
    assert!(matches!(
        verify(&finished.sink, Some(encryption), read_bytes - 1),
        Err(CreateError::Limit(CreateLimit::VerificationReadBytes))
    ));
    let colliding = ZipCryptoExpectation { password: "455", ..encryption };
    assert_eq!(
        crate::crypto::decrypt_zipcrypto("455", 0, &finished.sink[31..descriptor_at]).unwrap(),
        [0x18, 0x7f, 0xbb],
    );
    assert!(matches!(
        verify(&finished.sink, Some(colliding), u64::MAX),
        Err(CreateError::Verification("decoded length or CRC differs"))
    ));
    let wrong = ZipCryptoExpectation { password: "wrong", ..encryption };
    assert!(matches!(
        verify(&finished.sink, Some(wrong), u64::MAX),
        Err(CreateError::Verification("ZipCrypto password hint differs"))
    ));

    for offset in [
        6,
        14,
        18,
        30,
        descriptor_at - 4,
        descriptor_at - 1,
        descriptor_at,
        descriptor_at + 4,
        descriptor_at + 8,
        descriptor_at + 12,
        finished.summary.central_offset as usize + 8,
    ] {
        let mut bytes = finished.sink.clone();
        bytes[offset] ^= 1;
        assert!(verify(&bytes, Some(encryption), u64::MAX).is_err(), "mutation at {offset}");
    }
}

#[test]
fn verifies_mixed_clear_and_encrypted_entries_with_canonical_empty_and_wide_framing() {
    use crate::zip::write::{InputLength, WriterOptions, ZipStreamWriter};

    let temp = test_dir();
    let mut plan = CreatePlan::new(&temp.path().join("out.zip"), CreateOptions::default()).unwrap();
    let mut writer = ZipStreamWriter::new(tempfile::tempfile().unwrap(), WriterOptions::default()).unwrap();
    let mut receipts = Vec::new();
    let mut modes = Vec::new();
    let payload: Vec<u8> = (0..=255).cycle().take(65_537).collect();
    let deflate = Method::Deflate(DeflateLevel::new(6).unwrap());
    let timestamp = crate::zip::write::DosDateTime::new(2024, 7, 8, 21, 16, 24).unwrap();
    let directory = metadata("dir/");
    plan.add_directory(directory, None).unwrap();
    receipts.push(writer.add_directory(directory).unwrap());
    modes.push(None);
    for (name, method, length, bytes) in [
        ("exact-empty", deflate, InputLength::Exact(0), b"".as_slice()),
        ("unknown-empty", Method::Stored, InputLength::Unknown, b"".as_slice()),
        ("unknown-stored", Method::Stored, InputLength::Unknown, payload.as_slice()),
        ("deflate", deflate, InputLength::Exact(payload.len() as u64), payload.as_slice()),
    ] {
        let path = temp.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let mut meta = metadata(name);
        meta.method = method;
        meta.modified = timestamp;
        meta.extended_mtime = Some(1_700_000_000);
        meta.comment = b"file";
        plan.add_file(&path, meta, None).unwrap();
        let mut input = bytes;
        receipts.push(
            writer
                .add_zipcrypto_file(meta, &mut input, length, "verify-test", |random| {
                    random.fill(0x55);
                    Ok(())
                })
                .unwrap(),
        );
        modes.push(Some(ZipCryptoExpectation { password: "verify-test", length }));
    }
    let mut finished = writer.finish().unwrap();
    let attempts = Cell::new(0);
    let budget = Attempts::new(&plan.options, &attempts);
    let mut usage = VerificationUsage::default();
    verify_created(
        &mut finished.sink,
        (&plan.entries, &receipts),
        &plan.options,
        finished.summary,
        &budget,
        &mut usage,
        |ordinal| modes[ordinal],
    )
    .unwrap();
    assert_eq!((usage.entries, usage.payloads, usage.decoded_bytes), (5, 4, 131_074));
    assert_eq!((receipts[1].packed_size, receipts[2].packed_size), (12, 12));
    let local_zip64_sizes = receipts[3].local_offset + 30 + "unknown-stored".len() as u64 + 4;
    let local_deflate_descriptor = finished.summary.central_offset - 24;
    for offset in [local_zip64_sizes, local_deflate_descriptor - 1, local_deflate_descriptor + 16] {
        let mut original = [0];
        finished.sink.seek(SeekFrom::Start(offset)).unwrap();
        finished.sink.read_exact(&mut original).unwrap();
        finished.sink.seek(SeekFrom::Start(offset)).unwrap();
        finished.sink.write_all(&[original[0] ^ 0xff]).unwrap();
        assert!(
            verify_created(
                &mut finished.sink,
                (&plan.entries, &receipts),
                &plan.options,
                finished.summary,
                &budget,
                &mut VerificationUsage::default(),
                |ordinal| modes[ordinal],
            )
            .is_err(),
            "mutation at {offset}"
        );
        finished.sink.seek(SeekFrom::Start(offset)).unwrap();
        finished.sink.write_all(&original).unwrap();
    }
}

#[test]
#[ignore = "streams a physical encrypted member larger than 128 MiB"]
fn verifies_zipcrypto_packed_range_above_the_buffered_reader_ceiling() {
    use crate::zip::write::{InputLength, WriterOptions, ZipStreamWriter};

    const LENGTH: u64 = (128 << 20) + 1;
    let temp = test_dir();
    let path = temp.path().join("source");
    File::create(&path).unwrap().set_len(LENGTH).unwrap();
    let mut plan = CreatePlan::new(&temp.path().join("out.zip"), CreateOptions::default()).unwrap();
    let mut meta = metadata("large");
    meta.method = Method::Stored;
    plan.add_file(&path, meta, None).unwrap();

    let mut writer = ZipStreamWriter::new(tempfile::tempfile().unwrap(), WriterOptions::default()).unwrap();
    let length = InputLength::Exact(LENGTH);
    let receipt = writer
        .add_zipcrypto_file(meta, &mut File::open(&path).unwrap(), length, "verify-test", |random| {
            random.fill(0x11);
            Ok(())
        })
        .unwrap();
    let mut finished = writer.finish().unwrap();
    let attempts = Cell::new(0);
    let budget = Attempts::new(&plan.options, &attempts);
    let mut usage = VerificationUsage::default();
    verify_created(
        &mut finished.sink,
        (&plan.entries, &[receipt]),
        &plan.options,
        finished.summary,
        &budget,
        &mut usage,
        |_| Some(ZipCryptoExpectation { password: "verify-test", length }),
    )
    .unwrap();
    assert_eq!(receipt.packed_size, LENGTH + 12);
    assert_eq!(usage.decoded_bytes, LENGTH);
    assert_eq!(usage.payloads, 1);
}
