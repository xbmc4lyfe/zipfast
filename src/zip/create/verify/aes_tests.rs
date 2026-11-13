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

use super::super::tests::{metadata, test_dir};
use super::super::{Cell, CreatePlan};
use super::*;
use crate::zip::write::{AesEntryWritten, DeflateLevel, WriterOptions, ZipStreamWriter};
use std::io::Write;

fn sample(
    method: Method,
    variant: AesVariant,
) -> (tempfile::TempDir, CreatePlan, Vec<u8>, AesEntryWritten, WriteSummary) {
    let dir = test_dir();
    let path = dir.path().join("source");
    std::fs::write(&path, b"abc").unwrap();
    let mut plan = CreatePlan::new(&dir.path().join("out.zip"), CreateOptions::default()).unwrap();
    let mut meta = metadata("a");
    meta.method = method;
    plan.add_file(&path, meta, None).unwrap();
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let receipt = writer
        .add_winzip_aes_file(
            meta,
            &mut b"abc".as_slice(),
            InputLength::Exact(3),
            WinZipAesRequest::new("verify-aes", AesStrength::Aes128, variant).unwrap(),
            |salt| {
                salt.fill(1);
                Ok(())
            },
        )
        .unwrap();
    let done = writer.finish().unwrap();
    (dir, plan, done.sink, receipt, done.summary)
}

fn verify_bytes(
    plan: &CreatePlan,
    bytes: &[u8],
    receipt: EntryWritten,
    summary: WriteSummary,
    encryption: Option<EncryptionExpectation<'_>>,
    options: &CreateOptions,
) -> (Result<VerifiedCreation>, VerificationUsage, u64) {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    let count = Cell::new(0);
    let budget = Attempts::new(options, &count);
    let mut usage = VerificationUsage::default();
    let result =
        verify_created(&mut file, (&plan.entries, &[receipt]), options, summary, &budget, &mut usage, |_| encryption);
    (result, usage, count.get())
}

#[test]
fn aes_rejects_unrequested_or_mismatched_encryption_and_consistent_header_forgery() {
    for variant in [AesVariant::Ae1, AesVariant::Ae2] {
        let (_dir, plan, original, receipt, summary) = sample(Method::Stored, variant);
        let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes128, variant).unwrap();
        let expected =
            AesExpectation { request: &request, length: InputLength::Exact(3), plaintext_crc32: 0x3524_41c2 };
        assert!(verify_bytes(&plan, &original, receipt.entry, summary, None, &plan.options).0.is_err());
        let wrong_strength = WinZipAesRequest::new("verify-aes", AesStrength::Aes256, variant).unwrap();
        let wrong_variant = WinZipAesRequest::new(
            "verify-aes",
            AesStrength::Aes128,
            if variant == AesVariant::Ae1 { AesVariant::Ae2 } else { AesVariant::Ae1 },
        )
        .unwrap();
        for request in [&wrong_strength, &wrong_variant] {
            let mode = AesExpectation { request, ..expected };
            assert!(
                verify_bytes(&plan, &original, receipt.entry, summary, Some(mode.into()), &plan.options).0.is_err()
            );
        }
        let wrong_length = AesExpectation { length: InputLength::Exact(4), ..expected };
        assert!(
            verify_bytes(&plan, &original, receipt.entry, summary, Some(wrong_length.into()), &plan.options).0.is_err()
        );
        let central = summary.central_offset as usize;
        assert_eq!(central, 81);
        let mut bytes = original.clone();
        let mut forged_receipt = receipt.entry;
        forged_receipt.crc32 = if variant == AesVariant::Ae2 { 0x3524_41c2 } else { 0 };
        bytes[69..73].copy_from_slice(&forged_receipt.crc32.to_le_bytes());
        bytes[central + 16..central + 20].copy_from_slice(&forged_receipt.crc32.to_le_bytes());
        assert!(verify_bytes(&plan, &bytes, forged_receipt, summary, Some(expected.into()), &plan.options).0.is_err());
        let mut duplicate = original.clone();
        let extra = original[31..42].to_vec();
        duplicate.splice(42..42, extra.iter().copied());
        duplicate.splice(central + 11 + 58..central + 11 + 58, extra);
        duplicate[28..30].copy_from_slice(&22u16.to_le_bytes());
        duplicate[central + 11 + 30..central + 11 + 32].copy_from_slice(&22u16.to_le_bytes());
        let mut duplicate_summary = summary;
        duplicate_summary.central_offset += 11;
        duplicate_summary.usage.central_bytes += 11;
        duplicate_summary.usage.archive_extent += 22;
        let end = duplicate.len() - 22;
        duplicate[end + 12..end + 16].copy_from_slice(&(duplicate_summary.usage.central_bytes as u32).to_le_bytes());
        duplicate[end + 16..end + 20].copy_from_slice(&(duplicate_summary.central_offset as u32).to_le_bytes());
        assert!(
            verify_bytes(&plan, &duplicate, receipt.entry, duplicate_summary, Some(expected.into()), &plan.options)
                .0
                .is_err()
        );
        for (local, central_field) in [
            (8, central + 10),
            (35, central + 51),
            (37, central + 53),
            (39, central + 55),
            (40, central + 56),
            (31, central + 47),
            (33, central + 49),
        ] {
            let mut bytes = original.clone();
            bytes[local] ^= 1;
            bytes[central_field] ^= 1;
            assert!(
                verify_bytes(&plan, &bytes, receipt.entry, summary, Some(expected.into()), &plan.options).0.is_err(),
                "forgery at {local}/{central_field}"
            );
        }
        for offset in [
            6,
            14,
            18,
            22,
            28,
            30,
            42,
            49,
            50,
            51,
            52,
            54,
            55,
            60,
            64,
            65,
            69,
            73,
            77,
            central + 8,
            central + 16,
            central + 20,
            central + 24,
            central + 30,
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            assert!(
                verify_bytes(&plan, &bytes, receipt.entry, summary, Some(expected.into()), &plan.options).0.is_err(),
                "mutation at {offset}"
            );
        }
        for end in [41, 49, 51, 54, 55, 64, 65, 80, original.len() - 1] {
            assert!(
                verify_bytes(&plan, &original[..end], receipt.entry, summary, Some(expected.into()), &plan.options)
                    .0
                    .is_err(),
                "truncation at {end}"
            );
        }
    }
}

#[test]
fn aes_matching_password_verifier_is_insufficient_and_valid_tag_cannot_hide_wrong_private_crc() {
    let (_dir, plan, bytes, receipt, summary) = sample(Method::Stored, AesVariant::Ae2);
    let salt = [1; 8];
    // Independently found with Python hashlib.pbkdf2_hmac: both verifiers are d0ff.
    let correct = crate::crypto::aes_derive(b"verify-aes", &salt, 16).unwrap();
    let collision = crate::crypto::aes_derive(b"collision-12634", &salt, 16).unwrap();
    assert_eq!(&correct[32..], b"\xd0\xff");
    assert_eq!(&correct[32..], &collision[32..]);
    let request = WinZipAesRequest::new("collision-12634", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    let expected = AesExpectation { request: &request, length: InputLength::Exact(3), plaintext_crc32: 0x3524_41c2 };
    assert!(matches!(
        verify_bytes(&plan, &bytes, receipt.entry, summary, Some(expected.into()), &plan.options).0,
        Err(CreateError::Verification("AES authentication tag differs"))
    ));
    let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    let wrong_crc = AesExpectation { request: &request, plaintext_crc32: 0x3524_41c3, ..expected };
    assert!(matches!(
        verify_bytes(&plan, &bytes, receipt.entry, summary, Some(wrong_crc.into()), &plan.options).0,
        Err(CreateError::Verification("decoded length or CRC differs"))
    ));
}

#[test]
fn aes_decoder_and_authentication_cross_fixed_buffer_boundaries() {
    let mut state = 0x12ab_37c9u32;
    let contents = (0..2 * BUFFER + 17)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect::<Vec<_>>();
    for strength in [AesStrength::Aes128, AesStrength::Aes192, AesStrength::Aes256] {
        for variant in [AesVariant::Ae1, AesVariant::Ae2] {
            let dir = test_dir();
            let path = dir.path().join("source");
            std::fs::write(&path, &contents).unwrap();
            let mut plan = CreatePlan::new(&dir.path().join("out.zip"), CreateOptions::default()).unwrap();
            let mut meta = metadata("a");
            meta.method = Method::Deflate(DeflateLevel::new(6).unwrap());
            plan.add_file(&path, meta, None).unwrap();
            let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
            let request = WinZipAesRequest::new("verify-aes", strength, variant).unwrap();
            let receipt = writer
                .add_winzip_aes_file(
                    meta,
                    &mut contents.as_slice(),
                    InputLength::Exact(contents.len() as u64),
                    request,
                    |salt| {
                        salt.fill(1);
                        Ok(())
                    },
                )
                .unwrap();
            assert!(receipt.entry.packed_size > 2 * BUFFER as u64);
            let done = writer.finish().unwrap();
            let request = WinZipAesRequest::new("verify-aes", strength, variant).unwrap();
            let expected = AesExpectation {
                request: &request,
                length: InputLength::Exact(contents.len() as u64),
                plaintext_crc32: receipt.plaintext_crc32,
            };
            let (result, usage, _) =
                verify_bytes(&plan, &done.sink, receipt.entry, done.summary, Some(expected.into()), &plan.options);
            result.unwrap();
            assert_eq!((usage.entries, usage.payloads, usage.decoded_bytes), (1, 1, contents.len() as u64));
        }
    }
}

#[test]
fn aes_verification_read_decoded_and_attempt_ceilings_have_exact_boundaries() {
    for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
        let (_dir, plan, bytes, receipt, summary) = sample(method, AesVariant::Ae2);
        let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let expected = Some(
            AesExpectation { request: &request, length: InputLength::Exact(3), plaintext_crc32: 0x3524_41c2 }.into(),
        );
        let (result, usage, attempts) = verify_bytes(&plan, &bytes, receipt.entry, summary, expected, &plan.options);
        result.unwrap();
        for (limit_kind, maximum) in [
            (CreateLimit::VerificationReadBytes, usage.read_bytes),
            (CreateLimit::VerificationEntryBytes, 3),
            (CreateLimit::VerificationDecodedBytes, 3),
            (CreateLimit::VerificationMetadata, usage.metadata_bytes),
            (CreateLimit::VerificationScratch, usage.scratch_capacity),
            (CreateLimit::TransactionAttempts, attempts),
        ] {
            for less in [0, 1] {
                let mut options = plan.options.clone();
                let ceiling = match limit_kind {
                    CreateLimit::VerificationReadBytes => &mut options.limits.verification_read_bytes,
                    CreateLimit::VerificationEntryBytes => &mut options.limits.verification_entry_bytes,
                    CreateLimit::VerificationDecodedBytes => &mut options.limits.verification_decoded_bytes,
                    CreateLimit::VerificationMetadata => &mut options.limits.verification_metadata,
                    CreateLimit::VerificationScratch => &mut options.limits.verification_scratch,
                    CreateLimit::TransactionAttempts => &mut options.limits.transaction_attempts,
                    _ => unreachable!(),
                };
                *ceiling = maximum - less;
                let (result, observed, count) = verify_bytes(&plan, &bytes, receipt.entry, summary, expected, &options);
                if less == 0 {
                    result.unwrap();
                    assert_eq!(observed, usage);
                    assert_eq!(count, attempts);
                } else {
                    assert!(matches!(result,Err(CreateError::Limit(kind)) if kind == limit_kind));
                    assert_eq!(observed.payloads, u64::from(limit_kind == CreateLimit::TransactionAttempts));
                    assert!(count <= options.limits.transaction_attempts);
                    assert!(observed.read_bytes <= options.limits.verification_read_bytes);
                    assert!(observed.decoded_bytes <= options.limits.verification_decoded_bytes);
                }
            }
        }
    }
}

fn packed(raw: &[u8]) -> Vec<u8> {
    let salt = [1; 8];
    let mut cipher = WinZipAesEncryptor::new(b"verify-aes", &salt, 16).unwrap();
    let mut bytes = raw.to_vec();
    cipher.encrypt(&mut bytes).unwrap();
    let mut result = salt.to_vec();
    result.extend(cipher.verifier());
    result.extend(bytes);
    result.extend(cipher.tag());
    result
}

#[test]
fn aes_short_reads_and_interruptions_use_actual_bytes_and_bounded_attempts() {
    use super::super::tests::{Event, cap_verification_reads, with_hook};
    use std::rc::Rc;
    let (_dir, plan, bytes, receipt, summary) = sample(Method::Stored, AesVariant::Ae2);
    let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    let expected =
        Some(AesExpectation { request: &request, length: InputLength::Exact(3), plaintext_crc32: 0x3524_41c2 }.into());
    let (result, usage, attempts) = verify_bytes(&plan, &bytes, receipt.entry, summary, expected, &plan.options);
    result.unwrap();
    let seen = Rc::new(Cell::new(false));
    let interrupted = seen.clone();
    let (result, interrupted_usage, interrupted_attempts) = with_hook(
        move |event, _| {
            if event == Event::VerifyRead && !interrupted.replace(true) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        },
        || verify_bytes(&plan, &bytes, receipt.entry, summary, expected, &plan.options),
    );
    result.unwrap();
    assert!(seen.get());
    assert_eq!(interrupted_usage, usage);
    assert_eq!(interrupted_attempts, attempts + 1);
    let (result, short_usage, short_attempts) = with_hook(
        |_, _| {
            cap_verification_reads(1);
            Ok(())
        },
        || verify_bytes(&plan, &bytes, receipt.entry, summary, expected, &plan.options),
    );
    result.unwrap();
    assert_eq!(short_usage, usage);
    assert!(short_attempts > attempts);
    let mut options = plan.options.clone();
    options.limits.transaction_attempts = 4;
    let (result, observed, count) = with_hook(
        |event, _| if event == Event::VerifyRead { Err(io::ErrorKind::Interrupted.into()) } else { Ok(()) },
        || verify_bytes(&plan, &bytes, receipt.entry, summary, expected, &options),
    );
    assert!(matches!(result, Err(CreateError::Limit(CreateLimit::TransactionAttempts))));
    assert_eq!((count, observed.read_bytes, observed.payloads), (4, 0, 0));
}

#[test]
fn aes_cancellation_during_ciphertext_read_prevents_authenticated_completion() {
    use super::super::tests::{Event, with_hook};
    use std::rc::Rc;
    for early in [false, true] {
        let bytes = packed(b"abc");
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        file.rewind().unwrap();
        let options = CreateOptions::default();
        if early {
            options.cancel.cancel();
        }
        let cancel = options.cancel.clone();
        let reads = Rc::new(Cell::new(0));
        let observed = reads.clone();
        let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let expected = Some(
            AesExpectation { request: &request, length: InputLength::Exact(3), plaintext_crc32: 0x3524_41c2 }.into(),
        );
        let count = Cell::new(0);
        let budget = Attempts::new(&options, &count);
        let mut usage = VerificationUsage::default();
        let mut reader = Reader::new(&mut file, options.limits, &budget, &mut usage);
        let result = with_hook(
            move |event, _| {
                if event == Event::VerifyRead {
                    observed.set(observed.get() + 1);
                    if observed.get() == 2 {
                        cancel.cancel();
                    }
                }
                Ok(())
            },
            || {
                reader.verify_payload(
                    Payload { method: 0, packed_size: 23, decoded_size: 3, crc32: 0x3524_41c2 },
                    &mut [0; BUFFER],
                    expected,
                    0,
                )
            },
        );
        assert!(matches!(result, Err(CreateError::Canceled)));
        assert_eq!(usage.payloads, 0);
        assert_eq!(count.get(), if early { 0 } else { 2 });
        assert_eq!(usage.read_bytes, if early { 0 } else { 13 });
        assert_eq!(usage.decoded_bytes, if early { 0 } else { 3 });
    }
}

#[test]
fn aes_authenticated_deflate_requires_exact_codec_completion_and_tag_extent() {
    let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    let expectation =
        Some(AesExpectation { request: &request, length: InputLength::Exact(3), plaintext_crc32: 0x3524_41c2 }.into());
    for (raw, success) in [
        (&b"\x4b\x4c\x4a\x06\x00"[..], true),
        (&b"\x4b\x4c\x4a\x06\x00\x42"[..], false),
        (&b"\x4b\x4c\x4a\x06"[..], false),
    ] {
        let bytes = packed(raw);
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&bytes).unwrap();
        file.rewind().unwrap();
        let options = CreateOptions::default();
        let count = Cell::new(0);
        let attempts = Attempts::new(&options, &count);
        let mut usage = VerificationUsage::default();
        let mut reader = Reader::new(&mut file, options.limits, &attempts, &mut usage);
        let receipt = Payload { method: 8, packed_size: bytes.len() as u64, decoded_size: 3, crc32: 0x3524_41c2 };
        assert_eq!(reader.verify_payload(receipt, &mut [0; BUFFER], expectation, 0).is_ok(), success);
        assert_eq!(usage.payloads, 0);
    }
    let complete = packed(b"abc");
    for len in [0, 7, 9, 10, 12, 13, 22] {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&complete[..len]).unwrap();
        file.rewind().unwrap();
        let options = CreateOptions::default();
        let count = Cell::new(0);
        let attempts = Attempts::new(&options, &count);
        let mut usage = VerificationUsage::default();
        let mut reader = Reader::new(&mut file, options.limits, &attempts, &mut usage);
        assert!(matches!(
            reader.verify_payload(
                Payload { method: 0, packed_size: 23, decoded_size: 3, crc32: 0x3524_41c2 },
                &mut [0; BUFFER],
                expectation,
                0
            ),
            Err(CreateError::Io(_))
        ));
        assert_eq!(usage.read_bytes, len as u64);
    }
}

#[test]
#[ignore = "streams a physical AES member larger than 128 MiB"]
fn aes_native_verification_exceeds_the_public_buffered_reader_ceiling() {
    const LENGTH: u64 = (128 << 20) + 1;
    let dir = test_dir();
    let path = dir.path().join("source");
    File::create(&path).unwrap().set_len(LENGTH).unwrap();
    let mut plan = CreatePlan::new(&dir.path().join("out.zip"), CreateOptions::default()).unwrap();
    let mut meta = metadata("large");
    meta.method = Method::Stored;
    plan.add_file(&path, meta, None).unwrap();
    let stage_path = dir.path().join("stage.zip");
    let stage = File::options().create_new(true).read(true).write(true).open(&stage_path).unwrap();
    let mut writer = ZipStreamWriter::new(stage, WriterOptions::default()).unwrap();
    let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes256, AesVariant::Ae2).unwrap();
    let receipt = writer
        .add_winzip_aes_file(meta, &mut File::open(&path).unwrap(), InputLength::Exact(LENGTH), request, |salt| {
            salt.fill(1);
            Ok(())
        })
        .unwrap();
    let mut done = writer.finish().unwrap();
    let request = WinZipAesRequest::new("verify-aes", AesStrength::Aes256, AesVariant::Ae2).unwrap();
    let count = Cell::new(0);
    let attempts = Attempts::new(&plan.options, &count);
    let mut usage = VerificationUsage::default();
    verify_created(
        &mut done.sink,
        (&plan.entries, &[receipt.entry]),
        &plan.options,
        done.summary,
        &attempts,
        &mut usage,
        |_| {
            Some(
                AesExpectation {
                    request: &request,
                    length: InputLength::Exact(LENGTH),
                    plaintext_crc32: receipt.plaintext_crc32,
                }
                .into(),
            )
        },
    )
    .unwrap();
    assert_eq!(receipt.entry.packed_size, LENGTH + 28);
    assert_eq!((usage.entries, usage.payloads, usage.decoded_bytes), (1, 1, LENGTH));
    assert!(usage.read_bytes > LENGTH);
    let mut preview = crate::zip::Archive::open(&stage_path).unwrap();
    assert!(
        matches!(preview.read_at(0, Some("verify-aes"), u64::MAX, |_| Ok(())),Err(crate::Error::Unsupported(message)) if message.contains("128 MiB packed limit"))
    );
    println!(
        "AES256 AE2 physical decoded={} packed={} stage={} verification_read={} attempts={} parser_scratch={}",
        LENGTH,
        receipt.entry.packed_size,
        done.summary.usage.archive_extent,
        usage.read_bytes,
        count.get(),
        usage.scratch_capacity
    );
}
