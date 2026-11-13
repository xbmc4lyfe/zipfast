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

//! Encrypted RAR5 integration tests using archives generated from the format.
mod common;

use std::{fs, path::Path};

use common::*;
use zipfast::crypto::{derive_rar5_key_and_hash_key, encrypt_cbc, rar5_tweak_crc32};
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::testenc::{Op, tuned_blocks};

const PASSWORD: &str = "zipfast-test-only";
const SALT: [u8; 16] = [0x53; 16];
const IV: [u8; 16] = [0x49; 16];
const KDF_COUNT: u8 = 4;

// Independent known answer for bytes 0..17 under the parameters above.
// Python hashlib's BLAKE2s tree, PBKDF2-HMAC-SHA256 and hmac produced this tag.
const KEYED_BLAKE: [u8; 32] = [
    0xd1, 0xfd, 0xd8, 0xa0, 0xfb, 0x8c, 0x26, 0x4c, 0xfe, 0x4a, 0x04, 0xda, 0x91, 0xe7, 0x4e, 0x14, 0x72, 0x90, 0xfe,
    0xc9, 0xca, 0xf1, 0x10, 0x39, 0x37, 0x42, 0xa6, 0x46, 0x49, 0xb2, 0x4e, 0x50,
];

fn encrypted_data(data: &[u8], extra_padding: usize) -> Vec<u8> {
    let (key, _) = derive_rar5_key_and_hash_key(PASSWORD, KDF_COUNT, &SALT, None).unwrap();
    let mut padded = data.to_vec();
    padded.resize(data.len().next_multiple_of(16) + extra_padding, 0);
    encrypt_cbc(&key, &IV, &padded).unwrap()
}

fn encryption_record(tweaked: bool) -> Vec<u8> {
    let mut body = vec![1, 0, if tweaked { 2 } else { 0 }, KDF_COUNT]; // type, version, flags, exponent
    body.extend(SALT);
    body.extend(IV);
    let mut record = Vec::new();
    vint(body.len() as u64, &mut record);
    record.extend(body);
    record
}

fn encrypted_crc(data: &[u8]) -> u32 {
    let (_, hash_key) = derive_rar5_key_and_hash_key(PASSWORD, KDF_COUNT, &SALT, None).unwrap();
    rar5_tweak_crc32(crc32fast::hash(data), &hash_key)
}

fn options(dest: &Path, mode: Mode) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

fn assert_extracts(archive: &Path, out: &Path, expected: &[u8]) {
    let tested = extract::run_with_password(archive, &options(out, Mode::Test), Some(PASSWORD), |_| {}).unwrap();
    assert_eq!((tested.files, tested.errors.len()), (1, 0), "{:?}", tested.errors);
    let extracted = extract::run_with_password(archive, &options(out, Mode::Extract), Some(PASSWORD), |_| {}).unwrap();
    assert_eq!((extracted.files, extracted.errors.len()), (1, 0), "{:?}", extracted.errors);
    assert_eq!(fs::read(out.join("f")).unwrap(), expected);
    let mut selected = Vec::new();
    extract::SelectedEntry::open(archive, 0, Some(PASSWORD), 1 << 20)
        .unwrap()
        .read(Some(PASSWORD), |bytes| {
            selected.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(selected, expected);
}

fn assert_rejected(archive: &Path, out: &Path, reason: &str) {
    fs::create_dir_all(out).unwrap();
    let target = out.join("f");
    fs::write(&target, b"old destination").unwrap();
    let original_modified = fs::metadata(&target).unwrap().modified().unwrap();
    for mode in [Mode::Test, Mode::Extract] {
        let result = extract::run_with_password(archive, &options(out, mode), Some(PASSWORD), |_| {}).unwrap();
        assert_eq!((result.files, result.errors.len()), (0, 1), "{:?}", result.errors);
        assert!(result.errors[0].contains(reason), "{:?}", result.errors);
    }
    assert_eq!(fs::read(&target).unwrap(), b"old destination");
    assert_eq!(fs::metadata(&target).unwrap().modified().unwrap(), original_modified);
    assert_eq!(fs::read_dir(out).unwrap().count(), 1);
    let error = extract::SelectedEntry::open(archive, 0, Some(PASSWORD), 1 << 20)
        .unwrap()
        .read(Some(PASSWORD), |_| Ok(()))
        .unwrap_err();
    assert!(error.to_string().contains(reason), "{error}");
}

fn split_archive(dir: &Path, first: &FileSpec<'_>, last: &FileSpec<'_>, cut: usize, final_crc: u32) {
    let (first_data, last_data) = first.data.split_at(cut);
    for (i, (spec, data, crc)) in
        [(first, first_data, crc32fast::hash(first_data)), (last, last_data, final_crc)].into_iter().enumerate()
    {
        let mut volume = SIG.to_vec();
        volume.extend(main_block(true, (i != 0).then_some(i as u64)));
        volume.extend(file_block(spec, data, crc, i != 0, i == 0));
        volume.extend(end_block(i == 0));
        fs::write(dir.join(format!("test.part{}.rar", i + 1)), volume).unwrap();
    }
}

#[test]
fn encrypted_stored_alignment_at_block_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let out = dir.path().join("out");
    for size in [0u8, 1, 15, 16, 17] {
        let plain: Vec<_> = (0..size).collect();
        let encrypted = encrypted_data(&plain, 0);
        let spec =
            FileSpec { size: Some(size.into()), extra: encryption_record(true), ..FileSpec::new("f", &encrypted) };
        fs::write(&archive, archive_with(&[(spec, encrypted_crc(&plain))], false)).unwrap();
        assert_extracts(&archive, &out, &plain);
    }
}

#[test]
fn encrypted_stored_excess_padding_preserves_the_destination() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let plain = b"0123456789abcdefg";
    let encrypted = encrypted_data(plain, 16);
    let spec =
        FileSpec { size: Some(plain.len() as u64), extra: encryption_record(true), ..FileSpec::new("f", &encrypted) };
    fs::write(&archive, archive_with(&[(spec, encrypted_crc(plain))], false)).unwrap();
    assert_rejected(&archive, &dir.path().join("out"), "excess encrypted RAR5 padding");
}

#[test]
fn encrypted_stored_padding_is_bounded_across_volume_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.part1.rar");
    let out = dir.path().join("out");
    let plain = b"f";
    for extra in [0, 16] {
        let encrypted = encrypted_data(plain, extra);
        let spec = FileSpec { size: Some(1), extra: encryption_record(false), ..FileSpec::new("f", &encrypted) };
        // A volume can end inside a cipher block. In the invalid case the first
        // complete block already carries 15 bytes of padding.
        let cut = if extra == 0 { 7 } else { 23 };
        split_archive(dir.path(), &spec, &spec, cut, crc32fast::hash(plain));
        if extra == 0 {
            assert_extracts(&archive, &out, plain);
        } else {
            assert_rejected(&archive, &out, "excess encrypted RAR5 padding");
        }
    }
}

#[test]
fn encrypted_stored_unknown_size_keeps_all_decrypted_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let plain = b"0123456789abcdef0123456789abcdef";
    let encrypted = encrypted_data(plain, 0);
    let spec = FileSpec {
        size: Some(0),
        size_unknown: true,
        extra: encryption_record(true),
        ..FileSpec::new("f", &encrypted)
    };
    fs::write(&archive, archive_with(&[(spec, encrypted_crc(plain))], false)).unwrap();
    assert_extracts(&archive, &dir.path().join("out"), plain);
}

#[test]
fn encrypted_split_final_blake_without_hash_state_fails_even_with_correct_crc() {
    let dir = tempfile::tempdir().unwrap();
    let plain = b"0123456789abcdefg";
    let encrypted = encrypted_data(plain, 0);
    let first =
        FileSpec { size: Some(plain.len() as u64), extra: encryption_record(false), ..FileSpec::new("f", &encrypted) };
    let mut extra = encryption_record(false);
    extra.extend(blake_record(blake(b"wrong")));
    let last = FileSpec { extra, size: first.size, ..FileSpec::new("f", &encrypted) };
    split_archive(dir.path(), &first, &last, 16, crc32fast::hash(plain));
    assert_rejected(&dir.path().join("test.part1.rar"), &dir.path().join("out"), "BLAKE2sp");
}

#[test]
fn encrypted_keyed_blake_is_checked_without_a_crc() {
    let dir = tempfile::tempdir().unwrap();
    let plain: Vec<_> = (0..17).collect();
    let encrypted = encrypted_data(&plain, 0);
    let archive = dir.path().join("test.rar");
    let out = dir.path().join("out");
    for tag in [KEYED_BLAKE, [0; 32]] {
        let mut extra = encryption_record(true);
        extra.extend(blake_record(tag));
        let spec = FileSpec { no_crc: true, size: Some(plain.len() as u64), extra, ..FileSpec::new("f", &encrypted) };
        fs::write(&archive, archive_with(&[(spec, 0)], false)).unwrap();
        if tag == KEYED_BLAKE {
            assert_extracts(&archive, &out, &plain);
        } else {
            assert_rejected(&archive, &out, "checksum error");
        }
    }
}

#[test]
fn encrypted_compression_obeys_block_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let plain = b"encrypted packed data";
    let (first, last) = plain.split_at(7);
    let first_ops: Vec<_> = first.iter().copied().map(Op::Lit).collect();
    let last_ops: Vec<_> = last.iter().copied().map(Op::Lit).collect();
    let packed = tuned_blocks(&[&first_ops, &last_ops], true);
    let archive = dir.path().join("test.rar");
    let out = dir.path().join("out");
    for extra in [0, 16] {
        let encrypted = encrypted_data(&packed, extra);
        let spec = FileSpec {
            method: 3,
            size: Some(plain.len() as u64),
            extra: encryption_record(true),
            ..FileSpec::new("f", &encrypted)
        };
        fs::write(&archive, archive_with(&[(spec, encrypted_crc(plain))], false)).unwrap();
        if extra == 0 {
            assert_extracts(&archive, &out, plain);
        } else {
            assert_rejected(&archive, &out, "excess encrypted RAR5 padding");
        }
    }
}

#[test]
fn encrypted_stored_partial_cipher_block_preserves_the_destination() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let plain = b"one whole block!";
    let mut encrypted = encrypted_data(plain, 0);
    encrypted.push(0);
    let spec =
        FileSpec { size: Some(plain.len() as u64), extra: encryption_record(true), ..FileSpec::new("f", &encrypted) };
    fs::write(&archive, archive_with(&[(spec, encrypted_crc(plain))], false)).unwrap();
    assert_rejected(&archive, &dir.path().join("out"), "truncated");
}

#[test]
fn encrypted_crc_failure_preserves_the_destination() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let plain = b"new bytes";
    let encrypted = encrypted_data(plain, 0);
    let spec =
        FileSpec { size: Some(plain.len() as u64), extra: encryption_record(true), ..FileSpec::new("f", &encrypted) };
    fs::write(&archive, archive_with(&[(spec, encrypted_crc(plain) ^ 1)], false)).unwrap();
    assert_rejected(&archive, &dir.path().join("out"), "checksum error");
}

#[test]
fn encrypted_split_uses_the_final_volume_crc_mode() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.part1.rar");
    let out = dir.path().join("out");
    let plain = b"0123456789abcdefg";
    let encrypted = encrypted_data(plain, 0);
    let first =
        FileSpec { size: Some(plain.len() as u64), extra: encryption_record(false), ..FileSpec::new("f", &encrypted) };
    let last = FileSpec { size: first.size, extra: encryption_record(true), ..FileSpec::new("f", &encrypted) };
    split_archive(dir.path(), &first, &last, 7, encrypted_crc(plain));
    assert_extracts(&archive, &out, plain);
    use zipfast::rar5::session::{RarPrintOptions, RarSession, RarSessionOptions};
    let mut session = RarSession::open(&archive, Some(PASSWORD), RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    let mut printed = Vec::new();
    let options = RarPrintOptions { member_spool_bytes: plain.len() as u64, ..RarPrintOptions::default() };
    let summary = session.print_selected(&selection, &mut printed, &options, |_| {}).unwrap();
    assert_eq!((summary.files, summary.volumes, summary.bytes), (1, 2, 17));
    assert_eq!(printed, plain);
    let limit = encrypted.len() as u64;
    extract::SelectedEntry::open(&archive, 0, Some(PASSWORD), limit).unwrap().read(Some(PASSWORD), |_| Ok(())).unwrap();
    let error = extract::SelectedEntry::open(&archive, 0, Some(PASSWORD), limit - 1)
        .unwrap()
        .read(Some(PASSWORD), |_| panic!("decoded a split member beyond the packed budget"))
        .unwrap_err();
    assert!(matches!(error, zipfast::Error::Unsupported(message) if message.contains("packed byte limit")));

    split_archive(dir.path(), &first, &last, 7, crc32fast::hash(plain));
    assert_rejected(&archive, &out, "checksum error");
}

#[test]
fn encrypted_split_uses_the_final_volume_blake_mode() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.part1.rar");
    let out = dir.path().join("out");
    let plain: Vec<_> = (0..17).collect();
    let encrypted = encrypted_data(&plain, 0);
    let cut = 7;
    let mut extra = encryption_record(false);
    extra.extend(blake_record(blake(&encrypted[..cut])));
    let first = FileSpec { no_crc: true, extra, size: Some(plain.len() as u64), ..FileSpec::new("f", &encrypted) };
    for (tag, valid) in [(KEYED_BLAKE, true), (blake(&plain), false)] {
        let mut extra = encryption_record(true);
        extra.extend(blake_record(tag));
        let last = FileSpec { no_crc: true, size: first.size, extra, ..FileSpec::new("f", &encrypted) };
        split_archive(dir.path(), &first, &last, cut, 0);
        if valid {
            assert_extracts(&archive, &out, &plain);
        } else {
            assert_rejected(&archive, &out, "checksum error");
        }
    }
}

#[test]
fn selected_encrypted_rar_rejects_a_modified_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("modified.rar");
    let plain = b"0123456789abcdef";
    let mut cipher = encrypted_data(plain, 0);
    cipher[0] ^= 1;
    let spec = FileSpec { extra: encryption_record(true), ..FileSpec::new("f", &cipher) };
    fs::write(&path, archive_with(&[(spec, encrypted_crc(plain))], false)).unwrap();
    let entry = extract::SelectedEntry::open(&path, 0, Some(PASSWORD), 16).unwrap();
    let mut provisional = Vec::new();
    let error = entry
        .read(Some(PASSWORD), |bytes| {
            provisional.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(provisional.len(), 16);
    assert_ne!(provisional, plain);
    assert!(error.to_string().contains("checksum error"), "{error}");
}

#[test]
fn truncated_declared_password_check_never_publishes_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let out = dir.path().join("out");
    let plain = b"authenticated framing";
    let encrypted = encrypted_data(plain, 0);
    let mut extra = encryption_record(false);
    extra[3] = 1; // a verifier is declared, but its bytes are absent
    let spec = FileSpec { size: Some(plain.len() as u64), extra, ..FileSpec::new("f", &encrypted) };
    fs::write(&archive, archive_with(&[(spec, crc32fast::hash(plain))], false)).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("f"), b"original").unwrap();
    let summary = extract::run_with_password(&archive, &options(&out, Mode::Extract), Some(PASSWORD), |_| {}).unwrap();
    assert_eq!((summary.files, summary.errors.len()), (0, 1));
    assert_eq!(fs::read(out.join("f")).unwrap(), b"original");
}

#[test]
fn truncated_member_iv_never_publishes_an_empty_member() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let out = dir.path().join("out");
    let mut extra = encryption_record(false);
    extra[0] -= 1;
    extra.pop();
    let spec = FileSpec { extra, ..FileSpec::new("f", b"") };
    fs::write(&archive, archive_with(&[(spec, 0)], false)).unwrap();
    let summary = extract::run_with_password(&archive, &options(&out, Mode::Extract), Some(PASSWORD), |_| {}).unwrap();
    assert_eq!((summary.files, summary.errors.len()), (0, 1));
    assert!(!out.join("f").exists());
}

const CHECK: [u8; 12] = [0x17, 0x41, 0x9a, 0xfa, 0xa6, 0x98, 0xfd, 0x50, 0xa8, 0x4b, 0x9b, 0x32];

fn checked_record(check: [u8; 12]) -> Vec<u8> {
    let mut extra = encryption_record(false);
    extra[0] += 12;
    extra[3] = 1;
    extra.extend(check);
    extra
}

#[test]
fn typed_password_evidence_belongs_to_the_member_that_was_checked() {
    use zipfast::error::{RarFailure, RarIntegrityReason, RarPasswordEvidence, RarScope, RarVerifierUnavailable};
    use zipfast::extract::{RarOutcome, run_rar_with_outcomes};

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.rar");
    let out = dir.path().join("out");
    let plain = b"password evidence";
    let encrypted = encrypted_data(plain, 0);
    let mut damaged_check = CHECK;
    damaged_check[11] ^= 1;
    let specs = [
        (
            FileSpec {
                size: Some(plain.len() as u64),
                extra: checked_record(CHECK),
                ..FileSpec::new("trusted", &encrypted)
            },
            crc32fast::hash(plain),
        ),
        (
            FileSpec {
                size: Some(plain.len() as u64),
                extra: encryption_record(false),
                ..FileSpec::new("absent", &encrypted)
            },
            crc32fast::hash(plain),
        ),
        (
            FileSpec {
                size: Some(plain.len() as u64),
                extra: checked_record(damaged_check),
                ..FileSpec::new("damaged-check", &encrypted)
            },
            crc32fast::hash(plain),
        ),
        (
            FileSpec {
                size: Some(plain.len() as u64),
                extra: checked_record(CHECK),
                ..FileSpec::new("damaged-data", &encrypted)
            },
            crc32fast::hash(plain) ^ 1,
        ),
        (FileSpec::new("plain", plain), crc32fast::hash(plain)),
    ];
    fs::write(&archive, archive_with(&specs, false)).unwrap();
    for threads in [1, 4] {
        for password in [Some(PASSWORD), Some("wrong-password"), None, Some("")] {
            let opts = Options { threads: Some(threads), ..options(&out, Mode::Test) };
            let mut count = 0;
            let summary = run_rar_with_outcomes(&archive, &opts, password, |event| {
                let i = event.entry.index.unwrap();
                assert_eq!(i, count);
                count += 1;
                match &event.outcome {
                    RarOutcome::Verified { checks, .. } => {
                        assert!(i == 4 || password == Some(PASSWORD));
                        assert_eq!(
                            checks.password,
                            match i {
                                0 => RarPasswordEvidence::VerifierMatched,
                                1 => RarPasswordEvidence::VerifierUnavailable(RarVerifierUnavailable::Absent),
                                2 => RarPasswordEvidence::VerifierUnavailable(
                                    RarVerifierUnavailable::CheckChecksumMismatch
                                ),
                                4 => RarPasswordEvidence::NotEncrypted,
                                _ => panic!("damaged member verified"),
                            }
                        );
                    }
                    RarOutcome::Failed(cause) => match (password, i, cause.as_ref()) {
                        (
                            None | Some(""),
                            0..=3,
                            RarFailure::PasswordRequired { scope: RarScope::Member { index, .. }, .. },
                        )
                        | (
                            Some("wrong-password"),
                            0 | 3,
                            RarFailure::WrongPassword { scope: RarScope::Member { index, .. }, .. },
                        ) => {
                            assert_eq!(*index, Some(i));
                        }
                        (
                            Some("wrong-password"),
                            1 | 2,
                            RarFailure::EncryptedIntegrity {
                                reason: RarIntegrityReason::FinalChecks { crc32: true, .. },
                                verifier,
                                ..
                            },
                        ) => {
                            assert_eq!(
                                *verifier,
                                if i == 1 {
                                    RarVerifierUnavailable::Absent
                                } else {
                                    RarVerifierUnavailable::CheckChecksumMismatch
                                }
                            );
                        }
                        (
                            Some(PASSWORD),
                            3,
                            RarFailure::Integrity {
                                reason: RarIntegrityReason::FinalChecks { crc32: true, .. },
                                password: RarPasswordEvidence::VerifierMatched,
                                ..
                            },
                        ) => {}
                        _ => panic!("unexpected password outcome {event:?}"),
                    },
                    _ => panic!("unexpected outcome {event:?}"),
                }
            })
            .unwrap();
            assert_eq!(count, 5);
            assert_eq!((summary.files, summary.failed), if password == Some(PASSWORD) { (4, 1) } else { (1, 4) });
        }
    }
}

#[test]
fn encrypted_header_failures_identify_scope_and_verifier_evidence() {
    use zipfast::error::{RarFailure, RarIntegrityReason, RarPasswordEvidence, RarResource, RarScope, RarUnsupported};
    use zipfast::extract::run_rar_with_outcomes;

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("encrypted.rar");
    let opts = options(dir.path(), Mode::Test);
    let key = derive_rar5_key_and_hash_key(PASSWORD, KDF_COUNT, &SALT, None).unwrap().0;
    let mut params = vec![0, 1, KDF_COUNT];
    params.extend(SALT);
    params.extend(CHECK);

    let write_archive = |params: &[u8], corrupt: bool| {
        let mut bytes = SIG.to_vec();
        bytes.extend(block(4, 0, params, &[], &[], false));
        let mut main = main_block(false, None);
        if corrupt {
            main[0] ^= 1; // corruption is in the decrypted header CRC, with valid plaintext framing
        }
        for mut header in [main, end_block(false)] {
            header.resize(header.len().next_multiple_of(16), 0);
            bytes.extend(IV);
            bytes.extend(encrypt_cbc(&key, &IV, &header).unwrap());
        }
        fs::write(&archive, bytes).unwrap();
    };

    write_archive(&params, false);
    for (password, wrong) in [(None, false), (Some(""), false), (Some("wrong"), true)] {
        let err = run_rar_with_outcomes(&archive, &opts, password, |_| panic!("no member exists")).unwrap_err();
        let scope = match (wrong, err.failure.as_ref()) {
            (false, RarFailure::PasswordRequired { scope }) | (true, RarFailure::WrongPassword { scope }) => scope,
            _ => panic!("unexpected header error {err:?}"),
        };
        assert!(matches!(scope, RarScope::Header { volume, .. } if volume == &archive));
        assert!(err.entry.is_none());
        assert_eq!(err.partial.volumes, 0);
    }
    let result = run_rar_with_outcomes(&archive, &opts, Some(PASSWORD), |_| panic!("no member exists")).unwrap();
    assert_eq!((result.volumes, result.files), (1, 0));

    write_archive(&params, true);
    let err = run_rar_with_outcomes(&archive, &opts, Some(PASSWORD), |_| panic!("no member exists")).unwrap_err();
    assert!(matches!(
        err.failure.as_ref(),
        RarFailure::Integrity {
            reason: RarIntegrityReason::HeaderCrc,
            password: RarPasswordEvidence::VerifierMatched,
            ..
        }
    ));

    write_archive(&params[..params.len() - 1], false);
    let err = run_rar_with_outcomes(&archive, &opts, None, |_| panic!("no member exists")).unwrap_err();
    assert!(matches!(
        err.failure.as_ref(),
        RarFailure::Integrity { reason: RarIntegrityReason::MalformedEncryptionRecord, .. }
    ));

    params[2] = 25;
    write_archive(&params, false);
    let err = run_rar_with_outcomes(&archive, &opts, None, |_| panic!("no member exists")).unwrap_err();
    assert!(matches!(
        err.failure.as_ref(),
        RarFailure::Limit { resource: RarResource::KdfExponent, requested: Some(25), allowed: Some(24), .. }
    ));

    params[0] = 2;
    write_archive(&params, false);
    let err = run_rar_with_outcomes(&archive, &opts, None, |_| panic!("no member exists")).unwrap_err();
    assert!(matches!(err.failure.as_ref(), RarFailure::Unsupported(RarUnsupported::EncryptionVersion(2))));
}

#[test]
fn packed_piece_integrity_identifies_when_password_can_affect_the_check() {
    use zipfast::error::{RarFailure, RarIntegrityReason, RarVerifierUnavailable};
    use zipfast::extract::{RarOutcome, run_rar_with_outcomes};

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.part1.rar");
    let plain = b"checks before split";
    let encrypted = encrypted_data(plain, 0);
    for keyed in [false, true] {
        let spec = FileSpec {
            size: Some(plain.len() as u64),
            extra: encryption_record(keyed),
            ..FileSpec::new("f", &encrypted)
        };
        let (first, last) = encrypted.split_at(16);
        let checksum = if keyed { encrypted_crc(first) } else { crc32fast::hash(first) };
        for (i, data, crc) in [(0, first, checksum ^ 1), (1, last, crc32fast::hash(plain))] {
            let mut volume = SIG.to_vec();
            volume.extend(main_block(true, (i != 0).then_some(i)));
            volume.extend(file_block(&spec, data, crc, i != 0, i == 0));
            volume.extend(end_block(i == 0));
            fs::write(dir.path().join(format!("test.part{}.rar", i + 1)), volume).unwrap();
        }
        let out = dir.path().join("out");
        let mut seen = 0;
        let summary = run_rar_with_outcomes(&archive, &options(&out, Mode::Extract), Some(PASSWORD), |event| {
            seen += 1;
            assert_eq!(event.entry.index, Some(0));
            let RarOutcome::Failed(failure) = &event.outcome else { panic!("damaged piece verified") };
            match (keyed, failure.as_ref()) {
                (
                    false,
                    RarFailure::Integrity {
                        reason: RarIntegrityReason::PackedPiece { crc32: true, keyed: false, .. },
                        ..
                    },
                )
                | (
                    true,
                    RarFailure::EncryptedIntegrity {
                        reason: RarIntegrityReason::PackedPiece { crc32: true, keyed: true, .. },
                        verifier: RarVerifierUnavailable::Absent,
                        ..
                    },
                ) => {}
                _ => panic!("unexpected piece failure {event:?}"),
            }
        })
        .unwrap();
        assert_eq!((seen, summary.failed, summary.volumes), (1, 1, 2));
        assert!(!out.join("f").exists());
    }
}

#[test]
fn truncated_verifier_in_continuation_preserves_destination() {
    use zipfast::error::{RarFailure, RarIntegrityReason};
    use zipfast::extract::{RarOutcome, run_rar_with_outcomes};

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("test.part1.rar");
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("f"), b"original").unwrap();
    let plain = b"two encrypted pieces";
    let encrypted = encrypted_data(plain, 0);
    let first =
        FileSpec { size: Some(plain.len() as u64), extra: encryption_record(false), ..FileSpec::new("f", &encrypted) };
    let mut extra = encryption_record(false);
    extra[3] = 1; // The continuation declares a check without providing it.
    let last = FileSpec { extra, size: first.size, ..FileSpec::new("f", &encrypted) };
    split_archive(dir.path(), &first, &last, 16, crc32fast::hash(plain));

    let opts = options(&out, Mode::Extract);
    let legacy = extract::run_with_password(&archive, &opts, Some(PASSWORD), |_| {}).unwrap();
    assert_eq!(legacy.errors, ["f: encrypted (password required)"]);
    let mut seen = 0;
    let summary = run_rar_with_outcomes(&archive, &opts, Some(PASSWORD), |event| {
        seen += 1;
        assert_eq!(event.entry.index, Some(0));
        assert!(matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(failure.as_ref(),
            RarFailure::Integrity { reason: RarIntegrityReason::MalformedEncryptionRecord, .. }
        )));
    })
    .unwrap();
    assert_eq!((seen, summary.failed, summary.files), (1, 1, 0));
    assert_eq!(fs::read(out.join("f")).unwrap(), b"original");
    assert_eq!(fs::read_dir(out).unwrap().count(), 1);
}
