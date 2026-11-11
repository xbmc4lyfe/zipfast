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
