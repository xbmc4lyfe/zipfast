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

mod common;

use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::testenc::Op;

fn opts(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-packed-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn text_ops(text: &[u8]) -> Vec<Op> {
    let mut ops: Vec<Op> = text.iter().map(|&b| Op::Lit(b)).collect();
    ops.push(Op::Match(40, text.len() as u64));
    ops.push(Op::Match(500, 1));
    ops
}

fn spec<'a>(name: &'a str, packed: &'a [u8], size: usize) -> FileSpec<'a> {
    FileSpec { method: 3, size: Some(size as u64), ..FileSpec::new(name, packed) }
}

#[test]
fn extracts_a_compressed_file() {
    let dir = tmp("one");
    let (stream, plain) = packed("f", &text_ops(b"compressed with RAR 5.0 "));
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&[(spec("f.txt", &stream, plain.len()), crc32fast::hash(&plain))], false)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), plain);
}

#[test]
fn a_wrong_crc_on_a_compressed_file_fails_and_removes_it() {
    let dir = tmp("crc");
    let (stream, plain) = packed("f", &text_ops(b"abc"));
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&[(spec("f", &stream, plain.len()), 1234)], false)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1);
    assert!(!out.join("f").exists());
}

#[test]
fn corrupt_packed_data_is_reported_per_file() {
    let dir = tmp("corrupt");
    let (mut stream, plain) = packed("f", &text_ops(b"abc"));
    stream[1] ^= 0xff; // the block header checksum
    let ok = b"fine".to_vec();
    let arc = dir.join("t.rar");
    fs::write(
        &arc,
        archive_with(
            &[
                (spec("bad", &stream, plain.len()), crc32fast::hash(&plain)),
                (FileSpec::new("ok", &ok), crc32fast::hash(&ok)),
            ],
            false,
        ),
    )
    .unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (1, 1), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("ok")).unwrap(), b"fine");
}

#[test]
fn a_compressed_file_split_across_volumes() {
    let dir = tmp("split");
    let mut ops: Vec<Op> = (0..20_000u32).map(|i| Op::Lit((i * 31 % 253) as u8)).collect();
    ops.push(Op::Match(4000, 19_000));
    let (stream, plain) = packed("f", &ops);
    let cut = stream.len() / 3;
    let parts = [&stream[..cut], &stream[cut..2 * cut], &stream[2 * cut..]];
    let s = spec("movie.mkv", &stream, plain.len());
    for (i, part) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        let mut vol = SIG.to_vec();
        vol.extend(main_block(true, if i == 0 { None } else { Some(i as u64) }));
        // non-final parts carry the CRC of their own packed bytes
        let crc = if last { crc32fast::hash(&plain) } else { crc32fast::hash(part) };
        vol.extend(file_block(&s, part, crc, i > 0, !last));
        vol.extend(end_block(!last));
        fs::write(dir.join(format!("set.part{}.rar", i + 1)), vol).unwrap();
    }
    let out = dir.join("out");
    let r = extract::run(&dir.join("set.part1.rar"), &opts(&out), |_| {}).unwrap();
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    assert_eq!(fs::read(out.join("movie.mkv")).unwrap(), plain);
    let mut selected = Vec::new();
    extract::SelectedEntry::open(&dir.join("set.part1.rar"), 0, None, 1 << 20)
        .unwrap()
        .read(None, |bytes| {
            selected.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(selected, plain);
}

/// Two files in one solid stream: the second refers back into the first.
fn solid_pair() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let first_ops: Vec<Op> = b"shared words in a solid archive ".iter().map(|&b| Op::Lit(b)).collect();
    let (s1, p1) = packed("a", &first_ops);
    // the second file is one match into the first file's bytes, then a literal
    let second_ops = [Op::Match(20, 32), Op::Lit(b'!')];
    let s2 = zipfast::rar5::testenc::block(&second_ops, true, true);
    let p2 = {
        let mut all = first_ops.clone();
        all.extend(second_ops.iter().cloned());
        zipfast::rar5::testenc::model(&all)[p1.len()..].to_vec()
    };
    let a = FileSpec { method: 3, size: Some(p1.len() as u64), ..FileSpec::new("a", &s1) };
    let b = FileSpec { method: 3, size: Some(p2.len() as u64), solid: true, ..FileSpec::new("b", &s2) };
    let arc = archive_with(&[(a, crc32fast::hash(&p1)), (b, crc32fast::hash(&p2))], true);
    (arc, p1, p2)
}

#[test]
fn solid_archives_carry_the_window_between_files() {
    let dir = tmp("solid");
    let (arc_bytes, p1, p2) = solid_pair();
    let arc = dir.join("t.rar");
    fs::write(&arc, arc_bytes).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("a")).unwrap(), p1);
    assert_eq!(fs::read(out.join("b")).unwrap(), p2);
    let mut selected = Vec::new();
    extract::SelectedEntry::open(&arc, 1, None, 1 << 20)
        .unwrap()
        .read(None, |bytes| {
            selected.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(selected, p2);
}

#[test]
fn a_skipped_file_in_a_solid_archive_is_still_decoded() {
    let dir = tmp("solid-skip");
    let (arc_bytes, _, p2) = solid_pair();
    let arc = dir.join("t.rar");
    fs::write(&arc, arc_bytes).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("a"), b"keep me").unwrap();
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("a")).unwrap(), b"keep me");
    assert_eq!(fs::read(out.join("b")).unwrap(), p2);
}

/// The same runs with every compressed file decoded on worker threads.
fn par_opts(dest: &Path) -> Options {
    Options { threads: Some(4), parallel_min: Some(0), ..opts(dest) }
}

fn varied(n: u32) -> Vec<u8> {
    let mut data = Vec::new();
    let mut x = 5u32;
    for i in 0..n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        if i % 800 < 500 {
            data.extend_from_slice(format!("row {} col {} ", i % 61, (x >> 21) % 11).as_bytes());
        } else {
            data.push((x >> 16) as u8);
        }
    }
    data
}

#[test]
fn workers_decode_a_many_block_file_split_across_volumes() {
    let dir = tmp("par-split");
    let plain = varied(40_000);
    let ops = zipfast::rar5::testenc::lz(&plain, 1 << 16, 4);
    let stream = zipfast::rar5::testenc::tuned_stream(&ops, 1500);
    // cuts that fall inside blocks
    let (a, b) = (stream.len() / 3 + 7, 2 * stream.len() / 3 + 3);
    let parts = [&stream[..a], &stream[a..b], &stream[b..]];
    let s = spec("movie.mkv", &stream, plain.len());
    for (i, part) in parts.iter().enumerate() {
        let last = i == parts.len() - 1;
        let mut vol = SIG.to_vec();
        vol.extend(main_block(true, if i == 0 { None } else { Some(i as u64) }));
        let crc = if last { crc32fast::hash(&plain) } else { crc32fast::hash(part) };
        vol.extend(file_block(&s, part, crc, i > 0, !last));
        vol.extend(end_block(!last));
        fs::write(dir.join(format!("set.part{}.rar", i + 1)), vol).unwrap();
    }
    for (name, o) in [("serial", opts as fn(&Path) -> Options), ("workers", par_opts)] {
        let out = dir.join(name);
        let r = extract::run(&dir.join("set.part1.rar"), &o(&out), |_| {}).unwrap();
        assert!(r.errors.is_empty(), "{name}: {:?}", r.errors);
        assert_eq!(fs::read(out.join("movie.mkv")).unwrap(), plain, "{name}");
    }
}

#[test]
fn workers_handle_solid_archives_and_damaged_files() {
    let dir = tmp("par-solid");
    let (arc_bytes, p1, p2) = solid_pair();
    let arc = dir.join("t.rar");
    fs::write(&arc, arc_bytes).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &par_opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("a")).unwrap(), p1);
    assert_eq!(fs::read(out.join("b")).unwrap(), p2);

    // a damaged many-block file, then a good one: the first fails alone, the same way on both paths
    let plain = varied(20_000);
    let ops = zipfast::rar5::testenc::lz(&plain, 1 << 16, 4);
    let mut bad = zipfast::rar5::testenc::tuned_stream(&ops, 1000);
    let mid = bad.len() / 2;
    bad[mid] ^= 0x5a;
    let good = varied(3_000);
    let good_ops = zipfast::rar5::testenc::lz(&good, 1 << 16, 4);
    let good_stream = zipfast::rar5::testenc::tuned_stream(&good_ops, 1000);
    let arc = dir.join("two.rar");
    fs::write(
        &arc,
        archive_with(
            &[
                (spec("bad", &bad, plain.len()), crc32fast::hash(&plain)),
                (spec("good", &good_stream, good.len()), crc32fast::hash(&good)),
            ],
            false,
        ),
    )
    .unwrap();
    let mut seen = Vec::new();
    for (name, o) in [("serial", opts as fn(&Path) -> Options), ("workers", par_opts)] {
        let out = dir.join(format!("two-{name}"));
        let s = extract::run(&arc, &o(&out), |_| {}).unwrap();
        assert_eq!((s.files, s.errors.len()), (1, 1), "{name}: {:?}", s.errors);
        assert_eq!(fs::read(out.join("good")).unwrap(), good, "{name}");
        assert!(!out.join("bad").exists(), "{name}");
        seen.push(s.errors);
    }
    assert_eq!(seen[0], seen[1]);
}

#[test]
fn selected_solid_rar_counts_packed_and_decoded_prerequisites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("solid.rar");
    let (arc, _, _) = solid_pair();
    fs::write(&path, arc).unwrap();
    let listed = extract::list(&path).unwrap();
    let packed_limit = listed[0].packed + listed[1].packed;
    assert!(packed_limit > listed[0].size + listed[1].size);
    extract::SelectedEntry::open(&path, 1, None, packed_limit).unwrap().read(None, |_| Ok(())).unwrap();
    let error = extract::SelectedEntry::open(&path, 1, None, packed_limit - 1)
        .unwrap()
        .read(None, |_| panic!("decoded the selected member beyond the packed budget"))
        .unwrap_err();
    assert!(error.to_string().contains("packed byte limit"), "{error}");

    let first = [Op::Lit(b'x'), Op::Match(400, 1)];
    let (s1, p1) = packed("a", &first);
    let second = [Op::Match(400, 1)];
    let s2 = zipfast::rar5::testenc::block(&second, true, true);
    let p2 = [b'x'; 400];
    let a = spec("same", &s1, p1.len());
    let b = FileSpec { solid: true, ..spec("same", &s2, p2.len()) };
    fs::write(&path, archive_with(&[(a, crc32fast::hash(&p1)), (b, crc32fast::hash(&p2))], true)).unwrap();
    for limit in [800, 801] {
        let entry = extract::SelectedEntry::open(&path, 1, None, limit).unwrap();
        assert_eq!(entry.name(), "same");
        let mut actual = Vec::new();
        let result = entry.read(None, |bytes| {
            actual.extend_from_slice(bytes);
            Ok(())
        });
        if limit == 801 {
            result.unwrap();
            assert_eq!(actual, p2);
        } else {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("decoded byte limit"), "{error}");
            assert!(actual.len() <= 399);
        }
    }
}

#[test]
fn skipping_an_existing_encrypted_member_preserves_solid_history() {
    let dir = tmp("encrypted-solid-skip");
    let first: Vec<_> = b"shared words in a solid archive ".iter().copied().map(Op::Lit).collect();
    let second = [Op::Match(20, 32), Op::Lit(b'!')];
    let (mut packed_first, plain_first) = packed("a", &first);
    let packed_second = zipfast::rar5::testenc::block(&second, true, true);
    let plain = zipfast::rar5::testenc::model(&[first.as_slice(), &second].concat());
    let plain_second = &plain[plain_first.len()..];
    let salt = [1; 16];
    let iv = [2; 16];
    let key = zipfast::crypto::derive_rar5_key("fixture", 1, &salt, None).unwrap();
    packed_first.resize(packed_first.len().next_multiple_of(16), 0);
    let encrypted = zipfast::crypto::encrypt_cbc(&key, &iv, &packed_first).unwrap();
    let mut record = vec![1, 0, 0, 1];
    record.extend(salt);
    record.extend(iv);
    let mut extra = Vec::new();
    vint(record.len() as u64, &mut extra);
    extra.extend(record);
    let a = FileSpec { method: 3, size: Some(plain_first.len() as u64), extra, ..FileSpec::new("a", &encrypted) };
    let b = FileSpec {
        method: 3,
        size: Some(plain_second.len() as u64),
        solid: true,
        ..FileSpec::new("b", &packed_second)
    };
    let archive = dir.join("solid.rar");
    let write_archive = |first_crc| {
        // The helper only borrows these specs to build the two file blocks.
        let mut bytes = SIG.to_vec();
        bytes.extend(main_block_flags(false, None, true));
        bytes.extend(file_block(&a, a.data, first_crc, false, false));
        bytes.extend(file_block(&b, b.data, crc32fast::hash(plain_second), false, false));
        bytes.extend(end_block(false));
        fs::write(&archive, bytes).unwrap();
    };
    let crc = crc32fast::hash(&plain_first);
    write_archive(crc);
    let out = dir.join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("a"), b"Keep this file.").unwrap();
    let summary = extract::run_with_password(&archive, &opts(&out), Some("fixture"), |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(summary.skipped, 1);
    assert_eq!(fs::read(out.join("a")).unwrap(), b"Keep this file.");
    assert_eq!(fs::read(out.join("b")).unwrap(), plain_second);

    let mut selected = Vec::new();
    extract::SelectedEntry::open(&archive, 1, Some("fixture"), 1 << 20)
        .unwrap()
        .read(Some("fixture"), |bytes| {
            selected.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(selected, plain_second);

    write_archive(crc ^ 1);
    let error = extract::SelectedEntry::open(&archive, 1, Some("fixture"), 1 << 20)
        .unwrap()
        .read(Some("fixture"), |_| panic!("decoded the selection after a bad solid prerequisite"))
        .unwrap_err();
    assert!(error.to_string().contains("checksum error"), "{error}");
}

#[test]
fn selected_rar_refuses_a_window_larger_than_256_mib() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("window.rar");
    let (packed, plain) = packed("f", &[Op::Lit(b'x')]);
    // A dictionary power of 12 encodes 512 MiB. The fixture writer shifts
    // the combined method and dictionary bits seven places into the header.
    let member = FileSpec { method: 3 | (12 << 3), ..spec("f", &packed, plain.len()) };
    fs::write(&path, archive_with(&[(member, crc32fast::hash(&plain))], true)).unwrap();
    let error = extract::SelectedEntry::open(&path, 0, None, 1 << 20)
        .unwrap()
        .read(None, |_| panic!("decoded a member with an oversized window"))
        .unwrap_err();
    assert!(matches!(error, zipfast::Error::Unsupported(message) if message.contains("256 MiB")));
}

#[test]
fn selected_rar_skips_unrelated_compressed_members_of_a_solid_archive() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("independent.rar");
    let (before, first) = packed("a", &[Op::Lit(b'a')]);
    let (selected, second) = packed("b", &[Op::Lit(b'b')]);
    let a = spec("same", &before, first.len());
    let b = spec("same", &selected, second.len());
    fs::write(&path, archive_with(&[(a, 0), (b, crc32fast::hash(&second))], true)).unwrap();
    let entry = extract::SelectedEntry::open(&path, 1, None, selected.len() as u64).unwrap();
    let mut bytes = Vec::new();
    entry
        .read(None, |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(bytes, b"b");
}

#[test]
fn selected_rar_cancellation_stops_between_packed_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel.rar");
    let plain = vec![b'x'; 3 << 20];
    fs::write(&path, archive_with(&[(FileSpec::new("f", &plain), crc32fast::hash(&plain))], false)).unwrap();
    let cancel = extract::Cancellation::default();
    let entry = extract::SelectedEntry::open_cancelable(&path, 0, None, plain.len() as u64, cancel.clone()).unwrap();
    let mut received = 0;
    let error = entry
        .read(None, |chunk| {
            received += chunk.len();
            cancel.cancel();
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(error, zipfast::Error::Io(error) if error.kind() == std::io::ErrorKind::ConnectionAborted));
    assert!((1..plain.len()).contains(&received));
}
