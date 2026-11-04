mod common;

use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::testenc::Op;

fn opts(dest: &Path) -> Options {
    Options { mode: Mode::Extract, dest: dest.to_path_buf(), overwrite: Overwrite::Skip, flatten: false }
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
