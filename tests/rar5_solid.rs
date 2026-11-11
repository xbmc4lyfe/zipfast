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

//! Solid archives on several threads: each file's blocks go to the decoder's workers behind the files before it,
//! and everything comes out, and fails, as it does one file at a time.
mod common;

use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{self, Mode, Options, Overwrite, Summary};
use zipfast::rar5::testenc::{self, Op};

fn opts(dest: &Path, threads: usize) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(threads),
        parallel_min: None,
    }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-solid-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn noise_ops(n: usize, seed: u64) -> Vec<Op> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            Op::Lit((x >> 24) as u8)
        })
        .collect()
}

/// One solid stream cut into files: (packed, plain) for each. Some files copy from the ones before, some keep the
/// (fixed) tables before them, a few are big enough to take several runs of blocks.
fn solid_stream(n: usize, big: bool) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut all: Vec<Op> = Vec::new();
    let mut out = Vec::new();
    let mut at = 0;
    for i in 0..n {
        let ops = match i % 5 {
            0 => noise_ops(200 + i * 7, i as u64),
            1 if big && i % 10 == 1 => noise_ops(300_000, i as u64),
            2 if at > 400 => vec![Op::Match(250, 400), Op::Lit(b'#'), Op::Rep(0, 30)],
            3 => format!("file {i} says hello ").bytes().map(Op::Lit).collect(),
            _ => noise_ops(1_000, i as u64),
        };
        let stream =
            if ops.len() > 2_000 { testenc::tuned_stream(&ops, 4_000) } else { testenc::block(&ops, i % 4 != 1, true) };
        all.extend(ops);
        let plain = testenc::model(&all);
        out.push((stream, plain[at..].to_vec()));
        at = plain.len();
    }
    out
}

/// A file's name, packed bytes, plain bytes and the CRC its header states.
type File = (String, Vec<u8>, Vec<u8>, u32);

fn archive(files: &[File]) -> Vec<u8> {
    let specs: Vec<(FileSpec<'_>, u32)> = files
        .iter()
        .enumerate()
        .map(|(i, (name, stream, plain, crc))| {
            let spec =
                FileSpec { method: 3, size: Some(plain.len() as u64), solid: i > 0, ..FileSpec::new(name, stream) };
            (spec, *crc)
        })
        .collect();
    archive_with(&specs, true)
}

fn named(stream: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<File> {
    stream
        .into_iter()
        .enumerate()
        .map(|(i, (s, p))| {
            let crc = crc32fast::hash(&p);
            (format!("d{}/f{i:02}.bin", i % 3), s, p, crc)
        })
        .collect()
}

fn run(arc: &Path, o: &Options) -> (Summary, Vec<String>) {
    let mut lines = Vec::new();
    let s = extract::run(arc, o, |l| lines.push(l.to_string())).unwrap();
    (s, lines)
}

#[test]
fn a_solid_archive_comes_out_the_same_on_one_thread_and_on_several() {
    let dir = tmp("same");
    let files = named(solid_stream(40, true));
    let arc = dir.join("s.rar");
    fs::write(&arc, archive(&files)).unwrap();
    for (name, threads) in [("one", 1), ("four", 4)] {
        let out = dir.join(name);
        let (s, lines) = run(&arc, &opts(&out, threads));
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert!(lines.is_empty(), "{name}: {lines:?}");
        assert_eq!(s.files, files.len() as u64, "{name}");
        for (n, _, plain, _) in &files {
            assert!(fs::read(out.join(n)).unwrap() == *plain, "{name}: {n}");
        }
    }
    let t = run(&arc, &Options { mode: Mode::Test, ..opts(&dir.join("t"), 4) }).0;
    assert!(t.errors.is_empty() && t.files == files.len() as u64, "{:?}", t.errors);
}

#[test]
fn failures_in_a_solid_archive_are_reported_alike_and_in_order() {
    let dir = tmp("fail");
    let files = named(solid_stream(30, true));
    let mut cases: Vec<(&str, Vec<File>)> = Vec::new();
    // a wrong checksum: that file alone fails
    let mut c = files.clone();
    c[7].3 ^= 1;
    c[19].3 ^= 1;
    cases.push(("crc", c));
    // damaged packed data: the file and every one after it
    let mut c = files.clone();
    let n = c[11].1.len();
    c[11].1[n / 2] ^= 0xff;
    c[11].1[n / 2 + 1] ^= 0xff;
    cases.push(("damaged", c));
    // packed data that ends partway through a block
    let mut c = files.clone();
    let n = c[5].1.len();
    c[5].1.truncate(n - 3);
    cases.push(("cut", c));
    // more files than are held open at once, with trouble past that many
    let mut c = named(solid_stream(200, false));
    c[100].3 ^= 1;
    c[150].3 ^= 1;
    cases.push(("many-crc", c.clone()));
    for k in [70, 170] {
        let n = c[k].1.len();
        c[k].1[n / 2] ^= 0xff;
        c[k].1[n / 2 + 1] ^= 0xff;
    }
    cases.push(("many-damaged", c));
    for (what, c) in &cases {
        let arc = dir.join(format!("{what}.rar"));
        fs::write(&arc, archive(c)).unwrap();
        let one = run(&arc, &opts(&dir.join(format!("{what}-1")), 1));
        let four = run(&arc, &opts(&dir.join(format!("{what}-4")), 4));
        assert!(!one.0.errors.is_empty(), "{what}");
        assert_eq!(one.1, four.1, "{what}: reports");
        assert_eq!((one.0.files, one.0.bytes), (four.0.files, four.0.bytes), "{what}");
        for (n, _, plain, _) in c {
            let a = fs::read(dir.join(format!("{what}-1")).join(n)).ok();
            let b = fs::read(dir.join(format!("{what}-4")).join(n)).ok();
            assert_eq!(a.is_some(), b.is_some(), "{what}: {n}");
            if let Some(b) = b {
                assert!(b == *plain, "{what}: {n}");
            }
        }
    }
}

#[test]
fn skipped_and_repeated_files_keep_their_place_in_a_solid_archive() {
    let dir = tmp("skip");
    let mut files = named(solid_stream(20, true));
    // the same name twice: with overwriting on, the later one wins
    files[9].0 = files[4].0.clone();
    let arc = dir.join("s.rar");
    fs::write(&arc, archive(&files)).unwrap();
    let mut seen = Vec::new();
    for (name, threads) in [("one", 1), ("four", 4)] {
        let out = dir.join(name);
        fs::create_dir_all(out.join("d0")).unwrap();
        // already there: skipped, but still decoded for the files after it
        fs::write(out.join(&files[3].0), b"keep").unwrap();
        let (s, lines) = run(&arc, &opts(&out, threads));
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert_eq!(fs::read(out.join(&files[3].0)).unwrap(), b"keep");
        assert!(fs::read(out.join(&files[12].0)).unwrap() == files[12].2);
        let o = Options { overwrite: Overwrite::Always, ..opts(&out, threads) };
        let (s2, _) = run(&arc, &o);
        assert!(s2.errors.is_empty(), "{name}: {:?}", s2.errors);
        assert!(fs::read(out.join(&files[4].0)).unwrap() == files[9].2, "{name}: the later copy wins");
        assert!(fs::read(out.join(&files[3].0)).unwrap() == files[3].2);
        seen.push(lines);
    }
    assert_eq!(seen[0], seen[1]);
}

#[test]
fn a_repeated_name_waits_for_a_queued_copy_from_an_earlier_stream() {
    let dir = tmp("restart");
    // a, then b starting a stream of its own with a bad checksum, then b again carrying that stream on
    let first = named(solid_stream(1, false)).remove(0);
    let second = named(solid_stream(2, false));
    let mut files = vec![first];
    files.extend(second);
    files[1].0 = "b".into();
    files[2].0 = "b".into();
    files[1].3 ^= 1;
    let specs: Vec<(FileSpec<'_>, u32)> = files
        .iter()
        .enumerate()
        .map(|(i, (name, stream, plain, crc))| {
            let spec =
                FileSpec { method: 3, size: Some(plain.len() as u64), solid: i == 2, ..FileSpec::new(name, stream) };
            (spec, *crc)
        })
        .collect();
    let arc = dir.join("s.rar");
    fs::write(&arc, archive_with(&specs, true)).unwrap();
    for (name, threads) in [("one", 1), ("four", 4)] {
        let out = dir.join(name);
        let o = Options { overwrite: Overwrite::Always, ..opts(&out, threads) };
        let (s, _) = run(&arc, &o);
        assert_eq!((s.files, s.errors.len()), (2, 1), "{name}: {:?}", s.errors);
        assert!(fs::read(out.join("b")).unwrap() == files[2].2, "{name}: the later b is kept");
    }
}

#[test]
fn a_stored_file_among_queued_ones_reports_after_them() {
    let dir = tmp("stored");
    let mut files = named(solid_stream(12, false));
    files[4].3 ^= 1;
    let stored = b"stored between packed files".to_vec();
    let mut specs: Vec<(FileSpec<'_>, u32)> = files
        .iter()
        .enumerate()
        .map(|(i, (name, stream, plain, crc))| {
            let spec =
                FileSpec { method: 3, size: Some(plain.len() as u64), solid: i > 0, ..FileSpec::new(name, stream) };
            (spec, *crc)
        })
        .collect();
    // a stored file with a wrong checksum after the bad packed one, and a folder
    specs.insert(6, (FileSpec::new("plain.txt", &stored), crc32fast::hash(&stored) ^ 1));
    specs.insert(8, (FileSpec { dir: true, ..FileSpec::new("d0/sub", b"") }, 0));
    let arc = dir.join("s.rar");
    fs::write(&arc, archive_with(&specs, true)).unwrap();
    let mut seen = Vec::new();
    for (name, threads) in [("one", 1), ("four", 4)] {
        let out = dir.join(name);
        let (s, lines) = run(&arc, &opts(&out, threads));
        assert_eq!(s.errors.len(), 2, "{name}: {:?}", s.errors);
        assert!(lines[0].contains(&files[4].0) && lines[1].contains("plain.txt"), "{name}: {lines:?}");
        assert!(!out.join(&files[4].0).exists() && !out.join("plain.txt").exists(), "{name}");
        assert!(out.join("d0/sub").is_dir(), "{name}");
        for (i, (n, _, plain, _)) in files.iter().enumerate() {
            if i != 4 {
                assert!(fs::read(out.join(n)).unwrap() == *plain, "{name}: {n}");
            }
        }
        seen.push(lines);
    }
    assert_eq!(seen[0], seen[1]);
}
