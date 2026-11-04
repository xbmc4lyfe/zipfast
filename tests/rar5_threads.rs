//! Work spread over threads in archives that aren't solid: small files on workers, big stored data in pieces.
mod common;

use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::testenc::Op;

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
    let dir = std::env::temp_dir().join(format!("zipfast-threads-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes that don't repeat in any short stretch.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn many_small_files_come_out_whole_and_failures_are_reported_in_order() {
    let dir = tmp("many");
    let mut plains = Vec::new();
    let mut streams = Vec::new();
    for i in 0..60u32 {
        let text: Vec<u8> = format!("file {i} says hello; ").bytes().cycle().take(500 + i as usize * 37).collect();
        let mut ops: Vec<Op> = text.iter().map(|&b| Op::Lit(b)).collect();
        ops.push(Op::Match(100 + i, 21));
        let (stream, plain) = packed("f", &ops);
        streams.push(stream);
        plains.push(plain);
    }
    let names: Vec<String> = (0..60).map(|i| format!("d/f{i:02}.txt")).collect();
    let stored: Vec<Vec<u8>> = (0..20).map(|i| noise(3000 + i * 11, i as u64)).collect();
    let stored_names: Vec<String> = (0..20).map(|i| format!("s{i:02}.bin")).collect();
    let mut files = Vec::new();
    for i in 0..60 {
        // every tenth packed file has a wrong CRC
        let crc = if i % 10 == 3 { 1 } else { crc32fast::hash(&plains[i]) };
        let spec = FileSpec { method: 3, size: Some(plains[i].len() as u64), ..FileSpec::new(&names[i], &streams[i]) };
        files.push((spec, crc));
        if i % 3 == 0 {
            let j = i / 3;
            files.push((FileSpec::new(&stored_names[j], &stored[j]), crc32fast::hash(&stored[j])));
        }
    }
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&files, false)).unwrap();
    for threads in [1, 4] {
        let out = dir.join(format!("out{threads}"));
        let mut lines = Vec::new();
        let s = extract::run(&arc, &opts(&out, threads), |l| lines.push(l.to_string())).unwrap();
        assert_eq!((s.files, s.errors.len()), (74, 6), "{:?}", s.errors);
        let bad: Vec<String> =
            (0..60).filter(|i| i % 10 == 3).map(|i| format!("{}: checksum error", names[i])).collect();
        assert_eq!(s.errors, bad);
        assert_eq!(lines, bad);
        for i in 0..60 {
            let got = fs::read(out.join(&names[i]));
            if i % 10 == 3 {
                assert!(got.is_err(), "{} should be removed", names[i]);
            } else {
                assert_eq!(got.unwrap(), plains[i], "{}", names[i]);
            }
        }
        for j in 0..20 {
            assert_eq!(fs::read(out.join(&stored_names[j])).unwrap(), stored[j]);
        }
        // and testing alone agrees
        let t = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&out, threads) }, |_| {}).unwrap();
        assert_eq!((t.files, t.errors.len()), (74, 6));
    }
}

#[test]
fn a_big_stored_file_is_checked_and_copied_in_pieces() {
    let dir = tmp("big");
    let data = noise((70 << 20) + 12_345, 7);
    let spec = FileSpec::new("big.bin", &data);
    let arc = dir.join("big.rar");
    fs::write(&arc, archive(&[spec])).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out, 4), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(fs::read(out.join("big.bin")).unwrap() == data);

    // one flipped byte deep inside is caught, and the file is removed
    let mut bytes = fs::read(&arc).unwrap();
    let at = bytes.len() - 5_000_000;
    bytes[at] ^= 1;
    fs::write(&arc, bytes).unwrap();
    let out2 = dir.join("out2");
    let s = extract::run(&arc, &opts(&out2, 4), |_| {}).unwrap();
    assert_eq!(s.errors, ["big.bin: checksum error"]);
    assert!(!out2.join("big.bin").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_big_stored_file_split_across_volumes_is_copied_in_pieces() {
    let dir = tmp("bigvols");
    let data = noise((150 << 20) + 777, 9);
    let spec = FileSpec::new("movie.mkv", &data);
    // two parts big enough for pieces, then a small last one
    for (i, v) in volumes(&spec, 70 << 20).into_iter().enumerate() {
        fs::write(dir.join(format!("set.part{}.rar", i + 1)), v).unwrap();
    }
    let out = dir.join("out");
    let s = extract::run(&dir.join("set.part1.rar"), &opts(&out, 3), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(s.volumes, 3);
    assert!(fs::read(out.join("movie.mkv")).unwrap() == data);

    // a damaged middle part fails its own part's CRC
    let p2 = dir.join("set.part2.rar");
    let mut bytes = fs::read(&p2).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0x80;
    fs::write(&p2, bytes).unwrap();
    let out2 = dir.join("out2");
    let s = extract::run(&dir.join("set.part1.rar"), &opts(&out2, 3), |_| {}).unwrap();
    assert_eq!(s.errors, ["movie.mkv: checksum error in a volume's part"]);
    assert!(!out2.join("movie.mkv").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_later_entry_at_the_same_place_waits_for_the_earlier_one() {
    let dir = tmp("same");
    let good = noise(5000, 3);
    // big enough that its worker is still at it when the later copies come up
    let bad = noise(12 << 20, 4);
    // the first copy fails its CRC and is removed; the second, at the same place, must survive
    let entries = vec![
        (FileSpec::new("dup.bin", &bad), 1),
        (FileSpec::new("DUP.bin", &good), crc32fast::hash(&good)),
        (FileSpec::new("dup.bin", &good), crc32fast::hash(&good)),
    ];
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&entries, false)).unwrap();
    for overwrite in [Overwrite::Skip, Overwrite::Always] {
        let out = dir.join(format!("out{overwrite:?}"));
        let s = extract::run(&arc, &Options { overwrite, ..opts(&out, 4) }, |_| {}).unwrap();
        assert_eq!(s.errors, ["dup.bin: checksum error"], "{overwrite:?}");
        assert_eq!(fs::read(out.join("dup.bin")).unwrap(), good, "{overwrite:?}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn reports_keep_archive_order_across_files_done_here_and_on_workers() {
    let dir = tmp("order");
    let a = noise(3000, 5);
    let b = noise(3000, 6);
    let entries = vec![
        (FileSpec::new("a.bin", &a), 1),
        (FileSpec::new("../escape.bin", &b), crc32fast::hash(&b)),
        (FileSpec::new("b.bin", &b), 2),
    ];
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&entries, false)).unwrap();
    for mode in [Mode::Test, Mode::Extract] {
        let mut lines = Vec::new();
        let s =
            extract::run(&arc, &Options { mode, ..opts(&dir.join("out"), 4) }, |l| lines.push(l.to_string())).unwrap();
        assert_eq!(s.errors.len(), 3, "{:?}", s.errors);
        assert!(s.errors[0].starts_with("a.bin: checksum error"), "{:?}", s.errors);
        assert!(s.errors[1].starts_with("../escape.bin"), "{:?}", s.errors);
        assert!(s.errors[2].starts_with("b.bin: checksum error"), "{:?}", s.errors);
        assert_eq!(lines, s.errors);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_file_under_one_the_workers_still_hold_waits_for_it() {
    let dir = tmp("parent");
    let bad = noise(12 << 20, 8);
    let good = noise(3000, 9);
    // `a` fails its CRC and is removed, so `a/b` can then make the folder `a`, as on one thread
    let entries = vec![(FileSpec::new("a", &bad), 1), (FileSpec::new("a/b", &good), crc32fast::hash(&good))];
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&entries, false)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out, 4), |_| {}).unwrap();
    assert_eq!(s.errors, ["a: checksum error"]);
    assert_eq!(fs::read(out.join("a/b")).unwrap(), good);
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_big_stored_file_named_like_its_own_archive_is_read_from_the_open_archive() {
    let dir = tmp("selfname");
    let data = noise((66 << 20) + 5, 10);
    let arc = dir.join("same.bin");
    fs::write(&arc, archive(&[FileSpec::new("same.bin", &data)])).unwrap();
    // extracting next to the archive replaces its name with the output while the archive is still open
    let s = extract::run(&arc, &Options { overwrite: Overwrite::Always, ..opts(&dir, 4) }, |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(fs::read(&arc).unwrap() == data);
    let _ = fs::remove_dir_all(&dir);
}
