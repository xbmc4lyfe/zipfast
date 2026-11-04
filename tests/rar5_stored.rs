mod common;

use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{self, Mode, Options, Overwrite};

fn opts(dest: &Path) -> Options {
    Options { mode: Mode::Extract, dest: dest.to_path_buf(), overwrite: Overwrite::Skip, flatten: false }
}

fn tmp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn extracts_stored_files_with_folders() {
    let dir = tmp("basic");
    let big: Vec<u8> = (0..5_000_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
    let files = [
        FileSpec::new("a.txt", b"hello"),
        FileSpec { dir: true, ..FileSpec::new("sub", b"") },
        FileSpec::new("sub/big.bin", &big),
        FileSpec::new("empty", b""),
    ];
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&files)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!((s.files, s.dirs), (3, 1));
    assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(out.join("sub/big.bin")).unwrap(), big);
    assert_eq!(fs::read(out.join("empty")).unwrap(), b"");
    let mtime = fs::metadata(out.join("a.txt")).unwrap().modified().unwrap();
    assert_eq!(mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 1_700_000_000);
}

#[test]
fn lists_and_tests() {
    let dir = tmp("list");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("x/y.mkv", b"abc")])).unwrap();
    let entries = extract::list(&arc).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].name.as_str(), entries[0].size, entries[0].crc32),
        ("x/y.mkv", 3, Some(crc32fast::hash(b"abc")))
    );
    let s = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&dir.join("never")) }, |_| {}).unwrap();
    assert!(s.errors.is_empty());
    assert!(!dir.join("never").exists());
}

#[test]
fn joins_a_file_split_across_volumes() {
    let dir = tmp("volumes");
    let data: Vec<u8> = (0..1_000_003u32).map(|i| (i % 251) as u8).collect();
    let spec = FileSpec::new("movie.mkv", &data);
    for (i, vol) in volumes(&spec, 300_000).iter().enumerate() {
        fs::write(dir.join(format!("set.part{:02}.rar", i + 1)), vol).unwrap();
    }
    let out = dir.join("out");
    let s = extract::run(&dir.join("set.part01.rar"), &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(s.volumes, 4);
    assert_eq!(fs::read(out.join("movie.mkv")).unwrap(), data);
}

#[test]
fn missing_volume_is_an_error() {
    let dir = tmp("missing");
    let data = vec![9u8; 1000];
    let spec = FileSpec::new("f", &data);
    let vols = volumes(&spec, 400);
    fs::write(dir.join("s.part1.rar"), &vols[0]).unwrap();
    fs::write(dir.join("s.part2.rar"), &vols[1]).unwrap();
    let err = extract::run(&dir.join("s.part1.rar"), &opts(&dir.join("o")), |_| {}).unwrap_err();
    assert!(matches!(err, zipfast::Error::MissingVolume(_)), "{err}");
}

#[test]
fn bad_data_fails_its_checksum() {
    let dir = tmp("crc");
    let mut bytes = archive(&[FileSpec::new("f", b"0123456789")]);
    let at = bytes.windows(10).position(|w| w == b"0123456789").unwrap();
    bytes[at] = b'X';
    let arc = dir.join("t.rar");
    fs::write(&arc, bytes).unwrap();
    let s = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&dir) }, |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1);
}

#[test]
fn bad_header_is_corrupt() {
    let dir = tmp("hdr");
    let mut bytes = archive(&[FileSpec::new("name", b"x")]);
    let at = bytes.windows(4).position(|w| w == b"name").unwrap();
    bytes[at] = b'N';
    let arc = dir.join("t.rar");
    fs::write(&arc, bytes).unwrap();
    assert!(matches!(extract::run(&arc, &opts(&dir.join("o")), |_| {}), Err(zipfast::Error::Corrupt(_))));
}

#[test]
fn refuses_paths_that_escape() {
    let dir = tmp("escape");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("../evil", b"x"), FileSpec::new("/abs", b"y"), FileSpec::new("ok", b"z")]))
        .unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!(s.errors.len(), 2);
    assert_eq!(s.files, 1);
    assert!(!dir.join("evil").exists());
}

#[cfg(unix)]
#[test]
fn never_writes_through_a_link() {
    let dir = tmp("link");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("d/f", b"x")])).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let outside = dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, out.join("d")).unwrap();
    let r = extract::run(&arc, &opts(&out), |_| {});
    assert!(r.is_err());
    assert!(!outside.join("f").exists());
}

#[test]
fn skips_or_overwrites_existing() {
    let dir = tmp("over");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("f", b"new")])).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("f"), b"old").unwrap();
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.skipped, fs::read(out.join("f")).unwrap()), (1, b"old".to_vec()));
    extract::run(&arc, &Options { overwrite: Overwrite::Always, ..opts(&out) }, |_| {}).unwrap();
    assert_eq!(fs::read(out.join("f")).unwrap(), b"new");
}

#[test]
fn finds_the_signature_after_an_sfx_stub() {
    let dir = tmp("sfx");
    let mut bytes = vec![0x4d, 0x5a];
    bytes.extend(vec![0u8; 5000]);
    bytes.extend(archive(&[FileSpec::new("f", b"sfx")]));
    let arc = dir.join("t.exe");
    fs::write(&arc, bytes).unwrap();
    let out = dir.join("out");
    extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!(fs::read(out.join("f")).unwrap(), b"sfx");
}

#[test]
fn compressed_files_are_reported_not_mangled() {
    let dir = tmp("packed");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec { method: 3, ..FileSpec::new("p", b"zz") }, FileSpec::new("s", b"ok")]))
        .unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (1, 1));
    assert!(!out.join("p").exists());
}
