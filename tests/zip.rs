//! ZIP archives built by a small writer here, read back through the same entry points as RAR.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::DeflateEncoder;
use zipfast::extract::{self, Mode, Options, Overwrite};

struct Z<'a> {
    name: &'a [u8],
    data: &'a [u8],
    deflate: bool,
    mode: Option<u32>,
    flags: u16,
    method: Option<u16>,
    mtime: Option<u32>,
    crc: Option<u32>,
    size: Option<u32>,
}

impl<'a> Z<'a> {
    fn new(name: &'a str, data: &'a [u8]) -> Self {
        Z {
            name: name.as_bytes(),
            data,
            deflate: false,
            mode: Some(0o100644),
            flags: 0x0800,
            method: None,
            mtime: None,
            crc: None,
            size: None,
        }
    }
}

fn zip(entries: &[Z<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let packed = if e.deflate {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(e.data).unwrap();
            enc.finish().unwrap()
        } else {
            e.data.to_vec()
        };
        let method = e.method.unwrap_or(if e.deflate { 8 } else { 0 });
        let crc = e.crc.unwrap_or_else(|| crc32fast::hash(e.data));
        let size = e.size.unwrap_or(e.data.len() as u32);
        let mut extra = Vec::new();
        if let Some(t) = e.mtime {
            extra.extend_from_slice(&0x5455u16.to_le_bytes());
            extra.extend_from_slice(&5u16.to_le_bytes());
            extra.push(1);
            extra.extend_from_slice(&t.to_le_bytes());
        }
        let local_at = out.len() as u32;
        let common = |v: &mut Vec<u8>| {
            v.extend_from_slice(&e.flags.to_le_bytes());
            v.extend_from_slice(&method.to_le_bytes());
            // 2001-02-03 04:05:06
            v.extend_from_slice(&((4u16 << 11) | (5 << 5) | 3).to_le_bytes());
            v.extend_from_slice(&((21u16 << 9) | (2 << 5) | 3).to_le_bytes());
            v.extend_from_slice(&crc.to_le_bytes());
            v.extend_from_slice(&(packed.len() as u32).to_le_bytes());
            v.extend_from_slice(&size.to_le_bytes());
            v.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        };
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        common(&mut out);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(e.name);
        out.extend_from_slice(&packed);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        let host: u16 = if e.mode.is_some() { 3 << 8 } else { 0 };
        central.extend_from_slice(&(host | 20).to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        common(&mut central);
        central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 6]); // comment length, disk, internal attributes
        central.extend_from_slice(&(e.mode.unwrap_or(0) << 16).to_le_bytes());
        central.extend_from_slice(&local_at.to_le_bytes());
        central.extend_from_slice(e.name);
        central.extend_from_slice(&extra);
    }
    let cd_at = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_at.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-zip-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn opts(dest: &Path) -> Options {
    Options { mode: Mode::Extract, dest: dest.to_path_buf(), overwrite: Overwrite::Skip, flatten: false }
}

fn test_opts(dest: &Path) -> Options {
    Options { mode: Mode::Test, ..opts(dest) }
}

#[test]
fn extracts_stored_and_deflated_files_with_folders() {
    let dir = tmp("basic");
    let text = b"hello hello hello hello ".repeat(5000);
    let arc = dir.join("a.zip");
    fs::write(
        &arc,
        zip(&[
            Z { mode: Some(0o40755), ..Z::new("d/", b"") },
            Z { deflate: true, mtime: Some(1_600_000_000), ..Z::new("d/text.txt", &text) },
            Z { mode: Some(0o100600), ..Z::new("plain.bin", b"\x00\x01\x02") },
        ]),
    )
    .unwrap();
    let names: Vec<String> = extract::list(&arc).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["d/", "d/text.txt", "plain.bin"]);
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.dirs, s.errors.len()), (2, 1, 0));
    assert_eq!(fs::read(out.join("d/text.txt")).unwrap(), text);
    assert_eq!(fs::read(out.join("plain.bin")).unwrap(), b"\x00\x01\x02");
    let mtime = fs::metadata(out.join("d/text.txt")).unwrap().modified().unwrap();
    assert_eq!(mtime.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(), 1_600_000_000);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(out.join("plain.bin")).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn a_bad_crc_fails_the_file_and_removes_it() {
    let dir = tmp("crc");
    let arc = dir.join("a.zip");
    fs::write(&arc, zip(&[Z { crc: Some(1), deflate: true, ..Z::new("f", b"data data data") }, Z::new("g", b"ok")]))
        .unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (1, 1));
    assert!(!out.join("f").exists());
    assert!(out.join("g").exists());
}

#[test]
fn a_size_that_disagrees_with_the_directory_fails() {
    let dir = tmp("size");
    let arc = dir.join("a.zip");
    fs::write(&arc, zip(&[Z { size: Some(99), deflate: true, ..Z::new("f", b"abc") }])).unwrap();
    let s = extract::run(&arc, &test_opts(&dir), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (0, 1));
}

#[test]
fn escaping_paths_are_refused() {
    let dir = tmp("escape");
    let arc = dir.join("a.zip");
    fs::write(&arc, zip(&[Z::new("../evil", b"x"), Z::new("/abs", b"x")])).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (0, 2));
    assert!(!dir.join("evil").exists());
}

#[test]
fn encrypted_unknown_methods_and_links_are_refused() {
    let dir = tmp("refuse");
    let arc = dir.join("a.zip");
    fs::write(
        &arc,
        zip(&[
            Z { flags: 0x0801, ..Z::new("secret", b"x") },
            Z { method: Some(14), ..Z::new("lzma", b"x") },
            Z { mode: Some(0o120777), ..Z::new("link", b"target") },
            Z::new("fine", b"x"),
        ]),
    )
    .unwrap();
    let s = extract::run(&arc, &test_opts(&dir), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (1, 3));
}

#[test]
fn a_self_extracting_stub_in_front_is_skipped() {
    let dir = tmp("sfx");
    let arc = dir.join("a.exe");
    let mut bytes = b"MZ".to_vec();
    bytes.resize(10_000, 0);
    bytes.extend(zip(&[Z { deflate: true, ..Z::new("f.txt", b"inside") }]));
    fs::write(&arc, bytes).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (1, 0));
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"inside");
}

#[test]
fn truncated_data_fails_the_file() {
    let dir = tmp("trunc");
    let arc = dir.join("a.zip");
    let mut bytes = zip(&[Z::new("f", &[7u8; 1000])]);
    // cut the data short but keep a valid directory, as a damaged download might
    let cut: Vec<u8> = bytes.drain(30 + 1 + 500..30 + 1 + 1000).collect();
    assert_eq!(cut.len(), 500);
    let len = bytes.len();
    // the directory's offset moved back by the bytes removed
    let off = u32::from_le_bytes(bytes[len - 6..len - 2].try_into().unwrap()) - 500;
    bytes[len - 6..len - 2].copy_from_slice(&off.to_le_bytes());
    fs::write(&arc, bytes).unwrap();
    let s = extract::run(&arc, &test_opts(&dir), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (0, 1));
}

#[test]
fn names_without_the_utf8_flag_are_code_page_437() {
    let dir = tmp("cp437");
    let arc = dir.join("a.zip");
    fs::write(&arc, zip(&[Z { name: b"caf\x82.txt", flags: 0, ..Z::new("", b"x") }])).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!(s.files, 1);
    assert!(out.join("café.txt").exists());
}

#[test]
fn existing_files_are_skipped_unless_overwriting() {
    let dir = tmp("skip");
    let arc = dir.join("a.zip");
    fs::write(&arc, zip(&[Z::new("f", b"new")])).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("f"), b"old").unwrap();
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!(s.skipped, 1);
    assert_eq!(fs::read(out.join("f")).unwrap(), b"old");
    extract::run(&arc, &Options { overwrite: Overwrite::Always, ..opts(&out) }, |_| {}).unwrap();
    assert_eq!(fs::read(out.join("f")).unwrap(), b"new");
}
