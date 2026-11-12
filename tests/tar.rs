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

//! tar archives built by a small writer here, plain and gzip-compressed, read back through the same entry points
//! as RAR and ZIP.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use zipfast::extract::{self, Mode, Options, Overwrite};

/// One header block. `name` goes in the name field as is; `kind` is the type flag.
fn header(name: &[u8], kind: u8, size: u64, mode: u32, mtime: u64, link: &[u8], ustar: bool) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name);
    let octal = |h: &mut [u8; 512], at: usize, width: usize, v: u64| {
        let s = format!("{v:0w$o}\0", w = width - 1);
        h[at..at + width].copy_from_slice(s.as_bytes());
    };
    octal(&mut h, 100, 8, mode as u64);
    octal(&mut h, 108, 8, 1000);
    octal(&mut h, 116, 8, 1000);
    if size < 1 << 33 {
        octal(&mut h, 124, 12, size);
    } else {
        // GNU's base-256 form for sizes that don't fit in eleven octal digits
        h[124] = 0x80;
        h[128..136].copy_from_slice(&size.to_be_bytes());
    }
    octal(&mut h, 136, 12, mtime);
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link);
    if ustar {
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
    }
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

fn pad(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(512) {
        out.push(0);
    }
}

#[derive(Default)]
struct Tar {
    out: Vec<u8>,
}

impl Tar {
    fn raw(&mut self, h: [u8; 512], data: &[u8]) -> &mut Self {
        self.out.extend_from_slice(&h);
        self.out.extend_from_slice(data);
        pad(&mut self.out);
        self
    }

    fn file(&mut self, name: &str, data: &[u8]) -> &mut Self {
        self.raw(header(name.as_bytes(), b'0', data.len() as u64, 0o640, 981_173_106, b"", true), data)
    }

    fn dir(&mut self, name: &str, mode: u32) -> &mut Self {
        self.raw(header(name.as_bytes(), b'5', 0, mode, 981_173_106, b"", true), b"")
    }

    fn symlink(&mut self, name: &str, target: &str) -> &mut Self {
        self.raw(header(name.as_bytes(), b'2', 0, 0o777, 0, target.as_bytes(), true), b"")
    }

    /// A GNU long-name record, then the file under a cut-short name.
    fn gnu_long(&mut self, name: &str, data: &[u8]) -> &mut Self {
        let mut n = name.as_bytes().to_vec();
        n.push(0);
        self.raw(header(b"././@LongLink", b'L', n.len() as u64, 0, 0, b"", false), &n);
        self.raw(header(&name.as_bytes()[..100], b'0', data.len() as u64, 0o644, 0, b"", false), data)
    }

    /// A pax record set, then the file under a placeholder name.
    fn pax(&mut self, records: &[(&str, &str)], name: &str, data: &[u8]) -> &mut Self {
        let mut body = Vec::new();
        for (k, v) in records {
            let tail = format!(" {k}={v}\n");
            let mut n = tail.len() + 1;
            while format!("{n}{tail}").len() != n {
                n += 1;
            }
            body.extend_from_slice(format!("{n}{tail}").as_bytes());
        }
        self.raw(header(b"PaxHeaders/x", b'x', body.len() as u64, 0o644, 0, b"", true), &body);
        self.raw(header(name.as_bytes(), b'0', data.len() as u64, 0o644, 0, b"", true), data)
    }

    fn end(&mut self) -> Vec<u8> {
        self.out.extend_from_slice(&[0u8; 1024]);
        std::mem::take(&mut self.out)
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn xz(data: &[u8]) -> Vec<u8> {
    let mut enc = liblzma::write::XzEncoder::new(Vec::new(), 1);
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// xz in independent blocks, the way `xz -T0` writes it, which can be decoded on several threads
fn xz_blocks(data: &[u8]) -> Vec<u8> {
    let stream = liblzma::stream::MtStreamBuilder::new().threads(4).block_size(1 << 20).preset(0).encoder().unwrap();
    let mut enc = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// with a content checksum, as the zstd tool writes by default: without one, damage to stored data can't be seen
fn zstd(data: &[u8]) -> Vec<u8> {
    let mut enc = zstd::Encoder::new(Vec::new(), 1).unwrap();
    enc.include_checksum(true).unwrap();
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zipfast-tar-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn opts(mode: Mode, dest: &Path) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

fn data(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

#[test]
fn rejects_a_zstandard_window_above_the_decoder_limit() {
    use std::io::{BufReader, Read};
    use zipfast::stream::Codec;

    let dir = tmp("zstd-window-limit");
    let path = dir.join("large-window.zst");
    // A short Zstandard frame declaring a 512 MiB window and no stored content size.
    let encoded = [
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x98, 0xc1, 0, 0, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79,
        0x20, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x20, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x47, 0x32, 0x8e,
    ];
    fs::write(&path, encoded).unwrap();
    let mut decoder = Codec::Zstd.open(BufReader::new(fs::File::open(&path).unwrap()), 1).unwrap();
    let error = decoder.read(&mut [0; 64]).unwrap_err();
    assert!(error.to_string().contains("too much memory"), "{error}");
}

#[test]
fn rejects_an_xz_dictionary_above_the_decoder_limit() {
    use std::io::{BufReader, Read};
    use zipfast::stream::Codec;

    let dir = tmp("xz-dictionary-limit");
    let path = dir.join("large-dictionary.xz");
    let mut encoded = xz(b"small XZ stream");
    let block_start = 12;
    let crc_start = block_start + (usize::from(encoded[block_start]) + 1) * 4 - 4;
    // This block has one LZMA2 filter. Replace its dictionary property and update the block-header CRC.
    assert_eq!(&encoded[13..16], &[0, 0x21, 1]);
    encoded[16] = 36; // 256 MiB, excluding decoder overhead
    let crc = crc32fast::hash(&encoded[block_start..crc_start]);
    encoded[crc_start..crc_start + 4].copy_from_slice(&crc.to_le_bytes());
    fs::write(&path, encoded).unwrap();
    for threads in [1, 4] {
        let mut decoder = Codec::Xz.open(BufReader::new(fs::File::open(&path).unwrap()), threads).unwrap();
        let error = decoder.read(&mut [0; 64]).unwrap_err();
        assert_eq!(error.to_string(), "memory limit reached");
    }
}

#[test]
fn plain_and_compressed_tar_extract_the_same_tree() {
    let big = data(5 << 20, 1);
    let long = format!("deep/{}/name.bin", "a".repeat(120));
    let tar = Tar::default()
        .dir("deep/", 0o750)
        .file("deep/small.txt", b"hello tar")
        .file("big.bin", &big)
        .file("empty", b"")
        .gnu_long(&long, b"gnu long")
        .pax(&[("path", "deep/pax é name.txt"), ("mtime", "1700000000.5")], "deep/placeholder", b"pax data")
        .end();
    let forms = [
        ("tar", tar.clone()),
        ("tar.gz", gzip(&tar)),
        ("tar.xz", xz(&tar)),
        ("txz", xz_blocks(&tar)),
        ("tar.zst", zstd(&tar)),
        ("tar.bz2", bzip2(&tar)),
    ];
    for (label, bytes) in forms {
        let dir = tmp(&format!("tree-{label}"));
        let archive = dir.join(format!("a.{label}"));
        fs::write(&archive, &bytes).unwrap();

        let listed = extract::list(&archive).unwrap();
        let names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["deep/", "deep/small.txt", "big.bin", "empty", long.as_str(), "deep/pax é name.txt"]);
        assert_eq!(listed[2].size, big.len() as u64);
        assert!(listed[0].dir);

        let tested = extract::run(&archive, &opts(Mode::Test, &dir.join("unused")), |_| {}).unwrap();
        assert!(tested.errors.is_empty(), "{:?}", tested.errors);
        assert_eq!((tested.files, tested.dirs), (5, 1));
        assert!(!dir.join("unused").exists());

        let out = dir.join("out");
        let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{:?}", s.errors);
        assert_eq!(s.bytes, (big.len() + 9 + 8 + 8) as u64);
        assert_eq!(fs::read(out.join("deep/small.txt")).unwrap(), b"hello tar");
        assert!(fs::read(out.join("big.bin")).unwrap() == big);
        assert_eq!(fs::read(out.join("empty")).unwrap(), b"");
        assert_eq!(fs::read(out.join(&long)).unwrap(), b"gnu long");
        let pax = out.join("deep/pax é name.txt");
        assert_eq!(fs::read(&pax).unwrap(), b"pax data");
        let mtime = fs::metadata(&pax).unwrap().modified().unwrap();
        let since = mtime.duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(since.as_secs(), 1_700_000_000);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&out.join("deep/small.txt")), 0o640);
            assert_eq!(mode(&out.join("deep")), 0o750);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_lone_gzip_file_comes_out_under_its_stored_or_archive_name() {
    let dir = tmp("single");
    let body = data(300_000, 7);
    // no name in the header: the archive's name without .gz
    let archive = dir.join("movie.nfo.gz");
    fs::write(&archive, gzip(&body)).unwrap();
    let listed = extract::list(&archive).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "movie.nfo");
    assert_eq!(listed[0].size, body.len() as u64);
    let out = dir.join("out");
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(fs::read(out.join("movie.nfo")).unwrap() == body);

    // a stored name wins, but only its last part
    let mut enc = flate2::GzBuilder::new().filename("../../etc/stored.txt").write(Vec::new(), Compression::fast());
    enc.write_all(b"named").unwrap();
    let archive = dir.join("other.gz");
    fs::write(&archive, enc.finish().unwrap()).unwrap();
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("stored.txt")).unwrap(), b"named");

    // the other codecs, named from the archive
    for (name, bytes) in [("notes.txt.xz", xz(&body)), ("notes.txt.zst", zstd(&body)), ("notes.txt.bz2", bzip2(&body))]
    {
        let archive = dir.join(name);
        fs::write(&archive, bytes).unwrap();
        let o = dir.join(format!("out-{name}"));
        let s = extract::run(&archive, &opts(Mode::Extract, &o), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert!(fs::read(o.join("notes.txt")).unwrap() == body, "{name}");
    }

    // a zstd stream may open with a skippable frame
    let mut skip = vec![0x53, 0x2a, 0x4d, 0x18];
    skip.extend_from_slice(&5u32.to_le_bytes());
    skip.extend_from_slice(b"meta!");
    skip.extend_from_slice(&zstd(&body));
    let archive = dir.join("skip.txt.zst");
    fs::write(&archive, skip).unwrap();
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(fs::read(out.join("skip.txt")).unwrap() == body);

    // a stored name after an extra field of the largest size is still found
    let mut enc = flate2::GzBuilder::new()
        .extra(vec![7u8; 65535])
        .filename("after-extra.txt")
        .write(Vec::new(), Compression::fast());
    enc.write_all(b"extra").unwrap();
    let archive = dir.join("extra.gz");
    fs::write(&archive, enc.finish().unwrap()).unwrap();
    extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(fs::read(out.join("after-extra.txt")).unwrap(), b"extra");

    // xz streams back to back, with stream padding between them, are one file
    let mut two = xz(b"one ");
    two.extend_from_slice(&[0; 8]);
    two.extend_from_slice(&xz(b"two"));
    let archive = dir.join("cat.txt.xz");
    fs::write(&archive, two).unwrap();
    extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(fs::read(out.join("cat.txt")).unwrap(), b"one two");

    // two members back to back are one file, listed with the size of both
    let mut two = gzip(b"first ");
    two.extend_from_slice(&gzip(b"second"));
    let archive = dir.join("two.txt.gz");
    fs::write(&archive, two).unwrap();
    assert_eq!(extract::list(&archive).unwrap()[0].size, 12);
    extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(fs::read(out.join("two.txt")).unwrap(), b"first second");

    // a stored name with a drive prefix stays inside the destination
    let mut enc = flate2::GzBuilder::new().filename("C:escaped.txt").write(Vec::new(), Compression::fast());
    enc.write_all(b"drive").unwrap();
    let archive = dir.join("drive.gz");
    fs::write(&archive, enc.finish().unwrap()).unwrap();
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("C_escaped.txt")).unwrap(), b"drive");

    // a file that only starts with zero bytes is still a file, not an empty archive
    let mut zeros = vec![0u8; 4096];
    zeros.extend_from_slice(b"tail");
    let archive = dir.join("zeros.bin.gz");
    fs::write(&archive, gzip(&zeros)).unwrap();
    extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(fs::read(out.join("zeros.bin")).unwrap(), zeros);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn damage_is_reported_and_nothing_half_written_is_left() {
    let dir = tmp("damage");
    let big = data(6 << 20, 3);
    let tar = Tar::default().file("a.txt", b"fine").file("big.bin", &big).file("after.txt", b"later").end();

    // cut short inside big.bin
    let cut = dir.join("cut.tar");
    fs::write(&cut, &tar[..512 * 3 + (3 << 20)]).unwrap();
    for mode in [Mode::Test, Mode::Extract] {
        let out = dir.join(format!("out-cut-{mode:?}"));
        let s = extract::run(&cut, &opts(mode, &out), |_| {}).unwrap();
        assert_eq!(s.files, 1);
        assert_eq!(s.errors.len(), 1, "{:?}", s.errors);
        assert!(s.errors[0].starts_with("big.bin:"), "{:?}", s.errors);
        assert!(!out.join("big.bin").exists());
    }

    // a flipped byte in the compressed stream fails the gzip check
    let mut gz = gzip(&tar);
    let at = gz.len() / 2;
    gz[at] ^= 0x55;
    let bad = dir.join("bad.tar.gz");
    fs::write(&bad, &gz).unwrap();
    let out = dir.join("out-gz");
    let s = extract::run(&bad, &opts(Mode::Extract, &out), |_| {}).unwrap();
    // gzip's checksum comes at the end, so the damage may only be found after the files are out
    assert!(!s.errors.is_empty());
    let s = extract::run(&bad, &opts(Mode::Test, &out), |_| {}).unwrap();
    assert!(!s.errors.is_empty());

    for (label, mut packed) in [("xz", xz(&tar)), ("zst", zstd(&tar)), ("bz2", bzip2(&tar))] {
        let at = packed.len() / 2;
        packed[at] ^= 0x55;
        let bad = dir.join(format!("bad.tar.{label}"));
        fs::write(&bad, &packed).unwrap();
        let s = extract::run(&bad, &opts(Mode::Test, &out), |_| {}).unwrap();
        assert!(!s.errors.is_empty(), "{label}");
        // cut short
        let cut = dir.join(format!("cut.tar.{label}"));
        fs::write(&cut, &packed[..packed.len() / 3]).unwrap();
        let s = extract::run(&cut, &opts(Mode::Test, &out), |_| {}).unwrap();
        assert!(!s.errors.is_empty(), "cut {label}");
    }

    // a damaged header stops the run with an error, after what came before it
    let mut broken = tar.clone();
    broken[512 * 2 + 3] ^= 1; // big.bin's name
    let hdr = dir.join("hdr.tar");
    fs::write(&hdr, &broken).unwrap();
    let s = extract::run(&hdr, &opts(Mode::Test, &dir), |_| {}).unwrap();
    assert_eq!(s.files, 1);
    assert_eq!(s.errors.len(), 1);
    assert!(s.errors[0].contains("checksum"), "{:?}", s.errors);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unsafe_names_links_and_specials_are_refused() {
    let dir = tmp("refuse");
    let tar = Tar::default()
        .file("../escape.txt", b"no")
        .file("/abs.txt", b"no")
        .symlink("link", "/etc/passwd")
        .raw(header(b"fifo", b'6', 0, 0o644, 0, b"", true), b"")
        .file("ok.txt", b"yes")
        .end();
    let archive = dir.join("r.tar");
    fs::write(&archive, tar).unwrap();
    let out = dir.join("out");
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(s.files, 1);
    assert_eq!(s.errors.len(), 4, "{:?}", s.errors);
    assert_eq!(fs::read(out.join("ok.txt")).unwrap(), b"yes");
    assert!(!dir.join("escape.txt").exists());
    assert!(fs::symlink_metadata(out.join("link")).is_err());
    let listed = extract::list(&archive).unwrap();
    assert!(matches!(listed[2].link, Some(zipfast::rar5::Redirection::UnixSymlink(ref t)) if t == "/etc/passwd"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn old_style_headers_and_a_missing_end_marker_still_read() {
    let dir = tmp("v7");
    let mut tar = Vec::new();
    // pre-POSIX: no magic, a folder marked only by its trailing slash
    tar.extend_from_slice(&header(b"old/", b'0', 0, 0o755, 0, b"", false));
    tar.extend_from_slice(&header(b"old/f", 0, 3, 0o644, 0, b"", false));
    tar.extend_from_slice(b"abc");
    pad(&mut tar);
    let archive = dir.join("v7.tar");
    fs::write(&archive, &tar).unwrap();
    let out = dir.join("out");
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!((s.files, s.dirs), (1, 1));
    assert_eq!(fs::read(out.join("old/f")).unwrap(), b"abc");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_size_past_eight_gib_is_read_from_the_base_256_field() {
    // only the header: the data isn't there, so the member is cut short, but its size must be read right
    let dir = tmp("b256");
    let mut tar = header(b"huge.bin", b'0', 10 << 30, 0o644, 0, b"", false).to_vec();
    tar.extend_from_slice(&[7u8; 512]);
    let archive = dir.join("huge.tar");
    fs::write(&archive, &tar).unwrap();
    let listed = extract::list(&archive).unwrap_err();
    assert!(matches!(listed, zipfast::Error::Truncated), "{listed:?}");
    let s = extract::run(&archive, &opts(Mode::Test, &dir), |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1);
    assert!(s.errors[0].contains("truncated"), "{:?}", s.errors);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_archive_reads_as_empty() {
    let dir = tmp("empty");
    // GNU tar pads an empty archive to one 10 KiB record
    let empty = vec![0u8; 10240];
    for (name, bytes) in [("e.tar", empty.clone()), ("e.tar.gz", gzip(&empty))] {
        let archive = dir.join(name);
        fs::write(&archive, bytes).unwrap();
        assert!(extract::list(&archive).unwrap().is_empty(), "{name}");
        let out = dir.join(format!("out-{name}"));
        let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
        assert!(s.errors.is_empty(), "{name}: {:?}", s.errors);
        assert_eq!((s.files, s.dirs), (0, 0), "{name}");
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0, "{name}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_pax_size_with_no_room_for_padding_is_refused() {
    let dir = tmp("paxsize");
    let tar = Tar::default().pax(&[("size", "18446744073709551615")], "huge", b"").end();
    let archive = dir.join("p.tar");
    fs::write(&archive, tar).unwrap();
    assert!(extract::list(&archive).is_err());
    let s = extract::run(&archive, &opts(Mode::Test, &dir), |_| {}).unwrap();
    assert_eq!(s.files, 0);
    assert_eq!(s.errors.len(), 1, "{:?}", s.errors);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_refused_gnu_sparse_member_with_map_extensions_does_not_hide_what_follows() {
    let dir = tmp("sparse");
    let mut h = header(b"sparse.bin", b'S', 512, 0o644, 0, b"", false);
    h[257..265].copy_from_slice(b"ustar  \0");
    h[482] = 1; // the sparse map goes on in an extension block
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut ext = [0u8; 512];
    ext[..12].copy_from_slice(b"00000000000\0"); // one map entry, and no further extension
    let mut tar = Tar::default();
    tar.out.extend_from_slice(&h);
    tar.out.extend_from_slice(&ext);
    tar.out.extend_from_slice(&[b'x'; 512]);
    let tar = tar.file("after.txt", b"after").end();
    let archive = dir.join("s.tar");
    fs::write(&archive, tar).unwrap();
    let out = dir.join("out");
    let s = extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).unwrap();
    assert_eq!(s.files, 1, "{:?}", s.errors);
    assert_eq!(s.errors.len(), 1);
    assert!(s.errors[0].contains("sparse"), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("after.txt")).unwrap(), b"after");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn compressed_tar_preserves_order_for_conflicting_file_paths() {
    let dir = tmp("conflicting-paths");
    let tar = Tar::default().file("a", b"First").file("a/b", b"Second").end();
    let archive = dir.join("archive.tar.gz");
    fs::write(&archive, gzip(&tar)).unwrap();
    let out = dir.join("out");
    assert!(extract::run(&archive, &opts(Mode::Extract, &out), |_| {}).is_err());
    assert_eq!(fs::read(out.join("a")).unwrap(), b"First");
    assert_eq!(fs::read_dir(out).unwrap().count(), 1);
}

#[test]
fn failed_compressed_tar_verification_preserves_existing_files() {
    let dir = tmp("compressed-overwrite");
    let out = dir.join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("keep.txt"), b"Original").unwrap();
    let keep = fs::metadata(out.join("keep.txt")).unwrap();
    let folder = out.join("folder");
    fs::create_dir(&folder).unwrap();
    let folder_meta = fs::metadata(&folder).unwrap();
    let tar = Tar::default().file("keep.txt", b"Replacement").dir("folder", 0o700).file("new/child.txt", b"New").end();
    let mut broken = gzip(&tar);
    let trailer = broken.len() - 8;
    broken[trailer] ^= 1;
    let archive = dir.join("broken.tar.gz");
    fs::write(&archive, broken).unwrap();
    let options = Options { overwrite: Overwrite::Always, ..opts(Mode::Extract, &out) };
    let summary = extract::run(&archive, &options, |_| {}).unwrap();
    assert_eq!(summary.errors.len(), 1);
    assert_eq!(summary.files, 0);
    assert_eq!(fs::read(out.join("keep.txt")).unwrap(), b"Original");
    let keep_after = fs::metadata(out.join("keep.txt")).unwrap();
    let folder_after = fs::metadata(&folder).unwrap();
    assert_eq!(keep_after.modified().unwrap(), keep.modified().unwrap());
    assert_eq!(keep_after.permissions(), keep.permissions());
    assert_eq!(folder_after.modified().unwrap(), folder_meta.modified().unwrap());
    assert_eq!(folder_after.permissions(), folder_meta.permissions());
    assert_eq!(fs::read_dir(&out).unwrap().count(), 2);
    assert_eq!(fs::read_dir(&folder).unwrap().count(), 0);

    fs::write(&archive, gzip(&tar)).unwrap();
    let summary = extract::run(&archive, &options, |_| {}).unwrap();
    assert!(summary.errors.is_empty());
    assert_eq!(summary.files, 2);
    assert_eq!(fs::read(out.join("keep.txt")).unwrap(), b"Replacement");
    assert_eq!(fs::read(out.join("new/child.txt")).unwrap(), b"New");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(out.join("keep.txt")).unwrap().permissions().mode() & 0o777, 0o640);
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tar_extraction_preserves_its_input() {
    let dir = tmp("archive-collision");
    #[cfg(unix)]
    let alias = {
        let alias = dir.join("alias");
        std::os::unix::fs::symlink(&dir, &alias).unwrap();
        alias
    };
    for name in ["self.tar", "self.tar.gz"] {
        let arc = dir.join(name);
        let tar = Tar::default().file(name, b"replacement").end();
        let bytes = if name.ends_with(".gz") { gzip(&tar) } else { tar };
        for direct in [false, true] {
            #[cfg(unix)]
            let dest = if direct { &alias } else { &dir };
            #[cfg(not(unix))]
            let dest = &dir;
            let options = Options { overwrite: Overwrite::Always, ..opts(Mode::Extract, dest) };
            fs::write(&arc, &bytes).unwrap();
            let result = if direct {
                zipfast::tar::run(&arc, &options, |_| {}).unwrap()
            } else {
                extract::run(&arc, &options, |_| {}).unwrap()
            };
            assert_eq!(fs::read(&arc).unwrap(), bytes, "{name}");
            assert_eq!((result.files, result.errors.len()), (0, 1), "{name}");
        }
    }
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_prepublication_filesystem_error_leaves_compressed_tar_outputs_untouched() {
    let dir = tmp("staging-filesystem-error");
    let out = dir.join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("keep"), b"original").unwrap();
    fs::write(out.join("blocked"), b"obstruction").unwrap();
    let tar = Tar::default().file("keep", b"replacement").file("blocked/child", b"new").end();
    let archive = dir.join("archive.tar.gz");
    fs::write(&archive, gzip(&tar)).unwrap();
    let options = Options { overwrite: Overwrite::Always, ..opts(Mode::Extract, &out) };
    assert!(extract::run(&archive, &options, |_| {}).is_err());
    assert_eq!(fs::read(out.join("keep")).unwrap(), b"original");
    assert_eq!(fs::read(out.join("blocked")).unwrap(), b"obstruction");
    assert_eq!(fs::read_dir(&out).unwrap().count(), 2);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn reads_selected_tar_members_and_bounds_compressed_streams() {
    let dir = tmp("selected");
    let mut builder = Tar::default();
    let tar = builder.file("same.txt", b"first").file("same.txt", b"second").end();
    let mut broken = gzip(&tar);
    let trailer = broken.len() - 8;
    broken[trailer] ^= 1;
    for (name, data) in [("sample.tar", tar.clone()), ("sample.tgz", gzip(&tar)), ("broken.tgz", broken)] {
        let path = dir.join(name);
        fs::write(&path, data).unwrap();
        let mut bytes = Vec::new();
        let result = extract::SelectedEntry::open(&path, 1, None, 16 << 10).and_then(|entry| {
            assert_eq!(entry.name(), "same.txt");
            entry.read(None, |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            })
        });
        if name == "broken.tgz" {
            assert!(result.is_err());
        } else {
            result.unwrap();
            assert_eq!(bytes, b"second");
        }
    }
    let path = dir.join("standalone.gz");
    fs::write(&path, gzip(&vec![b'x'; 4096])).unwrap();
    let mut bytes = Vec::new();
    let result = extract::SelectedEntry::open(&path, 0, None, 1024).and_then(|entry| {
        entry.read(None, |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
    });
    assert!(result.is_err());
    assert!(bytes.len() <= 1024);
}

#[test]
fn selected_compressed_tar_drains_past_the_payload_to_verify_the_stream() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tail.tar.gz");
    let tar = Tar::default().file("selected", b"payload").end();
    let mut packed = gzip(&tar);
    packed.extend(gzip(&[0; 512]));
    let limit = (tar.len() + 512) as u64;
    for (max_bytes, damage) in [(limit, false), (limit - 1, false), (limit, true)] {
        let mut archive = packed.clone();
        if damage {
            let trailer = archive.len() - 8;
            archive[trailer] ^= 1;
        }
        fs::write(&path, archive).unwrap();
        let entry = extract::SelectedEntry::open(&path, 0, None, max_bytes).unwrap();
        assert_eq!(entry.unix_mode(), Some(0o640));
        assert_eq!(entry.modified(), Some((981_173_106, 0)));
        let mut output = Vec::new();
        let result = entry.read(None, |chunk| {
            output.extend_from_slice(chunk);
            Ok(())
        });
        assert_eq!(output, b"payload");
        assert_eq!(result.is_ok(), max_bytes == limit && !damage, "{result:?}");
        if damage {
            assert!(extract::list(&path).is_err());
        }
    }
}

#[test]
fn selected_compressed_tar_cancellation_stops_the_final_drain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel.tar.gz");
    let tar = Tar::default().file("selected", b"payload").end();
    fs::write(&path, gzip(&tar)).unwrap();
    let cancel = extract::Cancellation::default();
    let entry = extract::SelectedEntry::open_cancelable(&path, 0, None, 4096, cancel.clone()).unwrap();
    let error = entry
        .read(None, |bytes| {
            assert_eq!(bytes, b"payload");
            cancel.cancel();
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(error, zipfast::Error::Io(error) if error.kind() == std::io::ErrorKind::ConnectionAborted));
}

#[test]
fn selected_compressed_tar_counts_packed_bytes_while_draining() {
    use std::fs::OpenOptions;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("growing.tar.gz");
    let tar = Tar::default().file("selected", b"payload").end();
    let initial = gzip(&tar);
    let trailing = gzip(&data(4096, 321));
    let limit = (tar.len() + 4096) as u64;
    // Empty gzip members use packed bytes without increasing decoded bytes.
    let empty = gzip(b"");
    let count = (limit as usize - initial.len() - trailing.len()) / empty.len() + 1;
    fs::write(&path, initial).unwrap();
    let entry = extract::SelectedEntry::open(&path, 0, None, limit).unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&trailing).unwrap();
    for _ in 0..count {
        file.write_all(&empty).unwrap();
    }
    let error = entry.read(None, |_| Ok(())).unwrap_err();
    assert!(matches!(error, zipfast::Error::Unsupported(message) if message.contains("input byte limit")));
}

#[cfg(unix)]
#[test]
fn rejects_compressed_tar_listing_above_eight_gib_before_decoding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oversize.tar.gz");
    let mut file = fs::File::create(&path).unwrap();
    file.write_all(&[0x1f, 0x8b, 8]).unwrap();
    file.set_len((8 << 30) + 1).unwrap();
    let error = extract::list(&path).unwrap_err();
    assert!(matches!(error, zipfast::Error::Unsupported(message) if message.contains("input byte limit")));
}

#[test]
fn selected_tar_preserves_fractional_times_before_the_epoch() {
    use std::time::{Duration, UNIX_EPOCH};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("timestamps.tar");
    let tar = Tar::default().pax(&[("mtime", "-1.25")], "f", b"x").end();
    fs::write(&path, tar).unwrap();
    let entry = extract::SelectedEntry::open(&path, 0, None, 1).unwrap();
    let (seconds, nanos) = entry.modified().unwrap();
    let expected = UNIX_EPOCH - Duration::from_millis(1250);
    assert_eq!(extract::archive_time(seconds, nanos), Some(expected));
    let output = dir.path().join("out");
    let summary = extract::run(&path, &opts(Mode::Extract, &output), |_| {}).unwrap();
    assert!(summary.errors.is_empty(), "{:?}", summary.errors);
    assert_eq!(fs::metadata(output.join("f")).unwrap().modified().unwrap(), expected);
}
