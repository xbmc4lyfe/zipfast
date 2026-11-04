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
fn plain_and_gzip_tar_extract_the_same_tree() {
    let big = data(9 << 20, 1);
    let long = format!("deep/{}/name.bin", "a".repeat(120));
    let tar = Tar::default()
        .dir("deep/", 0o750)
        .file("deep/small.txt", b"hello tar")
        .file("big.bin", &big)
        .file("empty", b"")
        .gnu_long(&long, b"gnu long")
        .pax(&[("path", "deep/pax é name.txt"), ("mtime", "1700000000.5")], "deep/placeholder", b"pax data")
        .end();
    for (label, bytes) in [("plain", tar.clone()), ("gzip", gzip(&tar))] {
        let dir = tmp(&format!("tree-{label}"));
        let archive = dir.join(if label == "gzip" { "a.tar.gz" } else { "a.tar" });
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
