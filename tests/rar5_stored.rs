mod common;

use std::fs;
use std::path::Path;

use common::*;
use zipfast::extract::{self, Mode, Options, Overwrite};

fn opts(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
        parallel_min: None,
    }
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
        // a folder needs its execute bit for the files inside it to be read back as a normal user
        FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("sub", b"") },
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

#[cfg(unix)]
#[test]
fn never_writes_through_a_link_below_a_folder_it_made() {
    let dir = tmp("deeplink");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("a/x", b"x"), FileSpec::new("a/b/c/f", b"y")])).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(out.join("a")).unwrap();
    let outside = dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, out.join("a/b")).unwrap();
    let r = extract::run(&arc, &opts(&out), |_| {});
    assert!(r.is_err());
    assert_eq!(fs::read(out.join("a/x")).unwrap(), b"x");
    assert!(!outside.join("c").exists());
}

#[test]
fn a_file_in_the_way_of_a_folder_stops_the_run() {
    let dir = tmp("fileway");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("a/b/f", b"y")])).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(out.join("a")).unwrap();
    fs::write(out.join("a/b"), b"old").unwrap();
    assert!(extract::run(&arc, &opts(&out), |_| {}).is_err());
    assert_eq!(fs::read(out.join("a/b")).unwrap(), b"old");
}

#[test]
fn a_name_repeated_in_a_folder_the_run_made_is_still_seen_as_taken() {
    let dir = tmp("repeat");
    let arc = dir.join("t.rar");
    let mut sub = FileSpec::new("d/x", b"");
    sub.dir = true;
    let files = [FileSpec::new("d/f", b"one"), FileSpec::new("d/f", b"two"), sub, FileSpec::new("d/x", b"three")];
    fs::write(&arc, archive(&files)).unwrap();

    let out = dir.join("skip");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.skipped, s.errors.len()), (1, 2, 0));
    assert_eq!(fs::read(out.join("d/f")).unwrap(), b"one");
    assert!(out.join("d/x").is_dir());

    let out = dir.join("always");
    let s = extract::run(&arc, &Options { overwrite: Overwrite::Always, ..opts(&out) }, |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (2, 1));
    assert_eq!(fs::read(out.join("d/f")).unwrap(), b"two");
    assert!(out.join("d/x").is_dir());
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

#[test]
fn checks_blake2sp_when_there_is_no_crc() {
    let dir = tmp("blake");
    let data = b"hashed with BLAKE2sp only".to_vec();
    let good = FileSpec { no_crc: true, extra: blake_record(blake(&data)), ..FileSpec::new("f", &data) };
    let arc = dir.join("good.rar");
    fs::write(&arc, archive(&[good])).unwrap();
    let s = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&dir) }, |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);

    let wrong = FileSpec { no_crc: true, extra: blake_record(blake(b"other")), ..FileSpec::new("f", &data) };
    let arc = dir.join("bad.rar");
    fs::write(&arc, archive(&[wrong])).unwrap();
    let s = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&dir) }, |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1);
}

#[test]
fn a_file_that_fails_its_checksum_is_removed() {
    let dir = tmp("crc-remove");
    let mut bytes = archive(&[FileSpec::new("f", b"0123456789")]);
    let at = bytes.windows(10).position(|w| w == b"0123456789").unwrap();
    bytes[at] = b'X';
    let arc = dir.join("t.rar");
    fs::write(&arc, bytes).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1);
    assert!(!out.join("f").exists());
}

#[test]
fn a_set_under_a_name_without_a_volume_number_is_an_error() {
    let dir = tmp("unnamed");
    let data = vec![1u8; 1000];
    // two whole files, so the first volume ends between them and nothing is left half-written
    let first = FileSpec::new("a", &data);
    let mut vol = SIG.to_vec();
    vol.extend(main_block(true, None));
    vol.extend(file_block(&first, &data, crc32fast::hash(&data), false, false));
    vol.extend(end_block(true));
    let arc = dir.join("download.bin");
    fs::write(&arc, vol).unwrap();
    let err = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&dir) }, |_| {}).unwrap_err();
    assert!(matches!(err, zipfast::Error::UnnamedVolume(_)), "{err}");
}

#[cfg(unix)]
#[test]
fn restores_a_zero_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("mode0");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec { unix_mode: Some(0o100000), ..FileSpec::new("locked", b"x") }])).unwrap();
    let out = dir.join("out");
    extract::run(&arc, &opts(&out), |_| {}).unwrap();
    let mode = fs::metadata(out.join("locked")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0);
}

#[test]
fn a_missing_volume_removes_the_half_written_file() {
    let dir = tmp("missing-clean");
    let data = vec![7u8; 1000];
    let vols = volumes(&FileSpec::new("f", &data), 400);
    fs::write(dir.join("s.part1.rar"), &vols[0]).unwrap();
    let out = dir.join("out");
    assert!(extract::run(&dir.join("s.part1.rar"), &opts(&out), |_| {}).is_err());
    assert!(!out.join("f").exists());
}

#[cfg(unix)]
#[test]
fn restores_folder_permissions_after_their_files() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("dirmode");
    let arc = dir.join("t.rar");
    let files = [
        FileSpec { dir: true, unix_mode: Some(0o500), ..FileSpec::new("locked", b"") },
        FileSpec::new("locked/f", b"x"),
    ];
    fs::write(&arc, archive(&files)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert_eq!(fs::read(out.join("locked/f")).unwrap(), b"x");
    assert_eq!(fs::metadata(out.join("locked")).unwrap().permissions().mode() & 0o777, 0o500);
    // let the temp folder be cleaned up
    fs::set_permissions(out.join("locked"), fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn a_folder_listed_after_its_file_still_gets_its_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tmp("dirmode-late");
    let arc = dir.join("t.rar");
    let files =
        [FileSpec::new("late/f", b"x"), FileSpec { dir: true, unix_mode: Some(0o510), ..FileSpec::new("late", b"") }];
    fs::write(&arc, archive(&files)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    let meta = fs::metadata(out.join("late")).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o510);
    let mtime = meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(mtime, 1_700_000_000, "the folder's own time, not the time its file was written");
    fs::set_permissions(out.join("late"), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_size_that_disagrees_with_the_header_fails() {
    let dir = tmp("size");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec { size: Some(1000), ..FileSpec::new("short", b"abc") }])).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (0, 1));
    assert!(!out.join("short").exists());
    let t = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&out) }, |_| {}).unwrap();
    assert_eq!((t.files, t.errors.len()), (0, 1));
}

#[test]
fn older_versions_are_skipped_and_the_current_file_kept() {
    let dir = tmp("versions");
    let arc = dir.join("t.rar");
    // file version record: type 4, flags 0, version 1
    let old = FileSpec { extra: vec![3, 4, 0, 1], ..FileSpec::new("f.txt", b"old") };
    fs::write(&arc, archive(&[old, FileSpec::new("f.txt", b"new")])).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.skipped, s.errors.len()), (1, 1, 0));
    assert_eq!(fs::read(out.join("f.txt")).unwrap(), b"new");
    // a test still checks the older revision
    let t = extract::run(&arc, &Options { mode: Mode::Test, ..opts(&out) }, |_| {}).unwrap();
    assert_eq!((t.files, t.skipped, t.errors.len()), (2, 0, 0));
}

#[test]
fn a_block_whose_data_runs_past_the_end_is_truncation() {
    let dir = tmp("trunc-skip");
    let arc = dir.join("t.rar");
    let data = vec![1u8; 100];
    // a file this run refuses, so its data is skipped rather than read
    let full = archive(&[FileSpec::new("a", b"ok"), FileSpec { method: 3, ..FileSpec::new("b", &data) }]);
    let cut = full.len() - end_block(false).len() - 97;
    fs::write(&arc, &full[..cut]).unwrap();
    assert!(extract::run(&arc, &Options { mode: Mode::Test, ..opts(&dir.join("out")) }, |_| {}).is_err());
}

#[test]
fn a_name_with_mapped_non_utf8_bytes_is_refused() {
    let dir = tmp("fffe");
    let arc = dir.join("t.rar");
    fs::write(&arc, archive(&[FileSpec::new("x\u{FFFE}\u{E0FF}", b"z")])).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert_eq!((s.files, s.errors.len()), (0, 1));
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
}

#[test]
fn a_big_file_is_written_whole() {
    // big enough to be written on a thread of its own
    let dir = tmp("big");
    let data: Vec<u8> = (0..9_000_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let arc = dir.join("t.rar");
    fs::write(&arc, archive_with(&[(FileSpec::new("big.bin", &data), crc32fast::hash(&data))], false)).unwrap();
    let out = dir.join("out");
    let s = extract::run(&arc, &opts(&out), |_| {}).unwrap();
    assert!(s.errors.is_empty(), "{:?}", s.errors);
    assert!(fs::read(out.join("big.bin")).unwrap() == data);
    // a wrong checksum still removes it
    let arc2 = dir.join("bad.rar");
    fs::write(&arc2, archive_with(&[(FileSpec::new("big.bin", &data), 1)], false)).unwrap();
    let out2 = dir.join("out2");
    let s = extract::run(&arc2, &opts(&out2), |_| {}).unwrap();
    assert_eq!(s.errors.len(), 1);
    assert!(!out2.join("big.bin").exists());
}

/// A read by position may move the volume (Windows does); the next header is still found where it is.
#[test]
fn headers_are_found_after_the_volume_was_moved_under_the_reader() {
    use std::io::{Seek, SeekFrom};
    use zipfast::rar5::reader::{Block, Volume};
    let dir = tmp("moved");
    let arc = dir.join("t.rar");
    // past what one read holds, so the reader has to go to the file for the next header
    let big = vec![7u8; 3 << 20];
    fs::write(&arc, archive(&[FileSpec::new("a", &big), FileSpec::new("b", b"two")])).unwrap();
    let mut vol = Volume::open(&arc).unwrap();
    let Some(Block::File(a)) = vol.next_block().unwrap() else { panic!("first file") };
    assert_eq!(a.name, "a");
    let mut file = vol.file();
    file.seek(SeekFrom::Start(1)).unwrap();
    let Some(Block::File(b)) = vol.next_block().unwrap() else { panic!("second file") };
    assert_eq!(b.name, "b");
}
