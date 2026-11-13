use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;
use zipfast::zip::write::split::{Location, Options, VolumeProvider, ZipSplitWriter};
use zipfast::zip::write::{DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions};

#[derive(Clone, Default)]
struct Volumes(Rc<RefCell<Vec<Vec<u8>>>>);
struct Sink(Volumes, usize);
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.0.borrow_mut()[self.1].extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl VolumeProvider for Volumes {
    type Sink = Sink;
    fn open(&mut self, disk: u32) -> io::Result<Sink> {
        assert_eq!(self.0.borrow().len(), disk as usize);
        self.0.borrow_mut().push(Vec::new());
        Ok(Sink(self.clone(), disk as usize))
    }
}
fn options(name: &str, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"comment PK\x05\x06",
    }
}
fn u16at(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) as usize
}
fn u32at(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as u64
}
fn u64at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

// Parse lengths and field positions directly, without writer or container helpers.
fn parse(volumes: &[Vec<u8>], wanted: &[(&str, Vec<u8>)]) {
    fn cover(seen: &mut [Vec<bool>], disk: usize, at: usize, len: usize) {
        for bit in &mut seen[disk][at..at + len] {
            assert!(!*bit, "overlapping split ranges");
            *bit = true;
        }
    }
    let mut seen = volumes.iter().map(|v| vec![false; v.len()]).collect::<Vec<_>>();
    cover(&mut seen, 0, 0, 4);
    assert_eq!(&volumes[0][..4], b"PK\x07\x08");
    let last = volumes.last().unwrap();
    let e = last.windows(4).rposition(|b| b == b"PK\x05\x06").unwrap();
    assert_eq!(e + 22 + u16at(last, e + 20), last.len());
    let wide = e >= 20 && &last[e - 20..e - 16] == b"PK\x06\x07";
    let tail_start = if wide { u64at(last, e - 12) as usize } else { e };
    cover(&mut seen, volumes.len() - 1, tail_start, last.len() - tail_start);
    let (disk, offset, count, size, this_count) = if wide {
        let l = e - 20;
        let z = u64at(last, l + 8) as usize;
        assert_eq!(u32at(last, l + 4), (volumes.len() - 1) as u64);
        assert_eq!(u32at(last, l + 16), volumes.len() as u64);
        assert_eq!(&last[z..z + 4], b"PK\x06\x06");
        assert_eq!(u32at(last, z + 16), (volumes.len() - 1) as u64);
        (
            u32at(last, z + 20) as usize,
            u64at(last, z + 48) as usize,
            u64at(last, z + 32),
            u64at(last, z + 40),
            u64at(last, z + 24),
        )
    } else {
        assert_eq!(u16at(last, e + 4), volumes.len() - 1);
        (
            u16at(last, e + 6),
            u32at(last, e + 16) as usize,
            u16at(last, e + 10) as u64,
            u32at(last, e + 12),
            u16at(last, e + 8) as u64,
        )
    };
    assert_eq!(count, wanted.len() as u64);
    let (mut d, mut at) = (disk, offset);
    let mut central_bytes = 0;
    let mut on_last = 0;
    for (name, payload) in wanted {
        if at == volumes[d].len() {
            d += 1;
            at = 0;
        }
        let c = &volumes[d][at..];
        assert_eq!(&c[..4], b"PK\x01\x02");
        let (n, x, m) = (u16at(c, 28), u16at(c, 30), u16at(c, 32));
        assert_eq!(&c[46..46 + n], name.as_bytes());
        let mut decoded = u32at(c, 24);
        let mut packed = u32at(c, 20);
        let mut local = u32at(c, 42);
        let mut start = u16at(c, 34) as u64;
        let mut extra = &c[46 + n..46 + n + x];
        while !extra.is_empty() {
            let len = u16at(extra, 2);
            if u16at(extra, 0) == 1 {
                let mut p = 4;
                if decoded == u32::MAX as u64 {
                    decoded = u64at(extra, p);
                    p += 8;
                }
                if packed == u32::MAX as u64 {
                    packed = u64at(extra, p);
                    p += 8;
                }
                if local == u32::MAX as u64 {
                    local = u64at(extra, p);
                    p += 8;
                }
                if start == u16::MAX as u64 {
                    start = u32at(extra, p);
                }
            }
            extra = &extra[4 + len..];
        }
        assert_eq!(decoded, payload.len() as u64);
        let (mut pd, mut po) = (start as usize, local as usize);
        let h = &volumes[pd][po..];
        assert_eq!(&h[..4], b"PK\x03\x04");
        let header = 30 + u16at(h, 26) + u16at(h, 28);
        assert!(po + header <= volumes[pd].len());
        assert_eq!(&h[30..30 + n], name.as_bytes());
        cover(&mut seen, pd, po, header);
        po += header;
        let mut compressed = Vec::new();
        let mut left = packed as usize;
        while left > 0 {
            if po == volumes[pd].len() {
                pd += 1;
                po = 0;
            }
            let len = left.min(volumes[pd].len() - po);
            cover(&mut seen, pd, po, len);
            compressed.extend_from_slice(&volumes[pd][po..po + len]);
            po += len;
            left -= len;
        }
        let actual = if u16at(c, 10) == 8 {
            use std::io::Read;
            let mut b = Vec::new();
            let mut decoder = flate2::read::DeflateDecoder::new(compressed.as_slice());
            decoder.read_to_end(&mut b).unwrap();
            assert_eq!(decoder.total_in(), compressed.len() as u64);
            b
        } else {
            compressed
        };
        assert_eq!(&actual, payload);
        assert_eq!(u32at(c, 16), crc32fast::hash(payload) as u64);
        if u16at(h, 6) & 8 != 0 {
            if po == volumes[pd].len() {
                pd += 1;
                po = 0;
            }
            let width = if u32at(h, 18) == u32::MAX as u64 { 24 } else { 16 };
            cover(&mut seen, pd, po, width);
            let desc = &volumes[pd][po..];
            assert_eq!(&desc[..4], b"PK\x07\x08");
            assert_eq!(u32at(desc, 4), u32at(c, 16));
            if u32at(h, 18) == u32::MAX as u64 {
                assert_eq!(u64at(desc, 8), packed);
                assert_eq!(u64at(desc, 16), decoded);
            } else {
                assert_eq!(u32at(desc, 8), packed);
                assert_eq!(u32at(desc, 12), decoded);
            }
        }
        let len = 46 + n + x + m;
        assert!(at + len <= volumes[d].len());
        cover(&mut seen, d, at, len);
        central_bytes += len as u64;
        if d == volumes.len() - 1 {
            on_last += 1;
        }
        at += len;
    }
    assert_eq!(central_bytes, size);
    assert_eq!(on_last, this_count);
    assert!(seen.iter().flatten().all(|&byte| byte), "unclaimed split bytes");
}

#[test]
fn one_disk_and_many_disk_records_have_exact_independent_geometry() {
    for capacity in [256, 65536] {
        let volumes = Volumes::default();
        let mut writer =
            ZipSplitWriter::new(volumes.clone(), Options { volume_bytes: capacity, ..Options::default() }).unwrap();
        let mut wanted = Vec::new();
        writer.add_directory(options("dir/", Method::Stored)).unwrap();
        wanted.push(("dir/", Vec::new()));
        for (name, data, method, length) in [
            ("dir/stored", (0..=255).cycle().take(917).collect::<Vec<_>>(), Method::Stored, InputLength::Exact(917)),
            (
                "deflated",
                b"PK\x03\x04abcPK\x07\x08def".repeat(200),
                Method::Deflate(DeflateLevel::new(6).unwrap()),
                InputLength::Unknown,
            ),
            ("empty", Vec::new(), Method::Stored, InputLength::Exact(0)),
        ] {
            let receipt = writer.add_file(options(name, method), &mut data.as_slice(), length).unwrap();
            assert_eq!(receipt.ordinal, wanted.len() as u64);
            assert_eq!(receipt.decoded_size, data.len() as u64);
            if wanted.len() == 1 {
                assert_ne!(receipt.local, Location { disk: 0, offset: 0 });
            }
            wanted.push((name, data));
        }
        let finished = writer.finish().unwrap();
        assert_eq!(finished.usage.bytes, volumes.0.borrow().iter().map(|v| v.len() as u64).sum());
        assert!(volumes.0.borrow().iter().all(|v| v.len() as u64 <= capacity));
        parse(&volumes.0.borrow(), &wanted);
    }
}

#[test]
fn known_minimum_output_is_rejected_before_reading_the_source() {
    use zipfast::zip::write::{WriteLimits, WriterOptions};
    struct Unread;
    impl io::Read for Unread {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("preflight read a refused input")
        }
    }
    let volumes = Volumes::default();
    let mut writer = ZipSplitWriter::new(
        volumes.clone(),
        Options {
            writer: WriterOptions {
                limits: WriteLimits { output_bytes: 100, ..WriteLimits::default() },
                ..WriterOptions::default()
            },
            ..Options::default()
        },
    )
    .unwrap();
    assert!(writer.add_file(options("a", Method::Stored), &mut Unread, InputLength::Exact(80)).is_err());
    assert_eq!(*volumes.0.borrow(), [b"PK\x07\x08"]);
}

#[test]
fn central_records_and_final_group_roll_without_stale_disk_fields() {
    for size in [65428, 65444, 65500, 65370, 65440] {
        let volumes = Volumes::default();
        let mut writer =
            ZipSplitWriter::new(volumes.clone(), Options { volume_bytes: 65536, ..Options::default() }).unwrap();
        let data = vec![b'a'; size];
        let mut entry = options("a", Method::Stored);
        entry.comment = b"";
        writer.add_file(entry, &mut data.as_slice(), InputLength::Exact(size as u64)).unwrap();
        let done = writer.finish().unwrap();
        if size == 65428 {
            assert_eq!(done.central_start, Location { disk: 1, offset: 0 });
        }
        parse(&volumes.0.borrow(), &[("a", data)]);
    }
    let volumes = Volumes::default();
    let mut writer =
        ZipSplitWriter::new(volumes.clone(), Options { volume_bytes: 1024, ..Options::default() }).unwrap();
    let names = (0..120).map(|n| format!("member-{n:04}-{}", "n".repeat(38))).collect::<Vec<_>>();
    for name in &names {
        writer.add_file(options(name, Method::Stored), &mut b"".as_slice(), InputLength::Exact(0)).unwrap();
    }
    let done = writer.finish().unwrap();
    assert!(done.usage.disks > 10);
    parse(&volumes.0.borrow(), &names.iter().map(|name| (name.as_str(), Vec::new())).collect::<Vec<_>>());
}

#[test]
fn local_and_descriptor_rollover_keep_records_intact() {
    let volumes = Volumes::default();
    let mut writer = ZipSplitWriter::new(volumes.clone(), Options { volume_bytes: 256, ..Options::default() }).unwrap();
    let mut entry = options("a", Method::Stored);
    entry.comment = b"";
    let first = vec![b'a'; 211];
    writer.add_file(entry, &mut first.as_slice(), InputLength::Exact(211)).unwrap();
    assert_eq!(volumes.0.borrow()[0].len(), 246);
    let mut entry = options("second", Method::Stored);
    entry.comment = b"";
    let second = vec![b'b'; 210];
    let receipt = writer.add_file(entry, &mut second.as_slice(), InputLength::Exact(210)).unwrap();
    assert_eq!(receipt.local, Location { disk: 1, offset: 16 });
    writer.finish().unwrap();
    parse(&volumes.0.borrow(), &[("a", first), ("second", second)]);
}

#[test]
#[ignore = "exports split fixtures for pinned independent readers"]
fn export_split_fixtures() {
    let root = std::path::PathBuf::from(std::env::var_os("ZIPFAST_SPLIT_REFERENCE_DIR").unwrap());
    for (label, size, unknown) in [
        ("one", 1, false),
        ("tail", 65428, false),
        ("first-central", 65500, false),
        ("zip64", 65440, true),
        ("spanning", 180000, false),
    ] {
        let volumes = Volumes::default();
        let mut writer =
            ZipSplitWriter::new(volumes.clone(), Options { volume_bytes: 65536, ..Options::default() }).unwrap();
        let data = (0..=255).cycle().take(size).collect::<Vec<_>>();
        let mut entry = options("a", Method::Stored);
        entry.comment = b"";
        writer
            .add_file(
                entry,
                &mut data.as_slice(),
                if unknown { InputLength::Unknown } else { InputLength::Exact(size as u64) },
            )
            .unwrap();
        writer.finish().unwrap();
        parse(&volumes.0.borrow(), &[("a", data.clone())]);
        let dir = root.join(label);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.expected"), data).unwrap();
        let volumes = volumes.0.borrow();
        for (disk, bytes) in volumes.iter().enumerate() {
            let name = if disk + 1 == volumes.len() { "arc.zip".to_string() } else { format!("arc.z{:02}", disk + 1) };
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }
    for label in ["deflate-spanning", "deflate-two"] {
        let size = if label == "deflate-two" { 80000 } else { 180000 };
        let mut state = 0xabcdef01u32;
        let data = (0..size)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect::<Vec<_>>();
        let volumes = Volumes::default();
        let mut writer =
            ZipSplitWriter::new(volumes.clone(), Options { volume_bytes: 65536, ..Default::default() }).unwrap();
        let mut entry = options("a", Method::Deflate(DeflateLevel::new(6).unwrap()));
        entry.comment = b"";
        writer.add_file(entry, &mut data.as_slice(), InputLength::Exact(data.len() as u64)).unwrap();
        writer.finish().unwrap();
        parse(&volumes.0.borrow(), &[("a", data.clone())]);
        let dir = root.join(label);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.expected"), data).unwrap();
        let volumes = volumes.0.borrow();
        for (disk, bytes) in volumes.iter().enumerate() {
            let name = if disk + 1 == volumes.len() { "arc.zip".to_string() } else { format!("arc.z{:02}", disk + 1) };
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }

    let volumes = Volumes::default();
    let mut writer = ZipSplitWriter::new(
        volumes.clone(),
        Options {
            volume_bytes: 65536,
            writer: zipfast::zip::write::WriterOptions { comment: b"archive comment", ..Default::default() },
            ..Default::default()
        },
    )
    .unwrap();
    let mut wanted = Vec::new();
    writer.add_directory(options("dir/", Method::Stored)).unwrap();
    wanted.push(("dir/".to_string(), Vec::new()));
    for n in 0..1200 {
        let name = format!("dir/member-{n:04}-{}", "n".repeat(32));
        writer.add_file(options(&name, Method::Stored), &mut b"".as_slice(), InputLength::Exact(0)).unwrap();
        wanted.push((name, Vec::new()));
    }
    writer.finish().unwrap();
    parse(&volumes.0.borrow(), &wanted.iter().map(|(name, data)| (name.as_str(), data.clone())).collect::<Vec<_>>());
    let dir = root.join("central-many");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("names.expected"),
        wanted.iter().map(|(name, _)| name.as_str()).collect::<Vec<_>>().join("\n"),
    )
    .unwrap();
    let volumes = volumes.0.borrow();
    for (disk, bytes) in volumes.iter().enumerate() {
        let name = if disk + 1 == volumes.len() { "arc.zip".to_string() } else { format!("arc.z{:02}", disk + 1) };
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    let volumes = Volumes::default();
    let comment = vec![b'x'; 65500];
    let mut writer = ZipSplitWriter::new(
        volumes.clone(),
        Options {
            volume_bytes: 65536,
            writer: zipfast::zip::write::WriterOptions { comment: &comment, ..Default::default() },
            ..Default::default()
        },
    )
    .unwrap();
    let mut entry = options("a", Method::Stored);
    entry.comment = b"";
    writer.add_file(entry, &mut b"one".as_slice(), InputLength::Exact(3)).unwrap();
    writer.finish().unwrap();
    parse(&volumes.0.borrow(), &[("a", b"one".to_vec())]);
    let dir = root.join("classic-large-comment-end-only");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.expected"), b"one").unwrap();
    let volumes = volumes.0.borrow();
    for (disk, bytes) in volumes.iter().enumerate() {
        let name = if disk + 1 == volumes.len() { "arc.zip".to_string() } else { format!("arc.z{:02}", disk + 1) };
        std::fs::write(dir.join(name), bytes).unwrap();
    }

    for wide in [false, true] {
        let volumes = Volumes::default();
        let comment = vec![b'x'; if wide { 65390 } else { 65470 }];
        let mut writer = ZipSplitWriter::new(
            volumes.clone(),
            Options {
                volume_bytes: 65536,
                writer: zipfast::zip::write::WriterOptions::default(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = options("a", Method::Stored);
        entry.comment = &comment;
        writer
            .add_file(entry, &mut b"one".as_slice(), if wide { InputLength::Unknown } else { InputLength::Exact(3) })
            .unwrap();
        writer.finish().unwrap();
        parse(&volumes.0.borrow(), &[("a", b"one".to_vec())]);
        let dir = root.join(if wide { "zip64-end-only" } else { "classic-end-only" });
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.expected"), b"one").unwrap();
        let volumes = volumes.0.borrow();
        for (disk, bytes) in volumes.iter().enumerate() {
            let name = if disk + 1 == volumes.len() { "arc.zip".to_string() } else { format!("arc.z{:02}", disk + 1) };
            std::fs::write(dir.join(name), bytes).unwrap();
        }
    }
}

#[test]
fn classic_and_zip64_end_only_disks_have_zero_central_count() {
    for wide in [false, true] {
        let volumes = Volumes::default();
        let comment = vec![b'x'; if wide { 65390 } else { 65470 }];
        let mut writer = ZipSplitWriter::new(
            volumes.clone(),
            Options {
                volume_bytes: 65536,
                writer: zipfast::zip::write::WriterOptions::default(),
                ..Default::default()
            },
        )
        .unwrap();
        let mut entry = options("a", Method::Stored);
        entry.comment = &comment;
        writer
            .add_file(entry, &mut b"one".as_slice(), if wide { InputLength::Unknown } else { InputLength::Exact(3) })
            .unwrap();
        let done = writer.finish().unwrap();
        assert_eq!(done.usage.disks, 3);
        assert_eq!(done.zip64, wide);
        parse(&volumes.0.borrow(), &[("a", b"one".to_vec())]);
    }
}

#[test]
fn provider_failure_preserves_the_first_error_and_provisional_writer_counters() {
    struct Fails(Volumes);
    impl VolumeProvider for Fails {
        type Sink = Sink;
        fn open(&mut self, disk: u32) -> io::Result<Sink> {
            if disk == 1 { Err(io::ErrorKind::PermissionDenied.into()) } else { self.0.open(disk) }
        }
    }
    let volumes = Volumes::default();
    let mut writer =
        ZipSplitWriter::new(Fails(volumes.clone()), Options { volume_bytes: 256, ..Default::default() }).unwrap();
    let error = writer
        .add_file(options("a", Method::Stored), &mut [42; 1000].as_slice(), InputLength::Exact(1000))
        .unwrap_err();
    assert_eq!(error.at, Location { disk: 1, offset: 0 });
    assert_eq!(error.usage.bytes, 256);
    assert_eq!(error.writer.source_bytes, 1000);
    assert_eq!(error.writer.output_bytes, 256);
    assert_eq!(error.writer.entries, 0);
    assert!(std::sync::Arc::ptr_eq(&error, &writer.add_directory(options("dir/", Method::Stored)).unwrap_err()));
    assert!(std::sync::Arc::ptr_eq(&error, &writer.finish().err().unwrap()));
}

#[test]
fn source_failure_and_metadata_limits_keep_their_typed_causes() {
    use zipfast::zip::write::split::ErrorKind;
    use zipfast::zip::write::{WriteError, WriteLimits, WriterOptions};
    let volumes = Volumes::default();
    let mut writer = ZipSplitWriter::new(
        volumes.clone(),
        Options {
            writer: WriterOptions {
                limits: WriteLimits { metadata_capacity: 1, ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let error = writer.add_file(options("a", Method::Stored), &mut b"x".as_slice(), InputLength::Exact(1)).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Writer(WriteError::Limit(_))));
    assert_eq!(*volumes.0.borrow(), [b"PK\x07\x08"]);
    let volumes = Volumes::default();
    let mut writer = ZipSplitWriter::new(volumes, Options::default()).unwrap();
    let error = writer.add_file(options("a", Method::Stored), &mut b"x".as_slice(), InputLength::Exact(2)).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Writer(WriteError::SizeUnderrun { expected: 2, actual: 1 })));
    assert!(std::sync::Arc::ptr_eq(&error, &writer.finish().err().unwrap()));
}

#[test]
fn refused_member_preflight_keeps_the_split_writer_reusable() {
    use zipfast::zip::write::{WriteLimits, WriterOptions};
    for oversized in [false, true] {
        let volumes = Volumes::default();
        let mut writer = ZipSplitWriter::new(
            volumes.clone(),
            Options {
                volume_bytes: 256,
                writer: WriterOptions {
                    limits: WriteLimits { output_bytes: 200, ..Default::default() },
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let name = if oversized { "n".repeat(300) } else { "too-large".to_string() };
        assert!(
            writer
                .add_file(options(&name, Method::Stored), &mut [42; 1000].as_slice(), InputLength::Exact(1000))
                .is_err()
        );
        assert_eq!(*volumes.0.borrow(), [b"PK\x07\x08"]);
        writer.add_file(options("a", Method::Stored), &mut b"x".as_slice(), InputLength::Exact(1)).unwrap();
        writer.finish().unwrap();
        parse(&volumes.0.borrow(), &[("a", b"x".to_vec())]);
    }
}

#[test]
fn impossible_initial_end_geometry_never_opens_a_volume() {
    use zipfast::zip::write::{WriteLimits, WriterOptions};
    for (capacity, comment, output) in [
        (16, b"".as_slice(), 1000),
        (64, b"large archive comment".as_slice(), 25),
        (32, b"large archive comment".as_slice(), 1000),
    ] {
        let volumes = Volumes::default();
        let result = ZipSplitWriter::new(
            volumes.clone(),
            Options {
                volume_bytes: capacity,
                writer: WriterOptions {
                    comment,
                    limits: WriteLimits { output_bytes: output, ..Default::default() },
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        assert!(result.is_err());
        assert!(volumes.0.borrow().is_empty());
    }
}
