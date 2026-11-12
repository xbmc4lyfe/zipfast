// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5

use std::cell::Cell;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

use flate2::{Compression, GzBuilder};
use zipfast::Error;
use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, SelectedEntry};
use zipfast::stream::gzip::{
    self, Control, DecodeOptions, DecodeOutcome, FailureKind, Limit, Limits, MemberEvent, Tail,
};
use zipfast::stream::{Codec, gzip_name};

const STRICT: DecodeOptions = DecodeOptions { tail: gzip::TailPolicy::Strict };
const TAR_MTIME: i64 = 981_173_106;
const DAMAGED: &str = "corrupt archive: compressed data is damaged";
const TRUNCATED: &str = "archive is truncated";

fn gzip_with(builder: GzBuilder, data: &[u8]) -> Vec<u8> {
    let mut out = builder.write(Vec::new(), Compression::fast());
    out.write_all(data).unwrap();
    out.finish().unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    gzip_with(GzBuilder::new(), data)
}

fn named(data: &[u8], name: &[u8]) -> Vec<u8> {
    gzip_with(GzBuilder::new().filename(name), data)
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &(name, body) in entries {
        let mut header = [0; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000640\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[136..148].copy_from_slice(format!("{TAR_MTIME:011o}\0").as_bytes());
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..265].copy_from_slice(b"ustar\x0000");
        let checksum: u32 = header.iter().copied().map(u32::from).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        bytes.extend(header);
        bytes.extend_from_slice(body);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.extend([0; 1024]);
    bytes
}

fn options(mode: Mode, dest: &Path) -> Options {
    Options {
        mode,
        dest: dest.to_owned(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

fn scan(wire: &[u8], expected: &[u8], names: &[Option<&[u8]>]) {
    let mut output = Vec::new();
    let mut headers = 0;
    let DecodeOutcome::Verified(report) =
        gzip::decode(&mut &wire[..], &mut output, STRICT, Control::default(), |event| {
            if let MemberEvent::Header(header) = event {
                assert_eq!(header.index, headers as u64);
                assert_eq!(header.metadata.filename, names[headers]);
                headers += 1;
            }
            Ok(())
        })
        .unwrap()
    else {
        panic!("expected a verified gzip stream");
    };
    assert_eq!(output, expected);
    assert_eq!(headers, names.len());
    assert_eq!(report.totals.members, names.len() as u64);
    assert_eq!(report.totals.decoded_bytes, expected.len() as u64);
    assert_eq!(report.totals.compressed_bytes, wire.len() as u64);
    assert_eq!(report.source_consumed, wire.len() as u64);
    assert_eq!(report.tail, Tail::Clean);
}

fn selected(path: &Path, index: usize, limit: u64, output: &mut Vec<u8>) -> zipfast::Result<()> {
    SelectedEntry::open(path, index, None, limit)?.read(None, |chunk| {
        output.extend_from_slice(chunk);
        Ok(())
    })
}

fn standalone(path: &Path, dest: &Path, name: &str, expected: &[u8], packed: usize) {
    let listed = extract::list(path).unwrap();
    assert_eq!(listed.len(), 1);
    let entry = &listed[0];
    assert_eq!(entry.name, name);
    assert_eq!((entry.size, entry.packed, entry.method), (expected.len() as u64, packed as u64, 8));
    assert_eq!((entry.mtime, entry.crc32, &entry.link), (None, None, &None));
    assert!(!entry.dir && !entry.encrypted && !entry.solid);

    let entry = SelectedEntry::open(path, 0, None, (expected.len().max(packed)) as u64).unwrap();
    assert_eq!(entry.name(), name);
    assert_eq!(entry.relative_path().unwrap(), Path::new(name));
    assert_eq!((entry.modified(), entry.unix_mode()), (None, None));
    let mut output = Vec::new();
    entry
        .read(None, |chunk| {
            output.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(output, expected);

    for mode in [Mode::Test, Mode::Extract] {
        let summary = extract::run(path, &options(mode, dest), |_| {}).unwrap();
        assert!(summary.errors.is_empty(), "{:?}", summary.errors);
        assert_eq!((summary.files, summary.dirs, summary.bytes), (1, 0, expected.len() as u64));
        if mode == Mode::Test {
            assert!(!dest.exists());
        }
    }
    assert_eq!(fs::read(dest.join(name)).unwrap(), expected);
    assert_eq!(fs::read_dir(dest).unwrap().count(), 1);
}

#[test]
fn standalone_empty_concatenated_and_first_member_naming() {
    let dir = tempfile::tempdir().unwrap();
    let first = b"../../outside\\C:caf\xe9?.txt";
    let later = b"ignored.txt";
    let cases = [
        ("empty.gz", "empty", gzip(b""), &b""[..], vec![None]),
        (
            "combined.gz",
            "C_café_.txt",
            [named(b"hello ", first), gzip(b""), named(b"world", later)].concat(),
            &b"hello world"[..],
            vec![Some(&first[..]), None, Some(&later[..])],
        ),
        (
            "no-name.TgZ",
            "no-name.tar",
            [gzip(b"first "), named(b"second", later)].concat(),
            &b"first second"[..],
            vec![None, Some(&later[..])],
        ),
        (
            "unusable.taz",
            "unusable.tar",
            [named(b"", b"../\\.."), named(b"fallback", later)].concat(),
            &b"fallback"[..],
            vec![Some(&b"../\\.."[..]), Some(&later[..])],
        ),
    ];
    for (archive, name, wire, data, names) in cases {
        let path = dir.path().join(archive);
        fs::write(&path, &wire).unwrap();
        scan(&wire, data, &names);
        standalone(&path, &dir.path().join(format!("{archive}-out")), name, data, wire.len());
    }
}

#[test]
fn maximum_optional_fields_are_raw_in_the_scanner_and_named_by_root() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("maximum.gz");
    let mut filename = vec![b'f'; 65_535];
    filename[65_526..].copy_from_slice(b"/leaf.txt");
    let extra = vec![0; 65_535];
    let comment = vec![b'c'; 65_535];
    let builder = GzBuilder::new().filename(&filename[..]).extra(&extra[..]).comment(&comment[..]).mtime(42);
    let mut wire = gzip_with(builder, b"maximum fields");
    // GzBuilder emits no FHCRC. Add it independently to exercise the full wire bound.
    wire[3] |= 2;
    let fields_end = 196_619;
    let fhcrc = (crc32fast::hash(&wire[..fields_end]) as u16).to_le_bytes();
    wire.splice(fields_end..fields_end, fhcrc);

    let mut seen = false;
    let outcome = gzip::decode(&mut wire.as_slice(), &mut io::sink(), STRICT, Control::default(), |event| {
        if let MemberEvent::Verified { header, .. } = event {
            assert_eq!(header.header_bytes, 196_621);
            assert_eq!(header.metadata.mtime, 42);
            assert_eq!(header.metadata.filename, Some(filename.as_slice()));
            assert_eq!(header.metadata.extra, Some(extra.as_slice()));
            assert_eq!(header.metadata.comment, Some(comment.as_slice()));
            seen = true;
        }
        Ok(())
    })
    .unwrap();
    assert!(seen);
    assert!(matches!(outcome, DecodeOutcome::Verified(_)));
    fs::write(&path, &wire).unwrap();
    assert_eq!(gzip_name(&path).unwrap().as_bytes(), filename);
    standalone(&path, &dir.path().join("out"), "leaf.txt", b"maximum fields", wire.len());

    wire[fields_end] ^= 1;
    fs::write(&path, &wire).unwrap();
    // The public name helper reads FNAME only, even if verification later fails.
    assert_eq!(gzip_name(&path).unwrap().as_bytes(), filename);
    assert_eq!(extract::list(&path).unwrap_err().to_string(), DAMAGED);
    let failure =
        gzip::decode(&mut wire.as_slice(), &mut io::sink(), STRICT, Control::default(), |_| panic!("invalid FHCRC"))
            .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Format(_)));
    assert_eq!(failure.progress.verified.members, 0);
}

#[test]
fn tar_headers_and_payload_span_gzip_members() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stream.bin");
    let body = vec![b'A'; 801];
    let entries: &[(&str, &[u8])] = &[("a", &body), ("b", b"other entry")];
    let raw_tar = tar(entries);
    let wire =
        [named(&raw_tar[..137], b"gzip-header-name"), gzip(&raw_tar[137..529]), gzip(b""), gzip(&raw_tar[529..])]
            .concat();
    fs::write(&path, &wire).unwrap();
    scan(&wire, &raw_tar, &[Some(b"gzip-header-name"), None, None, None]);

    let listed = extract::list(&path).unwrap();
    assert_eq!(listed.len(), entries.len());
    let dest = dir.path().join("out");
    let limit = raw_tar.len() as u64;
    for (index, (&(name, data), row)) in entries.iter().zip(listed).enumerate() {
        assert_eq!(row.name, name);
        assert_eq!((row.size, row.packed, row.method), (data.len() as u64, data.len() as u64, 0));
        assert_eq!((row.mtime, row.crc32), (Some(TAR_MTIME), None));
        let entry = SelectedEntry::open(&path, index, None, limit).unwrap();
        assert_eq!(entry.name(), name);
        assert_eq!((entry.modified(), entry.unix_mode()), (Some((TAR_MTIME, 0)), Some(0o640)));
        let mut output = Vec::new();
        entry
            .read(None, |chunk| {
                output.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(output, data);
    }
    for mode in [Mode::Test, Mode::Extract] {
        let summary = extract::run(&path, &options(mode, &dest), |_| {}).unwrap();
        assert!(summary.errors.is_empty(), "{:?}", summary.errors);
        assert_eq!((summary.files, summary.dirs, summary.bytes), (2, 0, 812));
        if mode == Mode::Test {
            assert!(!dest.exists());
        }
    }
    for &(name, data) in entries {
        assert_eq!(fs::read(dest.join(name)).unwrap(), data);
    }
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
}

#[test]
fn empty_tar_recognition_is_bounded_and_replays_non_tar_prefixes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zeros.gz");
    for (size, nonzero, empty_tar) in [
        (512, false, false),
        (1024, false, true),
        (1025, false, false),
        (1 << 20, false, true),
        ((1 << 20) + 512, false, false),
        (1536, true, false),
    ] {
        let mut decoded = vec![0; size];
        if nonzero {
            decoded[size - 1] = 1;
        }
        let wire = [gzip(&decoded[..317]), gzip(&decoded[317..])].concat();
        fs::write(&path, &wire).unwrap();
        scan(&wire, &decoded, &[None, None]);

        let dest = dir.path().join(format!("out-{size}"));
        if empty_tar {
            assert!(extract::list(&path).unwrap().is_empty());
            assert!(matches!(SelectedEntry::open(&path, 0, None, size as u64), Err(Error::Unsupported(reason))
                if reason == "entry index is out of range"));
            for mode in [Mode::Test, Mode::Extract] {
                let result = extract::run(&path, &options(mode, &dest), |_| {}).unwrap();
                assert!(result.errors.is_empty());
                assert_eq!((result.files, result.dirs, result.bytes), (0, 0, 0));
            }
            assert_eq!(fs::read_dir(&dest).unwrap().count(), 0);
        } else {
            standalone(&path, &dest, "zeros", &decoded, wire.len());
        }
    }
}

#[test]
fn initial_detection_has_distinct_commitment_points() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("looks-like-gzip.gz");
    let mut invalid_method = gzip(b"");
    invalid_method[2] = 7;
    for (wire, replay) in [(&b""[..], Some(0)), (b"\x1f", Some(1)), (b"\x1f\x8b", None), (&invalid_method, None)] {
        fs::write(&path, wire).unwrap();
        assert_eq!(Codec::sniff(wire), None);
        assert!(matches!(extract::list(&path), Err(Error::NotAnArchive)));
        let mut input = wire;
        let result = gzip::decode(&mut input, &mut io::sink(), STRICT, Control::default(), |_| panic!("no header"));
        if let Some(expected_len) = replay {
            let DecodeOutcome::NotGzip { prefix, prefix_len } = result.unwrap() else {
                panic!("expected replayable non-gzip input");
            };
            assert_eq!(prefix_len, expected_len);
            let mut output = Vec::new();
            prefix[..usize::from(prefix_len)].chain(input).read_to_end(&mut output).unwrap();
            assert_eq!(output, wire);
        } else {
            let failure = result.unwrap_err();
            assert!(matches!(failure.kind, FailureKind::Format(_)));
            assert_eq!(failure.phase, gzip::Phase::Header);
        }
    }
    assert_eq!(Codec::sniff(b"\x1f\x8b\x08"), Some(Codec::Gzip));
}

#[test]
fn strict_tails_fail_verification_and_preserve_standalone_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output.gz");
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("output"), b"original").unwrap();
    let body = [b'x'; 640];
    let good = gzip(&body);
    let zeros_then_member = [&[0][..], &gzip(b"still a tail")].concat();
    let mut bad_method = gzip(b"");
    bad_method[2] = 7;

    for (tail, legacy, format) in [
        (&[0][..], TRUNCATED, false),
        (&[0; 10], DAMAGED, false),
        (b"garbage tail", DAMAGED, false),
        (&zeros_then_member, DAMAGED, false),
        (b"\x1f", TRUNCATED, true),
        (&bad_method, DAMAGED, true),
    ] {
        let wire = [good.as_slice(), tail].concat();
        fs::write(&path, &wire).unwrap();
        let mut output = Vec::new();
        let failure =
            gzip::decode(&mut wire.as_slice(), &mut output, STRICT, Control::default(), |_| Ok(())).unwrap_err();
        assert_eq!(output, body);
        assert_eq!(failure.progress.verified.members, 1);
        assert_eq!(failure.progress.verified.compressed_bytes, good.len() as u64);
        if format {
            assert!(matches!(failure.kind, FailureKind::Format(_)));
        } else {
            assert!(matches!(failure.kind, FailureKind::TrailingData));
        }

        assert_eq!(extract::list(&path).unwrap_err().to_string(), legacy, "{tail:?}");
        let mut output = Vec::new();
        let error = selected(&path, 0, 4096, &mut output).unwrap_err();
        assert_eq!(error.to_string(), legacy, "{tail:?}");
        // A failed selected read may have emitted a provisional prefix.
        assert!(body.starts_with(&output));
        for mode in [Mode::Test, Mode::Extract] {
            let summary = extract::run(&path, &options(mode, &dest), |_| {}).unwrap();
            assert_eq!(summary.errors, [format!("output: {legacy}")], "{tail:?}");
            assert_eq!((summary.files, summary.dirs, summary.bytes), (0, 0, 0));
        }
        assert_eq!(fs::read(dest.join("output")).unwrap(), b"original");
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 1);
    }
    fs::write(&path, good).unwrap();
    let summary = extract::run(&path, &options(Mode::Extract, &dest), |_| {}).unwrap();
    assert!(summary.errors.is_empty());
    assert_eq!(fs::read(dest.join("output")).unwrap(), body);
}

#[test]
fn corrupt_member_after_tar_end_fails_every_verifying_root_operation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("late.tar.gz");
    let dest = dir.path().join("out");
    let selected_body = b"replacement";
    let raw_tar = tar(&[("keep", selected_body), ("new", b"new file")]);
    let first = gzip(&raw_tar);
    let extra = gzip(b"decoded bytes past the tar end");
    let good = [first.as_slice(), extra.as_slice()].concat();
    let expected_raw = [raw_tar.as_slice(), b"decoded bytes past the tar end"].concat();
    let limit = expected_raw.len() as u64;
    scan(&good, &expected_raw, &[None, None]);
    fs::write(&path, &good).unwrap();
    assert_eq!(extract::list(&path).unwrap().len(), 2);
    let mut output = Vec::new();
    selected(&path, 0, limit, &mut output).unwrap();
    assert_eq!(output, selected_body);

    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("keep"), b"original").unwrap();
    let before = fs::metadata(dest.join("keep")).unwrap();
    for trailer_field in [8, 4] {
        let mut wire = good.clone();
        let damaged = wire.len() - trailer_field;
        wire[damaged] ^= 1; // Independently damage the later CRC32 or ISIZE.
        fs::write(&path, &wire).unwrap();

        let mut output = Vec::new();
        let failure =
            gzip::decode(&mut wire.as_slice(), &mut output, STRICT, Control::default(), |_| Ok(())).unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Format(_)));
        assert_eq!(failure.progress.verified.members, 1);
        assert_eq!(failure.progress.verified.compressed_bytes, first.len() as u64);
        assert_eq!(failure.progress.verified.decoded_bytes, raw_tar.len() as u64);
        assert!(output.starts_with(&raw_tar) && expected_raw.starts_with(&output));

        assert_eq!(extract::list(&path).unwrap_err().to_string(), DAMAGED);
        let mut output = Vec::new();
        let error = selected(&path, 0, limit, &mut output).unwrap_err();
        assert_eq!(error.to_string(), DAMAGED);
        assert_eq!(output, selected_body);
        let tested = extract::run(&path, &options(Mode::Test, &dest), |_| {}).unwrap();
        assert_eq!(tested.files, 2);
        assert_eq!(tested.errors, [format!("archive: {DAMAGED}")]);

        let extracted = extract::run(&path, &options(Mode::Extract, &dest), |_| {}).unwrap();
        assert_eq!(extracted.errors, [format!("archive: {DAMAGED}")]);
        assert_eq!((extracted.files, extracted.dirs, extracted.bytes), (0, 0, 0));
        assert_eq!(fs::read(dest.join("keep")).unwrap(), b"original");
        let after = fs::metadata(dest.join("keep")).unwrap();
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(after.permissions(), before.permissions());
        assert_eq!(fs::read_dir(&dest).unwrap().count(), 1);
    }

    fs::write(&path, good).unwrap();
    let extracted = extract::run(&path, &options(Mode::Extract, &dest), |_| {}).unwrap();
    assert!(extracted.errors.is_empty());
    assert_eq!((extracted.files, extracted.bytes), (2, 19));
    assert_eq!(fs::read(dest.join("keep")).unwrap(), selected_body);
    assert_eq!(fs::read(dest.join("new")).unwrap(), b"new file");
}

#[test]
fn cancellation_and_decoded_limits_cover_the_final_drain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("drain.tgz");
    let raw_tar = tar(&[("selected", b"payload")]);
    let first = gzip(&raw_tar);
    let post_tar = [0; 512];
    let wire = [first.as_slice(), &gzip(&post_tar)].concat();
    let expected_raw = [raw_tar.as_slice(), post_tar.as_slice()].concat();
    let limit = expected_raw.len() as u64;
    fs::write(&path, &wire).unwrap();

    for cap in [limit, limit - 1] {
        let mut output = Vec::new();
        let result = selected(&path, 0, cap, &mut output);
        assert_eq!(output, b"payload");

        let mut raw = Vec::new();
        let control = Control {
            limits: Limits { source_bytes: Some(cap), decoded_bytes: Some(cap), ..Limits::default() },
            ..Control::default()
        };
        let scanned = gzip::decode(&mut wire.as_slice(), &mut raw, STRICT, control, |_| Ok(()));
        assert_eq!(raw, expected_raw[..cap as usize]);
        if cap == limit {
            result.unwrap();
            assert!(matches!(scanned.unwrap(), DecodeOutcome::Verified(report) if report.totals.members == 2));
        } else {
            assert!(matches!(result, Err(Error::Unsupported(reason))
                if reason == "compressed stream exceeds the decoded byte limit"));
            let failure = scanned.unwrap_err();
            assert!(matches!(failure.kind, FailureKind::Limit(Limit::DecodedBytes)));
            assert_eq!(failure.progress.verified.members, 1);
        }
    }

    let short_source_cap = wire.len() as u64 - 1;
    assert!(matches!(SelectedEntry::open(&path, 0, None, short_source_cap), Err(Error::Unsupported(reason))
        if reason == "compressed stream exceeds the input byte limit"));
    let control =
        Control { limits: Limits { source_bytes: Some(short_source_cap), ..Limits::default() }, ..Control::default() };
    let failure = gzip::decode(&mut wire.as_slice(), &mut io::sink(), STRICT, control, |_| Ok(())).unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Limit(Limit::SourceBytes)));
    assert_eq!(failure.progress.source_consumed, short_source_cap);
    assert_eq!(failure.progress.verified.members, 1);

    let cancel = Cancellation::default();
    let entry = SelectedEntry::open_cancelable(&path, 0, None, limit, cancel.clone()).unwrap();
    let mut output = Vec::new();
    let failure = entry
        .read(None, |bytes| {
            output.extend_from_slice(bytes);
            cancel.cancel();
            Ok(())
        })
        .unwrap_err();
    assert_eq!(output, b"payload");
    assert!(matches!(failure, Error::Io(error)
        if error.kind() == io::ErrorKind::ConnectionAborted && error.to_string() == "operation canceled"));

    // The generic API exposes a member boundary where the caller can cancel before decoding post-tar bytes.
    let cancelled = Cell::new(false);
    let control = Control { cancelled: Some(&|| cancelled.get()), ..Control::default() };
    let mut raw = Vec::new();
    let failure = gzip::decode(&mut wire.as_slice(), &mut raw, STRICT, control, |event| {
        if matches!(event, MemberEvent::Verified { .. }) {
            cancelled.set(true);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Cancelled));
    assert_eq!(failure.progress.verified.members, 1);
    assert_eq!(raw, raw_tar);
}

#[test]
fn valid_gzip_can_fail_root_prepublication_checks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blocked.tar.gz");
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("keep"), b"original").unwrap();
    fs::write(dest.join("blocked"), b"obstruction").unwrap();

    let raw_tar = tar(&[("keep", b"replacement"), ("blocked/child", b"new")]);
    let wire = gzip(&raw_tar);
    fs::write(&path, &wire).unwrap();
    scan(&wire, &raw_tar, &[None]);
    assert_eq!(extract::list(&path).unwrap().len(), 2);
    let error = extract::run(&path, &options(Mode::Extract, &dest), |_| {}).unwrap_err();
    assert!(matches!(error, Error::UnsafePath(ref path) if Path::new(path) == dest.join("blocked")));
    assert_eq!(fs::read(dest.join("keep")).unwrap(), b"original");
    assert_eq!(fs::read(dest.join("blocked")).unwrap(), b"obstruction");
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
}

#[test]
fn standalone_overwrite_skip_does_not_verify_unread_members() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("output.gz");
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("output"), b"original").unwrap();

    let mut later = gzip(b"");
    let crc = later.len() - 8;
    later[crc] ^= 1;
    let first = gzip(&[b'x'; 512]); // Exactly the bytes needed for classification.
    let wire = [first.as_slice(), later.as_slice()].concat();
    fs::write(&path, &wire).unwrap();

    let failure =
        gzip::decode(&mut wire.as_slice(), &mut io::sink(), STRICT, Control::default(), |_| Ok(())).unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Format(_)));
    assert_eq!(failure.progress.verified.members, 1);
    assert_eq!(extract::list(&path).unwrap_err().to_string(), DAMAGED);
    let tested = extract::run(&path, &options(Mode::Test, &dest), |_| {}).unwrap();
    assert_eq!(tested.errors, [format!("output: {DAMAGED}")]);

    let skipped =
        extract::run(&path, &Options { overwrite: Overwrite::Skip, ..options(Mode::Extract, &dest) }, |_| {}).unwrap();
    assert!(skipped.errors.is_empty());
    assert_eq!((skipped.files, skipped.skipped, skipped.bytes), (0, 1, 0));
    assert_eq!(fs::read(dest.join("output")).unwrap(), b"original");
}
