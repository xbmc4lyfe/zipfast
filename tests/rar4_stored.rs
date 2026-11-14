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

#![cfg(unix)]

use std::fs;
use zipfast::crc32::hash;
use zipfast::extract::{self, Mode, Options, Overwrite};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn member(name: &[u8], data: &[u8], flags: u16, method: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((data.len() as u32).to_le_bytes());
    body.extend((data.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(data).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([20, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = block(0x74, flags | 0x8000, &body);
    bytes.extend(data);
    bytes
}

fn archive(files: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    for file in files {
        bytes.extend(file);
    }
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}

fn options(path: &std::path::Path, mode: Mode) -> Options {
    Options {
        mode,
        dest: path.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

#[test]
fn stored_reaches_listing_bulk_selection_and_verified_print() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.rar");
    fs::write(&path, archive(&[member(b"one", b"payload", 0, 0x30), member(b"empty", b"", 0, 0x30)])).unwrap();
    let listed = extract::list(&path).unwrap();
    assert_eq!(listed.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["one", "empty"]);
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    assert_eq!(session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap().files, 2);
    let mut stdout = Vec::new();
    session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap();
    assert_eq!(stdout, b"payload");
    let out = dir.path().join("selected");
    assert_eq!(
        session
            .extract_selected(&all, &options(&out, Mode::Extract), RarDecodeLimits::default(), |_| {})
            .unwrap()
            .files,
        2
    );
    assert_eq!(fs::read(out.join("one")).unwrap(), b"payload");
    let out = dir.path().join("bulk");
    let result = extract::run(&path, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert_eq!(result.files, 2);
    assert_eq!(fs::read(out.join("one")).unwrap(), b"payload");
    assert!(extract::run(&path, &options(&out, Mode::Test), |_| {}).unwrap().errors.is_empty());
}

#[test]
fn corrupt_stored_retains_existing_output_and_emits_no_print_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.rar");
    let mut bytes = archive(&[member(b"file", b"payload", 0, 0x30)]);
    let offset = bytes.windows(7).position(|b| b == b"payload").unwrap();
    bytes[offset] ^= 1;
    fs::write(&path, bytes).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let mut stdout = Vec::new();
    assert_eq!(session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap().failed, 1);
    assert!(stdout.is_empty());
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("file"), b"keep").unwrap();
    let result = extract::run(&path, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert!(!result.errors.is_empty());
    assert_eq!(fs::read(out.join("file")).unwrap(), b"keep");
}

#[test]
fn visible_unsupported_members_remain_catalogued_without_decoding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsupported.rar");
    fs::write(
        &path,
        archive(&[
            member(b"compressed", b"", 0, 0x33),
            member(b"encrypted", b"", 4, 0x30),
            member(b"split", b"", 2, 0x30),
        ]),
    )
    .unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.entries().len(), 3);
    assert!(session.entries().all(|e| e.payload_issue().is_some()));
    let all = session.select(|_| true).unwrap();
    assert_eq!(session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap().failed, 3);
}

#[test]
fn unicode_names_preserve_raw_fields_and_bounded_decoding() {
    use zipfast::rar5::RarFormat;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unicode.rar");
    let names = [
        (b"?.txt\0\0\xaa\xe9\0.\0t\0x\0\x80t\0".as_slice(), "é.txt"),
        (b"abc\0\0\xc0\x01".as_slice(), "abc"),
        (b"abc\0\x01\xc0\x81\x01".as_slice(), "ŢţŤ"),
        (b"xx\0\0\xa0\x3d\xd8\0\xde".as_slice(), "😀"),
        ("é".as_bytes(), "é"),
    ];
    for (encoded, expected) in names {
        fs::write(&path, archive(&[member(encoded, b"x", 0x200, 0x30)])).unwrap();
        let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let entry = session.entries().next().unwrap();
        assert_eq!(entry.name(), expected);
        assert_eq!(entry.raw_name(), encoded);
        assert_eq!(entry.format(), RarFormat::Rar4);
        assert_eq!(entry.rar4_metadata().unwrap().dos_time, 0x50221884);
        assert_eq!(entry.host_os(), 1);
        assert_eq!(entry.attributes(), 0o100644);
        assert_eq!(entry.modified(), Some((1_577_934_248, 0)));
        assert_eq!(entry.rar5_compression_info(), None);
    }
}

#[test]
fn malformed_headers_unicode_and_sizes_fail_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.rar");
    for encoded in [
        b"x\0\0\x80\0\xd8".as_slice(), // unmatched high surrogate
        b"x\0\0\xc0\x7f".as_slice(),   // legacy run outside name
        b"x\0\0\x80\x01".as_slice(),   // truncated literal
    ] {
        fs::write(&path, archive(&[member(encoded, b"x", 0x200, 0x30)])).unwrap();
        assert!(RarSession::open(&path, None, RarSessionOptions::default()).is_err());
    }
    let original = archive(&[member(b"file", b"payload", 0, 0x30)]);
    for boundary in [8, 19, 26, 40, original.len() - 8] {
        fs::write(&path, &original[..boundary]).unwrap();
        assert!(RarSession::open(&path, None, RarSessionOptions::default()).is_err());
    }
    let mut corrupt = original;
    corrupt[22] ^= 1;
    fs::write(&path, corrupt).unwrap();
    assert!(RarSession::open(&path, None, RarSessionOptions::default()).is_err());
}

#[test]
fn catalogue_and_selected_limits_are_enforced_at_small_boundaries() {
    use zipfast::error::{RarFailure, RarResource};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("limits.rar");
    fs::write(&path, archive(&[member(b"file", b"payload", 0, 0x30)])).unwrap();
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let usage = session.usage();
    for (resource, below) in [
        (RarResource::CatalogueReadBytes, usage.read_bytes - 1),
        (RarResource::CatalogueBlocks, usage.header_blocks - 1),
        (RarResource::CatalogueNameBytes, usage.name_bytes - 1),
        (RarResource::CatalogueEntries, 0),
        (RarResource::CatalogueParts, 0),
        (RarResource::CatalogueVolumes, 0),
        (RarResource::CatalogueCapacity, 64),
    ] {
        let mut options = RarSessionOptions::default();
        match resource {
            RarResource::CatalogueReadBytes => options.limits.read_bytes = below,
            RarResource::CatalogueBlocks => options.limits.header_blocks = below,
            RarResource::CatalogueNameBytes => options.limits.name_bytes = below,
            RarResource::CatalogueEntries => options.limits.entries = below,
            RarResource::CatalogueParts => options.limits.parts = below,
            RarResource::CatalogueVolumes => options.limits.volumes = below,
            _ => options.limits.capacity = below,
        }
        let failure = RarSession::open(&path, None, options).err().unwrap();
        assert!(matches!(failure.failure.as_ref(), RarFailure::Limit { .. }), "{failure:?}");
    }
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let exact = RarDecodeLimits { packed_bytes: 7, decoded_bytes: 7, ..RarDecodeLimits::default() };
    assert_eq!(session.test_selected(&all, exact, |_| {}).unwrap().files, 1);
    for limits in [RarDecodeLimits { packed_bytes: 6, ..exact }, RarDecodeLimits { decoded_bytes: 6, ..exact }] {
        assert!(session.test_selected(&all, limits, |_| {}).is_err());
    }
}

fn edit_file_header(file: &mut [u8], edit: impl FnOnce(&mut [u8])) {
    let len = usize::from(u16::from_le_bytes([file[5], file[6]]));
    edit(&mut file[..len]);
    let crc = hash(&file[2..len]) as u16;
    file[..2].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn stored_size_modes_and_extended_times_are_verified() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.rar");
    let mut file = member(b"file", b"payload", 0, 0x30);
    edit_file_header(&mut file, |header| header[28..32].copy_from_slice(&0o100640u32.to_le_bytes()));
    let old = usize::from(u16::from_le_bytes([file[5], file[6]]));
    file.splice(old..old, [0, 0x90, 0x80]);
    edit_file_header(&mut file, |header| {
        let flags = u16::from_le_bytes([header[3], header[4]]) | 0x1000;
        header[3..5].copy_from_slice(&flags.to_le_bytes());
    });
    // Length was changed after inserting a bounded extended-time field.
    let size = (old + 3) as u16;
    file[5..7].copy_from_slice(&size.to_le_bytes());
    edit_file_header(&mut file, |_| {});
    fs::write(&path, archive(&[file])).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.entries().next().unwrap().modified(), Some((1_577_934_248, 838_860_800)));
    let all = session.select(|_| true).unwrap();
    let out = dir.path().join("out");
    session.extract_selected(&all, &options(&out, Mode::Extract), RarDecodeLimits::default(), |_| {}).unwrap();
    assert_eq!(fs::metadata(out.join("file")).unwrap().permissions().mode() & 0o777, 0o640);

    let mut file = member(b"file", b"payload", 0, 0x30);
    edit_file_header(&mut file, |header| header[11..15].copy_from_slice(&6u32.to_le_bytes()));
    fs::write(&path, archive(&[file])).unwrap();
    let result = extract::run(&path, &options(&out, Mode::Extract), |_| {}).unwrap();
    assert!(!result.errors.is_empty());
    assert_eq!(fs::read(out.join("file")).unwrap(), b"payload");

    let mut directory = member(b"directory", b"", 0xe0, 0x30);
    edit_file_header(&mut directory, |header| header[28..32].copy_from_slice(&0o040755u32.to_le_bytes()));
    fs::write(&path, archive(&[directory])).unwrap();
    assert!(extract::run(&path, &options(&out, Mode::Extract), |_| {}).unwrap().errors.is_empty());
    assert!(out.join("directory").is_dir());
}

#[test]
fn encrypted_headers_high_sizes_and_special_modes_have_typed_boundaries() {
    use zipfast::error::{RarFailure, RarUnsupported};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("boundary.rar");
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0x80, &[0; 6]));
    fs::write(&path, bytes).unwrap();
    let error = RarSession::open(&path, Some("password"), RarSessionOptions::default()).err().unwrap();
    assert!(matches!(
        error.failure.as_ref(),
        RarFailure::Unsupported(RarUnsupported::Rar4Feature("encrypted headers"))
    ));

    for mode in [0o120777u32, 0o010644] {
        let mut file = member(b"link", b"target", 0, 0x30);
        edit_file_header(&mut file, |header| header[28..32].copy_from_slice(&mode.to_le_bytes()));
        fs::write(&path, archive(&[file])).unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        assert!(matches!(session.entries().next().unwrap().payload_issue(), Some(RarFailure::Unsupported(_))));
        let all = session.select(|_| true).unwrap();
        let out = dir.path().join("out");
        assert_eq!(
            session
                .extract_selected(&all, &options(&out, Mode::Extract), RarDecodeLimits::default(), |_| {})
                .unwrap()
                .failed,
            1
        );
        assert!(!out.join("link").exists());
    }
    let mut file = member(b"file", b"", 0x100, 0x30);
    file.splice(32..32, [1, 0, 0, 0, 0, 0, 0, 0]);
    file[5..7].copy_from_slice(&44u16.to_le_bytes());
    edit_file_header(&mut file, |_| {});
    fs::write(&path, archive(&[file])).unwrap();
    assert!(RarSession::open(&path, None, RarSessionOptions::default()).is_err());
}

#[test]
fn signature_dispatch_and_cancellation_preserve_format_precedence() {
    use zipfast::error::RarFailure;
    use zipfast::extract::{Cancellation, Inspection};
    use zipfast::rar5::RarFormat;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sfx.rar");
    let mut bytes = b"launcher".to_vec();
    bytes.extend(archive(&[member(b"file", b"payload", 0, 0x30)]));
    fs::write(&path, bytes).unwrap();
    let inspected = extract::inspect(&path).unwrap();
    assert!(matches!(inspected, Inspection::Other(entries) if entries.len() == 1 && entries[0].name == "file"));
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.archive().format(), RarFormat::Rar4);
    assert_eq!(session.volumes().next().unwrap().format(), RarFormat::Rar4);
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use zipfast::zip::ZipRunEvent;
        let opts = options(&dir.path().join("unused"), Mode::Test);
        let report = extract::run_with_zip_policy(
            &path,
            &opts,
            None,
            &Cancellation::default(),
            &Default::default(),
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        assert_eq!((report.files(), report.failed()), (1, 0));
        let mut context = zipfast::zip::EncryptedReadContext::new(Default::default()).unwrap();
        let report = extract::run_with_zip_context(
            &path,
            &opts,
            None,
            &Cancellation::default(),
            &mut context,
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        assert_eq!((report.files(), report.failed()), (1, 0));
        for command in ["t", "l", "v"] {
            let result =
                std::process::Command::new(env!("CARGO_BIN_EXE_zipfast")).arg(command).arg(&path).output().unwrap();
            assert!(result.status.success(), "{command}: {result:?}");
            if command != "t" {
                assert!(String::from_utf8_lossy(&result.stdout).contains("file"));
            }
        }
    }
    let cancel = Cancellation::default();
    cancel.cancel();
    let options = RarSessionOptions { cancel, ..RarSessionOptions::default() };
    let failure = RarSession::open(&path, None, options).err().unwrap();
    assert!(matches!(failure.failure.as_ref(), RarFailure::Canceled));
}

#[test]
fn known_signature_avoids_payload_probes_and_sfx_search_stays_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe.rar");
    let bytes = archive(&[member(b"file", b"payload", 0, 0x30)]);
    fs::write(&path, &bytes).unwrap();
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.usage().read_bytes, 64);
    for offset in [1 << 20, (1 << 20) + 1] {
        let mut prefixed = vec![0x90; offset];
        prefixed.extend_from_slice(&bytes);
        fs::write(&path, prefixed).unwrap();
        let result = extract::list(&path);
        assert_eq!(result.is_ok(), offset == 1 << 20, "{offset}: {result:?}");
    }
}

#[test]
fn end_header_requires_the_optional_fields_declared_by_flags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("end.rar");
    for (flag, length) in [(2, 4), (4, 7), (8, 2)] {
        for actual in [0, length - 1, length] {
            let mut bytes = archive(&[]);
            bytes.truncate(bytes.len() - 7);
            bytes.extend(block(0x7b, 0x4000 | flag, &vec![0; actual]));
            fs::write(&path, bytes).unwrap();
            assert_eq!(RarSession::open(&path, None, RarSessionOptions::default()).is_ok(), actual == length,);
        }
    }
}

#[test]
fn directory_payload_or_checksum_cannot_bypass_verification() {
    use zipfast::extract::RarOutcome;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory.rar");
    for data in [b"bad".as_slice(), b""] {
        let mut directory = member(b"directory", data, 0xe0, 0x30);
        edit_file_header(&mut directory, |header| {
            header[28..32].copy_from_slice(&0o040755u32.to_le_bytes());
            if data.is_empty() {
                header[16..20].copy_from_slice(&1u32.to_le_bytes());
            }
        });
        fs::write(&path, archive(&[directory])).unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        assert!(session.entries().next().unwrap().payload_issue().is_some());
        let all = session.select(|_| true).unwrap();
        let out = dir.path().join("selected");
        let mut failures = 0;
        let result = session
            .extract_selected(&all, &options(&out, Mode::Extract), RarDecodeLimits::default(), |event| {
                if matches!(event.outcome, RarOutcome::Failed(_)) {
                    failures += 1;
                }
            })
            .unwrap();
        assert_eq!((result.failed, result.dirs, failures), (1, 0, 1));
        assert!(!out.join("directory").exists());
        for mode in [Mode::Test, Mode::Extract] {
            let out = dir.path().join("bulk");
            let result = extract::run(&path, &options(&out, mode), |_| {}).unwrap();
            assert_eq!(result.dirs, 0);
            assert!(!result.errors.is_empty());
            assert!(!out.join("directory").exists());
        }
    }
}

#[test]
fn a_volume_set_cannot_switch_between_rar4_and_rar5() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("set.part1.rar");
    let next = dir.path().join("set.part2.rar");
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 1, &[0; 6]));
    bytes.extend(block(0x7b, 0x4001, &[]));
    fs::write(&first, bytes).unwrap();
    fs::write(&next, b"Rar!\x1a\x07\x01\0\xc5\x1a\x33\x32\x03\x01\0\0\x19\xb2\x3a\x35\x03\x05\0\0").unwrap();
    assert!(RarSession::open(&first, None, RarSessionOptions::default()).is_err());
    assert!(extract::list(&first).is_err());
    assert!(extract::run(&first, &options(dir.path(), Mode::Test), |_| {}).is_err());
}
