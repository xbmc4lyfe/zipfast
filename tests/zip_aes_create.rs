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

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::fs::{self, File};
use zipfast::zip::create::{AesCreateReport, CreateOptions, CreatePlan, Durability, DurabilityState, Publication};
use zipfast::zip::write::{
    AesStrength, AesVariant, DeflateLevel, DosDateTime, EntryName, EntryOptions, Method, Permissions, WinZipAesRequest,
};
use zipfast::zip::{Archive, ReadSession};

fn options(name: EntryName<'_>, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name,
        method,
        modified: DosDateTime::new(2024, 1, 2, 3, 4, 6).unwrap(),
        extended_mtime: Some(1_700_000_000),
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"AES native member",
    }
}

#[test]
fn native_aes_all_formats_publish_verified_receipts_and_bindings() {
    for (strength, overhead) in [(AesStrength::Aes128, 20), (AesStrength::Aes192, 24), (AesStrength::Aes256, 28)] {
        for variant in [AesVariant::Ae1, AesVariant::Ae2] {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("source");
            let empty = dir.path().join("empty");
            let directory = dir.path().join("source-directory");
            let output = dir.path().join("archive.zip");
            let data = (0..=255).cycle().take(65_537).collect::<Vec<_>>();
            fs::write(&source, &data).unwrap();
            fs::write(&empty, []).unwrap();
            fs::create_dir(&directory).unwrap();
            let mut plan = CreatePlan::new(
                &output,
                CreateOptions { durability: Durability::SyncFileAndDirectory, ..Default::default() },
            )
            .unwrap();
            plan.add_open_file(
                &source,
                File::open(&source).unwrap(),
                options(EntryName::Utf8("first"), Method::Stored),
                None,
            )
            .unwrap();
            plan.add_directory_from_path(&directory, options(EntryName::Utf8("dir/"), Method::Stored), None).unwrap();
            plan.add_file(
                &source,
                options(EntryName::Raw(b"raw\x82"), Method::Deflate(DeflateLevel::new(1).unwrap())),
                None,
            )
            .unwrap();
            plan.add_file(
                &source,
                options(EntryName::Utf8("雪"), Method::Deflate(DeflateLevel::new(9).unwrap())),
                None,
            )
            .unwrap();
            plan.add_file(
                &empty,
                options(EntryName::Utf8("empty"), Method::Deflate(DeflateLevel::new(6).unwrap())),
                None,
            )
            .unwrap();
            let request = WinZipAesRequest::new("native-aes-fixture", strength, variant).unwrap();
            let (report, binding) = plan.publish_winzip_aes_with_bound_receipts(request);
            assert_eq!((report.strength, report.variant), (strength, variant));
            let result = report.outcome.unwrap();
            assert_eq!((result.publication, result.durability), (Publication::Published, DurabilityState::Synced));
            assert_eq!(
                (
                    result.summary.verification.entries,
                    result.summary.verification.payloads,
                    result.summary.verification.decoded_bytes
                ),
                (5, 4, 3 * data.len() as u64)
            );
            assert_eq!(report.written.iter().map(|r| r.ordinal).collect::<Vec<_>>(), [0, 1, 2, 3, 4]);
            assert_eq!(report.written[0].packed_size, data.len() as u64 + overhead);
            assert_eq!((report.written[4].method, report.written[4].packed_size), (Method::Stored, overhead));
            assert_eq!(report.written[1].packed_size, 0);
            assert!(binding.unwrap().matches(&fs::symlink_metadata(&output).unwrap()));
            let metadata = ReadSession::open(&output).unwrap().metadata();
            for (index, entry) in metadata.entries().enumerate() {
                assert_eq!(entry.encrypted(), index != 1);
                assert_eq!(entry.header().crc32, report.written[index].crc32);
                assert_eq!(entry.header().method, if index == 1 { 0 } else { 99 });
                if index != 1 && variant == AesVariant::Ae2 {
                    assert_eq!(report.written[index].crc32, 0);
                }
            }
            let mut archive = Archive::open(&output).unwrap();
            for (index, expected) in
                [(0, data.as_slice()), (2, data.as_slice()), (3, data.as_slice()), (4, b"".as_slice())]
            {
                let mut actual = Vec::new();
                archive
                    .read_at(index, Some("native-aes-fixture"), 1 << 20, |chunk| {
                        actual.extend_from_slice(chunk);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(actual, expected);
            }
            assert_eq!(fs::read(&source).unwrap(), data);
        }
    }
}

#[test]
fn native_aes_report_outlives_borrowed_password() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let output = dir.path().join("out.zip");
    fs::write(&source, b"abc").unwrap();
    let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    plan.add_file(&source, options(EntryName::Utf8("a"), Method::Stored), None).unwrap();
    let report: AesCreateReport = {
        let password = String::from("distinctive-native-secret-that-must-not-survive");
        let request = WinZipAesRequest::new(&password, AesStrength::Aes128, AesVariant::Ae2).unwrap();
        plan.publish_winzip_aes_with_receipts(request)
    };
    assert!(!format!("{report:?}").contains("distinctive-native-secret"));
    assert_eq!(report.written.len(), 1);
    assert_eq!(report.outcome.unwrap().publication, Publication::Published);
}

#[test]
fn native_aes_empty_and_directory_only_remain_clear() {
    for directory in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("out.zip");
        let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
        if directory {
            plan.add_directory(options(EntryName::Utf8("dir/"), Method::Stored), None).unwrap();
        }
        let report = plan.publish_winzip_aes_with_receipts(
            WinZipAesRequest::new("native-aes-fixture", AesStrength::Aes256, AesVariant::Ae1).unwrap(),
        );
        report.outcome.unwrap();
        assert_eq!(report.written.len(), usize::from(directory));
        let metadata = ReadSession::open(&output).unwrap().metadata();
        assert!(metadata.entries().all(|entry| !entry.encrypted()));
    }
}

#[test]
#[ignore = "exports native AES creation for pinned independent readers"]
fn export_native_aes_reference_fixtures() {
    let folder = std::path::PathBuf::from(std::env::var_os("ZIPFAST_AES_NATIVE_REFERENCE_DIR").unwrap());
    for (strength, bits) in [(AesStrength::Aes128, 128), (AesStrength::Aes192, 192), (AesStrength::Aes256, 256)] {
        for (variant, label) in [(AesVariant::Ae1, "ae1"), (AesVariant::Ae2, "ae2")] {
            let directory = folder.join(format!("aes{bits}-{label}"));
            let expected = directory.join("expected");
            fs::create_dir_all(expected.join("folder")).unwrap();
            let payload = (0..=255).cycle().take(65_537).collect::<Vec<_>>();
            let text = b"native AES payload\n".repeat(6000);
            let mut plan = CreatePlan::new(
                &directory.join("fixture.zip"),
                CreateOptions { archive_comment: b"AES native fixture comment".to_vec(), ..Default::default() },
            )
            .unwrap();
            let mut metadata = options(EntryName::Utf8("folder/"), Method::Stored);
            metadata.permissions = Permissions::new(0o755).unwrap();
            plan.add_directory_from_path(&expected.join("folder"), metadata, None).unwrap();
            for (name, raw, method, bytes) in [
                ("stored", false, Method::Stored, payload.as_slice()),
                ("deflate1", false, Method::Deflate(DeflateLevel::new(1).unwrap()), text.as_slice()),
                ("deflate6", false, Method::Deflate(DeflateLevel::new(6).unwrap()), text.as_slice()),
                ("deflate9", false, Method::Deflate(DeflateLevel::new(9).unwrap()), text.as_slice()),
                ("empty", false, Method::Deflate(DeflateLevel::new(6).unwrap()), b"".as_slice()),
                ("rawé", true, Method::Stored, b"raw".as_slice()),
                ("雪", false, Method::Stored, b"utf8".as_slice()),
            ] {
                let source = expected.join(name);
                fs::write(&source, bytes).unwrap();
                let name = if raw { EntryName::Raw(b"raw\x82") } else { EntryName::Utf8(name) };
                plan.add_file(&source, options(name, method), None).unwrap();
            }
            let report =
                plan.publish_winzip_aes_with_receipts(WinZipAesRequest::new("password", strength, variant).unwrap());
            report.outcome.unwrap();
            assert_eq!(report.written.len(), 8);
        }
    }
}
