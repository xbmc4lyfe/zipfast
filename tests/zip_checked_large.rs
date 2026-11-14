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

//! Opt-in real-byte qualification. Fixture path environment only; no limit overrides.
#![cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(dead_code)] // Native fixtures and small helpers are also shared with zip_checked_resources.
#[path = "common/zip_checked.rs"]
mod checked;
use std::io::Read;
use std::path::Path;
use zipfast::extract::{Cancellation, SelectedEntry};
use zipfast::zip::write::{AesStrength, AesVariant, DeflateLevel, Method};
use zipfast::zip::*;

fn complete_reads(path: &Path, size: u64, old_succeeds: bool) {
    let expected = checked::repeated_digest(0, size);
    let cancel = Cancellation::default();
    let mut old = Archive::open(path).unwrap();
    let mut hash = checked::Digest::default();
    let result = old.read_at(0, Some("password"), u64::MAX, |b| {
        assert!(b.iter().all(|v| *v == 0));
        hash.update(b);
        Ok(())
    });
    if old_succeeds {
        result.unwrap();
        assert_eq!(hash.finish(), expected);
    } else {
        assert!(result.is_err());
        assert_eq!(hash.finish().0, 0);
    }
    let mut projected = ProjectedReadSession::open(path, &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut projected,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::Callback,
        Some("password"),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    assert_eq!(context.options().limits().member_decoded_bytes, size);
    let mut hash = checked::Digest::default();
    projected
        .read_at_with_context(0, Some("password"), u64::MAX, &cancel, &mut context, |b| {
            assert!(b.iter().all(|v| *v == 0));
            hash.update(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(hash.finish(), expected);
    assert_eq!(context.usage().live_spool_bytes, 0);
    println!("projected size={size} usage={:?} run={:?}", context.usage(), context.run_usage());

    let mut retained = ReadSession::open(path).unwrap();
    let id = retained.metadata().entry_id(0).unwrap();
    let mut context = EncryptedReadContext::for_session(
        &mut retained,
        &id,
        None,
        ZipReadOutput::Callback,
        Some("password"),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let mut hash = checked::Digest::default();
    retained
        .select(&id, u64::MAX, cancel.clone())
        .unwrap()
        .read_with_context(Some("password"), &mut context, |b| {
            hash.update(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(hash.finish(), expected);
    let mut selected =
        SelectedEntry::open_cancelable_with_zip_limit(path, 0, None, u64::MAX, None, cancel.clone()).unwrap();
    let mut context =
        selected.zip_read_context(Some("password"), ZipReadOutput::Callback, &Default::default()).unwrap().unwrap();
    let mut hash = checked::Digest::default();
    selected
        .read_with_zip_context(Some("password"), &mut context, |b| {
            hash.update(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(hash.finish(), expected);

    // Prove real staged extraction admission at original geometry, without publishing 8GiB+ output.
    let output = tempfile::tempdir().unwrap();
    let mut session = ProjectedReadSession::open(path, &cancel).unwrap();
    let context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::StagedFiles { destination: output.path() },
        Some("password"),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    assert_eq!(context.options().limits().member_decoded_bytes, size);
    assert!(context.options().limits().live_spool_bytes >= size as u128); // Combined ciphertext plus staged plaintext allowance.
    drop(context);
    assert_eq!(std::fs::read_dir(output.path()).unwrap().count(), 0);

    let options = checked::options(output.path(), false);
    let report = zipfast::zip::run_with_policy(
        path,
        &options,
        Some("password"),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed(), report.decoded_bytes()), (1, 0, size as u128));
    let mut limits = EncryptedReadLimits::default();
    limits.member_packed_bytes = old.entries[0].packed;
    limits.member_decoded_bytes = size;
    limits.member_spool_bytes = size.max(old.entries[0].packed);
    limits.live_spool_bytes = 2 * (size as u128);
    let mut context = EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
    let report = zipfast::zip::run_with_context(
        path,
        &options,
        Some("password"),
        &cancel,
        &mut context,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed(), report.decoded_bytes()), (1, 0, size as u128));
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q", "-mt1", "-ppassword"])
        .arg(path)
        .env_remove("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES")
        .env_remove("ZIPFAST_ZIP_TEMP_BYTES")
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    if let Some(binary) = std::env::var_os("ZIPFAST_TASK6_OLD_BINARY") {
        let result =
            std::process::Command::new(binary).args(["t", "-q", "-mt1", "-ppassword"]).arg(path).output().unwrap();
        assert_eq!(result.status.success(), old_succeeds);
    }
    println!("complete real reads U={size} digest={:02x?}", expected.1);
}

#[test]
#[ignore = "reads retained real 128MiB+1 member through public APIs and binary"]
fn retained_over_128m_actual_entrypoints_and_publication() {
    let path = std::env::var_os("ZIPFAST_TASK6_LARGE_ZIP").expect("set retained fixture path");
    let path = Path::new(&path);
    let archive = Archive::open(path).unwrap();
    assert_eq!((archive.entries[0].size, archive.entries[0].packed), (134217729, 134217757));
    complete_reads(path, 134217729, false);
    let dir = tempfile::tempdir().unwrap();
    let cancel = Cancellation::default();
    let options = checked::options(dir.path(), true);
    let report = zipfast::zip::run_with_policy(
        path,
        &options,
        Some("password"),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.files(), 1);
    let expected = checked::repeated_digest(0, 134217729);
    let output = dir.path().join("large");
    assert_eq!(checked::file_digest(&output), expected);
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let report = zipfast::zip::run_with_context(
        path,
        &options,
        Some("password"),
        &cancel,
        &mut context,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (1, 0));
    assert_eq!(checked::file_digest(&output), expected);
    let report = zipfast::extract::run_with_zip_policy(
        path,
        &options,
        Some("password"),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (1, 0));
    assert_eq!(checked::file_digest(&output), expected);
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let report = zipfast::extract::run_with_zip_context(
        path,
        &options,
        Some("password"),
        &cancel,
        &mut context,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed()), (1, 0));
    assert_eq!(checked::file_digest(&output), expected);
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["x", "-y", "-q", "-mt1", "-ppassword"])
        .arg(path)
        .arg(dir.path())
        .env_remove("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES")
        .env_remove("ZIPFAST_ZIP_TEMP_BYTES")
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(checked::file_digest(&output), expected);
    let old = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().path()).collect::<Vec<_>>();
    let report = zipfast::zip::run_with_policy(
        path,
        &options,
        Some("wrong"),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.failed(), 1);
    assert_eq!(checked::file_digest(&old[0]), checked::repeated_digest(0, 134217729));
}

#[test]
#[ignore = "generates and fully reads real encrypted >8GiB decoded fixture; bounded memory and discard"]
fn actual_decoded_over_8g_default_refusal_vs_derived_policy_and_legacy_compatibility() {
    let path = std::env::var_os("ZIPFAST_TASK6_HUGE_ZIP").expect("set persistent generated fixture path");
    let path = Path::new(&path);
    let size = (8u64 << 30) + 1;
    if !path.exists() {
        checked::aes_file(
            path,
            &mut std::io::repeat(0).take(size),
            size,
            "password",
            AesStrength::Aes256,
            AesVariant::Ae2,
            Method::Deflate(DeflateLevel::new(1).unwrap()),
        );
    }
    let archive = Archive::open(path).unwrap();
    assert_eq!(archive.entries[0].size, size);
    assert!(archive.entries[0].packed < 128 << 20);
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(path, &cancel).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let error = session
        .read_at_with_context(0, Some("password"), u64::MAX, &cancel, &mut context, |_| {
            panic!("default refusal before bytes")
        })
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::MemberDecodedBytes, .. })));
    complete_reads(path, size, true);
}

#[test]
#[ignore = "retained native writer fixtures independently qualified by pinned reference readers"]
fn retained_native_all_aes_strengths_variants_and_deflate_levels_public_full_bytes() {
    let root = std::env::var_os("ZIPFAST_TASK6_NATIVE_FIXTURES").expect("set native fixture directory");
    let root = Path::new(&root);
    let cancel = Cancellation::default();
    for strength in [128, 192, 256] {
        for variant in [1, 2] {
            let directory = root.join(format!("aes{strength}-ae{variant}"));
            let mut session = ProjectedReadSession::open(&directory.join("fixture.zip"), &cancel).unwrap();
            let entries = session
                .entries()
                .enumerate()
                .filter(|(_, e)| !e.is_dir())
                .map(|(i, e)| (i, e.name.clone(), e.size))
                .collect::<Vec<_>>();
            for (ordinal, name, size) in entries {
                let expected = checked::file_digest(&directory.join("expected").join(&name));
                let mut context = EncryptedReadContext::for_projected(
                    &mut session,
                    ProjectedReadScope::Entry(ordinal),
                    None,
                    ZipReadOutput::Callback,
                    Some("password"),
                    &Default::default(),
                    &cancel,
                )
                .unwrap();
                let mut digest = checked::Digest::default();
                session
                    .read_at_with_context(ordinal, Some("password"), u64::MAX, &cancel, &mut context, |b| {
                        digest.update(b);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(digest.finish(), expected);
                assert_eq!(expected.0, size);
                println!("native aes{strength} ae{variant} name={name:?} bytes={size} hash={:02x?}", expected.1);
            }
        }
    }
}
