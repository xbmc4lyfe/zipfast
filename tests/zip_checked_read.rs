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

#[allow(dead_code)] // Shared ZIP fixture covers metadata cases used by other targets.
#[path = "common/zip_parity_fixture.rs"]
mod fixture;
use std::io::Write;
use zipfast::extract::Cancellation;
use zipfast::zip::{
    EncryptedReadContext, EncryptedReadOverrides, ProjectedReadScope, ProjectedReadSession, ZipReadOutput,
};

#[test]
fn public_checked_clear_read_and_consumed_plan() {
    let bytes = fixture::build(&[fixture::Member::stored(b"one", b"payload")], &[0], b"", b"", false).bytes;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        Some(64),
        ZipReadOutput::Callback,
        None,
        &EncryptedReadOverrides::default(),
        &cancel,
    )
    .unwrap();
    let mut out = Vec::new();
    session
        .read_at_with_context(0, None, 64, &cancel, &mut context, |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"payload");
    assert_eq!(context.usage().members, 0);
    assert_eq!(context.run_usage().records, 1);
    assert!(session.read_at_with_context(0, None, 64, &cancel, &mut context, |_| Ok(())).is_err());
    session.check_source(&mut context).unwrap();
}

#[path = "common/mod.rs"]
mod common;
#[test]
fn checked_generic_recognized_rar_is_terminal_while_legacy_falls_through() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::ReadFault;
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.part1.rar");
    let next = dir.path().join("multi.part2.rar");
    let mut prefix = b"launcher".to_vec();
    prefix.extend(common::SIG);
    prefix.extend(common::main_block(true, None));
    prefix.extend(common::end_block(true));
    let zip = fixture::build(&[fixture::Member::stored(b"zip", b"one")], &[0], &prefix, b"", false).bytes;
    std::fs::write(&first, &zip).unwrap();
    std::fs::write(&next, b"not a rar volume").unwrap();
    let old = SelectedEntry::open(&first, 0, None, 64).unwrap();
    assert!(old.is_zip());
    assert_eq!(old.name(), "zip");
    let error = SelectedEntry::open_cancelable_with_zip_limit(&first, 0, None, 64, None, Cancellation::default())
        .err()
        .unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use zipfast::extract::{self, Mode, Options, Overwrite};
        use zipfast::zip::ZipRunEvent;
        let options = Options {
            mode: Mode::Test,
            dest: dir.path().join("out"),
            overwrite: Overwrite::Skip,
            flatten: false,
            threads: Some(1),
            protected_paths: Default::default(),
            parallel_min: None,
        };
        let error = extract::run_with_zip_policy(
            &first,
            &options,
            None,
            &Cancellation::default(),
            &Default::default(),
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))));
        let mut context = EncryptedReadContext::new(Default::default()).unwrap();
        let error = extract::run_with_zip_context(
            &first,
            &options,
            None,
            &Cancellation::default(),
            &mut context,
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::Legacy(zipfast::Error::NotAnArchive))));
        for command in ["t", "l", "v"] {
            let result =
                std::process::Command::new(env!("CARGO_BIN_EXE_zipfast")).arg(command).arg(&first).output().unwrap();
            assert_eq!(result.status.code(), Some(2), "{command}: {result:?}");
            assert!(!String::from_utf8_lossy(&result.stdout).contains("zip"));
        }
        assert_eq!(std::fs::read(&first).unwrap(), zip);
    }
}
#[test]
fn checked_rar_selected_header_parity_and_old_nonzip_consuming_read() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::ReadFault;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("one.rar");
    std::fs::write(&path, common::archive(&[common::FileSpec::new("rar", b"bytes")])).unwrap();
    let mut selected =
        SelectedEntry::open_cancelable_with_zip_limit(&path, 0, None, 64, Some(u64::MAX), Cancellation::default())
            .unwrap();
    assert!(!selected.is_zip());
    assert_eq!(selected.name(), "rar");
    assert!(selected.zip_read_context(None, ZipReadOutput::Callback, &Default::default()).unwrap().is_none());
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    assert!(matches!(
        selected.read_with_zip_context(None, &mut context, |_| Ok(())).unwrap_err().operation(),
        Some(ReadFault::UnsupportedCheckedFormat)
    ));
    let mut out = Vec::new();
    selected
        .read(None, |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"bytes");
}
#[test]
fn original_zip64_selection_override_replaces_default_before_factory() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::{ReadFault, ReadResource, ReadSession};
    let mut member = fixture::Member::stored(b"entry", b"123456789012345");
    member.flags = 1;
    member.zip64 = true;
    let mut zip = fixture::build(&[member], &[0], b"", b"", false);
    let central = zip.central[0];
    let extra = central + 46 + b"entry".len();
    let huge = (8u64 << 30) + 1;
    // Deliberately synthetic declaration: this tests constructor admission,
    // not physical multi-GiB decode/throughput (qualified in Tasks6/7).
    zip.bytes[extra + 4..extra + 12].copy_from_slice(&huge.to_le_bytes());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&zip.bytes).unwrap();
    assert!(SelectedEntry::open(file.path(), 0, None, 8 << 30).is_err());
    let error = SelectedEntry::open_cancelable_with_zip_limit(file.path(), 0, None, 1, None, Cancellation::default())
        .err()
        .unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes, .. })));
    let mut selected = SelectedEntry::open_cancelable_with_zip_limit(
        file.path(),
        0,
        None,
        8 << 30,
        Some(huge),
        Cancellation::default(),
    )
    .unwrap();
    let c = selected.zip_read_context(Some("pw"), ZipReadOutput::Callback, &Default::default()).unwrap().unwrap();
    assert_eq!(c.options().limits().member_decoded_bytes, huge);
    let mut retained = ReadSession::open(file.path()).unwrap();
    let id = retained.metadata().entry_id(0).unwrap();
    assert!(retained.select(&id, 8 << 30, Cancellation::default()).is_err());
    assert!(retained.select(&id, huge, Cancellation::default()).is_ok());
    zip.bytes[central + 8..central + 10].copy_from_slice(&0u16.to_le_bytes());
    std::fs::write(file.path(), &zip.bytes).unwrap();
    assert!(
        SelectedEntry::open_cancelable_with_zip_limit(
            file.path(),
            0,
            None,
            8 << 30,
            Some(huge),
            Cancellation::default()
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn raw_bootstrap_child() {
    use std::path::Path;
    use zipfast::zip::ReadFault;
    let Ok(case) = std::env::var("ZIPFAST_TASK4_BOOTSTRAP_CHILD") else { return };
    if case == "overlong" {
        let component = "d".repeat(100);
        let levels = libc::PATH_MAX as usize / 101 + 2;
        for _ in 0..levels {
            std::fs::create_dir(&component).unwrap();
            std::env::set_current_dir(&component).unwrap();
        }
        let result = ProjectedReadSession::open(Path::new("missing"), &Cancellation::default());
        for _ in 0..levels {
            std::env::set_current_dir("..").unwrap();
            std::fs::remove_dir(&component).unwrap();
        }
        let e = result.err().unwrap();
        assert!(!e.is_source_changed());
        assert_eq!(e.bootstrap_usage().unwrap().opens(), 0);
        assert_eq!(e.bootstrap_usage().unwrap().metadata(), 0);
        #[cfg(target_os = "macos")]
        assert_eq!(e.bootstrap_usage().unwrap().cwd_retirement(), Some(zipfast::zip::CloseDisposition::Closed));
        return;
    }
    if case == "removed" {
        let cwd = std::env::current_dir().unwrap();
        std::fs::remove_dir(cwd).unwrap();
        let e = ProjectedReadSession::open(Path::new("missing"), &Cancellation::default()).err().unwrap();
        assert!(e.bootstrap_usage().unwrap().opens() <= 1);
        assert_eq!(e.bootstrap_usage().unwrap().acquired_fds(), 0);
        return;
    }
    let mut s = ProjectedReadSession::open(Path::new("archive.zip"), &Cancellation::default()).unwrap();
    assert_eq!(s.entries().next().unwrap().name, "entry");
    assert_eq!(s.bootstrap_usage().opens(), 1);
    #[cfg(target_os = "macos")]
    assert_eq!(s.bootstrap_usage().cwd_retirement(), Some(zipfast::zip::CloseDisposition::Closed));
    #[cfg(target_os = "linux")]
    assert_eq!(s.bootstrap_usage().cwd_retirement(), None);
    assert!(s.bootstrap_usage().path_operations() >= 1);
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    s.read_at_with_context(0, None, 64, &Cancellation::default(), &mut c, |_| Ok(())).unwrap();
    let cancel = Cancellation::default();
    cancel.cancel();
    let e = ProjectedReadSession::open(Path::new("archive.zip"), &cancel).err().unwrap();
    assert!(matches!(e.operation(), Some(ReadFault::Cancelled)));
    assert_eq!(e.bootstrap_usage().unwrap().attempts(), 0);
}
#[cfg(unix)]
#[test]
fn raw_native_relative_unicode_removed_cwd_nul_and_long_paths() {
    use std::os::unix::ffi::OsStringExt;
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes;
    for name in [std::ffi::OsString::from("unicode-雪"), std::ffi::OsString::from_vec(b"raw-\xff".to_vec())] {
        let cwd = dir.path().join(name);
        if let Err(error) = std::fs::create_dir(&cwd) {
            assert!(cfg!(target_os = "macos") && error.raw_os_error() == Some(libc::EILSEQ));
            continue;
        }
        std::fs::write(cwd.join("archive.zip"), &bytes).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("raw_bootstrap_child")
            .arg("--nocapture")
            .current_dir(&cwd)
            .env("ZIPFAST_TASK4_BOOTSTRAP_CHILD", "normal")
            .status()
            .unwrap();
        assert!(status.success());
    }
    let deep = dir.path().join("overlong-cwd");
    std::fs::create_dir(&deep).unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("raw_bootstrap_child")
            .current_dir(&deep)
            .env("ZIPFAST_TASK4_BOOTSTRAP_CHILD", "overlong")
            .status()
            .unwrap()
            .success()
    );
    let cwd = dir.path().join("removed");
    std::fs::create_dir(&cwd).unwrap();
    assert!(
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("raw_bootstrap_child")
            .current_dir(&cwd)
            .env("ZIPFAST_TASK4_BOOTSTRAP_CHILD", "removed")
            .status()
            .unwrap()
            .success()
    );
    for path in [std::path::PathBuf::from("x".repeat(5000)), std::ffi::OsString::from_vec(b"nul\0path".to_vec()).into()]
    {
        let e = ProjectedReadSession::open(&path, &Cancellation::default()).err().unwrap();
        assert_eq!(e.bootstrap_usage().unwrap().opens(), 0);
    }
}

#[test]
fn r1_public_selection_refusals_keep_completed_parser_usage() {
    use zipfast::extract::SelectedEntry;
    use zipfast::zip::{CloseDisposition, ReadFault, ReadResource};
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    let decoded = [0u8; 256];
    encoder.write_all(&decoded).unwrap();
    let compressed = encoder.finish().unwrap();
    for case in 0..4 {
        let member = match case {
            1 => fixture::Member::stored(b"directory/", b""),
            3 => fixture::Member::deflated(b"entry", &compressed, &decoded),
            _ => fixture::Member::stored(b"entry", b"payload"),
        };
        let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        let expected = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap().parser_usage();
        let error = SelectedEntry::open_cancelable_with_zip_limit(
            file.path(),
            if case == 0 { 9 } else { 0 },
            None,
            match case {
                2 => 2,
                3 => 10,
                _ => 1024,
            },
            None,
            Cancellation::default(),
        )
        .err()
        .unwrap();
        match case {
            0 | 1 => assert!(matches!(error.operation(), Some(ReadFault::CheckedFormat { .. }))),
            2 => assert!(matches!(
                error.operation(),
                Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes, .. })
            )),
            3 => assert!(matches!(
                error.operation(),
                Some(ReadFault::Limit { resource: ReadResource::MemberDecodedBytes, .. })
            )),
            _ => unreachable!(),
        }
        assert_eq!(error.parser_usage(), Some(expected));
        assert!(expected.fetched_bytes > 0);
        let boot = error.bootstrap_usage().unwrap();
        assert_eq!(boot.metadata(), 6);
        assert_eq!(boot.source_retirement(), Some(CloseDisposition::Closed));
        assert_eq!(boot.acquired_fds(), 1);
        assert_eq!(error.cleanup_errors().len(), 0);
    }
}
#[test]
fn r1_public_unbound_missing_source_keeps_action_plan_origin() {
    use zipfast::zip::{BootstrapPhase, CheckedSourceFault, ReadIoOperation};
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&fixture::build(&[fixture::Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    std::fs::remove_file(file.path()).unwrap();
    let mut calls = 0;
    let error = session
        .read_at_with_context(0, None, 64, &cancel, &mut context, |_| {
            calls += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(calls, 0);
    assert!(matches!(error.source_change(), Some(CheckedSourceFault::Unavailable { .. })));
    let boot = error.bootstrap_usage().expect("originating explicit binding snapshot");
    assert_eq!(boot, context.bootstrap_usage());
    assert_eq!(boot.phase(), BootstrapPhase::ActionPlan);
    assert_eq!((boot.metadata(), boot.attempts(), boot.bytes(), boot.acquisition_attempts()), (2, 2, 0, 1));
    assert_eq!(context.run_usage().records, 0);
    assert_eq!(context.run_usage().io_attempts, 0);
    assert!(error.parser_usage().is_none());
    assert!(error.cleanup_errors().all(|e| e.operation != ReadIoOperation::Close));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn r2_rar_precedence_survives_sfx_corrupt_initializer_and_zip_tail() {
    use zipfast::extract::{self, Mode, Options, Overwrite};
    use zipfast::zip::{ReadFault, ZipRunEvent};
    let dir = tempfile::tempdir().unwrap();
    let rar = common::archive(&[common::FileSpec::new("rar-entry", b"payload")]);
    for prefix in [b"".as_slice(), b"launcher".as_slice()] {
        for corrupt in [false, true] {
            let mut first = prefix.to_vec();
            first.extend_from_slice(&rar);
            if corrupt {
                first[prefix.len() + common::SIG.len()] ^= 1;
            }
            let combined =
                fixture::build(&[fixture::Member::stored(b"zip-tail", b"one")], &[0], &first, b"", false).bytes;
            let path = dir.path().join(format!("case-{}-{corrupt}.bin", prefix.len()));
            std::fs::write(&path, &combined).unwrap();
            let options = Options {
                mode: Mode::Test,
                dest: dir.path().join("unused"),
                overwrite: Overwrite::Skip,
                flatten: false,
                threads: Some(1),
                protected_paths: Default::default(),
                parallel_min: None,
            };
            let result = extract::run_with_zip_policy(
                &path,
                &options,
                None,
                &Cancellation::default(),
                &Default::default(),
                |_: ZipRunEvent<'_>| Ok(()),
            );
            let mut context = EncryptedReadContext::new(Default::default()).unwrap();
            let contextual = extract::run_with_zip_context(
                &path,
                &options,
                None,
                &Cancellation::default(),
                &mut context,
                |_: ZipRunEvent<'_>| Ok(()),
            );
            for result in [result, contextual] {
                if corrupt {
                    assert!(matches!(
                        result.unwrap_err().operation(),
                        Some(ReadFault::Legacy(zipfast::Error::Corrupt(_)))
                    ));
                } else {
                    let report = result.unwrap();
                    assert_eq!((report.files(), report.decoded_bytes(), report.failed()), (1, 7, 0));
                }
            }
            for command in ["t", "l", "v"] {
                let result =
                    std::process::Command::new(env!("CARGO_BIN_EXE_zipfast")).arg(command).arg(&path).output().unwrap();
                assert_eq!(result.status.code(), Some(if corrupt { 2 } else { 0 }), "{command}: {result:?}");
                assert!(!String::from_utf8_lossy(&result.stdout).contains("zip-tail"));
                if !corrupt && command != "t" {
                    assert!(String::from_utf8_lossy(&result.stdout).contains("rar-entry"));
                }
            }
            assert_eq!(std::fs::read(&path).unwrap(), combined);
        }
    }
}
