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

//! Native split publication preserves complete physical sets and existing names.
#![cfg(any(target_os = "linux", target_os = "macos"))]
use zipfast::zip::create::{CreateOptions, CreatePlan, SplitCommitState, SplitCreateOptions, SplitVisibility};
use zipfast::zip::write::{EntryName, EntryOptions, Method};

#[test]
fn split_create_publishes_verified_numbered_then_final_set() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::write(&input, vec![0x5a; 2000]).unwrap();
    let destination = dir.path().join("archive.zip");
    let mut plan = CreatePlan::new(&destination, CreateOptions::default()).unwrap();
    plan.add_file(
        &input,
        EntryOptions {
            name: EntryName::Utf8("payload"),
            method: Method::Stored,
            modified: zipfast::zip::write::DosDateTime::default(),
            extended_mtime: None,
            permissions: zipfast::zip::write::Permissions::new(0o644).unwrap(),
            comment: b"",
        },
        None,
    )
    .unwrap();
    let mut options = SplitCreateOptions::default();
    options.volume_bytes = 512;
    let report = plan.publish_split_with_receipts(options);
    assert!(report.outcome.is_ok(), "{report:?}");
    assert_eq!(report.commit, SplitCommitState::Complete);
    assert_eq!(report.visibility, SplitVisibility::AllMatch);
    assert_eq!(report.written.len(), 1);
    assert_eq!(report.written[0].decoded_size, 2000);
    assert!(report.reconciliation.is_none());
    assert!(dir.path().join("archive.z01").is_file());
    assert!(destination.is_file());
    assert!(report.volumes.len() >= 4);
    assert_eq!(report.summary.verification.decoded_bytes, 2000);
    assert_eq!(std::fs::read(&input).unwrap(), vec![0x5a; 2000]);
}

#[test]
fn split_create_conflict_preserves_existing_numbered_file_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::write(&input, vec![0x33; 2000]).unwrap();
    let destination = dir.path().join("archive.zip");
    std::fs::write(dir.path().join("archive.z01"), b"existing").unwrap();
    let mut plan = CreatePlan::new(&destination, CreateOptions::default()).unwrap();
    plan.add_file(
        &input,
        EntryOptions {
            name: EntryName::Utf8("payload"),
            method: Method::Stored,
            modified: zipfast::zip::write::DosDateTime::default(),
            extended_mtime: None,
            permissions: zipfast::zip::write::Permissions::new(0o644).unwrap(),
            comment: b"",
        },
        None,
    )
    .unwrap();
    let mut options = SplitCreateOptions::default();
    options.volume_bytes = 512;
    let report = plan.publish_split_with_receipts(options);
    assert!(report.outcome.is_err());
    assert_eq!(report.commit, SplitCommitState::NonePublished);
    assert!(report.written.is_empty());
    assert!(!destination.exists());
    assert_eq!(std::fs::read(dir.path().join("archive.z01")).unwrap(), b"existing");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
}

fn entry(name: &str) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method: Method::Stored,
        modified: zipfast::zip::write::DosDateTime::default(),
        extended_mtime: None,
        permissions: zipfast::zip::write::Permissions::new(0o644).unwrap(),
        comment: b"",
    }
}

#[test]
fn split_create_actual_long_raw_and_empty_stem_names() {
    use std::os::unix::ffi::OsStringExt;
    for (name, size) in [
        (vec![b'x'; 251].into_iter().chain(b".ZIP".iter().copied()).collect::<Vec<_>>(), 0),
        (vec![b'x'; 251].into_iter().chain(b".zip".iter().copied()).collect(), 600),
        (b".zip".to_vec(), 600),
        (b"raw-\xff.zip".to_vec(), 600),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        std::fs::write(&input, vec![0x55; size]).unwrap();
        let target = dir.path().join(std::ffi::OsString::from_vec(name));
        let raw_supported = match std::fs::write(&target, b"probe") {
            Ok(()) => {
                std::fs::remove_file(&target).unwrap();
                true
            }
            Err(e) => {
                assert_eq!(e.raw_os_error(), Some(libc::EILSEQ));
                false
            }
        };
        let mut p = CreatePlan::new(&target, CreateOptions::default()).unwrap();
        p.add_file(&input, entry("data"), None).unwrap();
        let mut options = SplitCreateOptions::default();
        options.volume_bytes = 512;
        let r = p.publish_split_with_receipts(options);
        if !raw_supported {
            assert!(r.outcome.is_err());
            assert!(r.written.is_empty());
            continue;
        }
        assert!(r.outcome.is_ok(), "{r:?}");
        assert!(target.is_file());
        assert_eq!(r.volumes.len(), if size == 0 { 1 } else { 2 });
    }
}

#[test]
fn split_create_live_fd_budget_child() {
    let Ok(mode) = std::env::var("ZIPFAST_SPLIT_FD_CHILD") else {
        for mode in ["success", "logical", "os"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "split_create_live_fd_budget_child", "--nocapture"])
                .env("ZIPFAST_SPLIT_FD_CHILD", mode)
                .status()
                .unwrap();
            assert!(status.success(), "{mode}");
        }
        return;
    };
    let fd_count =
        || std::fs::read_dir(if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" }).unwrap().count();
    let baseline = fd_count();
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let mut f = std::fs::File::create(&input).unwrap();
    std::io::Write::write_all(&mut f, &vec![0x51; 6_815_775]).unwrap();
    drop(f);
    let held = dir.path().join("held");
    std::fs::write(&held, b"").unwrap();
    let mut p = CreatePlan::new(&dir.path().join("out.zip"), CreateOptions::default()).unwrap();
    p.add_open_file(&held, std::fs::File::open(&held).unwrap(), entry("held"), None).unwrap();
    p.add_open_directory(dir.path(), std::fs::File::open(dir.path()).unwrap(), entry("folder/"), None).unwrap();
    p.add_file(&input, entry("payload"), None).unwrap();
    let mut options = SplitCreateOptions::default();
    options.volume_bytes = 65536;
    options.limits.volumes = 128;
    options.limits.open_handles = if mode == "logical" { 109 } else { 120 };
    let limit = libc::rlimit { rlim_cur: if mode == "os" { 64 } else { 128 }, rlim_max: 128 };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let r = p.publish_split_with_receipts(options);
    if mode == "success" {
        assert!(r.outcome.is_ok(), "{r:?}");
        assert_eq!(r.volumes.len(), 105);
        assert_eq!(r.summary.open_handles_peak, 110);
        assert!(dir.path().join("out.z100").is_file());
    } else {
        assert!(r.outcome.is_err());
        assert!(!dir.path().join("out.zip").exists());
        assert!(r.reconciliation.is_none(), "{r:?}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    drop(r);
    assert_eq!(fd_count(), baseline);
}

#[test]
fn split_create_reference_fixture() {
    use zipfast::zip::write::DeflateLevel;
    let temporary = tempfile::tempdir().unwrap();
    let root = std::env::var_os("ZIPFAST_SPLIT_REFERENCE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    std::fs::create_dir_all(&root).unwrap();
    let payload: Vec<u8> = (0..6_815_775).map(|i| ((i * 29 + i / 11) % 251) as u8).collect();
    let input = root.join("payload");
    std::fs::write(&input, &payload).unwrap();
    let mut plan = CreatePlan::new(&root.join("stored.zip"), CreateOptions::default()).unwrap();
    plan.add_file(&input, entry("payload"), None).unwrap();
    let mut options = SplitCreateOptions::default();
    options.volume_bytes = 65536;
    let report = plan.publish_split_with_receipts(options);
    assert!(report.outcome.is_ok(), "{report:?}");
    assert_eq!(report.volumes.len(), 105);
    assert_eq!(report.summary.verification.decoded_bytes, 6_815_775);
    let creation = CreateOptions {
        archive_comment: b"independent split proof".to_vec(),
        output_permissions: 0o640,
        ..CreateOptions::default()
    };
    let mut plan = CreatePlan::new(&root.join("deflate.zip"), creation).unwrap();
    plan.add_directory(entry("folder/"), None).unwrap();
    let mut metadata = entry("folder/payload");
    metadata.method = Method::Deflate(DeflateLevel::new(6).unwrap());
    metadata.comment = b"member proof";
    metadata.extended_mtime = Some(1234);
    plan.add_file(&input, metadata, None).unwrap();
    let mut options = SplitCreateOptions::default();
    options.volume_bytes = 65536;
    let report = plan.publish_split_with_receipts(options);
    assert!(report.outcome.is_ok(), "{report:?}");
    assert_eq!(report.summary.verification.decoded_bytes, 6_815_775);
    assert_eq!(report.written.len(), 2);
    assert_eq!(std::fs::read(input).unwrap(), payload);
}

#[test]
fn split_create_preserves_source_aliases_and_qualified_case_aliases() {
    for case_alias in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        std::fs::write(&input, [b'Q'; 600]).unwrap();
        let reserved = dir.path().join(if case_alias { "OUT.Z01" } else { "out.z01" });
        std::fs::hard_link(&input, &reserved).unwrap();
        let aliases = dir.path().join("out.z01").exists();
        let mut p = CreatePlan::new(&dir.path().join("out.zip"), CreateOptions::default()).unwrap();
        p.add_file(&input, entry("data"), None).unwrap();
        let mut options = SplitCreateOptions::default();
        options.volume_bytes = 512;
        let r = p.publish_split_with_receipts(options);
        assert_eq!(r.outcome.is_err(), aliases, "{r:?}");
        assert_eq!(std::fs::read(&input).unwrap(), [b'Q'; 600]);
        assert_eq!(std::fs::read(reserved).unwrap(), [b'Q'; 600]);
        if aliases {
            assert_eq!(r.commit, SplitCommitState::NonePublished);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        }
    }
}
