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

use super::*;
use crate::zip::write::{DosDateTime, EntryName, Method, Permissions};

pub(super) fn metadata(name: &str) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method: Method::Stored,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"",
    }
}

#[test]
fn names_and_caller_keys_are_checked_as_paths() {
    for bad in ["", "/", "../x", "x/./y", "x//y", "C:foo", "c:/foo", "a\\b", "x\u{80}"] {
        assert!(validate_name(metadata(bad), false).is_err(), "{bad:?}");
    }
    for good in ["report:2026.txt", "dir/report:2026.txt", "é/雪.txt"] {
        assert!(validate_name(metadata(good), false).is_ok(), "{good:?}");
    }
    assert!(validate_name(metadata("a/"), true).is_ok());
    assert!(validate_name(metadata("a//"), true).is_err());
    assert!(validate_name(metadata("a/"), false).is_err());
    assert!(CollisionPath::new(&[b"x/y"]).is_err());
    assert!(CollisionPath::new(&[b""]).is_err());
}

#[test]
fn admission_preserves_previous_entries_and_bounds_held_sources() {
    let temp = test_dir();
    let path = temp.path().join("source");
    std::fs::write(&path, b"input").unwrap();
    let mut options = CreateOptions::default();
    options.limits.retained_handles = 1;
    let mut plan = CreatePlan::new(&temp.path().join("out.zip"), options).unwrap();
    assert_eq!(plan.add_file(&path, metadata("one"), None).unwrap(), CreateEntryId(0));
    assert!(matches!(plan.add_file(&path, metadata("../unsafe"), None), Err(CreateError::InvalidName(_))));
    assert_eq!(plan.add_open_file(&path, File::open(&path).unwrap(), metadata("two"), None).unwrap(), CreateEntryId(1));
    assert!(matches!(
        plan.add_open_file(&path, File::open(&path).unwrap(), metadata("three"), None),
        Err(CreateError::Limit(CreateLimit::RetainedHandles))
    ));
    assert_eq!(plan.usage().plan.entries, 2);
    assert_eq!(plan.usage().plan.retained_handles, 1);
    assert_eq!(std::fs::read(&path).unwrap(), b"input");
    assert!(!temp.path().join("out.zip").exists());
}

#[test]
fn hierarchy_rejects_exact_and_normalized_conflicts() {
    for (first, second, policy, expected) in [
        ("a", "a/b", CollisionPolicy::Exact, true),
        ("a/", "a/b", CollisionPolicy::Exact, false),
        ("a", "a/", CollisionPolicy::Exact, true),
        ("a", "a", CollisionPolicy::Exact, true),
        ("a/x/", "A/y/", CollisionPolicy::CallerKeys, true),
        ("a/x/", "a/y/", CollisionPolicy::CallerKeys, false),
    ] {
        let temp = test_dir();
        let path = temp.path().join("source");
        std::fs::write(&path, b"x").unwrap();
        let mut plan = CreatePlan::new(
            &temp.path().join("out.zip"),
            CreateOptions { collisions: policy, ..CreateOptions::default() },
        )
        .unwrap();
        for name in [first, second] {
            let keys = name.trim_end_matches('/').split('/').map(|part| part.to_ascii_lowercase()).collect::<Vec<_>>();
            let parts = keys.iter().map(|part| part.as_bytes()).collect::<Vec<_>>();
            let keys = CollisionPath::new(&parts).unwrap();
            let keys = (policy == CollisionPolicy::CallerKeys).then_some(&keys);
            if name.ends_with('/') {
                plan.add_directory(metadata(name), keys).unwrap();
            } else {
                plan.add_file(&path, metadata(name), keys).unwrap();
            }
        }
        assert_eq!(plan.preflight().is_err(), expected, "{first} {second}");
        assert!(!temp.path().join("out.zip").exists());
    }
}

pub(super) fn test_dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn publishes_new_zip_and_preserves_existing_targets() {
    let dir = test_dir();
    let input = dir.path().join("source");
    let output = dir.path().join("archive.zip");
    std::fs::write(&input, b"source data").unwrap();
    let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    plan.add_file(&input, metadata("payload"), None).unwrap();
    plan.add_file(&input, metadata("alias"), None).unwrap();
    assert!(!output.exists());
    let created = plan.publish().unwrap();
    assert_eq!(created.publication, Publication::Published);
    assert_eq!(created.durability, DurabilityState::NotRequested);
    assert!(matches!(created.cleanup, CleanupState::Clean));
    assert_eq!(created.summary.verification.payloads, 2);
    let original = std::fs::read(&output).unwrap();
    assert!(matches!(CreatePlan::new(&output, CreateOptions::default()), Err(CreateError::Conflict)));
    assert_eq!(std::fs::read(&output).unwrap(), original);
    assert_eq!(std::fs::read(&input).unwrap(), b"source data");
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn changed_source_cannot_publish() {
    let dir = test_dir();
    let source = dir.path().join("source");
    let output = dir.path().join("archive.zip");
    std::fs::write(&source, b"before").unwrap();
    let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    plan.add_file(&source, metadata("file"), None).unwrap();
    std::fs::write(&source, b"changed").unwrap();
    let error = plan.publish().unwrap_err();
    assert_eq!(error.publication, Publication::NotPublished);
    assert_eq!(error.stage, CreateStage::SourceRead);
    assert!(matches!(error.cause, CreateError::SourceChanged(CreateEntryId(0))));
    assert!(matches!(error.cleanup, CleanupState::Clean));
    assert_eq!(std::fs::read(&source).unwrap(), b"changed");
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn competing_end_in_binary_comment_cannot_publish() {
    let dir = test_dir();
    let source = dir.path().join("source");
    let output = dir.path().join("archive.zip");
    std::fs::write(&source, b"payload").unwrap();
    let mut fake_end = b"PK\x05\x06".to_vec();
    fake_end.resize(22, 0);
    let mut plan =
        CreatePlan::new(&output, CreateOptions { archive_comment: fake_end, ..CreateOptions::default() }).unwrap();
    plan.add_file(&source, metadata("file"), None).unwrap();
    let error = plan.publish().unwrap_err();
    assert_eq!(error.publication, Publication::NotPublished);
    assert_eq!(error.stage, CreateStage::Verify);
    assert!(matches!(error.cause, CreateError::AmbiguousDirectory { .. }));
    assert_eq!(std::fs::read(&source).unwrap(), b"payload");
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());
}

fn stages(directory: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(std::fs::canonicalize(directory).unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(".zipfast-"))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    AfterAdmissionClose,
    MetadataReserve,
    SourceOpen,
    AfterSourceReopen,
    BeforeSourceRead,
    ReadSource,
    AfterSourceRead,
    AfterSourceClose,
    BeforeFinalSourceCheck,
    StageOpen,
    SinkWrite { at: u64, signature: Option<[u8; 4]> },
    SinkSeek,
    SinkFlush,
    AfterFinish,
    BeforeVerify,
    VerifyRead,
    VerifySeek,
    AfterVerify,
    Chmod,
    FileSync,
    BeforeCommit,
    NativePublish,
    AfterCommit,
    BeforeCleanup,
    Unlink,
    DirectorySync,
}

type Hook = dyn FnMut(Event, Option<&Path>) -> io::Result<()>;
thread_local! {
    static HOOK: std::cell::RefCell<Option<Box<Hook>>> = const { std::cell::RefCell::new(None) };
    static SINK_WRITE_CAP: Cell<usize> = const { Cell::new(usize::MAX) };
    static SOURCE_READ_CAP: Cell<usize> = const { Cell::new(usize::MAX) };
}

fn with_hook<T>(hook: impl FnMut(Event, Option<&Path>) -> io::Result<()> + 'static, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with_borrow_mut(|cell| *cell = None);
            SINK_WRITE_CAP.set(usize::MAX);
            SOURCE_READ_CAP.set(usize::MAX);
        }
    }
    HOOK.with_borrow_mut(|cell| {
        assert!(cell.is_none());
        *cell = Some(Box::new(hook));
    });
    let _reset = Reset;
    run()
}

pub(super) fn sink_write_cap() -> usize {
    SINK_WRITE_CAP.get()
}

pub(super) fn source_read_cap() -> usize {
    SOURCE_READ_CAP.get()
}

pub(super) fn event_io(event: Event, path: Option<&Path>) -> io::Result<()> {
    HOOK.with_borrow_mut(|cell| cell.as_mut().map_or(Ok(()), |hook| hook(event, path)))
}

pub(super) fn event(event: Event, path: Option<&Path>) -> Result<()> {
    event_io(event, path).map_err(CreateError::from)
}

fn simple_plan(options: CreateOptions) -> (tempfile::TempDir, PathBuf, PathBuf, CreatePlan) {
    let dir = test_dir();
    let input = dir.path().join("source");
    let output = dir.path().join("archive.zip");
    std::fs::write(&input, b"source data").unwrap();
    let mut plan = CreatePlan::new(&output, options).unwrap();
    plan.add_file(&input, metadata("file"), None).unwrap();
    (dir, input, output, plan)
}

#[test]
fn creation_receipts_require_confirmed_publication() {
    for (fault, stage, publication) in [
        (Event::BeforeCommit, CreateStage::Precommit, Publication::NotPublished),
        (Event::NativePublish, CreateStage::Publish, Publication::Unknown),
        (Event::AfterCommit, CreateStage::Cleanup, Publication::Published),
        (Event::DirectorySync, CreateStage::DirectorySync, Publication::Published),
    ] {
        let (_dir, _source, output, plan) =
            simple_plan(CreateOptions { durability: Durability::SyncFileAndDirectory, ..CreateOptions::default() });
        let report = with_hook(
            move |event, path| {
                if event == fault {
                    if event == Event::AfterCommit {
                        std::fs::write(path.unwrap(), b"foreign after commit")?;
                    } else {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || plan.publish_with_receipts(),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!((failure.stage, failure.publication), (stage, publication));
        if publication == Publication::Published {
            assert_eq!(
                report.written,
                [EntryWritten {
                    ordinal: 0,
                    method: Method::Stored,
                    crc32: crate::crc32::hash(b"source data"),
                    decoded_size: 11,
                    packed_size: 11,
                    local_offset: 0,
                }]
            );
            let mut bytes = Vec::new();
            crate::zip::Archive::open(&output)
                .unwrap()
                .read_at(0, None, 64, |chunk| {
                    bytes.extend_from_slice(chunk);
                    Ok(())
                })
                .unwrap();
            assert_eq!(bytes, b"source data");
        } else {
            assert!(report.written.is_empty());
            assert!(!output.exists());
        }
    }
}

#[test]
fn each_precommit_failure_is_definite_and_cleans_the_stage() {
    let sync = || CreateOptions { durability: Durability::SyncFileAndDirectory, ..CreateOptions::default() };
    for (fault, expected) in [
        (Event::SinkWrite { at: 0, signature: Some(*b"PK\x03\x04") }, CreateStage::Write),
        (
            Event::SinkWrite { at: 14, signature: Some(crate::crc32::hash(b"source data").to_le_bytes()) },
            CreateStage::Write,
        ),
        (Event::SinkWrite { at: 45, signature: Some(*b"PK\x01\x02") }, CreateStage::Finish),
        (Event::SinkWrite { at: 95, signature: Some(*b"PK\x05\x06") }, CreateStage::Finish),
        (Event::SinkSeek, CreateStage::Write),
        (Event::SinkFlush, CreateStage::Finish),
        (Event::BeforeVerify, CreateStage::Verify),
        (Event::Chmod, CreateStage::Permissions),
        (Event::FileSync, CreateStage::FileSync),
        (Event::NativePublish, CreateStage::Publish),
    ] {
        let (dir, source, output, plan) = simple_plan(sync());
        let error = with_hook(
            move |event, _| if event == fault { Err(io::Error::from_raw_os_error(libc::EPERM)) } else { Ok(()) },
            || plan.publish().unwrap_err(),
        );
        assert_eq!(error.stage, expected, "{fault:?} {error:?}");
        assert_eq!(error.publication, Publication::NotPublished);
        assert_eq!(error.durability, DurabilityState::Unconfirmed);
        assert!(matches!(error.cleanup, CleanupState::Clean));
        assert!(error.summary.finalization_attempts >= 1);
        assert!(error.summary.writer.io_attempts >= 1);
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn archive_corruption_before_verification_cannot_publish() {
    use std::os::unix::fs::FileExt;
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let error = with_hook(
        |event, path| {
            if event == Event::BeforeVerify {
                let file = File::options().write(true).open(path.unwrap())?;
                file.write_all_at(b"x", 34)?;
            }
            Ok(())
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.stage, CreateStage::Verify);
    assert!(matches!(error.cause, CreateError::Verification("decoded length or CRC differs")));
    assert_eq!(error.publication, Publication::NotPublished);
    assert!(matches!(error.cleanup, CleanupState::Clean));
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn two_creators_use_one_native_commit_each() {
    use std::sync::{Arc, Barrier};
    let (dir, input, output, first) = simple_plan(CreateOptions::default());
    let mut second = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    second.add_file(&input, metadata("second"), None).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let run = |plan: CreatePlan, barrier: Arc<Barrier>| {
        with_hook(
            move |event, _| {
                if event == Event::BeforeCommit {
                    barrier.wait();
                }
                Ok(())
            },
            || plan.publish().map_err(Box::new),
        )
    };
    let thread_barrier = Arc::clone(&barrier);
    let thread = std::thread::spawn(move || run(first, thread_barrier));
    let second = run(second, barrier);
    let first = thread.join().unwrap();
    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        other => panic!("expected one winner and one loser: {other:?}"),
    };
    assert_eq!(winner.publication, Publication::Published);
    assert_eq!(winner.summary.verification.payloads, 1);
    assert_eq!(loser.publication, Publication::NotPublished);
    assert_eq!(loser.stage, CreateStage::Publish);
    assert!(matches!(loser.cause, CreateError::Conflict));
    assert!(matches!(loser.cleanup, CleanupState::Clean));
    let mut archive = crate::zip::Archive::open(&output).unwrap();
    let mut data = Vec::new();
    archive
        .read_at(0, None, 64, |bytes| {
            data.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(data, b"source data");
    assert_eq!(std::fs::read(&input).unwrap(), b"source data");
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn source_changes_after_reopen_read_or_close_are_rejected() {
    for (event, expected) in [
        (Event::AfterSourceReopen, CreateStage::SourceRead),
        (Event::AfterSourceRead, CreateStage::SourceRead),
        (Event::AfterSourceClose, CreateStage::Precommit),
        (Event::BeforeFinalSourceCheck, CreateStage::Precommit),
    ] {
        let (dir, source, output, plan) = simple_plan(CreateOptions::default());
        let original = source.clone();
        let error = with_hook(
            move |current, _| {
                if current == event {
                    std::fs::write(&original, b"mutated source")?;
                }
                Ok(())
            },
            || plan.publish().unwrap_err(),
        );
        assert_eq!(error.stage, expected);
        assert_eq!(error.publication, Publication::NotPublished);
        assert!(matches!(error.cause, CreateError::SourceChanged(CreateEntryId(0))));
        assert!(matches!(error.cleanup, CleanupState::Clean));
        assert_eq!(std::fs::read(&source).unwrap(), b"mutated source");
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn source_reopen_rejects_removal_replacement_symlinks_and_fifos() {
    use std::os::unix::ffi::OsStrExt;
    for action in 0..5 {
        let (dir, source, output, plan) = simple_plan(CreateOptions::default());
        let original = dir.path().join("original");
        std::fs::rename(&source, &original).unwrap();
        match action {
            0 => {}
            1 => std::fs::write(&source, b"source data").unwrap(),
            2 => std::os::unix::fs::symlink(&original, &source).unwrap(),
            3 => {
                let name = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
                // This test owns the directory and the NUL-terminated path.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            4 => std::fs::hard_link(&original, &source).unwrap(),
            _ => unreachable!(),
        }
        let error = plan.publish().unwrap_err();
        assert_eq!(error.stage, CreateStage::SourceRead);
        assert_eq!(error.publication, Publication::NotPublished);
        assert!(matches!(error.cleanup, CleanupState::Clean));
        assert_eq!(std::fs::read(&original).unwrap(), b"source data");
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn source_reopen_reports_permission_and_descriptor_errors() {
    for errno in [libc::EACCES, libc::EMFILE] {
        let (dir, source, output, plan) = simple_plan(CreateOptions::default());
        let error = with_hook(
            move |event, _| if event == Event::SourceOpen { Err(io::Error::from_raw_os_error(errno)) } else { Ok(()) },
            || plan.publish().unwrap_err(),
        );
        assert_eq!(error.stage, CreateStage::SourceRead);
        assert_eq!(error.publication, Publication::NotPublished);
        assert_eq!(matches!(error.cause, CreateError::DescriptorExhaustion(_)), errno == libc::EMFILE);
        assert!(matches!(error.cleanup, CleanupState::Clean));
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn replacement_stage_survives_verification_and_cleanup() {
    for before_verify in [true, false] {
        let (dir, source, output, plan) = simple_plan(CreateOptions::default());
        let moved = dir.path().join("moved");
        let held = moved.clone();
        let error = with_hook(
            move |event, path| {
                if event == if before_verify { Event::BeforeVerify } else { Event::BeforeCleanup } {
                    let stage = path.unwrap();
                    std::fs::rename(stage, &held)?;
                    std::fs::write(stage, b"foreign")?;
                }
                if !before_verify && event == Event::BeforeVerify {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                Ok(())
            },
            || plan.publish().unwrap_err(),
        );
        assert_eq!(error.stage, if before_verify { CreateStage::Precommit } else { CreateStage::Verify });
        assert_eq!(error.publication, Publication::NotPublished);
        assert_eq!(error.summary.verification.payloads, u64::from(before_verify));
        let CleanupState::ForeignStageName { path } = error.cleanup else { panic!("{error:?}") };
        assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
        assert_eq!(stages(dir.path()), [path]);
        assert!(crate::zip::Archive::open(&moved).is_ok());
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
        assert!(!output.exists());
    }
}

#[test]
fn stage_cannot_be_consumed_through_a_rebound_source_alias() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let original = dir.path().join("original");
    let source_path = source.clone();
    let original_path = original.clone();
    let mut alias = None;
    let error = with_hook(
        move |event, path| {
            if event == Event::StageOpen {
                // StageOpen precedes the exclusive open, so record the
                // generated path and bind the alias just before source reopen.
                alias = Some(path.unwrap().to_path_buf());
            }
            if event == Event::SourceOpen {
                let stage = alias.take().unwrap();
                std::fs::rename(&source_path, &original_path)?;
                std::fs::hard_link(stage, &source_path)?;
            }
            Ok(())
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.publication, Publication::NotPublished);
    assert!(matches!(error.cause, CreateError::SourceAliasesStage(CreateEntryId(0))));
    assert_eq!(std::fs::read(&original).unwrap(), b"source data");
    assert_eq!(std::fs::read(&source).unwrap(), b"");
    assert!(stages(dir.path()).is_empty());
    assert!(!output.exists());
}

#[test]
fn postcommit_cancellation_reused_name_and_directory_sync_keep_the_archive() {
    for mode in 0..3 {
        let cancel = Cancellation::default();
        let (dir, source, output, plan) = simple_plan(CreateOptions {
            cancel: cancel.clone(),
            durability: Durability::SyncFileAndDirectory,
            ..CreateOptions::default()
        });
        let created = with_hook(
            move |event, path| {
                if event == Event::AfterCommit {
                    cancel.cancel();
                    if mode == 1 {
                        std::fs::write(path.unwrap(), b"foreign after commit")?;
                    }
                }
                if mode == 2 && event == Event::DirectorySync {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                Ok(())
            },
            || plan.publish().map_err(Box::new),
        );
        match mode {
            0 => {
                let success = created.unwrap();
                assert_eq!(success.publication, Publication::Published);
                assert_eq!(success.durability, DurabilityState::Synced);
                assert!(stages(dir.path()).is_empty());
            }
            1 => {
                let error = created.unwrap_err();
                assert_eq!(error.publication, Publication::Published);
                assert_eq!(error.durability, DurabilityState::Synced);
                assert_eq!(error.stage, CreateStage::Cleanup);
                let CleanupState::ForeignStageName { path } = error.cleanup else { panic!("{error:?}") };
                assert_eq!(std::fs::read(&path).unwrap(), b"foreign after commit");
                assert_eq!(stages(dir.path()), [path]);
            }
            2 => {
                let error = created.unwrap_err();
                assert_eq!(error.publication, Publication::Published);
                assert_eq!(error.durability, DurabilityState::Unconfirmed);
                assert_eq!(error.stage, CreateStage::DirectorySync);
                assert!(matches!(error.cleanup, CleanupState::Clean));
                assert!(stages(dir.path()).is_empty());
            }
            _ => unreachable!(),
        }
        let mut data = Vec::new();
        crate::zip::Archive::open(&output)
            .unwrap()
            .read_at(0, None, 64, |bytes| {
                data.extend_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        assert_eq!(data, b"source data");
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    }
}

#[test]
fn ambiguous_publication_never_retries_or_removes_possible_output() {
    use std::cell::Cell;
    use std::rc::Rc;
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let destination = output.clone();
    let calls = Rc::new(Cell::new(0));
    let counted = Rc::clone(&calls);
    let mut held = None;
    let error = with_hook(
        move |event, path| {
            if event == Event::BeforeCommit {
                held = Some(path.unwrap().to_path_buf());
            }
            if event == Event::NativePublish {
                counted.set(counted.get() + 1);
                std::fs::rename(held.take().unwrap(), &destination)?;
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(error.publication, Publication::Unknown);
    assert_eq!(error.stage, CreateStage::Publish);
    let mut data = Vec::new();
    crate::zip::Archive::open(&output)
        .unwrap()
        .read_at(0, None, 64, |bytes| {
            data.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(data, b"source data");
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn stage_collisions_interruptions_and_cleanup_use_bounded_attempts() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let error = with_hook(
        |event, _| if event == Event::StageOpen { Err(io::Error::from(io::ErrorKind::AlreadyExists)) } else { Ok(()) },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.stage, CreateStage::StageCreate);
    assert_eq!(error.publication, Publication::NotPublished);
    assert!(matches!(error.cause, CreateError::Limit(CreateLimit::StageAttempts)));
    assert_eq!(error.summary.stage_attempts, 64);
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());

    let mut options = CreateOptions::default();
    options.limits.transaction_attempts = 40;
    let (dir, source, output, plan) = simple_plan(options);
    let error = with_hook(
        |event, _| if event == Event::ReadSource { Err(io::Error::from(io::ErrorKind::Interrupted)) } else { Ok(()) },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.stage, CreateStage::SourceRead);
    assert_eq!(error.publication, Publication::NotPublished);
    assert!(matches!(error.cause, CreateError::Limit(CreateLimit::TransactionAttempts)));
    assert_eq!(error.summary.transaction_attempts, 40);
    assert!(matches!(error.cleanup, CleanupState::Clean));
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());

    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let error = with_hook(
        |event, _| {
            if matches!(event, Event::BeforeVerify | Event::Unlink) {
                Err(io::Error::from_raw_os_error(libc::EPERM))
            } else {
                Ok(())
            }
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.publication, Publication::NotPublished);
    let CleanupState::Failed { path, error } = error.cleanup else { panic!("{error:?}") };
    assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    assert_eq!(stages(dir.path()), [path]);
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(!output.exists());
}

#[test]
fn cloned_caller_cursor_cannot_redirect_a_held_source() {
    use std::io::{Seek, SeekFrom};
    let dir = test_dir();
    let source = dir.path().join("source");
    let target = dir.path().join("target");
    std::fs::write(&source, b"whole file").unwrap();
    let file = File::open(&source).unwrap();
    let mut cloned = file.try_clone().unwrap();
    let mut plan = CreatePlan::new(&target, CreateOptions::default()).unwrap();
    plan.add_open_file(&source, file, metadata("file"), None).unwrap();
    let receipt = with_hook(
        move |event, _| {
            if event == Event::BeforeSourceRead {
                cloned.seek(SeekFrom::Start(5))?;
            }
            Ok(())
        },
        || plan.publish().unwrap(),
    );
    assert_eq!(receipt.summary.verification.decoded_bytes, 10);
    assert_eq!(std::fs::read(&source).unwrap(), b"whole file");
    assert!(stages(dir.path()).is_empty());
    let mut result = Vec::new();
    crate::zip::Archive::open(&target)
        .unwrap()
        .read_at(0, None, 10, |bytes| {
            result.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(result, b"whole file");
}

#[test]
fn limit_equalities_pass_and_one_less_stops_without_publication() {
    let (_directory, _, _, plan) = simple_plan(CreateOptions::default());
    let usage = plan.publish().unwrap().summary;
    let mut exact = CreateLimits {
        entries: usage.plan.entries,
        plan_capacity: usage.plan.capacity,
        plan_work: usage.plan.work,
        transaction_attempts: usage.transaction_attempts,
        verification_metadata: usage.verification.directory.owned.name_bytes as u64,
        verification_scratch: usage.verification.scratch_capacity,
        verification_records: usage.verification.record_capacity,
        verification_read_bytes: usage.verification.read_bytes,
        verification_entry_bytes: usage.verification.decoded_bytes,
        verification_decoded_bytes: usage.verification.decoded_bytes,
        ..CreateLimits::default()
    };
    exact.directory.entries = usage.verification.entries;
    exact.directory.directory_bytes = usage.verification.directory.directory_bytes;
    exact.directory.fetched_bytes = usage.verification.directory.fetched_bytes + usage.verification.discovery_bytes;
    exact.directory.work_units = usage.verification.directory.work_units + usage.verification.discovery_work;
    exact.writer.entries = usage.writer.entries;
    exact.writer.central_bytes = usage.writer.central_bytes;
    exact.writer.metadata_capacity = usage.writer.metadata_capacity;
    exact.writer.entry_decoded_bytes = usage.writer.decoded_bytes;
    exact.writer.source_bytes = usage.writer.source_bytes + 1;
    exact.writer.archive_extent = usage.writer.archive_extent;
    exact.writer.output_bytes = usage.writer.output_bytes;
    exact.writer.io_attempts = usage.writer.io_attempts;
    let (_keep, _, _, plan) = simple_plan(CreateOptions { limits: exact, ..CreateOptions::default() });
    assert_eq!(plan.publish().unwrap().summary, usage);

    type Reduce = fn(&mut CreateLimits);
    let budgets: [Reduce; 18] = [
        |l| l.plan_capacity -= 1,
        |l| l.plan_work -= 1,
        |l| l.transaction_attempts -= 1,
        |l| l.verification_metadata -= 1,
        |l| l.verification_scratch -= 1,
        |l| l.verification_read_bytes -= 1,
        |l| l.verification_entry_bytes -= 1,
        |l| l.verification_decoded_bytes -= 1,
        |l| l.directory.directory_bytes -= 1,
        |l| l.directory.fetched_bytes -= 1,
        |l| l.directory.work_units -= 1,
        |l| l.writer.central_bytes -= 1,
        |l| l.writer.metadata_capacity -= 1,
        |l| l.writer.entry_decoded_bytes -= 1,
        |l| l.writer.source_bytes -= 1,
        |l| l.writer.archive_extent -= 1,
        |l| l.writer.output_bytes -= 1,
        |l| l.writer.io_attempts -= 1,
    ];
    for reduce in budgets {
        let mut limits = exact;
        reduce(&mut limits);
        let dir = test_dir();
        let source = dir.path().join("source");
        let destination = dir.path().join("archive.zip");
        std::fs::write(&source, b"source data").unwrap();
        let mut plan = CreatePlan::new(&destination, CreateOptions { limits, ..CreateOptions::default() }).unwrap();
        if let Err(error) = plan.add_file(&source, metadata("file"), None) {
            assert!(matches!(error, CreateError::Limit(_)), "{error:?}");
        } else {
            let error = plan.publish().unwrap_err();
            assert_eq!(error.publication, Publication::NotPublished);
            assert!(
                matches!(
                    error.cause,
                    CreateError::Limit(_)
                        | CreateError::Directory(zip_container::DirectoryError::Limit(_))
                        | CreateError::Writer(WriteError::Limit(_))
                ),
                "{error:?}"
            );
            assert!(matches!(error.cleanup, CleanupState::Clean));
        }
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
        assert!(!destination.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn long_prefix_comparison_exhausts_a_bounded_plan_budget_before_staging() {
    let dir = test_dir();
    let output = dir.path().join("archive.zip");
    let mut options = CreateOptions::default();
    options.limits.plan_work = 126_000;
    let mut plan = CreatePlan::new(&output, options).unwrap();
    let prefix = "x".repeat(15_000);
    for suffix in ["/first/", "/second/"] {
        let name = format!("{prefix}{suffix}");
        plan.add_directory(metadata(&name), None).unwrap();
    }
    let error = plan.publish().unwrap_err();
    assert!(matches!(error.cause, CreateError::Limit(CreateLimit::PlanWork)));
    assert_eq!(error.summary.stage_attempts, 0);
    assert!(stages(dir.path()).is_empty());
    assert!(!output.exists());
}

#[test]
fn precommit_cancellation_and_unsupported_native_errors_are_definite() {
    for errno in [0, libc::ENOSYS, libc::EXDEV, libc::ENOTSUP] {
        let cancellation = Cancellation::default();
        let (dir, source, output, plan) =
            simple_plan(CreateOptions { cancel: cancellation.clone(), ..CreateOptions::default() });
        let error = with_hook(
            move |event, _| {
                if errno == 0 && event == Event::BeforeCommit {
                    cancellation.cancel();
                }
                if errno != 0 && event == Event::NativePublish {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                Ok(())
            },
            || plan.publish().unwrap_err(),
        );
        assert_eq!(error.publication, Publication::NotPublished);
        assert!(if errno == 0 {
            matches!(error.cause, CreateError::Canceled)
        } else {
            matches!(error.cause, CreateError::UnsupportedPublication(_))
        });
        assert!(matches!(error.cleanup, CleanupState::Clean));
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
        assert!(stages(dir.path()).is_empty());
        assert!(!output.exists());
    }
}

#[test]
fn changed_destination_parent_retains_the_unpublished_stage() {
    let dir = test_dir();
    let parent = dir.path().join("parent");
    let moved = dir.path().join("moved");
    std::fs::create_dir(&parent).unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"input").unwrap();
    let output = parent.join("archive.zip");
    let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    plan.add_file(&source, metadata("source"), None).unwrap();
    let originally = parent.clone();
    let later = moved.clone();
    let error = with_hook(
        move |event, _| {
            if event == Event::BeforeFinalSourceCheck {
                std::fs::rename(&originally, &later)?;
                std::fs::create_dir(&originally)?;
            }
            Ok(())
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.publication, Publication::NotPublished);
    assert!(matches!(error.cause, CreateError::ParentChanged));
    assert!(matches!(error.cleanup, CleanupState::RetainedOwnedStage { .. }));
    assert!(stages(&parent).is_empty());
    let leftover = stages(&moved);
    assert_eq!(leftover.len(), 1);
    assert!(crate::zip::Archive::open(&leftover[0]).is_ok());
    assert_eq!(std::fs::read(&source).unwrap(), b"input");
    assert!(!output.exists());
}

#[test]
fn directory_sync_interruptions_exhaust_only_the_aftermath_reserve() {
    let (dir, source, output, plan) =
        simple_plan(CreateOptions { durability: Durability::SyncFileAndDirectory, ..CreateOptions::default() });
    let error = with_hook(
        |event, _| {
            if event == Event::DirectorySync { Err(io::Error::from(io::ErrorKind::Interrupted)) } else { Ok(()) }
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.stage, CreateStage::DirectorySync);
    assert_eq!(error.publication, Publication::Published);
    assert_eq!(error.durability, DurabilityState::Unconfirmed);
    assert!(matches!(error.cause, CreateError::Limit(CreateLimit::FinalizationAttempts)));
    assert_eq!(error.summary.finalization_attempts, FINALIZATION_RESERVE);
    assert!(matches!(error.cleanup, CleanupState::Clean));
    assert!(crate::zip::Archive::open(&output).is_ok());
    assert!(stages(dir.path()).is_empty());
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
}

#[test]
fn stage_name_has_a_tilde_marker_disjoint_from_the_destination() {
    use std::os::unix::ffi::OsStrExt;
    for (leaf, stage_has_tilde) in [
        (".ZIPFAST-@ABCDEFGHIJKLMNOP", true),
        (".ZIPFAST-~ABCDEFGHIJKLMNOP", false),
        (".ZIPFAST-＠ABCDEFGHIJKLMNOP", true),
    ] {
        let dir = test_dir();
        let target = dir.path().join(leaf);
        let destination = target.clone();
        let plan = CreatePlan::new(&target, CreateOptions::default()).unwrap();
        let receipt = with_hook(
            move |event, path| {
                if event == Event::BeforeVerify {
                    let stage = path.unwrap().file_name().unwrap().as_bytes();
                    assert_eq!(stage.contains(&b'~'), stage_has_tilde);
                    assert!(!destination.exists());
                }
                Ok(())
            },
            || plan.publish().unwrap(),
        );
        assert_eq!(receipt.publication, Publication::Published);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(crate::zip::Archive::open(&target).is_ok());
    }
}

#[test]
fn native_filesystem_qualification() {
    let directory = test_dir();
    let target = directory.path().join("archive.zip");
    let filesystem = unix::filesystem(&File::open(directory.path()).unwrap()).unwrap();
    println!("qualified creation filesystem: {filesystem:?} at {}", directory.path().display());
    #[cfg(target_os = "macos")]
    assert!(matches!(filesystem, unix::Filesystem::Apfs));
    #[cfg(target_os = "linux")]
    assert!(matches!(filesystem, unix::Filesystem::Tmpfs | unix::Filesystem::ExtFamily));
    CreatePlan::new(&target, CreateOptions::default()).unwrap().publish().unwrap();
    assert!(crate::zip::Archive::open(&target).is_ok());
    println!("case-alias lookup: {}", target.with_file_name("ARCHIVE.ZIP").exists());
}

#[test]
fn short_io_and_interrupted_stage_io_complete_with_exact_payload() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let mut interrupted = [false; 4];
    let result = with_hook(
        move |event, _| {
            SINK_WRITE_CAP.set(3);
            SOURCE_READ_CAP.set(2);
            let slot = match event {
                Event::ReadSource => 0,
                Event::SinkSeek => 1,
                Event::VerifyRead => 2,
                Event::VerifySeek => 3,
                _ => return Ok(()),
            };
            if !std::mem::replace(&mut interrupted[slot], true) {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            Ok(())
        },
        || plan.publish().unwrap(),
    );
    assert_eq!(result.summary.verification.payloads, 1);
    assert_eq!(result.summary.writer.source_bytes, 11);
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(stages(dir.path()).is_empty());
    let mut archive = crate::zip::Archive::open(&output).unwrap();
    let mut bytes = Vec::new();
    archive
        .read_at(0, None, 11, |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    assert_eq!(bytes, b"source data");
}

#[test]
fn zero_writes_and_eof_probe_failures_are_precommit() {
    for zero_write in [true, false] {
        let (dir, source, output, plan) = simple_plan(CreateOptions::default());
        let mut source_reads = 0;
        let error = with_hook(
            move |event, _| {
                if zero_write {
                    SINK_WRITE_CAP.set(0);
                } else if event == Event::ReadSource {
                    source_reads += 1;
                    if source_reads == 2 {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || plan.publish().unwrap_err(),
        );
        assert_eq!(error.stage, if zero_write { CreateStage::Write } else { CreateStage::SourceRead });
        assert_eq!(error.publication, Publication::NotPublished);
        assert!(matches!(error.cleanup, CleanupState::Clean));
        assert_eq!(std::fs::read(&source).unwrap(), b"source data");
        assert!(stages(dir.path()).is_empty());
        assert!(!output.exists());
    }
}

#[test]
fn capture_is_not_refreshed_after_the_admission_handle_closes() {
    let dir = test_dir();
    let source = dir.path().join("source");
    let output = dir.path().join("archive.zip");
    std::fs::write(&source, b"first").unwrap();
    let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    with_hook(
        |event, path| {
            if event == Event::AfterAdmissionClose {
                let file = File::options().write(true).open(path.unwrap())?;
                use std::io::Write;
                (&file).write_all(b"later")?;
                file.set_times(std::fs::FileTimes::new().set_modified(std::time::UNIX_EPOCH))?;
            }
            Ok(())
        },
        || plan.add_file(&source, metadata("file"), None).unwrap(),
    );
    let error = plan.publish().unwrap_err();
    assert_eq!(error.stage, CreateStage::SourceRead);
    assert_eq!(error.publication, Publication::NotPublished);
    assert!(matches!(error.cause, CreateError::SourceChanged(CreateEntryId(0))));
    assert!(matches!(error.cleanup, CleanupState::Clean));
    assert_eq!(std::fs::read(&source).unwrap(), b"later");
    assert!(stages(dir.path()).is_empty());
    assert!(!output.exists());
}

#[test]
fn admission_allocation_failure_keeps_accepted_entries() {
    let (dir, source, output, mut plan) = simple_plan(CreateOptions::default());
    let before = plan.usage().plan;
    let error = with_hook(
        |event, _| {
            if event == Event::MetadataReserve {
                return Err(io::Error::from(io::ErrorKind::OutOfMemory));
            }
            Ok(())
        },
        || plan.add_file(&source, metadata("rejected"), None).unwrap_err(),
    );
    assert!(matches!(error, CreateError::Allocation(_)));
    assert_eq!(plan.usage().plan.entries, before.entries);
    assert_eq!(plan.usage().plan.capacity, before.capacity);
    assert_eq!(plan.publish().unwrap().summary.verification.payloads, 1);
    assert!(crate::zip::Archive::open(&output).is_ok());
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn identical_source_observations_cannot_prove_continuous_ownership() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let captured = plan.entries[0].source.as_ref().unwrap().stamp;
    std::fs::rename(&source, dir.path().join("old-source")).unwrap();
    std::fs::write(&source, b"other bytes").unwrap();
    let attempts = Attempts::new(&plan.options, &plan.attempts);
    let actual = unix::path_stamp(&source, &attempts).unwrap();
    assert!(transaction::verify_stamp(captured, actual, CreateEntryId(0)).is_err());
    // Inject the same observation as admission to model undetectable inode
    // reuse or a change whose final stamp is indistinguishable.
    assert!(transaction::verify_stamp(captured, captured, CreateEntryId(0)).is_ok());
    assert_eq!(std::fs::read(&source).unwrap(), b"other bytes");
    assert_eq!(std::fs::read(dir.path().join("old-source")).unwrap(), b"source data");
    assert!(!output.exists());
}

#[test]
fn native_stage_collision_keeps_the_other_file() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let mut first = true;
    let receipt = with_hook(
        move |event, path| {
            if event == Event::StageOpen && std::mem::take(&mut first) {
                std::fs::write(path.unwrap(), b"other creator's stage")?;
            }
            Ok(())
        },
        || plan.publish().unwrap(),
    );
    assert_eq!(receipt.publication, Publication::Published);
    assert!((2..=STAGE_ATTEMPTS).contains(&receipt.summary.stage_attempts));
    let files = stages(dir.path());
    assert_eq!(files.len(), 1);
    assert_eq!(std::fs::read(&files[0]).unwrap(), b"other creator's stage");
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(crate::zip::Archive::open(&output).is_ok());
}

#[test]
fn a_foreign_stage_symlink_is_never_followed_or_removed() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let link_target = source.clone();
    let displaced = dir.path().join("displaced");
    let moved = displaced.clone();
    let error = with_hook(
        move |event, path| {
            if event == Event::BeforeVerify {
                let stage = path.unwrap();
                std::fs::rename(stage, &moved)?;
                std::os::unix::fs::symlink(&link_target, stage)?;
            }
            Ok(())
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.publication, Publication::NotPublished);
    assert_eq!(error.stage, CreateStage::Precommit);
    assert_eq!(error.summary.verification.payloads, 1);
    let CleanupState::ForeignStageName { path } = error.cleanup else { panic!("{error:?}") };
    assert_eq!(std::fs::read_link(&path).unwrap(), source);
    assert_eq!(stages(dir.path()), [path]);
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(crate::zip::Archive::open(&displaced).is_ok());
    assert!(!output.exists());
}

#[test]
fn ambiguous_publish_keeps_an_owned_stage_when_rename_did_not_run() {
    let (dir, source, output, plan) = simple_plan(CreateOptions::default());
    let error = with_hook(
        |event, _| {
            if event == Event::NativePublish {
                return Err(io::Error::from_raw_os_error(libc::EINTR));
            }
            Ok(())
        },
        || plan.publish().unwrap_err(),
    );
    assert_eq!(error.publication, Publication::Unknown);
    assert_eq!(error.stage, CreateStage::Publish);
    let CleanupState::RetainedOwnedStage { path } = error.cleanup else { panic!("{error:?}") };
    assert!(crate::zip::Archive::open(&path).is_ok());
    assert_eq!(stages(dir.path()), [path]);
    assert_eq!(std::fs::read(&source).unwrap(), b"source data");
    assert!(!output.exists());
}

#[test]
fn scratch_ceiling_rejects_discovery_and_fragmented_central_growth_before_reserving() {
    let directory = test_dir();
    let source = directory.path().join("empty");
    let target = directory.path().join("archive.zip");
    std::fs::write(&source, []).unwrap();

    // The first cap fits only the EOCD tail. The second also fits the
    // discovery's inline buffers and reaches the fragmented central body.
    for (cap, reaches_directory) in [(65_633, false), (70_000, true)] {
        let mut options = CreateOptions::default();
        options.limits.verification_scratch = cap;
        let mut plan = CreatePlan::new(&target, options).unwrap();
        let name = "x".repeat(u16::MAX as usize);
        let comment = vec![b'a'; u16::MAX as usize];
        let mut metadata = metadata(&name);
        metadata.comment = &comment;
        plan.add_file(&source, metadata, None).unwrap();

        let failure = plan.publish().unwrap_err();
        assert_eq!(failure.stage, CreateStage::Verify);
        assert!(matches!(failure.cause, CreateError::Limit(CreateLimit::VerificationScratch)));
        assert_eq!(failure.publication, Publication::NotPublished);
        assert!(matches!(failure.cleanup, CleanupState::Clean));
        assert_eq!(failure.summary.verification.directory.fetched_bytes != 0, reaches_directory);
        assert!(
            failure.summary.verification.scratch_capacity <= cap,
            "scratch reservation exceeded {cap} bytes: {failure:?}"
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"");
        assert!(!target.exists());
        assert!(stages(directory.path()).is_empty());
    }
}

#[test]
fn corrupted_central_name_length_cannot_grow_scratch_past_the_cap() {
    use std::os::unix::fs::FileExt;

    let directory = test_dir();
    let source = directory.path().join("empty");
    let target = directory.path().join("archive.zip");
    std::fs::write(&source, []).unwrap();
    let cap = 120_000;
    let first = "a".repeat(48_000);
    let second = "b".repeat(48_000);
    let plan_at = |destination: &Path| {
        let mut options = CreateOptions::default();
        options.limits.verification_scratch = cap;
        let mut plan = CreatePlan::new(destination, options).unwrap();
        plan.add_file(&source, metadata(&first), None).unwrap();
        plan.add_file(&source, metadata(&second), None).unwrap();
        plan
    };
    let control = directory.path().join("control.zip");
    let valid = plan_at(&control).publish().unwrap();
    assert_eq!(valid.summary.verification.payloads, 2);
    assert!(valid.summary.verification.scratch_capacity <= cap);
    let control_bytes = std::fs::read(&control).unwrap();

    let central_at = 2 * (30 + 48_000); // Two Stored empty files with no local extras.
    let failure = with_hook(
        move |event, path| {
            if event == Event::BeforeVerify {
                let file = File::options().write(true).open(path.unwrap())?;
                file.write_all_at(&u16::MAX.to_le_bytes(), central_at + 28)?;
            }
            Ok(())
        },
        || plan_at(&target).publish().unwrap_err(),
    );
    assert_eq!(failure.stage, CreateStage::Verify);
    assert!(matches!(failure.cause, CreateError::Limit(CreateLimit::VerificationScratch)));
    assert_eq!(failure.publication, Publication::NotPublished);
    assert!(matches!(failure.cleanup, CleanupState::Clean));
    assert!(failure.summary.verification.directory.fetched_bytes > 0);
    assert!(failure.summary.verification.scratch_capacity <= cap);
    assert_eq!(std::fs::read(&source).unwrap(), b"");
    assert_eq!(std::fs::read(&control).unwrap(), control_bytes);
    assert!(!target.exists());
    assert!(stages(directory.path()).is_empty());
}
