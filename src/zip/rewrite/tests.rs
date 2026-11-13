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

use std::{cell::RefCell, io, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::zip) enum Event {
    Write,
    Flush,
    FileSync,
    BeforeInputRead,
    BeforeFinish,
    AfterFinish,
    AfterVerify,
    StageVerifyRead,
    BeforeFinalCheck,
    AfterFinalCheck,
    NativePublish,
    AfterCommit,
    DirectorySync,
}

type Hook = dyn FnMut(Event, Option<&Path>) -> io::Result<()>;

thread_local! {
    static HOOK: RefCell<Option<Box<Hook>>> = RefCell::new(None);
    static SOURCE_READ_CAP: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

pub(in crate::zip) fn test_event(event: Event, path: Option<&Path>) -> io::Result<()> {
    HOOK.with_borrow_mut(|hook| hook.as_mut().map_or(Ok(()), |hook| hook(event, path)))
}

use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{FileExt, MetadataExt},
    path::PathBuf,
};

use crate::zip::create::{CleanupState, Durability, DurabilityState, Publication};
use crate::zip::write::{
    DosDateTime, EntryName, EntryOptions, EntryWritten, InputLength, Method, Permissions, WriterOptions, ZipWriter,
};

use super::{
    DestinationObservation, Placement, Replacement, RewriteError, RewriteOptions, RewriteOutcome, RewritePlan,
    RewriteStage,
};

fn with_hook<T>(hook: impl FnMut(Event, Option<&Path>) -> io::Result<()> + 'static, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HOOK.with_borrow_mut(|hook| *hook = None);
            SOURCE_READ_CAP.set(usize::MAX)
        }
    }
    HOOK.with_borrow_mut(|stored| *stored = Some(Box::new(hook)));
    let _reset = Reset;
    run()
}

fn options() -> RewriteOptions {
    RewriteOptions::new(Replacement::LastWriterWins)
}

fn entry(name: &str) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method: Method::Stored,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"note",
    }
}

fn old_archive() -> (tempfile::TempDir, PathBuf, Vec<u8>) {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive.zip");
    let mut writer = ZipWriter::new(File::create(&archive).unwrap(), WriterOptions::default()).unwrap();
    writer.add_file(entry("old"), &mut b"old-data".as_slice(), InputLength::Exact(8)).unwrap();
    writer.finish().unwrap();
    let old = fs::read(&archive).unwrap();
    (root, archive, old)
}

fn edited(archive: &Path, options: RewriteOptions, name: &str) -> RewritePlan {
    let mut plan = RewritePlan::open(archive, options).unwrap();
    plan.add_directory(Placement::Append, entry(name), None).unwrap();
    plan
}

fn unchanged(archive: &Path, old: &[u8], before: &fs::Metadata) {
    assert_eq!(fs::read(archive).unwrap(), old);
    let current = fs::metadata(archive).unwrap();
    assert_eq!(
        (current.ino(), current.mode(), current.mtime(), current.mtime_nsec()),
        (before.ino(), before.mode(), before.mtime(), before.mtime_nsec())
    );
}

#[test]
fn write_flush_file_sync_and_definite_rename_failures_clean_the_stage() {
    for (event, expected_stage, errno) in [
        (Event::Write, RewriteStage::Write, libc::EIO),
        (Event::Flush, RewriteStage::Finish, libc::EIO),
        (Event::BeforeFinish, RewriteStage::Finish, libc::EIO),
        (Event::FileSync, RewriteStage::FileSync, libc::EIO),
        (Event::NativePublish, RewriteStage::Publish, libc::EACCES),
    ] {
        let (root, archive, old) = old_archive();
        let before = fs::metadata(&archive).unwrap();
        let mut options = options();
        options.durability = Durability::SyncFileAndDirectory;
        let plan = edited(&archive, options, "new/");
        let error = with_hook(
            move |observed, _| {
                if observed == event {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                Ok(())
            },
            || plan.publish(),
        )
        .unwrap_err();
        assert_eq!(error.stage, expected_stage);
        assert_eq!(error.publication, Publication::NotPublished);
        assert!(matches!(error.cleanup, CleanupState::Clean));
        unchanged(&archive, &old, &before);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[test]
fn retained_payload_and_central_patch_neighbor_corruption_are_detected() {
    for (relative_to_central, offset) in [(false, 33), (true, 41), (true, 46 + 3)] {
        let (root, archive, old) = old_archive();
        let before = fs::metadata(&archive).unwrap();
        let plan = edited(&archive, options(), "new/");
        let error = with_hook(
            move |event, path| {
                if event == Event::AfterFinish {
                    let path = path.unwrap();
                    let bytes = fs::read(path)?;
                    let central = bytes.windows(4).position(|b| b == b"PK\x01\x02").unwrap();
                    let at = if relative_to_central { central + offset } else { offset };
                    let file = OpenOptions::new().write(true).open(path)?;
                    file.write_all_at(&[bytes[at] ^ 1], at as u64)?;
                }
                Ok(())
            },
            || plan.publish(),
        )
        .unwrap_err();
        assert_eq!(error.stage, RewriteStage::Verify);
        assert!(matches!(error.cause, RewriteError::Verification("retained bytes differ")));
        unchanged(&archive, &old, &before);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[test]
fn changing_new_payload_after_finish_never_publishes() {
    let (root, archive, old) = old_archive();
    let source = root.path().join("input");
    fs::write(&source, b"new-data").unwrap();
    let before = fs::metadata(&archive).unwrap();
    let mut plan = RewritePlan::open(&archive, options()).unwrap();
    plan.add_file(Placement::Append, &source, entry("new"), None).unwrap();
    let error = with_hook(
        |event, path| {
            if event == Event::AfterFinish {
                // Old local: 30 + 3 + 8. New local: 30 + 3.
                OpenOptions::new().write(true).open(path.unwrap())?.write_all_at(b"N", 74)?;
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(error.stage, RewriteStage::Verify);
    assert_eq!(error.publication, Publication::NotPublished);
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read(source).unwrap(), b"new-data");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn foreign_stage_name_is_left_alone_after_substitution() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let plan = edited(&archive, options(), "new/");
    let saved = root.path().join("moved-stage");
    let moved = saved.clone();
    let failure = with_hook(
        move |event, path| {
            if event == Event::BeforeFinalCheck {
                let path = path.unwrap();
                fs::rename(path, &moved)?;
                fs::write(path, b"foreign")?;
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.stage, RewriteStage::Precommit);
    assert_eq!(failure.publication, Publication::NotPublished);
    let CleanupState::ForeignStageName { path } = failure.cleanup else { panic!("wrong cleanup receipt") };
    assert_eq!(fs::read(path).unwrap(), b"foreign");
    assert!(saved.is_file());
    unchanged(&archive, &old, &before);
}

#[test]
fn uncertain_native_failure_retains_owned_stage_and_observes_target() {
    let (_root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let plan = edited(&archive, options(), "new/");
    let failure = with_hook(
        |event, _| {
            if event == Event::NativePublish {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.publication, Publication::Unknown);
    let CleanupState::RetainedOwnedStage { path } = failure.cleanup else { panic!("wrong cleanup receipt") };
    let recovery = failure.recovery.unwrap();
    assert_eq!(recovery.stage_identity.inode, fs::metadata(path).unwrap().ino());
    assert!(matches!(recovery.destination, DestinationObservation::Regular(id) if id.inode == before.ino()));
    unchanged(&archive, &old, &before);
}

#[test]
fn uncertainty_after_native_replacement_leaves_the_destination() {
    let (root, archive, old) = old_archive();
    let plan = edited(&archive, options(), "new/");
    let target = archive.clone();
    let mut stage = None;
    let failure = with_hook(
        move |event, path| {
            if event == Event::AfterFinalCheck {
                stage = path.map(Path::to_path_buf)
            }
            if event == Event::NativePublish {
                fs::rename(stage.as_ref().unwrap(), &target)?;
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.publication, Publication::Unknown);
    assert!(matches!(failure.cleanup, CleanupState::Clean));
    let recovery = failure.recovery.unwrap();
    assert!(matches!(recovery.destination, DestinationObservation::Regular(id) if id == recovery.stage_identity));
    assert_ne!(fs::read(archive).unwrap(), old);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn cancellation_before_commit_preserves_original_and_after_commit_preserves_replacement() {
    for event in [Event::AfterFinalCheck, Event::AfterCommit] {
        let (root, archive, old) = old_archive();
        let before = fs::metadata(&archive).unwrap();
        let options = options();
        let cancel = options.cancel.clone();
        let plan = edited(&archive, options, "new/");
        let failure = with_hook(
            move |observed, _| {
                if observed == event {
                    cancel.cancel()
                }
                Ok(())
            },
            || plan.publish(),
        )
        .unwrap_err();
        if event == Event::AfterCommit {
            assert_eq!(failure.publication, Publication::Published);
            assert_eq!(failure.verification.unwrap().new_verified, 1);
            assert_ne!(fs::read(archive).unwrap(), old);
        } else {
            assert_eq!(failure.publication, Publication::NotPublished);
            unchanged(&archive, &old, &before);
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[test]
fn directory_sync_failure_reports_verified_published_output() {
    let (root, archive, old) = old_archive();
    let mut options = options();
    options.durability = Durability::SyncFileAndDirectory;
    let plan = edited(&archive, options, "new/");
    let failure = with_hook(
        |event, _| {
            if event == Event::DirectorySync {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(
        (failure.stage, failure.publication, failure.durability),
        (RewriteStage::DirectorySync, Publication::Published, DurabilityState::Unconfirmed)
    );
    assert_eq!(failure.verification.unwrap().new_verified, 1);
    assert_ne!(fs::read(archive).unwrap(), old);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn write_receipts_require_known_publication_even_when_finalization_fails() {
    for (event, publication) in [
        (Event::BeforeFinalCheck, Publication::NotPublished),
        (Event::NativePublish, Publication::Unknown),
        (Event::AfterCommit, Publication::Published),
        (Event::DirectorySync, Publication::Published),
    ] {
        let (root, archive, old) = old_archive();
        let before = fs::metadata(&archive).unwrap();
        let mut options = options();
        options.durability = Durability::SyncFileAndDirectory;
        let cancel = options.cancel.clone();
        let plan = edited(&archive, options, "new/");
        let report = with_hook(
            move |observed, _| {
                if observed == event {
                    if observed == Event::AfterCommit {
                        cancel.cancel();
                    } else {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || plan.publish_with_receipts(),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(failure.publication, publication);
        if publication == Publication::Published {
            assert_eq!(failure.verification.unwrap().new_verified, 1);
            assert_eq!(
                report.written,
                [EntryWritten {
                    ordinal: 1,
                    method: Method::Stored,
                    crc32: 0,
                    decoded_size: 0,
                    packed_size: 0,
                    local_offset: 41,
                }]
            );
            assert_ne!(fs::read(&archive).unwrap(), old);
        } else {
            assert!(report.written.is_empty());
            unchanged(&archive, &old, &before);
        }
        let files = if publication == Publication::Unknown { 2 } else { 1 };
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), files);
    }
}

#[test]
fn competing_rewrite_before_final_check_is_detected_and_after_check_can_be_overwritten() {
    for event in [Event::BeforeFinalCheck, Event::AfterFinalCheck] {
        let (_root, archive, _) = old_archive();
        let ours = edited(&archive, options(), "ours/");
        let theirs = edited(&archive, options(), "theirs/");
        let (start, waiting) = std::sync::mpsc::channel();
        let (completed, done) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            waiting.recv().unwrap();
            completed.send(theirs.publish()).unwrap();
        });
        let result = with_hook(
            move |observed, _| {
                if observed == event {
                    start.send(()).unwrap();
                    assert!(matches!(done.recv().unwrap().unwrap(), RewriteOutcome::Replaced(_)));
                }
                Ok(())
            },
            || ours.publish(),
        );
        other.join().unwrap();
        let snapshot = RewritePlan::open(&archive, options()).unwrap().metadata();
        let names: Vec<_> = snapshot.entries().map(|entry| entry.raw_name()).collect();
        if event == Event::BeforeFinalCheck {
            let failure = result.unwrap_err();
            assert_eq!(failure.publication, Publication::NotPublished);
            assert!(matches!(failure.cause, RewriteError::SourceChanged));
            assert_eq!(names, [b"old".as_slice(), b"theirs/"]);
        } else {
            assert!(matches!(result.unwrap(), RewriteOutcome::Replaced(_)));
            assert_eq!(names, [b"old".as_slice(), b"ours/"]);
        }
    }
}

#[test]
fn changed_input_before_stream_does_not_replace_the_destination() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let source = root.path().join("source");
    fs::write(&source, b"123").unwrap();
    let mut plan = RewritePlan::open(&archive, options()).unwrap();
    plan.add_file(Placement::Append, &source, entry("new"), None).unwrap();
    fs::write(&source, b"1234").unwrap();
    let failure = plan.publish().unwrap_err();
    assert_eq!(failure.stage, RewriteStage::SourceRead);
    assert!(matches!(failure.cause, RewriteError::InputChanged { input: 0 }));
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read(source).unwrap(), b"1234");
}

#[test]
fn unchanged_sync_request_uses_no_stage_or_fsync() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let mut options = options();
    options.durability = Durability::SyncFileAndDirectory;
    let plan = RewritePlan::open(&archive, options).unwrap();
    let result = with_hook(|_, _| panic!("no-op took a transaction action"), || plan.publish()).unwrap();
    assert_eq!(result.durability(), DurabilityState::NotRequested);
    assert!(matches!(result, RewriteOutcome::Unchanged { usage, .. } if usage.common.stage_attempts == 0));
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn repeated_interrupted_writes_exhaust_the_writer_attempt_budget() {
    use crate::zip::write::{Limit, WriteError};
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let mut options = options();
    options.limits.common.writer.io_attempts = 12;
    let plan = edited(&archive, options, "new/");
    let failure = with_hook(
        |event, _| {
            if event == Event::Write {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert!(matches!(failure.cause, RewriteError::Writer(WriteError::Limit(Limit::IoAttempts))));
    assert_eq!(failure.usage.common.writer.io_attempts, 12);
    assert_eq!(failure.publication, Publication::NotPublished);
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn cancellation_between_verifier_reads_cleans_the_stage() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let options = options();
    let cancel = options.cancel.clone();
    let plan = edited(&archive, options, "new/");
    let mut reads = 0;
    let failure = with_hook(
        move |event, _| {
            if event == Event::StageVerifyRead {
                reads += 1;
                if reads == 2 {
                    cancel.cancel()
                }
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.stage, RewriteStage::Verify);
    assert_eq!(failure.publication, Publication::NotPublished);
    assert!(failure.usage.common.verification.read_bytes > 0);
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn stage_change_after_successful_verification_blocks_publication() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let plan = edited(&archive, options(), "new/");
    let failure = with_hook(
        |event, path| {
            if event == Event::AfterVerify {
                use io::Write;
                OpenOptions::new().append(true).open(path.unwrap())?.write_all(b"x")?;
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.stage, RewriteStage::Permissions);
    assert_eq!(failure.publication, Publication::NotPublished);
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn tracked_directory_can_be_appended_or_replaced_with_a_descendant() {
    for replace in [false, true] {
        let (root, archive, _) = old_archive();
        let source = root.path().join("directory");
        fs::create_dir(&source).unwrap();
        let child = source.join("child");
        fs::write(&child, b"contents").unwrap();
        if replace {
            let mut initial = edited(&archive, options(), "directory/");
            initial.add_file(Placement::Append, &child, entry("directory/child"), None).unwrap();
            initial.publish().unwrap();
        }

        let mut plan = RewritePlan::open(&archive, options()).unwrap();
        let directory =
            if replace { Placement::Replace(plan.metadata().entry_id(1).unwrap()) } else { Placement::Append };
        plan.add_directory_from_path(directory, &source, entry("directory/"), None).unwrap();
        if !replace {
            plan.add_file(Placement::Append, &child, entry("directory/child"), None).unwrap();
        }
        plan.publish().unwrap();
        let result = RewritePlan::open(&archive, options()).unwrap();
        assert_eq!(
            result.metadata().entries().map(|entry| entry.raw_name()).collect::<Vec<_>>(),
            [b"old".as_slice(), b"directory/", b"directory/child"]
        );
    }
}

#[test]
fn tracked_directory_substitution_blocks_rewrite_publication() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let source = root.path().join("directory");
    let moved = root.path().join("moved");
    fs::create_dir(&source).unwrap();
    let mut plan = RewritePlan::open(&archive, options()).unwrap();
    plan.add_directory_from_path(Placement::Append, &source, entry("directory/"), None).unwrap();
    let changed = source.clone();
    let failure = with_hook(
        move |event, _| {
            if event == Event::BeforeFinalCheck {
                fs::rename(&changed, &moved)?;
                std::os::unix::fs::symlink(&moved, &changed)?;
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.stage, RewriteStage::Precommit);
    assert_eq!(failure.publication, Publication::NotPublished);
    assert!(matches!(failure.cause, RewriteError::InputChanged { input: 0 }));
    unchanged(&archive, &old, &before);
    assert!(fs::symlink_metadata(source).unwrap().is_symlink());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
}

#[test]
fn source_change_after_the_stream_binding_check_blocks_publication() {
    let (root, archive, old) = old_archive();
    let before = fs::metadata(&archive).unwrap();
    let source = root.path().join("input");
    fs::write(&source, b"original").unwrap();
    let mut plan = RewritePlan::open(&archive, options()).unwrap();
    plan.add_file(Placement::Append, &source, entry("new"), None).unwrap();
    let failure = with_hook(
        |event, path| {
            if event == Event::BeforeInputRead {
                let path = path.unwrap();
                fs::write(path, b"external")?;
                let permissions = fs::metadata(path)?.permissions();
                let mut different = permissions.clone();
                use std::os::unix::fs::PermissionsExt;
                different.set_mode(permissions.mode() ^ 0o100);
                fs::set_permissions(path, different)?;
            }
            Ok(())
        },
        || plan.publish(),
    )
    .unwrap_err();
    assert_eq!(failure.stage, RewriteStage::SourceRead);
    assert!(matches!(failure.cause, RewriteError::InputChanged { input: 0 }));
    assert_eq!(fs::read(source).unwrap(), b"external");
    unchanged(&archive, &old, &before);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

#[test]
fn recovery_rechecks_source_and_stage_before_publication() {
    use crate::zip::recovery::{RecoveryOptions, RecoveryPlan};
    for source_change in [true, false] {
        let (root, source, original) = old_archive();
        let target = root.path().join("recovered.zip");
        let plan = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap();
        let mutated_source = source.clone();
        let report = with_hook(
            move |event, stage| {
                if event == Event::AfterVerify {
                    let path = if source_change { mutated_source.as_path() } else { stage.unwrap() };
                    OpenOptions::new().write(true).open(path)?.write_at(b"x", 0)?;
                }
                Ok(())
            },
            || plan.recover(),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(failure.publication, Publication::NotPublished);
        assert!(matches!(failure.cleanup, CleanupState::Clean));
        if source_change {
            assert!(matches!(failure.cause, RewriteError::SourceChanged));
        } else {
            assert!(matches!(
                failure.cause,
                RewriteError::Infrastructure(crate::zip::create::CreateError::StageChanged)
            ));
            assert_eq!(fs::read(&source).unwrap(), original);
        }
        assert!(!target.exists());
        assert_eq!(report.entries.len(), 1);
    }
}

#[test]
fn recovery_preserves_foreign_stage_name_and_late_destination() {
    use crate::zip::recovery::{RecoveryOptions, RecoveryPlan};
    for substitute in [false, true] {
        let (root, source, original) = old_archive();
        let target = root.path().join("recovered.zip");
        let target_hook = target.clone();
        let stage_path = std::rc::Rc::new(RefCell::new(None));
        let path_hook = stage_path.clone();
        let plan = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap();
        let report = with_hook(
            move |event, path| {
                if event == Event::AfterVerify && substitute {
                    let path = path.unwrap();
                    fs::remove_file(path)?;
                    fs::write(path, b"foreign stage")?;
                    *path_hook.borrow_mut() = Some(path.to_path_buf());
                }
                if event == Event::AfterFinalCheck && !substitute {
                    fs::write(&target_hook, b"late destination")?;
                }
                Ok(())
            },
            || plan.recover(),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(failure.publication, Publication::NotPublished);
        if substitute {
            assert!(matches!(failure.cleanup, CleanupState::ForeignStageName { .. }));
            assert_eq!(fs::read(stage_path.borrow().as_ref().unwrap()).unwrap(), b"foreign stage");
            assert!(!target.exists());
        } else {
            assert!(matches!(failure.cause, RewriteError::Infrastructure(crate::zip::create::CreateError::Conflict)));
            assert!(matches!(failure.cleanup, CleanupState::Clean));
            assert_eq!(fs::read(&target).unwrap(), b"late destination");
        }
        assert_eq!(fs::read(source).unwrap(), original);
    }
}

#[test]
fn recovery_sync_failure_reports_published_survivors() {
    use crate::zip::recovery::{RecoveryOptions, RecoveryPlan};
    let (root, source, original) = old_archive();
    let target = root.path().join("recovered.zip");
    let options = RecoveryOptions { durability: Durability::SyncFileAndDirectory, ..RecoveryOptions::default() };
    let plan = RecoveryPlan::open(&source, &target, options).unwrap();
    let report = with_hook(
        |event, _| {
            if event == Event::DirectorySync { Err(io::Error::from_raw_os_error(libc::EIO)) } else { Ok(()) }
        },
        || plan.recover(),
    );
    let failure = report.outcome.unwrap_err();
    assert_eq!(failure.stage, RewriteStage::DirectorySync);
    assert_eq!(failure.publication, Publication::Published);
    assert!(failure.verification.is_some());
    assert!(target.exists());
    assert_eq!(fs::read(source).unwrap(), original);
    assert_eq!(report.entries.len(), 1);
}

pub(in crate::zip) fn source_read_cap() -> usize {
    SOURCE_READ_CAP.get()
}

#[test]
fn recovery_raw_copy_handles_single_byte_reads_through_descriptor_patch() {
    use crate::zip::recovery::{RecoveryOptions, RecoveryOutcome, RecoveryPlan};
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("old.zip");
    let target = root.path().join("recovered.zip");
    let old = include_bytes!("layout/fixtures/signed-descriptor-bad-crc-with-central.zip");
    fs::write(&source, old).unwrap();
    let plan = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap();
    let report = with_hook(
        |_, _| Ok(()),
        || {
            SOURCE_READ_CAP.set(1);
            plan.recover()
        },
    );
    assert!(matches!(report.outcome, Ok(RecoveryOutcome::Published(_))));
    assert_eq!(&fs::read(target).unwrap()[483..499], &[80, 75, 7, 8, 147, 68, 241, 76, 184, 1, 0, 0, 184, 1, 0, 0]);
    assert_eq!(fs::read(source).unwrap(), old);
}
