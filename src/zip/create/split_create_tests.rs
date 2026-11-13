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
use std::{cell::RefCell, io};
use tests::{Event, metadata, with_hook};
fn plan(durability: Durability) -> (tempfile::TempDir, CreatePlan) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::write(&input, [b'A'; 2000]).unwrap();
    let mut p =
        CreatePlan::new(&dir.path().join("out.zip"), CreateOptions { durability, ..CreateOptions::default() }).unwrap();
    p.add_file(&input, metadata("payload"), None).unwrap();
    (dir, p)
}
fn options() -> SplitCreateOptions {
    SplitCreateOptions { volume_bytes: 512, ..SplitCreateOptions::default() }
}
#[test]
fn split_create_every_definite_rename_failure_rolls_back_only_owned_names() {
    for fail in 1..=5 {
        let (dir, p) = plan(Durability::VisibilityOnly);
        let mut calls = 0;
        let r = with_hook(
            move |event, _| {
                if event == Event::NativePublish {
                    calls += 1;
                    if calls == fail {
                        return Err(io::Error::from_raw_os_error(libc::EACCES));
                    }
                }
                Ok(())
            },
            || p.publish_split_with_receipts(options()),
        );
        assert!(r.outcome.is_err(), "rename {fail}");
        assert_eq!(
            r.commit,
            if fail == 1 { SplitCommitState::NonePublished } else { SplitCommitState::PrefixPublished }
        );
        assert_eq!(r.visibility, SplitVisibility::NoneMatch);
        assert!(r.written.is_empty());
        assert!(r.reconciliation.is_none(), "{r:?}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "{r:?}");
    }
}
#[test]
fn split_create_every_unknown_rename_retains_the_whole_owned_set() {
    for fail in 1..=5 {
        let (dir, p) = plan(Durability::VisibilityOnly);
        let mut calls = 0;
        let r = with_hook(
            move |event, _| {
                if event == Event::NativePublish {
                    calls += 1;
                    if calls == fail {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || p.publish_split_with_receipts(options()),
        );
        assert!(r.outcome.is_err());
        assert_eq!(r.commit, SplitCommitState::Unknown);
        assert!(r.written.is_empty());
        let evidence = r.reconciliation.as_ref().unwrap();
        assert_eq!(evidence.staged_members().len(), 1);
        assert_eq!(r.summary.reconciliation_handles, 6);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 6);
        drop(r);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 6);
    }
}
#[test]
fn split_create_all_file_and_parent_barriers_preserve_commit_history() {
    for file_sync in [false, true] {
        for fail in 1..=if file_sync { 5 } else { 2 } {
            let (dir, p) = plan(Durability::SyncFileAndDirectory);
            let mut calls = 0;
            let r = with_hook(
                move |event, _| {
                    if event == if file_sync { Event::FileSync } else { Event::DirectorySync } {
                        calls += 1;
                        if calls == fail {
                            return Err(io::Error::from_raw_os_error(libc::EIO));
                        }
                    }
                    Ok(())
                },
                || p.publish_split_with_receipts(options()),
            );
            assert!(r.outcome.is_err());
            assert_eq!(r.durability, DurabilityState::Unconfirmed);
            if file_sync {
                assert_eq!(r.barriers.prefix_parent, SplitBarrierState::NotAttempted);
                assert_eq!(r.barriers.final_parent, SplitBarrierState::NotAttempted);
                for (index, row) in r.volumes.iter().enumerate() {
                    if index + 1 < fail {
                        assert_eq!(row.data_sync, SplitBarrierState::Complete);
                    } else if index + 1 == fail {
                        assert!(matches!(row.data_sync, SplitBarrierState::Failed(_)));
                    } else {
                        assert_eq!(row.data_sync, SplitBarrierState::NotAttempted);
                    }
                }
            }
            if !file_sync && fail == 2 {
                assert_eq!(r.commit, SplitCommitState::Complete);
                assert_eq!(r.written.len(), 1);
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 6);
            } else {
                assert!(r.written.is_empty());
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "{r:?}");
            }
        }
    }
}
#[test]
fn split_create_reports_requested_barriers_before_attempts() {
    for durability in [Durability::VisibilityOnly, Durability::SyncFileAndDirectory] {
        let pending = if durability == Durability::SyncFileAndDirectory {
            SplitBarrierState::NotAttempted
        } else {
            SplitBarrierState::NotRequested
        };
        for failure in ["planning", "after_verify", "conflict"] {
            let (dir, p) = plan(durability);
            let mut opts = options();
            if failure == "planning" {
                opts.limits.volumes = 0;
            }
            if failure == "conflict" {
                std::fs::write(dir.path().join("out.z01"), b"foreign").unwrap();
            }
            let r = with_hook(
                move |event, _| {
                    if failure == "after_verify" && event == Event::AfterVerify {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                    Ok(())
                },
                || p.publish_split_with_receipts(opts),
            );
            assert!(r.outcome.is_err(), "{failure}");
            assert_eq!(r.barriers.prefix_parent, pending, "{failure}");
            assert_eq!(r.barriers.final_parent, pending, "{failure}");
            let data_sync = if failure == "conflict" && durability == Durability::SyncFileAndDirectory {
                SplitBarrierState::Complete
            } else {
                pending
            };
            assert!(r.volumes.iter().all(|v| v.data_sync == data_sync), "{failure}: {r:?}");
            let aftermath = if failure != "planning" && durability == Durability::SyncFileAndDirectory {
                SplitBarrierState::Complete
            } else {
                SplitBarrierState::NotRequested
            };
            assert_eq!(r.barriers.aftermath_parent, aftermath, "{failure}");
            assert_eq!(r.commit, SplitCommitState::NonePublished);
            assert!(r.written.is_empty());
            if failure == "conflict" {
                assert_eq!(std::fs::read(dir.path().join("out.z01")).unwrap(), b"foreign");
            }
            assert_eq!(std::fs::read(dir.path().join("input")).unwrap(), [b'A'; 2000]);
        }
    }
}
#[test]
fn split_create_final_parent_rebinding_remains_unresolved_with_evidence() {
    let (dir, p) = plan(Durability::SyncFileAndDirectory);
    let old = dir.path().to_path_buf();
    let moved = old.with_extension("moved-split");
    let restore = moved.clone();
    let original = old.clone();
    let mut calls = 0;
    let r = with_hook(
        move |event, _| {
            if event == Event::DirectorySync {
                calls += 1;
                if calls == 2 {
                    std::fs::rename(&old, &moved)?;
                    std::fs::create_dir(&old)?;
                }
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err(), "{r:?}");
    assert_eq!(r.commit, SplitCommitState::Complete);
    assert_eq!(r.visibility, SplitVisibility::Unresolved);
    assert!(r.reconciliation.is_some());
    drop(r);
    std::fs::remove_dir(&original).unwrap();
    std::fs::rename(restore, original).unwrap();
}

#[test]
fn split_create_before_publication_hook_precedes_any_visible_name() {
    let (dir, p) = plan(Durability::VisibilityOnly);
    let count = std::rc::Rc::new(Cell::new(0));
    let seen = count.clone();
    let root = dir.path().to_path_buf();
    let r = with_hook(
        move |event, _| {
            if event == Event::BeforeCommit {
                seen.set(seen.get() + 1);
                assert!(!root.join("out.z01").exists());
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert_eq!(count.get(), 1);
    assert!(r.outcome.is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
#[test]
fn split_create_final_source_change_cleans_a_confirmed_prefix() {
    let (dir, p) = plan(Durability::VisibilityOnly);
    let source = dir.path().join("input");
    let mut renamed = 0;
    let r = with_hook(
        move |event, _| {
            if event == Event::AfterCommit {
                renamed += 1;
                if renamed == 1 {
                    std::fs::write(&source, b"changed")?;
                }
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err());
    assert_eq!(r.commit, SplitCommitState::PrefixPublished);
    assert!(r.written.is_empty());
    assert_eq!(std::fs::read(dir.path().join("input")).unwrap(), b"changed");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn split_create_postrename_allocator_refusal_child() {
    let Ok(mode) = std::env::var("ZIPFAST_SPLIT_ALLOC_CHILD") else {
        for mode in ["success", "source", "unknown", "cleanup"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "zip::create::native::split_create_tests::split_create_postrename_allocator_refusal_child",
                    "--nocapture",
                ])
                .env("ZIPFAST_SPLIT_ALLOC_CHILD", mode)
                .status()
                .unwrap();
            assert!(status.success(), "allocator mode {mode}");
        }
        return;
    };
    use std::io::Write;
    let fd_count =
        || std::fs::read_dir(if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" }).unwrap().count();
    let baseline = fd_count();
    let dir = tempfile::tempdir().unwrap();
    let mut root = dir.path().to_path_buf();
    for _ in 0..6 {
        root.push("long-prepared-component-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
        std::fs::create_dir(&root).unwrap();
    }
    let input = root.join("source");
    std::fs::write(&input, [b'A'; 2000]).unwrap();
    let mut changed = std::fs::OpenOptions::new().write(true).open(&input).unwrap();
    let mut p = CreatePlan::new(
        &root.join("out.zip"),
        CreateOptions { durability: Durability::SyncFileAndDirectory, ..CreateOptions::default() },
    )
    .unwrap();
    p.add_file(&input, metadata("payload"), None).unwrap();
    let m = mode.clone();
    let mut renames = 0;
    let mut changed_once = false;
    let r = with_hook(
        move |event, _| {
            if event == Event::BeforeCommit {
                split_verify_tests::set_allocations_refused(true);
            }
            if event == Event::NativePublish {
                renames += 1;
                if m == "unknown" && renames == 2 {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                if m == "cleanup" && renames == 2 {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
            }
            if event == Event::AfterCommit && m == "source" && !changed_once {
                changed.write_all(b"changed")?;
                changed.set_len(7)?;
                changed_once = true;
            }
            if event == Event::Unlink && m == "cleanup" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    split_verify_tests::set_allocations_refused(false);
    assert_eq!(fd_count(), baseline + r.summary.reconciliation_handles as usize);
    match mode.as_str() {
        "success" => {
            assert!(r.outcome.is_ok(), "{r:?}");
            assert_eq!(r.commit, SplitCommitState::Complete);
        }
        "source" => {
            assert!(r.outcome.is_err());
            assert_eq!(r.commit, SplitCommitState::PrefixPublished);
            assert!(r.reconciliation.is_none());
        }
        "unknown" => {
            assert_eq!(r.commit, SplitCommitState::Unknown);
            assert!(r.reconciliation.is_some());
        }
        "cleanup" => {
            assert_eq!(r.commit, SplitCommitState::PrefixPublished);
            assert!(r.reconciliation.is_some());
        }
        _ => unreachable!(),
    }
    drop(r);
    assert_eq!(fd_count(), baseline);
}

#[test]
fn split_create_failed_clone_keeps_original_ownership_and_cleans_it() {
    for event in [Event::SplitStageClone, Event::SplitStageStat] {
        let (dir, p) = plan(Durability::VisibilityOnly);
        let r = with_hook(
            move |seen, _| {
                if seen == event { Err(io::Error::from_raw_os_error(libc::EMFILE)) } else { Ok(()) }
            },
            || p.publish_split_with_receipts(options()),
        );
        assert!(r.outcome.is_err());
        assert!(r.writer_failure.is_some());
        assert!(matches!(r.outcome, Err(SplitCreateFailure { stage: SplitCreateStage::StageCreate, .. })));
        assert_eq!(r.summary.stage_files_created, 1);
        assert_eq!(r.summary.transport.disks, 0);
        assert!(!r.volumes[0].writer_opened);
        assert!(matches!(r.volumes[0].cleanup, SplitVolumeCleanup::Removed));
        assert!(r.reconciliation.is_none());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
#[test]
fn split_create_foreign_stage_substitution_retains_owned_evidence() {
    let (dir, p) = plan(Durability::VisibilityOnly);
    let moved = dir.path().join("owned-moved");
    let mut did = false;
    let r = with_hook(
        move |event, path| {
            if event == Event::BeforeCommit && !did {
                let path = path.unwrap();
                std::fs::rename(path, &moved)?;
                std::fs::write(path, b"foreign")?;
                did = true;
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err());
    assert_eq!(r.commit, SplitCommitState::NonePublished);
    assert!(r.reconciliation.is_some());
    assert!(matches!(r.volumes[0].cleanup, SplitVolumeCleanup::ForeignPreserved));
    assert_eq!(std::fs::read(r.volumes[0].stage_path.as_ref().unwrap()).unwrap(), b"foreign");
    assert_eq!(std::fs::read(dir.path().join("owned-moved")).unwrap().len(), 512);
}

#[test]
fn split_create_definite_and_ambiguous_stage_open_failures_keep_honest_evidence() {
    for ambiguous in [false, true] {
        let (dir, p) = plan(Durability::VisibilityOnly);
        let mut opens = 0;
        let r = with_hook(
            move |event, _| {
                if event == Event::StageOpen {
                    opens += 1;
                    if opens == 2 {
                        return Err(io::Error::from_raw_os_error(if ambiguous { libc::EIO } else { libc::EACCES }));
                    }
                }
                Ok(())
            },
            || p.publish_split_with_receipts(options()),
        );
        assert!(r.outcome.is_err());
        assert_eq!(r.summary.stage_files_created, 1);
        assert_eq!(r.summary.stage_open_attempts, 2);
        assert_eq!(r.volumes.len(), 2);
        assert!(!r.volumes[1].stage_created);
        if ambiguous {
            assert!(r.reconciliation.is_some());
            assert_eq!(r.summary.reconciliation_handles, 2);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
        } else {
            assert!(r.reconciliation.is_none());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
#[test]
fn split_create_source_budget_error_remains_typed_and_keeps_writer_context() {
    let (dir, p) = plan(Durability::VisibilityOnly);
    // Cancel from the actual source read boundary, after writer construction.
    let cancel = p.options.cancel.clone();
    let r = with_hook(
        move |event, _| {
            if event == Event::ReadSource {
                cancel.cancel();
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(
        matches!(r.outcome, Err(SplitCreateFailure { cause: SplitCreateError::Create(CreateError::Canceled), .. })),
        "{r:?}"
    );
    assert!(r.writer_failure.is_some());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn split_create_every_cleanup_failure_retains_evidence_and_remaining_names() {
    for fail in 1..=5 {
        let (dir, p) = plan(Durability::VisibilityOnly);
        let mut renames = 0;
        let mut unlinks = 0;
        let r = with_hook(
            move |event, _| {
                if event == Event::NativePublish {
                    renames += 1;
                    if renames == 2 {
                        return Err(io::Error::from_raw_os_error(libc::EACCES));
                    }
                }
                if event == Event::Unlink {
                    unlinks += 1;
                    if unlinks == fail {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || p.publish_split_with_receipts(options()),
        );
        assert!(r.outcome.is_err());
        assert_eq!(r.commit, SplitCommitState::PrefixPublished);
        assert!(r.written.is_empty());
        assert!(r.reconciliation.is_some());
        assert!(matches!(r.volumes[fail - 1].cleanup, SplitVolumeCleanup::Unresolved(_)));
        let before = std::fs::read_dir(dir.path()).unwrap().count();
        drop(r);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
    }
}
#[test]
fn split_create_exact_preparation_and_scratch_and_handle_limits() {
    let (_dir, p) = plan(Durability::VisibilityOnly);
    let baseline = p.publish_split_with_receipts(options());
    assert!(baseline.outcome.is_ok());
    for kind in 0..4 {
        for under in [false, true] {
            let (dir, mut p) = plan(Durability::VisibilityOnly);
            let mut o = options();
            match kind {
                0 => o.limits.native_capacity = baseline.summary.preparation_capacity - u64::from(under),
                1 => o.limits.verification_scratch = baseline.summary.verification.scratch_capacity - u64::from(under),
                2 => p.options.limits.plan_capacity = baseline.summary.plan.capacity - u64::from(under),
                _ => o.limits.open_handles = baseline.summary.open_handles_peak - u64::from(under),
            }
            let r = p.publish_split_with_receipts(o);
            assert_eq!(r.outcome.is_err(), under, "kind {kind}, under {under}: {r:?}");
            if under {
                assert!(r.written.is_empty());
                assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
            }
        }
    }
}
#[test]
fn split_create_allocator_refusal_before_staging_is_typed() {
    let (dir, p) = plan(Durability::VisibilityOnly);
    split_verify_tests::set_allocations_refused(true);
    let r = p.publish_split_with_receipts(options());
    split_verify_tests::set_allocations_refused(false);
    assert!(matches!(r.outcome, Err(SplitCreateFailure { cause: SplitCreateError::Allocation(_), .. })));
    assert!(r.volumes.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
#[test]
fn split_create_long_actual_numbered_leaf_refuses_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("input");
    std::fs::write(&source, vec![b'A'; 52_000]).unwrap();
    let name = "x".repeat(251) + ".zip";
    let mut p = CreatePlan::new(&dir.path().join(name), CreateOptions::default()).unwrap();
    p.add_file(&source, metadata("payload"), None).unwrap();
    let r = p.publish_split_with_receipts(options());
    assert!(matches!(r.outcome, Err(SplitCreateFailure { cause: SplitCreateError::NameTooLong { disk: 99, .. }, .. })));
    assert_eq!(r.commit, SplitCommitState::NonePublished);
    assert!(r.written.is_empty());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn split_create_same_size_stage_change_before_permissions_is_rejected() {
    use std::io::{Seek, Write};
    let (dir, p) = plan(Durability::VisibilityOnly);
    let r = with_hook(
        move |event, path| {
            if event == Event::AfterVerify {
                let mut f = std::fs::OpenOptions::new().read(true).write(true).open(path.unwrap())?;
                let old = f.metadata()?.modified()?;
                f.seek(std::io::SeekFrom::Start(50))?;
                f.write_all(b"different")?;
                f.set_modified(old)?;
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err());
    assert_eq!(r.commit, SplitCommitState::NonePublished);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn split_create_new_scratch_limit_is_independent_from_ordinary_parser_scratch() {
    for under in [false, true] {
        let (dir, mut p) = plan(Durability::VisibilityOnly);
        p.options.limits.verification_scratch = 0;
        let mut o = options();
        o.limits.verification_scratch = 131_170 - u64::from(under);
        let r = p.publish_split_with_receipts(o);
        assert_eq!(r.outcome.is_ok(), !under, "{r:?}");
        if under {
            assert_eq!(r.summary.stage_files_created, 0);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}

#[test]
fn split_create_ambiguous_completed_syscall_never_upgrades_or_rolls_back() {
    for fail in [2, 5] {
        let (dir, p) = plan(Durability::VisibilityOnly);
        let mut stages = Vec::new();
        let root = dir.path().to_path_buf();
        let mut calls = 0;
        let r = with_hook(
            move |event, path| {
                if event == Event::SplitStageClone {
                    stages.push(path.unwrap().to_path_buf());
                }
                if event == Event::NativePublish {
                    calls += 1;
                    if calls == fail {
                        let target =
                            if calls == 5 { root.join("out.zip") } else { root.join(format!("out.z{calls:02}")) };
                        std::fs::rename(&stages[calls - 1], target)?;
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || p.publish_split_with_receipts(options()),
        );
        assert_eq!(r.commit, SplitCommitState::Unknown);
        assert!(r.written.is_empty());
        assert!(r.reconciliation.is_some());
        assert_eq!(r.visibility, if fail == 5 { SplitVisibility::AllMatch } else { SplitVisibility::PartialMatch });
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 6);
        drop(r);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 6);
    }
}

#[test]
fn split_create_terminal_held_snapshot_includes_guarded_cleanup_mutation() {
    use std::os::unix::fs::MetadataExt;
    let (_dir, p) = plan(Durability::VisibilityOnly);
    let held = std::rc::Rc::new(RefCell::new(None));
    let observed = held.clone();
    let mut calls = 0;
    let r = with_hook(
        move |event, path| {
            if event == Event::BeforeCommit {
                *observed.borrow_mut() = Some(File::open(path.unwrap())?);
            }
            if event == Event::NativePublish {
                calls += 1;
                if calls == 2 {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    let metadata = held.borrow().as_ref().unwrap().metadata().unwrap();
    let snapshot = r.volumes[0].terminal_held.unwrap();
    assert_eq!(snapshot.changed, (metadata.ctime(), metadata.ctime_nsec()));
    assert_eq!(r.volumes[0].cleanup, SplitVolumeCleanup::Removed);
}

#[test]
fn split_create_known_source_and_decoded_limits_refuse_before_staging() {
    for which in 0..4 {
        let (dir, mut p) = plan(Durability::VisibilityOnly);
        match which {
            0 => p.options.limits.verification_entry_bytes = 1999,
            1 => p.options.limits.verification_decoded_bytes = 1999,
            2 => p.options.limits.writer.entry_decoded_bytes = 1999,
            _ => p.options.limits.writer.source_bytes = 1999,
        }
        let r = p.publish_split_with_receipts(options());
        assert!(r.outcome.is_err());
        assert_eq!(r.summary.stage_files_created, 0, "limit {which}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn split_create_missing_owned_name_preserves_reconciliation() {
    let (dir, p) = plan(Durability::VisibilityOnly);
    let moved = dir.path().join("moved-owned");
    let r = with_hook(
        move |event, path| {
            if event == Event::BeforeCommit {
                std::fs::rename(path.unwrap(), &moved)?;
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err());
    assert!(r.reconciliation.is_some());
    assert!(dir.path().join("moved-owned").exists());
}
#[test]
fn split_create_all_verified_rows_survive_first_permission_failure() {
    let (_dir, p) = plan(Durability::VisibilityOnly);
    let r = with_hook(
        |event, _| {
            if event == Event::Chmod { Err(io::Error::from_raw_os_error(libc::EACCES)) } else { Ok(()) }
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err());
    assert_eq!(r.volumes.len(), 5);
    assert!(r.volumes.iter().all(|r| r.verified.is_some()));
}
#[test]
fn split_create_reconciliation_recognizes_held_file_after_initial_stat_failure() {
    let (_dir, p) = plan(Durability::VisibilityOnly);
    let r = with_hook(
        |event, _| {
            if matches!(event, Event::SplitStageStat | Event::Unlink) {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        },
        || p.publish_split_with_receipts(options()),
    );
    let evidence = r.reconciliation.as_ref().unwrap();
    let metadata = std::fs::metadata(r.volumes[0].stage_path.as_ref().unwrap()).unwrap();
    assert!(evidence.matches_volume(0, &metadata));
    assert!(r.volumes[0].verified.is_none());
}

#[test]
fn split_create_finalization_reserve_bounds_interrupted_barrier_and_retains_set() {
    let (_dir, p) = plan(Durability::SyncFileAndDirectory);
    let calls = std::rc::Rc::new(Cell::new(0u64));
    let observed = calls.clone();
    let mut o = options();
    o.limits.volumes = 5;
    let r = with_hook(
        move |event, _| {
            if event == Event::DirectorySync {
                observed.set(observed.get() + 1);
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        },
        || p.publish_split_with_receipts(o),
    );
    assert!(r.outcome.is_err());
    assert_eq!(r.commit, SplitCommitState::PrefixPublished);
    assert_eq!(r.summary.finalization_reserve, 386);
    assert!(matches!(
        r.outcome,
        Err(SplitCreateFailure { cause: SplitCreateError::Limit(SplitCreateLimit::FinalizationAttempts), .. })
    ));
    assert_eq!(r.summary.finalization_attempts, 386);
    assert_eq!(calls.get(), 386);
    assert!(r.reconciliation.is_some());
    assert_eq!(r.summary.reconciliation_handles, 6);
    assert_eq!(r.visibility, SplitVisibility::Unresolved);
}
#[test]
fn split_create_cancellation_does_not_cancel_guarded_cleanup() {
    let (dir, p) = plan(Durability::SyncFileAndDirectory);
    let cancel = p.options.cancel.clone();
    let r = with_hook(
        move |event, _| {
            if event == Event::BeforeCommit {
                cancel.cancel();
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(matches!(
        r.outcome,
        Err(SplitCreateFailure { cause: SplitCreateError::Create(CreateError::Canceled), .. })
    ));
    assert_eq!(r.commit, SplitCommitState::NonePublished);
    assert!(r.reconciliation.is_none());
    assert_eq!(r.barriers.aftermath_parent, SplitBarrierState::Complete);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn split_create_postfinal_probe_failure_still_performs_reserved_parent_barrier() {
    let (_dir, p) = plan(Durability::SyncFileAndDirectory);
    let mut commits = 0;
    let r = with_hook(
        move |event, _| {
            if event == Event::AfterCommit {
                commits += 1;
                if commits == 5 {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
            }
            Ok(())
        },
        || p.publish_split_with_receipts(options()),
    );
    assert!(r.outcome.is_err());
    assert_eq!(r.commit, SplitCommitState::Complete);
    assert_eq!(r.written.len(), 1);
    assert_eq!(r.barriers.prefix_parent, SplitBarrierState::Complete);
    assert_eq!(r.barriers.final_parent, SplitBarrierState::Complete);
}
