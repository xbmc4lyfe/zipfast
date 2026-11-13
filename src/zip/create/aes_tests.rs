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
use crate::zip::write::{AesStrength, AesVariant, WinZipAesRequest};
use std::rc::Rc;

fn request() -> WinZipAesRequest<'static> {
    WinZipAesRequest::new("native-aes-fixture", AesStrength::Aes128, AesVariant::Ae2).unwrap()
}

fn tiny(options: CreateOptions) -> (tempfile::TempDir, PathBuf, PathBuf, CreatePlan) {
    let dir = test_dir();
    let source = dir.path().join("source");
    let output = dir.path().join("out.zip");
    std::fs::write(&source, b"abc").unwrap();
    let mut plan = CreatePlan::new(&output, options).unwrap();
    plan.add_file(&source, metadata("a"), None).unwrap();
    (dir, source, output, plan)
}

#[test]
fn aes_entropy_failure_stops_before_publication_with_truthful_usage() {
    for fail in [1, 2] {
        let (dir, source, output, mut plan) = tiny(CreateOptions::default());
        plan.add_file(&source, metadata("b"), None).unwrap();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let report = with_hook(
            move |event, _| {
                if let Event::AesEntropy { bytes } = event {
                    assert_eq!(bytes, 8);
                    seen.set(seen.get() + 1);
                    if seen.get() == fail {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(calls.get(), fail);
        assert_eq!((failure.stage, failure.publication), (CreateStage::Write, Publication::NotPublished));
        assert!(matches!(
            failure.cause,
            CreateError::Writer(WriteError::Io { stage: crate::zip::write::IoStage::EncryptionEntropy, .. })
        ));
        assert_eq!(failure.summary.writer.entries, fail - 1);
        assert_eq!(failure.summary.writer.output_bytes, (fail - 1) * 81);
        assert_eq!(failure.summary.writer.io_attempts, (fail - 1) * 10 + 1);
        assert!(report.written.is_empty());
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
        assert_eq!(std::fs::read(source).unwrap(), b"abc");
    }
}

#[test]
fn aes_crc_reservation_failure_is_typed_and_precedes_staging() {
    let (dir, _, output, plan) = tiny(CreateOptions::default());
    let admitted = plan.usage().plan.capacity;
    let report = with_hook(
        |event, _| {
            assert!(!matches!(event, Event::StageOpen | Event::AesEntropy { .. }));
            if event == Event::AesCrcReserve { Err(io::ErrorKind::OutOfMemory.into()) } else { Ok(()) }
        },
        || plan.publish_winzip_aes_with_receipts(request()),
    );
    let failure = report.outcome.unwrap_err();
    assert_eq!(
        (failure.stage, failure.publication, failure.summary.stage_attempts),
        (CreateStage::Planning, Publication::NotPublished, 0)
    );
    assert!(matches!(failure.cause, CreateError::Allocation(_)));
    assert_eq!(failure.summary.plan.capacity, admitted + size_of::<EntryWritten>() as u64 + size_of::<usize>() as u64);
    assert!(report.written.is_empty());
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn aes_directory_only_has_no_private_crc_reserve_or_entropy() {
    let dir = test_dir();
    let output = dir.path().join("out.zip");
    let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
    plan.add_directory(metadata("dir/"), None).unwrap();
    let report = with_hook(
        |event, _| {
            assert!(!matches!(event, Event::AesCrcReserve | Event::AesEntropy { .. }));
            Ok(())
        },
        || plan.publish_winzip_aes_with_receipts(request()),
    );
    report.outcome.unwrap();
    assert_eq!(report.written.len(), 1);
}

#[test]
fn aes_valid_tag_with_wrong_stored_private_crc_never_publishes() {
    let (dir, source, output, plan) = tiny(CreateOptions::default());
    let report = with_hook(
        |event, _| {
            if event == Event::BeforeVerify {
                AES_PRIVATE_CRC_XOR.set(1);
            }
            Ok(())
        },
        || plan.publish_winzip_aes_with_receipts(request()),
    );
    let failure = report.outcome.unwrap_err();
    assert_eq!((failure.stage, failure.publication), (CreateStage::Verify, Publication::NotPublished));
    assert!(matches!(failure.cause, CreateError::Verification("decoded length or CRC differs")));
    assert!(report.written.is_empty());
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());
    assert_eq!(std::fs::read(source).unwrap(), b"abc");
}

#[test]
fn aes_private_capacity_is_additive_and_ordinary_routes_pay_no_new_charge() {
    let (_dir, _, _, plan) = tiny(CreateOptions::default());
    let clear = plan.publish().unwrap().summary.plan.capacity;
    let (_dir, _, _, plan) = tiny(CreateOptions::default());
    let legacy = plan.publish_zipcrypto_with_receipts("native-aes-fixture").outcome.unwrap().summary.plan.capacity;
    let (_dir, _, _, plan) = tiny(CreateOptions::default());
    let aes = plan.publish_winzip_aes_with_receipts(request()).outcome.unwrap().summary.plan.capacity;
    assert_eq!(legacy, clear);
    assert_eq!(aes, clear + size_of::<u32>() as u64);
    for less in [0, 1] {
        let mut options = CreateOptions::default();
        options.limits.plan_capacity = aes - less;
        let (dir, _, output, plan) = tiny(options);
        let report = with_hook(
            move |event, _| {
                if less == 1 {
                    assert!(!matches!(event, Event::StageOpen | Event::AesEntropy { .. }));
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        if less == 0 {
            assert_eq!(report.outcome.unwrap().summary.plan.capacity, aes);
        } else {
            let failure = report.outcome.unwrap_err();
            assert!(matches!(failure.cause, CreateError::Limit(CreateLimit::PlanCapacity)));
            assert_eq!(failure.summary.stage_attempts, 0);
            assert!(report.written.is_empty());
            assert!(!output.exists());
            assert!(stages(dir.path()).is_empty());
        }
    }
}

#[test]
fn aes_geometry_and_exact_budgets_include_extras_tag_descriptor_and_entropy() {
    use crate::zip::write::Limit;
    for (strength, overhead) in [(AesStrength::Aes128, 20), (AesStrength::Aes192, 24), (AesStrength::Aes256, 28)] {
        for size in [u32::MAX as u64 - overhead - 1, u32::MAX as u64 - overhead] {
            let geometry =
                crate::zip::write::exact_winzip_aes_geometry(metadata("a"), size, 0, strength, AesVariant::Ae2)
                    .unwrap();
            assert_eq!(geometry.2, size + overhead >= u32::MAX as u64);
        }
        let (local, _, wide, _) =
            crate::zip::write::exact_winzip_aes_geometry(metadata("a"), 3, u32::MAX as u64, strength, AesVariant::Ae2)
                .unwrap();
        assert!(wide);
        assert_eq!(local, 42 + 3 + overhead + 16);
        let (local, _, wide, _) =
            crate::zip::write::exact_winzip_aes_geometry(metadata("a"), 0, 0, strength, AesVariant::Ae2).unwrap();
        assert!(!wide);
        assert_eq!(local, 42 + overhead + 16);
    }
    for (which, maximum) in [("extent", 161), ("output", 161), ("writer-attempts", 13), ("read", 575), ("metadata", 12)]
    {
        for less in [0, 1] {
            let mut options = CreateOptions::default();
            let bound = maximum - less;
            match which {
                "extent" => options.limits.writer.archive_extent = bound,
                "output" => options.limits.writer.output_bytes = bound,
                "writer-attempts" => options.limits.writer.io_attempts = bound,
                "read" => options.limits.verification_read_bytes = bound,
                "metadata" => options.limits.verification_metadata = bound,
                _ => unreachable!(),
            }
            let (dir, _, output, plan) = tiny(options);
            let report = with_hook(
                move |event, _| {
                    if less == 1 {
                        assert!(!matches!(event, Event::StageOpen | Event::AesEntropy { .. }));
                    }
                    Ok(())
                },
                || plan.publish_winzip_aes_with_receipts(request()),
            );
            if less == 0 {
                let summary = report.outcome.unwrap().summary;
                assert_eq!(
                    (
                        summary.writer.output_bytes,
                        summary.writer.io_attempts,
                        summary.verification.read_bytes,
                        summary.verification.metadata_bytes
                    ),
                    (161, 13, 575, 12)
                );
            } else {
                let failure = report.outcome.unwrap_err();
                assert_eq!(failure.stage, CreateStage::Planning);
                assert_eq!(failure.summary.stage_attempts, 0);
                assert!(matches!(
                    (which, failure.cause),
                    ("extent", CreateError::Writer(WriteError::Limit(Limit::ArchiveExtent)))
                        | ("output", CreateError::Writer(WriteError::Limit(Limit::OutputBytes)))
                        | ("writer-attempts", CreateError::Writer(WriteError::Limit(Limit::IoAttempts)))
                        | ("read", CreateError::Limit(CreateLimit::VerificationReadBytes))
                        | ("metadata", CreateError::Limit(CreateLimit::VerificationMetadata))
                ));
                assert!(report.written.is_empty());
                assert!(!output.exists());
                assert!(stages(dir.path()).is_empty());
            }
        }
    }
}

#[test]
fn aes_ciphertext_tag_and_metadata_corruption_never_publish() {
    use std::os::unix::fs::FileExt;
    for at in [35, 37, 39, 40, 42, 50, 52, 55, 64, 65, 69] {
        let (dir, source, output, plan) = tiny(CreateOptions::default());
        let report = with_hook(
            move |event, path| {
                if event == Event::BeforeVerify {
                    let file = std::fs::OpenOptions::new().read(true).write(true).open(path.unwrap())?;
                    let mut byte = [0];
                    file.read_exact_at(&mut byte, at)?;
                    byte[0] ^= 1;
                    file.write_all_at(&byte, at)?;
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!((failure.stage, failure.publication), (CreateStage::Verify, Publication::NotPublished));
        assert!(report.written.is_empty());
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
        assert_eq!(std::fs::read(source).unwrap(), b"abc");
    }
}

#[test]
fn aes_source_and_held_stage_name_substitution_preserve_foreign_objects() {
    for selected in [Event::AfterSourceRead, Event::BeforeFinalSourceCheck, Event::BeforeVerify, Event::AfterVerify] {
        let (dir, source, output, plan) = tiny(CreateOptions::default());
        let original = dir.path().join("original");
        let original_copy = original.clone();
        let source_copy = source.clone();
        let report = with_hook(
            move |event, path| {
                if event == selected {
                    if matches!(event, Event::AfterSourceRead | Event::BeforeFinalSourceCheck) {
                        std::fs::rename(&source_copy, &original_copy)?;
                        std::fs::write(&source_copy, b"foreign")?;
                    } else if event == Event::BeforeVerify {
                        std::fs::rename(path.unwrap(), &original_copy)?;
                        std::fs::write(path.unwrap(), b"foreign stage")?;
                    } else {
                        std::fs::write(path.unwrap(), b"damaged held stage")?;
                    }
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(failure.publication, Publication::NotPublished);
        assert!(report.written.is_empty());
        assert!(!output.exists());
        if selected == Event::BeforeVerify {
            assert!(matches!(failure.cause, CreateError::StageChanged));
            let CleanupState::ForeignStageName { path } = failure.cleanup else { panic!("{failure:?}") };
            assert_eq!(std::fs::read(path).unwrap(), b"foreign stage");
            assert!(crate::zip::Archive::open(&original).is_ok());
        } else if selected == Event::AfterVerify {
            assert!(matches!(failure.cause, CreateError::StageChanged));
            assert!(stages(dir.path()).is_empty());
        } else {
            assert!(matches!(failure.cause, CreateError::SourceChanged(_)));
            assert_eq!(std::fs::read(&original).unwrap(), b"abc");
            assert_eq!(std::fs::read(source).unwrap(), b"foreign");
            assert!(stages(dir.path()).is_empty());
        }
    }
}

#[test]
fn aes_publish_collision_and_uncertainty_expose_no_success_receipts() {
    for uncertain in [false, true] {
        let (dir, source, output, plan) = tiny(CreateOptions::default());
        let destination = output.clone();
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let report = with_hook(
            move |event, _| {
                if !uncertain && event == Event::BeforeCommit {
                    std::fs::write(&destination, b"foreign")?;
                }
                if event == Event::NativePublish {
                    seen.set(seen.get() + 1);
                    if uncertain {
                        return Err(io::Error::from_raw_os_error(libc::EINTR));
                    }
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(calls.get(), 1);
        assert_eq!(failure.stage, CreateStage::Publish);
        assert!(report.written.is_empty());
        if uncertain {
            assert_eq!(failure.publication, Publication::Unknown);
            let CleanupState::RetainedOwnedStage { path } = failure.cleanup else { panic!("{failure:?}") };
            assert!(crate::zip::Archive::open(&path).is_ok());
            assert_eq!(stages(dir.path()), [path]);
            assert!(!output.exists());
        } else {
            assert_eq!(failure.publication, Publication::NotPublished);
            assert_eq!(std::fs::read(output).unwrap(), b"foreign");
            assert!(stages(dir.path()).is_empty());
        }
        assert_eq!(std::fs::read(source).unwrap(), b"abc");
    }
}

#[test]
fn aes_postpublication_failures_retain_wire_receipts_and_require_stable_binding() {
    for selected in [Event::DirectorySync, Event::BeforeCleanup, Event::PublicationStamp] {
        let options = CreateOptions { durability: Durability::SyncFileAndDirectory, ..Default::default() };
        let (_dir, source, output, plan) = tiny(options);
        let (report, binding) = with_hook(
            move |event, _| if event == selected { Err(io::Error::from_raw_os_error(libc::EIO)) } else { Ok(()) },
            || plan.publish_winzip_aes_with_bound_receipts(request()),
        );
        assert!(binding.is_none());
        assert_eq!(report.written.len(), 1);
        assert_eq!(report.written[0].crc32, 0);
        if selected == Event::PublicationStamp {
            assert_eq!(report.outcome.unwrap().publication, Publication::Published);
        } else {
            assert_eq!(report.outcome.unwrap_err().publication, Publication::Published);
        }
        assert!(crate::zip::Archive::open(&output).is_ok());
        assert_eq!(std::fs::read(source).unwrap(), b"abc");
    }
    let options = CreateOptions { durability: Durability::SyncFileAndDirectory, ..Default::default() };
    let (dir, source, output, plan) = tiny(options);
    let destination = output.clone();
    let displaced = dir.path().join("published");
    let original = displaced.clone();
    let (report, binding) = with_hook(
        move |event, _| {
            if event == Event::DirectorySync {
                std::fs::rename(&destination, &displaced)?;
                std::fs::write(&destination, b"foreign")?;
            }
            Ok(())
        },
        || plan.publish_winzip_aes_with_bound_receipts(request()),
    );
    report.outcome.unwrap();
    assert!(binding.is_none());
    assert_eq!(report.written.len(), 1);
    assert_eq!(std::fs::read(output).unwrap(), b"foreign");
    assert!(crate::zip::Archive::open(&original).is_ok());
    assert_eq!(std::fs::read(source).unwrap(), b"abc");
}

#[test]
fn aes_tracked_output_parent_and_shared_source_cursor_keep_common_binding_rules() {
    use std::io::{Seek, SeekFrom};
    for changed in [false, true] {
        let dir = test_dir();
        let source = dir.path().join("source");
        let output = dir.path().join("out.zip");
        std::fs::write(&source, b"abc").unwrap();
        let mut plan = CreatePlan::new(&output, CreateOptions::default()).unwrap();
        plan.add_directory_from_path(dir.path(), metadata("root/"), None).unwrap();
        let file = std::fs::File::open(&source).unwrap();
        let mut cloned = file.try_clone().unwrap();
        plan.add_open_file(&source, file, metadata("root/a"), None).unwrap();
        let foreign = dir.path().join("foreign");
        let (report, binding) = with_hook(
            move |event, _| {
                if event == Event::BeforeSourceRead {
                    cloned.seek(SeekFrom::Start(99))?;
                }
                if changed && event == Event::BeforeFinalSourceCheck {
                    std::fs::write(&foreign, b"changed directory")?;
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_bound_receipts(request()),
        );
        if changed {
            let failure = report.outcome.unwrap_err();
            assert_eq!(failure.publication, Publication::NotPublished);
            assert!(matches!(failure.cause, CreateError::SourceChanged(CreateEntryId(0))));
            assert!(binding.is_none());
            assert!(report.written.is_empty());
            assert!(!output.exists());
        } else {
            report.outcome.unwrap();
            assert_eq!(report.written.iter().map(|r| r.ordinal).collect::<Vec<_>>(), [0, 1]);
            assert!(binding.unwrap().matches(&std::fs::symlink_metadata(&output).unwrap()));
        }
        assert_eq!(std::fs::read(source).unwrap(), b"abc");
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn aes_cursor_source_sink_and_flush_interruptions_have_one_charge_per_attempt() {
    let (_dir, _, _, plan) = tiny(CreateOptions::default());
    let baseline = plan.publish_winzip_aes_with_receipts(request()).outcome.unwrap().summary;
    for selected in 0..4 {
        let (dir, _, output, plan) = tiny(CreateOptions::default());
        let mut interrupted = false;
        let report = with_hook(
            move |event, _| {
                let matched = match selected {
                    0 => event == Event::SinkSeek,
                    1 => matches!(event, Event::SinkWrite { .. }),
                    2 => event == Event::ReadSource,
                    _ => event == Event::SinkFlush,
                };
                if matched && !std::mem::replace(&mut interrupted, true) {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let summary = report.outcome.unwrap().summary;
        assert_eq!(summary.transaction_attempts, baseline.transaction_attempts + 1);
        let mut expected = baseline.writer;
        expected.io_attempts += u64::from(selected != 0);
        assert_eq!(summary.writer, expected);
        assert_eq!(summary.verification, baseline.verification);
        assert!(output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn aes_native_attempt_exhaustion_prevents_the_second_entropy_callback() {
    let (_dir, source, _, mut plan) = tiny(CreateOptions::default());
    plan.add_file(&source, metadata("b"), None).unwrap();
    let admission = plan.usage().transaction_attempts;
    let mut options = CreateOptions::default();
    options.limits.transaction_attempts = admission + 46;
    let (dir, source, output, mut plan) = tiny(options);
    plan.add_file(&source, metadata("b"), None).unwrap();
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let report = with_hook(
        move |event, _| {
            match event {
                Event::SinkWrite { at: 0, .. } => SINK_WRITE_CAP.set(1),
                Event::SinkWrite { at: 18, .. } => SINK_WRITE_CAP.set(usize::MAX),
                Event::AesEntropy { .. } => seen.set(seen.get() + 1),
                _ => {}
            }
            Ok(())
        },
        || plan.publish_winzip_aes_with_receipts(request()),
    );
    let failure = report.outcome.unwrap_err();
    assert!(matches!(failure.cause, CreateError::Limit(CreateLimit::TransactionAttempts)));
    assert_eq!(failure.summary.transaction_attempts, admission + 46);
    assert_eq!(
        (
            failure.summary.writer.entries,
            failure.summary.writer.output_bytes,
            failure.summary.writer.io_attempts,
            calls.get()
        ),
        (1, 81, 29, 1)
    );
    assert!(report.written.is_empty());
    assert!(!output.exists());
    assert!(stages(dir.path()).is_empty());
}

#[test]
fn aes_entropy_interruption_is_single_shot_and_cancellation_remains_typed() {
    for canceled in [false, true] {
        let options = CreateOptions::default();
        let cancel = options.cancel.clone();
        let (dir, _, output, plan) = tiny(options);
        let calls = Rc::new(Cell::new(0));
        let seen = calls.clone();
        let report = with_hook(
            move |event, _| {
                if matches!(event, Event::AesEntropy { .. }) {
                    seen.set(seen.get() + 1);
                    if canceled {
                        cancel.cancel();
                    } else {
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(calls.get(), 1);
        assert_eq!(failure.publication, Publication::NotPublished);
        if canceled {
            assert!(matches!(failure.cause, CreateError::Canceled));
        } else {
            assert!(matches!(
                failure.cause,
                CreateError::Writer(WriteError::Io { stage: crate::zip::write::IoStage::EncryptionEntropy, .. })
            ));
        }
        assert_eq!(
            (failure.summary.writer.entries, failure.summary.writer.output_bytes, failure.summary.writer.io_attempts),
            (0, 0, 1)
        );
        assert!(report.written.is_empty());
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn aes_partial_tag_and_flush_failures_keep_actual_provisional_usage() {
    for flush in [false, true] {
        let (dir, _, output, plan) = tiny(CreateOptions::default());
        let report = with_hook(
            move |event, _| {
                if flush && event == Event::SinkFlush {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                if !flush {
                    match event {
                        Event::SinkWrite { at: 55, .. } => SINK_WRITE_CAP.set(5),
                        Event::SinkWrite { at: 60, .. } => return Err(io::Error::from_raw_os_error(libc::EIO)),
                        _ => {}
                    }
                }
                Ok(())
            },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(failure.publication, Publication::NotPublished);
        assert_eq!(failure.summary.writer.output_bytes, if flush { 161 } else { 60 });
        assert_eq!(failure.summary.writer.archive_extent, failure.summary.writer.output_bytes);
        assert_eq!(failure.summary.writer.entries, u64::from(flush));
        assert_eq!(failure.stage, if flush { CreateStage::Finish } else { CreateStage::Write });
        assert!(report.written.is_empty());
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
    }
}

#[test]
fn aes_possible_commit_on_native_error_preserves_output_but_no_success_receipts() {
    let (dir, source, output, plan) = tiny(CreateOptions::default());
    let destination = output.clone();
    let mut held = None;
    let calls = Rc::new(Cell::new(0));
    let seen = calls.clone();
    let (report, binding) = with_hook(
        move |event, path| {
            if event == Event::BeforeCommit {
                held = Some(path.unwrap().to_path_buf());
            }
            if event == Event::NativePublish {
                seen.set(seen.get() + 1);
                std::fs::rename(held.take().unwrap(), &destination)?;
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        },
        || plan.publish_winzip_aes_with_bound_receipts(request()),
    );
    let failure = report.outcome.unwrap_err();
    assert_eq!((failure.publication, calls.get()), (Publication::Unknown, 1));
    assert!(binding.is_none());
    assert!(report.written.is_empty());
    assert!(output.exists());
    assert!(stages(dir.path()).is_empty());
    assert_eq!(std::fs::read(source).unwrap(), b"abc");
}

#[test]
fn aes_provider_receives_each_strength_salt_once_for_nonempty_and_empty_files() {
    for (strength, salt_bytes) in [(AesStrength::Aes128, 8), (AesStrength::Aes192, 12), (AesStrength::Aes256, 16)] {
        let (dir, _, _, mut plan) = tiny(CreateOptions::default());
        let empty = dir.path().join("empty");
        std::fs::write(&empty, []).unwrap();
        plan.add_directory(metadata("dir/"), None).unwrap();
        plan.add_file(&empty, metadata("empty"), None).unwrap();
        let count = Rc::new(Cell::new(0));
        let seen = count.clone();
        let report = with_hook(
            move |event, _| {
                if let Event::AesEntropy { bytes } = event {
                    assert_eq!(bytes, salt_bytes);
                    seen.set(seen.get() + 1);
                }
                Ok(())
            },
            || {
                plan.publish_winzip_aes_with_receipts(
                    WinZipAesRequest::new("native-aes-fixture", strength, AesVariant::Ae2).unwrap(),
                )
            },
        );
        report.outcome.unwrap();
        assert_eq!(count.get(), 2);
        assert_eq!(report.written.len(), 3);
    }
}

#[test]
fn aes_permissions_and_stage_sync_fail_before_publication() {
    for selected in [Event::Chmod, Event::FileSync] {
        let options = CreateOptions { durability: Durability::SyncFileAndDirectory, ..Default::default() };
        let (dir, source, output, plan) = tiny(options);
        let report = with_hook(
            move |event, _| if event == selected { Err(io::Error::from_raw_os_error(libc::EIO)) } else { Ok(()) },
            || plan.publish_winzip_aes_with_receipts(request()),
        );
        let failure = report.outcome.unwrap_err();
        assert_eq!(failure.publication, Publication::NotPublished);
        assert_eq!(
            failure.stage,
            if selected == Event::Chmod { CreateStage::Permissions } else { CreateStage::FileSync }
        );
        assert!(report.written.is_empty());
        assert!(!output.exists());
        assert!(stages(dir.path()).is_empty());
        assert_eq!(std::fs::read(source).unwrap(), b"abc");
    }
}

#[test]
#[ignore = "physically publishes and binds an AES member larger than 128 MiB"]
fn aes_physical_native_publication_exceeds_buffered_reader_limit() {
    const LENGTH: u64 = (128 << 20) + 1;
    let dir = test_dir();
    let source = dir.path().join("source");
    let output = dir.path().join("large.zip");
    std::fs::File::create(&source).unwrap().set_len(LENGTH).unwrap();
    let options = CreateOptions { durability: Durability::SyncFileAndDirectory, ..Default::default() };
    let mut plan = CreatePlan::new(&output, options).unwrap();
    plan.add_file(&source, metadata("large"), None).unwrap();
    let request = WinZipAesRequest::new("password", AesStrength::Aes256, AesVariant::Ae2).unwrap();
    let (report, binding) = plan.publish_winzip_aes_with_bound_receipts(request);
    let result = report.outcome.unwrap();
    assert_eq!((result.publication, result.durability), (Publication::Published, DurabilityState::Synced));
    assert!(binding.unwrap().matches(&std::fs::symlink_metadata(&output).unwrap()));
    assert_eq!(
        (report.written[0].decoded_size, report.written[0].packed_size, report.written[0].crc32),
        (LENGTH, LENGTH + 28, 0)
    );
    assert_eq!((result.summary.verification.payloads, result.summary.verification.decoded_bytes), (1, LENGTH));
    let mut archive = crate::zip::Archive::open(&output).unwrap();
    assert!(
        matches!(archive.read_at(0,Some("password"),u64::MAX,|_|Ok(())),Err(crate::Error::Unsupported(message)) if message.contains("128 MiB packed limit"))
    );
    if let Some(path) = std::env::var_os("ZIPFAST_AES_NATIVE_LARGE_OUTPUT") {
        std::fs::copy(&output, path).unwrap();
    }
    println!(
        "AES native physical decoded={} packed={} extent={} writer_attempts={} verification_reads={} transaction_attempts={} finalization_attempts={} parser_scratch={}",
        LENGTH,
        report.written[0].packed_size,
        result.summary.writer.archive_extent,
        result.summary.writer.io_attempts,
        result.summary.verification.read_bytes,
        result.summary.transaction_attempts,
        result.summary.finalization_attempts,
        result.summary.verification.scratch_capacity
    );
}
