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

//! Typed RAR outcomes from format-generated archives.
mod common;

use std::{fs, path::Path};

use common::*;
use zipfast::error::{IoOperation, RarFailure, RarIntegrityReason, RarPasswordEvidence, RarUnsupported};
use zipfast::extract::{
    Mode, Options, Overwrite, RarMatchState, RarOutcome, RarOutput, RarSkipReason, run_rar_with_outcomes,
};
use zipfast::rar5::testenc::{Op, block as packed_block};

fn options(dest: &Path, mode: Mode, threads: usize) -> Options {
    Options {
        mode,
        dest: dest.to_owned(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(threads),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

#[test]
fn callbacks_report_mixed_members_on_the_caller_in_listing_order() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("mixed.rar");
    let data = b"ok";
    let packed = packed_block(&[Op::Lit(b'o'), Op::Lit(b'k')], true, true);
    let specs = [
        (FileSpec { method: 6, size: Some(2), ..FileSpec::new("same", &packed) }, crc32fast::hash(data)),
        (FileSpec { dir: true, ..FileSpec::new("dir", b"") }, 0),
        (FileSpec::new("same", b"later"), crc32fast::hash(b"later")),
        (FileSpec { no_crc: true, size_unknown: true, ..FileSpec::new("empty", b"") }, 0),
        (FileSpec::new("bad", b"bad"), 0),
        (FileSpec { method: 7, size: Some(2), ..FileSpec::new("seven", &packed) }, crc32fast::hash(data)),
    ];
    fs::write(&archive, archive_with(&specs, false)).unwrap();
    let original = fs::read(&archive).unwrap();
    let caller = std::thread::current().id();
    for threads in [1, 4] {
        let out = dir.path().join(format!("out-{threads}"));
        let mut seen = 0;
        let summary = run_rar_with_outcomes(&archive, &options(&out, Mode::Extract, threads), None, |event| {
            assert_eq!(std::thread::current().id(), caller);
            assert_eq!((event.entry.index, event.entry.order), (Some(seen), seen));
            assert_eq!(event.entry.name, specs[seen as usize].0.name);
            match (seen, &event.outcome) {
                (0 | 5, RarOutcome::Verified { bytes: 2, checks, output: RarOutput::Written }) => {
                    assert_eq!(event.method, if seen == 0 { 6 } else { 7 });
                    assert!(checks.size_checked && checks.crc32_checked && !checks.blake2sp_checked);
                    assert_eq!(checks.password, RarPasswordEvidence::NotEncrypted);
                }
                (1, RarOutcome::Directory) | (2, RarOutcome::Skipped(RarSkipReason::ExistingTarget)) => {}
                (3, RarOutcome::Verified { bytes: 0, checks, .. }) => {
                    assert!(!checks.size_checked && !checks.crc32_checked && !checks.blake2sp_checked);
                }
                (4, RarOutcome::Failed(cause)) => assert!(matches!(
                    cause.as_ref(),
                    RarFailure::Integrity {
                        reason: RarIntegrityReason::FinalChecks { crc32: true, blake2sp: false, .. },
                        ..
                    }
                )),
                _ => panic!("unexpected outcome {event:?}"),
            }
            seen += 1;
        })
        .unwrap();
        assert_eq!(seen, 6);
        assert_eq!((summary.encountered, summary.matched, summary.files, summary.dirs), (6, 6, 3, 1));
        assert_eq!((summary.bytes, summary.skipped, summary.failed, summary.volumes), (4, 1, 1, 1));
        assert_eq!(summary.match_state, RarMatchState::Matched);
        assert_eq!(fs::read(out.join("same")).unwrap(), data);
        assert_eq!(fs::read(out.join("seven")).unwrap(), data);
        assert!(!out.join("bad").exists());
        assert_eq!(fs::read(&archive).unwrap(), original);
    }
}

#[test]
fn empty_archive_has_no_match_and_foreign_input_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("empty.rar");
    let opts = options(dir.path(), Mode::Test, 4);
    fs::write(&archive, common::archive(&[])).unwrap();
    let result = run_rar_with_outcomes(&archive, &opts, None, |_| panic!("empty archive emitted an entry")).unwrap();
    assert_eq!(result.match_state, RarMatchState::NoMatch);
    assert_eq!((result.matched, result.volumes), (0, 1));
    fs::write(&archive, b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
    let error =
        run_rar_with_outcomes(&archive, &opts, None, |_| panic!("foreign archive emitted an entry")).unwrap_err();
    assert!(matches!(error.failure.as_ref(), RarFailure::NotRar));
    assert!(error.entry.is_none());
}

#[cfg(unix)]
#[test]
fn fatal_target_failure_owns_the_io_error_and_entry_event() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("target.rar");
    let original = common::archive(&[FileSpec::new("good", b"good"), FileSpec::new(&"a".repeat(300), b"too long")]);
    fs::write(&archive, &original).unwrap();
    for threads in [1, 4] {
        let out = dir.path().join(format!("out-{threads}"));
        let mut failure = None;
        let result = run_rar_with_outcomes(&archive, &options(&out, Mode::Extract, threads), None, |event| {
            if let RarOutcome::Failed(cause) = &event.outcome {
                assert_eq!(event.entry.index, Some(1));
                failure = Some(Arc::clone(cause));
            }
        })
        .unwrap_err();
        assert!(Arc::ptr_eq(&failure.unwrap(), &result.failure));
        assert!(matches!(
            result.failure.as_ref(),
            RarFailure::Output { operation: IoOperation::Metadata, source, .. }
                if source.raw_os_error() == Some(libc::ENAMETOOLONG)
        ));
        assert_eq!(result.entry.unwrap().index, Some(1));
        assert_eq!((result.partial.files, result.partial.failed, result.partial.volumes), (1, 1, 1));
        assert_eq!(fs::read(out.join("good")).unwrap(), b"good");
        assert_eq!(fs::read(&archive).unwrap(), original);
    }
}

#[test]
fn unsupported_algorithm_retains_the_method_and_algorithm() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("unsupported.rar");
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    let mut fields = vec![0, 1, 0x20];
    vint((7 << 7) | 1, &mut fields);
    fields.extend([0, 1, b'f']);
    bytes.extend(block(2, 0, &fields, &[], b"x", true));
    bytes.extend(end_block(false));
    fs::write(&archive, bytes).unwrap();
    let summary = run_rar_with_outcomes(&archive, &options(dir.path(), Mode::Test, 4), None, |event| {
        assert_eq!(event.method, 7);
        assert!(matches!(
            &event.outcome,
            RarOutcome::Failed(failure)
                if matches!(failure.as_ref(), RarFailure::Unsupported(RarUnsupported::CompressionAlgorithm { algorithm: 1, method: 7, .. }))
        ));
    }).unwrap();
    assert_eq!((summary.files, summary.failed, summary.matched), (0, 1, 1));
}

#[test]
fn compressed_split_preserves_initial_method_and_orphan_listing_ordinals() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("split.part1.rar");
    let second = dir.path().join("split.part2.rar");
    let plain = b"split";
    let ops: Vec<_> = plain.iter().copied().map(Op::Lit).collect();
    let packed = packed_block(&ops, true, true);
    let (head, tail) = packed.split_at(packed.len() / 2);
    for last_method in [7, 0] {
        let mut one = SIG.to_vec();
        one.extend(main_block(true, None));
        one.extend(file_block(&FileSpec::new("orphan", b"x"), b"x", 0, true, false));
        let spec = FileSpec { method: 6, size: Some(plain.len() as u64), ..FileSpec::new("file", &packed) };
        one.extend(file_block(&spec, head, crc32fast::hash(head), false, true));
        one.extend(end_block(true));
        let mut two = SIG.to_vec();
        two.extend(main_block(true, Some(1)));
        let last = FileSpec { method: last_method, ..spec };
        two.extend(file_block(&last, tail, crc32fast::hash(plain), true, false));
        let done = FileSpec::new("last", b"last");
        two.extend(file_block(&done, done.data, crc32fast::hash(done.data), false, false));
        two.extend(end_block(false));
        fs::write(&first, &one).unwrap();
        fs::write(&second, &two).unwrap();
        for threads in [1, 4] {
            let out = dir.path().join(format!("out-{last_method}-{threads}"));
            let mut seen = 0;
            let summary = run_rar_with_outcomes(&first, &options(&out, Mode::Extract, threads), None, |event| {
                assert_eq!(event.entry.order, seen);
                assert_eq!(event.entry.index, seen.checked_sub(1));
                match (seen, last_method, &event.outcome) {
                    (0, _, RarOutcome::Skipped(RarSkipReason::MissingStart)) => {}
                    (1, 7, RarOutcome::Verified { bytes: 5, checks, .. }) => {
                        assert!(checks.crc32_checked && checks.size_checked);
                        assert_eq!(event.method, 6);
                    }
                    (1, 0, RarOutcome::Failed(failure)) => assert!(matches!(
                        failure.as_ref(),
                        RarFailure::Integrity { reason: RarIntegrityReason::ChangedContinuationEncoding, .. }
                    )),
                    (2, _, RarOutcome::Verified { bytes: 4, .. }) => {}
                    _ => panic!("unexpected split outcome {event:?}"),
                }
                seen += 1;
            })
            .unwrap();
            assert_eq!(seen, 3);
            assert_eq!((summary.encountered, summary.matched, summary.skipped, summary.volumes), (2, 2, 1, 2));
            if last_method == 7 {
                assert_eq!(fs::read(out.join("file")).unwrap(), plain);
            } else {
                assert!(!out.join("file").exists());
            }
            assert_eq!(fs::read(out.join("last")).unwrap(), b"last");
        }
        assert_eq!(fs::read(&first).unwrap(), one);
        assert_eq!(fs::read(&second).unwrap(), two);
    }
}

#[test]
fn fatal_header_crc_keeps_completions_from_already_submitted_jobs() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("bad-header.rar");
    let specs = [(FileSpec::new("good", b"good"), crc32fast::hash(b"good")), (FileSpec::new("bad", b"bad"), 0)];
    let mut bytes = archive_with(&specs, false);
    let end = bytes.len() - end_block(false).len();
    bytes[end] ^= 1;
    fs::write(&archive, &bytes).unwrap();
    for threads in [1, 4] {
        let out = dir.path().join(format!("out-{threads}"));
        let mut seen = 0;
        let error = run_rar_with_outcomes(&archive, &options(&out, Mode::Extract, threads), None, |event| {
            assert_eq!(event.entry.index, Some(seen));
            assert!(match seen {
                0 => matches!(event.outcome, RarOutcome::Verified { bytes: 4, .. }),
                1 => matches!(event.outcome, RarOutcome::Failed(_)),
                _ => false,
            });
            seen += 1;
        })
        .unwrap_err();
        assert!(error.entry.is_none());
        assert!(matches!(error.failure.as_ref(), RarFailure::Integrity { reason: RarIntegrityReason::HeaderCrc, .. }));
        assert_eq!(seen, 2);
        assert_eq!((error.partial.files, error.partial.failed, error.partial.volumes), (1, 1, 1));
        assert_eq!(fs::read(out.join("good")).unwrap(), b"good");
        assert!(!out.join("bad").exists());
    }
}

#[test]
fn typed_run_streams_more_failures_than_the_worker_queue_can_hold() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("many.rar");
    const MEMBERS: u64 = 1300;
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    for _ in 0..MEMBERS {
        let file = FileSpec::new("bad", b"x");
        bytes.extend(file_block(&file, file.data, 0, false, false));
    }
    bytes.extend(end_block(false));
    fs::write(&archive, bytes).unwrap();
    let mut seen = 0;
    let summary = run_rar_with_outcomes(&archive, &options(dir.path(), Mode::Test, 4), None, |event| {
        assert_eq!((event.entry.index, event.entry.order), (Some(seen), seen));
        assert!(matches!(event.outcome, RarOutcome::Failed(_)));
        seen += 1;
    })
    .unwrap();
    assert_eq!(seen, MEMBERS);
    assert_eq!((summary.failed, summary.matched, summary.files), (MEMBERS, MEMBERS, 0));
}

#[test]
fn missing_input_preserves_open_error_source() {
    use std::error::Error as _;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("missing.rar");
    let expected = fs::File::open(&input).unwrap_err();
    let error = run_rar_with_outcomes(&input, &options(dir.path(), Mode::Test, 1), None, |_| panic!("entry emitted"))
        .unwrap_err();
    assert!(
        matches!(error.failure.as_ref(), RarFailure::Input { operation: IoOperation::Open, path: Some(path), .. } if path == &input)
    );
    let io = error.source().unwrap().source().unwrap().downcast_ref::<std::io::Error>().unwrap();
    assert_eq!(io.raw_os_error(), expected.raw_os_error());
    assert_eq!((error.partial.encountered, error.partial.volumes), (0, 0));
}

#[test]
fn compressed_size_failures_report_expected_and_actual_counts() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("sizes.rar");
    let packed = packed_block(&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c')], true, true);
    let specs = [
        (FileSpec { method: 6, size: Some(4), no_crc: true, ..FileSpec::new("short", &packed) }, 0),
        (FileSpec { method: 7, size: Some(2), no_crc: true, ..FileSpec::new("long", &packed) }, 0),
    ];
    fs::write(&archive, archive_with(&specs, false)).unwrap();
    for threads in [1, 4] {
        let result = run_rar_with_outcomes(&archive, &options(dir.path(), Mode::Test, threads), None, |event| {
            let expect = if event.entry.order == 0 { 4 } else { 2 };
            assert!(matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(
                failure.as_ref(),
                RarFailure::Integrity { reason: RarIntegrityReason::DecodedSize { expected, actual: 3, .. }, .. } if *expected == expect
            )), "{event:?}");
        }).unwrap();
        assert_eq!((result.files, result.failed), (0, 2));
    }
}

#[cfg(unix)]
#[test]
fn archive_failure_stays_primary_when_a_worker_fails_during_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("secondary.rar");
    let long = format!("sub/{}", "a".repeat(300));
    let mut bytes = common::archive(&[FileSpec::new("sub/good", b"good"), FileSpec::new(&long, b"failed")]);
    let end = bytes.len() - end_block(false).len();
    bytes[end] ^= 1;
    fs::write(&archive, &bytes).unwrap();

    let out = dir.path().join("out");
    let mut seen = 0;
    let error = run_rar_with_outcomes(&archive, &options(&out, Mode::Extract, 4), None, |event| {
        assert_eq!(event.entry.index, Some(seen));
        match (seen, &event.outcome) {
            (0, RarOutcome::Verified { bytes: 4, .. }) => {}
            (1, RarOutcome::Failed(failure)) => assert!(matches!(failure.as_ref(), RarFailure::Output {
                operation: IoOperation::CreateFile, path: Some(path), source, ..
            } if path == &out.join(&long) && source.raw_os_error() == Some(libc::ENAMETOOLONG))),
            _ => panic!("unexpected event {event:?}"),
        }
        seen += 1;
    })
    .unwrap_err();
    assert_eq!(seen, 2);
    assert!(error.entry.is_none());
    assert!(matches!(error.failure.as_ref(), RarFailure::Integrity { reason: RarIntegrityReason::HeaderCrc, .. }));
    assert_eq!((error.partial.files, error.partial.failed), (1, 1));
    assert_eq!(fs::read(out.join("sub/good")).unwrap(), b"good");
    assert_eq!(fs::read_dir(out.join("sub")).unwrap().count(), 1);
    assert_eq!(fs::read(archive).unwrap(), bytes);
}

#[test]
fn all_existing_target_skips_still_match_and_keep_destination() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("skip.rar");
    let out = dir.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("file"), b"keep").unwrap();
    fs::write(&archive, common::archive(&[FileSpec::new("file", b"replace")])).unwrap();
    let mut seen = 0;
    let summary = run_rar_with_outcomes(&archive, &options(&out, Mode::Extract, 4), None, |event| {
        assert_eq!(event.entry.index, Some(0));
        assert!(matches!(event.outcome, RarOutcome::Skipped(RarSkipReason::ExistingTarget)));
        seen += 1;
    })
    .unwrap();
    assert_eq!(seen, 1);
    assert_eq!(summary.match_state, RarMatchState::Matched);
    assert_eq!((summary.matched, summary.skipped, summary.files, summary.failed), (1, 1, 0, 0));
    assert_eq!(fs::read(out.join("file")).unwrap(), b"keep");
}
