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
mod common;

use common::*;
use std::fs;
use zipfast::error::{RarFailure, RarIntegrityReason, RarResource};
use zipfast::extract::{RarMatchState, RarOutcome, RarOutput};
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
use zipfast::rar5::testenc::{Op, tuned_blocks};

#[test]
fn selection_is_session_bound_and_reports_archive_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.rar");
    fs::write(
        &path,
        archive(&[
            FileSpec::new("same", b"first"),
            FileSpec::new("other", b"skip"),
            FileSpec::new("same", b"second"),
            FileSpec::new("empty", b""),
        ]),
    )
    .unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let mut foreign = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let mut visited = Vec::new();
    let selected = session
        .select(|entry| {
            visited.push(entry.ordinal());
            matches!(entry.name(), "same" | "empty")
        })
        .unwrap();
    assert_eq!(visited, [0, 1, 2, 3]);
    let failure = foreign.test_selected(&selected, RarDecodeLimits::default(), |_| panic!()).unwrap_err();
    assert!(matches!(failure.failure.as_ref(), RarFailure::ForeignSelection));
    let mut verified = Vec::new();
    let summary = session
        .test_selected(&selected, RarDecodeLimits::default(), |event| {
            let RarOutcome::Verified { bytes, output: RarOutput::Tested, .. } = event.outcome else {
                panic!("{event:?}")
            };
            assert_eq!(event.entry.index, Some(event.entry.order));
            verified.push((event.entry.order, bytes));
        })
        .unwrap();
    assert_eq!(verified, [(0, 5), (2, 6), (3, 0)]);
    assert_eq!((summary.encountered, summary.matched, summary.files, summary.bytes), (4, 3, 3, 11));
    let none = session.select(|_| false).unwrap();
    assert_eq!(
        session.test_selected(&none, RarDecodeLimits::default(), |_| panic!()).unwrap().match_state,
        RarMatchState::NoMatch
    );
}

#[test]
fn selected_directory_preserves_the_catalogue_issue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("directory.rar");
    let good = FileSpec { dir: true, ..FileSpec::new("good", b"") };
    let incomplete = FileSpec { dir: true, ..FileSpec::new("incomplete", b"") };
    let mut contents = SIG.to_vec();
    contents.extend(main_block(false, None));
    contents.extend(file_block(&good, b"", 0, false, false));
    contents.extend(file_block(&incomplete, b"", 0, false, true));
    contents.extend(end_block(false));
    fs::write(&path, contents).unwrap();

    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert!(matches!(
        session.entries().nth(1).unwrap().payload_issue(),
        Some(RarFailure::Integrity { reason: RarIntegrityReason::MissingSplitContinuation, .. })
    ));
    let selected = session.select(|_| true).unwrap();
    let summary = session
        .test_selected(&selected, RarDecodeLimits::default(), |event| match event.entry.order {
            0 => assert!(matches!(event.outcome, RarOutcome::Directory)),
            1 => assert!(matches!(
                &event.outcome,
                RarOutcome::Failed(failure) if matches!(
                    failure.as_ref(),
                    RarFailure::Integrity { reason: RarIntegrityReason::MissingSplitContinuation, .. }
                )
            )),
            ordinal => panic!("unexpected ordinal {ordinal}"),
        })
        .unwrap();
    assert_eq!((summary.dirs, summary.failed), (1, 1));
}

#[test]
fn known_packed_and_decoded_limits_precede_decoder_setup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("limits.rar");
    let packed = tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b')]], true);
    let spec = FileSpec { method: 3, size: Some(2), ..FileSpec::new("item", &packed) };
    fs::write(&path, archive_with(&[(spec, crc32fast::hash(b"ab"))], false)).unwrap();

    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    for (limits, expected_resource) in [
        (
            RarDecodeLimits { packed_bytes: 0, window_bytes: 0, ..RarDecodeLimits::default() },
            RarResource::SelectedPackedBytes,
        ),
        (
            RarDecodeLimits { decoded_bytes: 1, window_bytes: 0, ..RarDecodeLimits::default() },
            RarResource::SelectedDecodedBytes,
        ),
    ] {
        let failure = session.test_selected(&selected, limits, |_| {}).unwrap_err();
        assert!(matches!(
            failure.failure.as_ref(),
            RarFailure::Limit { resource, .. } if std::mem::discriminant(resource) == std::mem::discriminant(&expected_resource)
        ));
        assert_eq!((failure.partial.files, failure.partial.failed, failure.partial.bytes), (0, 1, 0));
    }
}

#[test]
fn uses_held_split_volumes_and_permanently_rejects_changed_binding() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("set.part1.rar");
    let second = dir.path().join("set.part2.rar");
    let spec = FileSpec::new("item", b"abcdef");
    let parts = volumes(&spec, 3);
    fs::write(&first, &parts[0]).unwrap();
    fs::write(&second, &parts[1]).unwrap();
    let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    assert_eq!(session.test_selected(&selected, RarDecodeLimits::default(), |_| {}).unwrap().bytes, 6);
    let previous = dir.path().join("previous.rar");
    fs::rename(&second, &previous).unwrap();
    fs::write(&second, &parts[1]).unwrap();
    for restore in [false, true] {
        if restore {
            fs::rename(&previous, &second).unwrap();
        }
        let failure = session.test_selected(&selected, RarDecodeLimits::default(), |_| panic!()).unwrap_err();
        assert!(matches!(failure.failure.as_ref(), RarFailure::SourceChanged { path } if path == &second));
    }
}

#[test]
fn failed_solid_predecessor_blocks_dependents_until_independent_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("solid.rar");
    let first = tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c')]], true);
    let next = tuned_blocks(&[&[Op::Lit(b'd'), Op::Lit(b'e'), Op::Lit(b'f')]], true);
    let initial = FileSpec { method: 3, size: Some(3), ..FileSpec::new("initial", &first) };
    let dependent = |name| FileSpec { method: 3, size: Some(3), solid: true, ..FileSpec::new(name, &next) };
    let restart = FileSpec { method: 3, size: Some(3), ..FileSpec::new("restart", &first) };
    fs::write(
        &path,
        archive_with(
            &[
                (initial, 0),
                (dependent("one"), crc32fast::hash(b"def")),
                (dependent("two"), crc32fast::hash(b"def")),
                (restart, crc32fast::hash(b"abc")),
            ],
            true,
        ),
    )
    .unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|m| m.ordinal() != 0).unwrap();
    let mut events = Vec::new();
    let summary = session
        .test_selected(&selection, RarDecodeLimits::default(), |event| {
            events.push(event.entry.order);
            match &event.outcome {
                RarOutcome::Failed(failure) if event.entry.order <= 2 => {
                    assert!(matches!(failure.as_ref(), RarFailure::SolidHistoryUnavailable {
                        predecessor: Some(0), cause: Some(cause)
                    } if matches!(cause.as_ref(), RarFailure::Integrity {
                        reason: RarIntegrityReason::FinalChecks { crc32: true, .. }, ..
                    })));
                }
                RarOutcome::Verified { bytes: 3, .. } if event.entry.order == 3 => {}
                other => panic!("{other:?}"),
            }
        })
        .unwrap();
    assert_eq!(events, [1, 2, 3]);
    assert_eq!((summary.files, summary.failed), (1, 2));
}

#[test]
fn cumulative_decode_limits_are_typed_and_include_unknown_sizes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("limits.rar");
    let spec = FileSpec { size_unknown: true, ..FileSpec::new("first", b"abc") };
    fs::write(&path, archive(&[spec, FileSpec::new("second", b"def")])).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    for (packed, decoded) in [(5, 6), (6, 5)] {
        let result = session
            .test_selected(
                &selection,
                RarDecodeLimits { packed_bytes: packed, decoded_bytes: decoded, ..Default::default() },
                |_| {},
            )
            .unwrap_err();
        assert_eq!((result.partial.files, result.partial.bytes), (1, 3));
        assert!(matches!(
            (packed, result.failure.as_ref()),
            (5, RarFailure::Limit { resource: RarResource::SelectedPackedBytes, .. })
                | (6, RarFailure::Limit { resource: RarResource::SelectedDecodedBytes, .. })
        ));
    }
    let limits = RarDecodeLimits { packed_bytes: 6, decoded_bytes: 6, ..Default::default() };
    assert_eq!(session.test_selected(&selection, limits, |_| {}).unwrap().bytes, 6);
}

#[test]
fn decodes_only_required_history_once_even_without_main_solid_flag() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("history.rar");
    let root = tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c')]], true);
    let dependency = tuned_blocks(&[&[Op::Match(3, 3), Op::Lit(b'x')]], true);
    let following = tuned_blocks(&[&[Op::Match(3, 3)]], true);
    let entry = |name, data, size, solid| FileSpec { method: 3, size: Some(size), solid, ..FileSpec::new(name, data) };
    fs::write(
        &path,
        archive_with(
            &[
                (entry("unrelated", b"invalid", 99, false), 0),
                (entry("start", &root, 3, false), crc32fast::hash(b"abc")),
                (entry("one", &dependency, 4, true), crc32fast::hash(b"abcx")),
                (FileSpec::new("stored", b"unrelated stored data"), 0),
                (entry("two", &following, 3, true), crc32fast::hash(b"bcx")),
            ],
            false,
        ),
    )
    .unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|m| matches!(m.name(), "one" | "two")).unwrap();
    let limits = RarDecodeLimits {
        packed_bytes: (root.len() + dependency.len() + following.len()) as u64,
        decoded_bytes: 10,
        window_bytes: 256 << 10,
    };
    let mut callbacks = Vec::new();
    let summary = session
        .test_selected(&selection, limits, |event| {
            assert!(matches!(event.outcome, RarOutcome::Verified { .. }), "{event:?}");
            callbacks.push(event.entry.order);
        })
        .unwrap();
    assert_eq!(callbacks, [2, 4]);
    assert_eq!((summary.matched, summary.files, summary.bytes), (2, 2, 7));

    let limits = RarDecodeLimits { decoded_bytes: 9, ..limits };
    let failure = session.test_selected(&selection, limits, |_| {}).unwrap_err();
    assert_eq!(failure.entry.unwrap().order, 4);
    assert!(matches!(
        failure.failure.as_ref(),
        RarFailure::Limit { resource: RarResource::SelectedDecodedBytes, requested: Some(10), allowed: Some(9) }
    ));

    let limits = RarDecodeLimits { window_bytes: (256 << 10) - 1, ..limits };
    let summary = session
        .test_selected(&selection, limits, |event| {
            assert!(matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(failure.as_ref(),
                RarFailure::SolidHistoryUnavailable { predecessor: Some(1), cause: Some(cause) }
                    if matches!(cause.as_ref(), RarFailure::Limit {
                        resource: RarResource::DictionarySize, requested: Some(262144), allowed: Some(262143)
                    })
            )));
        })
        .unwrap();
    assert_eq!((summary.files, summary.failed), (0, 2));
}

#[test]
fn split_cbc_uses_each_parts_hash_mode_and_records_password_evidence() {
    use zipfast::crypto::{derive_rar5_key_and_hash_key, encrypt_cbc, rar5_tweak_crc32};
    use zipfast::error::{RarPasswordEvidence, RarScope};

    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("encrypted.part1.rar");
    let second = dir.path().join("encrypted.part2.rar");
    let password = "zipfast-test-only";
    let salt = [0x53; 16];
    let iv = [0x49; 16];
    let check = [0x17, 0x41, 0x9a, 0xfa, 0xa6, 0x98, 0xfd, 0x50, 0xa8, 0x4b, 0x9b, 0x32];
    let (key, hash_key) = derive_rar5_key_and_hash_key(password, 4, &salt, None).unwrap();
    let plain = b"0123456789abcdefg";
    let mut padded = plain.to_vec();
    padded.resize(32, 0);
    let encrypted = encrypt_cbc(&key, &iv, &padded).unwrap();
    let spec = |mode| FileSpec {
        extra: [&[48, 1, 0, mode, 4], salt.as_slice(), iv.as_slice(), check.as_slice()].concat(),
        size: Some(17),
        ..FileSpec::new("item", &encrypted)
    };
    let (leading, trailing) = encrypted.split_at(7);
    let start = [
        SIG,
        &main_block(true, None),
        &file_block(&spec(1), leading, crc32fast::hash(leading), false, true),
        &end_block(true),
    ]
    .concat();
    let end = [
        SIG,
        &main_block(true, Some(1)),
        &file_block(&spec(3), trailing, rar5_tweak_crc32(crc32fast::hash(plain), &hash_key), true, false),
        &end_block(false),
    ]
    .concat();
    fs::write(&first, start).unwrap();
    fs::write(&second, end).unwrap();
    let mut session = RarSession::open(&first, Some(password), RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    let result = session
        .test_selected(&selection, RarDecodeLimits::default(), |event| {
            assert!(matches!(event.outcome, RarOutcome::Verified { bytes: 17, checks, .. }
            if checks.crc32_checked && checks.size_checked && checks.password == RarPasswordEvidence::VerifierMatched));
        })
        .unwrap();
    assert_eq!(result.bytes, 17);

    let mut wrong = RarSession::open(&first, Some("wrong"), RarSessionOptions::default()).unwrap();
    let selection = wrong.select(|_| true).unwrap();
    let result = wrong
        .test_selected(&selection, RarDecodeLimits::default(), |event| {
            assert!(matches!(&event.outcome, RarOutcome::Failed(failure)
            if matches!(failure.as_ref(), RarFailure::WrongPassword { scope: RarScope::Member { index: Some(0) } })));
        })
        .unwrap();
    assert_eq!(result.failed, 1);
}

#[test]
fn cancellation_after_one_callback_stops_before_next_payload() {
    use zipfast::extract::Cancellation;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel.rar");
    fs::write(&path, archive(&[FileSpec::new("first", b"abc"), FileSpec::new("next", b"def")])).unwrap();
    let cancel = Cancellation::default();
    let mut session =
        RarSession::open(&path, None, RarSessionOptions { cancel: cancel.clone(), ..Default::default() }).unwrap();
    let selection = session.select(|_| true).unwrap();
    let mut outcomes = Vec::new();
    let failure = session
        .test_selected(&selection, RarDecodeLimits::default(), |event| {
            outcomes.push(event.entry.order);
            if event.entry.order == 0 {
                cancel.cancel();
            }
        })
        .unwrap_err();
    assert_eq!(outcomes, [0, 1]);
    assert_eq!((failure.partial.files, failure.partial.bytes, failure.partial.failed), (1, 3, 1));
    assert!(matches!(failure.failure.as_ref(), RarFailure::Canceled));
}
