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
use std::{fs, os::unix::fs::PermissionsExt, path::Path};
use zipfast::error::{RarFailure, RarIntegrityReason, RarPolicyReason};
use zipfast::extract::{Mode, Options, Overwrite, RarMatchState, RarOutcome, RarOutput, RarSkipReason};
use zipfast::rar5::session::{RarDecodeLimits, RarSession, RarSessionOptions};
use zipfast::rar5::testenc::{Op, tuned_blocks};

fn options(dest: &Path, overwrite: Overwrite) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.to_path_buf(),
        overwrite,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

#[test]
fn foreign_and_empty_selections_have_no_destination_side_effects() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.rar");
    fs::write(&path, archive(&[FileSpec::new("file", b"ok")])).unwrap();
    let mut first = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let mut second = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let absent = dir.path().join("absent");
    let opts = options(&absent, Overwrite::Always);
    for matches in [false, true] {
        let foreign = first.select(|_| matches).unwrap();
        let failure = second.extract_selected(&foreign, &opts, RarDecodeLimits::default(), |_| panic!()).unwrap_err();
        assert!(matches!(failure.failure.as_ref(), RarFailure::ForeignSelection));
        assert!(!absent.exists());
    }
    let none = first.select(|_| false).unwrap();
    let summary = first.extract_selected(&none, &opts, RarDecodeLimits::default(), |_| panic!()).unwrap();
    assert_eq!(summary.match_state, RarMatchState::NoMatch);
    assert!(!absent.exists());
}

#[test]
fn selected_extraction_orders_duplicates_preserves_metadata_and_refuses_unsafe_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.rar");
    let folder = FileSpec { dir: true, unix_mode: Some(0o750), ..FileSpec::new("folder", b"") };
    let file = FileSpec { unix_mode: Some(0o640), ..FileSpec::new("folder/item", b"first") };
    let later = FileSpec { unix_mode: Some(0o600), ..FileSpec::new("folder/item", b"second") };
    fs::write(
        &path,
        archive(&[folder, file, FileSpec::new("unselected", b"x"), later, FileSpec::new("../escape", b"bad")]),
    )
    .unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|m| m.name() != "unselected").unwrap();
    for (overwrite, expected, mode, files, skips) in
        [(Overwrite::Skip, b"first".as_slice(), 0o640, 1, 1), (Overwrite::Always, b"second".as_slice(), 0o600, 2, 0)]
    {
        let dest = dir.path().join(format!("out-{files}"));
        let mut orders = Vec::new();
        let summary = session
            .extract_selected(&selected, &options(&dest, overwrite), RarDecodeLimits::default(), |event| {
                orders.push(event.entry.order);
                match (event.entry.order, &event.outcome) {
                    (0, RarOutcome::Directory) | (1 | 3, RarOutcome::Verified { output: RarOutput::Written, .. }) => {}
                    (3, RarOutcome::Skipped(RarSkipReason::ExistingTarget)) => assert_eq!(overwrite, Overwrite::Skip),
                    (4, RarOutcome::Failed(failure)) => assert!(matches!(
                        failure.as_ref(),
                        RarFailure::Policy { reason: RarPolicyReason::UnsafePath, .. }
                    )),
                    other => panic!("{other:?}"),
                }
            })
            .unwrap();
        assert_eq!(orders, [0, 1, 3, 4]);
        assert_eq!((summary.files, summary.dirs, summary.skipped, summary.failed), (files, 1, skips, 1));
        assert_eq!(fs::read(dest.join("folder/item")).unwrap(), expected);
        assert_eq!(fs::metadata(dest.join("folder/item")).unwrap().permissions().mode() & 0o777, mode);
        assert_eq!(fs::metadata(dest.join("folder")).unwrap().permissions().mode() & 0o777, 0o750);
        assert!(!dest.join("unselected").exists());
        assert!(!dir.path().join("escape").exists());
    }
}

#[test]
fn protects_a_hard_link_to_an_unselected_later_volume() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("set.part1.rar");
    let second = dir.path().join("set.part2.rar");
    let spec = FileSpec::new("target", b"new");
    let one = [
        SIG,
        &main_block(true, None),
        &file_block(&spec, b"new", crc32fast::hash(b"new"), false, false),
        &end_block(true),
    ]
    .concat();
    let two = [SIG, &main_block(true, Some(1)), &end_block(false)].concat();
    fs::write(&first, &one).unwrap();
    fs::write(&second, &two).unwrap();
    fs::hard_link(&second, dir.path().join("target")).unwrap();
    let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let result = session
        .extract_selected(&selected, &options(dir.path(), Overwrite::Always), RarDecodeLimits::default(), |event| {
            assert!(matches!(&event.outcome, RarOutcome::Failed(failure)
            if matches!(failure.as_ref(), RarFailure::Policy { reason: RarPolicyReason::ProtectedInput, .. })));
        })
        .unwrap();
    assert_eq!((result.files, result.failed), (0, 1));
    assert_eq!(fs::read(&first).unwrap(), one);
    assert_eq!(fs::read(&second).unwrap(), two);
    assert_eq!(fs::read(dir.path().join("target")).unwrap(), two);
}

#[test]
fn skipped_solid_predecessor_is_verified_only_when_needed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("solid.rar");
    let first = tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c')]], true);
    let next = tuned_blocks(&[&[Op::Match(3, 3)]], true);
    let initial = FileSpec { method: 3, size: Some(3), ..FileSpec::new("initial", &first) };
    let dependent = FileSpec { method: 3, size: Some(3), solid: true, ..FileSpec::new("dependent", &next) };
    let dest = dir.path().join("out");
    let opts = options(&dest, Overwrite::Skip);
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("initial"), b"existing").unwrap();
    for corrupt in [false, true] {
        let initial = FileSpec { extra: Vec::new(), ..initial };
        let dependent = FileSpec { extra: Vec::new(), ..dependent };
        let crc = crc32fast::hash(b"abc");
        fs::write(&path, archive_with(&[(initial, crc ^ u32::from(corrupt)), (dependent, crc)], true)).unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let only_skip = session.select(|m| m.ordinal() == 0).unwrap();
        let zero = RarDecodeLimits { packed_bytes: 0, decoded_bytes: 0, ..Default::default() };
        assert_eq!(session.extract_selected(&only_skip, &opts, zero, |_| {}).unwrap().skipped, 1);

        let all = session.select(|_| true).unwrap();
        let limits =
            RarDecodeLimits { packed_bytes: (first.len() + next.len()) as u64, decoded_bytes: 6, ..Default::default() };
        let result = session.extract_selected(&all, &opts, limits, |event| {
            match (event.entry.order, &event.outcome) {
                (0, RarOutcome::Skipped(RarSkipReason::ExistingTarget)) => {}
                (1, RarOutcome::Verified { output: RarOutput::Written, .. }) => assert!(!corrupt),
                (1, RarOutcome::Failed(failure)) => assert!(corrupt && matches!(failure.as_ref(),
                    RarFailure::SolidHistoryUnavailable { predecessor: Some(0), cause: Some(cause) }
                    if matches!(cause.as_ref(), RarFailure::Integrity { reason: RarIntegrityReason::FinalChecks { crc32: true, .. }, .. }))),
                other => panic!("{other:?}"),
            }
        }).unwrap();
        assert_eq!(result.skipped, 1);
        assert_eq!(result.files, u64::from(!corrupt));
        assert_eq!(fs::read(dest.join("initial")).unwrap(), b"existing");
        if !corrupt {
            assert_eq!(fs::read(dest.join("dependent")).unwrap(), b"abc");
            fs::remove_file(dest.join("dependent")).unwrap();
        } else {
            assert!(!dest.join("dependent").exists());
        }
    }
}
