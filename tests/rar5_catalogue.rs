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

use std::fs;
use std::path::Path;

use common::*;
use zipfast::error::{RarFailure, RarIntegrityReason, RarResource, RarScope};
use zipfast::extract::Cancellation;
use zipfast::rar5::session::{RarSession, RarSessionOptions};

fn write_volume(path: &Path, main: Vec<u8>, files: &[Vec<u8>], more: Option<bool>) -> Vec<u8> {
    let mut bytes = SIG.to_vec();
    bytes.extend(main);
    for file in files {
        bytes.extend(file);
    }
    if let Some(more) = more {
        bytes.extend(end_block(more));
    }
    fs::write(path, &bytes).unwrap();
    bytes
}

#[test]
fn projects_initial_metadata_and_final_split_checks() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("set.part1.rar");
    let second = dir.path().join("set.part2.rar");
    let third = dir.path().join("set.part3.rar");
    let plain = FileSpec::new("ordinary", b"one");
    let initial = FileSpec {
        size: Some(17),
        method: 6,
        unix_mode: Some(0o640),
        extra: [&[34, 2, 0], [0xa5; 32].as_slice()].concat(),
        ..FileSpec::new("split", b"")
    };
    let last = FileSpec {
        method: 7,
        mtime: Some(1_800_000_000),
        extra: [&[34, 2, 0], [0x5a; 32].as_slice()].concat(),
        ..initial
    };
    let unknown = FileSpec {
        method: 7,
        size_unknown: true,
        no_crc: true,
        extra: vec![3, 4, 0, 2, 5, 5, 1, 0, 1, b'x'],
        ..FileSpec::new("unknown", b"")
    };
    let one = write_volume(
        &first,
        main_block(false, None),
        &[file_block(&plain, b"one", 0, false, false), file_block(&initial, b"aa", 0x1111, false, true)],
        Some(true),
    );
    let two = write_volume(
        &second,
        main_block(true, Some(1)),
        &[file_block(&initial, b"bbb", 0x2222, true, true)],
        Some(true),
    );
    let three = write_volume(
        &third,
        main_block(true, Some(2)),
        &[file_block(&last, b"cccc", 0x3333, true, false), file_block(&unknown, b"", 0, false, false)],
        Some(false),
    );

    let session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.archive().volume_count(), 3);
    assert_eq!(session.volumes().map(|volume| volume.declared_number()).collect::<Vec<_>>(), [None, Some(1), Some(2)]);
    let members = session.entries().collect::<Vec<_>>();
    assert_eq!(
        members.iter().map(|m| (m.ordinal(), m.name())).collect::<Vec<_>>(),
        [(0, "ordinary"), (1, "split"), (2, "unknown"),]
    );
    let member = members[1];
    assert_eq!(member.packed_size(), 9);
    assert_eq!(member.unpacked_size(), Some(17));
    assert_eq!(member.method(), 6);
    assert_eq!(member.modified(), Some((1_700_000_000, 0)));
    assert_eq!(member.attributes(), 0o640);
    assert_eq!(member.host_os(), 1);
    assert!(member.is_complete());
    assert!(member.payload_issue().is_none());
    assert_eq!(member.final_checks().unwrap().crc32, Some(0x3333));
    assert_eq!(member.final_checks().unwrap().blake2sp, Some([0x5a; 32]));
    assert_eq!(member.parts().map(|p| (p.volume(), p.packed_size())).collect::<Vec<_>>(), [(0, 2), (1, 3), (2, 4)]);
    assert_eq!(members[2].unpacked_size(), None);
    assert_eq!(members[2].version(), Some(2));
    assert!(matches!(members[2].redirection(), Some(zipfast::rar5::Redirection::UnixSymlink(path)) if path == "x"));
    assert_eq!(fs::read(first).unwrap(), one);
    assert_eq!(fs::read(second).unwrap(), two);
    assert_eq!(fs::read(third).unwrap(), three);
}

fn named_bytes(name: u8, before: bool, after: bool) -> Vec<u8> {
    let flags = (8 * u64::from(before)) | (16 * u64::from(after));
    block(2, flags, &[0, 1, 0, 0, 1, 1, name], &[], b"x", true)
}

#[test]
fn associates_only_adjacent_matching_split_starts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("parts.rar");
    let same = FileSpec::new("same", b"x");
    let other = FileSpec::new("other", b"y");
    write_volume(
        &path,
        main_block(false, None),
        &[
            file_block(&same, b"x", 0, true, false),
            file_block(&same, b"x", 7, false, false),
            file_block(&same, b"x", 9, true, false),
            file_block(&same, b"x", 0, false, true),
            file_block(&other, b"y", 0, true, false),
            named_bytes(0xfe, false, true),
            named_bytes(0xff, true, false),
            file_block(&same, b"x", 11, false, false),
        ],
        Some(false),
    );
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.archive().orphan_continuations(), 4);
    let members = session.entries().collect::<Vec<_>>();
    assert_eq!(
        members.iter().map(|m| (m.ordinal(), m.name(), m.is_complete())).collect::<Vec<_>>(),
        [(0, "same", true), (1, "same", false), (2, "\u{fffd}", false), (3, "same", true),]
    );
    assert_eq!(members[0].final_checks().unwrap().crc32, Some(7));
    for member in &members[1..3] {
        assert_eq!(member.packed_size(), 1);
        assert!(member.final_checks().is_none());
        assert!(matches!(member.payload_issue(), Some(RarFailure::Integrity {
            scope: RarScope::Member { index: Some(index) },
            reason: RarIntegrityReason::MissingSplitContinuation,
            ..
        }) if *index == member.ordinal()));
    }
}

#[test]
fn retains_framed_payload_issues_and_rejects_broken_headers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("issues.rar");
    let malformed = FileSpec { extra: vec![2, 1, 0], ..FileSpec::new("crypt", b"x") };
    let split = FileSpec::new("split", b"xy");
    let changed = FileSpec { method: 6, extra: Vec::new(), ..split };
    let mut bytes = write_volume(
        &path,
        main_block(false, None),
        &[
            file_block(&malformed, b"x", 0, false, false),
            file_block(&split, b"x", 1, false, true),
            file_block(&changed, b"y", 2, true, false),
        ],
        Some(false),
    );
    let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let members = session.entries().collect::<Vec<_>>();
    assert!(members[0].encrypted());
    assert!(members[0].is_complete());
    assert!(matches!(
        members[0].payload_issue(),
        Some(RarFailure::Integrity {
            scope: RarScope::Member { index: Some(0) },
            reason: RarIntegrityReason::MalformedEncryptionRecord,
            ..
        })
    ));
    assert_eq!(members[1].packed_size(), 2);
    assert!(members[1].is_complete());
    assert!(matches!(
        members[1].payload_issue(),
        Some(RarFailure::Integrity {
            scope: RarScope::Member { index: Some(1) },
            reason: RarIntegrityReason::ChangedContinuationEncoding,
            ..
        })
    ));
    drop(session);

    bytes[SIG.len()] ^= 1;
    fs::write(&path, bytes).unwrap();
    let failure = RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap();
    assert!(matches!(failure.failure.as_ref(), RarFailure::Integrity { reason: RarIntegrityReason::HeaderCrc, .. }));

    let invalid = FileSpec { extra: vec![9, 1, 0], ..malformed };
    write_volume(&path, main_block(false, None), &[file_block(&invalid, b"x", 0, false, false)], Some(false));
    let failure = RarSession::open(&path, None, RarSessionOptions::default()).err().unwrap();
    assert!(matches!(failure.failure.as_ref(), RarFailure::Integrity { scope: RarScope::Header { .. }, .. }));
}

#[test]
fn required_missing_volume_and_optional_missing_volume_have_different_results() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("set.part1.rar");
    let second = dir.path().join("set.part2.rar");
    write_volume(&first, main_block(true, None), &[], None);
    let session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.archive().volume_count(), 1);
    drop(session);

    fs::create_dir(&second).unwrap();
    let failure = RarSession::open(&first, None, RarSessionOptions::default()).err().unwrap();
    assert!(matches!(failure.failure.as_ref(), RarFailure::Input { path: Some(path), .. } if path == &second));
    fs::remove_dir(&second).unwrap();

    write_volume(&first, main_block(false, None), &[], Some(true));
    let failure = RarSession::open(&first, None, RarSessionOptions::default()).err().unwrap();
    assert_eq!(failure.partial.volumes, 1);
    assert!(matches!(failure.failure.as_ref(), RarFailure::MissingVolume { path } if path == &second));
}

#[test]
fn applies_catalogue_limits_and_skips_payload_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large.rar");
    let content = [0x5a; 4096];
    let spec = FileSpec::new("entry", &content);
    let bytes =
        write_volume(&path, main_block(false, None), &[file_block(&spec, &content, 0, false, false)], Some(false));
    let mut options = RarSessionOptions::default();
    options.limits.read_bytes = (bytes.len() - content.len()) as u64;
    options.limits.header_blocks = 3;
    options.limits.entries = 1;
    options.limits.parts = 1;
    options.limits.volumes = 1;
    options.limits.name_bytes = 10;
    let session = RarSession::open(&path, None, options.clone()).unwrap();
    assert_eq!(session.usage().read_bytes, options.limits.read_bytes);
    options.limits.capacity = session.usage().capacity;
    drop(session);
    assert!(RarSession::open(&path, None, options.clone()).is_ok());
    for (budget, reduce) in [
        (RarResource::CatalogueReadBytes, 0),
        (RarResource::CatalogueBlocks, 1),
        (RarResource::CatalogueEntries, 2),
        (RarResource::CatalogueParts, 3),
        (RarResource::CatalogueVolumes, 4),
        (RarResource::CatalogueNameBytes, 5),
        (RarResource::CatalogueCapacity, 6),
    ] {
        let mut options = options.clone();
        let cap = match reduce {
            0 => &mut options.limits.read_bytes,
            1 => &mut options.limits.header_blocks,
            2 => &mut options.limits.entries,
            3 => &mut options.limits.parts,
            4 => &mut options.limits.volumes,
            5 => &mut options.limits.name_bytes,
            _ => &mut options.limits.capacity,
        };
        *cap -= 1;
        let failure = RarSession::open(&path, None, options).err().unwrap_or_else(|| panic!("accepted {budget:?}"));
        assert!(
            matches!(failure.failure.as_ref(), RarFailure::Limit { resource, .. } if std::mem::discriminant(resource) == std::mem::discriminant(&budget))
        );
    }
    let cancel = Cancellation::default();
    cancel.cancel();
    let failure = RarSession::open(&path, None, RarSessionOptions { cancel, ..Default::default() }).err().unwrap();
    assert_eq!(failure.partial.volumes, 0);
    assert!(matches!(failure.failure.as_ref(), RarFailure::Canceled));
}

#[test]
fn counts_encrypted_and_skipped_physical_headers() {
    use zipfast::crypto::{derive_rar5_key_and_hash_key, encrypt_cbc};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypted.rar");
    let password = "zipfast-test-only";
    let salt = [0x53; 16];
    let iv = [0x49; 16];
    let check = [0x17, 0x41, 0x9a, 0xfa, 0xa6, 0x98, 0xfd, 0x50, 0xa8, 0x4b, 0x9b, 0x32];
    let key = derive_rar5_key_and_hash_key(password, 4, &salt, None).unwrap().0;
    let params = [&[0, 1, 4], salt.as_slice(), check.as_slice()].concat();
    let mut bytes = SIG.to_vec();
    bytes.extend(block(4, 0, &params, &[], &[], false));
    let member = FileSpec::new("name", b"");
    let service = block(3, 0, &[0, 0, 0, 0, 0, 0], &[], &[], false);
    let skipped = [0xaa; 4096];
    for (mut header, payload) in [
        (main_block(false, None), b"".as_slice()),
        (block(91, 0, &[], &[], &skipped, true), skipped.as_slice()),
        (service, b"".as_slice()),
        (file_block(&member, b"", 0, false, false), b"".as_slice()),
        (end_block(false), b"".as_slice()),
    ] {
        header.truncate(header.len() - payload.len());
        header.resize(header.len().next_multiple_of(16), 0);
        bytes.extend(iv);
        bytes.extend(encrypt_cbc(&key, &iv, &header).unwrap());
        bytes.extend(payload);
    }
    fs::write(&path, &bytes).unwrap();
    let mut options = RarSessionOptions::default();
    options.limits.header_blocks = 6;
    options.limits.read_bytes = (bytes.len() - skipped.len()) as u64;
    let session = RarSession::open(&path, Some(password), options.clone()).unwrap();
    assert!(session.volumes().next().unwrap().encrypted_headers());
    assert_eq!(session.entries().next().unwrap().name(), "name");
    assert_eq!(session.usage().header_blocks, 6);
    assert_eq!(session.usage().read_bytes, options.limits.read_bytes);
    for (mut options, blocks) in [(options.clone(), true), (options, false)] {
        if blocks {
            options.limits.header_blocks -= 1;
        } else {
            options.limits.read_bytes -= 1;
        }
        let failure = RarSession::open(&path, Some(password), options).err().unwrap();
        assert!(matches!(
            (blocks, failure.failure.as_ref()),
            (true, RarFailure::Limit { resource: RarResource::CatalogueBlocks, .. })
                | (false, RarFailure::Limit { resource: RarResource::CatalogueReadBytes, .. })
        ));
    }
    for (password, wrong) in [(None, false), (Some("wrong"), true)] {
        let failure = RarSession::open(&path, password, RarSessionOptions::default()).err().unwrap();
        assert!(matches!(
            (wrong, failure.failure.as_ref()),
            (false, RarFailure::PasswordRequired { scope: RarScope::Header { .. } })
                | (true, RarFailure::WrongPassword { scope: RarScope::Header { .. } })
        ));
    }
}

#[test]
fn compares_only_known_split_sizes_and_projects_the_available_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sizes.rar");
    for (first, last, size, mismatch) in [
        (None, Some(17), Some(17), false),
        (Some(17), None, Some(17), false),
        (None, None, None, false),
        (Some(17), Some(18), Some(17), true),
    ] {
        let first = FileSpec { size: first, size_unknown: first.is_none(), ..FileSpec::new("split", b"a") };
        let last = FileSpec { size: last, size_unknown: last.is_none(), ..FileSpec::new("split", b"b") };
        write_volume(
            &path,
            main_block(false, None),
            &[file_block(&first, b"a", 1, false, true), file_block(&last, b"b", 2, true, false)],
            Some(false),
        );
        let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let member = session.entries().next().unwrap();
        assert_eq!(member.unpacked_size(), size);
        match (mismatch, member.payload_issue()) {
            (false, None) => {}
            (
                true,
                Some(RarFailure::Integrity {
                    reason: RarIntegrityReason::SplitSizeMismatch { expected: 17, actual: 18 },
                    ..
                }),
            ) => {}
            other => panic!("unexpected result {other:?}"),
        }
    }
}
