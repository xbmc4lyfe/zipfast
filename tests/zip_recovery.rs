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

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, io::Cursor};
use zipfast::zip::{
    ReadSession,
    recovery::{MemberRecovery, RecoveryOptions, RecoveryOutcome, RecoveryPlan},
    write::{DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions, WriterOptions, ZipWriter},
};

fn fixture() -> Vec<u8> {
    let mut writer =
        ZipWriter::new(Cursor::new(Vec::new()), WriterOptions { comment: b"archive-note", ..WriterOptions::default() })
            .unwrap();
    for (name, mut data) in [("same", b"first".as_slice()), ("same", b"second"), ("last", b"last")] {
        let len = data.len() as u64;
        writer
            .add_file(
                EntryOptions {
                    name: EntryName::Utf8(name),
                    method: Method::Stored,
                    modified: DosDateTime::default(),
                    extended_mtime: None,
                    permissions: Permissions::new(0o640).unwrap(),
                    comment: b"member-note",
                },
                &mut data,
                InputLength::Exact(len),
            )
            .unwrap();
    }
    writer.finish().unwrap().sink.into_inner()
}

fn signature(bytes: &[u8], magic: &[u8]) -> Vec<usize> {
    bytes.windows(magic.len()).enumerate().filter_map(|(i, b)| (b == magic).then_some(i)).collect()
}

#[test]
fn member_damage_is_partial_and_later_good_members_survive() {
    for local_header in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("old.zip");
        let target = root.path().join("fixed.zip");
        let mut old = fixture();
        let locals = signature(&old, b"PK\x03\x04");
        if local_header {
            old[locals[1]] = 0;
        } else {
            let at = old.windows(6).position(|b| b == b"second").unwrap();
            old[at] ^= 1;
        }
        fs::write(&source, &old).unwrap();
        let report = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap().recover();
        assert!(matches!(&report.outcome, Ok(RecoveryOutcome::Published(_))), "{:?}", report.outcome);
        assert!(matches!(report.entries[0].outcome, MemberRecovery::Verified { .. }));
        assert!(matches!(report.entries[1].outcome, MemberRecovery::Omitted(_)));
        assert!(matches!(report.entries[2].outcome, MemberRecovery::Verified { .. }));
        let archive = ReadSession::open(&target).unwrap();
        assert_eq!(archive.metadata().len(), 2);
        assert_eq!(archive.metadata().entries().next().unwrap().raw_name(), b"same");
        assert_eq!(archive.metadata().entries().nth(1).unwrap().raw_name(), b"last");
        assert_eq!(archive.metadata().raw_comment(), b"archive-note");
        assert_eq!(fs::read(source).unwrap(), old);
    }
}

#[test]
fn signed_descriptor_repair_publishes_independently_readable_bytes() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("old.zip");
    let target = root.path().join("fixed.zip");
    let old = include_bytes!("../src/zip/rewrite/layout/fixtures/signed-descriptor-bad-crc-with-central.zip");
    fs::write(&source, old).unwrap();
    let report = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap().recover();
    assert!(matches!(&report.outcome, Ok(RecoveryOutcome::Published(_))), "{:?}", report.outcome);
    assert!(matches!(report.entries[0].outcome, MemberRecovery::Verified { descriptor_repaired: true }));
    assert!(matches!(report.entries[1].outcome, MemberRecovery::Verified { descriptor_repaired: false }));
    let output = fs::read(target).unwrap();
    assert_eq!(&output[483..499], &[80, 75, 7, 8, 147, 68, 241, 76, 184, 1, 0, 0, 184, 1, 0, 0]);
    assert_eq!(fs::read(source).unwrap(), old);
}

#[test]
fn central_order_and_duplicate_occurrences_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("old.zip");
    let target = root.path().join("fixed.zip");
    let mut old = fixture();
    let central = signature(&old, b"PK\x01\x02");
    let a = old[central[0]..central[1]].to_vec();
    let b = old[central[1]..central[2]].to_vec();
    assert_eq!(a.len(), b.len());
    old[central[0]..central[1]].copy_from_slice(&b);
    old[central[1]..central[2]].copy_from_slice(&a);
    fs::write(&source, &old).unwrap();
    let report = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap().recover();
    assert!(matches!(&report.outcome, Ok(RecoveryOutcome::Published(_))), "{:?}", report.outcome);
    assert_eq!(report.entries.iter().map(|e| e.source_ordinal).collect::<Vec<_>>(), vec![0, 1, 2]);
    let archive = ReadSession::open(&target).unwrap();
    assert_eq!(archive.metadata().len(), 3);
    assert_eq!(archive.metadata().entries().next().unwrap().size(), 6);
    assert_eq!(archive.metadata().entries().nth(1).unwrap().size(), 5);
    assert_eq!(fs::read(source).unwrap(), old);
}

#[test]
fn all_omitted_no_output_and_conflicting_destination_untouched() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("old.zip");
    let target = root.path().join("fixed.zip");
    let mut old = fixture();
    for at in signature(&old, b"PK\x03\x04") {
        old[at] = 0;
    }
    fs::write(&source, &old).unwrap();
    let report = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap().recover();
    assert!(matches!(report.outcome, Ok(RecoveryOutcome::NoMembers { .. })));
    assert_eq!(report.entries.len(), 3);
    assert!(!target.exists());
    fs::write(&target, b"keep").unwrap();
    assert!(RecoveryPlan::open(&source, &target, RecoveryOptions::default()).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep");
    assert!(RecoveryPlan::open(&source, &source, RecoveryOptions::default()).is_err());
    assert_eq!(fs::read(source).unwrap(), old);
}

#[test]
fn known_limits_and_cancellation_stop_before_staging() {
    use zipfast::zip::create::{CreateError, CreateLimit, Publication};
    use zipfast::zip::rewrite::RewriteError;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("old.zip");
    let target = root.path().join("fixed.zip");
    let old = fixture();
    fs::write(&source, &old).unwrap();
    let mut options = RecoveryOptions::default();
    options.limits.common.verification_decoded_bytes = 5;
    let report = RecoveryPlan::open(&source, &target, options).unwrap().recover();
    let failure = report.outcome.unwrap_err();
    assert!(matches!(
        failure.cause,
        RewriteError::Infrastructure(CreateError::Limit(CreateLimit::VerificationDecodedBytes))
    ));
    assert_eq!(failure.publication, Publication::NotPublished);
    assert_eq!(failure.usage.source_payload.decoded_bytes, 5);
    assert_eq!(failure.usage.common.stage_attempts, 0);
    assert_eq!(report.entries.len(), 1);
    assert!(!target.exists());
    let options = RecoveryOptions::default();
    let cancel = options.cancel.clone();
    let plan = RecoveryPlan::open(&source, &target, options).unwrap();
    cancel.cancel();
    let failure = plan.recover().outcome.unwrap_err();
    assert!(matches!(failure.cause, RewriteError::Infrastructure(CreateError::Canceled)));
    assert_eq!(failure.usage.common.stage_attempts, 0);
    assert_eq!(fs::read(source).unwrap(), old);
}

#[test]
fn ambiguous_offsets_refuse_but_member_local_damage_keeps_later_rows() {
    for case in [
        "duplicate-offset",
        "crossing-size",
        "local-name",
        "directory-payload",
        "encrypted",
        "unsupported",
        "symlink",
        "device",
    ] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("old.zip");
        let target = root.path().join("fixed.zip");
        let mut old = fixture();
        let central = signature(&old, b"PK\x01\x02");
        match case {
            "duplicate-offset" => old[central[1] + 42..central[1] + 46].copy_from_slice(&0u32.to_le_bytes()),
            "crossing-size" => {
                for at in [18, 22, central[0] + 20, central[0] + 24] {
                    old[at..at + 4].copy_from_slice(&1000u32.to_le_bytes());
                }
            }
            "symlink" | "device" => {
                let kind = if case == "symlink" { 0o120777u32 } else { 0o020600u32 };
                old[central[0] + 5] = 3;
                old[central[0] + 38..central[0] + 42].copy_from_slice(&(kind << 16).to_le_bytes());
            }
            "local-name" => old[30] ^= 1,
            "directory-payload" => {
                old[30..34].copy_from_slice(b"bad/");
                old[central[0] + 46..central[0] + 50].copy_from_slice(b"bad/");
            }
            "encrypted" => {
                old[6] |= 1;
                old[central[0] + 8] |= 1;
            }
            "unsupported" => {
                old[8..10].copy_from_slice(&12u16.to_le_bytes());
                old[central[0] + 10..central[0] + 12].copy_from_slice(&12u16.to_le_bytes());
            }
            _ => unreachable!(),
        }
        fs::write(&source, &old).unwrap();
        let report = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap().recover();
        if case == "duplicate-offset" {
            assert!(report.outcome.is_err());
            assert!(!target.exists());
        } else {
            assert!(matches!(&report.outcome, Ok(RecoveryOutcome::Published(_))), "{case}: {:?}", report.outcome);
            assert!(matches!(report.entries[0].outcome, MemberRecovery::Omitted(_)), "{case}");
            assert!(matches!(report.entries[1].outcome, MemberRecovery::Verified { .. }), "{case}");
            assert!(matches!(report.entries[2].outcome, MemberRecovery::Verified { .. }), "{case}");
        }
        assert_eq!(fs::read(source).unwrap(), old);
    }
}

#[test]
fn source_aliases_and_changed_source_are_never_replaced() {
    use zipfast::zip::rewrite::RewriteError;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("old.zip");
    let alias = root.path().join("alias.zip");
    let target = root.path().join("fixed.zip");
    let old = fixture();
    fs::write(&source, &old).unwrap();
    fs::hard_link(&source, &alias).unwrap();
    assert!(RecoveryPlan::open(&source, &alias, RecoveryOptions::default()).is_err());
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert!(RecoveryPlan::open(&source, &alias, RecoveryOptions::default()).is_err());
    assert!(RecoveryPlan::open(&alias, &target, RecoveryOptions::default()).is_err());
    let case_alias = root.path().join("OLD.ZIP");
    if case_alias.exists() {
        assert!(RecoveryPlan::open(&source, &case_alias, RecoveryOptions::default()).is_err());
    }
    let plan = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap();
    fs::rename(&source, root.path().join("held.zip")).unwrap();
    fs::write(&source, &old).unwrap();
    let failure = plan.recover().outcome.unwrap_err();
    assert!(matches!(failure.cause, RewriteError::SourceChanged));
    assert!(!target.exists());
    assert_eq!(fs::read(source).unwrap(), old);
}

fn raw_pair(packed: &[u8], decoded: u32, method: u16, crc: u32) -> Vec<u8> {
    fn u16(out: &mut Vec<u8>, n: u16) {
        out.extend(n.to_le_bytes());
    }
    fn u32(out: &mut Vec<u8>, n: u32) {
        out.extend(n.to_le_bytes());
    }
    let mut local = Vec::new();
    let mut central = Vec::new();
    for (name, payload, size, method, crc) in [
        (b"raw-\xff".as_slice(), packed, decoded, method, crc),
        (b"tail".as_slice(), b"after".as_slice(), 5, 0, crc32fast::hash(b"after")),
    ] {
        let offset = local.len() as u32;
        let extra = b"\xfe\xca\x02\x00xy";
        let comment = b"\xff-note";
        u32(&mut local, 0x04034b50);
        for n in [20, 0, method, 0, 33] {
            u16(&mut local, n);
        }
        for n in [crc, payload.len() as u32, size] {
            u32(&mut local, n);
        }
        u16(&mut local, name.len() as u16);
        u16(&mut local, extra.len() as u16);
        local.extend(name);
        local.extend(extra);
        local.extend(payload);
        u32(&mut central, 0x02014b50);
        for n in [3 << 8 | 20, 20, 0, method, 0, 33] {
            u16(&mut central, n);
        }
        for n in [crc, payload.len() as u32, size] {
            u32(&mut central, n);
        }
        for n in [name.len() as u16, extra.len() as u16, comment.len() as u16, 0, 0] {
            u16(&mut central, n);
        }
        u32(&mut central, 0o100640 << 16);
        u32(&mut central, offset);
        central.extend(name);
        central.extend(extra);
        central.extend(comment);
    }
    let offset = local.len() as u32;
    let size = central.len() as u32;
    local.extend(central);
    u32(&mut local, 0x06054b50);
    for n in [0, 0, 2, 2] {
        u16(&mut local, n);
    }
    u32(&mut local, size);
    u32(&mut local, offset);
    u16(&mut local, 2);
    local.extend(b"\xffa");
    local
}

#[test]
fn exact_deflate_framing_and_empty_files_keep_raw_metadata() {
    use std::io::Write;
    fn compress(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }
    let data = b"deflate verification data";
    let packed = compress(data);
    let mut trailing = packed.clone();
    trailing.push(0);
    let mut concatenated = packed.clone();
    concatenated.extend(&packed);
    let fixtures = [
        (packed.clone(), data.len() as u32, 8, crc32fast::hash(data), true),
        (packed[..packed.len() - 1].to_vec(), data.len() as u32, 8, crc32fast::hash(data), false),
        (trailing, data.len() as u32, 8, crc32fast::hash(data), false),
        (concatenated, 2 * data.len() as u32, 8, crc32fast::hash(data), false),
        (packed.clone(), data.len() as u32 - 1, 8, crc32fast::hash(data), false),
        (packed, data.len() as u32, 8, crc32fast::hash(data) ^ 1, false),
        (compress(b""), 0, 8, 0, true),
        (Vec::new(), 0, 0, 0, true),
    ];
    for (packed, decoded, method, crc, good) in fixtures {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("old.zip");
        let target = root.path().join("fixed.zip");
        let old = raw_pair(&packed, decoded, method, crc);
        fs::write(&source, &old).unwrap();
        let report = RecoveryPlan::open(&source, &target, RecoveryOptions::default()).unwrap().recover();
        assert!(matches!(&report.outcome, Ok(RecoveryOutcome::Published(_))), "{:?}", report.outcome);
        assert_eq!(matches!(report.entries[0].outcome, MemberRecovery::Verified { .. }), good);
        assert!(matches!(report.entries[1].outcome, MemberRecovery::Verified { .. }));
        let read = ReadSession::open(&target).unwrap();
        let metadata = read.metadata();
        assert_eq!(metadata.raw_comment(), b"\xffa");
        assert_eq!(metadata.len(), if good { 2 } else { 1 });
        if good {
            let first = metadata.entries().next().unwrap();
            assert_eq!(first.raw_name(), b"raw-\xff");
            assert_eq!(first.raw_comment(), b"\xff-note");
            assert_eq!(first.header().external_attributes, 0o100640 << 16);
        }
        assert_eq!(fs::read(source).unwrap(), old);
    }
}
