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

//! Connected public consumers for independently specified fixed RAR4 bit vectors.
//! Provenance and bit-by-bit derivation are in the shared SDD worksheet.
//! This wraps fixed bytes with headers and does not compress arbitrary data.

#![cfg(unix)]

use std::{fs, path::Path};
use zipfast::crc32::hash;
use zipfast::error::{RarFailure, RarIntegrityReason, RarResource, RarUnsupported};
use zipfast::extract::{self, Mode, Options, Overwrite, RarOutcome};
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn member(name: &[u8], packed: &[u8], expected: &[u8], version: u8, method: u8, flags: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend((packed.len() as u32).to_le_bytes());
    body.extend((expected.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(expected).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([version, method]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = block(0x74, flags | 0x8000, &body);
    bytes.extend(packed);
    bytes
}
fn archive(files: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    for file in files {
        bytes.extend(file);
    }
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}
fn fixed_archive(packed: &[u8], expected: &[u8]) -> Vec<u8> {
    archive(&[member(b"vector", packed, expected, 29, 0x33, 0)])
}
fn options(dest: &Path, mode: Mode, threads: usize) -> Options {
    Options {
        mode,
        dest: dest.to_path_buf(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(threads),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

fn verify(packed: &[u8], expected: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixed.rar");
    std::fs::write(&path, fixed_archive(packed, expected)).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    let mut events = Vec::new();
    let result = session
        .test_selected(&selection, RarDecodeLimits::default(), |event| events.push(format!("{event:?}")))
        .unwrap();
    assert_eq!((result.files, result.failed), (1, 0), "fixed version-29 LZ vector must verify. Events {events:?}");
    let mut stdout = Vec::new();
    session.print_selected(&selection, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap();
    assert_eq!(stdout, expected);
    let selected = dir.path().join("selected");
    assert_eq!(
        session
            .extract_selected(&selection, &options(&selected, Mode::Extract, 4), RarDecodeLimits::default(), |_| {})
            .unwrap()
            .files,
        1
    );
    assert_eq!(fs::read(selected.join("vector")).unwrap(), expected);
    let mut legacy = Vec::new();
    extract::SelectedEntry::open(&path, 0, None, 1 << 20)
        .unwrap()
        .read(None, |bytes| {
            legacy.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(legacy, expected);
    for threads in [1, 4] {
        let dest = dir.path().join(format!("bulk{threads}"));
        let mut checked = 0;
        let result = extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Test, threads), None, |event| {
            if let RarOutcome::Verified { checks, .. } = &event.outcome {
                assert!(checks.size_checked && checks.crc32_checked);
                checked += 1;
            }
        })
        .unwrap();
        assert_eq!((result.files, result.failed, checked), (1, 0, 1));
        assert_eq!(
            extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Extract, threads), None, |_| {}).unwrap().files,
            1
        );
        assert_eq!(fs::read(dest.join("vector")).unwrap(), expected);
    }
}

#[test]
fn literal_a() {
    verify(include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A");
}

#[test]
fn initial_delta_zero_baseline() {
    verify(include_bytes!("fixtures/rar4-lz/initial-delta-zero-baseline.packed"), b"A");
}

#[test]
fn table_reuse_delta() {
    verify(include_bytes!("fixtures/rar4-lz/table-reuse-delta.packed"), b"AA");
}

#[test]
fn code_length_nibble_zero_run() {
    verify(include_bytes!("fixtures/rar4-lz/code-length-nibble-zero-run.packed"), b"A");
}

#[test]
fn new_match_repeat_last() {
    verify(include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed"), b"AAAAAAA");
}

#[test]
fn recent_distance_repeat() {
    verify(include_bytes!("fixtures/rar4-lz/recent-distance-repeat.packed"), b"AAAAAA");
}

#[test]
fn short_distance_match() {
    verify(include_bytes!("fixtures/rar4-lz/short-distance-match.packed"), b"AAA");
}

#[test]
fn zero_length_runs() {
    verify(include_bytes!("fixtures/rar4-lz/zero-length-runs.packed"), b"A");
}

#[test]
fn previous_length_runs() {
    verify(include_bytes!("fixtures/rar4-lz/previous-length-runs.packed"), b"AP");
}

fn issue(path: &Path) -> Vec<std::sync::Arc<RarFailure>> {
    let mut session = RarSession::open(path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let mut failures = Vec::new();
    session
        .test_selected(&all, RarDecodeLimits::default(), |event| {
            if let RarOutcome::Failed(failure) = &event.outcome {
                failures.push(failure.clone());
            }
        })
        .unwrap();
    failures
}

#[test]
fn unsupported_modes_and_bad_crc_never_publish_and_later_members_reset() {
    let dir = tempfile::tempdir().unwrap();
    let good = include_bytes!("fixtures/rar4-lz/initial-delta-zero-baseline.packed");
    let cases = [
        (include_bytes!("fixtures/rar4-lz/ppm-marker.packed").as_slice(), b"AA".as_slice(), 0),
        (include_bytes!("fixtures/rar4-lz/vm-marker-after-prefix.packed").as_slice(), b"AA".as_slice(), 1),
        (include_bytes!("fixtures/rar4-lz/literal-a.packed").as_slice(), b"B".as_slice(), 2),
    ];
    for (packed, expected, case) in cases {
        let path = dir.path().join(format!("case{case}.rar"));
        fs::write(
            &path,
            archive(&[member(b"bad", packed, expected, 29, 0x33, 0), member(b"good", good, b"A", 29, 0x35, 0)]),
        )
        .unwrap();
        let failures = issue(&path);
        assert_eq!(failures.len(), 1);
        match case {
            0 => assert!(matches!(
                failures[0].as_ref(),
                RarFailure::Unsupported(RarUnsupported::Rar4Feature("PPM payload"))
            )),
            1 => assert!(matches!(
                failures[0].as_ref(),
                RarFailure::Unsupported(RarUnsupported::Rar4Feature("VM/filter payload"))
            )),
            _ => assert!(matches!(
                failures[0].as_ref(),
                RarFailure::Integrity { reason: RarIntegrityReason::FinalChecks { crc32: true, .. }, .. }
            )),
        }
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut stdout = Vec::new();
        let summary = session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap();
        assert_eq!((summary.files, summary.failed), (1, 1));
        assert_eq!(stdout, b"A");
        for threads in [1, 4] {
            let dest = dir.path().join(format!("out{case}-{threads}"));
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("bad"), b"keep").unwrap();
            let summary =
                extract::run_rar_with_outcomes(&path, &options(&dest, Mode::Extract, threads), None, |_| {}).unwrap();
            assert_eq!((summary.files, summary.failed), (1, 1));
            assert_eq!(fs::read(dest.join("bad")).unwrap(), b"keep");
            assert_eq!(fs::read(dest.join("good")).unwrap(), b"A");
            assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
        }
        let dest = dir.path().join(format!("selected{case}"));
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("bad"), b"keep").unwrap();
        let summary = session
            .extract_selected(&all, &options(&dest, Mode::Extract, 4), RarDecodeLimits::default(), |_| {})
            .unwrap();
        assert_eq!((summary.files, summary.failed), (1, 1));
        assert_eq!(fs::read(dest.join("bad")).unwrap(), b"keep");
        assert_eq!(fs::read(dest.join("good")).unwrap(), b"A");
        assert_eq!(fs::read_dir(dest).unwrap().count(), 2);
    }
}

#[test]
fn exact_selected_limits_window_and_spool_failures_are_typed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("limits.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    fs::write(&path, fixed_archive(packed, b"A")).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let exact = RarDecodeLimits { packed_bytes: packed.len() as u64, decoded_bytes: 1, window_bytes: 65536 };
    assert_eq!(session.test_selected(&all, exact, |_| {}).unwrap().files, 1);
    for (limits, resource) in [
        (RarDecodeLimits { packed_bytes: packed.len() as u64 - 1, ..exact }, RarResource::SelectedPackedBytes),
        (RarDecodeLimits { decoded_bytes: 0, ..exact }, RarResource::SelectedDecodedBytes),
    ] {
        let error = session.test_selected(&all, limits, |_| {}).unwrap_err();
        assert!(
            matches!(error.failure.as_ref(),RarFailure::Limit{resource:actual,..} if std::mem::discriminant(actual)==std::mem::discriminant(&resource))
        );
    }
    let mut failures = Vec::new();
    assert_eq!(
        session
            .test_selected(&all, RarDecodeLimits { window_bytes: 65535, ..exact }, |event| {
                if let RarOutcome::Failed(failure) = &event.outcome {
                    failures.push(failure.clone());
                }
            })
            .unwrap()
            .failed,
        1
    );
    assert!(matches!(
        failures[0].as_ref(),
        RarFailure::Limit { resource: RarResource::DictionarySize, requested: Some(65536), allowed: Some(65535) }
    ));
    let mut stdout = Vec::new();
    let opts = RarPrintOptions { decode: exact, member_spool_bytes: 0, ..Default::default() };
    let error = session.print_selected(&all, &mut stdout, &opts, |_| {}).unwrap_err();
    assert!(stdout.is_empty());
    assert!(matches!(error.failure.as_ref(), RarFailure::Limit { resource: RarResource::PrintMemberSpoolBytes, .. }));
}

#[test]
fn old_versions_solid_encrypted_split_and_methods_stay_excluded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("excluded.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    for (version, method, flags, label) in [
        (20, 0x33, 0, "unpack version"),
        (26, 0x33, 0, "unpack version"),
        (15, 0x33, 0, "unpack version"),
        (29, 0x36, 0, "compression method"),
        (29, 0x33, 0x10, "solid payload"),
        (29, 0x33, 4, "encrypted payload"),
        (29, 0x33, 2, "split payload"),
    ] {
        fs::write(&path, archive(&[member(b"excluded", packed, b"A", version, method, flags)])).unwrap();
        let failures = issue(&path);
        assert_eq!(failures.len(), 1);
        assert!(
            matches!(failures[0].as_ref(),RarFailure::Unsupported(RarUnsupported::Rar4Feature(actual)) if *actual==label),
            "{failures:?}"
        );
    }
}

#[test]
fn size_underflow_overflow_and_terminal_slack_follow_exact_contract() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sizes.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    for bytes in [&packed[..packed.len() - 1], packed.as_slice()] {
        verify(bytes, b"A");
    }
    for tail in [0, 255] {
        let mut bytes = packed.to_vec();
        bytes.push(tail);
        verify(&bytes, b"A");
    }
    for (bytes, expected, actual) in [
        (packed.as_slice(), b"AA".as_slice(), 1),
        (include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed").as_slice(), b"AAA".as_slice(), 4),
    ] {
        fs::write(&path, fixed_archive(bytes, expected)).unwrap();
        let failures = issue(&path);
        assert!(
            matches!(failures[0].as_ref(),RarFailure::Integrity{reason:RarIntegrityReason::DecodedSize{expected:size,actual:got},..} if *size==expected.len() as u64 && *got==actual)
        );
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let all = session.select(|_| true).unwrap();
        let mut stdout = Vec::new();
        assert_eq!(session.print_selected(&all, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap().failed, 1);
        assert!(stdout.is_empty());
    }
    verify(&[128], b"");
}

#[test]
fn checked_output_aliases_and_source_changes_keep_typed_precedence() {
    use std::io::{self, Write};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.rar");
    let bytes = fixed_archive(include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A");
    fs::write(&path, &bytes).unwrap();
    let alias = dir.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    let output = fs::OpenOptions::new().append(true).open(&alias).unwrap();
    assert!(matches!(session.check_output_file(&output).unwrap_err().failure.as_ref(), RarFailure::OutputAliasesInput));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    struct BadSink {
        source: std::path::PathBuf,
    }
    impl Write for BadSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            let source = fs::OpenOptions::new().append(true).open(&self.source)?;
            source.set_len(0)?;
            Err(io::Error::from_raw_os_error(libc::ENOSPC))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let failure = session
        .print_selected(&all, &mut BadSink { source: path.clone() }, &RarPrintOptions::default(), |_| {})
        .unwrap_err();
    assert!(
        matches!(failure.failure.as_ref(),RarFailure::PrintWriter{source,..} if source.raw_os_error()==Some(libc::ENOSPC))
    );
    let failure = session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap_err();
    assert!(matches!(failure.failure.as_ref(), RarFailure::SourceChanged { .. }));
}

#[test]
fn cancellation_and_protected_archive_destination_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("archive.rar");
    let packed = include_bytes!("fixtures/rar4-lz/literal-a.packed");
    let bytes = archive(&[member(b"archive.rar", packed, b"A", 29, 0x33, 0)]);
    fs::write(&path, &bytes).unwrap();
    for threads in [1, 4] {
        let result =
            extract::run_rar_with_outcomes(&path, &options(dir.path(), Mode::Extract, threads), None, |_| {}).unwrap();
        assert_eq!((result.files, result.failed), (0, 1));
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let all = session.select(|_| true).unwrap();
    assert_eq!(
        session
            .extract_selected(&all, &options(dir.path(), Mode::Extract, 4), RarDecodeLimits::default(), |_| {})
            .unwrap()
            .failed,
        1
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let cancel = extract::Cancellation::default();
    let mut session =
        RarSession::open(&path, None, RarSessionOptions { cancel: cancel.clone(), ..Default::default() }).unwrap();
    let all = session.select(|_| true).unwrap();
    cancel.cancel();
    assert!(matches!(
        session.test_selected(&all, RarDecodeLimits::default(), |_| {}).unwrap_err().failure.as_ref(),
        RarFailure::Canceled
    ));
}

fn legacy_unsupported(packed: &[u8], label: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unsupported.rar");
    fs::write(&path, fixed_archive(packed, b"AA")).unwrap();
    let failures = issue(&path);
    assert_eq!(failures.len(), 1);
    assert!(matches!(failures[0].as_ref(),
        RarFailure::Unsupported(RarUnsupported::Rar4Feature(actual)) if *actual == label));
    let mut provisional = Vec::new();
    let error = extract::SelectedEntry::open(&path, 0, None, 1 << 20)
        .unwrap()
        .read(None, |bytes| {
            provisional.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap_err();
    assert!(provisional.is_empty());
    assert_eq!(error.to_string(), format!("unsupported: {label}"));
    assert!(matches!(error, zipfast::error::Error::Unsupported(actual) if actual == label));
}

#[test]
fn ppm_legacy_error_is_unsupported() {
    legacy_unsupported(include_bytes!("fixtures/rar4-lz/ppm-marker.packed"), "PPM payload");
}

#[test]
fn vm_legacy_error_is_unsupported() {
    legacy_unsupported(include_bytes!("fixtures/rar4-lz/vm-marker-after-prefix.packed"), "VM/filter payload");
}
