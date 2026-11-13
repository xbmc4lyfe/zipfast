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
use std::io::{self, Write};

use common::*;
use zipfast::error::{IoOperation, RarFailure, RarResource};
use zipfast::extract::{Cancellation, RarOutcome, RarOutput};
use zipfast::rar5::session::{RarPrintOptions, RarSession, RarSessionOptions};

#[test]
fn prints_only_verified_members_in_archive_order() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.rar");
    let good = FileSpec::new("good", b"first");
    let bad = FileSpec::new("bad", b"corrupt");
    let later = FileSpec::new("later", b"last");
    fs::write(
        &path,
        archive_with(&[(good, crc32fast::hash(b"first")), (bad, 0), (later, crc32fast::hash(b"last"))], false),
    )
    .unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut output = Vec::new();
    let mut events = Vec::new();
    let summary = session
        .print_selected(&selected, &mut output, &RarPrintOptions::default(), |event| {
            events.push(event.entry.order);
            match event.entry.order {
                1 => assert!(matches!(event.outcome, RarOutcome::Failed(_))),
                _ => assert!(matches!(event.outcome, RarOutcome::Verified { output: RarOutput::Printed, .. })),
            }
        })
        .unwrap();
    assert_eq!(events, [0, 1, 2]);
    assert_eq!(output, b"firstlast");
    assert_eq!((summary.matched, summary.files, summary.failed, summary.bytes), (3, 2, 1, 9));
}

#[test]
fn spool_limits_charge_actual_unknown_length_bytes_and_reset_between_members() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.rar");
    let first = FileSpec { size_unknown: true, ..FileSpec::new("a", b"1234") };
    let second = FileSpec { size_unknown: true, ..FileSpec::new("b", b"5678") };
    fs::write(&path, archive(&[first, second])).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut output = Vec::new();
    let mut options = RarPrintOptions { member_spool_bytes: 4, live_spool_bytes: 4, ..RarPrintOptions::default() };
    session.print_selected(&selected, &mut output, &options, |_| {}).unwrap();
    assert_eq!(output, b"12345678");
    for resource in [RarResource::PrintMemberSpoolBytes, RarResource::PrintLiveSpoolBytes] {
        output.clear();
        options.member_spool_bytes = if matches!(resource, RarResource::PrintMemberSpoolBytes) { 3 } else { 4 };
        options.live_spool_bytes = if matches!(resource, RarResource::PrintLiveSpoolBytes) { 3 } else { 4 };
        let error = session.print_selected(&selected, &mut output, &options, |_| {}).unwrap_err();
        assert!(
            matches!(error.failure.as_ref(), RarFailure::Limit { resource: actual, requested: Some(4), allowed: Some(3) }
            if std::mem::discriminant(actual) == std::mem::discriminant(&resource))
        );
        assert_eq!((error.partial.files, error.partial.failed, error.partial_member_bytes), (0, 1, 0));
        assert!(output.is_empty());
    }
}

struct PrefixWriter {
    bytes: Vec<u8>,
    cancel: Option<Cancellation>,
}
impl Write for PrefixWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let allowed = 6usize.saturating_sub(self.bytes.len()).min(bytes.len());
        if allowed == 0 {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.bytes.extend_from_slice(&bytes[..allowed]);
        if self.bytes.len() == 6
            && let Some(cancel) = &self.cancel
        {
            cancel.cancel();
        }
        Ok(allowed)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn terminal_copy_errors_preserve_completed_and_current_member_counts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.rar");
    fs::write(
        &path,
        archive(&[FileSpec::new("a", b"first"), FileSpec::new("b", b"second"), FileSpec::new("c", b"last")]),
    )
    .unwrap();
    for cancel_copy in [false, true] {
        let cancel = Cancellation::default();
        let mut session =
            RarSession::open(&path, None, RarSessionOptions { cancel: cancel.clone(), ..Default::default() }).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut writer = PrefixWriter { bytes: Vec::new(), cancel: cancel_copy.then_some(cancel) };
        let mut events = Vec::new();
        let error = session
            .print_selected(&selected, &mut writer, &RarPrintOptions::default(), |event| {
                events.push(event.entry.order);
            })
            .unwrap_err();
        assert_eq!(events, [0, 1]);
        assert_eq!(writer.bytes, b"firsts");
        assert_eq!(
            (error.partial.files, error.partial.failed, error.partial.bytes, error.partial_member_bytes),
            (1, 1, 5, 1)
        );
        if cancel_copy {
            assert!(matches!(error.failure.as_ref(), RarFailure::Canceled));
        } else {
            assert!(
                matches!(error.failure.as_ref(), RarFailure::PrintWriter { operation: IoOperation::Write, offset: 1, source }
                if source.kind() == io::ErrorKind::BrokenPipe)
            );
        }
    }
}

#[test]
fn empty_and_checksumless_members_keep_evidence_and_directories_report_ineligibility() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.rar");
    let empty = FileSpec { no_crc: true, ..FileSpec::new("empty", b"") };
    let dir = FileSpec { dir: true, ..FileSpec::new("dir", b"") };
    let data = FileSpec { no_crc: true, size_unknown: true, ..FileSpec::new("data", b"proof") };
    fs::write(&path, archive(&[empty, dir, data])).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let first_two = session.select(|member| member.ordinal() < 2).unwrap();
    let mut output = Vec::new();
    let options = RarPrintOptions {
        member_spool_bytes: 0,
        live_spool_bytes: 0,
        temp_dir: Some(temp.path().join("missing")),
        ..RarPrintOptions::default()
    };
    let summary = session
        .print_selected(&first_two, &mut output, &options, |event| match &event.outcome {
            RarOutcome::Verified { bytes: 0, checks, output: RarOutput::Printed } => {
                assert!(checks.size_checked);
                assert!(!checks.crc32_checked && !checks.blake2sp_checked);
            }
            RarOutcome::Failed(failure) => assert!(matches!(
                failure.as_ref(),
                RarFailure::Unsupported(zipfast::error::RarUnsupported::PrintDirectory)
            )),
            other => panic!("{other:?}"),
        })
        .unwrap();
    assert_eq!((summary.files, summary.failed, summary.bytes), (1, 1, 0));
    assert!(output.is_empty());

    let selected = session.select(|member| member.ordinal() == 2).unwrap();
    let summary = session
        .print_selected(&selected, &mut output, &RarPrintOptions::default(), |event| {
            assert!(matches!(event.outcome, RarOutcome::Verified { checks, .. }
            if !checks.size_checked && !checks.crc32_checked && !checks.blake2sp_checked));
        })
        .unwrap();
    assert_eq!((summary.files, summary.bytes), (1, 5));
    assert_eq!(output, b"proof");
}

#[test]
fn writer_flush_failure_and_interrupted_attempts_are_terminal() {
    struct Writer {
        bytes: Vec<u8>,
        interrupt: bool,
    }
    impl Write for Writer {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.interrupt { Err(io::ErrorKind::Interrupted.into()) } else { self.bytes.write(data) }
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.rar");
    fs::write(&path, archive(&[FileSpec::new("data", b"proof")])).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    for interrupt in [false, true] {
        let mut writer = Writer { bytes: Vec::new(), interrupt };
        let options = RarPrintOptions { io_attempts: 7, ..RarPrintOptions::default() };
        let error = session.print_selected(&selected, &mut writer, &options, |_| {}).unwrap_err();
        assert_eq!((error.partial.files, error.partial.bytes, error.partial.failed), (0, 0, 1));
        if interrupt {
            assert!(matches!(
                error.failure.as_ref(),
                RarFailure::Limit { resource: RarResource::PrintIoAttempts, requested: Some(8), allowed: Some(7) }
            ));
            assert!(writer.bytes.is_empty());
            assert_eq!(error.partial_member_bytes, 0);
        } else {
            assert!(matches!(error.failure.as_ref(), RarFailure::PrintWriter {
                operation: IoOperation::Flush, offset: 5, source
            } if source.kind() == io::ErrorKind::BrokenPipe));
            assert_eq!(writer.bytes, b"proof");
            assert_eq!(error.partial_member_bytes, 5);
        }
    }
}

#[test]
fn only_selected_solid_members_use_the_spool() {
    use zipfast::rar5::testenc::{Op, tuned_blocks};

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.rar");
    let root = tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c'), Op::Lit(b'd')]], true);
    let next = tuned_blocks(&[&[Op::Match(3, 3)]], true);
    let crc = crc32fast::hash(b"bcd");
    let root_crc = crc32fast::hash(b"abcd");
    for good in [true, false] {
        let seed = FileSpec { method: 3, size: Some(4), ..FileSpec::new("root", &root) };
        let member = FileSpec { method: 3, size: Some(3), solid: true, ..FileSpec::new("next", &next) };
        fs::write(&path, archive_with(&[(seed, if good { root_crc } else { 0 }), (member, crc)], true)).unwrap();
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|member| member.ordinal() == 1).unwrap();
        let mut output = Vec::new();
        let options = RarPrintOptions { member_spool_bytes: 3, live_spool_bytes: 3, ..RarPrintOptions::default() };
        let summary = session
            .print_selected(&selected, &mut output, &options, |event| {
                assert_eq!(event.entry.order, 1);
                if good {
                    assert!(matches!(event.outcome, RarOutcome::Verified { .. }), "{event:?}");
                } else {
                    assert!(matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(
                        failure.as_ref(), RarFailure::SolidHistoryUnavailable { predecessor: Some(0), .. }
                    )));
                }
            })
            .unwrap();
        assert_eq!(output, if good { b"bcd".as_slice() } else { b"" });
        assert_eq!((summary.files, summary.failed), (u64::from(good), u64::from(!good)));
    }
}

#[test]
fn output_identity_rejects_first_and_later_volume_hard_links_without_writing() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("set.part1.rar");
    let second = temp.path().join("set.part2.rar");
    let mut bytes = archive(&[FileSpec::new("first", b"one")]);
    bytes.truncate(bytes.len() - end_block(false).len());
    bytes.extend(end_block(true));
    fs::write(&first, &bytes).unwrap();
    fs::write(&second, archive(&[FileSpec::new("second", b"two")])).unwrap();
    let mut aliases = Vec::new();
    for (index, path) in [&first, &second].into_iter().enumerate() {
        let alias = temp.path().join(format!("alias-{index}"));
        fs::hard_link(path, &alias).unwrap();
        aliases.push(fs::OpenOptions::new().append(true).open(alias).unwrap());
    }
    let before = [fs::read(&first).unwrap(), fs::read(&second).unwrap()];
    let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
    assert_eq!(session.archive().volume_count(), 2);
    for output in aliases {
        let error = session.check_output_file(&output).unwrap_err();
        assert!(matches!(error.failure.as_ref(), RarFailure::OutputAliasesInput));
        assert_eq!(error.partial.bytes, 0);
        assert_eq!(error.partial_member_bytes, 0);
    }
    assert_eq!(fs::read(&first).unwrap(), before[0]);
    assert_eq!(fs::read(&second).unwrap(), before[1]);
}

#[test]
fn output_identity_accepts_distinct_files_and_sockets_and_preserves_changes() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("archive.rar");
    fs::write(&path, archive(&[FileSpec::new("file", b"bytes")])).unwrap();
    let output = temp.path().join("output");
    fs::write(&output, b"keep").unwrap();
    let output = fs::OpenOptions::new().append(true).open(&output).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    session.check_output_file(&output).unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    let socket = fs::File::from(OwnedFd::from(socket));
    session.check_output_file(&socket).unwrap();
    fs::write(&path, b"changed source").unwrap();
    let error = session.check_output_file(&output).unwrap_err();
    assert!(matches!(error.failure.as_ref(), RarFailure::SourceChanged { .. }));
    assert_eq!(error.partial.bytes, 0);
    assert_eq!(fs::read(temp.path().join("output")).unwrap(), b"keep");
    assert!(session.check_output_file(&output).is_err());
}
