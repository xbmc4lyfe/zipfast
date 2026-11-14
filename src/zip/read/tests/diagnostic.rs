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

use super::super::*;
use super::fixture::Member;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
struct Sink {
    fd: UnixStream,
    bytes: Vec<u8>,
    calls: usize,
    fail: usize,
    interrupted: usize,
    zero: bool,
}
impl Sink {
    fn new() -> Self {
        let (fd, peer) = UnixStream::pair().unwrap();
        drop(peer);
        Self { fd, bytes: Vec::new(), calls: 0, fail: usize::MAX, interrupted: 0, zero: false }
    }
}
impl AsFd for Sink {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.interrupted > 0 {
            self.interrupted -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.calls == self.fail {
            return if self.zero { Ok(0) } else { Err(io::ErrorKind::BrokenPipe.into()) };
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Observer<'a> {
    out: &'a mut Sink,
    calls: &'a mut usize,
    swallow: bool,
}
impl ZipRunObserver for Observer<'_> {
    fn prepare(&mut self, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
        scope.admit_sinks(None, Some(self.out))?;
        Ok(())
    }
    fn observe(&mut self, _event: ZipRunEvent<'_>, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
        *self.calls += 1;
        let result =
            scope.emit(ZipDiagnosticSink::Stderr, self.out, |_, writer| writer.write_fmt(format_args!("event\n")));
        if !self.swallow {
            result?;
        }
        Ok(())
    }
}
#[test]
fn actual_socket_admission_and_first_middle_final_write_faults_stop() {
    for fail in 1..=3 {
        for swallow in [false, true] {
            let (_file, mut session, options, mut context) =
                super::run::setup(&[Member::stored(b"a", b"a"), Member::stored(b"b", b"b")]);
            let mut sink = Sink::new();
            sink.fail = fail;
            let mut calls = 0;
            let error = session
                .run_with_context(
                    &options,
                    Some("pw"),
                    &Cancellation::default(),
                    &mut context,
                    Observer { out: &mut sink, calls: &mut calls, swallow },
                )
                .unwrap_err();
            assert_eq!((calls, sink.calls), (fail, fail));
            assert!(error.diagnostic_fault().is_some());
            assert_eq!(error.partial_run().unwrap().diagnostic_usage().accepted_bytes, ((fail - 1) * 6) as u128);
        }
    }
}
#[test]
fn finite_interrupted_and_zero_writes() {
    for interrupted in [16, 17] {
        let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
        let mut sink = Sink::new();
        sink.interrupted = interrupted;
        let mut calls = 0;
        let result = session.run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Observer { out: &mut sink, calls: &mut calls, swallow: false },
        );
        assert_eq!(result.is_ok(), interrupted == 16);
        if interrupted == 17 {
            assert_eq!((calls, sink.calls), (1, 17));
        }
    }
    let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let mut sink = Sink::new();
    sink.fail = 1;
    sink.zero = true;
    let mut calls = 0;
    let error = session
        .run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Observer { out: &mut sink, calls: &mut calls, swallow: false },
        )
        .unwrap_err();
    assert!(
        matches!(error.diagnostic_fault(),Some(ZipSinkFault::Io{error,..})if error.kind()==io::ErrorKind::WriteZero)
    );
    assert_eq!(calls, 1);
}
#[test]
fn terminal_phase_safe_socket_and_regular_refusal() {
    let mut sink = Sink::new();
    let usage = diagnostic::terminal(&mut sink, &Cancellation::default(), format_args!("fatal\n")).unwrap();
    assert_eq!(usage.metadata_attempts, 3);
    assert_eq!(usage.accepted_bytes, 6);
    let mut file = tempfile::tempfile().unwrap();
    let error = diagnostic::terminal(&mut file, &Cancellation::default(), format_args!("unsafe\n")).unwrap_err();
    assert_eq!(error.usage.metadata_attempts, 1);
    assert_eq!(file.metadata().unwrap().len(), 0);
}
#[test]
fn listing_metadata_is_constant_for_100k_actual_rows() {
    let one = super::fixture::build(&[Member::stored(b"x", b"")], &[0], b"", b"", false).bytes;
    let end = one.len() - 22;
    let start = u32::from_le_bytes(one[end + 16..end + 20].try_into().unwrap()) as usize;
    let mut bytes = one[..start].to_vec();
    for _ in 0..100_000 {
        bytes.extend_from_slice(&one[start..end]);
    }
    let size = bytes.len() - start;
    let zip64 = bytes.len();
    bytes.extend_from_slice(&0x06064b50u32.to_le_bytes());
    bytes.extend_from_slice(&44u64.to_le_bytes());
    for n in [45u16, 45] {
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    for n in [0u32, 0] {
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    for n in [100_000u64, 100_000, size as u64, start as u64] {
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    bytes.extend_from_slice(&0x07064b50u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&(zip64 as u64).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x06054b50u32.to_le_bytes());
    for n in [0u16, 0, u16::MAX, u16::MAX] {
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    bytes.extend_from_slice(&(size as u32).to_le_bytes());
    bytes.extend_from_slice(&(start as u32).to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    drop(bytes);
    let mut session = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap();
    let mut sink = Sink::new();
    let cancel = Cancellation::default();
    let (rows, usage, run) = session
        .render_listing(&mut sink, &cancel, |entries, writer| {
            writer.write_fmt(format_args!("header\n"))?;
            let mut rows = 0;
            for entry in entries {
                writer.write_fmt(format_args!("{}\n", entry.name))?;
                rows += 1;
            }
            Ok(rows)
        })
        .unwrap();
    assert_eq!(rows, 100_000);
    assert_eq!(sink.calls, 100_001);
    assert_eq!(usage.metadata_attempts, 8);
    assert_eq!(usage.source_metadata_attempts, 6);
    assert_eq!(usage.descriptor_metadata_attempts, 2);
    println!(
        "actual listing rows={rows} source_metadata={} descriptor_metadata={} write_attempts={}",
        usage.source_metadata_attempts, usage.descriptor_metadata_attempts, usage.write_attempts
    );
    assert_eq!(run.diagnostic_source_groups, 2);
    assert_eq!(run.diagnostic_admission_operations, 2);
}
#[test]
fn listing_zero_byte_write_failure_is_ineligible_for_fallback() {
    let (_file, mut session, _, context) = super::run::setup(&[Member::stored(b"x", b"")]);
    drop(context);
    let mut sink = Sink::new();
    sink.fail = 1;
    let error = session
        .render_listing(&mut sink, &Cancellation::default(), |_, writer| writer.write_fmt(format_args!("header\n")))
        .unwrap_err();
    assert!(!error.prewrite);
    assert_eq!(error.usage.accepted_bytes, 0);
    assert_eq!(sink.calls, 1);
    assert!(error.error.diagnostic_fault().is_some());
}
#[test]
fn summary_prewrite_source_fault_visible_in_same_callback() {
    struct Change<'a> {
        path: &'a Path,
        sink: &'a mut Sink,
        calls: &'a mut usize,
    }
    impl ZipRunObserver for Change<'_> {
        fn prepare(&mut self, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            scope.admit_sinks(None, Some(self.sink))?;
            Ok(())
        }
        fn observe(&mut self, event: ZipRunEvent<'_>, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            *self.calls += 1;
            if matches!(event, ZipRunEvent::RunEnded { .. }) {
                std::fs::OpenOptions::new().append(true).open(self.path).unwrap().write_all(b"changed").unwrap();
                scope.emit(ZipDiagnosticSink::Stderr, self.sink, |status, writer| {
                    assert!(status.source_fault().is_some());
                    writer.write_fmt(format_args!("fatal\n"))
                })?;
            }
            Ok(())
        }
    }
    let (file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let mut sink = Sink::new();
    let mut calls = 0;
    let error = session
        .run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Change { path: file.path(), sink: &mut sink, calls: &mut calls },
        )
        .unwrap_err();
    assert!(error.source_change().is_some());
    assert_eq!(calls, 2);
    assert_eq!(sink.bytes, b"fatal\n");
}

#[test]
fn independent_member_write_boundary_and_source_faults_survive_postfailure_checks() {
    struct Mutate {
        fd: UnixStream,
        replacement: Option<UnixStream>,
        path: std::path::PathBuf,
    }
    impl AsFd for Mutate {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }
    impl Write for Mutate {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            std::fs::OpenOptions::new().append(true).open(&self.path)?.write_all(b"changed")?;
            self.fd = self.replacement.take().unwrap();
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Render(Mutate);
    impl ZipRunObserver for Render {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(&self.0))?;
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.emit(ZipDiagnosticSink::Stderr, &mut self.0, |_, w| w.write_fmt(format_args!("fault\n")))?;
            Ok(())
        }
    }
    let mut bad = Member::stored(b"bad", b"bad");
    bad.crc = Some(1);
    let (file, mut session, options, mut context) = super::run::setup(&[bad]);
    let (fd, _peer) = UnixStream::pair().unwrap();
    let (replacement, _peer2) = UnixStream::pair().unwrap();
    let error = session
        .run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Render(Mutate { fd, replacement: Some(replacement), path: file.path().to_path_buf() }),
        )
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Integrity { .. })));
    assert!(error.diagnostic_fault().is_some());
    assert!(matches!(error.diagnostic_boundary_fault(), Some(DiagnosticBoundaryFault::DescriptorChanged)));
    assert!(error.source_change().is_some());
    assert_eq!(error.kind(), ZipReadErrorKind::SourceChanged);
    assert_eq!(error.partial_run().unwrap().failed(), 1);
}
#[test]
fn swallowed_and_foreign_action_recorded_tokens_do_not_authorize_more_work() {
    struct Capture<'a> {
        file: &'a File,
        token: &'a mut Option<ZipDiagnosticStop>,
    }
    impl ZipRunObserver for Capture<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            *self.token = Some(s.admit_sinks(Some(self.file), None).unwrap_err());
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, _: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            Ok(())
        }
    }
    let (file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let mut token = None;
    session
        .run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Capture { file: file.as_file(), token: &mut token },
        )
        .unwrap_err();
    assert_eq!(context.run_usage().records, 0);
    struct Replay(Option<ZipDiagnosticStop>);
    impl ZipRunObserver for Replay {
        fn prepare(&mut self, _: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            Err(self.0.take().unwrap().into())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, _: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            Ok(())
        }
    }
    let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let error = session
        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, Replay(token))
        .unwrap_err();
    assert!(matches!(
        error.diagnostic_boundary_fault(),
        Some(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan))
    ));
    assert_eq!(context.run_usage().records, 0);
}
#[test]
fn two_actual_writer_types_and_unused_descriptor_admission() {
    struct Two<'a> {
        regular: &'a mut File,
        socket: &'a mut Sink,
    }
    impl ZipRunObserver for Two<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(Some(self.regular), Some(self.socket))?;
            Ok(())
        }
        fn observe(&mut self, e: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            if matches!(e, ZipRunEvent::RunEnded { .. }) {
                s.emit(ZipDiagnosticSink::Stdout, self.regular, |_, w| w.write_fmt(format_args!("end\n")))?;
            } else {
                s.emit(ZipDiagnosticSink::Stderr, self.socket, |_, w| w.write_fmt(format_args!("member\n")))?;
            }
            Ok(())
        }
    }
    let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let mut regular = tempfile::tempfile().unwrap();
    let mut socket = Sink::new();
    let report = session
        .run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Two { regular: &mut regular, socket: &mut socket },
        )
        .unwrap();
    assert_eq!(report.diagnostic_usage().accepted_bytes, 11);
    assert_eq!(regular.metadata().unwrap().len(), 4);
}
#[test]
fn native_fifo_tty_and_nonterminal_character_classification() {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let root = tempfile::tempdir().unwrap();
    let path = std::ffi::CString::new(root.path().join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    assert!(fd >= 0);
    let mut fifo = unsafe { File::from_raw_fd(fd) };
    let usage = diagnostic::terminal(&mut fifo, &Cancellation::default(), format_args!("fifo\n")).unwrap();
    assert_eq!(usage.metadata_attempts, 3);
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        },
        0
    );
    let _master = unsafe { File::from_raw_fd(master) };
    let mut slave = unsafe { File::from_raw_fd(slave) };
    let usage = diagnostic::terminal(&mut slave, &Cancellation::default(), format_args!("tty\n")).unwrap();
    assert_eq!(usage.metadata_attempts, 6);
    let mut null = std::fs::OpenOptions::new().write(true).open("/dev/null").unwrap();
    let error = diagnostic::terminal(&mut null, &Cancellation::default(), format_args!("refused\n")).unwrap_err();
    assert_eq!(error.usage.accepted_bytes, 0);
    assert_eq!(error.usage.metadata_attempts, 2);
    assert!(null.as_raw_fd() >= 0);
}

#[test]
fn actual_event_category_counts_exact_one_under_zero_and_overflow() {
    for limits in [(6, 5), (5, 5), (6, 4), (0, 0)] {
        let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
        let mut sink = Sink::new();
        let mut calls = 0;
        budget::DIAGNOSTIC_BOUNDS.with(|s| s.set(Some(limits)));
        let result = session.run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Observer { out: &mut sink, calls: &mut calls, swallow: false },
        );
        assert_eq!(result.is_ok(), limits == (6, 5));
        if let Ok(report) = result {
            assert_eq!(report.run_usage().diagnostic_source_groups, 6);
            assert_eq!(report.run_usage().diagnostic_admission_operations, 5);
            assert_eq!(report.diagnostic_usage().metadata_attempts, 23);
        }
    }
    let (_file, _session, _options, context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    assert!(matches!(
        context.ledger.with_state(|s| s.bind_diagnostics(u128::MAX, 0, 0, false)),
        Err(ReadFault::CounterOverflow)
    ));
}
#[test]
fn formatter_length_change_and_second_emit_are_terminal_without_extra_write() {
    struct Changing(std::cell::Cell<bool>);
    impl std::fmt::Display for Changing {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.0.replace(true) { f.write_str("changed") } else { f.write_str("x") }
        }
    }
    struct Format<'a>(&'a mut Sink);
    impl ZipRunObserver for Format<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(self.0))?;
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            let display = Changing(std::cell::Cell::new(false));
            let _ = s.emit(ZipDiagnosticSink::Stderr, self.0, |_, w| w.write_fmt(format_args!("{display}")));
            let calls = self.0.calls;
            let _ = s.emit(ZipDiagnosticSink::Stderr, self.0, |_, w| w.write_fmt(format_args!("no retry")));
            assert_eq!(self.0.calls, calls);
            Ok(())
        }
    }
    let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let mut sink = Sink::new();
    let error = session
        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, Format(&mut sink))
        .unwrap_err();
    assert!(error.diagnostic_fault().is_some());
    assert_eq!(sink.calls, 0);
}

#[test]
fn owning_terminal_pre_and_post_retired_namespace_observations() {
    struct Aware<'a>(&'a mut Sink);
    impl ZipRunObserver for Aware<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(self.0))?;
            Ok(())
        }
        fn observe(&mut self, event: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            if matches!(event, ZipRunEvent::RunEnded { .. }) {
                s.emit(ZipDiagnosticSink::Stderr, self.0, |status, w| {
                    w.write_fmt(format_args!("{}\n", if status.is_fatal() { "fatal" } else { "normal" }))
                })?;
            }
            Ok(())
        }
    }
    for phase in [0, 1] {
        let (file, _session, options, old) = super::run::setup(&[Member::stored(b"a", b"a")]);
        drop(old);
        let mut sink = Sink::new();
        super::super::run::OWNED_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |at, path| {
                if at == phase {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(path.unwrap())
                        .unwrap()
                        .write_all(b"changed")
                        .unwrap();
                }
            }))
        });
        let error = crate::zip::run_with_policy(
            file.path(),
            &options,
            Some("pw"),
            &Cancellation::default(),
            &Default::default(),
            Aware(&mut sink),
        )
        .unwrap_err();
        super::super::run::OWNED_HOOK.with(|slot| *slot.borrow_mut() = None);
        assert!(error.source_change().is_some());
        assert_eq!(sink.bytes, b"fatal\n");
        assert_eq!(error.partial_run().unwrap().usage().live_fds, 0);
    }
}
#[test]
fn owned_listing_close_fault_keeps_zero_or_partial_write_ineligible() {
    for write_fault in [false, true] {
        let (_file, session, _options, old) = super::run::setup(&[Member::stored(b"a", b"a")]);
        drop(old);
        let mut sink = Sink::new();
        if write_fault {
            sink.fail = 1;
        }
        projected::CLOSE_FAULT.with(|s| s.set(Some(libc::EINTR)));
        let error = session
            .render_listing_owned(&mut sink, &Cancellation::default(), |_, w| w.write_fmt(format_args!("header\n")))
            .unwrap_err();
        assert!(!error.prewrite);
        assert_eq!(error.error.usage().live_fds, 1);
        assert!(
            error
                .error
                .cleanup_errors()
                .any(|f| f.object == OwnedObject::Source && f.operation == ReadIoOperation::Close)
        );
        if write_fault {
            assert!(error.error.diagnostic_fault().is_some());
            assert_eq!(error.usage.accepted_bytes, 0);
        } else {
            assert_eq!(error.usage.accepted_bytes, 7);
        }
    }
    let (_file, session, _options, old) = super::run::setup(&[Member::stored(b"a", b"a")]);
    drop(old);
    let mut sink = Sink::new();
    projected::CLOSE_FAULT.with(|s| s.set(Some(libc::EINTR)));
    let error = session
        .render_listing_owned(&mut sink, &Cancellation::default(), |_, w| w.write_fmt(format_args!("")))
        .unwrap_err();
    assert!(!error.prewrite);
    assert_eq!(error.usage.accepted_bytes, 0);
}
#[test]
fn normal_owned_close_admission_refusal_survives_successful_emergency_close() {
    let (file, _session, options, old) = super::run::setup(&[Member::stored(b"a", b"a")]);
    drop(old);
    super::super::run::OWNED_CLOSE_BOUND.with(|s| s.set(Some(0)));
    super::super::run::OWNED_CLOSE_CALLS.with(|s| s.set(0));
    let error = crate::zip::run_with_policy(
        file.path(),
        &options,
        Some("pw"),
        &Cancellation::default(),
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap_err();
    assert!(error.cleanup_errors().any(|f| matches!(
        f.cause,
        CleanupCause::Admission(ReadFault::Limit { resource: ReadResource::Run(RunCategory::FinalOperations), .. })
    )));
    assert_eq!(error.partial_run().unwrap().usage().live_fds, 0);
    super::super::run::OWNED_CLOSE_CALLS.with(|s| assert_eq!(s.get(), 1));
}

#[test]
fn fixed_slot_assembly_retains_all_independent_evidence_without_allocation() {
    let mut cleanup = ObjectCleanupReport::new(OwnedObject::Source);
    cleanup.push(CleanupFault {
        object: OwnedObject::Source,
        operation: ReadIoOperation::Close,
        offset: None,
        cause: CleanupCause::Io(io::Error::from_raw_os_error(libc::EINTR)),
        close: CloseDisposition::Unresolved,
    });
    let error = ZipReadError::from(ReadFault::AuthenticationFailed);
    let write = ZipSinkFault::Io {
        operation: ReadIoOperation::Write,
        offset: 0,
        error: io::Error::from_raw_os_error(libc::EPIPE),
    };
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(true));
    let error = error
        .merge_sink(ZipSinkFault::StageChanged)
        .merge_diagnostic(write)
        .merge_diagnostic_boundary(DiagnosticBoundaryFault::DescriptorChanged)
        .merge_source(CheckedSourceFault::StampMismatch)
        .merge_cleanup(cleanup)
        .with_partial(ZipRunReport::default());
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(false));
    assert!(error.operation().is_some());
    assert!(error.sink_fault().is_some());
    assert!(error.diagnostic_fault().is_some());
    assert!(error.diagnostic_boundary_fault().is_some());
    assert!(error.source_change().is_some());
    assert_eq!(error.cleanup_errors().len(), 1);
    assert!(error.partial_run().is_some());
    let error_size = std::mem::size_of::<ZipReadError>();
    let report_size = std::mem::size_of::<ZipRunReport>();
    let scope_size = std::mem::size_of::<ZipDiagnosticScope<'_>>();
    let retired = std::mem::size_of::<diagnostic::RetiredSource>();
    let header = shared::SHARED_LEDGER_CAPACITY;
    println!(
        "Task5B cwd_carrier={} diagnostic_usage={}",
        std::mem::size_of::<policy::cwd::CwdFailure>(),
        std::mem::size_of::<ZipDiagnosticUsage>()
    );
    println!(
        "Task5B layout error={error_size} result={} report={report_size} scope={scope_size} retired={retired} header={header} fixed_diagnostic_window=1024",
        std::mem::size_of::<ZipReadResult<()>>()
    );
    assert!(
        5 * error_size + 2 * report_size + 2 * scope_size + retired + header + libc::PATH_MAX as usize + 1024
            < 64 * 1024
    );
}
#[test]
fn owned_observer_failure_still_closes_source_without_another_callback() {
    let (file, _session, options, old) = super::run::setup(&[Member::stored(b"a", b"a"), Member::stored(b"b", b"b")]);
    drop(old);
    let mut callbacks = 0;
    super::super::run::OWNED_CLOSE_CALLS.with(|s| s.set(0));
    let error = crate::zip::run_with_policy(
        file.path(),
        &options,
        Some("pw"),
        &Cancellation::default(),
        &Default::default(),
        |_: ZipRunEvent<'_>| {
            callbacks += 1;
            Err(ZipSinkFault::StageChanged)
        },
    )
    .unwrap_err();
    assert_eq!(callbacks, 1);
    assert_eq!(error.partial_run().unwrap().usage().live_fds, 0);
    super::super::run::OWNED_CLOSE_CALLS.with(|s| assert_eq!(s.get(), 1));
}

#[test]
fn relative_protected_cwd_is_once_charged_only_for_regular_sinks() {
    struct Regular<'a>(&'a mut File);
    impl ZipRunObserver for Regular<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(self.0))?;
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.emit(ZipDiagnosticSink::Stderr, self.0, |_, w| w.write_fmt(format_args!("event\n")))?;
            Ok(())
        }
    }
    let (_file, mut session, mut options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    options.protected_paths.insert(std::path::PathBuf::from("."));
    let mut out = tempfile::tempfile().unwrap();
    let report = session
        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, Regular(&mut out))
        .unwrap();
    assert_eq!(report.diagnostic_usage().cwd_metadata_attempts, if cfg!(target_os = "macos") { 3 } else { 1 });
    assert_eq!(report.diagnostic_usage().target_metadata_attempts, 1);
    assert_eq!(report.run_usage().path_steps, 1);
    assert_eq!(context.policy_metadata_usage().caller.live_capacity, 0);
    let (_file, mut session, mut options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    options.protected_paths.insert(std::path::PathBuf::from("."));
    let mut out = Sink::new();
    let mut calls = 0;
    let report = session
        .run_with_context(
            &options,
            Some("pw"),
            &Cancellation::default(),
            &mut context,
            Observer { out: &mut out, calls: &mut calls, swallow: false },
        )
        .unwrap();
    assert_eq!(report.diagnostic_usage().cwd_metadata_attempts, 0);
    assert_eq!(report.diagnostic_usage().target_metadata_attempts, 0);
    assert_eq!(report.run_usage().path_steps, 0);
}
#[cfg(target_os = "macos")]
#[test]
fn closed_cwd_carrier_preserves_body_and_both_close_branches() {
    use shared::LedgerAccess;
    for scenario in 0..3 {
        let (_file, _session, _options, context) = super::run::setup(&[Member::stored(b"a", b"a")]);
        let ledger = context.ledger.view();
        let mut scratch = policy::PolicyScratch::new(ledger).unwrap();
        let calls = std::cell::Cell::new(0);
        policy::cwd::HOOK.with(|s| {
            *s.borrow_mut() = Some(Box::new(move |op| {
                if scenario == 0 && op == ReadIoOperation::DescriptorMode {
                    Some(libc::EIO)
                } else if (scenario == 0 || scenario == 2) && op == ReadIoOperation::Close {
                    Some(libc::EINTR)
                } else {
                    None
                }
            }))
        });
        let mut record = || {
            let n = calls.get() + 1;
            calls.set(n);
            if scenario != 0 && n == 2 {
                ledger.with_state(|s| s.test_limit_category(RunCategory::IoAttempts, s.run.usage.io_attempts));
            }
            Ok(())
        };
        let failure = policy::cwd::capture(ledger, &mut scratch, &Cancellation::default(), &mut record).err().unwrap();
        policy::cwd::HOOK.with(|s| *s.borrow_mut() = None);
        let error = failure.merge(ReadFault::InvalidPlan.into());
        assert_eq!(calls.get(), 3);
        assert!(error.source_change().is_none());
        assert!(error.cleanup_errors().all(|f| f.object == OwnedObject::SourcePathDirectory));
        if scenario == 0 {
            assert!(matches!(
                error.operation(),
                Some(ReadFault::Io { operation: ReadIoOperation::DescriptorMode, .. })
            ));
            assert_eq!(error.cleanup_errors().len(), 1);
        } else {
            assert!(error.cleanup_errors().any(|f| matches!(f.cause, CleanupCause::Admission(_))));
            assert_eq!(error.cleanup_errors().len(), if scenario == 2 { 2 } else { 1 });
        }
        assert_eq!(ledger.with_state(|s| s.live_fds), u64::from(scenario != 1));
        assert!(ledger.with_state(|s| s.poisoned));
    }
}
#[test]
fn cwd_copy_allocation_and_zero_path_allowance_stop_before_stage() {
    use shared::LedgerAccess;
    use std::os::unix::ffi::OsStrExt;
    let (_file, _session, _options, context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let ledger = context.ledger.view();
    let mut scratch = policy::PolicyScratch::new(ledger).unwrap();
    let capacity = std::env::current_dir().unwrap().as_os_str().as_bytes().len() + 1;
    crate::test_alloc::DENY_LAYOUT.with(|s| s.set(Some((capacity, 1))));
    let failure = policy::cwd::capture(ledger, &mut scratch, &Cancellation::default(), &mut || Ok(())).err();
    crate::test_alloc::DENY_LAYOUT.with(|s| s.set(None));
    let error = failure.unwrap().merge(ReadFault::InvalidPlan.into());
    assert!(matches!(error.operation(),Some(ReadFault::Allocation{capacity:c})if *c==capacity));
    assert_eq!(ledger.with_state(|s| s.live_fds), 0);
    ledger.with_state(|s| s.test_limit_category(RunCategory::PathSteps, s.run.usage.path_steps));
    let failure = policy::cwd::capture(ledger, &mut scratch, &Cancellation::default(), &mut || {
        panic!("zero allowance native call")
    })
    .err()
    .unwrap();
    assert!(matches!(
        failure.merge(ReadFault::InvalidPlan.into()).operation(),
        Some(ReadFault::Limit { resource: ReadResource::Run(RunCategory::PathSteps), .. })
    ));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn frozen_cwd_current_target_alias_is_checked_in_isolated_process() {
    const FLAG: &str = "ZIPFAST_TEST_CWD_DIAGNOSTIC_CHILD";
    if std::env::var_os(FLAG).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "zip::read::tests::diagnostic::frozen_cwd_current_target_alias_is_checked_in_isolated_process",
                "--nocapture",
            ])
            .env(FLAG, "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    struct Change {
        out: File,
        target: std::path::PathBuf,
        diagnostic: std::path::PathBuf,
        cwd: std::path::PathBuf,
    }
    impl ZipRunObserver for Change {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(&self.out))?;
            Ok(())
        }
        fn observe(&mut self, e: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            if matches!(e, ZipRunEvent::MemberSucceeded { .. }) {
                std::fs::remove_file(&self.target).unwrap();
                std::fs::hard_link(&self.diagnostic, &self.target).unwrap();
                std::env::set_current_dir(&self.cwd).unwrap();
                s.emit(ZipDiagnosticSink::Stderr, &mut self.out, |_, w| w.write_fmt(format_args!("must refuse\n")))?;
            }
            Ok(())
        }
    }
    let old_cwd = std::env::current_dir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    std::env::set_current_dir(root.path()).unwrap();
    let (_file, mut session, mut options, old) = super::run::setup(&[Member::stored(b"a", b"data")]);
    drop(old);
    options.mode = crate::extract::Mode::Extract;
    options.dest = std::path::PathBuf::from("out");
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::StagedFiles { destination: &options.dest },
        Some("pw"),
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap();
    let diagnostic = root.path().join("diagnostic");
    std::fs::write(&diagnostic, b"preserve").unwrap();
    let out = std::fs::OpenOptions::new().append(true).open(&diagnostic).unwrap();
    let result = session.run_with_context(
        &options,
        Some("pw"),
        &Cancellation::default(),
        &mut context,
        Change {
            out,
            target: root.path().join("out/a"),
            diagnostic: diagnostic.clone(),
            cwd: other.path().to_path_buf(),
        },
    );
    std::env::set_current_dir(old_cwd).unwrap();
    let error = result.unwrap_err();
    assert!(matches!(error.diagnostic_boundary_fault(), Some(DiagnosticBoundaryFault::Refused { .. })));
    assert_eq!(error.publication_state(), PublicationState::Published);
    assert_eq!(error.accepted_output_bytes(), 4);
    assert_eq!(std::fs::read(diagnostic).unwrap(), b"preserve");
}

#[test]
fn zero_sink_prepare_has_zero_diagnostic_metadata() {
    struct Silent;
    impl ZipRunObserver for Silent {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, None)?;
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, _: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            Ok(())
        }
    }
    let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let report =
        session.run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, Silent).unwrap();
    assert_eq!(report.diagnostic_usage(), ZipDiagnosticUsage::default());
}
#[test]
fn unproved_regular_admission_cannot_become_valid_later() {
    let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    context.ledger.with_state(|s| {
        s.bind_diagnostics(1, 1, 0, false).unwrap();
        s.test_limit_category(RunCategory::DiagnosticSourceGroups, 0);
    });
    let mut state = diagnostic::DiagnosticState::default();
    let mut out = tempfile::tempfile().unwrap();
    let cancel = Cancellation::default();
    let mut scope =
        ZipDiagnosticScope::new(&mut session.owner, &options, &mut context, &mut state, &cancel, None).unwrap();
    let _ = scope.admit_sinks(None, Some(&out));
    assert!(scope.finish(Ok(())).failed());
    context.ledger.with_state(|s| s.test_limit_category(RunCategory::DiagnosticSourceGroups, 8));
    let projected::ProjectedOwner { file, source, entries, .. } = &mut session.owner;
    let mut scope =
        ZipDiagnosticScope::from_parts(file, source, entries, &options, &mut context, &mut state, &cancel, None)
            .unwrap();
    let _ = scope.emit(ZipDiagnosticSink::Stderr, &mut out, |_, w| w.write_fmt(format_args!("refuse")));
    assert!(scope.finish(Ok(())).failed());
    assert_eq!(out.metadata().unwrap().len(), 0);
}

#[test]
fn empty_root_join_remains_relative_and_boundary_keeps_diagnostic_priority() {
    let (_file, _session, _options, context) = super::run::setup(&[Member::stored(b"a", b"a")]);
    let path =
        policy::PolicyPath::joined(&context.ledger, std::path::Path::new(""), std::path::Path::new("a")).unwrap();
    assert_eq!(path.path(), std::path::Path::new("a"));
    path.finish(&context.ledger).unwrap();
    let error = ZipReadError::from(ReadFault::AuthenticationFailed)
        .merge_diagnostic_boundary(DiagnosticBoundaryFault::DescriptorChanged)
        .merge_sink(ZipSinkFault::StageChanged);
    assert_eq!(error.kind(), ZipReadErrorKind::Diagnostic);
    assert!(error.operation().is_some());
    assert!(error.sink_fault().is_some());
    assert!(error.diagnostic_boundary_fault().is_some());
}

#[test]
fn owning_retired_source_native_namespace_matrix_and_inside_write() {
    struct Final<'a, W>(&'a mut W);
    impl<W: Write + AsFd> ZipRunObserver for Final<'_, W> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(self.0))?;
            Ok(())
        }
        fn observe(&mut self, e: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            if matches!(e, ZipRunEvent::RunEnded { .. }) {
                s.emit(ZipDiagnosticSink::Stderr, self.0, |status, w| {
                    w.write_fmt(format_args!("{}", if status.is_fatal() { "fatal" } else { "normal" }))
                })?;
            }
            Ok(())
        }
    }
    for phase in [0, 1] {
        for mutation in 0..5 {
            let (file, _session, options, old) = super::run::setup(&[Member::stored(b"a", b"a")]);
            drop(old);
            let backup = tempfile::tempdir().unwrap();
            let saved = backup.path().join("saved");
            super::super::run::OWNED_HOOK.with(|slot| {
                *slot.borrow_mut() = Some(Box::new(move |at, path| {
                    if at == phase {
                        let path = path.unwrap();
                        match mutation {
                            0 => std::fs::OpenOptions::new().write(true).open(path).unwrap().set_len(0).unwrap(),
                            1 => {
                                std::fs::rename(path, &saved).unwrap();
                                std::fs::write(path, b"replacement").unwrap();
                            }
                            2 | 4 => {
                                std::fs::rename(path, &saved).unwrap();
                            }
                            3 => {
                                std::fs::rename(path, &saved).unwrap();
                                let other = saved.with_extension("other");
                                std::fs::write(&other, b"other").unwrap();
                                std::fs::hard_link(other, path).unwrap();
                            }
                            _ => unreachable!(),
                        }
                    }
                    if mutation == 4 && at == 1 && phase == 0 {
                        std::fs::rename(&saved, path.unwrap()).unwrap();
                    }
                }))
            });
            let mut out = tempfile::tempfile().unwrap();
            let error = crate::zip::run_with_policy(
                file.path(),
                &options,
                Some("pw"),
                &Cancellation::default(),
                &Default::default(),
                Final(&mut out),
            )
            .unwrap_err();
            super::super::run::OWNED_HOOK.with(|slot| *slot.borrow_mut() = None);
            assert!(error.source_change().is_some(), "phase={phase} mutation={mutation}");
            assert_eq!(out.metadata().unwrap().len(), 0);
            assert_eq!(error.partial_run().unwrap().usage().live_fds, 0);
        }
    }
    struct Change {
        sink: Sink,
        path: std::path::PathBuf,
    }
    impl AsFd for Change {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.sink.as_fd()
        }
    }
    impl Write for Change {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            std::fs::OpenOptions::new().write(true).open(&self.path)?.set_len(0)?;
            self.sink.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (file, _session, options, old) = super::run::setup(&[Member::stored(b"a", b"a")]);
    drop(old);
    let mut out = Change { sink: Sink::new(), path: file.path().to_path_buf() };
    let error = crate::zip::run_with_policy(
        file.path(),
        &options,
        Some("pw"),
        &Cancellation::default(),
        &Default::default(),
        Final(&mut out),
    )
    .unwrap_err();
    assert!(error.source_change().is_some());
    assert_eq!(out.sink.calls, 1);
    assert_eq!(out.sink.bytes, b"normal");
    assert_eq!(error.partial_run().unwrap().diagnostic_usage().accepted_bytes, 6);
    assert_eq!(error.partial_run().unwrap().usage().live_fds, 0);
}

#[test]
fn listing_mid_and_final_source_changes_keep_provisional_rows_and_constant_metadata() {
    for after_row in [0, 1] {
        let (file, mut session, _options, _context) =
            super::run::setup(&[Member::stored(b"first", b"a"), Member::stored(b"last", b"b")]);
        let mut out = Sink::new();
        let failure = session
            .render_listing(&mut out, &Cancellation::default(), |entries, writer| {
                writer.write_fmt(format_args!("header\n"))?;
                for (i, entry) in entries.iter().enumerate() {
                    writer.write_fmt(format_args!("{}\n", entry.name))?;
                    if i == after_row {
                        std::fs::OpenOptions::new().write(true).open(file.path()).unwrap().set_len(0).unwrap();
                    }
                }
                Ok(())
            })
            .unwrap_err();
        assert!(failure.error.source_change().is_some());
        assert!(!failure.prewrite);
        assert_eq!(out.bytes, b"header\nfirst\nlast\n");
        assert_eq!(out.calls, 3);
        // Both complete held/path/held observations remain constant despite row count.
        assert_eq!(failure.usage.source_metadata_attempts, 6);
        assert_eq!(failure.usage.descriptor_metadata_attempts, 2);
        assert_eq!(failure.usage.accepted_bytes, out.bytes.len() as u128);
    }
}

#[test]
fn whole_wave_first_real_write_fault_survives_distinct_caller_error() {
    struct RealWrite {
        socket: UnixStream,
        peer: Option<UnixStream>,
        source: std::path::PathBuf,
        mutate: bool,
        calls: usize,
    }
    impl AsFd for RealWrite {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.socket.as_fd()
        }
    }
    impl Write for RealWrite {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                let n = self.socket.write(&bytes[..bytes.len().min(3)])?;
                let mut received = [0; 3];
                std::io::Read::read_exact(self.peer.as_mut().unwrap(), &mut received[..n])?;
                self.peer.take();
                Ok(n)
            } else {
                if self.mutate {
                    std::fs::OpenOptions::new().append(true).open(&self.source)?.write_all(b"change")?;
                }
                self.socket.write(bytes)
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Observer<'a> {
        out: &'a mut RealWrite,
        callbacks: &'a mut usize,
    }
    impl ZipRunObserver for Observer<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(self.out))?;
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            *self.callbacks += 1;
            assert!(s.emit(ZipDiagnosticSink::Stderr, self.out, |_, w| w.write_fmt(format_args!("fault\n"))).is_err());
            Err(ZipSinkFault::StageChanged.into())
        }
    }
    for mutate in [false, true] {
        let mut bad = Member::stored(b"bad", b"bad");
        bad.crc = Some(1);
        let (file, mut session, options, mut context) =
            super::run::setup(&[bad, Member::stored(b"unvisited", b"good")]);
        let (socket, peer) = UnixStream::pair().unwrap();
        let mut out = RealWrite { socket, peer: Some(peer), source: file.path().to_path_buf(), mutate, calls: 0 };
        let mut callbacks = 0;
        let error = session
            .run_with_context(
                &options,
                Some("pw"),
                &Cancellation::default(),
                &mut context,
                Observer { out: &mut out, callbacks: &mut callbacks },
            )
            .unwrap_err();
        assert!(
            matches!(error.diagnostic_fault(),Some(ZipSinkFault::Io{operation:ReadIoOperation::Write,offset:0,error})if error.raw_os_error()==Some(libc::EPIPE)),
            "diagnostic={:?}",
            error.diagnostic_fault()
        );
        assert!(matches!(error.operation(), Some(ReadFault::Integrity { .. })));
        assert_eq!(error.source_change().is_some(), mutate);
        assert_eq!(callbacks, 1);
        assert_eq!(out.calls, 2);
        let report = error.partial_run().unwrap();
        assert_eq!(report.run_usage().records, 1);
        assert_eq!(report.diagnostic_usage().accepted_bytes, 3);
        assert_eq!(report.diagnostic_usage().write_attempts, 2);
    }
}
