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

use super::super::shared::LedgerAccess;
use super::super::*;
use super::fixture::Member;
use crate::extract::{Mode, Options};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
fn context(session: &mut ProjectedReadSession, options: &Options, password: Option<&str>) -> EncryptedReadContext {
    EncryptedReadContext::for_projected(
        session,
        ProjectedReadScope::AllRegular,
        None,
        if options.mode == Mode::Extract {
            ZipReadOutput::StagedFiles { destination: &options.dest }
        } else {
            ZipReadOutput::Discard
        },
        password,
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap()
}
#[test]
fn r1_i1_directory_metadata_uses_original_cwd_in_isolated_process() {
    const FLAG: &str = "ZIPFAST_R1_DIRECTORY_CWD_CHILD";
    if std::env::var_os(FLAG).is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "zip::read::tests::review_r1::r1_i1_directory_metadata_uses_original_cwd_in_isolated_process",
                "--nocapture",
            ])
            .env(FLAG, "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let original_cwd = std::env::current_dir().unwrap();
    for (spelling, mode) in [("out", 0o751), ("", 0)] {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let path_a = a.path().join(spelling).join("folder");
        let path_b = b.path().join(spelling).join("folder");
        std::fs::create_dir_all(&path_a).unwrap();
        std::fs::create_dir_all(&path_b).unwrap();
        std::fs::set_permissions(&path_b, std::fs::Permissions::from_mode(0o705)).unwrap();
        let b_stamp = std::fs::metadata(&path_b).unwrap();
        let mut dir = Member::stored(b"folder/", b"");
        dir.external = (0o040000 | mode) << 16;
        let (_file, mut session, mut options, old) = super::run::setup(&[dir, Member::stored(b"file", b"data")]);
        drop(old);
        let expected_time = session.entries().next().unwrap().mtime.unwrap();
        options.mode = Mode::Extract;
        options.dest = std::path::PathBuf::from(spelling);
        std::env::set_current_dir(a.path()).unwrap();
        let mut c = context(&mut session, &options, Some("pw"));
        let report = session
            .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut c, |e: ZipRunEvent<'_>| {
                if matches!(e, ZipRunEvent::MemberSucceeded { .. }) {
                    std::env::set_current_dir(b.path()).unwrap();
                }
                Ok(())
            })
            .unwrap();
        std::env::set_current_dir(&original_cwd).unwrap();
        assert_eq!((report.files(), report.dirs()), (1, 1));
        let actual_a = std::fs::metadata(&path_a).unwrap();
        let actual_b = std::fs::metadata(&path_b).unwrap();
        assert_eq!(actual_a.permissions().mode() & 0o777, mode);
        assert_eq!(actual_a.mtime(), expected_time);
        assert_eq!(actual_b.permissions().mode() & 0o777, b_stamp.permissions().mode() & 0o777);
        assert_eq!((actual_b.mtime(), actual_b.mtime_nsec()), (b_stamp.mtime(), b_stamp.mtime_nsec()));
        std::fs::set_permissions(path_a, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
struct MutatingWriter {
    socket: UnixStream,
    replacement: Option<UnixStream>,
    regular: Option<File>,
    source: std::path::PathBuf,
    target: std::path::PathBuf,
    diagnostic: std::path::PathBuf,
    mutation: u8,
    writes: usize,
    bytes: usize,
}
impl AsFd for MutatingWriter {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.regular.as_ref().map_or_else(|| self.socket.as_fd(), |f| f.as_fd())
    }
}
impl Write for MutatingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let n = if let Some(f) = self.regular.as_mut() { f.write(bytes)? } else { bytes.len() };
        self.bytes += n;
        if self.writes == 1 {
            match self.mutation {
                0 => std::fs::OpenOptions::new().write(true).open(&self.source)?.set_len(0)?,
                1 => self.socket = self.replacement.take().unwrap(),
                2 => {
                    std::fs::remove_file(&self.target)?;
                    std::fs::hard_link(&self.diagnostic, &self.target)?;
                }
                _ => unreachable!(),
            }
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn r1_i2_member_postwrite_boundaries_stop_all_callbacks_borrowed_and_owned() {
    struct Observe<'a> {
        out: &'a mut MutatingWriter,
        calls: &'a mut usize,
        ended: &'a mut usize,
        swallow: bool,
    }
    impl ZipRunObserver for Observe<'_> {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(self.out))?;
            Ok(())
        }
        fn observe(&mut self, e: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            *self.calls += 1;
            if matches!(e, ZipRunEvent::RunEnded { .. }) {
                *self.ended += 1;
            }
            let result = s.emit(ZipDiagnosticSink::Stderr, self.out, |_, w| w.write_fmt(format_args!("event\n")));
            if !self.swallow {
                result?;
            }
            Ok(())
        }
    }
    for owned in [false, true] {
        for mutation in 0..3 {
            for swallow in [false, true] {
                let mut member = Member::stored(b"a", b"data");
                if mutation != 2 {
                    member.crc = Some(1);
                }
                let (file, mut session, mut options, old) =
                    super::run::setup(&[member, Member::stored(b"unvisited", b"x")]);
                drop(old);
                let dest = tempfile::tempdir().unwrap();
                let diagnostic = tempfile::NamedTempFile::new().unwrap();
                if mutation == 2 {
                    options.mode = Mode::Extract;
                    options.dest = dest.path().to_path_buf();
                }
                let (socket, _peer) = UnixStream::pair().unwrap();
                let (replacement, _peer2) = UnixStream::pair().unwrap();
                let mut out = MutatingWriter {
                    socket,
                    replacement: Some(replacement),
                    regular: if mutation == 2 {
                        Some(std::fs::OpenOptions::new().append(true).open(diagnostic.path()).unwrap())
                    } else {
                        None
                    },
                    source: file.path().to_path_buf(),
                    target: dest.path().join("a"),
                    diagnostic: diagnostic.path().to_path_buf(),
                    mutation,
                    writes: 0,
                    bytes: 0,
                };
                let (mut calls, mut ended) = (0, 0);
                let observe = Observe { out: &mut out, calls: &mut calls, ended: &mut ended, swallow };
                super::super::run::OWNED_CLOSE_CALLS.with(|s| s.set(0));
                let error = if owned {
                    crate::zip::run_with_policy(
                        file.path(),
                        &options,
                        Some("pw"),
                        &Cancellation::default(),
                        &Default::default(),
                        observe,
                    )
                    .unwrap_err()
                } else {
                    let mut c = context(&mut session, &options, Some("pw"));
                    session
                        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut c, observe)
                        .unwrap_err()
                };
                assert_eq!(
                    (calls, ended, out.writes, out.bytes),
                    (1, 0, 1, 6),
                    "owned={owned} mutation={mutation} swallow={swallow}"
                );
                assert_eq!(error.partial_run().unwrap().run_usage().records, 1);
                assert_eq!(error.partial_run().unwrap().diagnostic_usage().accepted_bytes, 6);
                assert_eq!(error.partial_run().unwrap().usage().live_fds, u64::from(!owned));
                if owned {
                    super::super::run::OWNED_CLOSE_CALLS.with(|s| assert_eq!(s.get(), 1));
                }
                assert!(error.diagnostic_fault().is_none(), "boundary faults are not writer faults");
                if mutation != 2 {
                    assert!(matches!(error.operation(), Some(ReadFault::Integrity { .. })));
                }
                if mutation == 0 {
                    assert!(error.source_change().is_some());
                    assert_eq!(error.kind(), ZipReadErrorKind::SourceChanged);
                } else {
                    assert!(error.diagnostic_boundary_fault().is_some());
                    assert_eq!(error.kind(), ZipReadErrorKind::Diagnostic);
                }
                if mutation == 2 {
                    assert_eq!(error.publication_state(), PublicationState::Published);
                    assert_eq!(error.accepted_output_bytes(), 4);
                }
            }
        }
    }
}
#[test]
fn r1_i3_missing_and_empty_password_precedes_existing_skip() {
    let frame = super::cipher::framed(1, "pw", b"data");
    let extra = super::fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    for password in [None, Some(""), Some("wrong")] {
        let mut member = Member::stored(b"a", &frame);
        member.flags = 1;
        member.method = 99;
        member.decoded = Some(b"data");
        member.central_extra = &extra;
        let (_file, mut session, mut options, old) = super::run::setup(&[member]);
        drop(old);
        let dest = tempfile::tempdir().unwrap();
        std::fs::write(dest.path().join("a"), b"original").unwrap();
        options.mode = Mode::Extract;
        options.dest = dest.path().to_path_buf();
        let mut c = context(&mut session, &options, password);
        let (mut required, mut skipped) = (0, 0);
        let report = session
            .run_with_context(&options, password, &Cancellation::default(), &mut c, |e: ZipRunEvent<'_>| {
                match e {
                    ZipRunEvent::MemberFailed { error, .. } => {
                        assert!(matches!(error.operation(), Some(ReadFault::PasswordRequired)));
                        required += 1;
                    }
                    ZipRunEvent::MemberSkipped { .. } => skipped += 1,
                    _ => {}
                }
                Ok(())
            })
            .unwrap();
        let absent = password.is_none_or(str::is_empty);
        assert_eq!(
            (report.failed(), report.skipped(), required, skipped),
            (u64::from(absent), u64::from(!absent), usize::from(absent), usize::from(!absent))
        );
        assert_eq!(report.run_usage().records, 1);
        assert_eq!(std::fs::read(dest.path().join("a")).unwrap(), b"original");
    }
}
#[test]
fn r1_i4_listing_retains_simultaneous_initial_source_and_descriptor_faults() {
    for owned in [false, true] {
        let (file, mut session, _options, _c) = super::run::setup(&[Member::stored(b"a", b"a")]);
        std::fs::OpenOptions::new().append(true).open(file.path()).unwrap().write_all(b"change").unwrap();
        let (mut out, _peer) = UnixStream::pair().unwrap();
        diagnostic::DESCRIPTOR_STAT_FAULT.with(|s| s.set(Some(libc::EIO)));
        super::super::run::OWNED_CLOSE_CALLS.with(|s| s.set(0));
        let render = |_: &[crate::zip::ZipEntry],
                      _: &mut ZipDiagnosticWriter<'_, UnixStream>|
         -> ZipDiagnosticResult<()> { panic!("must refuse before header") };
        let failure = if owned {
            session.render_listing_owned(&mut out, &Cancellation::default(), render).unwrap_err()
        } else {
            session.render_listing(&mut out, &Cancellation::default(), render).unwrap_err()
        };
        assert_eq!(failure.error.kind(), ZipReadErrorKind::SourceChanged);
        assert!(
            matches!(failure.error.diagnostic_boundary_fault(),Some(DiagnosticBoundaryFault::Admission(ReadFault::Io{error,..}))if error.raw_os_error()==Some(libc::EIO))
        );
        assert!(failure.prewrite);
        assert_eq!((failure.usage.accepted_bytes, failure.usage.write_attempts), (0, 0));
        assert_eq!((failure.usage.source_metadata_attempts, failure.usage.descriptor_metadata_attempts), (3, 2));
        assert_eq!(failure.error.run_usage().diagnostic_source_groups, 1);
        assert_eq!(failure.error.run_usage().diagnostic_admission_operations, 2);
        println!("R1 listing owned={owned} diagnostic={:?} run={:?}", failure.usage, failure.error.run_usage());
        if owned {
            super::super::run::OWNED_CLOSE_CALLS.with(|s| assert_eq!(s.get(), 1));
            assert_eq!(failure.error.usage().live_fds, 0);
            assert_eq!(failure.error.run_usage().emergency_cleanup, 0);
            assert_eq!(failure.error.run_usage().final_operations, 1);
        }
    }
}
#[test]
fn r1_i5_finalization_cancellation_preserves_prior_diagnostic_publication() {
    for prior in [false, true] {
        let mut dir = Member::stored(b"folder/", b"");
        dir.external = 0o040755 << 16;
        let (_file, mut session, mut options, old) = super::run::setup(&[dir, Member::stored(b"a", b"data")]);
        drop(old);
        let dest = tempfile::tempdir().unwrap();
        options.mode = Mode::Extract;
        options.dest = dest.path().to_path_buf();
        let mut c = context(&mut session, &options, Some("pw"));
        let cancel = Cancellation::default();
        let trigger = cancel.clone();
        super::super::run::FINALIZATION_HOOK.with(|s| *s.borrow_mut() = Some(Box::new(move || trigger.cancel())));
        let mut ended = 0;
        let error = session
            .run_with_context(&options, Some("pw"), &cancel, &mut c, |e: ZipRunEvent<'_>| {
                match e {
                    ZipRunEvent::MemberSucceeded { .. } if prior => return Err(ZipSinkFault::StageChanged),
                    ZipRunEvent::RunEnded { .. } => ended += 1,
                    _ => {}
                }
                Ok(())
            })
            .unwrap_err();
        super::super::run::FINALIZATION_HOOK.with(|s| *s.borrow_mut() = None);
        assert_eq!(ended, usize::from(!prior));
        assert_eq!(std::fs::read(dest.path().join("a")).unwrap(), b"data");
        assert_eq!(error.partial_run().unwrap().files(), 1);
        if prior {
            assert!(error.diagnostic_fault().is_some());
            assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
            assert_eq!(error.kind(), ZipReadErrorKind::Diagnostic);
            assert_eq!(error.publication_state(), PublicationState::Published);
            assert_eq!(error.accepted_output_bytes(), 4);
        } else {
            assert!(matches!(error.operation(), Some(ReadFault::Cancelled)));
        }
    }
}

#[test]
fn r1_i2_foreign_and_stale_tokens_stop_callback_protocol() {
    struct Replay {
        action: shared::LedgerIdentity,
        foreign: Option<shared::LedgerIdentity>,
        member: bool,
        calls: std::rc::Rc<std::cell::Cell<usize>>,
    }
    impl ZipRunObserver for Replay {
        fn prepare(&mut self, scope: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            if self.member {
                scope.admit_sinks(None, None)?;
                Ok(())
            } else {
                Err(diagnostic::protocol_test_token(self.foreign.unwrap_or(self.action), 0).into())
            }
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, _: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            self.calls.set(self.calls.get() + 1);
            Err(diagnostic::protocol_test_token(self.foreign.unwrap_or(self.action), 1).into())
        }
    }
    for member in [false, true] {
        for foreign in [false, true] {
            let (_file, mut session, options, mut context) = super::run::setup(&[Member::stored(b"a", b"a")]);
            let other = EncryptedReadContext::new(Default::default()).unwrap();
            let calls = std::rc::Rc::new(std::cell::Cell::new(0));
            let replay = Replay {
                action: context.ledger.identity(),
                foreign: foreign.then(|| other.ledger.identity()),
                member,
                calls: calls.clone(),
            };
            let error = session
                .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, replay)
                .unwrap_err();
            assert_eq!(calls.get(), usize::from(member), "member={member} foreign={foreign}");
            assert!(matches!(
                error.diagnostic_boundary_fault(),
                Some(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan))
            ));
        }
    }
}

#[test]
fn r1_i2_swallowed_render_protocol_error_still_stops_callbacks() {
    struct Observer {
        out: UnixStream,
        calls: usize,
        action: shared::LedgerIdentity,
    }
    impl ZipRunObserver for Observer {
        fn prepare(&mut self, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            s.admit_sinks(None, Some(&self.out))?;
            Ok(())
        }
        fn observe(&mut self, _: ZipRunEvent<'_>, s: &mut ZipDiagnosticScope<'_>) -> ZipObserverResult<()> {
            self.calls += 1;
            assert_eq!(self.calls, 1, "protocol error caused another callback");
            let stale = diagnostic::protocol_test_token(self.action, 0);
            let _ = s.emit(ZipDiagnosticSink::Stderr, &mut self.out, |_, _| Err(stale));
            Ok(())
        }
    }
    let (_file, mut session, options, mut c) =
        super::run::setup(&[Member::stored(b"a", b"a"), Member::stored(b"b", b"b")]);
    let (out, _peer) = UnixStream::pair().unwrap();
    let observer = Observer { out, calls: 0, action: c.ledger.identity() };
    let error = session.run_with_context(&options, Some("pw"), &Cancellation::default(), &mut c, observer).unwrap_err();
    assert_eq!(error.partial_run().unwrap().run_usage().records, 1);
    assert_eq!(error.partial_run().unwrap().diagnostic_usage().accepted_bytes, 0);
    assert_eq!(error.partial_run().unwrap().diagnostic_usage().write_attempts, 0);
    assert!(matches!(
        error.diagnostic_boundary_fault(),
        Some(DiagnosticBoundaryFault::Admission(ReadFault::InvalidPlan))
    ));
}
