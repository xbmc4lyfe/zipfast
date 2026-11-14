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
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
use zipfast::extract::{Mode, Options, Overwrite, RarEntryOutcome};
use zipfast::rar5::session::*;

fn options(dest: &Path) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    }
}
struct Observer {
    replace: bool,
    calls: usize,
    outcomes: usize,
}
impl RarExtractObserver for Observer {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        mut diagnostic: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        self.calls += 1;
        if let Some(file) = diagnostic.writer() {
            file.write_all(b"question\n").unwrap();
        }
        Ok(if self.replace { RarOverwriteDecision::Replace } else { RarOverwriteDecision::Skip })
    }
    fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
        self.outcomes += 1;
        if let Some(file) = diagnostic.writer() {
            file.write_all(b"outcome\n").unwrap();
        }
    }
}
#[test]
fn skipped_target_diagnostic_alias_is_preserved_without_stopping_extraction() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.rar");
    fs::write(&source, archive(&[FileSpec::new("skip", b"new"), FileSpec::new("next", b"ok")])).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    let target = dest.join("skip");
    fs::write(&target, b"original").unwrap();
    let diagnostic = OpenOptions::new().append(true).open(&target).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control =
        RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Ask, RarExtractControlLimits::default());
    let mut observer = Observer { replace: false, calls: 0, outcomes: 0 };
    let report = session.extract_selected_controlled(
        &selected,
        &options(&dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    let summary = report.outcome().as_ref().unwrap();
    assert_eq!((summary.files, summary.skipped, summary.failed), (1, 1, 0));
    assert!(matches!(report.diagnostic_failure(), Some(RarDiagnosticFailure::AliasTarget { ordinal: 0 })));
    let finished = report.finish();
    assert_eq!(finished.usage.diagnostics.open_handles, 0);
    assert_eq!(finished.usage.capacity, 0);
    assert_eq!((observer.calls, observer.outcomes), (1, 2));
    assert_eq!(fs::read(target).unwrap(), b"original");
    assert_eq!(fs::read(dest.join("next")).unwrap(), b"ok");
}
#[test]
fn terminal_writer_refreshes_and_refuses_a_rebound_target() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.rar");
    fs::write(&source, archive(&[FileSpec::new("item", b"new")])).unwrap();
    let log = dir.path().join("log");
    fs::write(&log, b"").unwrap();
    let diagnostic = OpenOptions::new().append(true).open(&log).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control =
        RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
    let dest = dir.path().join("out");
    let mut observer = Observer { replace: true, calls: 0, outcomes: 0 };
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut observer,
    );
    assert_eq!(report.outcome().as_ref().unwrap().files, 1);
    fs::remove_file(dest.join("item")).unwrap();
    fs::hard_link(&log, dest.join("item")).unwrap();
    assert!(report.diagnostic().writer().is_none());
    assert!(report.diagnostic_failure().is_some());
    assert_eq!(report.finish().outcome.unwrap().files, 1);
}

struct Quiet;
impl RarExtractObserver for Quiet {
    fn overwrite(
        &mut self,
        _: &RarOverwriteConflict<'_>,
        _: RarDiagnostic<'_>,
    ) -> Result<RarOverwriteDecision, RarDecisionError> {
        Ok(RarOverwriteDecision::Replace)
    }
    fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
}
#[test]
fn distinct_regular_log_is_available_repeatedly_and_quiet_callbacks_do_not_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.rar");
    fs::write(&source, archive(&[FileSpec::new("folder/a", b"A"), FileSpec::new("folder/b", b"B")])).unwrap();
    let log = dir.path().join("log");
    let diagnostic = OpenOptions::new().create_new(true).append(true).open(&log).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control =
        RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
    assert!(control.early_diagnostic().writer().is_none());
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&dir.path().join("out")),
        RarDecodeLimits::default(),
        &mut control,
        &mut Quiet,
    );
    assert_eq!(report.outcome().as_ref().unwrap().files, 2);
    assert_eq!(report.usage().diagnostics.writer_requests, 1);
    assert!(report.diagnostic_failure().is_none(), "{:?}", report.diagnostic_failure());
    for _ in 0..2 {
        report.diagnostic().writer().expect("distinct regular log").write_all(b"done\n").unwrap();
    }
    assert_eq!(report.usage().diagnostics.checkpoints, 3);
    let final_ = report.finish();
    assert_eq!(final_.usage.diagnostics.capacity, 0);
    assert_eq!(final_.usage.diagnostics.open_handles, 0);
    assert_eq!(fs::read(log).unwrap(), b"done\ndone\n");
}
#[test]
fn eof_after_first_publication_preserves_partial_summary_without_fake_failure() {
    struct Eof {
        calls: usize,
    }
    impl RarExtractObserver for Eof {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            self.calls += 1;
            if self.calls == 1 { Ok(RarOverwriteDecision::Replace) } else { Err(RarDecisionError::EndOfInput) }
        }
        fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    fs::write(&source, archive(&[FileSpec::new("a", b"A"), FileSpec::new("b", b"B")])).unwrap();
    for name in ["a", "b"] {
        fs::write(d.path().join(name), b"old").unwrap();
    }
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
    let final_ = s
        .extract_selected_controlled(
            &selected,
            &options(d.path()),
            RarDecodeLimits::default(),
            &mut c,
            &mut Eof { calls: 0 },
        )
        .finish();
    assert!(
        matches!(final_.outcome,Err(RarExtractError::Decision{partial,entry,cause:RarDecisionError::EndOfInput}) if partial.files==1&&partial.failed==0&&partial.skipped==0&&entry.order==1)
    );
    assert_eq!(fs::read(d.path().join("a")).unwrap(), b"A");
    assert_eq!(fs::read(d.path().join("b")).unwrap(), b"old");
    assert_eq!(final_.teardown.usage.decision_parents.successful_acquires, 2);
    assert_eq!(final_.teardown.usage.decision_parents.confirmed_closed, 2);
}
#[test]
fn final_callback_source_drift_is_native_failure_after_counting_published_output() {
    struct Drift(std::path::PathBuf);
    impl RarExtractObserver for Drift {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!()
        }
        fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {
            fs::write(&self.0, b"rebound").unwrap();
        }
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    fs::write(&source, archive(&[FileSpec::new("a", b"A")])).unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
    let result = s
        .extract_selected_controlled(
            &selected,
            &options(d.path()),
            RarDecodeLimits::default(),
            &mut c,
            &mut Drift(source),
        )
        .finish();
    assert!(
        matches!(result.outcome,Err(RarExtractError::Native(error)) if error.partial.files==1&&error.partial.failed==0&&matches!(error.failure.as_ref(),zipfast::error::RarFailure::SourceChanged{..}))
    );
    assert_eq!(fs::read(d.path().join("a")).unwrap(), b"A");
}
#[test]
fn directory_metadata_is_final_before_terminal_view_and_drop_never_restores_again() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let folder = FileSpec { dir: true, unix_mode: Some(0o710), ..FileSpec::new("folder", b"") };
    fs::write(&source, archive(&[folder, FileSpec::new("folder/a", b"A")])).unwrap();
    let out = d.path().join("out");
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Always, RarExtractControlLimits::default());
    let report =
        s.extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut Quiet);
    assert!(report.outcome().is_ok());
    assert_eq!(fs::metadata(out.join("folder")).unwrap().permissions().mode() & 0o777, 0o710);
    fs::set_permissions(out.join("folder"), fs::Permissions::from_mode(0o750)).unwrap();
    drop(report);
    assert_eq!(fs::metadata(out.join("folder")).unwrap().permissions().mode() & 0o777, 0o750);
}

#[test]
fn every_native_limit_has_an_exact_and_one_under_boundary() {
    use zipfast::error::RarResource;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    fs::write(&source, archive(&[FileSpec::new("item", b"A")])).unwrap();
    let run = |limits: RarExtractControlLimits| {
        fs::create_dir_all(&out).unwrap();
        fs::write(out.join("item"), b"old").unwrap();
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, limits);
        s.extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut Quiet)
            .finish()
    };
    let baseline = run(RarExtractControlLimits::default());
    assert!(baseline.outcome.is_ok());
    for (resource, value) in [
        (RarResource::ExtractControlCapacity, baseline.usage.capacity_peak),
        (RarResource::ExtractControlWork, baseline.usage.work),
        (RarResource::ExtractControlIoAttempts, baseline.usage.io_attempts),
        (RarResource::ExtractDecisionCalls, baseline.usage.decision_calls),
    ] {
        assert!(value > 0);
        for exact in [true, false] {
            let mut limits = RarExtractControlLimits::default();
            let allowed = if exact { value } else { value - 1 };
            match resource {
                RarResource::ExtractControlCapacity => limits.capacity = allowed,
                RarResource::ExtractControlWork => limits.work = allowed,
                RarResource::ExtractControlIoAttempts => limits.io_attempts = allowed,
                RarResource::ExtractDecisionCalls => limits.decisions = allowed,
                _ => unreachable!(),
            }
            let result = run(limits);
            if exact {
                assert!(result.outcome.is_ok(), "{resource:?}: {:?}", result.outcome);
            } else {
                assert!(
                    matches!(result.outcome,Err(RarExtractError::Control{partial,cause:RarExtractControlError::Limit{..},..}) if partial.failed==0)
                );
            }
        }
    }
}
#[test]
fn every_optional_limit_mutes_without_stopping_native_output() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    let log = d.path().join("log");
    fs::write(&source, archive(&[FileSpec::new("item", b"A")])).unwrap();
    fs::write(&log, b"").unwrap();
    let run = |diagnostics: RarDiagnosticLimits| {
        let _ = fs::remove_dir_all(&out);
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c = RarExtractControl::new(
            Some(OpenOptions::new().append(true).open(&log).unwrap()),
            RarOverwriteMode::Always,
            RarExtractControlLimits { diagnostics, ..Default::default() },
        );
        let mut r =
            s.extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut Quiet);
        let admitted = r.diagnostic().writer().is_some();
        let usage = r.usage();
        let f = r.finish();
        assert_eq!(f.outcome.unwrap().files, 1);
        (admitted, usage)
    };
    let (admitted, b) = run(RarDiagnosticLimits::default());
    assert!(admitted);
    for field in 0..7 {
        let value = match field {
            0 => b.diagnostics.targets,
            1 => b.diagnostics.parents,
            2 => b.diagnostics.capacity_peak,
            3 => b.diagnostics.open_handles_peak,
            4 => b.diagnostics.work,
            5 => b.diagnostics.io_attempts,
            6 => b.diagnostics.checkpoint_attempts_peak,
            _ => unreachable!(),
        };
        assert!(value > 0);
        for exact in [true, false] {
            let value = if exact { value } else { value - 1 };
            let mut l = RarDiagnosticLimits::default();
            match field {
                0 => l.targets = value,
                1 => l.parents = value,
                2 => l.capacity = value,
                3 => l.open_handles = value,
                4 => l.work = value,
                5 => l.io_attempts = value,
                6 => l.checkpoint_attempts = value,
                _ => unreachable!(),
            };
            assert_eq!(run(l).0, exact, "field {field}");
        }
    }
}
#[test]
fn source_and_failed_target_aliases_mute_but_keep_native_status() {
    for source_alias in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("a.rar");
        let target = d.path().join("item");
        fs::write(&source, archive_with(&[(FileSpec::new("item", b"new"), 0)], false)).unwrap();
        fs::write(&target, b"old").unwrap();
        let before = fs::read(if source_alias { &source } else { &target }).unwrap();
        let diagnostic = OpenOptions::new().append(true).open(if source_alias { &source } else { &target }).unwrap();
        let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = s.select(|_| true).unwrap();
        let mut c =
            RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
        let f = s
            .extract_selected_controlled(
                &selected,
                &options(d.path()),
                RarDecodeLimits::default(),
                &mut c,
                &mut Observer { replace: true, calls: 0, outcomes: 0 },
            )
            .finish();
        assert_eq!(f.outcome.unwrap().failed, 1);
        assert!(f.diagnostic_failure.is_some());
        assert_eq!(fs::read(if source_alias { &source } else { &target }).unwrap(), before);
    }
}
#[test]
fn writable_search_only_parent_and_unreadable_target_support_ask_replace() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("item"), b"old").unwrap();
    fs::write(&source, archive(&[FileSpec::new("item", b"new")])).unwrap();
    fs::set_permissions(out.join("item"), fs::Permissions::from_mode(0o0)).unwrap();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o300)).unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
    let f = s
        .extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut Quiet)
        .finish();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(f.outcome.unwrap().files, 1);
    assert_eq!(fs::read(out.join("item")).unwrap(), b"new");
}
#[test]
fn replacing_target_while_asking_cannot_transfer_approval() {
    struct Swap;
    impl RarExtractObserver for Swap {
        fn overwrite(
            &mut self,
            c: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            fs::remove_file(c.target).unwrap();
            fs::write(c.target, b"foreign").unwrap();
            Ok(RarOverwriteDecision::Replace)
        }
        fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    fs::write(&source, archive(&[FileSpec::new("item", b"new")])).unwrap();
    fs::write(d.path().join("item"), b"old").unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
    let f = s
        .extract_selected_controlled(&selected, &options(d.path()), RarDecodeLimits::default(), &mut c, &mut Swap)
        .finish();
    assert_eq!(f.outcome.unwrap().failed, 1);
    assert_eq!(fs::read(d.path().join("item")).unwrap(), b"foreign");
}

#[test]
fn committed_directories_finalize_on_control_native_and_decision_stops() {
    use std::os::unix::fs::PermissionsExt;
    struct Stop;
    impl RarExtractObserver for Stop {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            Err(RarDecisionError::Canceled)
        }
        fn entry(&mut self, _: &RarEntryOutcome, _: RarDiagnostic<'_>) {}
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    let long = "x".repeat(200);
    let first = FileSpec { dir: true, unix_mode: Some(0o711), ..FileSpec::new("parent", b"") };
    let second = FileSpec { dir: true, unix_mode: Some(0o710), ..FileSpec::new("parent/child", b"") };
    fs::write(&source, archive(&[first, second, FileSpec::new(&long, b"A")])).unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let prefix = s.select(|m| m.name() != long).unwrap();
    let all = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
    let prefix_usage = s
        .extract_selected_controlled(&prefix, &options(&out), RarDecodeLimits::default(), &mut c, &mut Quiet)
        .finish()
        .usage;
    for stop in 0..6 {
        fs::set_permissions(out.join("parent"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(out.join("parent/child"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&out).unwrap();
        fs::create_dir(&out).unwrap();
        fs::write(out.join(&long), b"old").unwrap();
        let mut limits = RarExtractControlLimits::default();
        match stop {
            0 => limits.work = prefix_usage.work,
            1 => limits.io_attempts = prefix_usage.io_attempts,
            2 => limits.capacity = prefix_usage.capacity_peak,
            3 => limits.decisions = 0,
            _ => {}
        }
        let decode = if stop == 4 {
            RarDecodeLimits { decoded_bytes: 0, ..Default::default() }
        } else {
            RarDecodeLimits::default()
        };
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, limits);
        let report = if stop == 5 {
            s.extract_selected_controlled(&all, &options(&out), decode, &mut c, &mut Stop)
        } else {
            s.extract_selected_controlled(&all, &options(&out), decode, &mut c, &mut Quiet)
        };
        assert!(report.outcome().is_err(), "stop {stop}: {:?}", report.outcome());
        for (path, mode) in [(out.join("parent"), 0o711), (out.join("parent/child"), 0o710)] {
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, mode, "stop {stop}");
        }
        fs::set_permissions(out.join("parent"), fs::Permissions::from_mode(0o750)).unwrap();
        drop(report);
        assert_eq!(fs::metadata(out.join("parent")).unwrap().permissions().mode() & 0o777, 0o750);
    }
}
#[test]
fn closed_control_requires_explicit_reset_and_recovery_returns_same_file_and_flags() {
    use std::os::fd::AsRawFd;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let log = d.path().join("log");
    fs::write(&source, archive(&[FileSpec::new("a", b"A")])).unwrap();
    let diagnostic = OpenOptions::new().create_new(true).append(true).open(&log).unwrap();
    let fd = diagnostic.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
    drop(s.extract_selected_controlled(&selected, &options(d.path()), RarDecodeLimits::default(), &mut c, &mut Quiet));
    assert_eq!(c.usage().phase, RarExtractControlPhase::Closed);
    assert_eq!(c.usage().diagnostics.capacity, 0);
    let f = s
        .extract_selected_controlled(&selected, &options(d.path()), RarDecodeLimits::default(), &mut c, &mut Quiet)
        .finish();
    assert!(matches!(f.outcome,Err(RarExtractError::ControlNotReset{partial}) if partial.matched==0&&partial.files==0));
    assert!(c.reset().is_ok());
    assert!(c.early_diagnostic().writer().is_none());
    let recovery = c.into_diagnostic();
    let file = recovery.diagnostic.unwrap();
    assert_eq!(file.as_raw_fd(), fd);
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
    assert_eq!(recovery.aftermath.usage.diagnostic_files, 1);
}

#[test]
fn native_pty_pipe_socket_and_fifo_are_available_before_catalogue() {
    use std::{
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt, net::UnixStream},
        },
    };
    fn check(file: File) {
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let mut c = RarExtractControl::new(Some(file), RarOverwriteMode::Ask, RarExtractControlLimits::default());
        let mut view = c.early_diagnostic();
        assert!(view.writer().is_some());
        assert_eq!(view.snapshot().state, RarDiagnosticState::AllowedByKind);
        let recovered = c.into_diagnostic().diagnostic.unwrap();
        assert_eq!(recovered.as_raw_fd(), fd);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) }, flags);
    }
    let mut master = 0;
    let mut slave = 0;
    assert_eq!(
        unsafe {
            libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        },
        0
    );
    let _master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    assert_eq!(unsafe { libc::isatty(slave.as_raw_fd()) }, 1);
    check(slave);
    let mut pipe = [0; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let _read = unsafe { File::from_raw_fd(pipe[0]) };
    check(unsafe { File::from_raw_fd(pipe[1]) });
    let (socket, _peer) = UnixStream::pair().unwrap();
    let fd: std::os::fd::OwnedFd = socket.into();
    check(fd.into());
    let d = tempfile::tempdir().unwrap();
    let fifo = d.path().join("fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    check(OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open(fifo).unwrap());
}
#[test]
fn repeated_prompt_writer_refreshes_parent_and_leaf_bindings() {
    struct Rename {
        seen: bool,
        log: std::path::PathBuf,
    }
    impl RarExtractObserver for Rename {
        fn overwrite(
            &mut self,
            c: &RarOverwriteConflict<'_>,
            mut diagnostic: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            assert!(diagnostic.writer().is_some());
            let parent = c.target.parent().unwrap();
            let moved = parent.with_extension("moved");
            fs::rename(parent, &moved).unwrap();
            fs::create_dir(parent).unwrap();
            fs::hard_link(&self.log, c.target).unwrap();
            assert!(diagnostic.writer().is_none());
            self.seen = true;
            Ok(RarOverwriteDecision::Replace)
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut d: RarDiagnostic<'_>) {
            assert!(d.writer().is_none());
        }
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    let log = d.path().join("log");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("item"), b"old").unwrap();
    fs::write(&log, b"log").unwrap();
    fs::write(&source, archive(&[FileSpec::new("item", b"new")])).unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(
        Some(OpenOptions::new().append(true).open(&log).unwrap()),
        RarOverwriteMode::Ask,
        RarExtractControlLimits::default(),
    );
    let mut o = Rename { seen: false, log: log.clone() };
    let f =
        s.extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut o).finish();
    assert!(o.seen);
    assert_eq!(f.outcome.unwrap().failed, 1);
    assert_eq!(fs::read(log).unwrap(), b"log");
    assert_eq!(fs::read(out.with_extension("moved").join("item")).unwrap(), b"old");
}

#[test]
fn foreign_future_target_is_not_recaptured_as_an_engine_creation() {
    struct Install {
        log: std::path::PathBuf,
        target: std::path::PathBuf,
        denied: bool,
    }
    impl RarExtractObserver for Install {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!()
        }
        fn entry(&mut self, e: &RarEntryOutcome, mut d: RarDiagnostic<'_>) {
            if e.entry.order == 0 {
                fs::hard_link(&self.log, &self.target).unwrap();
            } else {
                self.denied = d.writer().is_none();
            }
        }
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    let log = d.path().join("log");
    fs::write(&source, archive(&[FileSpec::new("a", b"A"), FileSpec::new("b", b"B")])).unwrap();
    fs::write(&log, b"old log").unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(
        Some(OpenOptions::new().append(true).open(&log).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut o = Install { log: log.clone(), target: out.join("b"), denied: false };
    let f =
        s.extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut o).finish();
    assert_eq!(f.outcome.unwrap().files, 2);
    assert!(o.denied);
    assert_eq!(fs::read(log).unwrap(), b"old log");
}

#[test]
fn controlled_skip_preserves_one_run_solid_history() {
    use zipfast::rar5::testenc::{Op, tuned_blocks};
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let first = tuned_blocks(&[&[Op::Lit(b'a'), Op::Lit(b'b'), Op::Lit(b'c')]], true);
    let next = tuned_blocks(&[&[Op::Match(3, 3)]], true);
    let initial = FileSpec { method: 3, size: Some(3), ..FileSpec::new("initial", &first) };
    let dependent = FileSpec { method: 3, size: Some(3), solid: true, ..FileSpec::new("dependent", &next) };
    fs::write(&source, archive_with(&[(initial, crc32fast::hash(b"abc")), (dependent, crc32fast::hash(b"abc"))], true))
        .unwrap();
    fs::write(d.path().join("initial"), b"old").unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(None, RarOverwriteMode::Skip, RarExtractControlLimits::default());
    let f = s
        .extract_selected_controlled(
            &selected,
            &options(d.path()),
            RarDecodeLimits { packed_bytes: (first.len() + next.len()) as u64, decoded_bytes: 6, ..Default::default() },
            &mut c,
            &mut Quiet,
        )
        .finish();
    let summary = f.outcome.unwrap();
    assert_eq!((summary.files, summary.skipped, summary.failed), (1, 1, 0));
    assert_eq!(fs::read(d.path().join("initial")).unwrap(), b"old");
    assert_eq!(fs::read(d.path().join("dependent")).unwrap(), b"abc");
}
#[test]
fn flattened_duplicate_and_empty_outputs_share_the_guard_projection() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    let log = d.path().join("log");
    fs::write(
        &source,
        archive(&[
            FileSpec::new("one/item", b"A"),
            FileSpec::new("two/item", b""),
            FileSpec { dir: true, ..FileSpec::new("no-target", b"") },
        ]),
    )
    .unwrap();
    fs::write(&log, b"").unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(
        Some(OpenOptions::new().append(true).open(log).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut opts = options(&out);
    opts.flatten = true;
    let mut r = s.extract_selected_controlled(&selected, &opts, RarDecodeLimits::default(), &mut c, &mut Quiet);
    assert!(r.diagnostic().writer().is_some(), "{:?}", r.diagnostic_failure());
    let f = r.finish();
    let summary = f.outcome.unwrap();
    assert_eq!((summary.files, summary.dirs), (2, 1));
    assert_eq!(fs::read(out.join("item")).unwrap(), b"");
    assert!(!out.join("no-target").exists());
}

#[test]
fn known_target_alias_precedes_an_unrelated_metadata_obstruction() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("a.rar");
    let out = d.path().join("out");
    let blocked = out.join("blocked");
    fs::create_dir_all(&blocked).unwrap();
    let alias = out.join("alias");
    fs::write(&alias, b"original").unwrap();
    fs::write(&source, archive(&[FileSpec::new("blocked/item", b"A"), FileSpec::new("alias", b"B")])).unwrap();
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o0)).unwrap();
    let mut s = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = s.select(|_| true).unwrap();
    let mut c = RarExtractControl::new(
        Some(OpenOptions::new().append(true).open(&alias).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let f = s
        .extract_selected_controlled(&selected, &options(&out), RarDecodeLimits::default(), &mut c, &mut Quiet)
        .finish();
    fs::set_permissions(blocked, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(f.diagnostic_failure, Some(RarDiagnosticFailure::AliasTarget { ordinal: 1 })));
    assert_eq!(fs::read(alias).unwrap(), b"original");
}

#[test]
fn corrupt_payload_keeps_regular_diagnostics_for_created_directories() {
    struct Log<'a> {
        bad: &'a Path,
        messages: usize,
    }
    impl RarExtractObserver for Log<'_> {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!("no existing targets")
        }
        fn entry(&mut self, entry: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            if entry.entry.order == 0 {
                assert!(
                    matches!(&entry.outcome, zipfast::extract::RarOutcome::Failed(failure) if matches!(failure.as_ref(), zipfast::error::RarFailure::Integrity { .. }))
                );
                assert!(!self.bad.exists());
                assert_eq!(
                    fs::read_dir(self.bad.parent().unwrap()).unwrap().count(),
                    0,
                    "unsuccessful stage is cleaned before callback"
                );
            }
            diagnostic
                .writer()
                .expect("independent log remains writable after a corrupt payload")
                .write_all(if entry.entry.order == 0 { b"corrupt\n" } else { b"valid\n" })
                .unwrap();
            self.messages += 1;
        }
    }
    for nested in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        let dest = d.path().join("new-destination");
        let log = d.path().join("log");
        let bad = if nested { "new/parents/bad" } else { "bad" };
        let good = if nested { "new/parents/good" } else { "good" };
        let corrupt = vec![b'x'; 70_000];
        let original = archive_with(
            &[
                (FileSpec::new(bad, &corrupt), crc32fast::hash(&corrupt) ^ 1),
                (FileSpec::new(good, b"verified"), crc32fast::hash(b"verified")),
            ],
            false,
        );
        fs::write(&source, &original).unwrap();
        let diagnostic = OpenOptions::new().create_new(true).append(true).open(&log).unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control =
            RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
        let bad_target = dest.join(bad);
        let mut observer = Log { bad: &bad_target, messages: 0 };
        let mut report = session.extract_selected_controlled(
            &selected,
            &options(&dest),
            RarDecodeLimits::default(),
            &mut control,
            &mut observer,
        );
        let summary = report.outcome().as_ref().unwrap();
        assert_eq!((summary.files, summary.failed, summary.skipped, summary.bytes), (1, 1, 0, 8));
        assert!(report.diagnostic_failure().is_none(), "{:?}", report.diagnostic_failure());
        report.diagnostic().writer().expect("delayed terminal log").write_all(b"terminal\n").unwrap();
        assert!(report.finish().diagnostic_failure.is_none());
        assert_eq!(observer.messages, 2);
        assert!(!bad_target.exists());
        assert_eq!(fs::read(dest.join(good)).unwrap(), b"verified");
        assert_eq!(fs::read(log).unwrap(), b"corrupt\nvalid\nterminal\n");
        assert_eq!(fs::read(source).unwrap(), original);
    }
}

#[test]
fn dot_and_repeated_separator_destinations_keep_regular_diagnostics() {
    struct Log;
    impl RarExtractObserver for Log {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!("new targets")
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            diagnostic
                .writer()
                .expect("equivalent destination components remain admitted")
                .write_all(b"entry\n")
                .unwrap();
        }
    }
    for spelling in ["existing/./new", "new/.", "new/./", "new//", "new//./"] {
        for nested in [false, true] {
            for corrupt in [false, true] {
                let d = tempfile::tempdir().unwrap();
                let source = d.path().join("source.rar");
                fs::create_dir(d.path().join("existing")).unwrap();
                if spelling == "new/." || spelling == "new/./" || spelling == "new//./" {
                    fs::create_dir(d.path().join("new")).unwrap();
                }
                let dest = d.path().join(spelling);
                let log = d.path().join("log");
                let a = if nested { "nested/a" } else { "a" };
                let b = if nested { "nested/b" } else { "b" };
                fs::write(
                    &source,
                    archive_with(
                        &[
                            (FileSpec::new(a, b"A"), crc32fast::hash(b"A") ^ u32::from(corrupt)),
                            (FileSpec::new(b, b"B"), crc32fast::hash(b"B")),
                        ],
                        false,
                    ),
                )
                .unwrap();
                let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
                let selected = session.select(|_| true).unwrap();
                let mut control = RarExtractControl::new(
                    Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
                    RarOverwriteMode::Always,
                    RarExtractControlLimits::default(),
                );
                let mut report = session.extract_selected_controlled(
                    &selected,
                    &options(&dest),
                    RarDecodeLimits::default(),
                    &mut control,
                    &mut Log,
                );
                let summary = report.outcome().as_ref().unwrap();
                assert_eq!(
                    (summary.files, summary.failed, summary.skipped),
                    (if corrupt { 1 } else { 2 }, u64::from(corrupt), 0)
                );
                report
                    .diagnostic()
                    .writer()
                    .expect("terminal log after harmless spelling variations")
                    .write_all(b"terminal\n")
                    .unwrap();
                assert!(report.finish().diagnostic_failure.is_none());
                assert_eq!(fs::read(dest.join(b)).unwrap(), b"B");
                assert_eq!(dest.join(a).exists(), !corrupt);
                assert_eq!(fs::read(log).unwrap(), b"entry\nentry\nterminal\n");
            }
        }
    }
}

#[test]
fn replacing_one_selected_hardlink_preserves_other_target_diagnostics() {
    struct Log {
        skip_second: bool,
        quiet: bool,
    }
    impl RarExtractObserver for Log {
        fn overwrite(
            &mut self,
            conflict: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            Ok(if conflict.entry.order == 1 && self.skip_second {
                RarOverwriteDecision::Skip
            } else {
                RarOverwriteDecision::Replace
            })
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            if !self.quiet {
                diagnostic
                    .writer()
                    .expect("known incumbent unlink does not revoke unrelated logging")
                    .write_all(b"entry\n")
                    .unwrap();
            }
        }
    }
    for (skip_second, always) in [(false, false), (true, false), (false, true)] {
        for quiet in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let source = d.path().join("source.rar");
            let dest = d.path().join("out");
            let log = d.path().join("log");
            let survivor = d.path().join("old-link");
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("a"), b"incumbent").unwrap();
            fs::hard_link(dest.join("a"), dest.join("b")).unwrap();
            fs::hard_link(dest.join("a"), &survivor).unwrap();
            fs::write(&source, archive(&[FileSpec::new("a", b"A"), FileSpec::new("b", b"B")])).unwrap();
            let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
            let selected = session.select(|_| true).unwrap();
            let mut control = RarExtractControl::new(
                Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
                if always { RarOverwriteMode::Always } else { RarOverwriteMode::Ask },
                RarExtractControlLimits::default(),
            );
            let mut observer = Log { skip_second, quiet };
            let mut report = session.extract_selected_controlled(
                &selected,
                &options(&dest),
                RarDecodeLimits::default(),
                &mut control,
                &mut observer,
            );
            let summary = report.outcome().as_ref().unwrap();
            assert_eq!(
                (summary.files, summary.skipped, summary.failed),
                (if skip_second { 1 } else { 2 }, u64::from(skip_second), 0)
            );
            assert_eq!(report.usage().decision_calls, if always { 0 } else { 2 });
            report
                .diagnostic()
                .writer()
                .expect("quiet and terminal paths retain valid hardlink observations")
                .write_all(b"terminal\n")
                .unwrap();
            assert!(report.finish().diagnostic_failure.is_none());
            assert_eq!(fs::read(dest.join("a")).unwrap(), b"A");
            assert_eq!(
                fs::read(dest.join("b")).unwrap(),
                if skip_second { b"incumbent".as_slice() } else { b"B".as_slice() }
            );
            assert_eq!(fs::read(survivor).unwrap(), b"incumbent");
            assert_eq!(
                fs::read(log).unwrap(),
                if quiet { b"terminal\n".as_slice() } else { b"entry\nentry\nterminal\n".as_slice() }
            );
        }
    }
}

#[test]
fn terminal_dot_after_symlink_to_regular_protects_the_followed_obstruction() {
    use std::os::unix::fs::symlink;
    struct Log {
        admitted: bool,
    }
    impl RarExtractObserver for Log {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!("obstructed root")
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            if let Some(file) = diagnostic.writer() {
                self.admitted = true;
                file.write_all(b"entry\n").unwrap();
            }
        }
    }
    for aliases in [true, false] {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        let obstruction = d.path().join("obstruction");
        let alias = d.path().join("alias");
        let independent = d.path().join("log");
        fs::write(&source, archive(&[FileSpec::new("a", b"A")])).unwrap();
        fs::write(&obstruction, b"original bytes").unwrap();
        fs::write(&independent, b"").unwrap();
        symlink(&obstruction, &alias).unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let diagnostic =
            OpenOptions::new().append(true).open(if aliases { &obstruction } else { &independent }).unwrap();
        let mut control =
            RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
        let mut observer = Log { admitted: false };
        let mut report = session.extract_selected_controlled(
            &selected,
            &options(&alias.join(".")),
            RarDecodeLimits::default(),
            &mut control,
            &mut observer,
        );
        assert!(
            matches!(report.outcome(),Err(RarExtractError::Native(error)) if error.partial.files==0&&error.partial.failed==1)
        );
        if let Some(file) = report.diagnostic().writer() {
            file.write_all(b"terminal\n").unwrap();
        }
        report.finish();
        assert_eq!(
            fs::read(&obstruction).unwrap(),
            b"original bytes",
            "diagnostics must preserve the followed regular obstruction"
        );
        assert_eq!(observer.admitted, !aliases);
        assert_eq!(
            fs::read(independent).unwrap(),
            if aliases { b"".as_slice() } else { b"entry\nterminal\n".as_slice() }
        );
    }
}

#[test]
fn symlink_and_parent_components_keep_their_lookup_semantics() {
    use std::os::unix::fs::symlink;
    for parent_component in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        let real = d.path().join("elsewhere");
        fs::create_dir_all(real.join("child")).unwrap();
        symlink(real.join("child"), d.path().join("link")).unwrap();
        let (dest, actual) = if parent_component {
            fs::create_dir(real.join("destination")).unwrap();
            (d.path().join("link/../destination/."), real.join("destination"))
        } else {
            (d.path().join("link/."), real.join("child"))
        };
        let log = d.path().join("log");
        fs::write(&source, archive(&[FileSpec::new("nested/a", b"A")])).unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control = RarExtractControl::new(
            Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
            RarOverwriteMode::Always,
            RarExtractControlLimits::default(),
        );
        let mut report = session.extract_selected_controlled(
            &selected,
            &options(&dest),
            RarDecodeLimits::default(),
            &mut control,
            &mut Observer { replace: true, calls: 0, outcomes: 0 },
        );
        assert_eq!(report.outcome().as_ref().unwrap().files, 1);
        report
            .diagnostic()
            .writer()
            .expect("raw symlink/dot and parent-component probes retain actual lookup")
            .write_all(b"terminal\n")
            .unwrap();
        assert!(report.finish().diagnostic_failure.is_none());
        assert_eq!(fs::read(actual.join("nested/a")).unwrap(), b"A");
        assert!(!d.path().join("destination").exists());
        assert_eq!(fs::read(log).unwrap(), b"outcome\nterminal\n");
    }
}

#[test]
fn unrelated_ctime_changes_after_known_unlink_still_revoke_diagnostics() {
    use std::os::unix::fs::MetadataExt;
    struct Change {
        b: std::path::PathBuf,
        extra: std::path::PathBuf,
    }
    impl RarExtractObserver for Change {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            Ok(RarOverwriteDecision::Replace)
        }
        fn entry(&mut self, entry: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            if entry.entry.order == 0 {
                diagnostic.writer().expect("known unlink was admitted").write_all(b"first\n").unwrap();
                let before = fs::metadata(&self.b).unwrap();
                fs::hard_link(&self.b, &self.extra).unwrap();
                fs::remove_file(&self.extra).unwrap();
                let after = fs::metadata(&self.b).unwrap();
                assert_eq!(
                    (after.ino(), after.nlink(), after.len(), after.mtime(), after.mtime_nsec()),
                    (before.ino(), before.nlink(), before.len(), before.mtime(), before.mtime_nsec())
                );
                assert_ne!((after.ctime(), after.ctime_nsec()), (before.ctime(), before.ctime_nsec()));
                assert!(
                    diagnostic.writer().is_none(),
                    "an unrelated ctime-only change must not inherit unlink authority"
                );
            } else {
                assert!(diagnostic.writer().is_none());
            }
        }
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.rar");
    let out = d.path().join("out");
    fs::create_dir(&out).unwrap();
    fs::write(out.join("a"), b"old").unwrap();
    fs::hard_link(out.join("a"), out.join("b")).unwrap();
    fs::write(&source, archive(&[FileSpec::new("a", b"A"), FileSpec::new("b", b"B")])).unwrap();
    let log = d.path().join("log");
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Ask,
        RarExtractControlLimits::default(),
    );
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&out),
        RarDecodeLimits::default(),
        &mut control,
        &mut Change { b: out.join("b"), extra: d.path().join("extra") },
    );
    assert_eq!(report.outcome().as_ref().unwrap().files, 2);
    assert!(report.diagnostic().writer().is_none());
    assert!(report.finish().diagnostic_failure.is_some());
    assert_eq!(fs::read(log).unwrap(), b"first\n");
    assert_eq!(fs::read(out.join("a")).unwrap(), b"A");
    assert_eq!(fs::read(out.join("b")).unwrap(), b"B");
}

#[test]
fn selected_leaf_symlinks_protect_followed_bytes_and_keep_distinct_logging() {
    use std::os::unix::fs::symlink;
    for replace_referent in [false, true] {
        for aliases in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let source = d.path().join("source.rar");
            let out = d.path().join("out");
            let original = d.path().join("original-link");
            let log = d.path().join("log");
            fs::create_dir(&out).unwrap();
            fs::write(out.join("a"), b"incumbent").unwrap();
            fs::hard_link(out.join("a"), &original).unwrap();
            symlink(out.join("a"), out.join("leaf")).unwrap();
            let members = if replace_referent {
                vec![FileSpec::new("a", b"A"), FileSpec::new("leaf", b"L")]
            } else {
                vec![FileSpec::new("leaf", b"L")]
            };
            fs::write(&source, archive(&members)).unwrap();
            fs::write(&log, b"").unwrap();
            let diagnostic = OpenOptions::new().append(true).open(if aliases { &original } else { &log }).unwrap();
            let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
            let selected = session.select(|_| true).unwrap();
            let mut control =
                RarExtractControl::new(Some(diagnostic), RarOverwriteMode::Always, RarExtractControlLimits::default());
            let mut report = session.extract_selected_controlled(
                &selected,
                &options(&out),
                RarDecodeLimits::default(),
                &mut control,
                &mut Observer { replace: true, calls: 0, outcomes: 0 },
            );
            let summary = report.outcome().as_ref().unwrap();
            assert_eq!((summary.files, summary.failed), (u64::from(replace_referent), 1));
            if aliases {
                assert!(report.diagnostic().writer().is_none());
            } else {
                report
                    .diagnostic()
                    .writer()
                    .expect("a rejected symlink target does not silence independent logging")
                    .write_all(b"terminal\n")
                    .unwrap();
            }
            let finished = report.finish();
            assert_eq!(finished.diagnostic_failure.is_some(), aliases);
            assert_eq!(fs::read(original).unwrap(), b"incumbent");
            assert_eq!(
                fs::read(out.join("a")).unwrap(),
                if replace_referent { b"A".as_slice() } else { b"incumbent".as_slice() }
            );
            assert_eq!(
                fs::read(log).unwrap(),
                if aliases {
                    b"".as_slice()
                } else if replace_referent {
                    b"outcome\noutcome\nterminal\n".as_slice()
                } else {
                    b"outcome\nterminal\n".as_slice()
                }
            );
        }
    }
}

#[test]
fn dangling_followed_bindings_are_not_treated_as_permission_for_later_objects() {
    use std::os::unix::fs::symlink;
    struct Observer {
        referent: std::path::PathBuf,
        log: std::path::PathBuf,
        install: bool,
    }
    impl RarExtractObserver for Observer {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!("symlink target refused")
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            diagnostic.writer().expect("proven dangling target permits distinct log").write_all(b"first\n").unwrap();
            if self.install {
                fs::hard_link(&self.log, &self.referent).unwrap();
                assert!(diagnostic.writer().is_none(), "new followed alias must revoke permission");
            }
        }
    }
    for install in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("source.rar");
        let out = d.path().join("out");
        fs::create_dir(&out).unwrap();
        let referent = d.path().join("missing");
        let log = d.path().join("log");
        symlink(&referent, out.join("leaf")).unwrap();
        fs::write(&source, archive(&[FileSpec::new("leaf", b"L")])).unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control = RarExtractControl::new(
            Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
            RarOverwriteMode::Always,
            RarExtractControlLimits::default(),
        );
        let mut observer = Observer { referent: referent.clone(), log: log.clone(), install };
        let mut report = session.extract_selected_controlled(
            &selected,
            &options(&out),
            RarDecodeLimits::default(),
            &mut control,
            &mut observer,
        );
        assert_eq!(report.outcome().as_ref().unwrap().failed, 1);
        if install {
            assert!(report.diagnostic().writer().is_none());
        } else {
            report.diagnostic().writer().unwrap().write_all(b"terminal\n").unwrap();
        }
        assert_eq!(report.finish().diagnostic_failure.is_some(), install);
        assert_eq!(
            fs::read(log).unwrap(),
            if install { b"first\n".as_slice() } else { b"first\nterminal\n".as_slice() }
        );
        if install {
            assert_eq!(fs::read(referent).unwrap(), b"first\n");
        }
    }
}

#[test]
fn followed_symlink_records_obey_separate_path_capacity_and_attempt_limits() {
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.rar");
    let out = d.path().join("out");
    let referent = d.path().join("referent");
    let log = d.path().join("log");
    fs::create_dir(&out).unwrap();
    fs::write(&referent, b"old").unwrap();
    fs::write(&log, b"").unwrap();
    symlink(&referent, out.join("leaf")).unwrap();
    fs::write(&source, archive(&[FileSpec::new("leaf", b"L")])).unwrap();
    let run = |diagnostics: RarDiagnosticLimits| {
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selected = session.select(|_| true).unwrap();
        let mut control = RarExtractControl::new(
            Some(OpenOptions::new().append(true).open(&log).unwrap()),
            RarOverwriteMode::Always,
            RarExtractControlLimits { diagnostics, ..Default::default() },
        );
        let mut report = session.extract_selected_controlled(
            &selected,
            &options(&out),
            RarDecodeLimits::default(),
            &mut control,
            &mut Quiet,
        );
        let admitted = report.diagnostic().writer().is_some();
        let usage = report.usage();
        assert_eq!(report.finish().outcome.unwrap().failed, 1);
        (admitted, usage)
    };
    let (admitted, usage) = run(RarDiagnosticLimits::default());
    assert!(admitted);
    assert_eq!(usage.diagnostics.targets, 1, "followed records do not add logical targets");
    for field in 0..7 {
        let value = match field {
            0 => usage.diagnostics.targets,
            1 => usage.diagnostics.parents,
            2 => usage.diagnostics.capacity_peak,
            3 => usage.diagnostics.open_handles_peak,
            4 => usage.diagnostics.work,
            5 => usage.diagnostics.io_attempts,
            6 => usage.diagnostics.checkpoint_attempts_peak,
            _ => unreachable!(),
        };
        for exact in [true, false] {
            let allowed = if exact { value } else { value - 1 };
            let mut limits = RarDiagnosticLimits::default();
            match field {
                0 => limits.targets = allowed,
                1 => limits.parents = allowed,
                2 => limits.capacity = allowed,
                3 => limits.open_handles = allowed,
                4 => limits.work = allowed,
                5 => limits.io_attempts = allowed,
                6 => limits.checkpoint_attempts = allowed,
                _ => unreachable!(),
            };
            assert_eq!(run(limits).0, exact, "followed field {field}");
        }
    }
}

#[test]
fn missing_trailing_dot_root_retains_incumbent_native_behavior() {
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.rar");
    let root = d.path().join("missing");
    let dest = root.join(".");
    fs::write(&source, archive(&[FileSpec::new("a", b"A")])).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let legacy = session.extract_selected(&selected, &options(&dest), RarDecodeLimits::default(), |_| {});
    if root.exists() {
        fs::remove_dir_all(&root).unwrap();
    }
    let log = d.path().join("log");
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(log).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&dest),
        RarDecodeLimits::default(),
        &mut control,
        &mut Quiet,
    );
    match (&legacy, report.outcome()) {
        (Ok(left), Ok(right)) => {
            assert_eq!((left.files, left.failed, left.bytes), (right.files, right.failed, right.bytes))
        }
        (Err(left), Err(RarExtractError::Native(right))) => {
            assert_eq!(format!("{:?}", left.failure), format!("{:?}", right.failure));
            assert_eq!((left.partial.files, left.partial.failed), (right.partial.files, right.partial.failed));
        }
        other => panic!("incumbent and controlled native outcomes differ: {other:?}"),
    }
    #[cfg(target_os = "macos")]
    assert!(
        matches!(report.outcome(),Err(RarExtractError::Native(error)) if matches!(error.failure.as_ref(),zipfast::error::RarFailure::Output{operation:zipfast::error::IoOperation::CreateDirectory,source,..} if source.raw_os_error()==Some(libc::ENOENT)))
    );
    assert!(report.diagnostic().writer().is_some());
    report.finish();
}

#[test]
fn foreign_hardlink_parent_rebinding_is_not_admitted_as_an_unlink_effect() {
    struct Rebind {
        out: std::path::PathBuf,
    }
    impl RarExtractObserver for Rebind {
        fn overwrite(
            &mut self,
            conflict: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            if conflict.entry.order == 0 {
                fs::rename(self.out.join("nested"), self.out.join("old-parent")).unwrap();
                fs::create_dir(self.out.join("nested")).unwrap();
                fs::write(self.out.join("nested/b"), b"foreign").unwrap();
            }
            Ok(RarOverwriteDecision::Replace)
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            assert!(diagnostic.writer().is_none(), "publication cannot authorize a foreign parent rebinding");
        }
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.rar");
    let out = d.path().join("out");
    let log = d.path().join("log");
    fs::create_dir_all(out.join("nested")).unwrap();
    fs::write(out.join("a"), b"incumbent").unwrap();
    fs::hard_link(out.join("a"), out.join("nested/b")).unwrap();
    fs::write(&source, archive(&[FileSpec::new("a", b"A"), FileSpec::new("nested/b", b"B")])).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Ask,
        RarExtractControlLimits::default(),
    );
    let finished = session
        .extract_selected_controlled(
            &selected,
            &options(&out),
            RarDecodeLimits::default(),
            &mut control,
            &mut Rebind { out: out.clone() },
        )
        .finish();
    assert_eq!(finished.outcome.unwrap().files, 2);
    assert!(finished.diagnostic_failure.is_some());
    assert_eq!(fs::read(out.join("a")).unwrap(), b"A");
    assert_eq!(fs::read(out.join("nested/b")).unwrap(), b"B");
    assert_eq!(fs::read(out.join("old-parent/b")).unwrap(), b"incumbent");
    assert!(fs::read(log).unwrap().is_empty());
}

#[test]
fn a_rebound_leaf_symlink_revokes_its_followed_authority() {
    use std::os::unix::fs::symlink;
    struct Rebind {
        leaf: std::path::PathBuf,
        log: std::path::PathBuf,
    }
    impl RarExtractObserver for Rebind {
        fn overwrite(
            &mut self,
            _: &RarOverwriteConflict<'_>,
            _: RarDiagnostic<'_>,
        ) -> Result<RarOverwriteDecision, RarDecisionError> {
            panic!("symlink refused")
        }
        fn entry(&mut self, _: &RarEntryOutcome, mut diagnostic: RarDiagnostic<'_>) {
            diagnostic.writer().expect("initial distinct referent").write_all(b"before\n").unwrap();
            fs::remove_file(&self.leaf).unwrap();
            symlink(&self.log, &self.leaf).unwrap();
            assert!(diagnostic.writer().is_none());
        }
    }
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.rar");
    let out = d.path().join("out");
    fs::create_dir(&out).unwrap();
    let referent = d.path().join("referent");
    fs::write(&referent, b"original").unwrap();
    let leaf = out.join("leaf");
    symlink(&referent, &leaf).unwrap();
    let log = d.path().join("log");
    fs::write(&source, archive(&[FileSpec::new("leaf", b"L")])).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&out),
        RarDecodeLimits::default(),
        &mut control,
        &mut Rebind { leaf, log: log.clone() },
    );
    assert_eq!(report.outcome().as_ref().unwrap().failed, 1);
    assert!(report.diagnostic().writer().is_none());
    assert!(report.finish().diagnostic_failure.is_some());
    assert_eq!(fs::read(log).unwrap(), b"before\n");
    assert_eq!(fs::read(referent).unwrap(), b"original");
}

#[test]
fn engine_created_referents_of_dangling_selected_symlinks_remain_loggable() {
    use std::os::unix::fs::symlink;
    for directory in [false, true] {
        for corrupt in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let source = d.path().join("source.rar");
            let out = d.path().join("out");
            let log = d.path().join("log");
            fs::create_dir(&out).unwrap();
            let name = if directory { "nested/a" } else { "a" };
            symlink(out.join(if directory { "nested" } else { "a" }), out.join("leaf")).unwrap();
            fs::write(
                &source,
                archive_with(
                    &[
                        (FileSpec::new(name, b"A"), crc32fast::hash(b"A") ^ u32::from(corrupt)),
                        (FileSpec::new("leaf", b"L"), crc32fast::hash(b"L")),
                    ],
                    false,
                ),
            )
            .unwrap();
            let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
            let selected = session.select(|_| true).unwrap();
            let mut control = RarExtractControl::new(
                Some(OpenOptions::new().create_new(true).append(true).open(&log).unwrap()),
                RarOverwriteMode::Always,
                RarExtractControlLimits::default(),
            );
            let mut report = session.extract_selected_controlled(
                &selected,
                &options(&out),
                RarDecodeLimits::default(),
                &mut control,
                &mut Observer { replace: true, calls: 0, outcomes: 0 },
            );
            let summary = report.outcome().as_ref().unwrap();
            assert_eq!((summary.files, summary.failed), (u64::from(!corrupt), 1 + u64::from(corrupt)));
            report
                .diagnostic()
                .writer()
                .expect("known created referent must not masquerade as a foreign binding")
                .write_all(b"terminal\n")
                .unwrap();
            assert!(report.finish().diagnostic_failure.is_none());
            assert_eq!(fs::read(log).unwrap(), b"outcome\noutcome\nterminal\n");
            assert_eq!(out.join(name).exists(), !corrupt);
        }
    }
}

#[test]
fn an_unresolved_obstruction_inside_a_symlink_target_cannot_prove_distinctness() {
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir().unwrap();
    let source = d.path().join("source.rar");
    let out = d.path().join("out");
    fs::create_dir(&out).unwrap();
    let obstruction = d.path().join("obstruction");
    fs::write(&obstruction, b"original").unwrap();
    symlink(obstruction.join("."), out.join("leaf")).unwrap();
    fs::write(&source, archive(&[FileSpec::new("leaf", b"L")])).unwrap();
    let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
    let selected = session.select(|_| true).unwrap();
    let mut control = RarExtractControl::new(
        Some(OpenOptions::new().append(true).open(&obstruction).unwrap()),
        RarOverwriteMode::Always,
        RarExtractControlLimits::default(),
    );
    let mut report = session.extract_selected_controlled(
        &selected,
        &options(&out),
        RarDecodeLimits::default(),
        &mut control,
        &mut Observer { replace: true, calls: 0, outcomes: 0 },
    );
    assert_eq!(report.outcome().as_ref().unwrap().failed, 1);
    assert!(report.diagnostic().writer().is_none());
    report.finish();
    assert_eq!(fs::read(obstruction).unwrap(), b"original");
}
