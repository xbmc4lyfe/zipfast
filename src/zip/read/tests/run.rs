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
use super::fixture::{Member, build};
use crate::extract::{Mode, Options, Overwrite};
use std::io::Write;
pub(super) fn setup(
    members: &[Member<'_>],
) -> (tempfile::NamedTempFile, ProjectedReadSession, Options, EncryptedReadContext) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let order = (0..members.len()).collect::<Vec<_>>();
    file.write_all(&build(members, &order, b"", b"", members.len() >= 65535).bytes).unwrap();
    let mut s = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap();
    let options = Options {
        mode: Mode::Test,
        dest: std::path::PathBuf::from("."),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let context = EncryptedReadContext::for_projected(
        &mut s,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::Discard,
        Some("pw"),
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap();
    (file, s, options, context)
}
#[test]
fn all_regular_original_action_clear_events_once() {
    let (_file, mut s, o, mut c) = setup(&[Member::stored(b"one", b"abc"), Member::stored(b"two", b"")]);
    let mut successes = 0;
    let mut ended = 0;
    let report = s
        .run_with_context(&o, Some("pw"), &Cancellation::default(), &mut c, |e: ZipRunEvent<'_>| {
            match e {
                ZipRunEvent::MemberSucceeded { .. } => successes += 1,
                ZipRunEvent::RunEnded { .. } => ended += 1,
                _ => panic!("unexpected"),
            };
            Ok(())
        })
        .unwrap();
    assert_eq!((successes, ended, report.files(), report.decoded_bytes()), (2, 1, 2, 3));
    assert_eq!(report.run_usage().records, 2);
    assert_eq!(report.diagnostic_usage(), ZipDiagnosticUsage::default());
}
#[test]
fn observer_fault_stops_without_terminal_callback() {
    for fail in 0..3 {
        let (_file, mut s, o, mut c) = setup(&[Member::stored(b"one", b"a"), Member::stored(b"two", b"b")]);
        let mut callbacks = 0;
        let error = s
            .run_with_context(&o, Some("pw"), &Cancellation::default(), &mut c, |_: ZipRunEvent<'_>| {
                let current = callbacks;
                callbacks += 1;
                if current == fail { Err(ZipSinkFault::StageChanged) } else { Ok(()) }
            })
            .unwrap_err();
        assert_eq!(callbacks, fail + 1);
        assert!(error.diagnostic_fault().is_some());
        assert!(error.partial_run().is_some());
    }
}
#[test]
fn crc_member_fault_then_good_continues() {
    let mut bad = Member::stored(b"bad", b"bad");
    bad.crc = Some(1);
    let (_file, mut s, o, mut c) = setup(&[bad, Member::stored(b"good", b"good")]);
    let mut failures = 0;
    let report = s
        .run_with_context(&o, Some("pw"), &Cancellation::default(), &mut c, |e: ZipRunEvent<'_>| {
            if matches!(e, ZipRunEvent::MemberFailed { .. }) {
                failures += 1;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!((report.failed(), report.files(), failures), (1, 1, 1));
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn staged_crc_member_fault_then_good_requires_normal_retirement() {
    let mut bad = Member::stored(b"bad", b"bad");
    bad.crc = Some(1);
    let (_file, mut s, mut o, old) = setup(&[bad, Member::stored(b"good", b"good")]);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    o.mode = Mode::Extract;
    o.dest = dest.path().to_path_buf();
    let mut c = EncryptedReadContext::for_projected(
        &mut s,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::StagedFiles { destination: &o.dest },
        Some("pw"),
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap();
    let report =
        s.run_with_context(&o, Some("pw"), &Cancellation::default(), &mut c, |_: ZipRunEvent<'_>| Ok(())).unwrap();
    assert_eq!((report.files(), report.failed()), (1, 1));
    assert!(!dest.path().join("bad").exists());
    assert_eq!(std::fs::read(dest.path().join("good")).unwrap(), b"good");
    c.ledger.with_state(|s| {
        assert!(!s.poisoned);
        assert_eq!(s.live_fds, 1);
        assert_eq!(s.run.usage.live_spool_bytes, 0);
    });
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn staged_password_auth_size_and_member_cap_then_good() {
    for case in [0, 1, 2, 3] {
        let mut frame = super::cipher::framed(1, if case == 0 { "wrong" } else { "pw" }, b"bad");
        if case == 1 {
            *frame.last_mut().unwrap() ^= 1;
        }
        let extra = super::fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
        let mut bad = Member::stored(b"bad", &frame);
        bad.flags = 1;
        bad.method = 99;
        bad.decoded = Some(if case == 2 { b"badd" } else { b"bad" });
        bad.central_extra = &extra;
        let (_file, mut session, mut options, old) = setup(&[bad, Member::stored(b"good", b"good")]);
        drop(old);
        let dest = tempfile::tempdir().unwrap();
        options.mode = Mode::Extract;
        options.dest = dest.path().to_path_buf();
        let overrides = if case == 3 {
            EncryptedReadOverrides { member_packed_bytes: Some(22), ..Default::default() }
        } else {
            Default::default()
        };
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::AllRegular,
            None,
            ZipReadOutput::StagedFiles { destination: &options.dest },
            Some("pw"),
            &overrides,
            &Cancellation::default(),
        )
        .unwrap();
        let mut failures = 0;
        let mut successes = 0;
        let mut ended = 0;
        let report = session
            .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |event: ZipRunEvent<'_>| {
                match event {
                    ZipRunEvent::MemberFailed { error, .. } => {
                        failures += 1;
                        assert_eq!(error.cleanup_errors().len(), 0);
                        assert_eq!(error.accepted_output_bytes(), if case == 2 { 3 } else { 0 });
                    }
                    ZipRunEvent::MemberSucceeded { .. } => successes += 1,
                    ZipRunEvent::RunEnded { .. } => ended += 1,
                    _ => panic!("unexpected"),
                };
                Ok(())
            })
            .unwrap();
        assert_eq!((failures, successes, ended, report.files(), report.failed()), (1, 1, 1, 1, 1), "case {case}");
        assert!(!dest.path().join("bad").exists());
        assert_eq!(std::fs::read(dest.path().join("good")).unwrap(), b"good");
        context.ledger.with_state(|s| {
            assert!(!s.poisoned);
            assert_eq!(s.live_fds, 1);
            assert_eq!(s.run.usage.live_spool_bytes, 0);
        });
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn structured_symlink_and_protected_block_then_good() {
    for protected in [false, true] {
        let (_file, mut session, mut options, old) =
            setup(&[Member::stored(b"blocked", b"bad"), Member::stored(b"good", b"good")]);
        drop(old);
        let dest = tempfile::tempdir().unwrap();
        options.mode = Mode::Extract;
        options.overwrite = Overwrite::Always;
        options.dest = dest.path().to_path_buf();
        let target = dest.path().join("protected");
        std::fs::write(&target, b"original").unwrap();
        if protected {
            std::fs::hard_link(&target, dest.path().join("blocked")).unwrap();
            options.protected_paths.insert(target.clone());
        } else {
            std::os::unix::fs::symlink(&target, dest.path().join("blocked")).unwrap();
        }
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
        let report = session
            .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |_: ZipRunEvent<'_>| Ok(()))
            .unwrap();
        assert_eq!((report.files(), report.failed()), (1, 1));
        assert_eq!(std::fs::read(target).unwrap(), b"original");
        assert_eq!(std::fs::read(dest.path().join("good")).unwrap(), b"good");
        assert!(!context.ledger.with_state(|s| s.poisoned));
    }
}

#[test]
fn owned_run_retires_source_before_sole_terminal_event() {
    for close_fault in [None, Some(libc::EINTR), Some(libc::EIO)] {
        let (file, _session, options, old) = setup(&[Member::stored(b"a", b"a")]);
        drop(old);
        let mut ended = 0;
        super::super::run::OWNED_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move |phase, _| {
                if phase == 0 {
                    super::super::projected::CLOSE_FAULT.with(|s| s.set(close_fault));
                }
            }))
        });
        let result = crate::zip::run_with_policy(
            file.path(),
            &options,
            Some("pw"),
            &Cancellation::default(),
            &Default::default(),
            |event: ZipRunEvent<'_>| {
                if let ZipRunEvent::RunEnded { report, error } = event {
                    ended += 1;
                    assert_eq!(report.usage().live_fds, u64::from(close_fault.is_some()));
                    assert_eq!(error.is_some(), close_fault.is_some());
                }
                Ok(())
            },
        );
        super::super::run::OWNED_HOOK.with(|slot| *slot.borrow_mut() = None);
        assert_eq!(ended, 1);
        assert_eq!(result.is_ok(), close_fault.is_none());
        if let Err(error) = result {
            assert!(
                error
                    .cleanup_errors()
                    .any(|f| f.object == OwnedObject::Source && f.operation == ReadIoOperation::Close)
            );
            assert_eq!(error.partial_run().unwrap().usage().live_fds, 1);
        }
    }
}
#[test]
fn owned_source_changes_before_and_after_close_are_not_revived() {
    for phase in [0, 1] {
        let (file, _session, options, old) = setup(&[Member::stored(b"a", b"a")]);
        drop(old);
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
        let mut ended = 0;
        // Source-aware terminal emission is checked in diagnostic tests; raw observers own their I/O.
        let result = crate::zip::run_with_policy(
            file.path(),
            &options,
            Some("pw"),
            &Cancellation::default(),
            &Default::default(),
            |event: ZipRunEvent<'_>| {
                if matches!(event, ZipRunEvent::RunEnded { .. }) {
                    ended += 1;
                }
                Ok(())
            },
        );
        super::super::run::OWNED_HOOK.with(|slot| *slot.borrow_mut() = None);
        assert_eq!(ended, 1);
        if phase == 0 {
            assert!(result.unwrap_err().source_change().is_some());
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn directories_use_depth_then_original_ordinal_and_restore_zero() {
    use std::os::unix::fs::PermissionsExt;
    fn dir(name: &'static [u8], mode: u32) -> Member<'static> {
        let mut e = Member::stored(name, b"");
        e.external = (0o040000 | mode) << 16;
        e
    }
    let members = [dir(b"a/", 0), dir(b"b/", 0o710), dir(b"a/deep/", 0o700), dir(b"a/", 0o751), dir(b"zero/", 0)];
    let (_file, mut session, mut options, old) = setup(&members);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = dest.path().to_path_buf();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::StagedFiles { destination: &options.dest },
        Some("pw"),
        &EncryptedReadOverrides { members: Some(0), io_attempts: Some(0), ..Default::default() },
        &Cancellation::default(),
    )
    .unwrap();
    let visits = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = visits.clone();
    super::super::run::DIRECTORY_HOOK
        .with(|s| *s.borrow_mut() = Some(Box::new(move |ordinal| observed.borrow_mut().push(ordinal))));
    let report = session
        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |_: ZipRunEvent<'_>| Ok(()))
        .unwrap();
    super::super::run::DIRECTORY_HOOK.with(|s| *s.borrow_mut() = None);
    assert_eq!(*visits.borrow(), [2, 0, 1, 3, 4]);
    assert_eq!(report.dirs(), 5);
    assert_eq!(report.usage().io_attempts, 0);
    assert_eq!(report.usage().members, 0);
    assert_eq!(std::fs::metadata(dest.path().join("a")).unwrap().permissions().mode() & 0o777, 0o751);
    assert_eq!(std::fs::metadata(dest.path().join("zero")).unwrap().permissions().mode() & 0o777, 0);
    std::fs::set_permissions(dest.path().join("zero"), std::fs::Permissions::from_mode(0o700)).unwrap();
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn directory_index_allocation_is_before_output_effects() {
    let mut a = Member::stored(b"a/", b"");
    a.external = 0o040755 << 16;
    let mut b = Member::stored(b"b/", b"");
    b.external = 0o040755 << 16;
    let mut c = Member::stored(b"c/", b"");
    c.external = 0o040755 << 16;
    let (_file, mut session, mut options, old) = setup(&[a, b, c]);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = dest.path().to_path_buf();
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
    crate::test_alloc::DENY_LAYOUT
        .with(|s| s.set(Some((3 * std::mem::size_of::<(usize, usize)>(), std::mem::align_of::<(usize, usize)>()))));
    let result =
        session.run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |_: ZipRunEvent<'_>| {
            Ok(())
        });
    crate::test_alloc::DENY_LAYOUT.with(|s| s.set(None));
    assert!(matches!(result.unwrap_err().operation(), Some(ReadFault::Allocation { capacity: 48 })));
    assert_eq!(std::fs::read_dir(dest.path()).unwrap().count(), 0);
    assert_eq!(context.run_usage().records, 0);
}

#[test]
fn borrowed_failure_catalogue_has_constant_live_policy_storage() {
    for count in [1, 5_000] {
        let members = (0..count)
            .map(|_| {
                let mut m = Member::stored(b"bad", b"");
                m.method = 1;
                m
            })
            .collect::<Vec<_>>();
        let (_file, mut session, options, old) = setup(&members);
        drop(old);
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::AllRegular,
            None,
            ZipReadOutput::Discard,
            Some("pw"),
            &EncryptedReadOverrides {
                members: Some(0),
                packed_bytes: Some(0),
                decoded_bytes: Some(0),
                io_bytes: Some(0),
                io_attempts: Some(0),
                work_bytes: Some(0),
                ..Default::default()
            },
            &Cancellation::default(),
        )
        .unwrap();
        let pointers = session.entries().map(|e| e.name.as_ptr()).collect::<Vec<_>>();
        let mut failures = 0;
        let mut ended = 0;
        let report = session
            .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |event: ZipRunEvent<'_>| {
                match event {
                    ZipRunEvent::MemberFailed { ordinal, name, error } => {
                        assert_eq!(name.as_ptr(), pointers[ordinal as usize]);
                        assert!(matches!(error.operation(), Some(ReadFault::UnsupportedMethod { method: 1 })));
                        failures += 1;
                    }
                    ZipRunEvent::RunEnded { .. } => ended += 1,
                    _ => panic!("unexpected"),
                };
                Ok(())
            })
            .unwrap();
        assert_eq!((report.failed(), failures, ended), (count as u64, count, 1));
        let policy = context.policy_metadata_usage().caller;
        assert_eq!(policy.live_capacity, 0);
        assert_eq!(policy.peak_capacity, 4);
        assert_eq!(policy.allocations, count as u64);
        assert_eq!(report.usage().io_attempts, 0);
        assert_eq!(report.run_usage().source_seeks, 0);
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Exercises original-source final checking with inline terminal evidence.
fn normal_member_retirement_admission_fault_keeps_owned_provenance() {
    let mut bad = Member::stored(b"bad", b"bad");
    bad.crc = Some(1);
    let (_file, mut session, mut options, old) = setup(&[bad]);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = dest.path().to_path_buf();
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
    {
        let action = context.action.as_mut().unwrap();
        action.run_bound = true;
        action.active_ordinal = Some(0);
        action.active_record_charged = true;
    }
    context.ledger.with_state(|s| s.charge_category(RunCategory::Records, 1)).unwrap();
    context.ledger.with_state(|s| s.active_encrypted = Some(false));
    let (mut stage, blocked) = ZipReadStage::prepare_run_file(
        session.stage_entry(0).unwrap(),
        Path::new("bad"),
        &options,
        &Cancellation::default(),
        &mut context,
    )
    .unwrap();
    assert!(blocked.is_none());
    let mut stage = stage.take().unwrap();
    let fault = session
        .read_at_with_context(0, Some("pw"), u64::MAX, &Cancellation::default(), &mut context, |b| {
            stage.write_all(b, &Cancellation::default())
        })
        .unwrap_err();
    context
        .ledger
        .with_state(|s| s.test_limit_category(RunCategory::StageFinalization, s.run.usage.stage_finalization));
    let error = stage.finish_member_error(fault, &mut context, &Cancellation::default(), |c| session.check_source(c));
    assert!(matches!(error.operation(), Some(ReadFault::Integrity { .. })));
    assert!(error.cleanup_errors().any(|f| f.object == OwnedObject::OutputPrivateDirectory
        && f.operation == ReadIoOperation::Open
        && matches!(f.cause, CleanupCause::Admission(_))));
    assert!(error.source_change().is_none());
    assert!(context.ledger.with_state(|s| s.poisoned));
    assert!(!dest.path().join("bad").exists());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn actual_many_member_stage_helper_inventory() {
    let names = (0..16).map(|n| format!("file{n}")).collect::<Vec<_>>();
    let members = names.iter().map(|n| Member::stored(n.as_bytes(), b"data")).collect::<Vec<_>>();
    let (_file, mut session, mut options, old) = setup(&members);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = dest.path().to_path_buf();
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
    let result =
        session.run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |_: ZipRunEvent<'_>| {
            Ok(())
        });
    println!("actual 16-member stage inventory {:?}", context.run_usage());
    let report = result.unwrap();
    assert_eq!(report.files(), 16);
    for name in names {
        assert_eq!(std::fs::read(dest.path().join(name)).unwrap(), b"data");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn actual_sixteen_encrypted_members_fit_staged_source_allowance() {
    let names = (0..16).map(|n| format!("aes{n}")).collect::<Vec<_>>();
    let frame = super::cipher::framed(1, "pw", b"data");
    let extra = super::fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let members = names
        .iter()
        .map(|n| {
            let mut m = Member::stored(n.as_bytes(), &frame);
            m.flags = 1;
            m.method = 99;
            m.decoded = Some(b"data");
            m.central_extra = &extra;
            m
        })
        .collect::<Vec<_>>();
    let (file, _session, mut options, old) = setup(&members);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = dest.path().to_path_buf();
    let result = crate::zip::run_with_policy(
        file.path(),
        &options,
        Some("pw"),
        &Cancellation::default(),
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    );
    println!("actual AES16 result {result:?}");
    let report = result.unwrap();
    assert_eq!(report.files(), 16);
    assert_eq!(report.usage().allocation_attempts, 3);
    assert_eq!(report.usage().live_fds, 0);
    for name in names {
        assert_eq!(std::fs::read(dest.path().join(name)).unwrap(), b"data");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn record_refusal_precedes_stage_effect_and_activation_cannot_replay() {
    let (_file, mut session, mut options, old) = setup(&[Member::stored(b"a", b"a")]);
    drop(old);
    let root = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = root.path().join("not-created");
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
    context.ledger.with_state(|s| s.test_limit_category(RunCategory::Records, 0));
    let error = session
        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |_: ZipRunEvent<'_>| Ok(()))
        .unwrap_err();
    assert!(matches!(
        error.operation(),
        Some(ReadFault::Limit { resource: ReadResource::Run(RunCategory::Records), .. })
    ));
    assert!(!options.dest.exists());
    assert_eq!(context.run_usage().records, 0);
    assert_eq!(context.run_usage().temporary_groups, 0);
    let usage = context.run_usage();
    assert!(matches!(
        session
            .read_at_with_context(0, Some("pw"), u64::MAX, &Cancellation::default(), &mut context, |_| panic!(
                "no replay"
            ))
            .unwrap_err()
            .operation(),
        Some(ReadFault::InvalidPlan)
    ));
    assert!(
        session
            .run_with_context(
                &options,
                Some("pw"),
                &Cancellation::default(),
                &mut context,
                |_: ZipRunEvent<'_>| panic!("no replay callback")
            )
            .is_err()
    );
    assert_eq!(context.run_usage(), usage);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn mixed_clear_aes_directory_and_large_aes_spool_inventory() {
    let big = vec![0x5a; 65_537];
    let small = super::cipher::framed(1, "pw", b"data");
    let large = super::cipher::framed(1, "pw", &big);
    let extra = super::fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut a = Member::stored(b"small", &small);
    a.flags = 1;
    a.method = 99;
    a.decoded = Some(b"data");
    a.central_extra = &extra;
    let mut b = Member::stored(b"folder/big", &large);
    b.flags = 1;
    b.method = 99;
    b.decoded = Some(&big);
    b.central_extra = &extra;
    let mut dir = Member::stored(b"folder/", b"");
    dir.external = 0o040755 << 16;
    let (_file, mut session, mut options, old) = setup(&[Member::stored(b"clear", b"abc"), a, dir, b]);
    drop(old);
    let dest = tempfile::tempdir().unwrap();
    let temp = tempfile::tempdir().unwrap();
    options.mode = Mode::Extract;
    options.dest = dest.path().to_path_buf();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::StagedFiles { destination: &options.dest },
        Some("pw"),
        &EncryptedReadOverrides { temp_dir: Some(temp.path().to_path_buf()), ..Default::default() },
        &Cancellation::default(),
    )
    .unwrap();
    let report = session
        .run_with_context(&options, Some("pw"), &Cancellation::default(), &mut context, |_: ZipRunEvent<'_>| Ok(()))
        .unwrap();
    println!("actual mixed clear/AES/dir/largeAES inventory {:?} encrypted {:?}", report.run_usage(), report.usage());
    assert_eq!((report.files(), report.dirs(), report.run_usage().records), (3, 1, 4));
    assert_eq!(report.run_usage().source_check_groups, 31);
    assert_eq!(report.usage().members, 2);
    assert_eq!(std::fs::read(dest.path().join("folder/big")).unwrap(), big);
    assert_eq!(std::fs::read(dest.path().join("clear")).unwrap(), b"abc");
    assert_eq!(report.run_usage().live_spool_bytes, 0);
    assert_eq!(report.usage().live_spool_bytes, 0);
    context.ledger.with_state(|s| {
        assert_eq!(s.live_fds, 1);
        assert!(s.peak_fds <= 5);
        assert!(!s.poisoned);
    });
}

#[test]
fn staged_source_group_correction_is_exact_once_and_checked() {
    for output_passes in [0, 1, 3] {
        let g = budget::PlanGeometry { records: 16, regular: 16, output_passes, ..Default::default() };
        let mut state = budget::LedgerState::new(&Default::default()).unwrap();
        super::core::bind_plan(&mut state, budget::ActionPlan::derive(g, 16, 16).unwrap());
        let limit = 136 + if output_passes == 1 { 16 } else { 0 };
        assert_eq!(state.run_bounds().source_check_groups, limit);
        state.charge_category(RunCategory::SourceCheckGroups, limit).unwrap();
        assert!(state.charge_category(RunCategory::SourceCheckGroups, 1).is_err());
        assert_eq!(state.run.usage.source_check_groups, limit);
    }
    let g = budget::PlanGeometry {
        records: u128::MAX / 8 - 1,
        regular: u128::MAX / 8 - 1,
        output_passes: 1,
        ..Default::default()
    };
    assert!(matches!(budget::ActionPlan::derive(g, 16, 16), Err(ReadFault::CounterOverflow)));
}
