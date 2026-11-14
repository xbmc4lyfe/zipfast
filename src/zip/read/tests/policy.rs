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
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
fn native(
    path: &Path,
    cwd: &Path,
    limit: u128,
) -> (Result<(PathBuf, policy::CanonicalIdentity), policy::CanonicalFailure>, u128) {
    let mut scratch = vec![0u8; 65536];
    let mut calls = 0;
    let result = policy::canonicalize(path, cwd, &mut scratch, 16, &Cancellation::default(), &mut |_, first| {
        if first {
            let next = calls + 1;
            if next > limit {
                return Err(ReadFault::Limit { resource: ReadResource::IoAttempts, limit, attempted: next });
            }
            calls = next;
        }
        Ok(())
    })
    .map(|e| (PathBuf::from(std::ffi::OsStr::from_bytes(e.bytes(&scratch))), e.identity));
    (result, calls)
}
#[cfg(target_os = "macos")]
#[test]
fn canonical_requested_names_match_native_reference() {
    let root = tempfile::tempdir().unwrap();
    let cwd = std::fs::canonicalize(root.path()).unwrap();
    std::fs::write(cwd.join("MixedCase"), b"bytes").unwrap();
    std::fs::hard_link(cwd.join("MixedCase"), cwd.join("second")).unwrap();
    std::fs::write(cwd.join("caf\u{e9}"), b"unicode").unwrap();
    for path in [
        PathBuf::from("MixedCase"),
        PathBuf::from("mixedcase"),
        PathBuf::from("second"),
        PathBuf::from("caf\u{e9}"),
        PathBuf::from("cafe\u{301}"),
        PathBuf::from("."),
        PathBuf::from(".."),
        PathBuf::from("/"),
        PathBuf::from("/dev"),
        PathBuf::from("/System/Volumes/Data"),
    ] {
        let expected = std::fs::canonicalize(cwd.join(&path));
        let (actual, calls) = native(&path, &cwd, u128::MAX);
        match expected {
            Ok(expected) => assert_eq!(actual.unwrap().0, expected, "{path:?}, {calls} calls"),
            Err(expected) => assert!(
                matches!(actual, Err(policy::CanonicalFailure::Ordinary(ReadFault::Io { error, .. }))
                if error.raw_os_error() == expected.raw_os_error()),
                "{path:?}"
            ),
        }
    }
    let first = native(Path::new("MixedCase"), &cwd, u128::MAX).0.unwrap();
    let second = native(Path::new("second"), &cwd, u128::MAX).0.unwrap();
    assert_eq!(first.1, second.1);
    assert_ne!(first.0, second.0, "hardlink identity never substitutes for requested canonical name");
}
#[cfg(target_os = "macos")]
#[test]
fn canonical_thirty_three_success_and_thirty_four_failure() {
    for n in [31, 32, 33, 34] {
        let root = tempfile::tempdir().unwrap();
        let cwd = std::fs::canonicalize(root.path()).unwrap();
        std::fs::write(cwd.join("target"), b"bytes").unwrap();
        for i in 0..n {
            symlink(
                if i + 1 == n { "target".to_owned() } else { format!("link{}", i + 1) },
                cwd.join(format!("link{i}")),
            )
            .unwrap();
        }
        let requested = cwd.join("link0");
        let expected = std::fs::canonicalize(&requested);
        let (actual, _) = native(&requested, &cwd, u128::MAX);
        if n == 34 {
            assert_eq!(expected.unwrap_err().raw_os_error(), Some(libc::ELOOP));
            assert!(
                matches!(actual, Err(policy::CanonicalFailure::Ordinary(ReadFault::Io { error, .. })) if error.raw_os_error() == Some(libc::ELOOP))
            );
        } else {
            assert_eq!(actual.unwrap().0, expected.unwrap(), "{n} link expansions");
            if n == 33 {
                assert_eq!(std::fs::metadata(requested).unwrap_err().raw_os_error(), Some(libc::ELOOP));
            }
        }
    }
}
#[cfg(target_os = "macos")]
#[test]
fn canonical_counter_is_exact_and_refuses_before_one_under() {
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    let (_, exact) = native(&cwd, &cwd, u128::MAX);
    let (error, actual) = native(&cwd, &cwd, exact - 1);
    assert_eq!(actual, exact - 1);
    assert!(matches!(error, Err(policy::CanonicalFailure::Terminal(ReadFault::Limit { .. }))));
    assert!(native(&cwd, &cwd, exact).0.is_ok());
}

#[cfg(target_os = "macos")]
#[test]
fn second_pass_replacement_or_failure_is_terminal_including_optional_keys() {
    for failure in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let cwd = std::fs::canonicalize(root.path()).unwrap();
        let target = cwd.join("target");
        std::fs::write(&target, b"old").unwrap();
        let changed = target.clone();
        let retained = cwd.join("retained-old");
        policy::between_passes(Some(Box::new(move || {
            std::fs::rename(&changed, &retained).unwrap();
            if !failure {
                std::fs::write(&changed, b"new").unwrap();
            }
        })));
        let result = native(&target, &cwd, u128::MAX).0;
        policy::between_passes(None);
        if failure {
            assert!(
                matches!(result,Err(policy::CanonicalFailure::Terminal(ReadFault::Io {error,..})) if error.raw_os_error()==Some(libc::ENOENT))
            );
        } else {
            assert!(matches!(result, Err(policy::CanonicalFailure::Terminal(ReadFault::CheckedFormat { .. }))));
        }
    }
}
#[cfg(target_os = "macos")]
#[test]
fn canonical_is_allocation_free_and_uses_one_phase_window() {
    let root = tempfile::tempdir().unwrap();
    let cwd = std::fs::canonicalize(root.path()).unwrap();
    std::fs::write(cwd.join("target"), b"bytes").unwrap();
    symlink("target", cwd.join("alias")).unwrap();
    let path = cwd.join("alias");
    let mut scratch = vec![0u8; 65536];
    let cancel = Cancellation::default();
    let mut count = 0usize;
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|state| state.set(true));
    let result = policy::canonicalize(&path, &cwd, &mut scratch, 16, &cancel, &mut |_, first| {
        count += usize::from(first);
        Ok(())
    });
    let mounted = policy::canonicalize(Path::new("/dev"), &cwd, &mut scratch, 16, &cancel, &mut |_, first| {
        count += usize::from(first);
        Ok(())
    });
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|state| state.set(false));
    assert!(result.is_ok());
    assert!(mounted.is_ok());
    let [capacity, used, saved, bound] = policy::canonical_layout();
    assert!(used <= capacity);
    assert_eq!(capacity, 65536);
    assert_eq!(saved, 1024);
    assert!(count <= bound);
    eprintln!(
        "canonical scratch capacity={capacity}, used={used}, saved={saved}, logical={count}, two-pass-bound={bound}"
    );
}
#[cfg(target_os = "macos")]
#[test]
fn canonical_ordinary_errors_fifo_and_path_components_match_native() {
    let root = tempfile::tempdir().unwrap();
    let cwd = std::fs::canonicalize(root.path()).unwrap();
    std::fs::write(cwd.join("file"), b"bytes").unwrap();
    std::fs::create_dir(cwd.join("directory")).unwrap();
    symlink("directory", cwd.join("alias")).unwrap();
    let fifo = cwd.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let paths = [
        "file/.",
        "file/..",
        "file/",
        "file//",
        "file/./child",
        "file/./..",
        "missing",
        "missing/..",
        "alias/../file",
        "fifo",
        "directory/..",
        "./directory/.",
    ];
    for path in paths {
        let expected = std::fs::canonicalize(cwd.join(path));
        let actual = native(Path::new(path), &cwd, u128::MAX).0;
        match expected {
            Ok(expected) => assert_eq!(
                actual.unwrap_or_else(|error| panic!("{path}: {error:?}, expected {expected:?}")).0,
                expected,
                "{path}"
            ),
            Err(expected) => assert!(
                matches!(actual,Err(policy::CanonicalFailure::Ordinary(ReadFault::Io {error,..}))
                if error.raw_os_error()==expected.raw_os_error()),
                "{path}: {expected}"
            ),
        }
    }
}

#[test]
fn controlled_policy_envelope_is_once_bound_exact_and_does_not_reset_usage() {
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    let geometry = budget::PlanGeometry {
        records: 3,
        regular: 2,
        directories: 1,
        packed: 10,
        decoded: 7,
        large_aes: 1,
        ciphertext: 5,
        path_bytes: 11,
        live_spool: 20,
        output_passes: 1,
        output_encrypted: true,
    };
    super::core::bind_plan(&mut state, budget::ActionPlan::derive(geometry, 16, 16).unwrap());
    state.charge_category(RunCategory::PathSteps, 1).unwrap();
    state.attempt(false).unwrap();
    let before = state.run.usage;
    state
        .bind_policy_geometry(budget::PolicyGeometry {
            protected: 2,
            raw_bytes: 17,
            absolute_bytes: 41,
            cwd_bytes: 10,
            relative: true,
        })
        .unwrap();
    assert_eq!(state.run.usage, before);
    let bounds = state.run_bounds();
    #[cfg(target_os = "macos")]
    {
        assert_eq!(bounds.canonical_metadata_operations, 501561774);
        assert_eq!(bounds.policy_probe_operations, 94);
        assert_eq!(bounds.output_directory_operations, 82);
        assert_eq!(bounds.path_steps, 1954732);
        assert_eq!(bounds.io_attempts, 8692721928);
    }
    assert_eq!(bounds.stage_finalization, 71);
    assert_eq!(bounds.temporary_groups, 7);
    assert_eq!(bounds.storage_backend_operations, 3);
    assert!(state.bind_policy_geometry(Default::default()).is_err());
}
#[test]
fn native_policy_categories_are_exact_and_one_under_and_overflow_is_before_binding() {
    for category in [
        RunCategory::CanonicalMetadataOperations,
        RunCategory::PolicyProbeOperations,
        RunCategory::OutputDirectoryOperations,
    ] {
        let mut state = budget::LedgerState::new(&Default::default()).unwrap();
        super::core::bind_plan(
            &mut state,
            budget::ActionPlan::derive(
                budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
                16,
                16,
            )
            .unwrap(),
        );
        state
            .bind_policy_geometry(budget::PolicyGeometry {
                protected: 1,
                raw_bytes: 8,
                absolute_bytes: 9,
                ..Default::default()
            })
            .unwrap();
        let bound = match category {
            RunCategory::CanonicalMetadataOperations => state.run_bounds().canonical_metadata_operations,
            RunCategory::PolicyProbeOperations => state.run_bounds().policy_probe_operations,
            _ => state.run_bounds().output_directory_operations,
        };
        state.charge_category(category, bound - 1).unwrap();
        state.charge_category(category, 1).unwrap();
        assert!(state.charge_category(category, 1).is_err());
    }
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    super::core::bind_plan(
        &mut state,
        budget::ActionPlan::derive(
            budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
            16,
            16,
        )
        .unwrap(),
    );
    let old = state.run_bounds();
    assert!(
        state
            .bind_policy_geometry(budget::PolicyGeometry {
                protected: u128::MAX,
                absolute_bytes: u128::MAX,
                ..Default::default()
            })
            .is_err()
    );
    assert_eq!(state.run_bounds(), old);
}

#[test]
fn policy_metadata_is_fallible_separate_and_explicitly_retired() {
    use super::super::shared::LedgerAccess;
    let context = EncryptedReadContext::new(Default::default()).unwrap();
    let baseline = context.usage();
    {
        let bytes = policy::MetadataLease::<u8>::zeroed(context.ledger.view(), policy::PolicyComponent::Caller, 300000)
            .unwrap();
        assert_eq!(bytes.len(), 300000);
        let usage = context.policy_metadata_usage();
        assert_eq!(usage.caller.live_requested_bytes, 300000);
        assert_eq!(usage.caller.live_allocations, 1);
        assert!(usage.caller.live_capacity >= 300000);
        assert_eq!(context.usage(), baseline);
    }
    let usage = context.policy_metadata_usage();
    assert_eq!(usage.caller.live_capacity, 0);
    assert_eq!(usage.caller.releases, 1);
    let scratch =
        policy::MetadataLease::<u8>::zeroed(context.ledger.view(), policy::PolicyComponent::Scratch, 65536).unwrap();
    assert!(
        policy::MetadataLease::<u8>::zeroed(context.ledger.view(), policy::PolicyComponent::Scratch, 65536).is_err()
    );
    drop(scratch);
    assert_eq!(context.policy_metadata_usage().scratch.live_capacity, 0);
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|state| state.set(true));
    let refused = policy::MetadataLease::<u8>::zeroed(context.ledger.view(), policy::PolicyComponent::Caller, 10);
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|state| state.set(false));
    assert!(matches!(refused, Err(ReadFault::Allocation { capacity: 10 })));
    let usage = context.policy_metadata_usage();
    assert_eq!(usage.caller.allocation_attempts, 2);
    assert_eq!(usage.caller.allocations, 1);
    assert_eq!(usage.caller.live_capacity, 0);
    assert_eq!(context.usage(), baseline);
}
#[test]
fn native_policy_buffers_and_context_first_transfer_keep_exact_owner() {
    use super::super::shared::LedgerAccess;
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let token = context.ledger.mint_reservation().unwrap();
    let bytes =
        policy::MetadataLease::<u8>::zeroed(token.view(), policy::PolicyComponent::NativeAcl, 44).unwrap().into_owned();
    drop(context);
    assert_eq!(token.with_state(|s| s.policy_metadata.native_acl.live_capacity), 44);
    bytes.finish(&token).unwrap();
    assert_eq!(token.with_state(|s| s.policy_metadata.native_acl.live_capacity), 0);
    assert_eq!(token.with_state(|s| s.policy_metadata.native_acl.releases), 1);
}

#[cfg(target_os = "macos")]
#[test]
fn admitted_phase_scratch_is_native_aligned_and_retires_before_payload_workspace() {
    use super::super::shared::LedgerAccess;
    let context = EncryptedReadContext::new(Default::default()).unwrap();
    let baseline = context.usage();
    let mut scratch = policy::PolicyScratch::new(context.ledger.view()).unwrap();
    assert_eq!(scratch.as_ptr().align_offset(std::mem::align_of::<libc::statfs>()), 0);
    let cwd = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    policy::canonicalize(Path::new("/dev"), &cwd, &mut scratch, 16, &Cancellation::default(), &mut |_, _| Ok(()))
        .unwrap();
    assert_eq!(context.policy_metadata_usage().scratch.live_requested_bytes, 65536);
    assert_eq!(context.usage(), baseline);
    drop(scratch);
    assert_eq!(context.policy_metadata_usage().scratch.live_capacity, 0);
    assert_eq!(context.policy_metadata_usage().scratch.releases, 1);
}

#[cfg(target_os = "macos")]
#[test]
fn frozen_policy_keeps_namespace_keys_after_inode_replacement_and_exact_configuration() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let cwd = std::fs::canonicalize(root.path()).unwrap();
    let source = cwd.join("source.zip");
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
    let mut file = std::fs::File::create(&source).unwrap();
    file.write_all(&bytes).unwrap();
    drop(file);
    let victim = cwd.join("victim");
    std::fs::write(&victim, b"old").unwrap();
    let alias = cwd.join("alias");
    symlink("victim", &alias).unwrap();
    let missing = cwd.join("missing//later");
    let mut options = crate::extract::Options {
        mode: crate::extract::Mode::Extract,
        dest: cwd.clone(),
        overwrite: crate::extract::Overwrite::Always,
        flatten: false,
        threads: None,
        protected_paths: [alias, missing].into_iter().collect(),
        parallel_min: None,
    };
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(&source, &cancel).unwrap();
    let context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination: &cwd },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let binding = session.owner.source.as_ref().unwrap();
    let snapshot = policy::FrozenPolicy::bind(
        &context.ledger,
        &options,
        &binding.path,
        &session.owner.file,
        binding.stamp,
        u128::MAX,
        &cancel,
    )
    .unwrap();
    assert!(snapshot.matches(&options, &cwd));
    std::fs::rename(&victim, cwd.join("retained")).unwrap();
    std::fs::write(&victim, b"new").unwrap();
    let (canonical, identity) = native(&victim, &cwd, u128::MAX).0.unwrap();
    assert!(snapshot.protects(&canonical, identity));
    std::fs::create_dir(cwd.join("missing")).unwrap();
    std::fs::write(cwd.join("missing/later"), b"later").unwrap();
    let (canonical, identity) = native(&cwd.join("missing/later"), &cwd, u128::MAX).0.unwrap();
    assert!(snapshot.protects(&canonical, identity));
    options.flatten = true;
    assert!(!snapshot.matches(&options, &cwd));
    snapshot.finish(&context.ledger).unwrap();
    assert_eq!(context.policy_metadata_usage().caller.live_capacity, 0);
    assert_eq!(context.policy_metadata_usage().scratch.live_capacity, 0);
}

#[cfg(target_os = "macos")]
use super::fixture;

#[cfg(target_os = "macos")]
#[test]
fn frozen_relative_destination_cwd_and_context_first_teardown_are_exact() {
    use std::io::Write;
    let source = tempfile::NamedTempFile::new().unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(source.path())
        .unwrap()
        .write_all(&fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes)
        .unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let destination = Path::new(".");
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let options = crate::extract::Options {
        mode: crate::extract::Mode::Extract,
        dest: destination.to_owned(),
        overwrite: crate::extract::Overwrite::Always,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let binding = session.owner.source.as_ref().unwrap();
    let before = context.ledger.with_state(|s| s.live_fds);
    let snapshot = policy::FrozenPolicy::bind(
        &context.ledger,
        &options,
        &binding.path,
        &session.owner.file,
        binding.stamp,
        u128::MAX,
        &cancel,
    )
    .unwrap();
    assert_eq!(
        std::fs::canonicalize(snapshot.cwd()).unwrap(),
        std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap()
    );
    assert_eq!(snapshot.uid, unsafe { libc::geteuid() });
    assert_eq!(context.ledger.with_state(|s| s.live_fds), before);
    context.action.as_mut().unwrap().policy = Some(snapshot);
    let token = context.ledger.mint_reservation().unwrap();
    drop(context);
    assert_eq!(token.with_state(|s| s.policy_metadata.caller.live_capacity), 0);
    assert_eq!(token.with_state(|s| s.policy_metadata.scratch.live_capacity), 0);
}

#[test]
fn semantic_close_category_exact_and_one_under_preserves_admission_and_one_syscall() {
    use std::os::fd::IntoRawFd;
    for category in [
        RunCategory::PolicyProbeOperations,
        RunCategory::OutputDirectoryOperations,
        RunCategory::CanonicalMetadataOperations,
    ] {
        for remaining in [0, 1] {
            let mut state = budget::LedgerState::new(&Default::default()).unwrap();
            super::core::bind_plan(
                &mut state,
                budget::ActionPlan::derive(
                    budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
                    16,
                    16,
                )
                .unwrap(),
            );
            state.bind_policy_geometry(Default::default()).unwrap();
            let bounds = state.run_bounds();
            let bound = match category {
                RunCategory::PolicyProbeOperations => bounds.policy_probe_operations,
                RunCategory::OutputDirectoryOperations => bounds.output_directory_operations,
                _ => bounds.canonical_metadata_operations,
            };
            state.charge_category(category, bound - remaining).unwrap();
            state.acquire_fds(1).unwrap();
            let ledger = shared::ContextLedger::try_new(state).unwrap();
            let file = tempfile::tempfile().unwrap();
            let fd = file.into_raw_fd();
            let mut calls = 0;
            let closed = io::retire_in(&ledger, false, OwnedObject::ProbeFile, Some(category), true, || {
                calls += 1;
                native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ())
            });
            assert!(closed.closed);
            assert!(closed.fault.is_none());
            assert_eq!(calls, 1);
            assert_eq!(closed.admission.is_some(), remaining == 0);
            ledger.with_state(|s| {
                assert_eq!(s.live_fds, 0);
                assert_eq!(s.run.usage.stage_finalization, 0);
                assert_eq!(s.run.usage.emergency_cleanup, u128::from(remaining == 0));
                assert_eq!(s.poisoned, remaining == 0);
            });
        }
    }
}

#[test]
fn actual_parent_policy_tolerates_own_names_and_rejects_security_mutation() {
    use shared::LedgerAccess;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let directory = std::fs::File::open(root.path()).unwrap();
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    super::core::bind_plan(
        &mut state,
        budget::ActionPlan::derive(
            budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
            16,
            16,
        )
        .unwrap(),
    );
    let ledger = shared::ContextLedger::try_new(state).unwrap();
    let cancel = Cancellation::default();
    ledger.with_state(|s| s.bind_policy_geometry(Default::default())).unwrap();
    let mut scratch = policy::PolicyScratch::new(ledger.view()).unwrap();
    let snapshot = policy::ParentPolicy::capture(
        &ledger,
        directory.as_raw_fd(),
        RunCategory::PolicyProbeOperations,
        &mut scratch,
        &cancel,
    )
    .unwrap();
    let before = ledger.with_state(|s| s.run.usage.policy_probe_operations);
    std::fs::write(root.path().join("own-name"), b"").unwrap();
    snapshot
        .matches(&ledger, directory.as_raw_fd(), RunCategory::PolicyProbeOperations, &mut scratch, &cancel)
        .unwrap();
    let calls = ledger.with_state(|s| s.run.usage.policy_probe_operations) - before;
    assert_eq!(calls, if cfg!(target_os = "linux") { 4 } else { 3 });
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // tempdir starts0700; choose a distinct stable security policy.
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        snapshot
            .matches(&ledger, directory.as_raw_fd(), RunCategory::PolicyProbeOperations, &mut scratch, &cancel)
            .is_err()
    );
    snapshot.finish(&ledger).unwrap();
    drop(scratch);
    assert_eq!(ledger.with_state(|s| s.policy_metadata.native_acl.live_capacity), 0);
}

#[test]
fn empty_actual_parent_probe_captures_creation_policy_and_retires_its_namespace() {
    use shared::LedgerAccess;
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    super::core::bind_plan(
        &mut state,
        budget::ActionPlan::derive(
            budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
            16,
            16,
        )
        .unwrap(),
    );
    state.bind_policy_geometry(Default::default()).unwrap();
    state.acquire_fds(2).unwrap();
    let ledger = shared::ContextLedger::try_new(state).unwrap();
    let cancel = Cancellation::default();
    let mut scratch = policy::PolicyScratch::new(ledger.view()).unwrap();
    let (snapshot, child) =
        policy::probe(&ledger, &parent, unsafe { libc::geteuid() }, false, &mut scratch, &cancel).unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert_eq!(ledger.with_state(|s| s.live_fds), 2);
    assert_eq!(
        ledger.with_state(|s| s.run.usage.policy_probe_operations),
        if cfg!(target_os = "linux") { 19 } else { 17 }
    );
    let ordinary = std::fs::OpenOptions::new().write(true).create_new(true).open(root.path().join("ordinary")).unwrap();
    let expected = native_policy::stat(ordinary.as_raw_fd()).unwrap();
    assert_eq!(child.mode, expected.st_mode as u32 & 0o777);
    assert_eq!(child.gid, expected.st_gid);
    snapshot.finish(&ledger).unwrap();
    child.finish(&ledger).unwrap();
    drop(scratch);
    assert_eq!(ledger.with_state(|s| s.policy_metadata.native_acl.live_capacity), 0);
}

#[test]
fn empty_probe_every_native_boundary_fails_closed_without_repeating_close() {
    use shared::LedgerAccess;
    use std::cell::Cell;
    use std::rc::Rc;
    for fault_at in 1..=if cfg!(target_os = "linux") { 19 } else { 17 } {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        let mut state = budget::LedgerState::new(&Default::default()).unwrap();
        super::core::bind_plan(
            &mut state,
            budget::ActionPlan::derive(
                budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
                16,
                16,
            )
            .unwrap(),
        );
        state.bind_policy_geometry(Default::default()).unwrap();
        state.acquire_fds(2).unwrap();
        let ledger = shared::ContextLedger::try_new(state).unwrap();
        let cancel = Cancellation::default();
        let mut scratch = policy::PolicyScratch::new(ledger.view()).unwrap();
        let count = Rc::new(Cell::new(0));
        let calls = count.clone();
        let closed = Rc::new(Cell::new(false));
        let actual_close = closed.clone();
        spool::hooks::HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |op, fd| {
                calls.set(calls.get() + 1);
                if calls.get() != fault_at {
                    return None;
                }
                if op == ReadIoOperation::Close {
                    assert_eq!(unsafe { libc::close(fd) }, 0);
                    actual_close.set(true);
                    Some(std::io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Some(std::io::Error::from_raw_os_error(libc::EIO))
                }
            }))
        });
        let result = policy::probe(&ledger, &parent, unsafe { libc::geteuid() }, false, &mut scratch, &cancel);
        spool::hooks::HOOK.with(|hook| *hook.borrow_mut() = None);
        assert!(result.is_err(), "native boundary {fault_at}");
        assert!(count.get() >= fault_at);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0, "boundary {fault_at}");
        assert_eq!(ledger.with_state(|s| s.live_fds), 2 + u64::from(closed.get()), "boundary {fault_at}");
        drop(scratch);
        assert_eq!(ledger.with_state(|s| s.policy_metadata.native_acl.live_capacity), 0);
    }
}

#[test]
fn procfd_spelling_is_fixed_bounded_decimal_without_allocation() {
    for (fd, expected) in [
        (0, b"/proc/self/fd/0".as_slice()),
        (9, b"/proc/self/fd/9".as_slice()),
        (10, b"/proc/self/fd/10".as_slice()),
        (2147483647, b"/proc/self/fd/2147483647".as_slice()),
    ] {
        let mut bytes = [0u8; 64];
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(true));
        let actual = native_policy::procfd_path(fd, &mut bytes);
        crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(false));
        assert_eq!(actual.unwrap().to_bytes(), expected);
    }
    assert!(native_policy::procfd_path(-1, &mut [0; 64]).is_err());
}

#[cfg(target_os = "linux")]
fn linux_canonical(
    path: &Path,
    cwd: &Path,
    remaining: u128,
    held: Option<&File>,
) -> (Result<(PathBuf, policy::CanonicalIdentity), policy::CanonicalFailure>, u128, u64, bool) {
    use shared::LedgerAccess;
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    super::core::bind_plan(
        &mut state,
        budget::ActionPlan::derive(
            budget::PlanGeometry { records: 1, regular: 1, output_passes: 1, ..Default::default() },
            16,
            16,
        )
        .unwrap(),
    );
    state.bind_policy_geometry(Default::default()).unwrap();
    state.acquire_fds(1).unwrap();
    let bound = state.run_bounds().canonical_metadata_operations;
    let start = bound - remaining;
    state.charge_category(RunCategory::CanonicalMetadataOperations, start).unwrap();
    let ledger = shared::ContextLedger::try_new(state).unwrap();
    let mut scratch = policy::PolicyScratch::new(ledger.view()).unwrap();
    let result = policy::canonicalize(
        &ledger,
        policy::CanonicalRequest { input: path, cwd, held },
        &mut scratch,
        16,
        &Cancellation::default(),
        &mut |_, first| {
            ledger.with_state(|s| {
                if first {
                    s.charge_category(RunCategory::CanonicalMetadataOperations, 1)?;
                }
                s.attempt(false)
            })
        },
    )
    .map(|e| (PathBuf::from(std::ffi::OsStr::from_bytes(e.bytes(&scratch))), e.identity));
    assert_eq!(ledger.with_state(|s| s.live_fds), 1);
    (
        result,
        ledger.with_state(|s| s.run.usage.canonical_metadata_operations) - start,
        ledger.with_state(|s| s.peak_fds),
        ledger.with_state(|s| s.poisoned),
    )
}
#[cfg(target_os = "linux")]
#[test]
fn linux_actual_procfd_canonical_exact_eight_and_original_source_shortcut_six() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a"), b"data").unwrap();
    std::fs::hard_link(root.path().join("a"), root.path().join("b")).unwrap();
    let mut identities = Vec::new();
    for name in ["a", "b"] {
        let input = root.path().join(name);
        let (actual, calls, peak, poison) = linux_canonical(&input, Path::new("/"), 8, None);
        let (path, id) = actual.unwrap();
        assert_eq!(path, std::fs::canonicalize(&input).unwrap());
        identities.push(id);
        assert_eq!(calls, 8);
        assert_eq!(peak, 2);
        assert!(!poison);
    }
    assert_eq!(identities[0], identities[1]);
    let input = root.path().join("a");
    let held = File::open(&input).unwrap();
    let (actual, calls, peak, poison) = linux_canonical(&input, Path::new("/"), 6, Some(&held));
    assert_eq!(actual.unwrap().0, std::fs::canonicalize(&input).unwrap());
    assert_eq!(calls, 6);
    assert_eq!(peak, 1);
    assert!(!poison);
    let (actual, calls, peak, poison) = linux_canonical(&input, Path::new("/"), 7, None);
    assert!(
        matches!(actual,Err(policy::CanonicalFailure::Cleanup(ref error)) if matches!(error.operation(),Some(ReadFault::Limit {resource:ReadResource::Run(RunCategory::CanonicalMetadataOperations),..})))
    );
    assert_eq!(calls, 7);
    assert_eq!(peak, 2);
    assert!(poison);
}
#[cfg(target_os = "linux")]
#[test]
fn linux_procfd_metadata_only_paths_match_native_fifo_relative_and_symlink_failures() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("d")).unwrap();
    std::fs::write(root.path().join("d/file"), b"data").unwrap();
    let fifo = root.path().join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    symlink("d/file", root.path().join("alias")).unwrap();
    for name in ["d/file", "./d/../d/file", "alias", "fifo", "missing", "d/file/child"] {
        let reference = std::fs::canonicalize(root.path().join(name));
        let (actual, _, _, _) = linux_canonical(Path::new(name), root.path(), 8, None);
        match reference {
            Ok(path) => assert_eq!(actual.unwrap().0, path),
            Err(error) => assert!(
                matches!(actual,Err(policy::CanonicalFailure::Ordinary(ReadFault::Io {error:ref actual,..})) if actual.raw_os_error()==error.raw_os_error())
            ),
        }
    }
}
