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
use crate::test_alloc::{DENY_LAYOUT, REFUSE_ALLOCATIONS};

#[test]
fn shared_ledger_allocation_is_recoverable() {
    DENY_LAYOUT.with(|v| v.set(Some(shared::header_layout())));
    let error = EncryptedReadContext::new(Default::default()).err().expect("refused header");
    assert!(matches!(error.operation(), Some(ReadFault::Allocation { .. })));
}

#[test]
fn unbound_reservation_refuses_before_io() {
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let file = tempfile::tempfile().unwrap();
    let error = context.reserve_output(&file, None, 1).err().unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(context.usage(), initial_usage());
}

#[test]
fn shared_ledger_drop_orders_and_single_token() {
    for context_first in [false, true] {
        let mut owner = shared::ContextLedger::try_new(budget::LedgerState::new(&Default::default()).unwrap()).unwrap();
        let token = owner.mint_reservation().unwrap();
        assert!(owner.mint_reservation().is_err());
        REFUSE_ALLOCATIONS.with(|v| v.set(true));
        if context_first {
            drop(owner);
            token.with_state(|s| assert_eq!(s.encrypted.usage.members, 0));
            drop(token);
        } else {
            drop(token);
            let token = owner.mint_reservation().unwrap();
            drop(token);
            drop(owner);
        }
        REFUSE_ALLOCATIONS.with(|v| v.set(false));
    }
}

#[test]
fn shared_ledger_reentrancy_and_poison() {
    let mut owner = shared::ContextLedger::try_new(budget::LedgerState::new(&Default::default()).unwrap()).unwrap();
    let token = owner.mint_reservation().unwrap();
    // A callback is outside with_state: no RefCell guard may escape into it.
    owner.with_state(|s| s.acquire_fds(1)).unwrap();
    let callback = || {
        owner.with_state(|s| assert_eq!(s.live_fds, 1));
        token.with_state(|s| s.retire_fd(false));
    };
    callback();
    assert!(owner.with_state(|s| s.acquire_fds(1)).is_err());
    assert_eq!(owner.with_state(|s| s.live_fds), 1);
}

#[test]
fn source_faults_need_no_new_wrapper_allocation() {
    let operation = ZipReadError::from(ReadFault::AuthenticationFailed);
    let source =
        CheckedSourceFault::Unavailable { stage: IoStage::SourcePath, error: std::io::Error::from_raw_os_error(2) };
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let combined = operation.merge_source(source);
    assert!(combined.is_source_changed());
    assert!(matches!(combined.operation(), Some(ReadFault::AuthenticationFailed)));
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
}

#[test]
fn both_ledgers_exact_one_under_and_failed_attempts() {
    let limits = EncryptedReadLimits { members: 1, packed_bytes: 3, ..Default::default() };
    let mut ledger = budget::LedgerState::new(&EncryptedReadOptions::default().with_limits(limits)).unwrap();
    ledger.encrypted.begin_member(3, 0, 0, 1, false).unwrap();
    assert!(ledger.encrypted.begin_member(3, 0, 0, 1, false).is_err());
    assert_eq!(ledger.encrypted.usage.members, 1);
    assert_eq!(ledger.encrypted.usage.packed_bytes, 3);
    assert!(budget::checked_sum(u128::MAX, 1).is_err());
}

#[test]
fn empty_and_clear_plans_do_not_spend_encrypted_quota() {
    let limits = EncryptedReadLimits { io_bytes: 0, decoded_bytes: 0, live_spool_bytes: 0, ..Default::default() };
    let mut state = budget::LedgerState::new(&EncryptedReadOptions::default().with_limits(limits)).unwrap();
    bind_plan(&mut state, budget::ActionPlan::derive(budget::PlanGeometry::default(), 16, 16).unwrap());
    state.charge_category(RunCategory::SourceCheckGroups, 1).unwrap();
    state.charge_io(false, 1).unwrap_err(); // Empty action has no payload allowance.
    assert_eq!(state.encrypted.usage, initial_usage());
    assert_eq!(state.run.usage.source_check_groups, 1);
}

#[test]
fn context_has_exactly_one_fallible_allocation_even_with_temp_path() {
    use crate::test_alloc::{ALLOC_REQUESTS, DEALLOC_REQUESTS, TRACK_ALLOC};
    let options = EncryptedReadOptions::default().with_temp_dir("already/owned/path".into());
    ALLOC_REQUESTS.with(|v| v.set(0));
    DEALLOC_REQUESTS.with(|v| v.set(0));
    TRACK_ALLOC.with(|v| v.set(true));
    let context = EncryptedReadContext::new(options).unwrap();
    let count = ALLOC_REQUESTS.with(|v| v.get());
    drop(context);
    TRACK_ALLOC.with(|v| v.set(false));
    assert_eq!(count, 1, "only the fallible fixed shared header may allocate");
    assert_eq!(DEALLOC_REQUESTS.with(|v| v.get()), 2, "header and moved preexisting path");
}

fn bound_context(encrypted: bool, bytes: u64, passes: u128) -> EncryptedReadContext {
    let context = EncryptedReadContext::new(Default::default()).unwrap();
    let plan = budget::ActionPlan::derive(
        budget::PlanGeometry {
            records: 1,
            regular: 1,
            decoded: bytes.into(),
            live_spool: bytes.into(),
            output_passes: passes,
            output_encrypted: encrypted,
            ..Default::default()
        },
        16,
        16,
    )
    .unwrap();
    context.ledger.with_state(|s| {
        bind_plan(s, plan);
        s.active_encrypted = Some(encrypted);
    });
    context
}

#[test]
fn output_registration_rejects_nonempty_files_before_reserving() {
    use std::io::Write;
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"old").unwrap();
    let mut context = bound_context(false, 1, 3);
    assert!(context.reserve_output(&file, None, 1).is_err());
    assert_eq!(context.run_usage().live_spool_bytes, 0);
}

#[test]
fn checked_source_remains_invalid_without_any_wrapper_allocation() {
    use std::io::Write;
    let mut fixture = tempfile::NamedTempFile::new().unwrap();
    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    fixture.write_all(&eocd).unwrap();
    let mut session = crate::zip::ReadSession::open(fixture.path()).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    std::fs::remove_file(fixture.path()).unwrap();
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let first = session.check_source_checked(&mut context).unwrap_err();
    let combined = first.merge_sink(ZipSinkFault::Cancelled).merge_diagnostic(ZipSinkFault::StageChanged);
    let second = session.check_source_checked(&mut context).unwrap_err();
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
    assert!(combined.is_source_changed());
    assert!(combined.sink_fault().is_some());
    assert!(combined.diagnostic_fault().is_some());
    assert!(matches!(second.source_change(), Some(CheckedSourceFault::PreviouslyInvalidated { .. })));
}

#[test]
fn raw_registration_drop_keeps_unresolved_usage_and_poison() {
    for context_first in [false, true] {
        let mut context = bound_context(false, 3, 3);
        let file = tempfile::tempfile().unwrap();
        let token = context.reserve_output(&file, None, 3).unwrap();
        if context_first {
            drop(context);
            drop(token);
        } else {
            drop(token);
            assert_eq!(context.run_usage().live_spool_bytes, 3);
            assert_eq!(context.usage().live_fds, 1);
            assert!(context.reserve_output(&file, None, 3).is_err());
        }
        assert!(file.metadata().unwrap().is_file());
    }
    let mut context = bound_context(false, 3, 3);
    let file = tempfile::tempfile().unwrap();
    let token = context.reserve_output(&file, None, 3).unwrap();
    // Only controlled owned stages will access this private confirmation seam.
    token.retire_confirmed();
    assert_eq!(context.run_usage().live_spool_bytes, 0);
    assert_eq!(context.usage().live_fds, 0);
    let token = context.reserve_output(&file, None, 3).unwrap();
    token.retire_confirmed();
}

#[test]
fn output_transfers_are_bounded_and_clear_quota_independent() {
    let length = 2 * io::WINDOW + 13;
    let bytes = vec![0x42; length];
    let cancel = crate::extract::Cancellation::default();
    let mut context = bound_context(false, length as u64, 3);
    context.ledger.with_state(|s| {
        s.encrypted.limits.io_bytes = 0;
        s.encrypted.limits.live_spool_bytes = 0;
    });
    let mut file = tempfile::tempfile().unwrap();
    let mut token = context.reserve_output(&file, None, length as u64).unwrap();
    token.write_all(&mut file, &bytes, &cancel).unwrap();
    struct Writer {
        bytes: usize,
        max: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.max = self.max.max(b.len());
            self.bytes += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut out = Writer { bytes: 0, max: 0 };
    assert_eq!(token.copy_to(&mut file, &mut out, &cancel).unwrap(), length as u64);
    assert_eq!(out.bytes, length);
    assert_eq!(out.max, io::WINDOW);
    assert_eq!(context.usage().io_bytes, 0);
    assert_eq!(context.run_usage().io_bytes, 3 * length as u128);
    token.retire_confirmed();
}

#[test]
fn interrupted_reset_short_success_failed_syscall_and_cancel_are_charged() {
    struct Short {
        calls: u64,
    }
    impl std::io::Write for Short {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls % 2 == 1 { Err(std::io::ErrorKind::Interrupted.into()) } else { Ok(1) }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let context = bound_context(true, 3, 3);
    context.ledger.with_state(|s| s.encrypted.limits.interrupted_retries = 1);
    let mut owner = context;
    let token = owner.ledger.mint_reservation().unwrap();
    let cancel = crate::extract::Cancellation::default();
    let mut writer = Short { calls: 0 };
    for _ in 0..3 {
        assert_eq!(io::write(&token, true, &mut writer, IoStage::Output, 0, b"xxx", &cancel).unwrap(), 1);
    }
    assert_eq!(writer.calls, 6);
    assert_eq!(owner.usage().io_attempts, 6);
    assert_eq!(owner.usage().io_bytes, 3);
    let mut group = io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel).unwrap();
    let result = group.create(&cancel, || Err::<(), _>(std::io::ErrorKind::AlreadyExists.into()));
    assert!(result.is_err());
    assert_eq!(owner.usage().io_attempts, 7);
    cancel.cancel();
    let result = io::write(&token, true, &mut writer, IoStage::Output, 0, b"x", &cancel);
    assert!(matches!(result, Err(ReadFault::Cancelled)));
    assert_eq!(writer.calls, 6);
}

#[test]
fn explicit_close_is_once_and_ambiguous_close_poison_survives_context_drop() {
    use std::cell::Cell;
    for ambiguous in [false, true] {
        let mut owner = bound_context(true, 1, 1);
        owner.ledger.with_state(|s| s.acquire_fds(1)).unwrap();
        let token = owner.ledger.mint_reservation().unwrap();
        let calls = Cell::new(0);
        let result = io::retire_once(&token, true, OwnedObject::Ciphertext, || {
            calls.set(calls.get() + 1);
            if ambiguous { Err(std::io::ErrorKind::Interrupted.into()) } else { Ok(()) }
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(result.is_err(), ambiguous);
        if ambiguous {
            assert_eq!(owner.usage().live_fds, 1);
            assert!(owner.ledger.with_state(|s| s.acquire_fds(1)).is_err());
            drop(owner);
            token.with_state(|s| {
                assert!(s.poisoned);
                assert_eq!(s.live_fds, 1);
            });
        } else {
            assert_eq!(owner.usage().live_fds, 0);
        }
    }
}

#[test]
fn cleanup_inventory_retains_forty_faults_and_every_slot_without_allocating() {
    let objects = [
        OwnedObject::Source,
        OwnedObject::Output,
        OwnedObject::OutputParent,
        OwnedObject::Ciphertext,
        OwnedObject::CiphertextDirectory,
    ];
    let mut error = ZipReadError::from(ReadFault::AuthenticationFailed);
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    for object in objects {
        let mut report = ObjectCleanupReport::new(object);
        for _ in 0..8 {
            report.push(CleanupFault {
                object,
                operation: ReadIoOperation::Close,
                offset: None,
                cause: CleanupCause::Io(std::io::Error::from_raw_os_error(5)),
                close: CloseDisposition::Unresolved,
            });
        }
        error = error.merge_cleanup(report);
    }
    error = error.with_partial(ZipRunReport::default());
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
    assert_eq!(error.cleanup_errors().len(), 40);
    assert!(error.partial_run().is_some());
    assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
    println!(
        "SharedHeader={} ZipReadError={} ZipSinkFault={} ZipRunReport={} Result<()>={} scratch={}",
        shared::SHARED_LEDGER_CAPACITY,
        std::mem::size_of::<ZipReadError>(),
        std::mem::size_of::<ZipSinkFault>(),
        std::mem::size_of::<ZipRunReport>(),
        std::mem::size_of::<ZipReadResult<()>>(),
        4 * io::WINDOW
    );
}

#[test]
#[should_panic(expected = "eight terminal operations")]
fn cleanup_cannot_spill_or_silently_truncate() {
    let mut report = ObjectCleanupReport::new(OwnedObject::Source);
    for _ in 0..9 {
        report.push(CleanupFault {
            object: OwnedObject::Source,
            operation: ReadIoOperation::Close,
            offset: None,
            cause: CleanupCause::Policy("test"),
            close: CloseDisposition::Unresolved,
        });
    }
}

#[test]
fn actual_member_decoded_limit_is_independent_of_cumulative_limit() {
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    state.encrypted.begin_member(3, 2, 0, 1, false).unwrap();
    state.encrypted.decode(2, 0).unwrap();
    assert!(state.encrypted.decode(1, 0).is_err());
    assert_eq!(state.encrypted.usage.decoded_bytes, 2);
}

#[test]
fn every_payload_limit_is_enforced_at_exact_zero_and_one_under() {
    fn fresh(limits: EncryptedReadLimits) -> budget::LedgerState {
        budget::LedgerState::new(&EncryptedReadOptions::default().with_limits(limits)).unwrap()
    }
    macro_rules! cases {
        ($field:ident, $amount:expr, $call:expr) => {
            for cap in [0, $amount - 1, $amount] {
                let mut limits = EncryptedReadLimits::default();
                limits.$field = cap;
                let mut state = fresh(limits);
                let result: Result<(), ReadFault> = ($call)(&mut state);
                assert_eq!(result.is_ok(), cap == $amount, "{} cap={cap}", stringify!($field));
            }
        };
    }
    cases!(member_packed_bytes, 3, |s: &mut budget::LedgerState| s.encrypted.begin_member(3, 0, 0, 1, false));
    cases!(member_decoded_bytes, 3, |s: &mut budget::LedgerState| s.encrypted.begin_member(0, 3, 0, 1, false));
    cases!(packed_bytes, 3, |s: &mut budget::LedgerState| s.encrypted.begin_member(3, 0, 0, 1, false));
    cases!(members, 1, |s: &mut budget::LedgerState| s.encrypted.begin_member(0, 0, 0, 1, false));
    cases!(password_bytes, 3, |s: &mut budget::LedgerState| s.encrypted.begin_member(0, 0, 0, 3, false));
    cases!(kdf_calls, 1, |s: &mut budget::LedgerState| s.encrypted.begin_member(0, 0, 0, 1, true));
    cases!(codec_steps, 1, |s: &mut budget::LedgerState| s.encrypted.decode(0, 0));
    cases!(work_bytes, 3, |s: &mut budget::LedgerState| s.encrypted.decode(0, 3));
    cases!(allocation_attempts, 1, |s: &mut budget::LedgerState| s.encrypted.allocation(0));
    cases!(live_fds, 5, |s: &mut budget::LedgerState| s.acquire_fds(5));
    for cap in [0, 2, 3] {
        let limits = EncryptedReadLimits { member_spool_bytes: cap, ciphertext_memory_bytes: 0, ..Default::default() };
        assert_eq!(fresh(limits).encrypted.begin_member(3, 0, 3, 0, true).is_ok(), cap == 3);
    }
    for cap in [0, 2, 3] {
        let limits = EncryptedReadLimits { decoded_bytes: cap, ..Default::default() };
        let mut state = fresh(limits);
        state.encrypted.begin_member(0, 3, 0, 1, false).unwrap();
        assert_eq!(state.encrypted.decode(3, 0).is_ok(), cap == 3);
    }
    // u64/u128 overflow is a typed fault rather than a sentinel or saturation.
    let limits = EncryptedReadLimits { members: u64::MAX, packed_bytes: u128::MAX, ..Default::default() };
    let mut state = fresh(limits);
    state.encrypted.usage.members = u64::MAX;
    assert!(matches!(state.encrypted.begin_member(0, 0, 0, 0, false), Err(ReadFault::CounterOverflow)));
    state.encrypted.usage.members = 0;
    state.encrypted.usage.packed_bytes = u128::MAX;
    assert!(matches!(state.encrypted.begin_member(1, 0, 0, 0, false), Err(ReadFault::CounterOverflow)));
}

#[test]
fn fixed_memory_threshold_and_capacity_relationships_are_checked_before_allocation() {
    for threshold in [0, 64 << 10, 1 << 20] {
        let mut limits = EncryptedReadLimits { ciphertext_memory_bytes: threshold, ..Default::default() };
        let exact = threshold + 3 * (64 << 10);
        limits.reader_capacity = exact;
        assert!(EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits.clone())).is_ok());
        limits.reader_capacity = exact - 1;
        assert!(EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).is_err());
    }
    let limits =
        EncryptedReadLimits { ciphertext_memory_bytes: (1 << 20) + 1, reader_capacity: u64::MAX, ..Default::default() };
    assert!(EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).is_err());
    assert!(EncryptedReadContext::new(EncryptedReadOptions::default().with_lzma_memory_bytes(0)).is_err());
    assert!(
        EncryptedReadContext::new(EncryptedReadOptions::default().with_lzma_memory_bytes((256 << 20) + 1)).is_err()
    );
    assert!(EncryptedReadContext::new(EncryptedReadOptions::default().with_zstd_window_log_max(28)).is_err());
}

#[test]
fn all_record_geometry_categories_have_exact_finite_allowances() {
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    // R=3, Rg=1, Rd=2, J=10+30+3*5+3*7=76, L=4*11+4*4=60, T=2.
    let geometry = budget::PlanGeometry {
        records: 3,
        regular: 1,
        directories: 2,
        packed: 10,
        decoded: 7,
        large_aes: 1,
        ciphertext: 5,
        path_bytes: 11,
        live_spool: 12,
        output_passes: 3,
        output_encrypted: true,
    };
    bind_plan(&mut state, budget::ActionPlan::derive(geometry, 16, 16).unwrap());
    let m = 3 * 32 + 5 * 60 + 12 * 16 * 2 + 8 + 32 + 36 + 16;
    for (category, exact) in [
        (RunCategory::Records, 3),
        (RunCategory::SourceCheckGroups, 32),
        (RunCategory::PathSteps, 60),
        (RunCategory::TemporaryGroups, 2),
        (RunCategory::PositiveTransfers, 76),
        (RunCategory::TerminalProbes, 8),
        (RunCategory::StageFinalization, 32),
        (RunCategory::DirectoryFinalization, 36),
        (RunCategory::FinalOperations, 16),
        (RunCategory::DecodeSteps, 4 * (10 + 7 + 64 + 1)),
        (RunCategory::EmergencyCleanup, 160),
        (RunCategory::IoAttempts, (76 + m + 1) * 17),
        (RunCategory::IoBytes, 76),
    ] {
        state.charge_category(category, exact - 1).unwrap();
        state.charge_category(category, 1).unwrap();
        assert!(state.charge_category(category, 1).is_err(), "{category:?}");
    }
    assert!(
        budget::ActionPlan::derive(budget::PlanGeometry { records: u128::MAX, ..Default::default() }, 16, 16).is_err()
    );
    assert!(
        budget::ActionPlan::derive(
            budget::PlanGeometry { output_passes: u128::MAX, decoded: 2, ..Default::default() },
            16,
            16
        )
        .is_err()
    );
}

pub(super) fn bind_plan(state: &mut budget::LedgerState, plan: budget::ActionPlan) -> crate::zip::session::SourceStamp {
    let fixture = tempfile::NamedTempFile::new_in("/tmp").unwrap();
    let mut bootstrap = io::BootstrapIo::new(0, 16).unwrap();
    let stamp = crate::zip::session::SourceStamp::capture_checked(fixture.as_file(), fixture.path(), |stage, call| {
        bootstrap.stat(stage, call)
    })
    .unwrap();
    let binding = budget::PlanBinding {
        source: stamp,
        scope: ProjectedReadScope::AllRegular,
        output: match plan.output_passes {
            1 => budget::PlannedOutput::StagedFiles,
            3 => budget::PlannedOutput::VerifiedStdout,
            _ => budget::PlannedOutput::Callback,
        },
        configuration_id: 1,
    };
    state.bind(plan.with_binding(binding).unwrap()).unwrap();
    stamp
}

#[test]
fn many_output_chunks_and_caller_seek_cannot_escape_reserved_file_length() {
    use std::io::{Seek, SeekFrom};
    let cancel = crate::extract::Cancellation::default();
    let mut context = bound_context(false, 32, 3);
    let mut file = tempfile::tempfile().unwrap();
    let mut token = context.reserve_output(&file, None, 32).unwrap();
    file.seek(SeekFrom::Start(100_000)).unwrap();
    for _ in 0..32 {
        token.write_all(&mut file, b"x", &cancel).unwrap();
    }
    assert_eq!(file.metadata().unwrap().len(), 32);
    let mut out = Vec::new();
    token.copy_to(&mut file, &mut out, &cancel).unwrap();
    assert_eq!(out, vec![b'x'; 32]);
    token.retire_confirmed();
}

#[cfg(unix)]
#[test]
fn output_append_mode_is_refused_before_reservation() {
    use std::os::fd::AsRawFd;
    let file = tempfile::tempfile().unwrap();
    assert_eq!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_APPEND) }, 0);
    let mut context = bound_context(false, 1, 3);
    assert!(context.reserve_output(&file, None, 1).is_err());
    assert_eq!(context.run_usage().live_spool_bytes, 0);
}

fn initial_usage() -> EncryptedReadUsage {
    EncryptedReadUsage { reader_capacity: shared::SHARED_LEDGER_CAPACITY as u64, ..Default::default() }
}

#[test]
fn shared_roles_allocate_and_deallocate_once_in_both_drop_orders() {
    use crate::test_alloc::{ALLOC_REQUESTS, DEALLOC_REQUESTS, TRACK_ALLOC};
    for context_first in [true, false] {
        ALLOC_REQUESTS.with(|v| v.set(0));
        DEALLOC_REQUESTS.with(|v| v.set(0));
        TRACK_ALLOC.with(|v| v.set(true));
        let mut owner = shared::ContextLedger::try_new(budget::LedgerState::new(&Default::default()).unwrap()).unwrap();
        let token = owner.mint_reservation().unwrap();
        if context_first {
            drop(owner);
            drop(token);
        } else {
            drop(token);
            drop(owner);
        }
        TRACK_ALLOC.with(|v| v.set(false));
        assert_eq!(ALLOC_REQUESTS.with(|v| v.get()), 1);
        assert_eq!(DEALLOC_REQUESTS.with(|v| v.get()), 1);
    }
}

#[test]
fn combined_ciphertext_output_live_reservations_and_fd_five_are_checked() {
    for cap in [0, 7, 8] {
        let context = bound_context(true, 8, 3);
        context.ledger.with_state(|s| s.encrypted.limits.live_spool_bytes = cap);
        context.ledger.with_state(|s| {
            let first = s.reserve(true, 3, 2);
            if cap == 0 {
                assert!(first.is_err());
                return;
            }
            first.unwrap();
            assert_eq!(s.reserve(true, 5, 3).is_ok(), cap == 8);
            if cap == 8 {
                assert_eq!(s.live_fds, 5);
                assert!(s.acquire_fds(1).is_err());
            }
        });
    }
    let context = bound_context(false, 8, 3);
    context.ledger.with_state(|s| {
        s.encrypted.limits.live_spool_bytes = 0;
        s.reserve(false, 8, 5).unwrap();
        assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
        assert_eq!(s.run.usage.live_spool_bytes, 8);
    });
}

#[test]
fn source_io_attempt_and_transferred_byte_limits_precede_syscalls() {
    struct Reader {
        calls: usize,
    }
    impl std::io::Read for Reader {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            bytes.fill(0);
            Ok(bytes.len())
        }
    }
    let cancel = crate::extract::Cancellation::default();
    for resource in [ReadResource::SourceBytes, ReadResource::IoBytes, ReadResource::IoAttempts] {
        for cap in [0, 2, 3] {
            let mut context = bound_context(true, 3, 3);
            context.ledger.with_state(|s| match resource {
                ReadResource::SourceBytes => s.encrypted.limits.source_bytes = cap,
                ReadResource::IoBytes => s.encrypted.limits.io_bytes = cap,
                ReadResource::IoAttempts => s.encrypted.limits.io_attempts = cap,
                _ => unreachable!(),
            });
            let token = context.ledger.mint_reservation().unwrap();
            let mut reader = Reader { calls: 0 };
            let mut byte = [0u8; 1];
            for i in 0..3 {
                assert_eq!(
                    io::read(&token, true, &mut reader, IoStage::Source, i, &mut byte, &cancel).is_ok(),
                    (i as u128) < cap
                );
            }
            assert_eq!(reader.calls as u128, cap);
        }
    }
}

#[test]
fn legacy_invalidation_is_borrowed_by_checked_source_without_allocation() {
    use std::io::Write;
    let mut fixture = tempfile::NamedTempFile::new().unwrap();
    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    fixture.write_all(&eocd).unwrap();
    let mut session = crate::zip::ReadSession::open(fixture.path()).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    std::fs::remove_file(fixture.path()).unwrap();
    assert!(session.check_source().is_err());
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let fault = session.check_source_checked(&mut context).unwrap_err();
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
    assert!(matches!(
        fault.source_change(),
        Some(CheckedSourceFault::PreviouslyInvalidated { code: SourceInvalidationCode::LegacyUnavailable, .. })
    ));
}

#[test]
fn callbacks_can_observe_usage_without_a_refcell_guard() {
    struct Observer<'a>(&'a EncryptedReadContext);
    impl std::io::Write for Observer<'_> {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            assert!(self.0.run_usage().io_attempts > 0);
            let _ = self.0.usage();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut context = bound_context(false, 3, 3);
    let mut file = tempfile::tempfile().unwrap();
    let mut token = context.reserve_output(&file, None, 3).unwrap();
    let cancel = crate::extract::Cancellation::default();
    token.write_all(&mut file, b"abc", &cancel).unwrap();
    assert_eq!(token.copy_to(&mut file, &mut Observer(&context), &cancel).unwrap(), 3);
    token.retire_confirmed();
}

#[test]
fn sink_diagnostic_source_and_publication_evidence_stay_independent() {
    let operation =
        ReadFault::Integrity { reason: IntegrityReason::Checksum, password_evidence: PasswordEvidence::HeaderMatched };
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let error = ZipReadError::from(operation)
        .merge_sink(ZipSinkFault::Cancelled)
        .merge_diagnostic(ZipSinkFault::StageChanged)
        .with_publication(PublicationState::Published, 17)
        .merge_source(CheckedSourceFault::StampMismatch);
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
    assert_eq!(error.kind(), ZipReadErrorKind::SourceChanged);
    assert_eq!(error.accepted_output_bytes(), 17);
    assert_eq!(error.publication_state(), PublicationState::Published);
    assert!(matches!(
        error.operation(),
        Some(ReadFault::Integrity { password_evidence: PasswordEvidence::HeaderMatched, .. })
    ));
    assert!(error.sink_fault().is_some());
    assert!(error.diagnostic_fault().is_some());
}

#[test]
fn transfer_exhaustion_names_the_actual_encrypted_resource() {
    let cancel = crate::extract::Cancellation::default();
    for resource in [ReadResource::SourceBytes, ReadResource::IoBytes] {
        let mut owner = bound_context(true, 1, 3);
        owner.ledger.with_state(|s| match resource {
            ReadResource::SourceBytes => s.encrypted.limits.source_bytes = 0,
            _ => s.encrypted.limits.io_bytes = 0,
        });
        let token = owner.ledger.mint_reservation().unwrap();
        let mut data = &b"x"[..];
        let mut byte = [0u8; 1];
        let fault = io::read(&token, true, &mut data, IoStage::Source, 0, &mut byte, &cancel).unwrap_err();
        assert!(matches!(fault, ReadFault::Limit { resource: actual, limit: 0, attempted: 1 } if actual == resource));
        assert_eq!(data, b"x");
    }
}

#[test]
fn legacy_source_primary_is_not_demoted_by_sink_or_diagnostic_merge() {
    let legacy = crate::zip::SessionError::SourceChanged {
        change: crate::zip::SourceChange::StampMismatch,
        context: Some(crate::Error::Truncated),
    };
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let error = ZipReadError::from(ReadFault::Session(legacy))
        .merge_sink(ZipSinkFault::Cancelled)
        .merge_diagnostic(ZipSinkFault::StageChanged);
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
    assert!(error.is_source_changed());
    assert_eq!(error.kind(), ZipReadErrorKind::SourceChanged);
    assert!(matches!(
        error.operation(),
        Some(ReadFault::Session(crate::zip::SessionError::SourceChanged {
            context: Some(crate::Error::Truncated),
            ..
        }))
    ));
}

#[test]
fn bootstrap_six_metadata_calls_and_payload_fetch_are_finite() {
    let mut bootstrap = io::BootstrapIo::new(3, 1).unwrap();
    let mut calls = 0;
    for _ in 0..6 {
        bootstrap
            .stat(IoStage::SourceHandle, || {
                calls += 1;
                Ok(())
            })
            .unwrap();
    }
    assert!(
        bootstrap
            .stat(IoStage::SourceHandle, || {
                calls += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(calls, 6);
    let mut bootstrap = io::BootstrapIo::new(3, 1).unwrap();
    let mut calls = 0;
    assert!(
        bootstrap
            .stat(IoStage::SourceHandle, || {
                calls += 1;
                Err::<(), _>(std::io::ErrorKind::Interrupted.into())
            })
            .is_err()
    );
    assert_eq!(calls, 2);
    let cancel = crate::extract::Cancellation::default();
    let mut bytes = [0u8; 64];
    let mut source = &b"1234567"[..];
    assert_eq!(bootstrap.read(&mut source, &mut bytes, &cancel).unwrap(), 3);
    assert!(bootstrap.read(&mut source, &mut bytes, &cancel).is_err());
    assert_eq!(source, b"4567");
}

#[test]
fn empty_and_directory_runs_keep_metadata_with_all_encrypted_quotas_zero() {
    for records in [0, 3] {
        let context = EncryptedReadContext::new(Default::default()).unwrap();
        context.ledger.with_state(|s| {
            s.encrypted.limits.members = 0;
            s.encrypted.limits.io_attempts = 0;
            s.encrypted.limits.packed_bytes = 0;
            s.encrypted.limits.decoded_bytes = 0;
            s.encrypted.limits.work_bytes = 0;
            s.encrypted.limits.source_bytes = 0;
            s.encrypted.limits.live_spool_bytes = 0;
            bind_plan(
                s,
                budget::ActionPlan::derive(
                    budget::PlanGeometry { records, directories: records, ..Default::default() },
                    16,
                    16,
                )
                .unwrap(),
            );
            s.charge_category(RunCategory::Records, records).unwrap();
            s.charge_category(RunCategory::DirectoryFinalization, 12 * (records + 1)).unwrap();
            s.charge_category(RunCategory::SourceCheckGroups, 8 * (records + 1)).unwrap();
            s.charge_category(RunCategory::FinalOperations, 16).unwrap();
        });
        assert_eq!(context.usage(), initial_usage());
        // Scope is deliberately no active member: no artificial stage for directories.
        context.ledger.with_state(|s| s.active_encrypted = None);
        assert_eq!(context.run_usage().records, records);
    }
}

#[test]
fn reader_allocations_include_header_capacity_and_never_reset_cumulative_work() {
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    let available = state.encrypted.limits.reader_capacity - shared::SHARED_LEDGER_CAPACITY as u64;
    state.encrypted.allocation(available).unwrap();
    assert!(state.encrypted.allocation(1).is_err());
    assert_eq!(state.encrypted.usage.allocation_attempts, 2);
    assert_eq!(state.encrypted.usage.reader_capacity, state.encrypted.limits.reader_capacity);
    state.encrypted.begin_member(3, 1, 0, 1, true).unwrap();
    state.encrypted.decode(1, 3).unwrap();
    state.encrypted.begin_member(3, 1, 0, 1, true).unwrap();
    state.encrypted.decode(1, 3).unwrap();
    assert_eq!(state.encrypted.usage.members, 2);
    assert_eq!(state.encrypted.usage.kdf_calls, 2);
    assert_eq!(state.encrypted.usage.packed_bytes, 6);
    assert_eq!(state.encrypted.usage.decoded_bytes, 2);
    assert_eq!(state.encrypted.usage.work_bytes, 6);
}

#[test]
fn checked_source_bootstrap_never_resets_and_budget_refusal_does_not_invalidate() {
    use std::io::Write;
    let mut fixture = tempfile::NamedTempFile::new().unwrap();
    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    fixture.write_all(&eocd).unwrap();
    let mut session = crate::zip::ReadSession::open(fixture.path()).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    session.check_source_checked(&mut context).unwrap();
    session.check_source_checked(&mut context).unwrap();
    let error = session.check_source_checked(&mut context).unwrap_err();
    assert!(!error.is_source_changed());
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::BootstrapMetadata, .. })));
    let mut fresh = EncryptedReadContext::new(Default::default()).unwrap();
    session.check_source_checked(&mut fresh).unwrap();
}

#[test]
fn checked_source_bound_action_charges_groups_and_actual_attempts_with_configured_retries() {
    use std::io::Write;
    let mut fixture = tempfile::NamedTempFile::new().unwrap();
    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    fixture.write_all(&eocd).unwrap();
    let mut session = crate::zip::ReadSession::open(fixture.path()).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let mut bootstrap = io::BootstrapIo::new(0, 16).unwrap();
    let source = crate::zip::session::SourceStamp::capture_checked(fixture.as_file(), fixture.path(), |stage, call| {
        bootstrap.stat(stage, call)
    })
    .unwrap();
    let plan = budget::ActionPlan::derive(Default::default(), 16, 16)
        .unwrap()
        .with_binding(budget::PlanBinding {
            source,
            scope: ProjectedReadScope::AllRegular,
            output: budget::PlannedOutput::Discard,
            configuration_id: 1,
        })
        .unwrap();
    context.ledger.with_state(|s| {
        s.bind(plan).unwrap();
        s.encrypted.limits.io_attempts = 0;
    });
    for _ in 0..8 {
        session.check_source_checked(&mut context).unwrap();
    }
    assert_eq!(context.run_usage().source_check_groups, 8);
    assert_eq!(context.run_usage().io_attempts, 24);
    assert_eq!(context.usage().io_attempts, 0);
    assert!(!session.check_source_checked(&mut context).unwrap_err().is_source_changed());
    context.options.limits.interrupted_retries = 1;
    let mut attempts = 0;
    context
        .source_stat(IoStage::SourceHandle, || {
            attempts += 1;
            if attempts == 1 { Err(std::io::ErrorKind::Interrupted.into()) } else { Ok(()) }
        })
        .unwrap();
    assert_eq!(attempts, 2);
    assert_eq!(context.run_usage().io_attempts, 26);
    context.options.limits.interrupted_retries = 0;
    attempts = 0;
    assert!(
        context
            .source_stat(IoStage::SourceHandle, || {
                attempts += 1;
                Err::<(), _>(std::io::ErrorKind::Interrupted.into())
            })
            .is_err()
    );
    assert_eq!(attempts, 1);
    assert_eq!(context.run_usage().io_attempts, 27);
}

#[test]
fn action_binding_refuses_output_mode_drift_and_pre_read_all_regular_reservations() {
    let fixture = tempfile::NamedTempFile::new().unwrap();
    let mut bootstrap = io::BootstrapIo::new(0, 16).unwrap();
    let source = crate::zip::session::SourceStamp::capture_checked(fixture.as_file(), fixture.path(), |stage, call| {
        bootstrap.stat(stage, call)
    })
    .unwrap();
    let binding = budget::PlanBinding {
        source,
        scope: ProjectedReadScope::AllRegular,
        output: budget::PlannedOutput::VerifiedStdout,
        configuration_id: 1,
    };
    assert!(budget::ActionPlan::derive(Default::default(), 16, 16).unwrap().with_binding(binding).is_err());
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    context.ledger.with_state(|s| bind_plan(s, budget::ActionPlan::derive(Default::default(), 16, 16).unwrap()));
    let file = tempfile::tempfile().unwrap();
    let before = context.run_usage();
    assert!(context.reserve_output(&file, None, 0).is_err());
    assert_eq!(context.run_usage(), before);
}

#[test]
fn emergency_close_is_separate_finite_and_never_retries_interrupted() {
    use std::cell::Cell;
    let mut context = bound_context(true, 1, 1);
    context.ledger.with_state(|s| {
        s.acquire_fds(1).unwrap();
        s.encrypted.limits.io_attempts = 0;
    });
    let token = context.ledger.mint_reservation().unwrap();
    let calls = Cell::new(0);
    io::retire_once(&token, true, OwnedObject::Ciphertext, || {
        calls.set(calls.get() + 1);
        Ok(())
    })
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(context.run_usage().emergency_cleanup, 1);
    assert_eq!(context.run_usage().stage_finalization, 0);
    context.ledger.with_state(|s| {
        s.acquire_fds(1).unwrap();
        s.charge_category(RunCategory::EmergencyCleanup, 79).unwrap();
    });
    assert!(
        io::retire_once(&token, true, OwnedObject::Ciphertext, || {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(context.usage().live_fds, 1);
}

#[test]
fn policy_rejected_attempts_spend_members_and_packed_before_size_checks() {
    for policy in [ReadResource::MemberPackedBytes, ReadResource::MemberDecodedBytes, ReadResource::MemberSpoolBytes] {
        for exhausted in [ReadResource::Members, ReadResource::PackedBytes] {
            let mut limits =
                EncryptedReadLimits { members: 2, packed_bytes: 6, ciphertext_memory_bytes: 0, ..Default::default() };
            if exhausted == ReadResource::PackedBytes {
                limits.members = 10;
            }
            match policy {
                ReadResource::MemberPackedBytes => limits.member_packed_bytes = 2,
                ReadResource::MemberDecodedBytes => limits.member_decoded_bytes = 2,
                ReadResource::MemberSpoolBytes => limits.member_spool_bytes = 2,
                _ => unreachable!(),
            }
            let mut state = budget::LedgerState::new(&EncryptedReadOptions::default().with_limits(limits)).unwrap();
            for attempt in 1..=3 {
                let (decoded, ciphertext) = match policy {
                    ReadResource::MemberDecodedBytes => (3, 0),
                    ReadResource::MemberSpoolBytes => (0, 3),
                    _ => (0, 0),
                };
                let fault = state.encrypted.begin_member(3, decoded, ciphertext, 1, true).unwrap_err();
                let expected = if attempt < 3 { policy } else { exhausted };
                assert!(
                    matches!(fault, ReadFault::Limit { resource, .. } if resource == expected),
                    "policy={policy:?} attempt={attempt} fault={fault:?}"
                );
                let expected_members = if exhausted == ReadResource::Members { attempt.min(2) } else { attempt };
                assert_eq!(state.encrypted.usage.members, expected_members);
                assert_eq!(state.encrypted.usage.packed_bytes, u128::from(attempt.min(2) * 3));
                assert_eq!(state.encrypted.usage.kdf_calls, 0);
                assert_eq!(state.encrypted.usage.decoded_bytes, 0);
                assert_eq!(state.encrypted.usage.source_bytes, 0);
                assert_eq!(state.encrypted.usage.io_bytes, 0);
                assert_eq!(state.encrypted.usage.io_attempts, 0);
                assert_eq!(state.encrypted.usage.work_bytes, 0);
                assert_eq!(state.encrypted.usage.live_spool_bytes, 0);
                assert_eq!(state.live_fds, 0);
                assert_eq!(state.encrypted.usage.allocation_attempts, 0);
            }
        }
    }
}

#[test]
fn malformed_and_unsupported_terminal_attempts_share_finite_admission_without_kdf() {
    let limits = EncryptedReadLimits { members: 3, packed_bytes: 8, ..Default::default() };
    let mut state = budget::LedgerState::new(&EncryptedReadOptions::default().with_limits(limits)).unwrap();
    let malformed = state.encrypted.reject_member(3, ReadFault::CheckedFormat { reason: "invalid cipher framing" });
    assert!(matches!(malformed, ReadFault::CheckedFormat { .. }));
    let unsupported = state.encrypted.reject_member(3, ReadFault::UnsupportedMethod { method: 999 });
    assert!(matches!(unsupported, ReadFault::UnsupportedMethod { method: 999 }));
    assert_eq!(state.encrypted.usage.members, 2);
    assert_eq!(state.encrypted.usage.packed_bytes, 6);
    let fault = state.encrypted.begin_member(3, 0, 0, 1, true).unwrap_err();
    assert!(matches!(fault, ReadFault::Limit { resource: ReadResource::PackedBytes, limit: 8, attempted: 9 }));
    assert_eq!(state.encrypted.usage.members, 3);
    assert_eq!(state.encrypted.usage.packed_bytes, 6);
    let fault = state.encrypted.reject_member(0, ReadFault::CheckedFormat { reason: "another invalid record" });
    assert!(matches!(fault, ReadFault::Limit { resource: ReadResource::Members, limit: 3, attempted: 4 }));
    assert_eq!(state.encrypted.usage.members, 3);
    assert_eq!(state.encrypted.usage.kdf_calls, 0);
    assert_eq!(state.encrypted.usage.io_attempts, 0);
    assert_eq!(state.encrypted.usage.decoded_bytes, 0);
    assert_eq!(state.encrypted.usage.live_spool_bytes, 0);
    assert_eq!(state.live_fds, 0);
    assert_eq!(state.encrypted.usage.allocation_attempts, 0);
}

#[test]
fn r1_generic_create_cannot_bypass_per_namespace_admission() {
    use std::cell::Cell;
    let mut context = bound_context(true, 1, 1);
    context.ledger.with_state(|s| s.encrypted.limits.create_attempts = 0);
    let token = context.ledger.mint_reservation().unwrap();
    let cancel = crate::extract::Cancellation::default();
    let calls = Cell::new(0);
    let result = io::operation(
        &token,
        true,
        RunCategory::TemporaryGroups,
        IoStage::Ciphertext,
        ReadIoOperation::Create,
        Some(&cancel),
        || {
            calls.set(calls.get() + 1);
            Ok(())
        },
    );
    assert!(result.is_err(), "generic create must require the finite namespace admission seam");
    assert_eq!(calls.get(), 0);
}

fn r1_namespace_context(creates: u64, retries: u64) -> EncryptedReadContext {
    let context = EncryptedReadContext::new(Default::default()).unwrap();
    context.ledger.with_state(|s| {
        bind_plan(
            s,
            budget::ActionPlan::derive(
                budget::PlanGeometry { records: 1, regular: 1, packed: 1, ..Default::default() },
                creates,
                retries,
            )
            .unwrap(),
        )
    });
    context
}

#[test]
fn r1_creation_groups_bound_zero_one_exact_one_under_and_collisions() {
    let cancel = crate::extract::Cancellation::default();
    for cap in [0, 1, 2, 3] {
        let mut context = r1_namespace_context(3, 16);
        context.ledger.with_state(|s| s.encrypted.limits.create_attempts = cap);
        let token = context.ledger.mint_reservation().unwrap();
        let mut group = io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel).unwrap();
        let mut calls = 0;
        for _ in 0..cap {
            let fault = group
                .create(&cancel, || {
                    calls += 1;
                    Err::<(), _>(std::io::ErrorKind::AlreadyExists.into())
                })
                .unwrap_err();
            assert!(matches!(fault, ReadFault::Io { error, .. } if error.kind() == std::io::ErrorKind::AlreadyExists));
        }
        REFUSE_ALLOCATIONS.with(|flag| flag.set(true));
        let result = group.create(&cancel, || {
            calls += 1;
            Ok(())
        });
        REFUSE_ALLOCATIONS.with(|flag| flag.set(false));
        let fault = result.unwrap_err();
        assert!(
            matches!(fault, ReadFault::Limit { resource: ReadResource::CreateAttempts, limit, attempted } if limit == cap.into() && attempted == u128::from(cap)+1)
        );
        assert_eq!(calls, cap);
        assert_eq!(context.run_usage().temporary_groups, 1);
        assert_eq!(context.run_usage().io_attempts, cap.into());
        assert_eq!(context.usage().io_attempts, cap.into());
        assert_eq!(context.usage().create_attempts, cap);
        assert!(matches!(
            io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel),
            Err(ReadFault::Limit { resource: ReadResource::Run(RunCategory::TemporaryGroups), limit: 1, attempted: 2 })
        ));
        assert_eq!(context.run_usage().temporary_groups, 1);
    }
    let mut context = r1_namespace_context(3, 16);
    let token = context.ledger.mint_reservation().unwrap();
    let mut group = io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel).unwrap();
    let mut calls = 0;
    for _ in 0..2 {
        assert!(
            group
                .create(&cancel, || {
                    calls += 1;
                    Err::<(), _>(std::io::ErrorKind::AlreadyExists.into())
                })
                .is_err()
        );
    }
    group
        .create(&cancel, || {
            calls += 1;
            assert_eq!(context.run_usage().temporary_groups, 1);
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        group.create(&cancel, || {
            calls += 1;
            Ok(())
        }),
        Err(ReadFault::InvalidPlan)
    ));
    assert_eq!(calls, 3);
    assert_eq!(context.usage().create_attempts, 3);
    assert_eq!(context.run_usage().temporary_groups, 1);
    assert!(matches!(budget::next_creation_attempt(u64::MAX, u64::MAX), Err(ReadFault::CounterOverflow)));
    assert_eq!(budget::next_creation_attempt(1, 2).unwrap(), 2);
    assert!(
        budget::ActionPlan::derive(
            budget::PlanGeometry { records: 1, regular: 1, ..Default::default() },
            u64::MAX,
            u64::MAX
        )
        .is_err()
    );
}

#[test]
fn r1_creation_clear_policy_is_immutable_and_independent_of_encrypted_caps() {
    let cancel = crate::extract::Cancellation::default();
    for encrypted in [false, true] {
        let mut context = r1_namespace_context(2, 1);
        context.ledger.with_state(|s| {
            s.encrypted.limits.create_attempts = 0;
            s.encrypted.limits.interrupted_retries = 0;
            s.encrypted.limits.io_attempts = 0;
        });
        let token = context.ledger.mint_reservation().unwrap();
        let mut group = io::CreationGroup::new(&token, encrypted, IoStage::Output, &cancel).unwrap();
        let mut calls = 0;
        let result = group.create(&cancel, || {
            calls += 1;
            if calls == 1 { Err(std::io::ErrorKind::Interrupted.into()) } else { Ok(()) }
        });
        assert_eq!(result.is_ok(), !encrypted);
        assert_eq!(calls, if encrypted { 0 } else { 2 });
        assert_eq!(context.run_usage().io_attempts, calls as u128);
        assert_eq!(context.usage().create_attempts, 0);
        assert_eq!(context.usage().io_attempts, 0);
    }
    // A finite zero run policy also refuses clear acquisition, without consulting encrypted quotas.
    let mut context = r1_namespace_context(0, 16);
    let token = context.ledger.mint_reservation().unwrap();
    let mut group = io::CreationGroup::new(&token, false, IoStage::Output, &cancel).unwrap();
    let mut calls = 0;
    assert!(matches!(
        group.create(&cancel, || {
            calls += 1;
            Ok(())
        }),
        Err(ReadFault::Limit { resource: ReadResource::CreateAttempts, limit: 0, attempted: 1 })
    ));
    assert_eq!(calls, 0);
    assert_eq!(context.run_usage().io_attempts, 0);
}

#[test]
fn r1_creation_interrupted_exhaustion_reset_and_cancellation_are_charged() {
    for (creates, retries, expected_calls, resource) in
        [(5, 1, 2, ReadResource::InterruptedRetries), (1, 16, 1, ReadResource::CreateAttempts)]
    {
        let mut context = r1_namespace_context(creates, retries);
        let token = context.ledger.mint_reservation().unwrap();
        let cancel = crate::extract::Cancellation::default();
        let mut group = io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel).unwrap();
        let mut calls = 0;
        let fault = group
            .create(&cancel, || {
                calls += 1;
                Err::<(), _>(std::io::ErrorKind::Interrupted.into())
            })
            .unwrap_err();
        assert!(matches!(fault, ReadFault::Limit { resource: actual, .. } if actual == resource));
        assert_eq!(calls, expected_calls);
        assert_eq!(context.usage().create_attempts, expected_calls);
        assert_eq!(context.run_usage().io_attempts, expected_calls.into());
    }
    let mut context = r1_namespace_context(5, 1);
    let token = context.ledger.mint_reservation().unwrap();
    let cancel = crate::extract::Cancellation::default();
    let mut group = io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel).unwrap();
    let mut calls = 0;
    assert!(
        group
            .create(&cancel, || {
                calls += 1;
                Err::<(), _>(
                    if calls == 1 { std::io::ErrorKind::Interrupted } else { std::io::ErrorKind::AlreadyExists }.into(),
                )
            })
            .is_err()
    );
    group
        .create(&cancel, || {
            calls += 1;
            if calls == 3 { Err(std::io::ErrorKind::Interrupted.into()) } else { Ok(()) }
        })
        .unwrap();
    assert_eq!(calls, 4);
    assert_eq!(context.run_usage().temporary_groups, 1);
    assert_eq!(context.usage().create_attempts, 4);
    let mut context = r1_namespace_context(3, 1);
    let token = context.ledger.mint_reservation().unwrap();
    let cancel = crate::extract::Cancellation::default();
    let mut group = io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel).unwrap();
    let mut calls = 0;
    assert!(
        group
            .create(&cancel, || {
                calls += 1;
                Err::<(), _>(std::io::ErrorKind::AlreadyExists.into())
            })
            .is_err()
    );
    cancel.cancel();
    assert!(matches!(
        group.create(&cancel, || {
            calls += 1;
            Ok(())
        }),
        Err(ReadFault::Cancelled)
    ));
    assert_eq!(calls, 1);
    assert_eq!(context.run_usage().io_attempts, 1);
    assert_eq!(context.usage().create_attempts, 1);
    assert!(matches!(io::CreationGroup::new(&token, true, IoStage::Ciphertext, &cancel), Err(ReadFault::Cancelled)));
    assert_eq!(context.run_usage().temporary_groups, 1);
}

#[test]
fn r1_actual_zero_write_is_typed_and_spends_one_attempt_without_bytes() {
    struct Zero(usize);
    impl std::io::Write for Zero {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.0 += 1;
            Ok(0)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut context = bound_context(true, 3, 3);
    let token = context.ledger.mint_reservation().unwrap();
    let mut writer = Zero(0);
    let cancel = crate::extract::Cancellation::default();
    let fault = io::write(&token, true, &mut writer, IoStage::ExternalOutput, 7, b"abc", &cancel).unwrap_err();
    assert!(
        matches!(fault, ReadFault::Io { stage: IoStage::ExternalOutput, operation: ReadIoOperation::Write, offset: 7, error } if error.kind() == std::io::ErrorKind::WriteZero)
    );
    assert_eq!(writer.0, 1);
    assert_eq!(context.run_usage().io_attempts, 1);
    assert_eq!(context.usage().io_attempts, 1);
    assert_eq!(context.run_usage().io_bytes, 0);
    assert_eq!(context.usage().io_bytes, 0);
    assert_eq!(context.run_usage().positive_transfers, 0);
}

#[test]
fn r1_copy_prefix_then_failure_reports_actual_accepted_bytes_and_releases_scratch() {
    struct Prefix {
        calls: usize,
        accepted: [u8; 2],
    }
    impl std::io::Write for Prefix {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                self.accepted.copy_from_slice(&bytes[..2]);
                Ok(2)
            } else {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut context = bound_context(true, 6, 3);
    let mut file = tempfile::tempfile().unwrap();
    let mut token = context.reserve_output(&file, None, 6).unwrap();
    let cancel = crate::extract::Cancellation::default();
    token.write_all(&mut file, b"abcdef", &cancel).unwrap();
    let before = context.usage();
    let run_before = context.run_usage();
    let mut writer = Prefix { calls: 0, accepted: [0; 2] };
    let error = token.copy_to(&mut file, &mut writer, &cancel).unwrap_err();
    assert_eq!(writer.calls, 2);
    assert_eq!(writer.accepted, *b"ab");
    assert_eq!(error.accepted_output_bytes(), 2);
    assert!(
        matches!(error.operation(), Some(ReadFault::Io { stage: IoStage::ExternalOutput, operation: ReadIoOperation::Write, offset: 2, error }) if error.kind() == std::io::ErrorKind::BrokenPipe)
    );
    assert!(error.partial_run().is_none(), "a raw token copy has no runner/report");
    assert_eq!(error.publication_state(), PublicationState::NotPublished);
    assert_eq!(context.usage().reader_capacity, before.reader_capacity);
    assert_eq!(error.usage().reader_capacity, before.reader_capacity);
    assert_eq!(context.usage().io_attempts - before.io_attempts, 5);
    assert_eq!(context.run_usage().io_attempts - run_before.io_attempts, 5);
    assert_eq!(context.usage().io_bytes - before.io_bytes, 8);
    assert_eq!(context.run_usage().io_bytes - run_before.io_bytes, 8);
    assert_eq!(error.usage(), context.usage());
    assert_eq!(error.run_usage(), context.run_usage());
}

#[test]
fn checked_ledger_identity_exhaustion_and_concurrent_uniqueness() {
    use std::sync::{Arc, atomic::AtomicU64};
    let sequence = AtomicU64::new(u64::MAX - 1);
    assert_eq!(shared::test_issue_identity(&sequence).unwrap(), u64::MAX - 1);
    assert!(matches!(shared::test_issue_identity(&sequence), Err(ReadFault::CounterOverflow)));
    let sequence = Arc::new(AtomicU64::new(1));
    let threads = (0..4)
        .map(|_| {
            let sequence = sequence.clone();
            std::thread::spawn(move || {
                (0..1000).map(|_| shared::test_issue_identity(&sequence).unwrap()).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let mut ids = threads.into_iter().flat_map(|t| t.join().unwrap()).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 4000);
}

#[test]
fn source_admission_retains_eight_typed_slots_without_allocation() {
    let mut error = ZipReadError::from(ReadFault::AuthenticationFailed);
    let mut source = ObjectCleanupReport::new(OwnedObject::Source);
    REFUSE_ALLOCATIONS.with(|v| v.set(true));
    for index in 0..8 {
        source.push(CleanupFault {
            object: OwnedObject::Source,
            operation: ReadIoOperation::Stat,
            offset: None,
            cause: CleanupCause::Admission(ReadFault::Limit {
                resource: ReadResource::Run(RunCategory::SourceCheckGroups),
                limit: 16,
                attempted: 17 + index,
            }),
            close: CloseDisposition::NotApplicable,
        });
    }
    error = error.merge_cleanup(source);
    REFUSE_ALLOCATIONS.with(|v| v.set(false));
    assert_eq!(error.cleanup_errors().len(), 8);
    for (index, fault) in error.cleanup_errors().enumerate() {
        assert_eq!(fault.object, OwnedObject::Source);
        assert!(
            matches!(fault.cause, CleanupCause::Admission(ReadFault::Limit { resource: ReadResource::Run(RunCategory::SourceCheckGroups), limit: 16, attempted }) if attempted == 17 + index as u128)
        );
    }
    assert!(!error.is_source_changed());
    let mut excess = ObjectCleanupReport::new(OwnedObject::Source);
    excess.push(CleanupFault {
        object: OwnedObject::Source,
        operation: ReadIoOperation::Stat,
        offset: None,
        cause: CleanupCause::Admission(ReadFault::Cancelled),
        close: CloseDisposition::NotApplicable,
    });
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| error.merge_cleanup(excess))).is_err());
    println!(
        "R1 ReadFault={} CleanupCause={} CleanupFault={} ObjectCleanupReport={} ZipReadError={} Result<()>={} SharedHeader={}",
        std::mem::size_of::<ReadFault>(),
        std::mem::size_of::<CleanupCause>(),
        std::mem::size_of::<CleanupFault>(),
        std::mem::size_of::<ObjectCleanupReport>(),
        std::mem::size_of::<ZipReadError>(),
        std::mem::size_of::<ZipReadResult<()>>(),
        shared::SHARED_LEDGER_CAPACITY
    );
}
