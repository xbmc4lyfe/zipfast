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

use super::super::projected::*;
use super::super::*;
use super::fixture;
use crate::test_alloc::REFUSE_ALLOCATIONS;
use crate::zip::{Archive, ReadSession, ZipEntry};
use fixture::{Member, build};
use std::io::Write;
fn opened(members: &[Member<'_>]) -> (tempfile::NamedTempFile, ProjectedReadSession) {
    let order = (0..members.len()).collect::<Vec<_>>();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&build(members, &order, b"", b"", false).bytes).unwrap();
    let session = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap();
    (file, session)
}
fn context(
    session: &mut ProjectedReadSession,
    cap: Option<u64>,
    overrides: &EncryptedReadOverrides,
) -> EncryptedReadContext {
    EncryptedReadContext::for_projected(
        session,
        ProjectedReadScope::Entry(0),
        cap,
        ZipReadOutput::Callback,
        Some("pw"),
        overrides,
        &Cancellation::default(),
    )
    .unwrap()
}
#[test]
fn caller_policy_refusal_counts_original_encrypted_attempt_before_local_io() {
    let mut m = Member::stored(b"entry", b"123456789012345");
    m.flags = 1;
    let (_file, mut session) = opened(&[m]);
    let mut context = context(&mut session, Some(4), &Default::default());
    let error = session
        .read_at_with_context(0, Some("pw"), 4, &Cancellation::default(), &mut context, |_| panic!("no callback"))
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes, .. })));
    assert_eq!(context.usage().members, 1);
    assert_eq!(context.usage().packed_bytes, 15);
    assert_eq!(context.run_usage().source_seeks, 0);
    assert_eq!(context.usage().allocation_attempts, 0);
}
#[test]
fn unsupported_encrypted_method_counts_one_attempt_without_workspace() {
    let mut m = Member::stored(b"entry", b"123456789012345");
    m.flags = 1;
    m.method = 1;
    let (_file, mut session) = opened(&[m]);
    let mut context = context(&mut session, Some(64), &Default::default());
    let error = session
        .read_at_with_context(0, Some("pw"), 64, &Cancellation::default(), &mut context, |_| panic!("no callback"))
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::UnsupportedMethod { method: 1 })));
    assert_eq!(context.usage().members, 1);
    assert_eq!(context.usage().allocation_attempts, 0);
    assert_eq!(context.run_usage().source_seeks, 0);
}

#[test]
fn one_parse_one_catalogue_no_name_clone() {
    let cancel = Cancellation::default();
    OBSERVATIONS.with(|s| s.set(Default::default()));
    let (_file, mut session) = opened(&[Member::stored(b"same", b"one"), Member::stored(b"same", b"two")]);
    let pointer = session.entries().next().unwrap().name.as_ptr();
    let id = session.entry_id(0).unwrap();
    let cloned = id.clone();
    assert_eq!(session.entry(&cloned).unwrap().name.as_ptr(), pointer);
    let mut c = context(&mut session, Some(64), &Default::default());
    session.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| Ok(())).unwrap();
    session.check_source(&mut c).unwrap();
    let observed = OBSERVATIONS.with(|s| s.get());
    assert_eq!((observed.opens, observed.parses, observed.records, observed.names, observed.headers), (1, 1, 2, 2, 1));
    assert_eq!(session.entries().next().unwrap().name.as_ptr(), pointer);
    assert_eq!(session.parser_usage().fetched_bytes, session.bootstrap_usage().bytes());
    assert_eq!(session.bootstrap_usage().metadata(), 6);
}
#[test]
fn mutable_archive_cannot_seal_original_metadata() {
    let (file, session) = opened(&[Member::stored(b"original", b"one"), Member::stored(b"second", b"two")]);
    let mut legacy = Archive::open(file.path()).unwrap();
    legacy.entries.reverse();
    legacy.entries[0] = ZipEntry {
        name: "evil".into(),
        flags: 65535,
        method: 99,
        host: 0,
        crc32: 0,
        packed: u64::MAX,
        size: u64::MAX,
        local_at: u64::MAX,
        external: u32::MAX,
        mtime: Some(0),
        nanos: u32::MAX,
        aes_info: Some((3, 2, 0)),
    };
    assert_eq!(session.entries().next().unwrap().name, "original");
    let mut edited = session.entries().next().unwrap().clone();
    edited.name.clear();
    edited.size = u64::MAX;
    assert_eq!(session.entries().next().unwrap().size, 3);
    let other = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap();
    assert!(other.entry(&session.entry_id(0).unwrap()).is_err());
    let canonical = ReadSession::open(file.path()).unwrap();
    assert!(session.entry(&canonical.metadata().entry_id(0).unwrap()).is_err());
    assert!(canonical.metadata().entry(&session.entry_id(0).unwrap()).is_err());
}
#[test]
fn identities_are_unique_concurrently_and_exhaustion_never_wraps() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let local = AtomicU64::new(u64::MAX - 1);
    assert_eq!(next_identity(&local).unwrap(), u64::MAX - 1);
    assert!(matches!(next_identity(&local), Err(ReadFault::CounterOverflow)));
    assert_eq!(local.load(Ordering::Relaxed), u64::MAX);
    let ids = std::thread::scope(|scope| {
        let workers = (0..4)
            .map(|_| scope.spawn(|| (0..128).map(|_| identity().unwrap()).collect::<Vec<_>>()))
            .collect::<Vec<_>>();
        workers.into_iter().flat_map(|w| w.join().unwrap()).collect::<Vec<_>>()
    });
    let unique = ids.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), unique.len());
}
#[test]
fn checked_source_failure_keeps_error_without_allocation() {
    let (file, mut session) = opened(&[Member::stored(b"entry", b"one")]);
    let mut c = context(&mut session, Some(64), &Default::default());
    std::fs::remove_file(file.path()).unwrap();
    REFUSE_ALLOCATIONS.with(|s| s.set(true));
    let first = session.check_source(&mut c).unwrap_err();
    let next = session.check_source(&mut c).unwrap_err();
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    assert!(
        matches!(first.source_change(),Some(CheckedSourceFault::Unavailable{error,..}) if error.raw_os_error()==Some(libc::ENOENT))
    );
    assert!(matches!(next.source_change(), Some(CheckedSourceFault::PreviouslyInvalidated { .. })));
}
#[test]
fn retained_and_generic_reads_keep_source_owner() {
    let (file, mut projected) = opened(&[Member::stored(b"entry", b"one")]);
    let cancel = Cancellation::default();
    let mut canonical = ReadSession::open(file.path()).unwrap();
    let id = canonical.metadata().entry_id(0).unwrap();
    let mut c = EncryptedReadContext::for_session(
        &mut canonical,
        &id,
        Some(64),
        ZipReadOutput::Callback,
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    canonical.select(&id, 64, cancel.clone()).unwrap().read_with_context(None, &mut c, |_| Ok(())).unwrap();
    canonical.check_source_checked(&mut c).unwrap();
    let mut selected =
        crate::extract::SelectedEntry::open_cancelable_with_zip_limit(file.path(), 0, None, 64, None, cancel.clone())
            .unwrap();
    assert!(selected.is_zip());
    assert_eq!(selected.name(), "entry");
    let mut c = selected.zip_read_context(None, ZipReadOutput::Callback, &Default::default()).unwrap().unwrap();
    selected.read_with_zip_context(None, &mut c, |_| Ok(())).unwrap();
    selected.check_zip_source(&mut c).unwrap();
    let before = c.run_usage();
    assert!(projected.check_source(&mut c).is_err());
    assert_eq!(c.run_usage(), before);
    let mut foreign = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut c = context(&mut projected, Some(64), &Default::default());
    let before = c.run_usage();
    assert!(foreign.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| panic!("foreign callback")).is_err());
    assert_eq!(c.run_usage(), before);
    projected.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| Ok(())).unwrap();
}
#[test]
fn policy_factories_preserve_old_admission() {
    let (_file, mut session) = opened(&[Member::stored(b"entry", b"one")]);
    let overrides = EncryptedReadOverrides {
        member_packed_bytes: Some(0),
        member_decoded_bytes: Some(0),
        packed_bytes: Some(0),
        decoded_bytes: Some(0),
        io_bytes: Some(0),
        work_bytes: Some(0),
        members: Some(0),
        kdf_calls: Some(0),
        temp_dir: Some(PathBuf::from("x".repeat(5000))),
        ..Default::default()
    };
    let mut c = context(&mut session, Some(64), &overrides);
    assert!(c.temp.is_none());
    assert_eq!(c.usage().members, 0);
    session.read_at_with_context(0, Some("pw"), 64, &Cancellation::default(), &mut c, |_| Ok(())).unwrap();
    assert_eq!(c.usage().members, 0);
    assert_eq!(c.usage().io_bytes, 0);
    assert_eq!(c.usage().allocation_attempts, 0);
    assert!(c.run_usage().io_bytes > 0);
    assert_eq!(c.bootstrap_usage().phase(), BootstrapPhase::ActionPlan);
    assert_eq!(c.bootstrap_usage().metadata(), 6);
    assert_eq!(c.bootstrap_usage().bytes(), 0);
    let second = context(&mut session, Some(64), &overrides);
    assert_eq!(second.bootstrap_usage().metadata(), 6);
    assert_eq!(session.bootstrap_usage().metadata(), 6);
}
#[test]
fn factory_formulas_one_borrowed_pass_and_large_simulated_catalogues() {
    let (_file, session) = opened(&[Member::stored(b"entry", b"one")]);
    let stamp = session.owner.source.as_ref().ok().unwrap().stamp;
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let visits = std::cell::Cell::new(0usize);
    let e = ZipEntry { name: "n".into(), flags: 1, packed: 20, size: 7, ..Default::default() };
    let rows = std::iter::repeat_with(|| {
        visits.set(visits.get() + 1);
        (e.read_description(), false, false)
    })
    .take(100_001);
    factory(
        &mut c,
        true,
        rows,
        identity().unwrap(),
        stamp,
        17,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::Callback,
        Some("pw"),
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(visits.get(), 100_001);
    let l = c.options().limits();
    let n = 100_001u128;
    assert_eq!(l.members, 100_001);
    assert_eq!(l.kdf_calls, 0);
    assert_eq!(l.packed_bytes, 20 * n);
    assert_eq!(l.decoded_bytes, 8 * n);
    assert_eq!(l.source_bytes, 50 * n);
    assert_eq!(l.io_bytes, 50 * n);
    assert_eq!(l.work_bytes, (60 + 14 + 2 + 64) * n);
    assert_eq!(l.codec_steps, 4 * (20 * n + 7 * n + 64 * n + 1));
    let q = n + (n + 1) * (17 + 64);
    let path = 4 * q + 4 * (n + 1);
    let j = 50 * n;
    let m = 3 * 8 * (n + 1) + 5 * path + 12 * 16 * n + 4 * (n + 1) + 16 * (n + 1) + 12 + 16 + 2 * n;
    let bounds = c.ledger.with_state(|s| s.run_bounds());
    assert_eq!(bounds.source_seeks, 2 * n);
    assert_eq!(bounds.path_steps, path);
    assert_eq!(bounds.io_bytes, j);
    assert_eq!(bounds.io_attempts, (j + m + 1) * 17);
    assert_eq!(l.io_attempts, bounds.io_attempts);
    // Synthetic immutable-record harness: not physical KDF/throughput evidence.
    let huge = ZipEntry {
        packed: u64::MAX,
        size: u64::MAX,
        flags: 1,
        method: 99,
        aes_info: Some((3, 2, 0)),
        ..Default::default()
    };
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let over = EncryptedReadOverrides { member_packed_bytes: Some(0), ..Default::default() };
    factory(
        &mut c,
        true,
        std::iter::repeat_with(|| (huge.read_description(), false, false)).take(1_000_000),
        identity().unwrap(),
        stamp,
        1,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::Discard,
        None,
        &over,
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(c.options().limits().kdf_calls, 1_000_000);
    assert!(c.options().limits().packed_bytes > u128::from(u64::MAX));
    assert!(c.options().limits().packed_bytes > 1 << 40);
    assert!(c.temp.is_none());
}
#[test]
fn factories_accept_actual_borrowed_password_lengths_without_65535_default_cap() {
    let mut m = Member::stored(b"entry", b"123456789012");
    m.flags = 1;
    let (_file, mut s) = opened(&[m]);
    for len in [65535, 65536, 131073] {
        let pw = "p".repeat(len);
        let c = EncryptedReadContext::for_projected(
            &mut s,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::Callback,
            Some(&pw),
            &Default::default(),
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(c.options().limits().password_bytes, len as u64);
    }
}
#[test]
fn public_explicit_context_preserves_default_payload_limits_and_binds_run() {
    let (_file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    s.read_at_with_context(0, None, 64, &Cancellation::default(), &mut c, |_| Ok(())).unwrap();
    assert_eq!(c.run_usage().records, 1);
    assert_eq!(c.options().limits().members, 100_000);
    assert_eq!(c.options().limits().password_bytes, 65535);
}
#[test]
fn malformed_framing_has_one_attempt_and_no_local_work() {
    let mut m = Member::stored(b"entry", b"short");
    m.flags = 1;
    let (_file, mut s) = opened(&[m]);
    let mut c = context(&mut s, Some(64), &Default::default());
    let e = s
        .read_at_with_context(0, Some("pw"), 64, &Cancellation::default(), &mut c, |_| panic!("no output"))
        .unwrap_err();
    assert!(matches!(e.operation(), Some(ReadFault::CheckedFormat { .. })));
    assert_eq!(c.usage().members, 1);
    assert_eq!(c.usage().packed_bytes, 5);
    assert_eq!(c.usage().kdf_calls, 0);
    assert_eq!(c.usage().allocation_attempts, 0);
    assert_eq!(c.run_usage().source_seeks, 0);
}
#[test]
fn descriptor_zipcrypto_uses_actual_local_time_after_admission() {
    let plain = b"descriptor original local timestamp";
    let mut payload = vec![0; 12];
    payload[11] = 0x55;
    payload.extend(plain);
    crate::crypto::ZipCrypto::new("pw").encrypt(&mut payload);
    let mut member = Member::stored(b"entry", &payload);
    member.flags = 9;
    member.decoded = Some(plain);
    member.dos_time = 0x5500;
    let mut fixture = build(&[member], &[0], b"", b"", false);
    fixture.bytes[fixture.central[0] + 12..fixture.central[0] + 14].copy_from_slice(&0x9900u16.to_le_bytes());
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&fixture.bytes).unwrap();
    let cancel = Cancellation::default();
    let mut s = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut c = context(&mut s, Some(1024), &Default::default());
    let mut out = Vec::new();
    s.read_at_with_context(0, Some("pw"), 1024, &cancel, &mut c, |b| {
        out.extend_from_slice(b);
        Ok(())
    })
    .unwrap();
    assert_eq!(out, plain);
    assert_eq!(c.run_usage().source_seeks, 2);
}
#[test]
fn projected_expanded_names_exceed_canonical_extra_name_allowance() {
    let name = vec![0xb0; 65535];
    let fixture = build(&[Member::stored(&name, b"")], &vec![0; 700], b"", b"", false);
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&fixture.bytes).unwrap();
    drop(fixture);
    let projected = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap();
    let names: usize = projected.entries().map(|e| e.name.len()).sum();
    assert_eq!(names, 700 * 65535 * 3);
    assert!(names > 128 << 20);
    drop(projected);
    assert!(ReadSession::open(file.path()).is_err());
}

#[test]
fn aes_public_reads_authenticate_before_callbacks_and_reuse_retained_temp() {
    for size in [0, 17, 65536, 65537] {
        let plain = vec![0x5a; size];
        let frame = super::cipher::framed(1, "pw", &plain);
        let aes = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
        let mut m = Member::stored(b"aes", &frame);
        m.method = 99;
        m.flags = 1;
        m.decoded = Some(&plain);
        m.central_extra = &aes;
        let (_file, mut s) = opened(&[m]);
        let temp = tempfile::tempdir().unwrap();
        let overrides = EncryptedReadOverrides { temp_dir: Some(temp.path().to_path_buf()), ..Default::default() };
        let mut c = context(&mut s, Some(1 << 20), &overrides);
        assert_eq!(c.temp.is_some(), size > 65536);
        let choice = c.temp.as_ref().map(spool::ResolvedTempDirectory::path_bytes);
        let mut out = Vec::new();
        s.read_at_with_context(0, Some("pw"), 1 << 20, &Cancellation::default(), &mut c, |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(out, plain);
        assert_eq!(c.temp.as_ref().map(spool::ResolvedTempDirectory::path_bytes), choice);
        assert_eq!(c.usage().kdf_calls, 1);
        assert_eq!(c.usage().live_fds, 0);
        let mut bad = context(&mut s, Some(1 << 20), &overrides);
        let mut callbacks = 0;
        let result = s.read_at_with_context(0, Some("no"), 1 << 20, &Cancellation::default(), &mut bad, |_| {
            callbacks += 1;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(callbacks, 0);
    }
}
#[test]
fn temp_choice_scope_eligibility_and_clear_zero_output_reservation() {
    let cancel = Cancellation::default();
    let bad = EncryptedReadOverrides { temp_dir: Some(PathBuf::from("x".repeat(5000))), ..Default::default() };
    let (_file, mut empty) = opened(&[]);
    let c = EncryptedReadContext::for_projected(
        &mut empty,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &bad,
        &cancel,
    )
    .unwrap();
    assert!(c.temp.is_none());
    assert!(c.ledger.with_state(|s| s.run_bounds().source_check_groups) > 0);
    let (_file, mut zero) = opened(&[Member::stored(b"zero", b"")]);
    let error = EncryptedReadContext::for_projected(
        &mut zero,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &bad,
        &cancel,
    )
    .err()
    .unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(error.bootstrap_usage().unwrap().phase(), BootstrapPhase::ActionPlan);
    let temp = tempfile::tempdir().unwrap();
    let over = EncryptedReadOverrides {
        temp_dir: Some(temp.path().into()),
        members: Some(0),
        io_bytes: Some(0),
        ..Default::default()
    };
    let mut c = EncryptedReadContext::for_projected(
        &mut zero,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &over,
        &cancel,
    )
    .unwrap();
    assert!(c.temp.is_some());
    assert_eq!(c.usage().allocation_attempts, 0);
    let out = tempfile::tempfile().unwrap();
    let reservation = c.reserve_output(&out, None, 0).unwrap();
    assert_eq!(c.usage().members, 0);
    drop(out);
    reservation.retire_confirmed();
    let long = vec![0; 65537];
    let frame = super::cipher::framed(1, "pw", &long);
    let aes = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut m = Member::stored(b"aes", &frame);
    m.method = 99;
    m.flags = 1;
    m.central_extra = &aes;
    m.decoded = Some(&long);
    let (_f, mut large) = opened(&[m]);
    let bad = EncryptedReadOverrides { member_packed_bytes: Some(0), ..bad };
    let c = EncryptedReadContext::for_projected(
        &mut large,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::Callback,
        Some("pw"),
        &bad,
        &cancel,
    )
    .unwrap();
    assert!(c.temp.is_none());
}
#[test]
fn output_destination_is_owned_and_capacity_released_before_header_owner() {
    let (_file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let destination = PathBuf::from("retained/relative/destination");
    let mut c = EncryptedReadContext::for_projected(
        &mut s,
        ProjectedReadScope::Entry(0),
        Some(64),
        ZipReadOutput::StagedFiles { destination: &destination },
        None,
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(c.action.as_ref().unwrap().destination.as_deref(), Some(destination.as_path()));
    assert!(c.temp.is_none());
    let file = tempfile::tempfile().unwrap();
    let token = c.reserve_output(&file, None, 3).unwrap();
    drop(c);
    drop(file);
    token.retire_confirmed();
    // Caller configuration metadata has its own finite input-derived scope,
    // rather than becoming a hidden 256KiB payload-reader admission policy.
    let large = PathBuf::from("p".repeat(300_000));
    let c = EncryptedReadContext::for_projected(
        &mut s,
        ProjectedReadScope::Entry(0),
        Some(64),
        ZipReadOutput::StagedFiles { destination: &large },
        None,
        &Default::default(),
        &Cancellation::default(),
    )
    .unwrap();
    assert_eq!(c.bootstrap_usage().configuration_bytes(), 300_000);
    assert_eq!(c.usage().reader_capacity, shared::SHARED_LEDGER_CAPACITY as u64);
}
#[test]
fn no_allocation_checked_open_failure_and_parser_provenance() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let cancel = Cancellation::default();
    REFUSE_ALLOCATIONS.with(|s| s.set(true));
    let error = ProjectedReadSession::open(file.path(), &cancel).err();
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    let error = error.unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Allocation { .. })));
    assert_eq!(error.bootstrap_usage().unwrap().opens(), 0);
    std::fs::write(file.path(), [0u8; 100]).unwrap();
    let error = ProjectedReadSession::open(file.path(), &Cancellation::default()).err().unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::CheckedFormat { .. })));
    assert!(error.parser_usage().is_some());
    assert_eq!(error.bootstrap_usage().unwrap().metadata(), 6);
    assert_eq!(error.bootstrap_usage().unwrap().retirement(), Some(CloseDisposition::Closed));
}

#[test]
fn bootstrap_short_io_exact_under_eof_and_retry_boundaries() {
    struct OneByte {
        remaining: usize,
        interrupts: usize,
        calls: usize,
    }
    impl std::io::Read for OneByte {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.interrupts > 0 {
                self.interrupts -= 1;
                return Err(std::io::ErrorKind::Interrupted.into());
            }
            if self.remaining == 0 {
                return Ok(0);
            }
            self.remaining -= 1;
            out[0] = b'x';
            Ok(1)
        }
    }
    let cancel = Cancellation::default();
    let mut bytes = [0; 64];
    let mut reader = OneByte { remaining: 4, interrupts: 2, calls: 0 };
    let mut boot = io::BootstrapIo::new(4, 2).unwrap();
    for _ in 0..4 {
        assert_eq!(boot.read(&mut reader, &mut bytes, &cancel).unwrap(), 1);
    }
    assert_eq!(boot.usage().attempts(), 6);
    assert_eq!(boot.usage().bytes(), 4);
    let calls = reader.calls;
    assert!(matches!(
        boot.read(&mut reader, &mut bytes, &cancel),
        Err(ReadFault::Limit { resource: ReadResource::BootstrapBytes, limit: 4, attempted: 5 })
    ));
    assert_eq!(reader.calls, calls);
    let mut reader = OneByte { remaining: 1, interrupts: 3, calls: 0 };
    let mut boot = io::BootstrapIo::new(1, 2).unwrap();
    assert!(matches!(
        boot.read(&mut reader, &mut bytes, &cancel),
        Err(ReadFault::Limit { resource: ReadResource::InterruptedRetries, .. })
    ));
    assert_eq!(reader.calls, 3);
    assert_eq!(boot.usage().bytes(), 0);
    let mut boot = io::BootstrapIo::new(0, 0).unwrap();
    let mut calls = 0;
    assert!(matches!(
        boot.stat(IoStage::SourceHandle, || {
            calls += 1;
            Err::<(), _>(std::io::ErrorKind::Interrupted.into())
        }),
        Err(io::SourceCheckError::Admission(ReadFault::Limit { resource: ReadResource::InterruptedRetries, .. }))
    ));
    assert_eq!(calls, 1);
    for _ in 0..5 {
        boot.stat(IoStage::SourceHandle, || Ok(())).unwrap();
    }
    let before = boot.usage().attempts();
    assert!(matches!(
        boot.stat::<()>(IoStage::SourceHandle, || panic!("refused before stat")),
        Err(io::SourceCheckError::Admission(_))
    ));
    assert_eq!(boot.usage().attempts(), before);
    let mut boot = io::BootstrapIo::new(4, 0).unwrap();
    let mut eof = std::io::empty();
    for _ in 0..3 {
        assert_eq!(boot.read(&mut eof, &mut bytes, &cancel).unwrap(), 0);
    }
    assert!(boot.read(&mut eof, &mut bytes, &cancel).is_err());
}
#[test]
fn source_positioning_zero_exact_under_and_interrupted_are_metered() {
    let (_file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let mut c = context(&mut s, Some(64), &Default::default());
    c.ledger.with_state(|state| state.charge_category(RunCategory::SourceSeeks, 1)).unwrap();
    let e = s
        .read_at_with_context(0, Some("pw"), 64, &Cancellation::default(), &mut c, |_| panic!("no payload"))
        .unwrap_err();
    assert!(matches!(
        e.operation(),
        Some(ReadFault::Limit { resource: ReadResource::Run(RunCategory::SourceSeeks), .. })
    ));
    assert_eq!(c.run_usage().source_seeks, 2);
    let (_file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let c = context(&mut s, Some(64), &Default::default());
    let mut calls = 0;
    let result =
        io::operation(&c.ledger, false, RunCategory::SourceSeeks, IoStage::Source, ReadIoOperation::Seek, None, || {
            calls += 1;
            if calls < 3 { Err(std::io::ErrorKind::Interrupted.into()) } else { Ok(0) }
        });
    assert_eq!(result.unwrap(), 0);
    assert_eq!(calls, 3);
    assert_eq!(c.run_usage().source_seeks, 1);
    assert_eq!(c.run_usage().io_attempts, 3);
    assert_eq!(c.usage().io_attempts, 0);
}
#[test]
fn directory_fault_preserves_every_parser_shape_without_allocation() {
    use zip_container::{
        DirectoryError as D, LimitKind as L, OwnershipError as O, OwnershipKind as K, ParseError as P, SupplyError as S,
    };
    let mut errors = vec![
        D::MalformedEnd,
        D::MalformedZip64,
        D::EntryCount { declared: 2, observed: 1 },
        D::InvalidLocalOffset,
        D::UnsupportedDisk,
        D::Allocation,
        D::Incomplete,
    ];
    errors.extend(
        [
            L::DirectoryBytes,
            L::Entries,
            L::FetchedBytes,
            L::RangeBytes,
            L::WorkUnits,
            L::NameBytes,
            L::ExtraBytes,
            L::CommentBytes,
            L::ScratchBytes,
        ]
        .map(D::Limit),
    );
    errors.extend([S::OutOfBounds, S::Unsolicited, S::UnexpectedOffset, S::Overlong].map(D::Supply));
    errors.extend(
        [
            P::OffsetOverflow,
            P::BadSignature { offset: 7 },
            P::Truncated { offset: 9, needed: 3, available: 1 },
            P::TruncatedExtraHeader { offset: 8, available: 2 },
            P::TruncatedExtraBody { offset: 8, id: 1, advertised: 3, available: 2 },
            P::ExtraBodyTooLong { len: 65536 },
        ]
        .map(D::Parse),
    );
    for kind in [K::Entries, K::NameBytes, K::ExtraBytes, K::CommentBytes] {
        errors.extend([
            D::Ownership(O::CounterOverflow { kind }),
            D::Ownership(O::LimitExceeded { kind, needed: 4, limit: 3 }),
            D::Ownership(O::Allocation { kind }),
        ]);
    }
    REFUSE_ALLOCATIONS.with(|s| s.set(true));
    for error in errors {
        let wrapped = ZipReadError::from(directory_fault(error));
        assert!(matches!(wrapped.operation(),Some(ReadFault::Directory{error:actual}) if *actual==error));
    }
    let notzip = directory_fault(D::NotZip);
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    assert!(matches!(notzip, ReadFault::CheckedFormat { .. }));
}

#[test]
fn source_open_parse_failure_keeps_original_raw_source_fault_and_usage() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[0; 100]).unwrap();
    let path = file.path().to_path_buf();
    OPEN_HOOK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |event| {
            if event == 1 {
                std::fs::remove_file(&path).unwrap();
            }
        }))
    });
    let result = ProjectedReadSession::open(file.path(), &Cancellation::default());
    OPEN_HOOK.with(|s| *s.borrow_mut() = None);
    let e = result.err().unwrap();
    assert!(e.is_source_changed());
    assert!(
        matches!(e.source_change(),Some(CheckedSourceFault::Unavailable{error,..}) if error.raw_os_error()==Some(libc::ENOENT))
    );
    assert!(matches!(e.operation(), Some(ReadFault::CheckedFormat { .. })));
    assert!(e.parser_usage().is_some());
    assert_eq!(e.bootstrap_usage().unwrap().retirement(), Some(CloseDisposition::Closed));
}
#[test]
fn prepare_failure_and_cancel_run_final_source_observation_before_workspace() {
    let cancel = Cancellation::default();
    let (file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let mut c = context(&mut s, Some(64), &Default::default());
    let path = file.path().to_path_buf();
    let owned_cancel = cancel.clone();
    OPEN_HOOK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |event| {
            if event == 4 {
                std::fs::remove_file(&path).unwrap();
                owned_cancel.cancel();
            }
        }))
    });
    let result = s.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| panic!("no output"));
    OPEN_HOOK.with(|s| *s.borrow_mut() = None);
    let e = result.unwrap_err();
    assert!(e.is_source_changed());
    assert!(matches!(e.operation(), Some(ReadFault::Cancelled)));
    assert_eq!(c.usage().allocation_attempts, 0);
    assert_eq!(c.run_usage().source_seeks, 1);
    assert_eq!(c.run_usage().io_bytes, 0);
}
#[test]
fn initial_legacy_proof_failure_is_not_recaptured_to_bless_metadata() {
    // The private legacy owner may retain an unsupported/unproved source while
    // serving its old buffered route; checked entrypoints must move the first
    // raw error once and then return only Copy invalidation evidence.
    let (_file, mut session) = opened(&[Member::stored(b"entry", b"one")]);
    session.owner.source = Err(io::SourceCheckError::Source(CheckedSourceFault::Unavailable {
        stage: IoStage::SourceHandle,
        error: std::io::Error::from_raw_os_error(libc::EIO),
    }));
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    REFUSE_ALLOCATIONS.with(|s| s.set(true));
    let first = session.check_source(&mut c).unwrap_err();
    let next = session.check_source(&mut c).unwrap_err();
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    assert!(
        matches!(first.source_change(),Some(CheckedSourceFault::Unavailable{error,..}) if error.raw_os_error()==Some(libc::EIO))
    );
    assert!(matches!(next.source_change(), Some(CheckedSourceFault::PreviouslyInvalidated { .. })));
    assert_eq!(c.bootstrap_usage().metadata(), 0);
}

#[test]
fn mixed_all_record_geometry_paths_spools_outputs_and_override_intersections() {
    let (_file, s) = opened(&[Member::stored(b"entry", b"one")]);
    let stamp = s.owner.source.as_ref().ok().unwrap().stamp;
    let temp = tempfile::tempdir().unwrap();
    let aes = ZipEntry {
        name: "a".into(),
        method: 99,
        flags: 1,
        packed: 70020,
        size: 9,
        aes_info: Some((1, 2, 0)),
        ..Default::default()
    };
    let clear = ZipEntry { name: "../blocked".into(), packed: 5, size: 7, ..Default::default() };
    let dir = ZipEntry { name: "d/".into(), ..Default::default() };
    let link = ZipEntry { name: "link".into(), ..Default::default() };
    let rows =
        [(&aes, false, false), (&clear, false, false), (&dir, true, false), (&dir, true, false), (&link, false, true)];
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let over = EncryptedReadOverrides { temp_dir: Some(temp.path().into()), ..Default::default() };
    factory(
        &mut c,
        true,
        rows.into_iter().map(|(e, d, l)| (e.read_description(), d, l)),
        identity().unwrap(),
        stamp,
        17,
        ProjectedReadScope::AllRegular,
        None,
        ZipReadOutput::StagedFiles { destination: Path::new("out") },
        Some("pw"),
        &over,
        &Cancellation::default(),
    )
    .unwrap();
    let l = c.options().limits();
    assert_eq!((l.member_packed_bytes, l.member_decoded_bytes, l.member_spool_bytes), (70020, 9, 70000));
    assert_eq!((l.live_spool_bytes, l.io_bytes), (70009, 70020 + 30 + 3 * 70000 + 9));
    assert_eq!((l.packed_bytes, l.decoded_bytes, l.source_bytes), (70020, 10, 70050));
    assert_eq!((l.members, l.kdf_calls, l.password_bytes), (1, 1, 2));
    let q = (1 + 10 + 2 + 2 + 4) + 6 * (17 + temp.path().as_os_str().len() as u128 + 3 + 64);
    let b = c.ledger.with_state(|s| s.run_bounds());
    assert_eq!(b.records, 5);
    assert_eq!(b.path_steps, 4 * q + 24);
    assert_eq!(b.io_bytes, 70025 + 60 + 210000 + 16);
    assert_eq!(b.source_seeks, 4);
    assert_eq!(b.temporary_groups, 3);
    assert_eq!(b.directory_finalization, 36);
    assert_eq!(b.live_spool_bytes, 70009);
    assert_eq!(c.bootstrap_usage().configuration_bytes(), 3);
    assert_eq!(c.usage().reader_capacity, shared::SHARED_LEDGER_CAPACITY as u64 + 4096);
    assert_eq!(c.usage().allocation_attempts, 0);
    let bad = EncryptedReadOverrides {
        member_packed_bytes: Some(1),
        member_decoded_bytes: Some(2),
        live_spool_bytes: Some(3),
        packed_bytes: Some(4),
        decoded_bytes: Some(5),
        io_bytes: Some(6),
        work_bytes: Some(7),
        io_attempts: Some(8),
        codec_steps: Some(9),
        members: Some(0),
        kdf_calls: Some(0),
        password_bytes: Some(1),
        interrupted_retries: Some(2),
        create_attempts: Some(3),
        temp_dir: Some("x".repeat(5000).into()),
    };
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    factory(
        &mut c,
        true,
        std::iter::once((aes.read_description(), false, false)),
        identity().unwrap(),
        stamp,
        17,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::Discard,
        Some("pw"),
        &bad,
        &Cancellation::default(),
    )
    .unwrap();
    let l = c.options().limits();
    assert_eq!((l.member_packed_bytes, l.member_decoded_bytes), (1, 2));
    assert_eq!(
        (l.live_spool_bytes, l.packed_bytes, l.decoded_bytes, l.io_bytes, l.work_bytes, l.io_attempts, l.codec_steps),
        (3, 4, 5, 6, 7, 8, 9)
    );
    assert_eq!((l.members, l.kdf_calls, l.password_bytes, l.interrupted_retries, l.create_attempts), (0, 0, 1, 2, 3));
    assert!(c.temp.is_none());
}
#[test]
fn explicit_zero_encrypted_allocation_does_not_block_preplan_path_or_clear_workspace() {
    let plain = vec![1; 65537];
    let frame = super::cipher::framed(1, "pw", &plain);
    let extra = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut m = Member::stored(b"aes", &frame);
    m.method = 99;
    m.flags = 1;
    m.decoded = Some(&plain);
    m.central_extra = &extra;
    let (_file, mut s) = opened(&[m]);
    let temp = tempfile::tempdir().unwrap();
    let limits = EncryptedReadLimits { allocation_attempts: 0, ..Default::default() };
    let mut c = EncryptedReadContext::new(
        EncryptedReadOptions::default().with_limits(limits).with_temp_dir(temp.path().into()),
    )
    .unwrap();
    let e = s
        .read_at_with_context(0, Some("pw"), 1 << 20, &Cancellation::default(), &mut c, |_| panic!("no payload"))
        .unwrap_err();
    assert!(matches!(e.operation(), Some(ReadFault::Limit { resource: ReadResource::AllocationAttempts, .. })));
    assert_eq!(c.usage().members, 1);
    assert_eq!(c.usage().kdf_calls, 1);
    assert!(c.temp.is_some());
    assert_eq!(c.bootstrap_usage().acquisition_attempts(), 2);
    assert_eq!(c.usage().allocation_attempts, 0);
    assert_eq!(c.usage().reader_capacity, shared::SHARED_LEDGER_CAPACITY as u64 + 4096);
}

#[test]
fn bootstrap_closes_are_independent_one_shot_admitted_and_never_retry() {
    let mut boot = io::BootstrapIo::opening().unwrap();
    let mut calls = 0;
    let fault = boot
        .retire_once(OwnedObject::SourcePathDirectory, || {
            calls += 1;
            Err(std::io::ErrorKind::Interrupted.into())
        })
        .unwrap_err();
    assert_eq!(calls, 1);
    assert!(matches!(fault.cause, CleanupCause::Io(_)));
    assert_eq!(fault.close, CloseDisposition::Unresolved);
    assert_eq!(boot.usage().attempts(), 1);
    assert!(boot.retire_once(OwnedObject::SourcePathDirectory, || panic!("cannot close again")).is_err());
    assert_eq!(boot.usage().attempts(), 1);
    boot.retire_once(OwnedObject::Source, || {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(boot.usage().attempts(), 2);
    assert_eq!(boot.usage().source_retirement(), Some(CloseDisposition::Closed));
    assert_eq!(boot.usage().cwd_retirement(), Some(CloseDisposition::Unresolved));
}

#[test]
fn native_raw_open_flags_and_explicit_retirement_faults_keep_phase_exclusion() {
    use std::os::fd::AsRawFd;
    let (_file, s) = opened(&[Member::stored(b"entry", b"one")]);
    let fd = s.owner.file.as_raw_fd();
    assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK, 0);
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&[0; 100]).unwrap();
    CLOSE_FAULT.with(|s| s.set(Some(libc::EINTR)));
    let e = ProjectedReadSession::open(file.path(), &Cancellation::default()).err().unwrap();
    assert_eq!(e.cleanup_errors().len(), 1);
    let fault = e.cleanup_errors().next().unwrap();
    assert_eq!(fault.object, OwnedObject::Source);
    assert_eq!(fault.close, CloseDisposition::Unresolved);
    assert_eq!(e.bootstrap_usage().unwrap().source_retirement(), Some(CloseDisposition::Unresolved));
    assert!(matches!(e.operation(), Some(ReadFault::CheckedFormat { .. })));
    #[cfg(target_os = "macos")]
    {
        OBSERVATIONS.with(|s| s.set(Default::default()));
        CLOSE_FAULT.with(|s| s.set(Some(libc::EINTR)));
        let e = ProjectedReadSession::open(Path::new("nonexistent-relative-source"), &Cancellation::default())
            .err()
            .unwrap();
        assert_eq!(e.bootstrap_usage().unwrap().opens(), 0);
        assert_eq!(OBSERVATIONS.with(|s| s.get().opens), 0);
        assert_eq!(e.cleanup_errors().len(), 1);
        assert_eq!(e.cleanup_errors().next().unwrap().object, OwnedObject::SourcePathDirectory);
        assert_eq!(e.bootstrap_usage().unwrap().source_retirement(), None);
    }
}

#[test]
fn stale_wrong_ordinal_output_password_length_and_reuse_refuse_before_io() {
    let (_file, mut s) = opened(&[Member::stored(b"first", b"one"), Member::stored(b"second", b"two")]);
    let mut c = context(&mut s, Some(64), &Default::default());
    let cancel = Cancellation::default();
    let initial = c.run_usage();
    for (index, pw, max) in [(1, Some("pw"), 64), (0, Some("wrong-length"), 64), (0, Some("pw"), 63)] {
        let e = s.read_at_with_context(index, pw, max, &cancel, &mut c, |_| panic!("invalid callback")).unwrap_err();
        assert!(matches!(e.operation(), Some(ReadFault::InvalidPlan)));
        assert_eq!(c.run_usage(), initial);
    }
    c.action.as_mut().unwrap().output = budget::PlannedOutput::Discard;
    assert!(matches!(
        s.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| panic!("invalid output"))
            .unwrap_err()
            .operation(),
        Some(ReadFault::InvalidPlan)
    ));
    assert_eq!(c.run_usage(), initial);
    c.action.as_mut().unwrap().output = budget::PlannedOutput::Callback;
    s.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| Ok(())).unwrap();
    assert!(c.action.as_ref().unwrap().completed);
    let usage = c.run_usage();
    assert!(s.read_at_with_context(0, Some("pw"), 64, &cancel, &mut c, |_| panic!("consumed callback")).is_err());
    assert_eq!(c.run_usage(), usage);
}

#[test]
fn public_output_fd_admission_is_bound_and_rejects_the_held_source_alias() {
    use std::os::fd::AsFd;
    let (file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let output = tempfile::tempfile().unwrap();
    let e = s.admit_output_fd(output.as_fd(), &mut c).unwrap_err();
    assert!(matches!(e.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(c.bootstrap_usage().attempts(), 0);
    let mut c = context(&mut s, Some(64), &Default::default());
    s.admit_output_fd(output.as_fd(), &mut c).unwrap();
    assert!(matches!(
        s.admit_output_fd(file.as_file().as_fd(), &mut c).unwrap_err().operation(),
        Some(ReadFault::CheckedFormat { .. })
    ));
}

#[test]
fn refused_initial_proof_never_becomes_a_fabricated_source_observation() {
    let (_file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    s.owner.source = Err(io::SourceCheckError::Admission(ReadFault::Limit {
        resource: ReadResource::InterruptedRetries,
        limit: 16,
        attempted: 17,
    }));
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let first = s.check_source(&mut c).unwrap_err();
    let next = s.check_source(&mut c).unwrap_err();
    assert!(!first.is_source_changed());
    assert!(!next.is_source_changed());
    assert!(matches!(first.operation(), Some(ReadFault::Limit { resource: ReadResource::InterruptedRetries, .. })));
    assert!(matches!(next.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(c.bootstrap_usage().metadata(), 0);
}

#[test]
fn derived_envelope_retained_zero_lie_then_valid_member_and_hard_lower_override() {
    fn deflate(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }
    let bad = super::cipher::framed(1, "pw", &deflate(b"too much"));
    let good = super::cipher::framed(1, "pw", &deflate(&[0]));
    let aes = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 8, 0]);
    for cap in [None, Some(0), Some(1)] {
        let mut a = Member::stored(b"bad", &bad);
        a.flags = 1;
        a.method = 99;
        a.decoded = Some(b"");
        a.central_extra = &aes;
        let mut b = Member::stored(b"good", &good);
        b.flags = 1;
        b.method = 99;
        b.decoded = Some(&[0]);
        b.central_extra = &aes;
        let (_file, mut s) = opened(&[a, b]);
        let over = EncryptedReadOverrides { decoded_bytes: cap, ..Default::default() };
        let mut c = EncryptedReadContext::for_projected(
            &mut s,
            ProjectedReadScope::AllRegular,
            None,
            ZipReadOutput::Callback,
            Some("pw"),
            &over,
            &Cancellation::default(),
        )
        .unwrap();
        assert_eq!(c.options().limits().decoded_bytes, cap.unwrap_or(3));
        let error = test_original_all_member(&mut s, 0, &mut c, &mut |_| panic!("unexposed probe")).unwrap_err();
        assert_eq!(c.usage().decoded_bytes, 1);
        if cap == Some(0) {
            assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::DecodedBytes, .. })));
            continue;
        }
        assert!(matches!(error.operation(), Some(ReadFault::Integrity { reason: IntegrityReason::DecodedSize, .. })));
        let mut accepted = 0;
        let result = test_original_all_member(&mut s, 1, &mut c, &mut |bytes| {
            accepted += bytes.len();
            Ok(())
        });
        if cap.is_none() {
            result.unwrap();
            assert_eq!(accepted, 1);
            assert_eq!(c.usage().members, 2);
            assert_eq!(c.usage().decoded_bytes, 2);
        } else {
            assert!(matches!(
                result.unwrap_err().operation(),
                Some(ReadFault::Limit { resource: ReadResource::DecodedBytes, .. })
            ));
            assert_eq!(accepted, 0);
        }
    }
}

#[test]
fn optional_legacy_cwd_or_absolute_path_allocation_cannot_break_old_reads() {
    let fixture = build(&[Member::stored(b"entry", b"one")], &[0], b"", b"", false);
    let mut relative = tempfile::Builder::new().prefix(".zipfast-task4-proof-").tempfile_in(".").unwrap();
    relative.write_all(&fixture.bytes).unwrap();
    let path = Path::new(relative.path().file_name().unwrap());
    LEGACY_CWD_FAULT.with(|s| s.set(Some(libc::ENOENT)));
    let mut selected = crate::extract::SelectedEntry::open(path, 0, None, 64).unwrap();
    assert_eq!(selected.name(), "entry");
    let first = selected.zip_read_context(None, ZipReadOutput::Callback, &Default::default()).err().unwrap();
    assert!(!first.is_source_changed());
    assert!(
        matches!(first.operation(),Some(ReadFault::Io{stage:IoStage::SourcePath,operation:ReadIoOperation::Directory,error,..}) if error.raw_os_error()==Some(libc::ENOENT))
    );
    assert_eq!(first.bootstrap_usage().unwrap().phase(), BootstrapPhase::LegacySourceProof);
    let next = selected.zip_read_context(None, ZipReadOutput::Callback, &Default::default()).err().unwrap();
    assert!(!next.is_source_changed());
    assert!(matches!(next.operation(), Some(ReadFault::InvalidPlan)));
    let mut out = Vec::new();
    selected
        .read(None, |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"one");
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), fixture.bytes).unwrap();
    crate::test_alloc::DENY_LAYOUT.with(|s| s.set(Some((file.path().as_os_str().len(), 1))));
    let mut owner = ProjectedOwner::open_legacy(file.path(), &Cancellation::default()).unwrap();
    assert!(crate::test_alloc::DENY_LAYOUT.with(|s| s.get()).is_none());
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let e = owner.check_source(&mut c).unwrap_err();
    assert!(matches!(e.operation(), Some(ReadFault::Allocation { .. })));
    assert!(!e.is_source_changed());
    let mut out = Vec::new();
    owner
        .legacy_read(0, None, 64, &Cancellation::default(), |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"one");
}

fn inject_bootstrap(
    stage: Option<IoStage>,
    operation: ReadIoOperation,
    remaining: u64,
    errno: i32,
    deny_allocations: bool,
) {
    io::BOOTSTRAP_FAULT
        .with(|s| s.set(Some(io::BootstrapTestFault { stage, operation, remaining, errno, deny_allocations })));
}
#[test]
fn checked_probe_error_keeps_initial_source_and_close_without_new_allocation() {
    let (file, _) = opened(&[Member::stored(b"entry", b"one")]);
    let path = file.path().to_path_buf();
    OPEN_HOOK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |event| {
            if event == 0 {
                std::fs::remove_file(&path).unwrap();
            }
        }))
    });
    let cancel = Cancellation::default();
    let opened = CheckedOpen::open(file.path(), &cancel).unwrap();
    OPEN_HOOK.with(|s| *s.borrow_mut() = None);
    inject_bootstrap(None, ReadIoOperation::Read, 1, libc::EIO, true);
    CLOSE_FAULT.with(|s| s.set(Some(libc::EINTR)));
    let result = opened.probe(1024, &cancel);
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    let error = result.err().unwrap();
    assert!(error.is_source_changed());
    assert!(
        matches!(error.source_change(),Some(CheckedSourceFault::Unavailable{stage:IoStage::SourcePath,error}) if error.raw_os_error()==Some(libc::ENOENT))
    );
    assert!(
        matches!(error.operation(),Some(ReadFault::Io{stage:IoStage::Bootstrap,operation:ReadIoOperation::Read,error,..}) if error.raw_os_error()==Some(libc::EIO))
    );
    assert_eq!(error.cleanup_errors().len(), 1);
    assert!(
        matches!(&error.cleanup_errors().next().unwrap().cause,CleanupCause::Io(error) if error.raw_os_error()==Some(libc::EINTR))
    );
    let boot = error.bootstrap_usage().unwrap();
    assert_eq!((boot.metadata(), boot.dispatch_bytes(), boot.bytes(), boot.seeks(), boot.attempts()), (2, 0, 0, 1, 6));
    assert_eq!(boot.source_retirement(), Some(CloseDisposition::Unresolved));
    assert!(io::BOOTSTRAP_FAULT.with(|s| s.get()).is_none());
}
#[test]
fn checked_probe_error_keeps_initial_admission_without_fabricated_source_change() {
    let (file, _) = opened(&[Member::stored(b"entry", b"one")]);
    let cancel = Cancellation::default();
    inject_bootstrap(Some(IoStage::SourcePath), ReadIoOperation::Stat, 17, libc::EINTR, false);
    let opened = CheckedOpen::open(file.path(), &cancel).unwrap();
    inject_bootstrap(None, ReadIoOperation::Read, 1, libc::EIO, true);
    let result = opened.probe(1024, &cancel);
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    let error = result.err().unwrap();
    assert!(!error.is_source_changed());
    assert!(
        matches!(error.operation(),Some(ReadFault::Io{operation:ReadIoOperation::Read,error,..}) if error.raw_os_error()==Some(libc::EIO))
    );
    let fault = error.cleanup_errors().next().unwrap();
    assert_eq!(fault.object, OwnedObject::Source);
    assert_eq!(fault.operation, ReadIoOperation::Stat);
    assert_eq!(fault.close, CloseDisposition::NotApplicable);
    assert!(matches!(
        &fault.cause,
        CleanupCause::Admission(ReadFault::Limit {
            resource: ReadResource::InterruptedRetries,
            limit: 16,
            attempted: 17
        })
    ));
    let boot = error.bootstrap_usage().unwrap();
    assert_eq!((boot.metadata(), boot.attempts(), boot.dispatch_bytes()), (2, 22, 0));
    assert_eq!(boot.source_retirement(), Some(CloseDisposition::Closed));
}
#[test]
fn no_observed_handle_length_is_not_invented_zero_and_never_probes() {
    let (file, _) = opened(&[Member::stored(b"entry", b"one")]);
    let cancel = Cancellation::default();
    for code in [libc::EIO, libc::EINTR] {
        inject_bootstrap(
            Some(IoStage::SourceHandle),
            ReadIoOperation::Stat,
            if code == libc::EINTR { 17 } else { 1 },
            code,
            true,
        );
        let result = CheckedOpen::open(file.path(), &cancel);
        REFUSE_ALLOCATIONS.with(|s| s.set(false));
        let e = result.err().unwrap();
        let boot = e.bootstrap_usage().unwrap();
        assert_eq!((boot.metadata(), boot.bytes(), boot.dispatch_bytes(), boot.seeks()), (1, 0, 0, 0));
        assert_eq!(boot.source_retirement(), Some(CloseDisposition::Closed));
        assert_eq!(boot.attempts(), if code == libc::EINTR { 19 } else { 3 });
        if code == libc::EINTR {
            assert!(!e.is_source_changed());
            assert!(matches!(e.operation(), Some(ReadFault::Limit { resource: ReadResource::InterruptedRetries, .. })));
        } else {
            assert!(
                matches!(e.source_change(),Some(CheckedSourceFault::Unavailable{stage:IoStage::SourceHandle,error}) if error.raw_os_error()==Some(libc::EIO))
            );
        }
    }
    let empty = tempfile::NamedTempFile::new().unwrap();
    let opened = CheckedOpen::open(empty.path(), &cancel).unwrap();
    assert_eq!(opened.len, 0);
    let (opened, bytes) = opened.probe(1024, &cancel).unwrap();
    assert!(bytes.is_empty());
    opened.retire().unwrap();
}
#[test]
fn invalid_projected_scope_precedes_context_allocation_and_source_io() {
    let (_file, mut s) = opened(&[Member::stored(b"entry", b"one")]);
    let cancel = Cancellation::default();
    REFUSE_ALLOCATIONS.with(|s| s.set(true));
    let result = EncryptedReadContext::for_projected(
        &mut s,
        ProjectedReadScope::Entry(1),
        None,
        ZipReadOutput::Callback,
        None,
        &Default::default(),
        &cancel,
    );
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    let e = result.err().unwrap();
    assert!(matches!(e.operation(), Some(ReadFault::InvalidPlan)));
    assert!(e.bootstrap_usage().is_none());
}
#[test]
fn terminal_parser_cancel_keeps_usage_and_foreign_calls_do_not_consume_raw_proof() {
    let bytes = build(&[Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let held = cancel.clone();
    OPEN_HOOK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |event| {
            if event == 2 {
                held.cancel();
            }
        }))
    });
    let result = ProjectedReadSession::open(file.path(), &cancel);
    OPEN_HOOK.with(|s| *s.borrow_mut() = None);
    let e = result.err().unwrap();
    assert!(matches!(e.operation(), Some(ReadFault::Cancelled)));
    assert!(e.parser_usage().is_some());
    assert_eq!(e.bootstrap_usage().unwrap().metadata(), 6);
    assert_eq!(e.bootstrap_usage().unwrap().source_retirement(), Some(CloseDisposition::Closed));
    let (_file, mut original) = opened(&[Member::stored(b"entry", b"one")]);
    let mut context = context(&mut original, Some(64), &Default::default());
    let (_file, mut foreign) = opened(&[Member::stored(b"entry", b"one")]);
    foreign.owner.source = Err(io::SourceCheckError::Source(CheckedSourceFault::Unavailable {
        stage: IoStage::SourcePath,
        error: std::io::Error::from_raw_os_error(libc::EIO),
    }));
    assert!(matches!(foreign.check_source(&mut context).unwrap_err().operation(), Some(ReadFault::InvalidPlan)));
    let mut own = EncryptedReadContext::new(Default::default()).unwrap();
    let first = foreign.check_source(&mut own).unwrap_err();
    assert!(
        matches!(first.source_change(),Some(CheckedSourceFault::Unavailable{error,..}) if error.raw_os_error()==Some(libc::EIO))
    );
}

#[test]
fn legacy_length_change_before_proof_cannot_bless_older_parser_geometry() {
    let bytes = build(&[Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let path = file.path().to_path_buf();
    OPEN_HOOK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |event| {
            if event == 5 {
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"appended after legacy length")
                    .unwrap();
            }
        }))
    });
    let result = ProjectedOwner::open_legacy(file.path(), &Cancellation::default());
    OPEN_HOOK.with(|s| *s.borrow_mut() = None);
    let mut owner = result.unwrap();
    let mut out = Vec::new();
    owner
        .legacy_read(0, None, 64, &Cancellation::default(), |b| {
            out.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(out, b"one");
    let mut c = EncryptedReadContext::new(Default::default()).unwrap();
    let error = owner.check_source(&mut c).unwrap_err();
    assert!(matches!(error.source_change(), Some(CheckedSourceFault::StampMismatch)));
    assert_eq!(c.bootstrap_usage().metadata(), 0);
    assert!(matches!(
        owner.check_source(&mut c).unwrap_err().source_change(),
        Some(CheckedSourceFault::PreviouslyInvalidated { .. })
    ));
}

#[test]
fn r1_postparse_constructor_failures_keep_successful_usage_and_retirement() {
    for generic in [false, true] {
        for case in 0..6 {
            let bytes = build(&[Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes;
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(&bytes).unwrap();
            let cancel = Cancellation::default();
            let baseline = if generic {
                let (source, _) = CheckedOpen::open(file.path(), &cancel).unwrap().probe(1024, &cancel).unwrap();
                ProjectedReadSession { owner: source.into_zip(&cancel).unwrap() }
            } else {
                ProjectedReadSession::open(file.path(), &cancel).unwrap()
            };
            let expected = baseline.parser_usage();
            let attempts = baseline.bootstrap_usage().attempts();
            drop(baseline);
            let path = file.path().to_path_buf();
            let held = cancel.clone();
            OPEN_HOOK.with(|s| {
                *s.borrow_mut() = Some(Box::new(move |event| {
                    if event == 6 {
                        match case {
                            0 => std::fs::remove_file(&path).unwrap(),
                            1 => std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"x").unwrap(),
                            2 => {
                                inject_bootstrap(Some(IoStage::SourceHandle), ReadIoOperation::Stat, 1, libc::EIO, true)
                            }
                            3 => inject_bootstrap(
                                Some(IoStage::SourceHandle),
                                ReadIoOperation::Stat,
                                17,
                                libc::EINTR,
                                true,
                            ),
                            4 => held.cancel(),
                            5 => IDENTITY_FAULT.with(|s| s.set(true)),
                            _ => unreachable!(),
                        }
                    }
                }))
            });
            let result = if generic {
                crate::extract::SelectedEntry::open_cancelable_with_zip_limit(
                    file.path(),
                    0,
                    None,
                    64,
                    None,
                    cancel.clone(),
                )
                .map(|_| ())
            } else {
                ProjectedReadSession::open(file.path(), &cancel).map(|_| ())
            };
            REFUSE_ALLOCATIONS.with(|s| s.set(false));
            OPEN_HOOK.with(|s| *s.borrow_mut() = None);
            let error = result.unwrap_err();
            match case {
                0 | 2 => assert!(matches!(error.source_change(), Some(CheckedSourceFault::Unavailable { .. }))),
                1 => assert!(matches!(error.source_change(), Some(CheckedSourceFault::StampMismatch))),
                3 => assert!(matches!(
                    error.operation(),
                    Some(ReadFault::Limit { resource: ReadResource::InterruptedRetries, limit: 16, attempted: 17 })
                )),
                4 => assert!(matches!(error.operation(), Some(ReadFault::Cancelled))),
                5 => assert!(matches!(error.operation(), Some(ReadFault::CounterOverflow))),
                _ => unreachable!(),
            }
            assert_eq!(error.parser_usage(), Some(expected), "generic={generic} case={case}");
            let boot = error.bootstrap_usage().unwrap();
            assert_eq!(boot.phase(), BootstrapPhase::SourceOpen);
            assert_eq!(
                boot.metadata(),
                match case {
                    0 => 5,
                    2 | 3 => 4,
                    _ => 6,
                }
            );
            assert_eq!(
                boot.attempts(),
                match case {
                    0 => attempts,
                    2 => attempts - 1,
                    3 => attempts + 15,
                    _ => attempts + 1,
                }
            );
            assert_eq!(boot.source_retirement(), Some(CloseDisposition::Closed));
            assert_eq!(error.cleanup_errors().len(), 0);
            assert!(IDENTITY_FAULT.with(|s| !s.get()));
        }
    }
}
#[test]
fn r1_explicit_postfactory_source_refusals_keep_action_plan_usage() {
    for admission in [false, true] {
        let (file, mut session) = opened(&[Member::stored(b"entry", b"one")]);
        let mut context = EncryptedReadContext::new(Default::default()).unwrap();
        let path = file.path().to_path_buf();
        OPEN_HOOK.with(|s| {
            *s.borrow_mut() = Some(Box::new(move |event| {
                if event == 8 {
                    if admission {
                        inject_bootstrap(Some(IoStage::SourceHandle), ReadIoOperation::Stat, 17, libc::EINTR, true);
                    } else {
                        std::fs::remove_file(&path).unwrap();
                    }
                }
            }))
        });
        let mut calls = 0;
        let result = session.read_at_with_context(0, None, 64, &Cancellation::default(), &mut context, |_| {
            calls += 1;
            Ok(())
        });
        REFUSE_ALLOCATIONS.with(|s| s.set(false));
        OPEN_HOOK.with(|s| *s.borrow_mut() = None);
        let error = result.unwrap_err();
        assert_eq!(calls, 0);
        if admission {
            assert!(!error.is_source_changed());
            assert!(matches!(
                error.operation(),
                Some(ReadFault::Limit { resource: ReadResource::InterruptedRetries, .. })
            ));
        } else {
            assert!(error.is_source_changed());
        }
        let boot = error.bootstrap_usage().expect("postfactory binding origin");
        assert_eq!(boot, context.bootstrap_usage());
        assert_eq!(boot.phase(), BootstrapPhase::ActionPlan);
        assert_eq!(boot.metadata(), if admission { 4 } else { 5 });
        assert_eq!(boot.attempts(), if admission { 20 } else { 5 });
        assert_eq!(boot.bytes(), 0);
        assert_eq!(boot.acquisition_attempts(), 1);
        assert!(error.parser_usage().is_none());
        assert_eq!(context.run_usage(), RunUsage::default());
        assert_eq!(context.usage().members, 0);
        assert_eq!(context.usage().packed_bytes, 0);
    }
}

#[test]
fn r1_member_failures_are_not_relabelled_as_prebinding_failures() {
    for bound in [false, true] {
        let mut m = Member::stored(b"entry", b"one");
        m.crc = Some(0);
        let (_file, mut session) = opened(&[m]);
        let cancel = Cancellation::default();
        let mut context = if bound {
            EncryptedReadContext::for_projected(
                &mut session,
                ProjectedReadScope::Entry(0),
                Some(64),
                ZipReadOutput::Callback,
                None,
                &Default::default(),
                &cancel,
            )
            .unwrap()
        } else {
            EncryptedReadContext::new(Default::default()).unwrap()
        };
        let mut delivered = 0;
        let error = session
            .read_at_with_context(0, None, 64, &cancel, &mut context, |b| {
                delivered += b.len();
                Ok(())
            })
            .unwrap_err();
        assert_eq!(delivered, 3);
        assert!(matches!(error.operation(), Some(ReadFault::Integrity { reason: IntegrityReason::Checksum, .. })));
        assert!(error.bootstrap_usage().is_none());
        assert!(error.parser_usage().is_none());
        assert_eq!(context.bootstrap_usage().metadata(), 6);
        assert_eq!(context.run_usage().records, 1);
    }
}
#[test]
fn r1_cancel_origin_belongs_only_to_unbound_prebinding() {
    for bound in [false, true] {
        let (_file, mut session) = opened(&[Member::stored(b"entry", b"one")]);
        let cancel = Cancellation::default();
        let mut context = if bound {
            EncryptedReadContext::for_projected(
                &mut session,
                ProjectedReadScope::Entry(0),
                Some(64),
                ZipReadOutput::Callback,
                None,
                &Default::default(),
                &cancel,
            )
            .unwrap()
        } else {
            EncryptedReadContext::new(Default::default()).unwrap()
        };
        cancel.cancel();
        let error = session
            .read_at_with_context(0, None, 64, &cancel, &mut context, |_| panic!("no cancelled payload"))
            .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::Cancelled)));
        if bound {
            assert!(error.bootstrap_usage().is_none());
        } else {
            let boot = error.bootstrap_usage().unwrap();
            assert_eq!(boot.phase(), BootstrapPhase::ActionPlan);
            assert_eq!((boot.metadata(), boot.attempts(), boot.acquisition_attempts()), (0, 0, 1));
        }
        assert_eq!(context.run_usage(), RunUsage::default());
    }
}
#[test]
fn r1_existing_legacy_origin_survives_unbound_generic_read() {
    let bytes = build(&[Member::stored(b"entry", b"one")], &[0], b"", b"", false).bytes;
    let mut file = tempfile::Builder::new().prefix(".zipfast-r1-origin-").tempfile_in(".").unwrap();
    file.write_all(&bytes).unwrap();
    let path = Path::new(file.path().file_name().unwrap());
    LEGACY_CWD_FAULT.with(|s| s.set(Some(libc::ENOENT)));
    let mut selected = crate::extract::SelectedEntry::open(path, 0, None, 64).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let error =
        selected.read_with_zip_context(None, &mut context, |_| panic!("unproved source cannot deliver")).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Io { stage: IoStage::SourcePath, .. })));
    assert!(!error.is_source_changed());
    assert_eq!(error.bootstrap_usage().unwrap().phase(), BootstrapPhase::LegacySourceProof);
    assert_eq!(context.bootstrap_usage().metadata(), 0);
    assert_eq!(context.run_usage(), RunUsage::default());
}
#[test]
fn r1_parse_failure_snapshot_survives_and_preparse_snapshot_is_not_invented() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), [0u8; 100]).unwrap();
    let cancel = Cancellation::default();
    let error = ProjectedReadSession::open(file.path(), &cancel).err().unwrap();
    let usage = error.parser_usage().unwrap();
    assert_eq!(usage.fetched_bytes, 100);
    assert_eq!(error.bootstrap_usage().unwrap().bytes(), 100);
    assert_eq!(error.bootstrap_usage().unwrap().metadata(), 6);
    assert_eq!(error.bootstrap_usage().unwrap().source_retirement(), Some(CloseDisposition::Closed));
    inject_bootstrap(Some(IoStage::SourceHandle), ReadIoOperation::Stat, 1, libc::EIO, true);
    let result = ProjectedReadSession::open(file.path(), &cancel);
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    let error = result.err().unwrap();
    assert!(error.parser_usage().is_none());
    assert!(error.is_source_changed());
    assert_eq!(error.bootstrap_usage().unwrap().metadata(), 1);
    assert_eq!(error.bootstrap_usage().unwrap().source_retirement(), Some(CloseDisposition::Closed));
}
#[test]
fn r1_prebinding_factory_fault_keeps_final_source_admission_and_latest_snapshot() {
    let plain = vec![0; 65537];
    let frame = super::cipher::framed(1, "pw", &plain);
    let aes = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut member = Member::stored(b"entry", &frame);
    member.flags = 1;
    member.method = 99;
    member.decoded = Some(&plain);
    member.central_extra = &aes;
    let (_file, mut session) = opened(&[member]);
    let mut context =
        EncryptedReadContext::new(EncryptedReadOptions::default().with_temp_dir("p".repeat(5000).into())).unwrap();
    OPEN_HOOK.with(|s| {
        *s.borrow_mut() = Some(Box::new(move |event| {
            if event == 8 {
                inject_bootstrap(Some(IoStage::SourceHandle), ReadIoOperation::Stat, 17, libc::EINTR, true);
            }
        }))
    });
    let result = session.read_at_with_context(0, Some("pw"), 1 << 20, &Cancellation::default(), &mut context, |_| {
        panic!("no prebinding output")
    });
    REFUSE_ALLOCATIONS.with(|s| s.set(false));
    OPEN_HOOK.with(|s| *s.borrow_mut() = None);
    let error = result.unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert!(!error.is_source_changed());
    let fault = error.cleanup_errors().next().unwrap();
    assert_eq!(fault.operation, ReadIoOperation::Stat);
    assert_eq!(fault.close, CloseDisposition::NotApplicable);
    assert!(matches!(
        &fault.cause,
        CleanupCause::Admission(ReadFault::Limit { resource: ReadResource::InterruptedRetries, .. })
    ));
    let boot = error.bootstrap_usage().unwrap();
    assert_eq!(boot, context.bootstrap_usage());
    assert_eq!(boot.phase(), BootstrapPhase::ActionPlan);
    assert_eq!((boot.metadata(), boot.attempts(), boot.acquisition_attempts()), (4, 21, 2));
    assert_eq!(context.usage().members, 0);
    assert_eq!(context.run_usage(), RunUsage::default());
}
