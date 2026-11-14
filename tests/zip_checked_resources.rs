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

//! Finite public entrypoint qualification; fixture generation is outside reads.
#![cfg(any(target_os = "macos", target_os = "linux"))]
#[allow(dead_code)] // Shared large-fixture helpers are used by zip_checked_large.
#[path = "common/zip_checked.rs"]
mod checked;
use std::io::{Cursor, Read};
use std::os::fd::AsFd;
use zipfast::extract::{Cancellation, SelectedEntry};
use zipfast::zip::write::{AesStrength, AesVariant, DeflateLevel, Method};
use zipfast::zip::*;

// Independent public paths use separate frames: the old omnibus debug frame was
// 280768 bytes and could push nested checked-run calls beyond Linux's default test stack.
fn qualify(path: &std::path::Path, data: &[u8], password: &str) {
    let mut digest = checked::Digest::default();
    digest.update(data);
    let expected = digest.finish();
    let output = tempfile::tempdir().unwrap();
    let opts = checked::options(output.path(), true);
    qualify_projected(path, data, password, &expected, &opts);
    qualify_retained(path, data, password, &expected, &opts);
    qualify_selected(path, data, password, &expected, &opts);
    qualify_zip_policy(path, data, password, &expected, &opts);
    qualify_zip_context(path, data, password, &expected, &opts);
    qualify_generic_policy(path, data, password, &expected, &opts);
    qualify_generic_context(path, data, password, &expected, &opts);
    qualify_cli(path, data, password, &expected, &opts);
    qualify_stage(path, data, password, &expected, &opts);
}
fn qualify_projected(
    path: &std::path::Path,
    _data: &[u8],
    password: &str,
    expected: &(u64, [u8; 32]),
    _opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let max = 1 << 20;
    let mut projected = ProjectedReadSession::open(path, &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut projected,
        ProjectedReadScope::Entry(0),
        Some(max),
        ZipReadOutput::Callback,
        Some(password),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let mut hash = checked::Digest::default();
    projected
        .read_at_with_context(0, Some(password), max, &cancel, &mut context, |b| {
            hash.update(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(&hash.finish(), expected);
    assert_eq!(context.usage().live_spool_bytes, 0);
    assert_eq!(context.usage().live_fds, 0);
    assert_eq!(context.run_usage().records, 1);
    projected.check_source(&mut context).unwrap();
}

fn qualify_retained(
    path: &std::path::Path,
    _data: &[u8],
    password: &str,
    expected: &(u64, [u8; 32]),
    _opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let max = 1 << 20;
    let mut retained = ReadSession::open(path).unwrap();
    let id = retained.metadata().entry_id(0).unwrap();
    let mut context = EncryptedReadContext::for_session(
        &mut retained,
        &id,
        Some(max),
        ZipReadOutput::Callback,
        Some(password),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let mut hash = checked::Digest::default();
    retained
        .select(&id, max, cancel.clone())
        .unwrap()
        .read_with_context(Some(password), &mut context, |b| {
            hash.update(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(&hash.finish(), expected);
    retained.check_source_checked(&mut context).unwrap();
}

fn qualify_selected(
    path: &std::path::Path,
    _data: &[u8],
    password: &str,
    expected: &(u64, [u8; 32]),
    _opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let max = 1 << 20;
    let mut selected = SelectedEntry::open_cancelable_with_zip_limit(path, 0, None, max, None, cancel.clone()).unwrap();
    let mut context =
        selected.zip_read_context(Some(password), ZipReadOutput::Callback, &Default::default()).unwrap().unwrap();
    let mut hash = checked::Digest::default();
    selected
        .read_with_zip_context(Some(password), &mut context, |b| {
            hash.update(b);
            Ok(())
        })
        .unwrap();
    assert_eq!(&hash.finish(), expected);
    selected.check_zip_source(&mut context).unwrap();
}

fn qualify_zip_policy(
    path: &std::path::Path,
    data: &[u8],
    password: &str,
    _expected: &(u64, [u8; 32]),
    opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let report = zipfast::zip::run_with_policy(
        path,
        opts,
        Some(password),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!((report.files(), report.failed(), report.decoded_bytes()), (1, 0, data.len() as u128));
    assert_eq!(std::fs::read(opts.dest.join("payload")).unwrap(), data);
}

fn qualify_zip_context(
    path: &std::path::Path,
    data: &[u8],
    password: &str,
    _expected: &(u64, [u8; 32]),
    opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let mut limits = EncryptedReadLimits::default();
    limits.password_bytes = password.len() as u64;
    let mut context = EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
    let report =
        zipfast::zip::run_with_context(path, opts, Some(password), &cancel, &mut context, |_: ZipRunEvent<'_>| Ok(()))
            .unwrap();
    assert_eq!(report.files(), 1);
    assert_eq!(std::fs::read(opts.dest.join("payload")).unwrap(), data);
}

fn qualify_generic_policy(
    path: &std::path::Path,
    _data: &[u8],
    password: &str,
    _expected: &(u64, [u8; 32]),
    opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let report = zipfast::extract::run_with_zip_policy(
        path,
        opts,
        Some(password),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.files(), 1);
}

fn qualify_generic_context(
    path: &std::path::Path,
    _data: &[u8],
    password: &str,
    _expected: &(u64, [u8; 32]),
    opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let mut limits = EncryptedReadLimits::default();
    limits.password_bytes = password.len() as u64;
    let mut context = EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
    let report = zipfast::extract::run_with_zip_context(
        path,
        opts,
        Some(password),
        &cancel,
        &mut context,
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.files(), 1);
}

fn qualify_cli(
    path: &std::path::Path,
    data: &[u8],
    password: &str,
    _expected: &(u64, [u8; 32]),
    _opts: &zipfast::extract::Options,
) {
    let cli_output = tempfile::tempdir().unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["x", "-y", "-mt1", "-q"])
        .arg(format!("-p{password}"))
        .arg(path)
        .arg(cli_output.path())
        .env_remove("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES")
        .env_remove("ZIPFAST_ZIP_TEMP_BYTES")
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(std::fs::read(cli_output.path().join("payload")).unwrap(), data);
}

#[allow(clippy::result_large_err)] // Final-source closure retains the mandatory 5360-byte inline error.
fn qualify_stage(
    path: &std::path::Path,
    data: &[u8],
    password: &str,
    _expected: &(u64, [u8; 32]),
    _opts: &zipfast::extract::Options,
) {
    let cancel = Cancellation::default();
    let max = 1 << 20;
    let mut owner = ProjectedReadSession::open(path, &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut owner,
        ProjectedReadScope::Entry(0),
        Some(max),
        ZipReadOutput::VerifiedStdout,
        Some(password),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let mut output = tempfile::tempfile().unwrap();
    owner.admit_output_fd(output.as_fd(), &mut context).unwrap();
    let mut stage = ZipReadStage::prepare_stdout(owner.stage_entry(0).unwrap(), &cancel, &mut context).unwrap();
    owner.read_at_with_context(0, Some(password), max, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
    assert_eq!(
        stage.copy_verified(&mut output, &cancel, &mut context, |c| owner.check_source(c)).unwrap(),
        data.len() as u64
    );
    use std::io::{Seek, SeekFrom};
    output.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, data);
    assert_eq!(context.usage().live_spool_bytes, 0);
    assert_eq!(context.usage().live_fds, 1); // Action retains its resolved private directory until context teardown.
}

#[test]
fn every_aes_strength_variant_and_native_writer_method_streams_actual_public_bytes() {
    let dir = tempfile::tempdir().unwrap();
    for strength in [AesStrength::Aes128, AesStrength::Aes192, AesStrength::Aes256] {
        for variant in [AesVariant::Ae1, AesVariant::Ae2] {
            for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
                for data in [b"".as_slice(), b"public complete bytes".as_slice()] {
                    let path = dir.path().join("fixture.zip");
                    checked::aes_file(
                        &path,
                        &mut Cursor::new(data),
                        data.len() as u64,
                        "password",
                        strength,
                        variant,
                        method,
                    );
                    qualify(&path, data, "password");
                }
            }
        }
    }
}

#[test]
fn ciphertext_threshold_neighbors_use_bounded_memory_and_explicit_disk_retirement() {
    let dir = tempfile::tempdir().unwrap();
    for size in [0, 1, 65535, 65536, 65537, 131073] {
        let data = vec![0x91; size];
        let path = dir.path().join("fixture.zip");
        checked::aes_file(
            &path,
            &mut Cursor::new(&data),
            size as u64,
            "pw",
            AesStrength::Aes256,
            AesVariant::Ae2,
            Method::Stored,
        );
        for threshold in [0, 65535, 65536, 65537] {
            let mut limits = EncryptedReadLimits::default();
            limits.ciphertext_memory_bytes = threshold;
            limits.reader_capacity = threshold + 3 * (64 << 10);
            let mut context = EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
            let cancel = Cancellation::default();
            let mut session = ProjectedReadSession::open(&path, &cancel).unwrap();
            let mut out = Vec::new();
            session
                .read_at_with_context(0, Some("pw"), 1 << 20, &cancel, &mut context, |b| {
                    out.extend_from_slice(b);
                    Ok(())
                })
                .unwrap();
            assert_eq!(out, data);
            assert_eq!(context.usage().live_spool_bytes, 0);
            assert_eq!(context.usage().live_fds, 0);
            assert!(context.usage().reader_capacity <= threshold + 3 * (64 << 10));
        }
    }
}

#[test]
fn public_long_passwords_are_policy_derived_and_explicit_lower_caps_remain_distinct() {
    let dir = tempfile::tempdir().unwrap();
    for size in [65535, 65536, 100000] {
        let password = "p".repeat(size);
        let path = dir.path().join("fixture.zip");
        let fixture: &[u8] = match size {
            65535 => include_bytes!("fixtures/zip-checked-password-65535.zip"),
            65536 => include_bytes!("fixtures/zip-checked-password-65536.zip"),
            100000 => include_bytes!("fixtures/zip-checked-password-100000.zip"),
            _ => unreachable!(),
        };
        checked::save_bytes(&path, fixture);
        let mut old = Archive::open(&path).unwrap();
        let mut bytes = Vec::new();
        old.read_at(0, Some(&password), 1 << 20, |b| {
            bytes.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(bytes, b"long password actual plaintext");
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(&path, &cancel).unwrap();
        let mut default = EncryptedReadContext::new(Default::default()).unwrap();
        let result = session.read_at_with_context(0, Some(&password), 1 << 20, &cancel, &mut default, |_| Ok(()));
        if size > 65535 {
            assert!(matches!(
                result.unwrap_err().operation(),
                Some(ReadFault::Limit { resource: ReadResource::PasswordBytes, .. })
            ));
        } else {
            result.unwrap();
        }
        qualify(&path, b"long password actual plaintext", &password);
        let mut overrides = EncryptedReadOverrides::default();
        overrides.password_bytes = Some(size as u64 - 1);
        let mut session = ProjectedReadSession::open(&path, &cancel).unwrap();
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::Callback,
            Some(&password),
            &overrides,
            &cancel,
        )
        .unwrap();
        let error = session
            .read_at_with_context(0, Some(&password), 1 << 20, &cancel, &mut context, |_| panic!("cap before callback"))
            .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::PasswordBytes, .. })));
    }
}

#[test]
fn bad_aes_credentials_and_authentication_never_deliver_callback_or_publish() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.zip");
    checked::aes_file(
        &path,
        &mut Cursor::new(b"secret"),
        6,
        "pw",
        AesStrength::Aes128,
        AesVariant::Ae2,
        Method::Stored,
    );
    for password in [None, Some(""), Some("wrong")] {
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(&path, &cancel).unwrap();
        let mut context = EncryptedReadContext::new(Default::default()).unwrap();
        let mut calls = 0;
        assert!(
            session
                .read_at_with_context(0, password, 64, &cancel, &mut context, |_| {
                    calls += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(calls, 0);
        let output = dir.path().join("out");
        std::fs::create_dir_all(&output).unwrap();
        checked::save_bytes(&output.join("payload"), b"preserved");
        let report = zipfast::zip::run_with_policy(
            &path,
            &checked::options(&output, true),
            password,
            &cancel,
            &Default::default(),
            |_: ZipRunEvent<'_>| Ok(()),
        )
        .unwrap();
        assert_eq!(report.failed(), 1);
        assert_eq!(std::fs::read(output.join("payload")).unwrap(), b"preserved");
    }
}

// Observe successful Rust allocations issued during the checked read. Metadata,
// fixture generation, context construction, C-library malloc and caller storage
// stay outside this scope. Fixed slots avoid recursively allocating in alloc().
#[derive(Clone, Copy)]
struct AllocationMeter {
    enabled: bool,
    requested: u64,
    attempts: u64,
    live: usize,
    peak: usize,
    overflow: bool,
    slots: [(usize, usize); 128],
}
impl AllocationMeter {
    const fn empty() -> Self {
        Self { enabled: false, requested: 0, attempts: 0, live: 0, peak: 0, overflow: false, slots: [(0, 0); 128] }
    }
    fn release(&mut self, pointer: usize) {
        if let Some(slot) = self.slots.iter_mut().find(|s| s.0 == pointer && pointer != 0) {
            self.live -= slot.1;
            *slot = (0, 0);
        }
    }
    fn acquire(&mut self, pointer: usize, size: usize) {
        self.attempts += 1;
        self.requested = self.requested.checked_add(size as u64).unwrap();
        if pointer == 0 {
            return;
        }
        if let Some(slot) = self.slots.iter_mut().find(|s| s.0 == 0) {
            *slot = (pointer, size);
            self.live = self.live.checked_add(size).unwrap();
            self.peak = self.peak.max(self.live);
        } else {
            self.overflow = true;
        }
    }
}
thread_local! { static ALLOCATIONS: std::cell::RefCell<AllocationMeter> = const { std::cell::RefCell::new(AllocationMeter::empty()) }; }
struct ObservedAllocator;
#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;
fn meter_update(update: impl FnOnce(&mut AllocationMeter)) {
    let _ = ALLOCATIONS.try_with(|s| {
        if let Ok(mut meter) = s.try_borrow_mut()
            && meter.enabled
        {
            update(&mut meter);
        }
    });
}
// SAFETY: allocations and frees retain System's original pointer/layout. The
// thread-local observer never allocates and never changes allocator outcomes.
unsafe impl std::alloc::GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let pointer = unsafe { std::alloc::System.alloc(layout) };
        meter_update(|m| m.acquire(pointer as usize, layout.size()));
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let pointer = unsafe { std::alloc::System.alloc_zeroed(layout) };
        meter_update(|m| m.acquire(pointer as usize, layout.size()));
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        let result = unsafe { std::alloc::System.realloc(pointer, layout, size) };
        meter_update(|m| {
            if !result.is_null() {
                m.release(pointer as usize);
            }
            m.acquire(result as usize, size);
        });
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        meter_update(|m| m.release(pointer as usize));
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }
}
struct MeterScope;
impl MeterScope {
    fn start() -> Self {
        ALLOCATIONS.with(|s| {
            let mut m = AllocationMeter::empty();
            m.enabled = true;
            *s.borrow_mut() = m;
        });
        Self
    }
    fn finish(self) -> AllocationMeter {
        let meter = ALLOCATIONS.with(|s| {
            s.borrow_mut().enabled = false;
            *s.borrow()
        });
        drop(self);
        meter
    }
}
impl Drop for MeterScope {
    fn drop(&mut self) {
        let _ = ALLOCATIONS.try_with(|s| s.borrow_mut().enabled = false);
    }
}

#[test]
#[ignore = "root-scheduled actual-public API resource trials; no concurrent builds"]
fn public_small_api_adjacent_threshold_resources() {
    let receipt = std::env::var_os("ZIPFAST_TASK6_RESOURCE_SLOT").expect("root scheduling receipt required");
    assert!(std::path::Path::new(&receipt).is_file());
    let dir = tempfile::tempdir().unwrap();
    for size in [1, 65535, 65536, 65537, 1 << 20] {
        let path = dir.path().join("fixture.zip");
        checked::aes_file(
            &path,
            &mut std::io::repeat(0).take(size),
            size,
            "password",
            AesStrength::Aes256,
            AesVariant::Ae2,
            Method::Stored,
        );
        let expected = checked::repeated_digest(0, size);
        for threshold in [65535, 65536, 65537] {
            for repetition in 0..3 {
                // Warm identical bytes before each read; setup/hash/checks outside measurement.
                let _ = std::fs::read(&path).unwrap();
                let cancel = Cancellation::default();
                let mut session = ProjectedReadSession::open(&path, &cancel).unwrap();
                let mut limits = EncryptedReadLimits::default();
                limits.ciphertext_memory_bytes = threshold;
                limits.reader_capacity = threshold + 3 * (64 << 10);
                let mut context =
                    EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
                let mut digest = checked::Digest::default();
                let mut first = None;
                let meter = MeterScope::start();
                let start = std::time::Instant::now();
                session
                    .read_at_with_context(0, Some("password"), u64::MAX, &cancel, &mut context, |b| {
                        if first.is_none() {
                            first = Some(start.elapsed());
                        }
                        digest.update(b);
                        Ok(())
                    })
                    .unwrap();
                let elapsed = start.elapsed();
                let usage = context.usage();
                let run = context.run_usage();
                let teardown = std::time::Instant::now();
                drop(context);
                let teardown = teardown.elapsed();
                let meter = meter.finish();
                assert!(!meter.overflow);
                assert_eq!(meter.live, 0);
                assert_eq!(digest.finish(), expected);
                assert_eq!(usage.live_spool_bytes, 0);
                assert_eq!(usage.live_fds, 0);
                println!(
                    "TASK6_API size={size} threshold={threshold} repetition={repetition} elapsed_ns={} authenticated_first_callback_ns={} rust_requested={} rust_peak_live={} rust_allocations={} action_teardown_ns={} usage={usage:?} run={run:?}",
                    elapsed.as_nanos(),
                    first.unwrap().as_nanos(),
                    meter.requested,
                    meter.peak,
                    meter.attempts,
                    teardown.as_nanos()
                );
            }
        }
    }
}

#[test]
#[allow(clippy::result_large_err)] // Final-source closure preserves the mandated 5360-byte inline error without boxing.
fn verified_stage_source_change_prevents_acceptance_and_preserves_original_destination() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.zip");
    checked::aes_file(
        &path,
        &mut Cursor::new(b"verified"),
        8,
        "pw",
        AesStrength::Aes256,
        AesVariant::Ae2,
        Method::Stored,
    );
    let cancel = Cancellation::default();
    let mut owner = ProjectedReadSession::open(&path, &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut owner,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        Some("pw"),
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let output = dir.path().join("destination");
    checked::save_bytes(&output, b"preserved");
    let mut out = std::fs::OpenOptions::new().read(true).write(true).open(&output).unwrap();
    owner.admit_output_fd(out.as_fd(), &mut context).unwrap();
    let mut stage = ZipReadStage::prepare_stdout(owner.stage_entry(0).unwrap(), &cancel, &mut context).unwrap();
    owner
        .read_at_with_context(0, Some("pw"), u64::MAX, &cancel, &mut context, |b| stage.write_all(b, &cancel))
        .unwrap();
    let input = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    input.set_len(input.metadata().unwrap().len() + 1).unwrap();
    let error = stage.copy_verified(&mut out, &cancel, &mut context, |c| owner.check_source(c)).unwrap_err();
    assert!(error.source_change().is_some());
    assert_eq!(error.accepted_output_bytes(), 0);
    assert_eq!(std::fs::read(output).unwrap(), b"preserved");
}

#[test]
fn damaged_native_aes_tag_prevents_callbacks_and_existing_file_publication() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture.zip");
    checked::aes_file(
        &path,
        &mut Cursor::new(b"authenticated"),
        13,
        "pw",
        AesStrength::Aes256,
        AesVariant::Ae2,
        Method::Stored,
    );
    let entry = Archive::open(&path).unwrap().entries.remove(0);
    let mut archive = std::fs::read(&path).unwrap();
    let at = entry.local_at as usize;
    let name = u16::from_le_bytes(archive[at + 26..at + 28].try_into().unwrap()) as usize;
    let extra = u16::from_le_bytes(archive[at + 28..at + 30].try_into().unwrap()) as usize;
    archive[at + 30 + name + extra + entry.packed as usize - 1] ^= 1;
    checked::save_bytes(&path, &archive);
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(&path, &cancel).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    let error = session
        .read_at_with_context(0, Some("pw"), 64, &cancel, &mut context, |_| panic!("no unauthenticated bytes"))
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
    let output = dir.path().join("out");
    std::fs::create_dir(&output).unwrap();
    checked::save_bytes(&output.join("payload"), b"preserved");
    let report = zipfast::zip::run_with_policy(
        &path,
        &checked::options(&output, true),
        Some("pw"),
        &cancel,
        &Default::default(),
        |_: ZipRunEvent<'_>| Ok(()),
    )
    .unwrap();
    assert_eq!(report.failed(), 1);
    assert_eq!(std::fs::read(output.join("payload")).unwrap(), b"preserved");
}
