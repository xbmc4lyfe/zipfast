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

use super::split_verify::{self, Error, HeldVolumes, Layout, Problem, Scratch};
use super::*;
use crate::zip::write::split::{EntryWritten, Location, Options, VolumeProvider, ZipSplitWriter};
use crate::zip::write::{DeflateLevel, DosDateTime, InputLength, Permissions, WriterOptions};
use std::io::{self, Cursor};
use std::os::unix::fs::{FileExt, PermissionsExt};

struct AllocationControl;
thread_local! { static REFUSE_ALLOCATIONS: Cell<bool> = const { Cell::new(false) }; }
#[global_allocator]
static TEST_ALLOCATOR: AllocationControl = AllocationControl;
// SAFETY: permitted calls delegate with the original layout/pointer to System;
// refused requests return null as required by GlobalAlloc. Deallocation is
// always delegated. Refusal is local to the invoking test thread.
unsafe impl std::alloc::GlobalAlloc for AllocationControl {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if REFUSE_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::GlobalAlloc::alloc(&std::alloc::System, layout) }
        }
    }
    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        if REFUSE_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::GlobalAlloc::alloc_zeroed(&std::alloc::System, layout) }
        }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: std::alloc::Layout, size: usize) -> *mut u8 {
        if REFUSE_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
            std::ptr::null_mut()
        } else {
            unsafe { std::alloc::GlobalAlloc::realloc(&std::alloc::System, pointer, layout, size) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::GlobalAlloc::dealloc(&std::alloc::System, pointer, layout) }
    }
}
pub(super) fn set_allocations_refused(value: bool) {
    REFUSE_ALLOCATIONS.set(value);
}

fn refusing_allocations<T>(run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            REFUSE_ALLOCATIONS.set(false)
        }
    }
    REFUSE_ALLOCATIONS.set(true);
    let _reset = Reset;
    run()
}

struct Fixture {
    _root: tempfile::TempDir,
    plan: CreatePlan,
    files: Vec<File>,
    stamps: Vec<Stamp>,
    receipts: Vec<EntryWritten>,
    layout: Layout,
}

impl HeldVolumes for Fixture {
    fn len(&self) -> usize {
        self.files.len()
    }
    fn get(&self, disk: usize) -> Option<(&File, Stamp)> {
        Some((self.files.get(disk)?, *self.stamps.get(disk)?))
    }
}

struct Provider<'a>(&'a mut Vec<File>);
impl VolumeProvider for Provider<'_> {
    type Sink = File;
    fn open(&mut self, disk: u32) -> io::Result<File> {
        assert_eq!(disk as usize, self.0.len());
        let file = tempfile::tempfile()?;
        let sink = file.try_clone()?;
        self.0.push(file);
        Ok(sink)
    }
}

fn entry(name: &[u8], method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Raw(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: Some(1234),
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"note",
    }
}

fn fixture(capacity: u64, comment: &[u8], members: &[(Method, &[u8])]) -> Fixture {
    let names: Vec<_> = (0..members.len()).map(|n| format!("m{n}")).collect();
    let records: Vec<_> = members
        .iter()
        .zip(&names)
        .map(|(&(method, bytes), name)| (entry(name.as_bytes(), method), Some(bytes)))
        .collect();
    fixture_options(capacity, comment, &records)
}

fn fixture_options(capacity: u64, comment: &[u8], records: &[(EntryOptions<'_>, Option<&[u8]>)]) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let mut plan = CreatePlan::new(&root.path().join("out.zip"), CreateOptions::default()).unwrap();
    plan.options.archive_comment = comment.to_vec();
    let mut files = Vec::new();
    let mut writer = ZipSplitWriter::new(
        Provider(&mut files),
        Options {
            volume_bytes: capacity,
            writer: WriterOptions { comment, ..WriterOptions::default() },
            ..Options::default()
        },
    )
    .unwrap();
    let mut receipts = Vec::new();
    for (ordinal, &(metadata, bytes)) in records.iter().enumerate() {
        if let Some(bytes) = bytes {
            let source = root.path().join(format!("input-{ordinal}"));
            std::fs::write(&source, bytes).unwrap();
            plan.add_file(&source, metadata, None).unwrap();
            receipts.push(
                writer.add_file(metadata, &mut Cursor::new(bytes), InputLength::Exact(bytes.len() as u64)).unwrap(),
            );
        } else {
            plan.add_directory(metadata, None).unwrap();
            receipts.push(writer.add_directory(metadata).unwrap());
        }
    }
    let finished = writer.finish().unwrap();
    let layout = Layout {
        volume_bytes: capacity,
        transport: finished.usage,
        writer: finished.writer,
        central_start: finished.central_start,
        zip64: finished.zip64,
    };
    let Provider(_) = finished.provider;
    let attempts = Attempts::new(&plan.options, &plan.attempts);
    let stamps = files.iter().map(|f| unix::file_stamp(f, &attempts).unwrap()).collect();
    Fixture { _root: root, plan, files, stamps, receipts, layout }
}

fn run(fixture: &Fixture) -> std::result::Result<VerificationUsage, Error> {
    let mut scratch = Scratch::new(fixture.plan.options.limits.verification_scratch).unwrap();
    let attempts = Attempts::new(&fixture.plan.options, &fixture.plan.attempts);
    let mut usage = VerificationUsage::default();
    split_verify::verify(
        fixture,
        (&fixture.plan.entries, &fixture.receipts),
        fixture.layout,
        &fixture.plan.options,
        &attempts,
        &mut scratch,
        &mut usage,
    )?;
    Ok(usage)
}

fn bless(fixture: &mut Fixture) {
    let attempts = Attempts::new(&fixture.plan.options, &fixture.plan.attempts);
    fixture.stamps = fixture.files.iter().map(|file| unix::file_stamp(file, &attempts).unwrap()).collect();
}

fn patch(fixture: &mut Fixture, at: Location, bytes: &[u8]) {
    fixture.files[at.disk as usize].write_all_at(bytes, at.offset).unwrap();
    bless(fixture);
}

#[test]
fn split_verifier_accepts_multidisk_payload_and_intact_rollovers() {
    let payload: Vec<_> = (0..801).map(|n| (n % 251) as u8).collect();
    for capacity in [108, 109, 127, 160, 256] {
        let f = fixture(
            capacity,
            b"archive",
            &[
                (Method::Stored, &payload),
                (Method::Deflate(DeflateLevel::new(6).unwrap()), &payload),
                (Method::Stored, b""),
            ],
        );
        assert!(f.files.len() >= 4);
        let usage = run(&f).unwrap();
        assert_eq!(usage.decoded_bytes, 1602);
        assert_eq!(usage.entries, 3);
        assert_eq!(usage.payloads, 3);
        assert_eq!(usage.record_capacity, 0);
        assert_eq!(usage.read_bytes, f.layout.transport.bytes);
        assert!(f.stamps.iter().take(f.stamps.len() - 1).any(|stamp| stamp.len < capacity));
    }
}

#[test]
fn split_verifier_accepts_classic_and_wide_end_only_final_disks() {
    for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
        let capacity = if method == Method::Stored { 80 } else { 120 };
        let f = fixture(capacity, &[b'x'; 22], &[(method, b"payload")]);
        assert!(f.layout.central_start.disk < f.files.len() as u32 - 1);
        run(&f).unwrap();
    }
    let f = fixture(26, b"", &[]);
    assert_eq!(f.layout.transport.bytes, 26);
    let mut bytes = [0; 26];
    f.files[0].read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(&bytes[..8], &[0x50, 0x4b, 7, 8, 0x50, 0x4b, 5, 6]);
    let mut expected = [0; 26];
    expected[..8].copy_from_slice(&[0x50, 0x4b, 7, 8, 0x50, 0x4b, 5, 6]);
    expected[20] = 4; // Empty directory starts after the spanning marker.
    assert_eq!(bytes, expected);
    run(&f).unwrap();
}

#[test]
fn split_verifier_rejects_plan_receipt_and_paired_header_forgery() {
    for field in [6, 8, 10, 12, 14, 26] {
        let mut f = fixture(256, b"", &[(Method::Stored, b"payload")]);
        let local = f.receipts[0].local;
        patch(&mut f, Location { offset: local.offset + field, ..local }, &[0xff]);
        assert!(run(&f).is_err(), "local field {field}");
    }
    let mut f = fixture(256, b"", &[(Method::Stored, b"payload")]);
    let local = f.receipts[0].local;
    let central = f.layout.central_start;
    patch(&mut f, Location { offset: local.offset + 30, ..local }, b"xx");
    patch(&mut f, Location { offset: central.offset + 46, ..central }, b"xx");
    assert!(matches!(run(&f), Err(Error::Invalid { at, kind: Problem::LocalHeader, member:Some(0) }) if at.disk == 0));
    for field in [0, 1, 2, 3] {
        let mut f = fixture(256, b"", &[(Method::Stored, b"payload")]);
        match field {
            0 => f.receipts[0].ordinal = 1,
            1 => f.receipts[0].decoded_size += 1,
            2 => f.receipts[0].local.offset += 1,
            _ => f.receipts[0].crc32 ^= 1,
        }
        assert!(run(&f).is_err());
    }
}

#[test]
fn split_verifier_rejects_payload_descriptor_end_and_physical_mutations() {
    for which in 0..7 {
        let mut f = fixture(128, b"comment", &[(Method::Stored, &[b'p'; 300])]);
        match which {
            0 => patch(&mut f, Location::default(), b"bad!"),
            1 => patch(&mut f, Location { disk: 0, offset: 45 }, b"X"),
            2 => {
                f.files[1].set_len(127).unwrap();
                bless(&mut f);
            }
            3 => {
                let last = f.files.len() - 1;
                f.files[last].write_all_at(b"X", f.stamps[last].len).unwrap();
                bless(&mut f);
            }
            4 => {
                f.files.swap(0, 1);
                bless(&mut f);
            }
            5 => {
                f.files.pop();
                f.stamps.pop();
            }
            _ => {
                let last = f.files.len() - 1;
                f.files[last].write_all_at(b"bad!", f.stamps[last].len - 22 - 7).unwrap();
                bless(&mut f);
            }
        }
        assert!(run(&f).is_err(), "mutation {which}");
    }
}

#[test]
fn split_verifier_rejects_changed_held_stamps_and_preserves_file_cursors() {
    let f = fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    use std::io::{Seek, SeekFrom};
    let mut observer = f.files[0].try_clone().unwrap();
    observer.seek(SeekFrom::Start(19)).unwrap();
    run(&f).unwrap();
    assert_eq!(observer.stream_position().unwrap(), 19);
    f.files[1].write_all_at(b"X", 0).unwrap();
    assert!(matches!(run(&f), Err(Error::Native(CreateError::StageChanged))));
}

#[test]
fn split_verifier_read_decode_work_and_attempt_limits_are_exact() {
    let make = || fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    let baseline = make();
    let before = baseline.plan.attempts.get();
    let usage = run(&baseline).unwrap();
    let attempts = baseline.plan.attempts.get() - before;
    for limit in 0..6 {
        for exact in [false, true] {
            let mut f = make();
            let less = u64::from(!exact);
            match limit {
                0 => f.plan.options.limits.verification_read_bytes = usage.read_bytes - less,
                1 => f.plan.options.limits.verification_entry_bytes = 300 - less,
                2 => f.plan.options.limits.verification_decoded_bytes = 300 - less,
                3 => f.plan.options.limits.verification_metadata = usage.metadata_bytes - less,
                4 => f.plan.options.limits.directory.work_units = usage.directory.work_units - less,
                _ => f.plan.options.limits.transaction_attempts = f.plan.attempts.get() + attempts - less,
            }
            let result = run(&f);
            assert_eq!(result.is_ok(), exact, "limit {limit}, exact {exact}");
            if !exact {
                let expected = [
                    CreateLimit::VerificationReadBytes,
                    CreateLimit::VerificationEntryBytes,
                    CreateLimit::VerificationDecodedBytes,
                    CreateLimit::VerificationMetadata,
                    CreateLimit::PlanWork,
                    CreateLimit::TransactionAttempts,
                ][limit];
                if limit == 4 {
                    assert!(matches!(
                        result,
                        Err(Error::Native(CreateError::Directory(zip_container::DirectoryError::Limit(
                            zip_container::LimitKind::WorkUnits
                        ))))
                    ));
                } else {
                    assert!(matches!(result,Err(Error::Native(CreateError::Limit(kind))) if kind==expected));
                }
            }
        }
    }
    let f = make();
    f.plan.options.cancel.cancel();
    let before = f.plan.attempts.get();
    assert!(matches!(run(&f), Err(Error::Native(CreateError::Canceled))));
    assert_eq!(f.plan.attempts.get(), before);
}

#[test]
fn split_verifier_checks_utf8_directory_binary_comments_and_all_central_fields() {
    let directory = EntryOptions { name: EntryName::Utf8("d/"), comment: b"\0dir", ..entry(b"", Method::Stored) };
    let file = EntryOptions { name: EntryName::Utf8("d/é"), comment: b"\0file", ..entry(b"", Method::Stored) };
    let raw = EntryOptions { comment: b"\0raw\xff", ..entry(b"raw\x82", Method::Stored) };
    let f =
        fixture_options(256, b"\0archive\xff", &[(directory, None), (file, Some(b"data")), (raw, Some(b"PK\x07\x08"))]);
    let usage = run(&f).unwrap();
    assert_eq!((usage.entries, usage.payloads, usage.decoded_bytes), (3, 2, 8));
    for field in [4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 30, 32, 34, 36, 38, 42, 46, 48, 52, 59] {
        let mut f = fixture(256, b"", &[(Method::Stored, b"payload")]);
        let at = f.layout.central_start;
        patch(&mut f, Location { offset: at.offset + field, ..at }, &[0xff]);
        assert!(run(&f).is_err(), "central field {field}");
    }
}

#[test]
fn split_verifier_checks_directory_component_and_scratch_budgets() {
    let make = || fixture(128, b"archive", &[(Method::Stored, &[b'p'; 300])]);
    let usage = run(&make()).unwrap();
    for which in 0..6 {
        for exact in [false, true] {
            let mut f = make();
            let less = u64::from(!exact);
            match which {
                0 => f.plan.options.limits.directory.fetched_bytes = usage.directory.fetched_bytes - less,
                1 => f.plan.options.limits.directory.directory_bytes = usage.directory.directory_bytes - less,
                2 => f.plan.options.limits.directory.name_bytes = usage.directory.owned.name_bytes as u64 - less,
                3 => f.plan.options.limits.directory.comment_bytes = usage.directory.owned.comment_bytes as u64 - less,
                4 => {
                    f.plan.options.limits.verification_records = size_of::<zip_container::CentralRecord>() as u64 - less
                }
                _ => f.plan.options.limits.directory.entries = 1 - less,
            }
            assert_eq!(run(&f).is_ok(), exact, "component {which},exact {exact}");
        }
    }
    assert!(Scratch::new(usage.scratch_capacity).is_ok());
    assert!(matches!(
        Scratch::new(usage.scratch_capacity - 1),
        Err(CreateError::Limit(CreateLimit::VerificationScratch))
    ));
    let mut f = make();
    f.plan.options.limits.directory.range_bytes = 1;
    run(&f).unwrap();
    f.plan.options.limits.directory.range_bytes = 0;
    assert!(matches!(
        run(&f),
        Err(Error::Native(CreateError::Directory(zip_container::DirectoryError::Limit(
            zip_container::LimitKind::RangeBytes
        ))))
    ));
}

#[test]
fn split_verifier_retries_short_reads_cancellation_and_post_read_stamps() {
    use std::rc::Rc;
    let make = || fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    let f = make();
    let before = f.plan.attempts.get();
    run(&f).unwrap();
    let normal = f.plan.attempts.get() - before;
    let f = make();
    let before = f.plan.attempts.get();
    let once = Rc::new(Cell::new(false));
    let seen = Rc::clone(&once);
    super::tests::with_hook(
        move |event, _| {
            if event == super::tests::Event::VerifyRead && !seen.replace(true) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            Ok(())
        },
        || run(&f),
    )
    .unwrap();
    assert!(once.get());
    assert_eq!(f.plan.attempts.get() - before, normal + 1);
    let f = make();
    let full = run(&f).unwrap();
    let short = super::tests::with_hook(
        |_, _| Ok(()),
        || {
            super::tests::cap_verification_reads(1);
            run(&f)
        },
    )
    .unwrap();
    assert_eq!(short.read_bytes, full.read_bytes);
    let f = make();
    let file = f.files[0].try_clone().unwrap();
    let once = Cell::new(false);
    let result = super::tests::with_hook(
        move |event, _| {
            if event == super::tests::Event::VerifyRead && !once.replace(true) {
                file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
            }
            Ok(())
        },
        || run(&f),
    );
    assert!(matches!(result, Err(Error::Native(CreateError::StageChanged))));
    let f = make();
    let cancel = f.plan.options.cancel.clone();
    let result = super::tests::with_hook(
        move |event, _| {
            if event == super::tests::Event::VerifyRead {
                cancel.cancel();
            }
            Ok(())
        },
        || run(&f),
    );
    assert!(matches!(result, Err(Error::Native(CreateError::Canceled))));
}

fn word(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend(value.to_le_bytes())
}
fn long(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend(value.to_le_bytes())
}
fn quad(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend(value.to_le_bytes())
}

// Independent wire fixtures. These do not use writer records, relocation or
// the verifier's layout helpers. All widths here are explicitly ZIP64.
fn wide_end(e: split_verify::EndExpectation) -> Vec<u8> {
    let mut b = Vec::new();
    long(&mut b, 0x06064b50);
    quad(&mut b, 44);
    word(&mut b, 0x032d);
    word(&mut b, 45);
    long(&mut b, e.at.disk);
    long(&mut b, e.central.disk);
    for v in [e.on_disk, e.entries, e.size, e.central.offset] {
        quad(&mut b, v)
    }
    long(&mut b, 0x07064b50);
    long(&mut b, e.at.disk);
    quad(&mut b, e.at.offset);
    long(&mut b, e.at.disk + 1);
    long(&mut b, 0x06054b50);
    for v in [u64::from(e.at.disk), u64::from(e.central.disk), e.on_disk, e.entries] {
        word(&mut b, v.min(65535) as u16)
    }
    long(&mut b, e.size.min(4294967295) as u32);
    long(&mut b, e.central.offset.min(4294967295) as u32);
    word(&mut b, 0);
    b
}

fn manual_deflate(packed: &[u8]) -> Fixture {
    let mut f = fixture(4096, b"", &[(Method::Deflate(DeflateLevel::new(6).unwrap()), b"AAAAAA")]);
    let crc = crc32fast::hash(b"AAAAAA");
    let mut b = vec![0x50, 0x4b, 7, 8];
    long(&mut b, 0x04034b50);
    for v in [45, 8, 8, 0, 0x21] {
        word(&mut b, v)
    }
    for v in [0, u32::MAX, u32::MAX] {
        long(&mut b, v)
    }
    word(&mut b, 2);
    word(&mut b, 29);
    b.extend(b"m0");
    word(&mut b, 1);
    word(&mut b, 16);
    quad(&mut b, 0);
    quad(&mut b, 0);
    word(&mut b, 0x5455);
    word(&mut b, 5);
    b.push(1);
    long(&mut b, 1234);
    b.extend(packed);
    long(&mut b, 0x08074b50);
    long(&mut b, crc);
    quad(&mut b, packed.len() as u64);
    quad(&mut b, 6);
    let central = b.len() as u64;
    long(&mut b, 0x02014b50);
    word(&mut b, 0x032d);
    for v in [45, 8, 8, 0, 0x21] {
        word(&mut b, v)
    }
    for v in [crc, u32::MAX, u32::MAX] {
        long(&mut b, v)
    }
    for v in [2, 29, 4, 0, 0] {
        word(&mut b, v)
    }
    long(&mut b, 0o100640 << 16);
    long(&mut b, 4);
    b.extend(b"m0");
    word(&mut b, 1);
    word(&mut b, 16);
    quad(&mut b, 6);
    quad(&mut b, packed.len() as u64);
    word(&mut b, 0x5455);
    word(&mut b, 5);
    b.push(1);
    long(&mut b, 1234);
    b.extend(b"note");
    let central_size = b.len() as u64 - central;
    let end = split_verify::EndExpectation {
        at: Location { disk: 0, offset: b.len() as u64 },
        central: Location { disk: 0, offset: central },
        entries: 1,
        on_disk: 1,
        size: central_size,
        wide: true,
    };
    b.extend(wide_end(end));
    f.files[0].set_len(0).unwrap();
    f.files[0].write_all_at(&b, 0).unwrap();
    f.layout.central_start = end.central;
    f.layout.transport.bytes = b.len() as u64;
    f.layout.writer.archive_extent = b.len() as u64;
    f.layout.writer.output_bytes = b.len() as u64;
    f.layout.writer.central_bytes = central_size;
    f.layout.writer.packed_bytes = packed.len() as u64;
    f.receipts[0].packed_size = packed.len() as u64;
    bless(&mut f);
    f
}

#[test]
fn split_verifier_requires_exact_raw_deflate_completion_and_actual_crc() {
    // Raw Deflate 73 74 04 01 00 decodes to six ASCII A bytes.
    let f = manual_deflate(&[0x73, 0x74, 4, 1, 0]);
    assert_eq!(run(&f).unwrap().decoded_bytes, 6);
    for (packed, want) in [
        (&[0x73, 0x74, 4, 1][..], Problem::CodecCompletion),
        (&[0x73, 0x74, 4, 1, 0, 0][..], Problem::PackedExtent),
        (&[0xff, 0xff, 0xff][..], Problem::CodecCompletion),
    ] {
        assert!(matches!(run(&manual_deflate(packed)),Err(Error::Invalid {kind,member:Some(0),..}) if kind==want));
    }
    let mut f = manual_deflate(&[0x73, 0x74, 4, 1, 0]);
    // Even paired descriptor/central CRC and receipt forgery cannot replace
    // computing the CRC of the actual decoded payload.
    f.receipts[0].crc32 ^= 1;
    let crc = f.receipts[0].crc32.to_le_bytes();
    let central = f.layout.central_start;
    patch(&mut f, Location { disk: 0, offset: 74 }, &crc);
    patch(&mut f, Location { offset: central.offset + 16, ..central }, &crc);
    assert!(matches!(run(&f), Err(Error::Invalid { kind: Problem::Checksum, .. })));
}

#[test]
fn split_verifier_checks_zip64_disk_offset_count_and_independent_classic_saturation() {
    for (disk, offset, count, size) in [
        (65534, 4294967294, 65534, 4294967294),
        (65535, 4294967295, 65535, 4294967295),
        (65536, 4294967296, 65536, 4294967296),
    ] {
        let e = split_verify::EndExpectation {
            at: Location { disk, offset: offset + 100 },
            central: Location { disk: disk - 1, offset },
            entries: count,
            on_disk: 7,
            size,
            wide: true,
        };
        let b = wide_end(e);
        split_verify::check_end(&b, e, 0).unwrap();
        for field in [0, 4, 12, 14, 16, 20, 24, 32, 40, 48, 56, 60, 64, 72, 76, 80, 82, 84, 86, 88, 92, 96] {
            let mut corrupt = b.clone();
            corrupt[field] ^= 1;
            assert!(split_verify::check_end(&corrupt, e, 0).is_err(), "field {field}");
        }
    }
}

#[test]
fn split_verifier_keeps_actual_accounting_on_read_error_and_checked_overflow() {
    let f = fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    let calls = Cell::new(0);
    let result = super::tests::with_hook(
        move |event, _| {
            if event == super::tests::Event::VerifyRead {
                calls.set(calls.get() + 1);
                if calls.get() == 3 {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
            }
            Ok(())
        },
        || {
            let mut scratch = Scratch::new(f.plan.options.limits.verification_scratch).unwrap();
            let attempts = Attempts::new(&f.plan.options, &f.plan.attempts);
            let mut usage = VerificationUsage::default();
            let error = split_verify::verify(
                &f,
                (&f.plan.entries, &f.receipts),
                f.layout,
                &f.plan.options,
                &attempts,
                &mut scratch,
                &mut usage,
            )
            .unwrap_err();
            (error, usage)
        },
    );
    assert!(matches!(result.0,Error::Native(CreateError::Io(error)) if error.kind()==io::ErrorKind::PermissionDenied));
    assert_eq!(result.1.read_bytes, 34); // Marker and fixed local header only.
    for which in 0..3 {
        let mut scratch = Scratch::new(f.plan.options.limits.verification_scratch).unwrap();
        let attempts = Attempts::new(&f.plan.options, &f.plan.attempts);
        let mut usage = VerificationUsage::default();
        match which {
            0 => usage.read_bytes = u64::MAX,
            1 => usage.directory.work_units = u64::MAX,
            _ => f.plan.attempts.set(u64::MAX),
        }
        assert!(matches!(
            split_verify::verify(
                &f,
                (&f.plan.entries, &f.receipts),
                f.layout,
                &f.plan.options,
                &attempts,
                &mut scratch,
                &mut usage
            ),
            Err(Error::Native(CreateError::Overflow))
        ));
    }
}

fn recount(f: &mut Fixture) {
    bless(f);
    let total = f.stamps.iter().map(|stamp| stamp.len).sum();
    f.layout.transport.bytes = total;
    f.layout.transport.disks = f.files.len() as u32;
    f.layout.writer.archive_extent = total;
    f.layout.writer.output_bytes = total;
}

#[test]
fn split_verifier_rejects_padding_early_rotation_and_changed_descriptor() {
    let mut f = fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    // The payload ends at disk2:89; its 16-byte descriptor leaves disk2:105.
    assert_eq!(f.stamps[2].len, 105);
    f.files[2].write_all_at(b"X", 105).unwrap();
    recount(&mut f);
    assert!(matches!(run(&f), Err(Error::Invalid { kind: Problem::Placement, .. })));
    let mut f = fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    patch(&mut f, Location { disk: 2, offset: 89 }, b"bad!");
    assert!(matches!(run(&f), Err(Error::Invalid { kind: Problem::Descriptor, .. })));
    let mut f = fixture(256, b"", &[(Method::Stored, b"payload")]);
    let central = f.layout.central_start.offset;
    let mut tail = vec![0; (f.stamps[0].len - central) as usize];
    f.files[0].read_exact_at(&mut tail, central).unwrap();
    f.files[0].set_len(central).unwrap();
    let next = tempfile::tempfile().unwrap();
    next.write_all_at(&tail, 0).unwrap();
    f.files.push(next);
    f.layout.central_start = Location { disk: 1, offset: 0 };
    recount(&mut f);
    assert!(matches!(run(&f), Err(Error::Invalid { kind: Problem::Placement, .. })));
}

#[test]
fn split_verifier_streams_maximum_names_and_comments_without_record_allocation() {
    let name = vec![b'a'; 65535];
    let comment = vec![0xff; 65535];
    let metadata = EntryOptions { comment: b"", extended_mtime: None, ..entry(&name, Method::Stored) };
    let f = fixture_options(70000, &comment, &[(metadata, Some(b"data"))]);
    let usage = run(&f).unwrap();
    assert_eq!(usage.record_capacity, 0);
    assert_eq!(usage.directory.owned.name_bytes, 65535);
    assert_eq!(usage.directory.owned.comment_bytes, 65535);
    assert_eq!(usage.read_bytes, f.layout.transport.bytes);
    assert!(f.layout.central_start.disk < f.files.len() as u32 - 1);
    assert!(usage.scratch_capacity < 132000);
}

#[test]
fn split_verifier_scratch_allocation_is_fallible_and_stored_verification_allocates_nothing() {
    assert!(matches!(refusing_allocations(|| Scratch::new(1 << 20)), Err(CreateError::Allocation(_))));
    let f = fixture(128, b"comment", &[(Method::Stored, &[b'p'; 300])]);
    let mut scratch = Scratch::new(f.plan.options.limits.verification_scratch).unwrap();
    let attempts = Attempts::new(&f.plan.options, &f.plan.attempts);
    let mut usage = VerificationUsage::default();
    let result = refusing_allocations(|| {
        split_verify::verify(
            &f,
            (&f.plan.entries, &f.receipts),
            f.layout,
            &f.plan.options,
            &attempts,
            &mut scratch,
            &mut usage,
        )
    });
    result.unwrap();
    assert_eq!(usage.decoded_bytes, 300);
    let mut f = fixture(128, b"", &[(Method::Stored, &[b'p'; 300])]);
    patch(&mut f, Location { disk: 0, offset: 45 }, b"X");
    let attempts = Attempts::new(&f.plan.options, &f.plan.attempts);
    let mut usage = VerificationUsage::default();
    let result = refusing_allocations(|| {
        split_verify::verify(
            &f,
            (&f.plan.entries, &f.receipts),
            f.layout,
            &f.plan.options,
            &attempts,
            &mut scratch,
            &mut usage,
        )
    });
    assert!(matches!(result, Err(Error::Invalid { kind: Problem::Checksum, .. })));
}

#[test]
fn split_verifier_handles_105_physical_volumes() {
    let payload: Vec<_> = (0..104 * 65536 + 31).map(|n| (n % 251) as u8).collect();
    let f = fixture(65536, b"", &[(Method::Stored, &payload)]);
    assert_eq!(f.files.len(), 105);
    assert_eq!(f.receipts[0].crc32, crc32fast::hash(&payload));
    let usage = run(&f).unwrap();
    assert_eq!(usage.decoded_bytes, 6815775);
    assert_eq!(usage.read_bytes, f.layout.transport.bytes);
    assert_eq!(usage.record_capacity, 0);
}

#[test]
fn split_verifier_large_volume_capacity_keeps_small_payload_progress() {
    // The local record ends at 4 + 30 + 2 + 9 = 45. At payload entry the
    // remaining capacity is exactly 2^32; narrowing it first becomes zero
    // on a 32-bit target even though seven physical payload bytes remain.
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let f = fixture((1_u64 << 32) + 45, b"", &[(Method::Stored, b"payload")]);
        assert_eq!(f.files.len(), 1);
        assert_eq!(f.stamps[0].len, 151);
        let before = f.plan.attempts.get();
        let usage = run(&f).unwrap();
        assert_eq!(usage.decoded_bytes, 7);
        assert_eq!(usage.read_bytes, 151);
        assert!(f.plan.attempts.get() > before);
        send.send(()).unwrap();
    });
    // A regressed 32-bit loop must fail this test rather than hang the suite.
    receive.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
    worker.join().unwrap();
}
