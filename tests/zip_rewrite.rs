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

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs::{self, File},
    io::{Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    path::Path,
    process::Command,
};

use zipfast::zip::rewrite::{
    Placement, Replacement, RewriteError, RewriteLimit, RewriteOptions, RewriteOutcome, RewritePlan, Verification,
};
use zipfast::zip::write::{
    DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions, WriterOptions,
    ZipStreamWriter, ZipWriter,
};

fn u16le(out: &mut Vec<u8>, val: u16) {
    out.extend(val.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, val: u32) {
    out.extend(val.to_le_bytes());
}

#[derive(Default)]
struct Fixture<'a> {
    prefix: &'a [u8],
    descriptor: &'a [u8],
    flags: u16,
    extra: &'a [u8],
    gap: &'a [u8],
    crc: u32,
    method: u16,
    name: Option<&'a [u8]>,
    comment: Option<&'a [u8]>,
    archive_comment: Option<&'a [u8]>,
    packed: &'a [u8],
    decoded_len: Option<u64>,
    wide_sizes: bool,
    wide_offset: bool,
    relative_offsets: bool,
}

fn archive(f: Fixture<'_>) -> Vec<u8> {
    let mut out = f.prefix.to_vec();
    let shift = if f.relative_offsets { f.prefix.len() as u32 } else { 0 };
    let local = out.len() as u32 - shift;
    let name = f.name.unwrap_or(b"x");
    let comment = f.comment.unwrap_or(&[0xff]);
    let end_comment = f.archive_comment.unwrap_or(&[0xfe, 0xff]);
    let packed = f.packed.len() as u64;
    let decoded = f.decoded_len.unwrap_or(packed);
    let version = if f.wide_sizes || f.wide_offset { 45 } else { 20 };
    let sizes = |placeholder: bool| {
        if f.wide_sizes {
            [u32::MAX; 2]
        } else if placeholder {
            [0; 2]
        } else {
            [packed as u32, decoded as u32]
        }
    };
    let extra = |local: bool, placeholder: bool| {
        let mut extra = f.extra.to_vec();
        let offset = f.wide_offset && !local;
        if f.wide_sizes || offset {
            u16le(&mut extra, 1);
            u16le(&mut extra, 16 * u16::from(f.wide_sizes) + 8 * u16::from(offset));
            if f.wide_sizes {
                extra.extend(if placeholder { 0 } else { decoded }.to_le_bytes());
                extra.extend(if placeholder { 0 } else { packed }.to_le_bytes());
            }
            if offset {
                extra.extend(u64::from(if f.relative_offsets { 0 } else { f.prefix.len() as u32 }).to_le_bytes());
            }
        }
        extra
    };

    u32le(&mut out, 0x0403_4b50);
    for val in [version, f.flags, f.method, 0, 0x21] {
        u16le(&mut out, val)
    }
    let descriptor = f.flags & 8 != 0;
    u32le(&mut out, if descriptor { 0 } else { f.crc });
    for val in sizes(descriptor) {
        u32le(&mut out, val)
    }
    let local_extra = extra(true, descriptor);
    u16le(&mut out, name.len() as u16);
    u16le(&mut out, local_extra.len() as u16);
    out.extend(name);
    out.extend(local_extra);
    out.extend(f.packed);
    out.extend(f.descriptor);
    out.extend(f.gap);

    let central = out.len() as u32;
    u32le(&mut out, 0x0201_4b50);
    for val in [20, version, f.flags, f.method, 0, 0x21] {
        u16le(&mut out, val)
    }
    u32le(&mut out, f.crc);
    for val in sizes(false) {
        u32le(&mut out, val)
    }
    let central_extra = extra(false, false);
    for val in [name.len() as u16, central_extra.len() as u16, comment.len() as u16, 0, 0] {
        u16le(&mut out, val);
    }
    u32le(&mut out, 0);
    u32le(&mut out, if f.wide_offset { u32::MAX } else { local });
    out.extend(name);
    out.extend(central_extra);
    out.extend(comment);
    let central_size = out.len() as u32 - central;
    end32(&mut out, 1, central_size, central - shift, end_comment);
    out
}

fn end32(out: &mut Vec<u8>, entries: u16, size: u32, offset: u32, comment: &[u8]) {
    u32le(out, 0x0605_4b50);
    for val in [0, 0, entries, entries] {
        u16le(out, val)
    }
    u32le(out, size);
    u32le(out, offset);
    u16le(out, comment.len() as u16);
    out.extend(comment);
}

fn opts() -> RewriteOptions {
    RewriteOptions::new(Replacement::LastWriterWins)
}

fn entry(name: EntryName<'_>, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name,
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"introduced",
    }
}

fn run(bytes: &[u8], options: RewriteOptions) -> Result<RewriteOutcome, RewriteError> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    fs::write(&path, bytes).unwrap();
    let result = RewritePlan::open(&path, options).and_then(|plan| plan.publish().map_err(|error| error.cause));
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    result
}

#[test]
fn write_receipts_follow_output_order_and_exclude_retained_entries() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let mut writer = ZipWriter::new(File::create(&path).unwrap(), WriterOptions::default()).unwrap();
    for name in ["removed", "retained", "replaced"] {
        writer
            .add_file(entry(EntryName::Utf8(name), Method::Stored), &mut b"old".as_slice(), InputLength::Exact(3))
            .unwrap();
    }
    writer.finish().unwrap();
    let data = [b'a'; 4096];
    let source = root.path().join("payload");
    fs::write(&source, data).unwrap();
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    let metadata = plan.metadata();
    let deflate = Method::Deflate(DeflateLevel::new(6).unwrap());
    plan.add_file(Placement::Append, &source, entry(EntryName::Utf8("appended"), Method::Stored), None).unwrap();
    plan.add_file(
        Placement::Replace(metadata.entry_id(2).unwrap()),
        &source,
        entry(EntryName::Utf8("replaced"), deflate),
        None,
    )
    .unwrap();
    plan.remove(&metadata.entry_id(0).unwrap()).unwrap();
    let report = plan.publish_with_receipts();
    assert!(matches!(report.outcome, Ok(RewriteOutcome::Replaced(_))));
    assert_eq!(report.written.iter().map(|receipt| receipt.ordinal).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(report.written[0].method, deflate);
    assert!(report.written[0].packed_size < 4096);
    assert_eq!(report.written[1].method, Method::Stored);
    assert_eq!(report.written[1].packed_size, 4096);

    let output = RewritePlan::open(&path, opts()).unwrap().metadata();
    assert_eq!(
        output.entries().map(|entry| entry.raw_name()).collect::<Vec<_>>(),
        [b"retained".as_slice(), b"replaced", b"appended"]
    );
    for (receipt, output) in report.written.iter().zip(output.entries().skip(1)) {
        assert_eq!(receipt.decoded_size, 4096);
        assert_eq!(receipt.crc32, crc32fast::hash(&data));
        assert_eq!(receipt.packed_size, output.packed_size());
        assert_eq!(receipt.local_offset, output.physical_local_header_offset());
    }
}

#[test]
fn no_op_and_deletion_only_rewrites_have_no_write_receipts() {
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let bytes = archive(Fixture::default());
    fs::write(&path, &bytes).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let report = RewritePlan::open(&path, opts()).unwrap().publish_with_receipts();
    let Ok(RewriteOutcome::Unchanged { usage, .. }) = report.outcome else { panic!("expected unchanged archive") };
    assert_eq!(usage.common.stage_attempts, 0);
    assert!(report.written.is_empty());
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    plan.remove(&plan.metadata().entry_id(0).unwrap()).unwrap();
    let report = plan.publish_with_receipts();
    assert!(matches!(report.outcome, Ok(RewriteOutcome::Replaced(_))));
    assert!(report.written.is_empty());
    assert_ne!(fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(RewritePlan::open(&path, opts()).unwrap().metadata().len(), 0);
}

#[test]
fn receipt_capacity_is_charged_before_staging_only_when_requested() {
    use zipfast::zip::create::{CreateError, CreateLimit};
    use zipfast::zip::rewrite::RewriteStage;
    use zipfast::zip::write::EntryWritten;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let bytes = archive(Fixture::default());
    let plan = |options| {
        fs::write(&path, &bytes).unwrap();
        let mut plan = RewritePlan::open(&path, options).unwrap();
        plan.add_directory(Placement::Append, entry(EntryName::Utf8("appended/"), Method::Stored), None).unwrap();
        plan
    };
    let RewriteOutcome::Replaced(baseline) = plan(opts()).publish().unwrap() else { panic!("expected replacement") };
    let mut options = opts();
    options.limits.common.plan_capacity = baseline.usage.common.plan.capacity;
    assert!(matches!(plan(options.clone()).publish(), Ok(RewriteOutcome::Replaced(_))));
    let report = plan(options.clone()).publish_with_receipts();
    let failure = report.outcome.unwrap_err();
    assert!(matches!(failure.cause, RewriteError::Infrastructure(CreateError::Limit(CreateLimit::PlanCapacity))));
    assert_eq!(failure.stage, RewriteStage::Planning);
    assert_eq!(failure.usage.common.stage_attempts, 0);
    assert!(report.written.is_empty());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);

    options.limits.common.plan_capacity += size_of::<EntryWritten>() as u64;
    let report = plan(options.clone()).publish_with_receipts();
    let Ok(RewriteOutcome::Replaced(output)) = report.outcome else { panic!("expected replacement") };
    assert_eq!(output.usage.common.plan.capacity, options.limits.common.plan_capacity);
    assert_eq!(report.written.len(), 1);
}

#[test]
fn descriptor_boundary_disambiguates_a_crc_equal_to_its_signature() {
    let mut descriptor = 0x0807_4b50_u32.to_le_bytes().to_vec();
    descriptor.extend([0; 8]);
    let bytes = archive(Fixture { flags: 8, descriptor: &descriptor, crc: 0x0807_4b50, ..Fixture::default() });
    assert!(matches!(
        run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
        Ok(RewriteOutcome::Unchanged { .. })
    ));
    descriptor.push(0);
    let bytes = archive(Fixture { flags: 8, descriptor: &descriptor, crc: 0x0807_4b50, ..Fixture::default() });
    assert!(matches!(
        run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
        Err(RewriteError::UnsupportedLayout(_))
    ));
}

#[test]
fn known_relocation_sensitive_extras_are_refused_but_unknown_repetitions_are_admitted() {
    for id in [0x000f_u16, 0x0016, 0x0017, 0xa11e, 0xd935] {
        let [low, high] = id.to_le_bytes();
        let bytes = archive(Fixture { extra: &[low, high, 0, 0], ..Fixture::default() });
        assert!(
            matches!(
                run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
                Err(RewriteError::UnsupportedLayout(_))
            ),
            "{id:04x}"
        );
    }
    let bytes = archive(Fixture { extra: &[0x0d, 0xf0, 0, 0, 0x0d, 0xf0, 1, 0, 0xff], ..Fixture::default() });
    assert!(matches!(
        run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
        Ok(RewriteOutcome::Unchanged { .. })
    ));
}

#[test]
fn interior_padding_is_refused_and_an_absolute_opaque_prefix_is_admitted() {
    let bytes = archive(Fixture { gap: b"interior gap", ..Fixture::default() });
    assert!(matches!(
        run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
        Err(RewriteError::UnsupportedLayout(_))
    ));
    let bytes = archive(Fixture { prefix: b"opaque\x00prefix", ..Fixture::default() });
    assert!(matches!(
        run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
        Ok(RewriteOutcome::Unchanged { .. })
    ));
}

#[test]
fn full_noop_checks_payload_even_when_the_layout_is_valid() {
    let bytes = archive(Fixture { crc: 1, ..Fixture::default() });
    assert!(matches!(
        run(&bytes, RewriteOptions::new(Replacement::LastWriterWins)),
        Ok(RewriteOutcome::Unchanged { .. })
    ));
    let options =
        RewriteOptions { verification: Verification::Full, ..RewriteOptions::new(Replacement::LastWriterWins) };
    assert!(run(&bytes, options).is_err());
}

#[test]
fn append_retains_local_and_central_wire_bytes_and_old_alias() {
    let bytes =
        archive(Fixture { prefix: b"stub", extra: &[0x0d, 0xf0, 1, 0, 0x02], method: 93, ..Fixture::default() });
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let alias = root.path().join("alias.zip");
    fs::write(&path, &bytes).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    let mut plan = RewritePlan::open(&path, RewriteOptions::new(Replacement::LastWriterWins)).unwrap();
    plan.add_directory(
        Placement::Append,
        EntryOptions {
            name: EntryName::Utf8("new/"),
            method: Method::Stored,
            modified: DosDateTime::default(),
            extended_mtime: None,
            permissions: Permissions::new(0o755).unwrap(),
            comment: &[],
        },
        None,
    )
    .unwrap();
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!("expected replacement") };
    assert_eq!(receipt.verification.new_verified, 1);
    assert_eq!(receipt.verification.retained_structural_only, 1);
    let actual = fs::read(&path).unwrap();
    assert_eq!(fs::read(alias).unwrap(), bytes);
    assert_eq!(&actual[..40], &bytes[..40]);
    let central = actual.windows(4).position(|b| b == [0x50, 0x4b, 1, 2]).unwrap();
    assert_eq!(&actual[central..central + 53], &bytes[40..93]);
    assert_eq!(&actual[actual.len() - 2..], &[0xfe, 0xff]);
}

#[test]
fn foreign_and_already_edited_ids_cannot_change_the_plan() {
    let bytes = archive(Fixture::default());
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    fs::write(&path, &bytes).unwrap();
    let mut plan = RewritePlan::open(&path, RewriteOptions::new(Replacement::LastWriterWins)).unwrap();
    let foreign = RewritePlan::open(&path, RewriteOptions::new(Replacement::LastWriterWins)).unwrap();
    assert!(matches!(plan.remove(&foreign.metadata().entry_id(0).unwrap()), Err(RewriteError::ForeignEntryId)));
    let selected = plan.metadata().entry_id(0).unwrap();
    plan.remove(&selected).unwrap();
    assert!(matches!(plan.remove(&selected), Err(RewriteError::DuplicateEdit)));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!("expected replacement") };
    assert!(receipt.verification.entries.is_empty());
    assert_eq!(
        fs::read(&path).unwrap(),
        b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\xfe\xff"
    );
}

#[test]
fn all_four_descriptor_framings_and_offset_only_zip64_follow_member_size_fields() {
    let payload = b"framed";
    for (wide, wide_offset) in [(false, false), (false, true), (true, false)] {
        for signed in [false, true] {
            let mut descriptor = Vec::new();
            if signed {
                u32le(&mut descriptor, 0x0807_4b50)
            }
            let crc = crc32fast::hash(payload);
            u32le(&mut descriptor, crc);
            for _ in 0..2 {
                if wide {
                    descriptor.extend((payload.len() as u64).to_le_bytes())
                } else {
                    u32le(&mut descriptor, payload.len() as u32)
                }
            }
            let bytes = archive(Fixture {
                flags: 8,
                descriptor: &descriptor,
                crc,
                packed: payload,
                wide_sizes: wide,
                wide_offset,
                ..Fixture::default()
            });
            let options = RewriteOptions { verification: Verification::Full, ..opts() };
            let RewriteOutcome::Unchanged { verification, .. } = run(&bytes, options).unwrap() else { panic!() };
            assert_eq!(verification.retained_payload_verified, 1);
            let descriptor = &descriptor[..descriptor.len() - 1];
            let bytes = archive(Fixture {
                flags: 8,
                descriptor,
                crc,
                packed: payload,
                wide_sizes: wide,
                wide_offset,
                ..Fixture::default()
            });
            assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
        }
    }
}

#[test]
fn opaque_encryption_and_unknown_codec_are_structural_only() {
    let aes = [1, 0x99, 7, 0, 2, 0, b'A', b'E', 1, 0, 0];
    for fixture in [
        Fixture { method: 93, ..Fixture::default() },
        Fixture { flags: 1, packed: &[0; 12], decoded_len: Some(0), ..Fixture::default() },
        Fixture { flags: 1, method: 99, packed: &[0; 20], decoded_len: Some(0), extra: &aes, ..Fixture::default() },
    ] {
        let bytes = archive(fixture);
        let RewriteOutcome::Unchanged { verification, .. } = run(&bytes, opts()).unwrap() else { panic!() };
        assert_eq!(verification.retained_structural_only, 1);
        let options = RewriteOptions { verification: Verification::Full, ..opts() };
        assert!(matches!(run(&bytes, options), Err(RewriteError::CannotFullyVerify { source_ordinal: 0 })));
    }
    let bytes = archive(Fixture { flags: 1, packed: &[0; 11], ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
}

#[test]
fn structurally_preserved_corrupt_stored_payload_remains_corrupt() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let corrupt = archive(Fixture { packed: b"bad", crc: 1, ..Fixture::default() });
    fs::write(&path, &corrupt).unwrap();
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("new/"), Method::Stored), None).unwrap();
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!() };
    assert_eq!(receipt.verification.retained_structural_only, 1);
    let staged = fs::read(&path).unwrap();
    assert_eq!(&staged[31..34], b"bad");
    let options = RewriteOptions { verification: Verification::Full, ..opts() };
    assert!(run(&staged, options).is_err());
}

#[test]
fn recognizable_archive_level_and_reserved_member_structures_are_refused() {
    for flags in [1 << 4, 1 << 5, 1 << 6, 1 << 13, 1 << 15] {
        let bytes = archive(Fixture { flags, ..Fixture::default() });
        assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
    }
    let archive_extra = b"PK\x06\x08\x00\x00\x00\x00";
    let bytes = archive(Fixture { prefix: archive_extra, ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
    let bytes = archive(Fixture { gap: archive_extra, ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));

    let clean = archive(Fixture::default());
    let mut signed = clean[..clean.len() - 24].to_vec();
    signed.extend(b"PK\x05\x05\x00\x00");
    end32(&mut signed, 1, 54, 31, &[0xfe, 0xff]);
    assert!(matches!(run(&signed, opts()), Err(RewriteError::UnsupportedLayout(_))));
    let mut split = clean;
    let end = split.len() - 24;
    split[end + 4] = 1;
    assert!(run(&split, opts()).is_err());
}

#[test]
fn malformed_extra_duplicate_zip64_and_inconsistent_local_metadata_are_rejected() {
    let short_extra = [0x0d, 0xf0, 5, 0, 1];
    let bytes = archive(Fixture { extra: &short_extra, ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
    let mut duplicate = [0; 20];
    duplicate[..4].copy_from_slice(&[1, 0, 16, 0]);
    let bytes = archive(Fixture { extra: &duplicate, wide_sizes: true, ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
    let mut different = archive(Fixture::default());
    different[30] = b'y';
    assert!(matches!(run(&different, opts()), Err(RewriteError::UnsupportedLayout(_))));
    let mut different = archive(Fixture::default());
    different[14] = 1;
    assert!(matches!(run(&different, opts()), Err(RewriteError::UnsupportedLayout(_))));
}

#[test]
fn earlier_eof_candidate_cannot_be_hidden_by_a_fake_end_in_an_opaque_prefixed_archive_comment() {
    let prefix = b"opaque stub";
    let mut fake = Vec::new();
    let offset = prefix.len() as u32 + 31 + 48 + 22;
    end32(&mut fake, 0, 0, offset, b"");
    let bytes = archive(Fixture { prefix, archive_comment: Some(&fake), ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::AmbiguousDirectory { .. })));
}

#[test]
fn source_and_layout_caps_fail_closed_with_no_stage() {
    let bytes = archive(Fixture { prefix: b"stub", ..Fixture::default() });
    for edit in [0, 1, 2, 3, 4] {
        let mut options = opts();
        match edit {
            0 => options.limits.source_scratch = 1,
            1 => options.limits.source_records = 1,
            2 => options.limits.source_metadata = 1,
            3 => options.limits.layout_read_bytes = 1,
            _ => options.limits.prefix_bytes = 3,
        }
        assert!(run(&bytes, options).is_err());
    }
    let mut options = opts();
    options.limits.prefix_bytes = 4;
    assert!(run(&bytes, options).is_ok());
}

#[test]
fn raw_and_retained_comparison_actual_bytes_have_independent_limits() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let bytes = archive(Fixture::default());
    for (limit, expected) in
        [(74, Some(RewriteLimit::RawCopyBytes)), (75, Some(RewriteLimit::RetainedComparisonBytes)), (77, None)]
    {
        fs::write(&path, &bytes).unwrap();
        let mut options = opts();
        options.limits.raw_copy_bytes = limit;
        let mut plan = RewritePlan::open(&path, options).unwrap();
        plan.add_directory(Placement::Append, entry(EntryName::Utf8("new/"), Method::Stored), None).unwrap();
        let result = plan.publish();
        if let Some(expected) = expected {
            let failure = result.unwrap_err();
            assert!(matches!(failure.cause, RewriteError::Limit(limit) if limit == expected));
            assert_eq!(failure.usage.common.stage_attempts, 0);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        } else {
            let RewriteOutcome::Replaced(receipt) = result.unwrap() else { panic!() };
            assert_eq!(receipt.usage.raw_copy_bytes, 75);
            assert_eq!(receipt.usage.retained_comparison_bytes, 77);
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[test]
fn relative_prefix_is_copied_and_output_offsets_are_physical() {
    let prefix = b"relative-prefix";
    let original = archive(Fixture { prefix, relative_offsets: true, ..Fixture::default() });
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    fs::write(&path, &original).unwrap();
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    assert_eq!(plan.metadata().prefix_shift(), prefix.len() as u64);
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("new/"), Method::Stored), None).unwrap();
    assert!(matches!(plan.publish().unwrap(), RewriteOutcome::Replaced(_)));
    let rewritten = fs::read(&path).unwrap();
    assert_eq!(&rewritten[..prefix.len() + 31], &original[..prefix.len() + 31]);
    let plan = RewritePlan::open(&path, opts()).unwrap();
    assert_eq!(plan.metadata().prefix_shift(), 0);
    assert_eq!(plan.metadata().entries().next().unwrap().stored_local_header_offset(), prefix.len() as u64);
}

fn descriptors() -> usize {
    let directory = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    fs::read_dir(directory).unwrap().count()
}

#[test]
fn thousands_of_old_duplicates_and_new_path_inputs_under_low_fd_limit() {
    const CHILD: &str = "ZIPFAST_REWRITE_TEST_LOW_FD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "thousands_of_old_duplicates_and_new_path_inputs_under_low_fd_limit", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    let mut rlimit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // Only this isolated test subprocess changes its soft limit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, rlimit.as_mut_ptr()) }, 0);
    let mut rlimit = unsafe { rlimit.assume_init() };
    rlimit.rlim_cur = rlimit.rlim_cur.min(24);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlimit) }, 0);

    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("archive.zip");
    let source = root.path().join("input");
    fs::write(&source, b"x").unwrap();
    let mut writer = ZipWriter::new(File::create(&archive).unwrap(), WriterOptions::default()).unwrap();
    for _ in 0..6000 {
        writer
            .add_file(entry(EntryName::Raw(b"duplicate"), Method::Stored), &mut [].as_slice(), InputLength::Exact(0))
            .unwrap();
    }
    drop(writer.finish().unwrap());

    let baseline = descriptors();
    let mut plan = RewritePlan::open(&archive, opts()).unwrap();
    for index in 0..6000 {
        let name = format!("nested/new-{index:05}");
        plan.add_file(Placement::Append, &source, entry(EntryName::Utf8(&name), Method::Stored), None).unwrap();
    }
    let admitted = descriptors();
    assert_eq!(admitted, baseline + 2);
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!() };
    let finished = descriptors();
    assert_eq!(finished, baseline);
    assert_eq!(receipt.verification.retained_structural_only, 6000);
    assert_eq!(receipt.verification.new_verified, 6000);
    assert_eq!(receipt.usage.common.plan.retained_handles, 0);
    assert_eq!(fs::read(&source).unwrap(), b"x");
    println!(
        "fd_limit={} baseline={baseline} admitted={admitted} finished={finished} usage={:?}",
        rlimit.rlim_cur, receipt.usage
    );
}

fn u64le(out: &mut Vec<u8>, value: u64) {
    out.extend(value.to_le_bytes())
}

fn local_record(name: &[u8], size: u64, crc: u32) -> Vec<u8> {
    let wide = size >= u64::from(u32::MAX);
    let mut bytes = Vec::new();
    u32le(&mut bytes, 0x0403_4b50);
    for field in [if wide { 45 } else { 20 }, 0, 0, 0, 0x21] {
        u16le(&mut bytes, field)
    }
    u32le(&mut bytes, crc);
    for _ in 0..2 {
        u32le(&mut bytes, if wide { u32::MAX } else { size as u32 })
    }
    u16le(&mut bytes, name.len() as u16);
    u16le(&mut bytes, if wide { 20 } else { 0 });
    bytes.extend(name);
    if wide {
        bytes.extend([1, 0, 16, 0]);
        u64le(&mut bytes, size);
        u64le(&mut bytes, size);
    }
    bytes
}

fn central_record(name: &[u8], size: u64, crc: u32, offset: u32, extra: &[u8], comment: &[u8]) -> Vec<u8> {
    let wide = size >= u64::from(u32::MAX);
    let mut bytes = Vec::new();
    u32le(&mut bytes, 0x0201_4b50);
    for field in [20, if wide { 45 } else { 20 }, 0, 0, 0, 0x21] {
        u16le(&mut bytes, field)
    }
    u32le(&mut bytes, crc);
    for _ in 0..2 {
        u32le(&mut bytes, if wide { u32::MAX } else { size as u32 })
    }
    for field in [name.len() as u16, extra.len() as u16 + if wide { 20 } else { 0 }, comment.len() as u16, 0, 0] {
        u16le(&mut bytes, field);
    }
    u32le(&mut bytes, 0);
    u32le(&mut bytes, offset);
    bytes.extend(name);
    bytes.extend(extra);
    if wide {
        bytes.extend([1, 0, 16, 0]);
        u64le(&mut bytes, size);
        u64le(&mut bytes, size);
    }
    bytes.extend(comment);
    bytes
}

fn end64(out: &mut Vec<u8>, entries: u64, size: u64, offset: u64, comment: &[u8]) {
    u32le(out, 0x0606_4b50);
    u64le(out, 44);
    u16le(out, 45);
    u16le(out, 45);
    u32le(out, 0);
    u32le(out, 0);
    for value in [entries, entries, size, offset] {
        u64le(out, value)
    }
    u32le(out, 0x0706_4b50);
    u32le(out, 0);
    u64le(out, offset + size);
    u32le(out, 1);
    end32(out, u16::MAX, u32::MAX, u32::MAX, comment);
}

#[test]
fn reversed_physical_and_central_order_uses_exact_duplicate_id_and_preserves_legacy_raw_names() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let source = root.path().join("input");
    fs::write(&source, b"replacement").unwrap();
    let mut locals = Vec::new();
    let mut central = Vec::new();
    for (name, payload, comment) in [
        (b"dup".as_slice(), b"first".as_slice(), b"one".as_slice()),
        (b"\x84\x00\x01name", b"legacy", b"\xff"),
        (b"dup", b"third", b"three"),
    ] {
        let crc = crc32fast::hash(payload);
        central.push(central_record(name, payload.len() as u64, crc, locals.len() as u32, &[], comment));
        locals.extend(local_record(name, payload.len() as u64, crc));
        locals.extend(payload);
    }
    let central_at = locals.len() as u32;
    for record in central.iter().rev() {
        locals.extend(record)
    }
    let central_size = locals.len() as u32 - central_at;
    end32(&mut locals, 3, central_size, central_at, b"archive comment");
    fs::write(&path, &locals).unwrap();

    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    let selected = plan.metadata().entry_id(2).unwrap();
    assert!(matches!(
        plan.add_file(Placement::Append, &source, entry(EntryName::Raw(b"dup"), Method::Stored), None),
        Err(RewriteError::NameConflict)
    ));
    assert!(matches!(
        plan.add_file(
            Placement::Replace(selected.clone()),
            &source,
            entry(EntryName::Utf8("dup"), Method::Stored),
            None
        ),
        Err(RewriteError::ReplacementName)
    ));
    plan.add_file(Placement::Replace(selected), &source, entry(EntryName::Raw(b"dup"), Method::Stored), None).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("appended/"), Method::Stored), None).unwrap();
    assert!(matches!(plan.publish().unwrap(), RewriteOutcome::Replaced(_)));
    let plan = RewritePlan::open(&path, opts()).unwrap();
    let metadata = plan.metadata();
    let entries: Vec<_> = metadata.entries().collect();
    assert_eq!(
        entries.iter().map(|entry| entry.raw_name()).collect::<Vec<_>>(),
        [b"dup".as_slice(), b"\x84\x00\x01name", b"dup", b"appended/"]
    );
    assert_eq!(
        entries.iter().map(|entry| entry.raw_comment()).collect::<Vec<_>>(),
        [b"three".as_slice(), b"\xff", b"introduced", b"introduced"]
    );
    let bytes = fs::read(path).unwrap();
    assert_eq!(&bytes[33..38], b"third");
    let second = entries[1].physical_local_header_offset() as usize;
    let original_second = 30 + 3 + 5;
    assert_eq!(&bytes[second..second + 42], &locals[original_second..original_second + 42]);
    assert_eq!(fs::read(source).unwrap(), b"replacement");
}

#[test]
fn no_downgrade_for_an_original_zip64_offset_below_the_sentinel() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let bytes = archive(Fixture { wide_offset: true, ..Fixture::default() });
    fs::write(&path, &bytes).unwrap();
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("new/"), Method::Stored), None).unwrap();
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!() };
    assert_eq!(receipt.verification.retained_structural_only, 1);
    let plan = RewritePlan::open(&path, opts()).unwrap();
    let metadata = plan.metadata();
    let member = metadata.entries().next().unwrap();
    assert_eq!(member.header().local_header_offset, u32::MAX);
    assert_eq!(member.stored_local_header_offset(), 0);
    assert_eq!(member.header().version_needed, 45);
    assert_eq!(metadata.end_record().entries, u16::MAX);
    assert!(metadata.zip64_end().is_some());
}

#[test]
#[ignore = "streams and verifies a real retained payload above four GiB"]
fn retained_payload_streams_above_four_gib_and_widens_the_next_raw_offset() {
    let root = tempfile::tempdir().unwrap();
    let export = std::env::var_os("ZIPFAST_REWRITE_LARGE_DIR");
    let directory = export.as_deref().map(Path::new).unwrap_or(root.path());
    let archive = directory.join("retained.zip");
    let mut file = File::options().read(true).write(true).create_new(true).open(&archive).unwrap();
    let small = b"relocated";
    let small_crc = crc32fast::hash(small);
    file.write_all(&local_record(b"small", small.len() as u64, small_crc)).unwrap();
    file.write_all(small).unwrap();
    let large_at = file.stream_position().unwrap();
    const LARGE: u64 = (1 << 32) + 4096;
    let header = local_record(b"large", LARGE, 0);
    file.write_all(&header).unwrap();
    let mut original = crc32fast::Hasher::new();
    let chunk: Vec<u8> = (0..1 << 20).map(|index| (index % 251) as u8).collect();
    let mut remaining = LARGE;
    while remaining != 0 {
        let len = remaining.min(chunk.len() as u64) as usize;
        file.write_all(&chunk[..len]).unwrap();
        original.update(&chunk[..len]);
        remaining -= len as u64;
    }
    let crc = original.finalize();
    file.write_all_at(&crc.to_le_bytes(), large_at + 14).unwrap();
    let start = file.stream_position().unwrap();
    let mut central = central_record(b"large", LARGE, crc, large_at as u32, &[], b"large comment");
    central.extend(central_record(
        b"small",
        small.len() as u64,
        small_crc,
        0,
        &[0x0d, 0xf0, 1, 0, 7],
        b"small comment",
    ));
    let central_len = central.len() as u64;
    end64(&mut central, 2, central_len, start, b"large source");
    file.write_all(&central).unwrap();
    drop(file);

    let mut plan = RewritePlan::open(&archive, RewriteOptions { verification: Verification::Full, ..opts() }).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("new/"), Method::Stored), None).unwrap();
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!() };
    assert_eq!(receipt.verification.retained_payload_verified, 2);
    assert_eq!(receipt.usage.common.verification.decoded_bytes, LARGE + small.len() as u64);
    assert!(receipt.usage.raw_copy_bytes > LARGE);
    assert!(receipt.usage.retained_comparison_bytes > LARGE);
    let plan = RewritePlan::open(&archive, opts()).unwrap();
    let metadata = plan.metadata();
    let relocated = metadata.entries().nth(1).unwrap();
    assert_eq!(relocated.stored_local_header_offset(), header.len() as u64 + LARGE);
    assert_eq!(relocated.header().local_header_offset, u32::MAX);
    assert_eq!(relocated.header().version_needed, 45);
    let mut local = [0; 35];
    let file = File::open(&archive).unwrap();
    file.read_exact_at(&mut local, relocated.stored_local_header_offset()).unwrap();
    assert_eq!(&local[4..6], &[45, 0]);
    assert_eq!(&local[30..], b"small");
    let mut bytes = [0; 9];
    file.read_exact_at(&mut bytes, relocated.stored_local_header_offset() + 35).unwrap();
    assert_eq!(&bytes, small);
    println!(
        "actual_retained_size={LARGE} widened_offset={} usage={:?}",
        relocated.stored_local_header_offset(),
        receipt.usage
    );
}

#[test]
fn an_eof_shaped_malformed_alternative_is_not_a_second_archive() {
    let mut fake = Vec::new();
    // This candidate declares a full central record but its physical
    // directory position lands inside data without a central signature.
    end32(&mut fake, 1, 46, 0, b"");
    let bytes = archive(Fixture { prefix: b"stub", archive_comment: Some(&fake), ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Ok(RewriteOutcome::Unchanged { .. })));
    let mut options = opts();
    options.limits.source_directory.fetched_bytes = 2 * bytes.len() as u64;
    assert!(matches!(run(&bytes, options), Err(RewriteError::Directory(zip_container::DirectoryError::Limit(_)))));
}

#[test]
fn directory_payloads_must_be_structurally_empty() {
    let bytes = archive(Fixture { name: Some(b"folder/"), packed: b"unexpected", ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
    let bytes = archive(Fixture { name: Some(b"folder/"), ..Fixture::default() });
    let options = RewriteOptions { verification: Verification::Full, ..opts() };
    let RewriteOutcome::Unchanged { verification, .. } = run(&bytes, options).unwrap() else { panic!() };
    assert_eq!(verification.retained_payload_verified, 0);
    assert_eq!(verification.retained_structural_only, 0);
    assert_eq!(verification.retained_directories_verified, 1);
}

#[test]
#[ignore = "copies almost four GiB before reaching data-dependent ZIP64 offset growth"]
fn late_deflate_growth_that_cannot_extend_a_full_old_extra_never_publishes() {
    use std::os::unix::fs::MetadataExt;
    use zipfast::zip::create::{CleanupState, Publication};
    use zipfast::zip::rewrite::RewriteStage;
    use zipfast::zip::write::WriteError;

    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("late.zip");
    let new_input = root.path().join("input");
    let replacement = (0..4096).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    fs::write(&new_input, &replacement).unwrap();

    // Minimum replacement Deflate framing is 30 + 3 + 20 + 1 bytes,
    // leaving the next raw offset 16 bytes below the ZIP64 sentinel.
    let lead_size = u64::from(u32::MAX) - 16 - 34 - 54;
    let mut file = File::options().read(true).write(true).create_new(true).open(&archive).unwrap();
    file.write_all(&local_record(b"lead", lead_size, 0)).unwrap();
    file.seek(SeekFrom::Current(lead_size as i64)).unwrap();
    let middle_at = file.stream_position().unwrap();
    file.write_all(&local_record(b"mid", 0, 0)).unwrap();
    let last_at = file.stream_position().unwrap();
    file.write_all(&local_record(b"full", 0, 0)).unwrap();
    let central_at = file.stream_position().unwrap();
    let mut maximum = vec![0; u16::MAX as usize];
    maximum[..4].copy_from_slice(&[0x0d, 0xf0, 0xfb, 0xff]);
    let mut central = central_record(b"lead", lead_size, 0, 0, &[], b"");
    central.extend(central_record(b"mid", 0, 0, middle_at as u32, &[], b""));
    central.extend(central_record(b"full", 0, 0, last_at as u32, &maximum, b""));
    let central_len = central.len() as u64;
    end64(&mut central, 3, central_len, central_at, b"late geometry");
    file.write_all(&central).unwrap();
    let original = file.metadata().unwrap();

    let mut plan = RewritePlan::open(&archive, opts()).unwrap();
    let selected = plan.metadata().entry_id(1).unwrap();
    plan.add_file(
        Placement::Replace(selected),
        &new_input,
        entry(EntryName::Raw(b"mid"), Method::Deflate(DeflateLevel::new(6).unwrap())),
        None,
    )
    .unwrap();
    let failure = plan.publish().unwrap_err();
    assert_eq!(failure.stage, RewriteStage::Write);
    assert!(matches!(failure.cause, RewriteError::Writer(WriteError::InvalidMetadata(_))));
    assert_eq!(failure.publication, Publication::NotPublished);
    assert!(matches!(failure.cleanup, CleanupState::Clean));
    assert_eq!(failure.usage.common.stage_attempts, 1);
    assert!(failure.usage.raw_copy_bytes > lead_size);
    let observed = fs::metadata(&archive).unwrap();
    assert_eq!(
        (observed.ino(), observed.len(), observed.mtime(), observed.mtime_nsec()),
        (original.ino(), original.len(), original.mtime(), original.mtime_nsec())
    );
    let mut original_central = vec![0; central.len()];
    file.read_exact_at(&mut original_central, central_at).unwrap();
    assert_eq!(original_central, central);
    assert_eq!(fs::read(&new_input).unwrap(), replacement);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
    println!(
        "late_old_extent={} actual_retained_reads={} writer={:?}",
        original.len(),
        failure.usage.raw_copy_bytes,
        failure.usage.common.writer
    );
}

#[test]
#[ignore = "rewrites three real central-directory count boundaries"]
fn rewrites_count_sentinel_boundaries() {
    for count in [65_534, 65_535, 65_536] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("archive.zip");
        let mut writer = ZipWriter::new(File::create(&path).unwrap(), WriterOptions::default()).unwrap();
        for _ in 0..count {
            writer
                .add_file(entry(EntryName::Raw(b"x"), Method::Stored), &mut [].as_slice(), InputLength::Exact(0))
                .unwrap();
        }
        drop(writer.finish().unwrap());
        let mut plan = RewritePlan::open(&path, opts()).unwrap();
        let selected = plan.metadata().entry_id(0).unwrap();
        plan.remove(&selected).unwrap();
        plan.add_directory(Placement::Append, entry(EntryName::Utf8("last/"), Method::Stored), None).unwrap();
        let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!() };
        assert_eq!(receipt.verification.retained_structural_only, count - 1);
        let metadata = RewritePlan::open(&path, opts()).unwrap().metadata();
        assert_eq!(metadata.len() as u64, count);
        assert_eq!(metadata.zip64_end().is_some(), count >= 65_535);
        assert_eq!(metadata.end_record().entries, count.min(65_535) as u16);
        assert_eq!(metadata.entries().next_back().unwrap().raw_name(), b"last/");
        println!(
            "count={count} plan_capacity={} transaction_attempts={}",
            receipt.usage.common.plan.capacity, receipt.usage.common.transaction_attempts
        );
    }
}

#[test]
#[ignore = "exports source and rewritten ZIPs for pinned reference readers"]
fn export_rewrite_reference_fixtures() {
    let folder = std::env::var_os("ZIPFAST_REWRITE_REFERENCE_DIR").expect("existing reference directory");
    let folder = Path::new(&folder);
    let expected = folder.join("expected");
    fs::create_dir(&expected).unwrap();
    let kept_stored = b"stored old payload\n".repeat(127);
    let kept_deflate = b"deflate old payload\x00\xff\n".repeat(8192);
    let replacement = b"new replacement payload\n".repeat(17);
    let added = b"new added payload\n".repeat(32);
    let path = folder.join("rewritten.zip");
    let mut writer = ZipStreamWriter::new(
        File::create(&path).unwrap(),
        WriterOptions { comment: b"retained archive comment", ..WriterOptions::default() },
    )
    .unwrap();
    writer
        .add_file(
            entry(EntryName::Utf8("kept-stored"), Method::Stored),
            &mut kept_stored.as_slice(),
            InputLength::Exact(kept_stored.len() as u64),
        )
        .unwrap();
    writer
        .add_file(
            entry(EntryName::Utf8("kept-deflate"), Method::Deflate(DeflateLevel::new(6).unwrap())),
            &mut kept_deflate.as_slice(),
            InputLength::Unknown,
        )
        .unwrap();
    writer
        .add_file(entry(EntryName::Utf8("replace"), Method::Stored), &mut b"obsolete".as_slice(), InputLength::Exact(8))
        .unwrap();
    drop(writer.finish().unwrap());
    fs::copy(&path, folder.join("before.zip")).unwrap();

    for (name, payload) in [
        ("kept-stored", kept_stored.as_slice()),
        ("kept-deflate", kept_deflate.as_slice()),
        ("replace", replacement.as_slice()),
        ("added", added.as_slice()),
    ] {
        fs::write(expected.join(name), payload).unwrap();
    }
    let mut plan = RewritePlan::open(&path, RewriteOptions { verification: Verification::Full, ..opts() }).unwrap();
    let selected = plan.metadata().entry_id(2).unwrap();
    plan.add_file(
        Placement::Replace(selected),
        &expected.join("replace"),
        entry(EntryName::Utf8("replace"), Method::Stored),
        None,
    )
    .unwrap();
    plan.add_file(
        Placement::Append,
        &expected.join("added"),
        entry(EntryName::Utf8("added"), Method::Deflate(DeflateLevel::new(6).unwrap())),
        None,
    )
    .unwrap();
    let RewriteOutcome::Replaced(receipt) = plan.publish().unwrap() else { panic!() };
    assert_eq!(receipt.verification.new_verified, 2);
    assert_eq!(receipt.verification.retained_payload_verified, 2);

    let prefix_path = folder.join("prefixed.zip");
    let payload = b"retained opaque-prefix payload\n";
    let fixture = archive(Fixture {
        prefix: b"opaque stub\x00",
        relative_offsets: true,
        name: Some(b"prefixed"),
        comment: Some(b"member comment"),
        archive_comment: Some(b"archive comment"),
        packed: payload,
        crc: crc32fast::hash(payload),
        ..Fixture::default()
    });
    fs::write(&prefix_path, &fixture).unwrap();
    fs::write(expected.join("prefixed"), payload).unwrap();
    let mut plan = RewritePlan::open(&prefix_path, opts()).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("directory/"), Method::Stored), None).unwrap();
    plan.publish().unwrap();
}

#[test]
fn retained_legacy_hierarchy_conflicts_block_only_introduced_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let mut writer = ZipWriter::new(File::create(&path).unwrap(), WriterOptions::default()).unwrap();
    for name in ["legacy", "legacy/child"] {
        writer
            .add_file(entry(EntryName::Utf8(name), Method::Stored), &mut [].as_slice(), InputLength::Exact(0))
            .unwrap();
    }
    drop(writer.finish().unwrap());
    let original = fs::read(&path).unwrap();
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("legacy/new/"), Method::Stored), None).unwrap();
    assert!(matches!(plan.publish().unwrap_err().cause, RewriteError::NameConflict));
    assert_eq!(fs::read(&path).unwrap(), original);
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("separate/"), Method::Stored), None).unwrap();
    plan.publish().unwrap();
}

#[test]
fn archive_comment_that_becomes_ambiguous_after_relocation_blocks_publication() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let mut fake = Vec::new();
    // The source comment starts at 101. The added member moves it
    // by 34 local bytes and 60 central bytes.
    end32(&mut fake, 0, 0, 195, b"");
    let old = archive(Fixture { archive_comment: Some(&fake), ..Fixture::default() });
    fs::write(&path, &old).unwrap();
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    plan.add_directory(Placement::Append, entry(EntryName::Utf8("new/"), Method::Stored), None).unwrap();
    let failure = plan.publish().unwrap_err();
    assert_eq!(failure.stage, zipfast::zip::rewrite::RewriteStage::Verify);
    assert!(matches!(failure.cause, RewriteError::AmbiguousDirectory { .. }));
    assert_eq!(fs::read(&path).unwrap(), old);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn hard_link_inputs_aliasing_the_original_and_final_symlinks_are_refused() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    let alias = root.path().join("alias.zip");
    let link = root.path().join("link.zip");
    let old = archive(Fixture::default());
    fs::write(&path, &old).unwrap();
    fs::hard_link(&path, &alias).unwrap();
    symlink(&path, &link).unwrap();
    assert!(RewritePlan::open(&link, opts()).is_err());
    let mut plan = RewritePlan::open(&path, opts()).unwrap();
    let add = entry(EntryName::Utf8("added"), Method::Stored);
    assert!(matches!(
        plan.add_file(Placement::Append, &alias, add, None),
        Err(RewriteError::InputAliasesArchive { input: 0 })
    ));
    assert!(plan.add_file(Placement::Append, &link, add, None).is_err());
    assert!(matches!(
        plan.add_open_file(Placement::Append, &alias, File::open(&path).unwrap(), add, None),
        Err(RewriteError::InputAliasesArchive { input: 0 })
    ));
    assert!(matches!(plan.publish().unwrap(), RewriteOutcome::Unchanged { .. }));
    assert_eq!(fs::read(&path).unwrap(), old);
    assert_eq!(fs::read(&alias).unwrap(), old);
    assert_eq!(fs::read_link(&link).unwrap(), path);
}

#[test]
fn zip64_tail_requires_consistent_classic_values_and_no_unknown_extension() {
    let clean = archive(Fixture::default());
    let mut bytes = clean[..clean.len() - 24].to_vec();
    end64(&mut bytes, 1, 48, 31, &[0xfe, 0xff]);
    assert!(run(&bytes, opts()).is_ok());

    let mut disagree = bytes.clone();
    let end = disagree.len() - 24;
    disagree[end + 16..end + 20].copy_from_slice(&0_u32.to_le_bytes());
    assert!(matches!(run(&disagree, opts()), Err(RewriteError::UnsupportedLayout(_))));

    let tail = bytes.len() - 24 - 20 - 56;
    bytes[tail + 4..tail + 12].copy_from_slice(&45_u64.to_le_bytes());
    bytes.insert(tail + 56, 0xab);
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
}

#[test]
fn full_deflate_requires_stream_end_at_the_exact_declared_boundary() {
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    let original = b"strict raw deflate framing";
    encoder.write_all(original).unwrap();
    let mut packed = encoder.finish().unwrap();
    packed.push(0);
    for input in [&packed[..], &packed[..packed.len() - 2]] {
        let bytes = archive(Fixture {
            method: 8,
            packed: input,
            decoded_len: Some(original.len() as u64),
            crc: crc32fast::hash(original),
            ..Fixture::default()
        });
        assert!(run(&bytes, opts()).is_ok());
        assert!(run(&bytes, RewriteOptions { verification: Verification::Full, ..opts() }).is_err());
    }
}

#[test]
fn shared_local_address_and_recognizable_leading_orphan_are_rejected() {
    let clean = archive(Fixture::default());
    let mut shared = clean[..31].to_vec();
    for _ in 0..2 {
        shared.extend(&clean[31..79]);
    }
    end32(&mut shared, 2, 96, 31, b"");
    assert!(matches!(run(&shared, opts()), Err(RewriteError::UnsupportedLayout(_))));

    let orphan = local_record(b"unused", 0, 0);
    let bytes = archive(Fixture { prefix: &orphan, ..Fixture::default() });
    assert!(matches!(run(&bytes, opts()), Err(RewriteError::UnsupportedLayout(_))));
}

fn archive_with_empty_end_in_comment(
    name: &[u8],
    member_extra: &[u8],
    member_comment: &[u8],
    comment_len: usize,
    wide: bool,
) -> (Vec<u8>, u64) {
    let mut bytes = b"opaque stub".to_vec();
    let local_at = bytes.len() as u32;
    bytes.extend(local_record(name, 0, 0));
    let central_at = bytes.len() as u32;
    let central = central_record(name, 0, 0, local_at, member_extra, member_comment);
    bytes.extend(&central);
    let actual_end = bytes.len() as u64 + if wide { 76 } else { 0 };
    let mut comment = vec![b'c'; comment_len - 22];
    let empty_end = (actual_end + comment_len as u64) as u32;
    end32(&mut comment, 0, 0, empty_end, b"");
    if wide {
        end64(&mut bytes, 1, central.len() as u64, u64::from(central_at), &comment);
        // The disk entry count is the sole classic sentinel. The locator
        // precedes the standard EOF window at the maximum comment size.
        let end = actual_end as usize;
        bytes[end + 10..end + 12].copy_from_slice(&1_u16.to_le_bytes());
        bytes[end + 12..end + 16].copy_from_slice(&(central.len() as u32).to_le_bytes());
        bytes[end + 16..end + 20].copy_from_slice(&central_at.to_le_bytes());
    } else {
        end32(&mut bytes, 1, central.len() as u32, central_at, &comment);
    }
    (bytes, actual_end)
}

#[test]
fn zip64_alternate_with_only_disk_count_saturated_is_seen_at_the_tail_boundary() {
    for len in [65_515, 65_516, 65_535] {
        let (bytes, anchor) = archive_with_empty_end_in_comment(b"x", b"", b"", len, true);
        let mut parser =
            zip_container::DirectoryParser::at_eocd(bytes.len() as u64, anchor, zip_container::Limits::default())
                .unwrap();
        while let Some(range) = parser.next_read().unwrap() {
            parser.supply(range.start, &bytes[range.start as usize..range.end as usize]).unwrap();
        }
        let directory = parser.finish().unwrap();
        assert_eq!(directory.entries.len(), 1);
        assert_eq!(directory.end_record.disk_entries, u16::MAX);
        assert_eq!(directory.end_record.entries, 1);
        assert_eq!(directory.raw_comment.len(), len);
        assert!(matches!(run(&bytes, opts()), Err(RewriteError::AmbiguousDirectory { .. })), "{len}");
    }
}

mod allocation_watch {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    struct ObservedAllocator;

    #[global_allocator]
    static ALLOCATOR: ObservedAllocator = ObservedAllocator;

    thread_local! {
        static WATCH: Cell<Option<([usize; 3], usize)>> = const { Cell::new(None) };
    }

    fn observe(size: usize) {
        let _ = WATCH.try_with(|watch| {
            if let Some((sizes, allocations)) = watch.get()
                && sizes.contains(&size)
            {
                watch.set(Some((sizes, allocations + 1)));
            }
        });
    }

    // Allocation and deallocation forward the original pointer and layout
    // to System. The observer only updates a thread-local counter.
    unsafe impl GlobalAlloc for ObservedAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            observe(layout.size());
            unsafe { System.alloc(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            observe(new_size);
            unsafe { System.realloc(ptr, layout, new_size) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    pub(super) fn measure<T>(sizes: [usize; 3], operation: impl FnOnce() -> T) -> (T, usize) {
        WATCH.set(Some((sizes, 0)));
        let result = operation();
        let (_, allocations) = WATCH.replace(None).unwrap();
        (result, allocations)
    }
}

fn assert_alternate_metadata_cap(bytes: &[u8], exact: u64, watched_sizes: [usize; 3]) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("archive.zip");
    fs::write(&path, bytes).unwrap();
    for (maximum, within_budget) in [(20_000, false), (exact - 1, false), (exact, true)] {
        let mut options = opts();
        options.limits.source_metadata = maximum;
        let (result, allocations) = allocation_watch::measure(watched_sizes, || RewritePlan::open(&path, options));
        assert_eq!(allocations, 0, "alternate materialized variable metadata");
        if within_budget {
            assert!(matches!(result, Err(RewriteError::AmbiguousDirectory { .. })));
        } else {
            assert!(matches!(result, Err(RewriteError::Limit(RewriteLimit::SourceMetadata))));
        }
    }
    assert_eq!(fs::read(path).unwrap(), bytes);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn alternate_name_and_member_comment_share_the_preallocation_metadata_cap() {
    let name = vec![b'n'; 12_000];
    let comment = vec![b'm'; 12_001];
    let (bytes, _) = archive_with_empty_end_in_comment(&name, b"", &comment, 3_011, false);
    assert_alternate_metadata_cap(&bytes, 27_012, [name.len(), comment.len(), 3_011]);
}

#[test]
fn zip64_alternate_raw_extra_and_unicode_projection_share_the_preallocation_metadata_cap() {
    let mut extra = vec![0x75, 0x70];
    u16le(&mut extra, 7_005);
    extra.push(1);
    u32le(&mut extra, crc32fast::hash(b"x"));
    extra.resize(extra.len() + 7_000, b'u');
    extra.extend([0x0d, 0xf0]);
    u16le(&mut extra, 5_000);
    extra.resize(extra.len() + 5_000, 0);
    let (bytes, _) = archive_with_empty_end_in_comment(b"x", &extra, b"", 3_011, true);
    assert_alternate_metadata_cap(&bytes, 22_025, [7_000, 7_005, 3_011]);
}
