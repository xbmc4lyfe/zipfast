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

use std::{
    cell::Cell,
    fs::{self, File},
    io::Write,
    sync::Arc,
};

use super::recovery::{RecoveryIssue, RecoveryOutcome, RecoveryUsage, recover_member};
use super::*;
use crate::zip::{
    Metadata,
    create::{CreateError, CreateLimit},
    rewrite::{Replacement, RewriteLimits, RewriteOptions, RewritePlan},
    write::{
        DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions, WriterOptions,
        ZipStreamWriter,
    },
};

fn options(name: &str, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"",
    }
}

fn fixture(method: Method) -> (tempfile::TempDir, File, Arc<Metadata>, Vec<u8>) {
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    writer.add_file(options("a", method), &mut b"abc".as_slice(), InputLength::Exact(3)).unwrap();
    writer.add_file(options("b", Method::Stored), &mut b"tail".as_slice(), InputLength::Exact(4)).unwrap();
    let bytes = writer.finish().unwrap().sink;
    load(bytes)
}

fn load(bytes: Vec<u8>) -> (tempfile::TempDir, File, Arc<Metadata>, Vec<u8>) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("source.zip");
    fs::write(&path, &bytes).unwrap();
    let plan = RewritePlan::open(&path, RewriteOptions::new(Replacement::LastWriterWins)).unwrap();
    let metadata = plan.metadata();
    let file = File::open(path).unwrap();
    (root, file, metadata, bytes)
}

#[test]
fn repairs_only_signed_descriptor_fields_after_payload_verification() {
    for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
        let (_, _, original, mut bytes) = fixture(method);
        let end = original.view(1).physical_local_header_offset();
        let width = if method == Method::Stored { 16 } else { 24 };
        let descriptor = end as usize - width;
        let expected = bytes[descriptor..end as usize].to_vec();
        bytes[descriptor + 4] ^= 1;
        let (_root, mut file, metadata, damaged) = load(bytes);
        let limits = RewriteLimits::default();
        let count = Cell::new(0);
        let cancel = crate::extract::Cancellation::default();
        let attempts = Attempts::with_limits(&cancel, limits.common.transaction_attempts, &count);
        let mut usage = RecoveryUsage::default();
        let recovered = recover_member(&mut file, metadata.view(0), end, limits, &attempts, &mut usage).unwrap();
        let RecoveryOutcome::Verified(recovered) = recovered else { panic!("verified payload was omitted") };
        let repair = recovered.descriptor.expect("damaged descriptor needs repair");
        assert_eq!(repair.offset, descriptor as u64);
        assert_eq!(repair.bytes(), expected);
        assert_eq!(usage.payload.decoded_bytes, 3);
        let mut read_bytes = 0;
        assert!(
            member(
                &mut Reader {
                    file: &file,
                    attempts: &attempts,
                    bytes: &mut read_bytes,
                    max: u64::MAX,
                    exhausted: ReadLimit::Parser
                },
                metadata.view(0),
                end,
                &mut [0; BUFFER]
            )
            .is_err()
        );
        assert_eq!(fs::read(_root.path().join("source.zip")).unwrap(), damaged);
    }
}

#[test]
fn rejects_bad_payload_without_repairing_its_descriptor_and_can_verify_later_member() {
    let (_, _, metadata, mut bytes) = fixture(Method::Stored);
    let end = metadata.view(1).physical_local_header_offset();
    bytes[31] ^= 1;
    bytes[end as usize - 12] ^= 1;
    let (_root, mut file, metadata, _) = load(bytes);
    let limits = RewriteLimits::default();
    let count = Cell::new(0);
    let cancel = crate::extract::Cancellation::default();
    let attempts = Attempts::with_limits(&cancel, limits.common.transaction_attempts, &count);
    let mut usage = RecoveryUsage::default();
    assert!(matches!(
        recover_member(&mut file, metadata.view(0), end, limits, &attempts, &mut usage).unwrap(),
        RecoveryOutcome::Omitted(RecoveryIssue::Payload(_))
    ));
    assert!(matches!(
        recover_member(&mut file, metadata.view(1), metadata.directory_range().start, limits, &attempts, &mut usage)
            .unwrap(),
        RecoveryOutcome::Verified(_)
    ));
    assert_eq!(usage.payload.decoded_bytes, 7);
}

#[test]
fn refuses_a_lost_descriptor_signature_and_an_overlapping_boundary() {
    let (_, _, metadata, mut bytes) = fixture(Method::Stored);
    let end = metadata.view(1).physical_local_header_offset();
    bytes[end as usize - 16] ^= 1;
    let (_root, mut file, metadata, _) = load(bytes);
    let limits = RewriteLimits::default();
    let count = Cell::new(0);
    let cancel = crate::extract::Cancellation::default();
    let attempts = Attempts::with_limits(&cancel, limits.common.transaction_attempts, &count);
    let mut usage = RecoveryUsage::default();
    for boundary in [end, 2] {
        assert!(matches!(
            recover_member(&mut file, metadata.view(0), boundary, limits, &attempts, &mut usage).unwrap(),
            RecoveryOutcome::Omitted(RecoveryIssue::Framing(_))
        ));
    }
    assert_eq!(usage.payload.decoded_bytes, 0);
}

#[test]
fn resource_cancellation_and_source_io_failures_remain_terminal() {
    let (root, mut file, metadata, _) = fixture(Method::Stored);
    let end = metadata.view(1).physical_local_header_offset();
    let mut limits = RewriteLimits::default();
    limits.common.verification_decoded_bytes = 2;
    let count = Cell::new(0);
    let cancel = crate::extract::Cancellation::default();
    let attempts = Attempts::with_limits(&cancel, limits.common.transaction_attempts, &count);
    let mut usage = RecoveryUsage::default();
    assert!(matches!(
        recover_member(&mut file, metadata.view(0), end, limits, &attempts, &mut usage),
        Err(RewriteError::Infrastructure(CreateError::Limit(CreateLimit::VerificationDecodedBytes)))
    ));
    assert_eq!(usage.layout_read_bytes, 0);
    limits = RewriteLimits::default();
    File::create(root.path().join("source.zip")).unwrap().write_all(b"PK").unwrap();
    assert!(matches!(
        recover_member(&mut file, metadata.view(0), end, limits, &attempts, &mut usage),
        Err(RewriteError::Infrastructure(CreateError::Io(_)))
    ));
    cancel.cancel();
    assert!(matches!(
        recover_member(&mut file, metadata.view(0), end, limits, &attempts, &mut usage),
        Err(RewriteError::Infrastructure(CreateError::Canceled))
    ));
}

// Python-generated fixture from the pinned 29-case recovery oracle. Info-ZIP
// -F repairs this CRC field and both independent readers verify its output.
#[test]
fn pinned_intact_central_descriptor_fixture_has_one_proved_repair() {
    let bytes = include_bytes!("fixtures/signed-descriptor-bad-crc-with-central.zip").to_vec();
    let (_root, mut file, metadata, _) = load(bytes);
    let limits = RewriteLimits::default();
    let count = Cell::new(0);
    let cancel = crate::extract::Cancellation::default();
    let attempts = Attempts::with_limits(&cancel, limits.common.transaction_attempts, &count);
    let mut usage = RecoveryUsage::default();
    let first_end = metadata.view(1).physical_local_header_offset();
    let first = recover_member(&mut file, metadata.view(0), first_end, limits, &attempts, &mut usage).unwrap();
    let RecoveryOutcome::Verified(first) = first else { panic!("first verified payload omitted") };
    let descriptor = first.descriptor.unwrap();
    assert_eq!(descriptor.offset, 483);
    assert_eq!(descriptor.bytes(), &[80, 75, 7, 8, 147, 68, 241, 76, 184, 1, 0, 0, 184, 1, 0, 0]);
    let second =
        recover_member(&mut file, metadata.view(1), metadata.directory_range().start, limits, &attempts, &mut usage)
            .unwrap();
    let RecoveryOutcome::Verified(second) = second else { panic!("later verified payload omitted") };
    assert!(second.descriptor.is_none());
    assert_eq!(usage.payload.payloads, 2);
}
