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

use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use zipfast::zip::Archive;
use zipfast::zip::create::{
    CleanupState, CreateError, CreateOptions, CreatePlan, Durability, DurabilityState, Publication,
};
use zipfast::zip::write::{DeflateLevel, DosDateTime, EntryName, EntryOptions, Method, Permissions};

fn options(name: EntryName<'_>, method: Method, mode: u16) -> EntryOptions<'_> {
    EntryOptions {
        name,
        method,
        modified: DosDateTime::new(2020, 1, 2, 3, 4, 4).unwrap(),
        extended_mtime: None,
        permissions: Permissions::new(mode).unwrap(),
        comment: b"",
    }
}

fn deflate(level: u32) -> Method {
    Method::Deflate(DeflateLevel::new(level).unwrap())
}

fn bytes_at(archive: &mut Archive, index: usize, max: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    archive
        .read_at(index, None, max, |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        })
        .unwrap();
    bytes
}

#[test]
fn public_creation_preserves_order_metadata_and_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("archive.zip");
    let source = dir.path().join("source");
    let payload = b"streamed Deflate contents\0".repeat(4096);
    fs::write(&source, &payload).unwrap();
    let empty = dir.path().join("empty");
    fs::write(&empty, []).unwrap();
    let mut plan = CreatePlan::new(
        &archive_path,
        CreateOptions {
            output_permissions: 0o640,
            archive_comment: b"binary\0 near-miss PK\x05\x06 comment".to_vec(),
            durability: Durability::SyncFileAndDirectory,
            ..CreateOptions::default()
        },
    )
    .unwrap();
    plan.add_directory(options(EntryName::Utf8("雪/"), Method::Stored, 0o755), None).unwrap();
    for (index, (name, method)) in [
        ("雪/report:2026.txt", Method::Stored),
        ("level-1", deflate(1)),
        ("level-6", deflate(6)),
        ("level-9", deflate(9)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut meta = options(EntryName::Utf8(name), method, 0o751);
        meta.extended_mtime = Some(1_577_934_245);
        meta.comment = b"member";
        let ordinal = if index == 1 {
            let mut held = File::open(&source).unwrap();
            use std::io::{Seek, SeekFrom};
            held.seek(SeekFrom::End(0)).unwrap();
            plan.add_open_file(&source, held, meta, None)
        } else {
            plan.add_file(&source, meta, None)
        }
        .unwrap();
        assert_eq!(ordinal.ordinal(), index + 1);
    }
    let mut meta = options(EntryName::Raw(b"empty"), deflate(9), 0o644);
    meta.comment = b"raw \xff";
    plan.add_file(&empty, meta, None).unwrap();
    let result = plan.publish().unwrap();
    assert_eq!(result.destination, archive_path);
    assert_eq!(result.publication, Publication::Published);
    assert_eq!(result.durability, DurabilityState::Synced);
    assert!(matches!(result.cleanup, CleanupState::Clean));
    assert_eq!(result.summary.writer.entries, 6);
    assert_eq!(result.summary.verification.entries, 6);
    assert_eq!(result.summary.verification.payloads, 5);
    assert_eq!(result.summary.verification.decoded_bytes, payload.len() as u64 * 4);
    assert_eq!(fs::metadata(&archive_path).unwrap().permissions().mode() & 0o777, 0o640);
    assert_eq!(fs::read(&source).unwrap(), payload);
    assert_eq!(fs::read(&empty).unwrap(), b"");
    let mut archive = Archive::open(&archive_path).unwrap();
    for index in 1..=4 {
        assert_eq!(bytes_at(&mut archive, index, (payload.len() * 2) as u64), payload);
    }
    assert_eq!(bytes_at(&mut archive, 5, 0), b"");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn existing_files_links_and_directories_are_early_conflicts() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::write(&source, b"source").unwrap();
    let regular = dir.path().join("regular");
    let hardlink = dir.path().join("hardlink");
    let dangling = dir.path().join("dangling");
    let subdir = dir.path().join("directory");
    fs::write(&regular, b"existing bytes").unwrap();
    fs::hard_link(&source, &hardlink).unwrap();
    symlink("missing", &dangling).unwrap();
    fs::create_dir(&subdir).unwrap();
    for existing in [&regular, &hardlink, &dangling, &subdir] {
        assert!(matches!(CreatePlan::new(existing, CreateOptions::default()), Err(CreateError::Conflict)));
    }
    assert_eq!(fs::read(regular).unwrap(), b"existing bytes");
    assert_eq!(fs::read(hardlink).unwrap(), b"source");
    assert_eq!(fs::read(source).unwrap(), b"source");
    assert_eq!(fs::read_link(dangling).unwrap(), Path::new("missing"));
    assert!(subdir.is_dir());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 5);
}

fn open_descriptors() -> usize {
    #[cfg(target_os = "linux")]
    let path = "/proc/self/fd";
    #[cfg(target_os = "macos")]
    let path = "/dev/fd";
    fs::read_dir(path).unwrap().count()
}

#[test]
fn thousands_of_path_sources_use_bounded_descriptors() {
    const CHILD: &str = "ZIPFAST_TEST_LOW_FD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "thousands_of_path_sources_use_bounded_descriptors", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        print!("{}", String::from_utf8_lossy(&output.stdout));
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        return;
    }

    let mut previous = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // The subprocess owns its limit and passes writable storage to getrlimit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, previous.as_mut_ptr()) }, 0);
    let mut limit = unsafe { previous.assume_init() };
    limit.rlim_cur = limit.rlim_cur.min(24);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let baseline = open_descriptors();
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::write(&source, b"x").unwrap();
    let target = dir.path().join("archive.zip");
    let mut plan = CreatePlan::new(&target, CreateOptions::default()).unwrap();
    for index in 0..6000 {
        let name = format!("files/entry-{index:05}");
        plan.add_file(&source, options(EntryName::Utf8(&name), Method::Stored, 0o600), None).unwrap();
    }
    let admitted = open_descriptors();
    assert_eq!(admitted, baseline + 1);
    assert_eq!(plan.usage().plan.retained_handles, 0);
    let result = plan.publish().unwrap();
    let finished = open_descriptors();
    assert_eq!(finished, baseline);
    assert_eq!(result.summary.writer.entries, 6000);
    assert_eq!(result.summary.verification.payloads, 6000);
    assert_eq!(fs::read(&source).unwrap(), b"x");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    let mut archive = Archive::open(&target).unwrap();
    assert_eq!(bytes_at(&mut archive, 0, 1), b"x");
    assert_eq!(bytes_at(&mut archive, 5999, 1), b"x");
    drop(archive);

    let mut handles = Vec::new();
    let mut exhausted = CreatePlan::new(&dir.path().join("exhausted.zip"), CreateOptions::default()).unwrap();
    loop {
        match File::open(&source) {
            Ok(file) => handles.push(file),
            Err(error) if error.raw_os_error() == Some(libc::EMFILE) => break,
            Err(error) => panic!("{error}"),
        }
    }
    assert!(matches!(
        exhausted.add_file(&source, options(EntryName::Utf8("source"), Method::Stored, 0o600), None),
        Err(CreateError::DescriptorExhaustion(_))
    ));
    drop(handles);
    assert!(!dir.path().join("exhausted.zip").exists());
    assert_eq!(fs::read(&source).unwrap(), b"x");
    println!(
        "RLIMIT_NOFILE={} baseline_fds={baseline} admitted_fds={admitted} final_fds={finished} usage={:?}",
        limit.rlim_cur, result.summary
    );
}

#[test]
#[ignore = "writes a real ZIP64 archive above four GiB"]
fn streamed_zip64_transaction_exceeds_four_gib() {
    let default = tempfile::tempdir().unwrap();
    let export = std::env::var_os("ZIPFAST_CREATE_LARGE_DIR");
    let dir = export.as_deref().map(Path::new).unwrap_or(default.path());
    const SIZE: u64 = (1 << 32) + 4096;
    const MARKER: &[u8] = b"checked ZIP64 end";
    let path = dir.join("large-source");
    let file = File::options().read(true).write(true).create_new(true).open(&path).unwrap();
    file.set_len(SIZE).unwrap();
    file.write_all_at(MARKER, SIZE - MARKER.len() as u64).unwrap();
    drop(file);
    let tail = dir.join("tail-source");
    fs::write(&tail, b"offset-only").unwrap();
    let archive_path = dir.join("large.zip");
    let baseline = open_descriptors();
    let mut plan = CreatePlan::new(&archive_path, CreateOptions::default()).unwrap();
    plan.add_file(&path, options(EntryName::Utf8("large"), Method::Stored, 0o640), None).unwrap();
    plan.add_file(&tail, options(EntryName::Utf8("after"), Method::Stored, 0o600), None).unwrap();
    let admitted = open_descriptors();
    let receipt = plan.publish().unwrap();
    let finished = open_descriptors();
    assert_eq!(baseline + 1, admitted);
    assert_eq!(baseline, finished);
    assert_eq!(receipt.summary.verification.decoded_bytes, SIZE + 11);
    assert_eq!(receipt.summary.verification.payloads, 2);
    assert_eq!(fs::metadata(&path).unwrap().len(), SIZE);
    assert!(fs::metadata(&archive_path).unwrap().len() > SIZE);
    let mut archive = Archive::open(&archive_path).unwrap();
    let original = File::open(path).unwrap();
    let mut count = 0;
    let mut buffer = vec![0; 1 << 20];
    archive
        .read_at(0, None, SIZE, |bytes| {
            original.read_exact_at(&mut buffer[..bytes.len()], count)?;
            assert_eq!(bytes, &buffer[..bytes.len()]);
            count += bytes.len() as u64;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, SIZE);
    assert_eq!(bytes_at(&mut archive, 1, 11), b"offset-only");
    assert_eq!(fs::read(tail).unwrap(), b"offset-only");
    println!("baseline_fds={baseline} admitted_fds={admitted} final_fds={finished} usage={:?}", receipt.summary);
}

#[test]
#[ignore = "exports fixtures for checksum-verified reference readers"]
fn export_creation_reference_fixtures() {
    let folder = std::env::var_os("ZIPFAST_CREATE_REFERENCE_DIR").expect("existing reference directory");
    let folder = Path::new(&folder);
    let expected = folder.join("expected");
    fs::create_dir(&expected).unwrap();
    let dir = expected.join("docs");
    fs::create_dir(&dir).unwrap();
    let payload = dir.join("run.sh");
    File::create(&payload).unwrap().write_all(&b"#!/bin/sh\nprintf 'verified\\n'\n".repeat(8192)).unwrap();
    let empty = expected.join("empty");
    File::create(&empty).unwrap();
    let output = folder.join("metadata.zip");
    let mut plan = CreatePlan::new(
        &output,
        CreateOptions { archive_comment: b"reference comment".to_vec(), ..CreateOptions::default() },
    )
    .unwrap();
    plan.add_directory(options(EntryName::Utf8("docs/"), Method::Stored, 0o755), None).unwrap();
    let mut script = options(EntryName::Utf8("docs/run.sh"), deflate(6), 0o751);
    script.extended_mtime = Some(1_577_934_245);
    script.comment = b"script";
    plan.add_file(&payload, script, None).unwrap();
    let mut raw = options(EntryName::Raw(b"empty"), Method::Stored, 0o644);
    raw.comment = b"raw comment";
    plan.add_file(&empty, raw, None).unwrap();
    let receipt = plan.publish().unwrap();
    assert_eq!(receipt.summary.verification.payloads, 2);
    CreatePlan::new(&folder.join("empty.zip"), CreateOptions::default()).unwrap().publish().unwrap();
}

#[test]
fn unqualified_linux_mount_is_rejected_when_provided() -> io::Result<()> {
    if let Some(path) = std::env::var_os("ZIPFAST_TEST_UNQUALIFIED_DIR") {
        let directory = tempfile::tempdir_in(path)?;
        let target = directory.path().join("archive.zip");
        assert!(matches!(CreatePlan::new(&target, CreateOptions::default()), Err(CreateError::UnsupportedFilesystem)));
        assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn maximum_binary_comment_with_an_inexact_signature_can_publish() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive.zip");
    let mut comment = vec![0xff; u16::MAX as usize];
    let fake = comment.len() - 23;
    comment[fake..fake + 22].fill(0);
    comment[fake..fake + 4].copy_from_slice(b"PK\x05\x06");
    let mut plan =
        CreatePlan::new(&path, CreateOptions { archive_comment: comment.clone(), ..CreateOptions::default() }).unwrap();
    plan.add_directory(options(EntryName::Utf8("directory/"), Method::Stored, 0o750), None).unwrap();
    assert_eq!(plan.publish().unwrap().summary.verification.entries, 1);
    assert_eq!(Archive::open(&path).unwrap().entries.len(), 1);
    let bytes = fs::read(path).unwrap();
    assert!(bytes.ends_with(&comment));
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
#[ignore = "runs three real central-directory count boundaries"]
fn zip64_count_sentinel_requires_widening() {
    use std::io::{Read, Seek, SeekFrom};
    let dir = tempfile::tempdir().unwrap();
    for count in [65_534, 65_535, 65_536] {
        let path = dir.path().join(format!("{count}.zip"));
        let mut plan = CreatePlan::new(&path, CreateOptions::default()).unwrap();
        for index in 0..count {
            let name = format!("directory-{index:05}/");
            plan.add_directory(options(EntryName::Utf8(&name), Method::Stored, 0o755), None).unwrap();
        }
        let result = plan.publish().unwrap();
        assert_eq!(result.summary.verification.entries, count);
        assert_eq!(result.summary.verification.payloads, 0);
        let mut file = File::open(&path).unwrap();
        let mut end = [0; 22];
        file.seek(SeekFrom::End(-22)).unwrap();
        file.read_exact(&mut end).unwrap();
        assert_eq!(&end[..4], b"PK\x05\x06");
        let declared_count = u16::from_le_bytes(end[10..12].try_into().unwrap());
        assert_eq!(declared_count, count.min(u64::from(u16::MAX)) as u16);
        let declared_offset = u32::from_le_bytes(end[16..20].try_into().unwrap());
        assert_eq!(declared_offset == u32::MAX, count >= u64::from(u16::MAX));
        assert_eq!(Archive::open(&path).unwrap().entries.len() as u64, count);
    }
}
