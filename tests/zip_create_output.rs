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
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::symlink;
use zipfast::extract::Cancellation;
use zipfast::zip::create::{CreateError, CreateLimit, CreateOptions, CreatePlan};
use zipfast::zip::write::{DosDateTime, EntryName, EntryOptions, Method, Permissions};

fn entry(name: &str) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method: Method::Stored,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o640).unwrap(),
        comment: b"",
    }
}

#[test]
fn create_output_aliases_use_actual_admitted_identity_and_do_not_poison_publication() {
    for held in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let target = root.path().join("out.zip");
        fs::write(&source, b"original source").unwrap();
        let hard = root.path().join("hard");
        let link = root.path().join("link");
        fs::hard_link(&source, &hard).unwrap();
        symlink(&source, &link).unwrap();
        let mut plan = CreatePlan::new(&target, CreateOptions::default()).unwrap();
        plan.add_directory(entry("metadata/"), None).unwrap();
        let id = if held {
            plan.add_open_file(&source, File::open(&source).unwrap(), entry("data"), None).unwrap()
        } else {
            plan.add_file(&source, entry("data"), None).unwrap()
        };
        for path in [&source, &hard, &link] {
            let output = fs::OpenOptions::new().append(true).open(path).unwrap();
            let error = plan.check_output_file(&output).unwrap_err();
            assert!(matches!(error, CreateError::OutputAliasesInput(found) if found.ordinal() == id.ordinal()));
            assert!(!error.to_string().contains("source"));
            assert_eq!(fs::read(&source).unwrap(), b"original source");
            assert!(!target.exists());
        }
        let output = tempfile::tempfile().unwrap();
        plan.check_output_file(&output).unwrap();
        assert_eq!(output.metadata().unwrap().len(), 0);
        plan.publish().unwrap();
        let mut archive = zipfast::zip::Archive::open(&target).unwrap();
        let mut payload = Vec::<u8>::new();
        archive
            .read_at(1, None, 1024, |bytes| {
                payload.extend(bytes);
                Ok(())
            })
            .unwrap();
        assert_eq!(payload, b"original source");
    }
}

#[test]
fn create_output_known_and_rebound_aliases_precede_binding_errors() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::write(&source, b"original").unwrap();
    let target = root.path().join("out.zip");
    let mut plan = CreatePlan::new(&target, CreateOptions::default()).unwrap();
    plan.add_file(&source, entry("data"), None).unwrap();
    let original = File::open(&source).unwrap();
    fs::rename(&source, root.path().join("saved")).unwrap();
    assert!(matches!(plan.check_output_file(&original), Err(CreateError::OutputAliasesInput(_))));
    let console_path = root.path().join("console");
    fs::write(&console_path, b"console").unwrap();
    let console = File::open(&console_path).unwrap();
    fs::hard_link(&console_path, &source).unwrap();
    assert!(matches!(plan.check_output_file(&console), Err(CreateError::OutputAliasesInput(_))));
    let distinct = tempfile::tempfile().unwrap();
    assert!(matches!(plan.check_output_file(&distinct), Err(CreateError::SourceChanged(_))));
    assert_eq!(fs::read(&console_path).unwrap(), b"console");
    assert!(!target.exists());
}

#[test]
fn create_output_checks_path_and_held_tracked_directories() {
    for held in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("directory");
        fs::create_dir(&source).unwrap();
        let mut plan = CreatePlan::new(&root.path().join("out.zip"), CreateOptions::default()).unwrap();
        plan.add_directory(entry("metadata/"), None).unwrap();
        let id = if held {
            plan.add_open_directory(&source, File::open(&source).unwrap(), entry("tracked/"), None).unwrap()
        } else {
            plan.add_directory_from_path(&source, entry("tracked/"), None).unwrap()
        };
        let output = File::open(&source).unwrap();
        assert!(
            matches!(plan.check_output_file(&output), Err(CreateError::OutputAliasesInput(found)) if found.ordinal() == id.ordinal())
        );
        plan.check_output_file(&tempfile::tempfile().unwrap()).unwrap();
        fs::write(source.join("changed"), b"change").unwrap();
        assert!(matches!(plan.check_output_file(&tempfile::tempfile().unwrap()), Err(CreateError::SourceChanged(_))));
    }
}

#[test]
fn create_output_accepts_distinct_descriptors_without_seeking_or_writing() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::write(&source, b"original").unwrap();
    let mut held = File::open(&source).unwrap();
    held.seek(SeekFrom::Start(3)).unwrap();
    let mut observer = held.try_clone().unwrap();
    let mut plan = CreatePlan::new(&root.path().join("out.zip"), CreateOptions::default()).unwrap();
    plan.add_open_file(&source, held, entry("data"), None).unwrap();
    let before_handles = plan.usage().plan.retained_handles;
    let mut output = tempfile::tempfile().unwrap();
    output.seek(SeekFrom::Start(9)).unwrap();
    plan.check_output_file(&output).unwrap();
    assert_eq!(observer.stream_position().unwrap(), 3);
    assert_eq!(output.stream_position().unwrap(), 9);
    assert_eq!(output.metadata().unwrap().len(), 0);
    let mut descriptors = [0; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    let mut reader = unsafe { File::from_raw_fd(descriptors[0]) };
    let writer = unsafe { File::from_raw_fd(descriptors[1]) };
    plan.check_output_file(&writer).unwrap();
    assert_eq!(unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) }, 0);
    assert_eq!(reader.read(&mut [0]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    let (_peer, socket) = UnixStream::pair().unwrap();
    plan.check_output_file(&File::from(OwnedFd::from(socket))).unwrap();
    assert_eq!(plan.usage().plan.retained_handles, before_handles);
    assert_eq!(fs::read(source).unwrap(), b"original");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    let mut empty = CreatePlan::new(&root.path().join("empty.zip"), CreateOptions::default()).unwrap();
    empty.check_output_file(&output).unwrap();
}

#[test]
fn create_output_obeys_attempt_work_and_cancellation_bounds() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::write(&source, b"original").unwrap();
    let target = root.path().join("out.zip");
    let make = |options| {
        let mut plan = CreatePlan::new(&target, options).unwrap();
        plan.add_directory(entry("metadata/"), None).unwrap();
        plan.add_file(&source, entry("data"), None).unwrap();
        plan
    };
    let output = tempfile::tempfile().unwrap();
    let mut baseline = make(CreateOptions::default());
    let before = baseline.usage();
    baseline.check_output_file(&output).unwrap();
    let after = baseline.usage();
    assert!(after.transaction_attempts > before.transaction_attempts);
    assert_eq!(after.plan.work - before.plan.work, 4); // two entries in each of two passes
    for attempts in [false, true] {
        for exact in [false, true] {
            let mut options = CreateOptions::default();
            if attempts {
                options.limits.transaction_attempts = after.transaction_attempts - u64::from(!exact);
            } else {
                options.limits.plan_work = after.plan.work - u64::from(!exact);
            }
            let mut plan = make(options);
            let result = plan.check_output_file(&output);
            assert_eq!(result.is_ok(), exact);
            if !exact {
                assert!(matches!(
                    result,
                    Err(CreateError::Limit(CreateLimit::TransactionAttempts | CreateLimit::PlanWork))
                ));
            }
        }
    }
    let cancel = Cancellation::default();
    let mut plan = make(CreateOptions { cancel: cancel.clone(), ..CreateOptions::default() });
    let before = plan.usage();
    cancel.cancel();
    assert!(matches!(plan.check_output_file(&output), Err(CreateError::Canceled)));
    assert_eq!(plan.usage().transaction_attempts, before.transaction_attempts);
    assert_eq!(plan.usage().plan.work, before.plan.work);
    assert_eq!(output.metadata().unwrap().len(), 0);
    assert!(!target.exists());
}

#[test]
fn create_output_known_alias_precedes_parent_binding_failure() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::write(&source, b"source").unwrap();
    let parent = root.path().join("parent");
    fs::create_dir(&parent).unwrap();
    let mut plan = CreatePlan::new(&parent.join("out.zip"), CreateOptions::default()).unwrap();
    plan.add_file(&source, entry("data"), None).unwrap();
    let alias = File::open(&source).unwrap();
    fs::rename(&parent, root.path().join("saved-parent")).unwrap();
    fs::create_dir(&parent).unwrap();
    assert!(matches!(plan.check_output_file(&alias), Err(CreateError::OutputAliasesInput(_))));
    assert!(matches!(plan.check_output_file(&tempfile::tempfile().unwrap()), Err(CreateError::ParentChanged)));
    assert_eq!(fs::read(source).unwrap(), b"source");
}
