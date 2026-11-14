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
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;

#[test]
fn atomic_birth_and_backend_are_native() {
    let parent = tempfile::tempdir().unwrap();
    let directory = File::open(parent.path()).unwrap();
    native_policy::backend(directory.as_raw_fd()).unwrap();
    let path = CString::new(parent.path().as_os_str().as_bytes()).unwrap();
    let leaf = c"atomic";
    let fd = native_policy::atomic_file(directory.as_raw_fd(), &path, leaf).unwrap();
    let file = unsafe { File::from_raw_fd(fd) };
    let stat = native_policy::stat(file.as_raw_fd()).unwrap();
    assert_eq!(stat.st_mode & 0o077, 0);
    assert_eq!(stat.st_size, 0);
    let mut bytes = [0u8; 4096];
    assert!(native_policy::private_acl(file.as_raw_fd(), &mut bytes).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn apfs_ownership_gate_and_atomic_abi_layout() {
    assert!(native_policy::mac_backend(b"apfs\0", libc::MNT_LOCAL as u32, 0));
    assert!(!native_policy::mac_backend(b"apfs\0", libc::MNT_LOCAL as u32 | 0x00200000, 0));
    assert!(!native_policy::mac_backend(b"apfs\0", libc::MNT_LOCAL as u32, 2));
    assert!(!native_policy::mac_backend(b"hfs\0", libc::MNT_LOCAL as u32, 0));
    assert_eq!(native_policy::atomic_abi_layout(), (44, 4, 36, 40, u32::MAX - 100));
}

#[cfg(target_os = "macos")]
#[test]
fn inherited_allow_ace_is_suppressed_at_atomic_birth() {
    let parent = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow read,write,file_inherit,directory_inherit"])
        .arg(parent.path())
        .status()
        .unwrap();
    assert!(status.success());
    let directory = File::open(parent.path()).unwrap();
    let path = CString::new(parent.path().as_os_str().as_bytes()).unwrap();
    let ordinary =
        std::fs::OpenOptions::new().write(true).create_new(true).open(parent.path().join("ordinary")).unwrap();
    let mut bytes = [0u8; 4096];
    assert!(!native_policy::private_acl(ordinary.as_raw_fd(), &mut bytes).unwrap(), "control must inherit a real ACE");
    let fd = native_policy::atomic_file(directory.as_raw_fd(), &path, c"private").unwrap();
    let private = unsafe { File::from_raw_fd(fd) };
    assert!(native_policy::private_acl(private.as_raw_fd(), &mut bytes).unwrap());
    native_policy::atomic_directory(directory.as_raw_fd(), &path, c"private-directory").unwrap();
    let private_directory = File::open(parent.path().join("private-directory")).unwrap();
    assert!(native_policy::private_acl(private_directory.as_raw_fd(), &mut bytes).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn shared_cipher_birth_does_not_inherit_a_mutator_ace() {
    let parent = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write,file_inherit,directory_inherit"])
            .arg(parent.path())
            .status()
            .unwrap()
            .success()
    );
    let (ledger, _) = super::spool::ledger(0);
    let cancel = Cancellation::default();
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(parent.path()), &cancel).unwrap();
    let observed = std::rc::Rc::new(std::cell::Cell::new(false));
    let copy = observed.clone();
    spool::hooks::HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |op, fd| {
            if op == ReadIoOperation::Stat && fd >= 0 {
                let stat = native_policy::stat(fd).unwrap();
                if stat.st_mode & libc::S_IFMT == libc::S_IFREG {
                    copy.set(true);
                    let mut bytes = [0; 4096];
                    if !native_policy::private_acl(fd, &mut bytes).unwrap() {
                        return Some(std::io::Error::from_raw_os_error(libc::EACCES));
                    }
                }
            }
            None
        }))
    });
    let result = spool::OwnedCiphertext::copy(
        &ledger,
        &directory,
        &mut std::io::Cursor::new(b"owned authenticated bytes"),
        25,
        &mut [0; 64],
        &cancel,
    );
    spool::hooks::HOOK.with(|hook| *hook.borrow_mut() = None);
    assert!(observed.get());
    result.unwrap().finish().unwrap();
}

use super::fixture;

#[test]
fn original_borrowed_receipt_rejects_nonregular_and_invalid_ordinal() {
    use std::io::Write;
    let mut directory = fixture::Member::stored(b"directory/", b"");
    directory.external = (0o040755u32) << 16;
    directory.made_by = 0x0314;
    let bytes =
        fixture::build(&[fixture::Member::stored(b"entry", b"data"), directory], &[0, 1], b"", b"", false).bytes;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let mut session = ProjectedReadSession::open(file.path(), &Cancellation::default()).unwrap();
    assert!(session.stage_entry(2).is_err());
    assert!(session.stage_entry(1).is_err());
    {
        let _receipt = session.stage_entry(0).unwrap();
    }
    assert_eq!(session.entries().next().unwrap().name, "entry");
    let mut selected = crate::extract::SelectedEntry::open(file.path(), 0, None, 100).unwrap();
    {
        let _receipt = selected.zip_stage_entry().unwrap().unwrap();
    }
    assert_eq!(selected.name(), "entry");
    let mut retained = crate::zip::ReadSession::open(file.path()).unwrap();
    let id = retained.metadata().entry_id(0).unwrap();
    let mut selected = retained.select(&id, 100, Cancellation::default()).unwrap();
    {
        let _receipt = selected.stage_entry().unwrap();
    }
    assert_eq!(selected.relative_path(), Path::new("entry"));
}

#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn final_boundary_requires_fresh_actual_original_source_observation() {
    use std::io::Write;
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let proof = output::FinalSourceProof::original(session.owner.identity, &context).unwrap();
    assert!(proof.observe(&mut context, &mut |_| Ok(())).is_err());
    session.check_source(&mut context).unwrap();
    assert!(
        proof.observe(&mut context, &mut |_| Ok(())).is_err(),
        "prior observation cannot authorize current boundary"
    );
    proof.observe(&mut context, &mut |c| session.check_source(c)).unwrap();
    let mut other = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    assert!(
        proof.observe(&mut other, &mut |c| session.check_source(c)).is_err(),
        "same catalogue still needs exact action identity"
    );
    let mut foreign = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    assert!(proof.observe(&mut context, &mut |c| foreign.check_source(c)).is_err());
    drop(session);
    assert!(proof.observe(&mut context, &mut |_| Ok(())).is_err(), "dropped owner has no fresh observation");
}

#[cfg(unix)]
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn stdout_is_real_file_verified_and_requires_actual_fd_admission() {
    use std::io::Write;
    use std::os::fd::AsFd;
    for data in [b"".as_slice(), b"verified bytes".as_slice()] {
        let bytes = fixture::build(&[fixture::Member::stored(b"entry", data)], &[0], b"", b"", false).bytes;
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::VerifiedStdout,
            None,
            &Default::default(),
            &cancel,
        )
        .unwrap();
        let receipt = session.stage_entry(0).unwrap();
        assert!(ZipReadStage::prepare_stdout(receipt, &cancel, &mut context).is_err());
        let mut out = tempfile::tempfile().unwrap();
        session.admit_output_fd(out.as_fd(), &mut context).unwrap();
        let mut stage = ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).unwrap();
        assert!(stage.file.as_ref().unwrap().metadata().unwrap().is_file());
        assert_eq!(native_policy::stat(stage.file.as_ref().unwrap().as_raw_fd()).unwrap().st_nlink, 0);
        session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
        let accepted = stage.copy_verified(&mut out, &cancel, &mut context, |c| session.check_source(c)).unwrap();
        assert_eq!(accepted, data.len() as u64);
        use std::io::{Read, Seek, SeekFrom};
        out.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        out.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, data);
        assert_eq!(context.run_usage().live_spool_bytes, 0);
        assert_eq!(context.usage().members, 0);
        assert_eq!(context.usage().io_attempts, 0);
    }
}

fn stdout_stage(
    data: &[u8],
) -> (tempfile::NamedTempFile, ProjectedReadSession, EncryptedReadContext, ZipReadStage, File) {
    use std::io::Write;
    use std::os::fd::AsFd;
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", data)], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let out = tempfile::tempfile().unwrap();
    session.admit_output_fd(out.as_fd(), &mut context).unwrap();
    let stage = ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).unwrap();
    (source, session, context, stage, out)
}
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn byte_count_cannot_forge_completion_or_final_source() {
    let cancel = Cancellation::default();
    let (_source, mut session, mut context, mut stage, mut out) = stdout_stage(b"data");
    stage.write_all(b"data", &cancel).unwrap();
    let error = stage.copy_verified(&mut out, &cancel, &mut context, |c| session.check_source(c)).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(out.metadata().unwrap().len(), 0);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
    let (_source, mut session, mut context, mut stage, mut out) = stdout_stage(b"data");
    session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
    let error = stage.copy_verified(&mut out, &cancel, &mut context, |_| Ok(())).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(out.metadata().unwrap().len(), 0);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
}
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn actual_writer_must_match_original_admission() {
    let cancel = Cancellation::default();
    let (_source, mut session, mut context, mut stage, out) = stdout_stage(b"data");
    session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
    let mut other = tempfile::tempfile().unwrap();
    let error = stage.copy_verified(&mut other, &cancel, &mut context, |c| session.check_source(c)).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(out.metadata().unwrap().len(), 0);
    assert_eq!(other.metadata().unwrap().len(), 0);
}
struct PartialWriter {
    file: File,
    limit: usize,
    accepted: usize,
    interrupt: bool,
    mutate: Option<std::path::PathBuf>,
}
impl std::os::fd::AsFd for PartialWriter {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.file.as_fd()
    }
}
impl std::io::Write for PartialWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.interrupt {
            self.interrupt = false;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if self.accepted == self.limit {
            if let Some(path) = self.mutate.take() {
                std::fs::write(path, b"source changed").unwrap();
            }
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        let n = self.file.write(&bytes[..bytes.len().min(self.limit - self.accepted)])?;
        self.accepted += n;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn first_middle_final_broken_pipe_keeps_exact_bytes_and_postfault_source() {
    let cancel = Cancellation::default();
    for limit in [0, 2, 3] {
        for changed in [false, true] {
            let (source, mut session, mut context, mut stage, out) = stdout_stage(b"data");
            session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
            let mut out = PartialWriter {
                file: out,
                limit,
                accepted: 0,
                interrupt: true,
                mutate: changed.then(|| source.path().to_owned()),
            };
            let error = stage.copy_verified(&mut out, &cancel, &mut context, |c| session.check_source(c)).unwrap_err();
            assert_eq!(error.accepted_output_bytes(), limit as u64);
            assert_eq!(out.accepted, limit);
            assert_eq!(out.file.metadata().unwrap().len(), limit as u64);
            assert!(matches!(error.operation(), Some(ReadFault::Io { operation: ReadIoOperation::Write, error, .. })
                if error.kind() == std::io::ErrorKind::BrokenPipe));
            assert_eq!(error.is_source_changed(), changed);
            assert_eq!(context.run_usage().live_spool_bytes, 0);
        }
    }
}
#[test]
fn unbound_checked_source_observation_keeps_incumbent_behavior() {
    use std::io::Write;
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"")], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let mut session = ProjectedReadSession::open(source.path(), &Cancellation::default()).unwrap();
    let mut context = EncryptedReadContext::new(Default::default()).unwrap();
    session.check_source(&mut context).unwrap();
}

#[test]
fn shared_namespace_does_not_retry_ambiguous_create() {
    let (ledger, _) = super::spool::ledger(0);
    let cancel = Cancellation::default();
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let observed = calls.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, _| {
            if op == ReadIoOperation::Create {
                observed.set(observed.get() + 1);
                Some(std::io::ErrorKind::Interrupted.into())
            } else {
                None
            }
        }))
    });
    let result = spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel);
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    let error = result.err().unwrap();
    assert_eq!(calls.get(), 1, "ambiguous creation must not acquire another name");
    assert!(matches!(error.operation(), Some(ReadFault::Io { operation: ReadIoOperation::Create, error, .. })
        if error.kind() == std::io::ErrorKind::Interrupted));
}

#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn stdout_preparation_freezes_the_actual_descriptor() {
    use std::os::fd::AsFd;
    let cancel = Cancellation::default();
    let (_source, mut session, mut context, mut stage, original) = stdout_stage(b"data");
    session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
    let mut other = tempfile::tempfile().unwrap();
    let _ = session.admit_output_fd(other.as_fd(), &mut context);
    let error = stage.copy_verified(&mut other, &cancel, &mut context, |c| session.check_source(c)).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(original.metadata().unwrap().len(), 0);
    assert_eq!(other.metadata().unwrap().len(), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_full_birth_path_limit_refuses_before_create_attempt() {
    let root = tempfile::tempdir().unwrap();
    let mut parent = root.path().to_owned();
    while parent.as_os_str().as_bytes().len() + 201 < 1000 {
        parent.push("p".repeat(200));
    }
    let remaining = 1000 - parent.as_os_str().as_bytes().len() - 1;
    parent.push("p".repeat(remaining));
    std::fs::create_dir_all(&parent).unwrap();
    let (ledger, _) = super::spool::ledger(0);
    let cancel = Cancellation::default();
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(&parent), &cancel).unwrap();
    let calls = std::rc::Rc::new(std::cell::Cell::new(0));
    let observed = calls.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, _| {
            if op == ReadIoOperation::Create {
                observed.set(observed.get() + 1);
            }
            None
        }))
    });
    let result = spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel);
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    let error = result.err().unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Io { operation: ReadIoOperation::Create, error, .. })
        if error.raw_os_error() == Some(libc::ENAMETOOLONG)));
    assert_eq!(calls.get(), 0);
    assert_eq!(ledger.with_state(|s| s.run.usage.live_spool_bytes), 0);
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn atomic_abi_matches_installed_sdk_headers() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("abi.c");
    let binary = root.path().join("abi");
    std::fs::write(
        &source,
        br#"#define _DARWIN_C_SOURCE 1
#include <sys/acl.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <stddef.h>
#include <stdio.h>
int main(void) {
 printf("%zu %zu %zu %zu %u %u %u %u\n", (size_t)KAUTH_FILESEC_SIZE(0),
  _Alignof(struct kauth_filesec), offsetof(struct kauth_filesec,fsec_acl.acl_entrycount),
  offsetof(struct kauth_filesec,fsec_acl.acl_flags), (unsigned)KAUTH_UID_NONE,
  (unsigned)KAUTH_GID_NONE, (unsigned)MNT_IGNORE_OWNERSHIP, (unsigned)MNT_UNKNOWNPERMISSIONS);
 return 0;
}
"#,
    )
    .unwrap();
    let result = std::process::Command::new("/usr/bin/cc")
        .args(["-std=gnu11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let result = std::process::Command::new(binary).output().unwrap();
    assert!(result.status.success());
    let values = String::from_utf8(result.stdout)
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse::<usize>().unwrap())
        .collect::<Vec<_>>();
    let (size, align, entries, flags, none) = native_policy::atomic_abi_layout();
    assert_eq!(values, [size, align, entries, flags, none as usize, none as usize, 0x00200000, 0x00200000]);
}

#[cfg(target_os = "macos")]
#[test]
fn native_acl_parser_rejects_malformed_or_deferred_security() {
    let mut bytes = [0u8; 56];
    bytes[0..4].copy_from_slice(&56u32.to_ne_bytes());
    bytes[4..8].copy_from_slice(&8u32.to_ne_bytes());
    bytes[8..12].copy_from_slice(&44u32.to_ne_bytes());
    bytes[12..16].copy_from_slice(&0x012cc16du32.to_ne_bytes());
    assert_eq!(native_policy::parse_mac_acl(&bytes).unwrap().unwrap().len(), 44);
    for (offset, bad) in [(0, 57u32), (4, u32::MAX), (8, 43), (12, 0), (48, 129), (52, 1 << 16)] {
        let mut altered = bytes;
        altered[offset..offset + 4].copy_from_slice(&bad.to_ne_bytes());
        assert!(native_policy::parse_mac_acl(&altered).is_err(), "field {offset}");
    }
    bytes[48..52].copy_from_slice(&u32::MAX.to_ne_bytes());
    assert!(native_policy::parse_mac_acl(&bytes).unwrap().is_none());
    for n in 0..56 {
        assert!(native_policy::parse_mac_acl(&bytes[..n]).is_err());
    }
}

#[test]
fn controlled_sink_admission_failure_poison_stops_later_payload() {
    let cancel = Cancellation::default();
    let (_source, mut session, mut context, mut stage, _out) = stdout_stage(b"data");
    assert!(stage.write_all(b"oversized", &cancel).is_err());
    assert!(context.ledger.with_state(|s| s.poisoned));
    assert!(
        session
            .read_at_with_context(0, None, 100, &cancel, &mut context, |_| panic!(
                "poison must refuse before payload callback"
            ))
            .is_err()
    );
    assert_eq!(context.run_usage().source_seeks, 0);
    let _ = stage.finish_error(ReadFault::InvalidPlan.into(), &mut context);
}

#[cfg(target_os = "macos")]
#[test]
fn native_acl_writeback_preserves_actual_parent_creation_policy_and_absence() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write,file_inherit,directory_inherit"])
            .arg(root.path())
            .status()
            .unwrap()
            .success()
    );
    let parent = File::open(root.path()).unwrap();
    let spelling = CString::new(root.path().as_os_str().as_bytes()).unwrap();
    let ordinary = std::fs::OpenOptions::new().write(true).create_new(true).open(root.path().join("probe")).unwrap();
    let mut scratch = vec![0u8; 65536];
    let captured = native_policy::read_acl(ordinary.as_raw_fd(), false, &mut scratch).unwrap().unwrap().to_vec();
    let file =
        unsafe { File::from_raw_fd(native_policy::atomic_file(parent.as_raw_fd(), &spelling, c"stage").unwrap()) };
    native_policy::prepare_acl_write(Some(&captured), &mut scratch).unwrap().apply(file.as_raw_fd()).unwrap();
    assert_eq!(native_policy::read_acl(file.as_raw_fd(), false, &mut scratch).unwrap().unwrap(), captured);
    native_policy::prepare_acl_write(None, &mut scratch).unwrap().apply(file.as_raw_fd()).unwrap();
    assert!(native_policy::read_acl(file.as_raw_fd(), false, &mut scratch).unwrap().is_none());
}

#[test]
fn dropping_controlled_stage_inside_a_callback_stops_buffered_decoder_progress() {
    use std::io::Write;
    use std::os::fd::AsFd;
    let data = vec![b'x'; 200000];
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&data).unwrap();
    let packed = encoder.finish().unwrap();
    let mut member = fixture::Member::stored(b"entry", &packed);
    member.method = 8;
    member.decoded = Some(&data);
    let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let out = tempfile::tempfile().unwrap();
    session.admit_output_fd(out.as_fd(), &mut context).unwrap();
    let mut stage = Some(ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).unwrap());
    let mut callbacks = 0;
    let result = session.read_at_with_context(0, None, 300000, &cancel, &mut context, |_| {
        callbacks += 1;
        if callbacks == 1 {
            drop(stage.take());
        }
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(callbacks, 1, "poison must stop even when compressed input is already buffered");
    assert!(context.ledger.with_state(|s| s.poisoned));
}

#[test]
fn original_relative_projection_matches_incumbent_sanitization_without_allocation() {
    for name in
        ["foo/bar", "foo\\bar", "./C:/thing", "C:/thing", "a//./b", "", ".", "a/../b", "/abs", "\\abs", "a?b", "a\0b"]
    {
        for windows in [false, true] {
            match crate::path::sanitize(name, windows) {
                Ok(relative) => {
                    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(true));
                    let result = output::sanitized_matches(name, windows, &relative);
                    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(false));
                    assert!(result.is_ok(), "{name:?} windows={windows}");
                    assert!(output::sanitized_matches(name, windows, Path::new("foreign")).is_err());
                }
                Err(_) => assert!(output::sanitized_matches(name, windows, Path::new("foreign")).is_err()),
            }
        }
    }
}

#[test]
fn statically_ineligible_stdout_reports_original_cap_without_temp_acquisition() {
    use std::io::Write;
    use std::os::fd::AsFd;
    let mut member = fixture::Member::stored(b"entry", b"1234567890123456");
    member.flags = 1;
    let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let overrides = EncryptedReadOverrides { member_packed_bytes: Some(0), ..Default::default() };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::VerifiedStdout,
        None,
        &overrides,
        &cancel,
    )
    .unwrap();
    assert!(context.temp.is_none());
    let out = tempfile::tempfile().unwrap();
    session.admit_output_fd(out.as_fd(), &mut context).unwrap();
    let result = ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context);
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("known packed cap must refuse before storage"),
    };
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::MemberPackedBytes, .. })));
    assert_eq!(context.run_usage().temporary_groups, 0);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn file_binding_rejects_foreign_tuple_before_effects_and_borrows_operational_name() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let destination = std::fs::canonicalize(root.path()).unwrap();
    let mut member = fixture::Member::stored(b"dir/test?.txt", b"data");
    member.made_by = 0x0014;
    let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination: &destination },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let mut options = crate::extract::Options {
        mode: crate::extract::Mode::Extract,
        dest: destination.clone(),
        overwrite: crate::extract::Overwrite::Always,
        flatten: true,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let before = context.run_usage();
    assert!(session.stage_entry(0).unwrap().bind_file(Path::new("foreign"), &options, &cancel, &mut context).is_err());
    assert_eq!(context.run_usage(), before);
    assert!(!context.ledger.with_state(|s| s.poisoned));
    options.dest = destination.join("other");
    assert!(
        session.stage_entry(0).unwrap().bind_file(Path::new("dir/test_.txt"), &options, &cancel, &mut context).is_err()
    );
    assert_eq!(context.run_usage(), before);
    options.dest = destination;
    let prepared =
        session.stage_entry(0).unwrap().bind_file(Path::new("dir/test_.txt"), &options, &cancel, &mut context).unwrap();
    assert_eq!(prepared.relative, Path::new("test_.txt"));
    assert_eq!(prepared.bytes, 4);
    assert!(!prepared.encrypted);
    assert!(
        session.stage_entry(0).unwrap().bind_file(Path::new("dir/test_.txt"), &options, &cancel, &mut context).is_err()
    );
    assert_eq!(session.entries().next().unwrap().name, "dir/test?.txt");
}

#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn normal_stdout_close_admission_stays_primary_after_successful_emergency_close() {
    let cancel = Cancellation::default();
    let (_source, mut session, mut context, mut stage, mut out) = stdout_stage(b"data");
    session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
    let mut boundaries = 0;
    let result = stage.copy_verified(&mut out, &cancel, &mut context, |c| {
        session.check_source(c)?;
        boundaries += 1;
        if boundaries == 2 {
            c.ledger.with_state(|s| {
                let remaining = s.run_bounds().stage_finalization - s.run.usage.stage_finalization;
                s.charge_category(RunCategory::StageFinalization, remaining).unwrap();
            });
        }
        Ok(())
    });
    let error = result.unwrap_err();
    assert!(matches!(
        error.operation(),
        Some(ReadFault::Limit { resource: ReadResource::Run(RunCategory::StageFinalization), .. })
    ));
    assert_eq!(error.accepted_output_bytes(), 4);
    assert_eq!(out.metadata().unwrap().len(), 4);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
    assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
}

#[test]
fn required_default_mode_and_best_effort_archive_errno_preserve_incumbent_baseline() {
    use output::metadata::{MetadataPlan, MetadataStep};
    let root = tempfile::tempdir().unwrap();
    let parent = File::open(root.path()).unwrap();
    let path = CString::new(root.path().as_os_str().as_bytes()).unwrap();
    let probe = std::fs::OpenOptions::new().write(true).create_new(true).open(root.path().join("probe")).unwrap();
    let baseline = native_policy::stat(probe.as_raw_fd()).unwrap().st_mode as u32 & 0o777;
    for failed in [MetadataStep::BaselineMode, MetadataStep::ArchiveMode] {
        let leaf = if failed == MetadataStep::BaselineMode { c"baseline" } else { c"archive" };
        let file = unsafe { File::from_raw_fd(native_policy::atomic_file(parent.as_raw_fd(), &path, leaf).unwrap()) };
        let stat = native_policy::stat(file.as_raw_fd()).unwrap();
        let (ledger, _) = super::spool::ledger(0);
        let cancel = Cancellation::default();
        let mut scratch = vec![0u8; 65536];
        output::metadata::HOOK.with(|state| {
            *state.borrow_mut() =
                Some(Box::new(
                    move |step| {
                        if step == failed { Some(std::io::Error::from_raw_os_error(libc::EPERM)) } else { None }
                    },
                ))
        });
        let result = output::metadata::restore(
            &ledger,
            false,
            &file,
            &MetadataPlan {
                identity: FileIdentity { dev: stat.st_dev as u64, ino: stat.st_ino as u64 },
                uid: stat.st_uid,
                gid: stat.st_gid,
                bytes: 0,
                baseline,
                mode: Some(0o400),
                mtime: Some((-1, 500000000)),
                acl: None,
            },
            &mut scratch,
            &cancel,
        );
        output::metadata::HOOK.with(|state| *state.borrow_mut() = None);
        if failed == MetadataStep::BaselineMode {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
            assert_eq!(native_policy::stat(file.as_raw_fd()).unwrap().st_mode as u32 & 0o777, baseline);
        }
    }
}

#[test]
fn controlled_source_reservation_is_once_borrowed_and_precedes_storage() {
    use std::io::Write;
    use std::os::fd::AsFd;
    for limit in [0, 1, 2, 3, 5] {
        let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
        let options = EncryptedReadOverrides::default();
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::VerifiedStdout,
            None,
            &options,
            &cancel,
        )
        .unwrap();
        assert_eq!(
            context.ledger.with_state(|s| s.live_fds),
            0,
            "raw catalogue context has no owned source reservation"
        );
        context.ledger.with_state(|s| s.encrypted.limits.live_fds = limit);
        let out = tempfile::tempfile().unwrap();
        session.admit_output_fd(out.as_fd(), &mut context).unwrap();
        let result = ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context);
        if limit < 3 {
            let error = result.err().unwrap();
            assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::LiveFds, .. })));
            assert_eq!(context.run_usage().temporary_groups, 0);
            assert_eq!(context.ledger.with_state(|s| s.live_fds), u64::from(limit > 0));
        } else {
            let stage = result.unwrap();
            assert_eq!(context.ledger.with_state(|s| s.live_fds), 2);
            let before = context.ledger.with_state(|s| s.live_fds);
            assert!(ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).is_err());
            assert_eq!(context.ledger.with_state(|s| s.live_fds), before);
            drop(stage);
            assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
        }
        // Ending action accounting never retires the caller's original File.
        drop(context);
        assert!(source.as_file().metadata().is_ok());
        assert_eq!(session.entries().next().unwrap().size, 4);
    }
}

#[test]
fn held_parent_accepts_configured_root_alias_and_refuses_archive_relative_symlink() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let alias = root.path().join("alias");
    symlink(&real, &alias).unwrap();
    for relative in [Path::new("new/sub/file"), Path::new("escape/file")] {
        let mut state = budget::LedgerState::new(&Default::default()).unwrap();
        super::core::bind_plan(
            &mut state,
            budget::ActionPlan::derive(
                budget::PlanGeometry {
                    records: 1,
                    regular: 1,
                    path_bytes: 4096,
                    output_passes: 1,
                    ..Default::default()
                },
                16,
                16,
            )
            .unwrap(),
        );
        state.acquire_fds(2).unwrap();
        let ledger = shared::ContextLedger::try_new(state).unwrap();
        if relative.starts_with("escape") {
            symlink(&real, real.join("escape")).unwrap();
        }
        let result = output::parent::open_parent(&ledger, &alias, relative, Path::new("/"), &Cancellation::default());
        if relative.starts_with("escape") {
            assert!(result.is_err());
        } else {
            let held = result.unwrap();
            assert!(real.join("new/sub").is_dir());
            held.finish(&ledger).unwrap();
        }
        assert_eq!(ledger.with_state(|s| s.live_fds), 1);
        assert_eq!(ledger.with_state(|s| s.policy_metadata.caller.live_capacity), 0);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn private_directory_control(mask: Option<libc::mode_t>) {
    use shared::LedgerAccess;
    let root = tempfile::tempdir().unwrap();
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    super::core::bind_plan(
        &mut state,
        budget::ActionPlan::derive(
            budget::PlanGeometry { records: 1, regular: 1, path_bytes: 4096, output_passes: 1, ..Default::default() },
            16,
            16,
        )
        .unwrap(),
    );
    state.bind_policy_geometry(Default::default()).unwrap();
    state.acquire_fds(2).unwrap();
    let ledger = shared::ContextLedger::try_new(state).unwrap();
    let cancel = Cancellation::default();
    let parent =
        output::parent::open_parent(&ledger, root.path(), Path::new("target"), Path::new("/"), &cancel).unwrap();
    let mut scratch = policy::PolicyScratch::new(ledger.view()).unwrap();
    struct Restore(Option<libc::mode_t>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(mask) = self.0 {
                unsafe { libc::umask(mask) };
            }
        }
    }
    let restore = Restore(mask.map(|mask| unsafe { libc::umask(mask) }));
    let mut directory = output::directory::PrivateDirectory::create(
        &ledger,
        &parent,
        false,
        unsafe { libc::geteuid() },
        false,
        &mut scratch,
        &cancel,
    )
    .unwrap();
    assert_eq!(ledger.with_state(|s| s.live_fds), 3);
    let stat = native_policy::stat(directory.file.as_ref().unwrap().as_raw_fd()).unwrap();
    assert_eq!(stat.st_mode & 0o777, 0o700);
    #[cfg(target_os = "macos")]
    assert!(native_policy::private_acl(directory.file.as_ref().unwrap().as_raw_fd(), &mut scratch).unwrap());
    directory.close_before_payload(&ledger, false).unwrap();
    assert_eq!(ledger.with_state(|s| s.live_fds), 2);
    assert!(ledger.with_state(|s| s.run.usage.output_directory_operations) <= 11);
    drop(restore);
    directory.retire_empty(&ledger, &parent, false).unwrap();
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    parent.finish(&ledger).unwrap();
    assert_eq!(ledger.with_state(|s| s.live_fds), 1);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn private_directory_is_atomic_empty_and_retires_after_pre_payload_close() {
    private_directory_control(None);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn private_directory_restrictive_umask_child() {
    if std::env::var_os("ZIPFAST_PRIVATE_DIRECTORY_UMASK_CHILD").is_none() {
        return;
    }
    for mask in [0, 0o077, 0o777] {
        private_directory_control(Some(mask));
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn private_directory_restrictive_umask_is_process_isolated() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "zip::read::tests::output::private_directory_restrictive_umask_child", "--nocapture"])
        .env("ZIPFAST_PRIVATE_DIRECTORY_UMASK_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn empty_named_stage_moves_inside_private_directory_before_plaintext() {
    use shared::LedgerAccess;
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let cancel = Cancellation::default();
    let mut state = budget::LedgerState::new(&Default::default()).unwrap();
    super::core::bind_plan(
        &mut state,
        budget::ActionPlan::derive(
            budget::PlanGeometry {
                records: 1,
                regular: 1,
                path_bytes: 4096,
                decoded: 4,
                live_spool: 4,
                output_passes: 1,
                ..Default::default()
            },
            16,
            16,
        )
        .unwrap(),
    );
    state.bind_policy_geometry(Default::default()).unwrap();
    state.acquire_fds(1).unwrap();
    state.reserve(false, 4, 2).unwrap();
    let ledger = shared::ContextLedger::try_new(state).unwrap();
    let parent =
        output::parent::open_parent(&ledger, root.path(), Path::new("target"), Path::new("/"), &cancel).unwrap();
    let mut scratch = policy::PolicyScratch::new(ledger.view()).unwrap();
    let (snapshot, child) =
        policy::probe(&ledger, &parent.file, unsafe { libc::geteuid() }, true, &mut scratch, &cancel).unwrap();
    let mut directory =
        output::directory::PrivateDirectory::create(&ledger, &parent, false, child.uid, true, &mut scratch, &cancel)
            .unwrap();
    let mut group = io::CreationGroup::new(&ledger, false, IoStage::Output, &cancel).unwrap();
    let mut stage = output::named::NamedFile::create_and_place(
        &ledger,
        &parent,
        &directory,
        &snapshot,
        &child,
        false,
        4,
        true,
        &mut group,
        &mut scratch,
        &cancel,
    )
    .unwrap();
    assert!(!root.path().join("target").exists());
    assert_eq!(stage.file.as_ref().unwrap().metadata().unwrap().len(), 0);
    directory.close_before_payload(&ledger, false).unwrap();
    snapshot.finish(&ledger).unwrap();
    assert_eq!(ledger.with_state(|s| s.live_fds), 3);
    stage.file.as_mut().unwrap().write_all(b"data").unwrap();
    ledger.with_state(|s| s.poisoned = true);
    directory.reopen_cleanup(&ledger, &parent).unwrap();
    let (clear, report) = stage.retire(&ledger, &parent, &directory, false);
    assert!(clear);
    assert!(report.is_empty());
    ledger.with_state(|s| s.release_bytes(false, 4));
    directory.retire_empty(&ledger, &parent, false).unwrap();
    child.finish(&ledger).unwrap();
    drop(scratch);
    parent.finish(&ledger).unwrap();
    assert_eq!(ledger.with_state(|s| s.live_fds), 1);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[cfg(target_os = "macos")]
#[test]
fn original_file_stage_is_private_during_fill_and_finish_error_preserves_prior_target() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("entry");
    std::fs::write(&target, b"prior").unwrap();
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let options = crate::extract::Options {
        dest: root.path().to_owned(),
        overwrite: crate::extract::Overwrite::Always,
        mode: crate::extract::Mode::Extract,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination: root.path() },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let mut stage = ZipReadStage::prepare_file(
        session.stage_entry(0).unwrap(),
        Path::new("entry"),
        &options,
        &cancel,
        &mut context,
    )
    .unwrap()
    .unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"prior");
    session.read_at_with_context(0, None, 100, &cancel, &mut context, |bytes| stage.write_all(bytes, &cancel)).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"prior");
    let error = stage.finish_error(ReadFault::InvalidPlan.into(), &mut context);
    assert!(error.operation().is_some());
    assert_eq!(std::fs::read(&target).unwrap(), b"prior");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
}

#[cfg(target_os = "macos")]
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn original_file_publication_requires_completion_and_two_fresh_source_observations() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("entry");
    std::fs::write(&target, b"prior").unwrap();
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let options = crate::extract::Options {
        dest: root.path().to_owned(),
        overwrite: crate::extract::Overwrite::Always,
        mode: crate::extract::Mode::Extract,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination: root.path() },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let original = session.entries().next().unwrap();
    let mode = original.unix_mode();
    let mtime = original.mtime.map(|seconds| (seconds, original.nanos));
    let mut stage = ZipReadStage::prepare_file(
        session.stage_entry(0).unwrap(),
        Path::new("entry"),
        &options,
        &cancel,
        &mut context,
    )
    .unwrap()
    .unwrap();
    session.read_at_with_context(0, None, 100, &cancel, &mut context, |bytes| stage.write_all(bytes, &cancel)).unwrap();
    let mut checks = 0;
    let before = context.run_usage().stage_finalization;
    assert!(
        stage
            .publish(mode, mtime, &cancel, &mut context, |c| {
                checks += 1;
                session.check_source(c)
            })
            .unwrap()
    );
    assert_eq!(context.run_usage().stage_finalization - before, 19);
    assert_eq!(checks, 2);
    assert_eq!(std::fs::read(&target).unwrap(), b"data");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
    assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct FileFixture {
    stage: ZipReadStage,
    session: ProjectedReadSession,
    context: EncryptedReadContext,
    mode: Option<u32>,
    mtime: Option<(i64, u32)>,
    _source: tempfile::NamedTempFile,
    root: tempfile::TempDir,
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn file_fixture(overwrite: crate::extract::Overwrite, prior: Option<&[u8]>) -> FileFixture {
    file_fixture_ready(overwrite, prior, true)
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn file_fixture_ready(overwrite: crate::extract::Overwrite, prior: Option<&[u8]>, read: bool) -> FileFixture {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    if let Some(prior) = prior {
        std::fs::write(root.path().join("entry"), prior).unwrap();
    }
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let options = crate::extract::Options {
        dest: root.path().to_owned(),
        overwrite,
        mode: crate::extract::Mode::Extract,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination: root.path() },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let entry = session.entries().next().unwrap();
    let mode = entry.unix_mode();
    let mtime = entry.mtime.map(|s| (s, entry.nanos));
    let mut stage = ZipReadStage::prepare_file(
        session.stage_entry(0).unwrap(),
        Path::new("entry"),
        &options,
        &cancel,
        &mut context,
    )
    .unwrap()
    .unwrap();
    if read {
        session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
    } else {
        stage.write_all(b"data", &cancel).unwrap();
    }
    FileFixture { stage, session, context, mode, mtime, _source: source, root }
}
#[cfg(target_os = "macos")]
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn named_publication_each_of_nineteen_native_boundaries_preserves_status_and_one_close() {
    use std::cell::Cell;
    use std::rc::Rc;
    for fail in 1..=19 {
        let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
        let count = Rc::new(Cell::new(0));
        let calls = count.clone();
        let unresolved = Rc::new(Cell::new(false));
        let observed = unresolved.clone();
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, fd| {
                calls.set(calls.get() + 1);
                if calls.get() != fail {
                    return None;
                }
                if op == ReadIoOperation::Close {
                    assert_eq!(unsafe { libc::close(fd) }, 0);
                    observed.set(true);
                    Some(std::io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Some(std::io::Error::from_raw_os_error(libc::EIO))
                }
            }))
        });
        let result =
            fixture.stage.publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                fixture.session.check_source(c)
            });
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        assert!(count.get() >= fail, "boundary {fail}");
        if [5, 9].contains(&fail) {
            assert!(result.unwrap(), "optional metadata errno at {fail}");
        } else {
            let error = result.unwrap_err();
            assert_eq!(
                error.publication_state(),
                if fail >= 16 {
                    PublicationState::Published
                } else if fail == 15 {
                    PublicationState::Unknown
                } else {
                    PublicationState::NotPublished
                },
                "boundary {fail}"
            );
        }
        assert_eq!(
            std::fs::read(fixture.root.path().join("entry")).unwrap(),
            if fail >= 16 || [5, 9].contains(&fail) { b"data".as_slice() } else { b"prior".as_slice() },
            "boundary {fail}"
        );
        assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1, "boundary {fail}");
        assert_eq!(
            fixture.context.ledger.with_state(|s| s.live_fds),
            1 + u64::from(unresolved.get()),
            "boundary {fail}"
        );
        assert_eq!(fixture.context.run_usage().live_spool_bytes, if fail == 11 { 4 } else { 0 }, "boundary {fail}");
    }
}

#[cfg(target_os = "macos")]
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn actual_original_named_aes_pipeline_has_five_reserved_fds_and_one_under_refuses_before_cipher_birth() {
    use std::io::Write;
    for limit in [4, 5] {
        let plain = vec![b'x'; 65537];
        let frame = super::cipher::framed(1, "pw", &plain);
        let extra = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
        let mut member = fixture::Member::stored(b"entry", &frame);
        member.method = 99;
        member.flags = 1;
        member.decoded = Some(&plain);
        member.central_extra = &extra;
        let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("entry"), b"prior").unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
        let options = crate::extract::Options {
            dest: root.path().to_owned(),
            overwrite: crate::extract::Overwrite::Always,
            mode: crate::extract::Mode::Extract,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        let overrides = EncryptedReadOverrides { temp_dir: Some(temporary.path().to_owned()), ..Default::default() };
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            Some(100000),
            ZipReadOutput::StagedFiles { destination: root.path() },
            Some("pw"),
            &overrides,
            &cancel,
        )
        .unwrap();
        context.ledger.with_state(|s| s.encrypted.limits.live_fds = limit);
        let entry = session.entries().next().unwrap();
        let mode = entry.unix_mode();
        let mtime = entry.mtime.map(|s| (s, entry.nanos));
        let mut stage = ZipReadStage::prepare_file(
            session.stage_entry(0).unwrap(),
            Path::new("entry"),
            &options,
            &cancel,
            &mut context,
        )
        .unwrap()
        .unwrap();
        assert_eq!(context.ledger.with_state(|s| s.live_fds), 3);
        let creates = std::rc::Rc::new(std::cell::Cell::new(0));
        let calls = creates.clone();
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, _| {
                if op == ReadIoOperation::Create {
                    calls.set(calls.get() + 1);
                }
                None
            }))
        });
        let mut callbacks = 0;
        let result = session.read_at_with_context(0, Some("pw"), 100000, &cancel, &mut context, |b| {
            callbacks += 1;
            stage.write_all(b, &cancel)
        });
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        if limit == 5 {
            result.unwrap();
            assert!(callbacks > 0);
            assert_eq!(creates.get(), 1);
            assert_eq!(context.ledger.with_state(|s| s.peak_fds), 5);
            assert!(stage.publish(mode, mtime, &cancel, &mut context, |c| session.check_source(c)).unwrap());
            assert_eq!(std::fs::read(root.path().join("entry")).unwrap(), plain);
        } else {
            let error = result.unwrap_err();
            assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::LiveFds, .. })));
            assert_eq!(callbacks, 0);
            assert_eq!(creates.get(), 0);
            let _ = stage.finish_error(error, &mut context);
            assert_eq!(std::fs::read(root.path().join("entry")).unwrap(), b"prior");
            assert_eq!(context.ledger.with_state(|s| s.peak_fds), 4);
        }
        assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
        assert_eq!(context.run_usage().live_spool_bytes, 0);
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn actual_named_cipher_unresolved_pair_refuses_cleanup_reopen_and_retains_u_without_allocation() {
    use std::io::Write;
    let plain = vec![b'x'; 65537];
    let frame = super::cipher::framed(1, "pw", &plain);
    let extra = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut member = fixture::Member::stored(b"entry", &frame);
    member.method = 99;
    member.flags = 1;
    member.decoded = Some(&plain);
    member.central_extra = &extra;
    let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("entry"), b"prior").unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let options = crate::extract::Options {
        dest: root.path().to_owned(),
        overwrite: crate::extract::Overwrite::Always,
        mode: crate::extract::Mode::Extract,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let overrides = EncryptedReadOverrides { temp_dir: Some(temporary.path().to_owned()), ..Default::default() };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        Some(100000),
        ZipReadOutput::StagedFiles { destination: root.path() },
        Some("pw"),
        &overrides,
        &cancel,
    )
    .unwrap();
    let mut stage = ZipReadStage::prepare_file(
        session.stage_entry(0).unwrap(),
        Path::new("entry"),
        &options,
        &cancel,
        &mut context,
    )
    .unwrap()
    .unwrap();
    let count = std::rc::Rc::new(std::cell::Cell::new(0));
    let closes = count.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, fd| {
            if op == ReadIoOperation::Close && closes.get() < 2 {
                closes.set(closes.get() + 1);
                assert_eq!(unsafe { libc::close(fd) }, 0);
                Some(std::io::Error::from_raw_os_error(libc::EINTR))
            } else {
                None
            }
        }))
    });
    let mut callbacks = 0;
    let error = session
        .read_at_with_context(0, Some("pw"), 100000, &cancel, &mut context, |b| {
            callbacks += 1;
            stage.write_all(b, &cancel)
        })
        .unwrap_err();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert_eq!(count.get(), 2);
    assert_eq!(callbacks, 0);
    assert_eq!(context.ledger.with_state(|s| s.live_fds), 5);
    let count = std::rc::Rc::new(std::cell::Cell::new(0));
    let opens = count.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, _| {
            if op == ReadIoOperation::Open {
                opens.set(opens.get() + 1);
            }
            None
        }))
    });
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let error = stage.finish_error(error, &mut context);
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(false));
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert_eq!(count.get(), 0);
    assert_eq!(error.publication_state(), PublicationState::NotPublished);
    assert!(
        error.cleanup_errors().any(|f| matches!(
            f.cause,
            CleanupCause::Admission(ReadFault::Limit { resource: ReadResource::LiveFds, .. })
        ))
    );
    assert_eq!(context.ledger.with_state(|s| s.peak_fds), 5);
    assert_eq!(context.ledger.with_state(|s| s.live_fds), 3);
    assert_eq!(context.run_usage().live_spool_bytes, 2 * plain.len() as u128);
    assert_eq!(std::fs::read(root.path().join("entry")).unwrap(), b"prior");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2, "unresolved private namespace remains accounted");
    // The test harness's TempDir teardown is external fixture cleanup, not an
    // engine success or an assertion that an ambiguous close was resolved.
}

#[cfg(target_os = "macos")]
#[test]
fn named_stage_phase_control_includes_held_namespace_and_native_birth_frames() {
    let s = output::control_layout();
    let c = codecs::control_layout();
    let e = std::mem::size_of::<ZipReadError>();
    let r = std::mem::size_of::<ObjectCleanupReport>();
    let fault_values = 2 * e + 2 * r;
    let native_stat = std::mem::size_of::<libc::stat>();
    let backend = std::mem::size_of::<libc::statfs>();
    // Distinct phases never hold codec engine/input and prepayload backend birth
    // frames together. Account every owning stage/preparation type explicitly;
    // its nested child types are measured below rather than counted twice.
    let decode = fault_values + c[..6].iter().sum::<usize>() + s[0] + 22 + 512;
    let cipher_birth = fault_values + c[2] + c[3] + c[4] + s[0] + backend.max(1024 + 44) + 512;
    let preparing = 2 * e.max(s[10]).max(s[11])
        + 2 * r
        + s[2]
        + s[3]
        + s[4]
        + s[9]
        + backend.max(3 * native_stat + 1024 + 44)
        + 512;
    let publication = fault_values + s[0] + s[8] + s[9] + 3 * native_stat + 512;
    let max = decode.max(cipher_birth).max(preparing).max(publication);
    eprintln!(
        "named_stage/prepared/preparing/entry/binding/parent/directory/inode/metadata/scratch/dirfailure/filefailure={s:?} native_stat={native_stat} backend={backend} decode={decode} cipher_birth={cipher_birth} preparing={preparing} publication={publication} max={max}"
    );
    assert!(max <= 16384);
    assert_eq!(shared::SHARED_LEDGER_CAPACITY, 1904);
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::result_large_err)] // Exercises fixed5120-byte allocator-independent production terminal evidence.
fn linux_real_original_named_stage_publication_uses_eighteen_final_calls() {
    let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
    let before = fixture.context.run_usage().stage_finalization;
    let mut checks = 0;
    assert!(
        fixture
            .stage
            .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                checks += 1;
                fixture.session.check_source(c)
            })
            .unwrap()
    );
    assert_eq!(checks, 2);
    assert_eq!(fixture.context.run_usage().stage_finalization - before, 18);
    assert_eq!(
        fixture.context.run_usage().canonical_metadata_operations,
        22,
        "original held-source6 plus initial/final target8 each"
    );
    assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"data");
    assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
    assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
    assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
}
#[cfg(target_os = "linux")]
#[test]
fn linux_canonical_cleanup_inline_representation_stays_in_phase_control() {
    let s = output::control_layout();
    let error = std::mem::size_of::<ZipReadError>();
    let canonical = std::mem::size_of::<policy::CanonicalFailure>();
    let reports = 2 * std::mem::size_of::<ObjectCleanupReport>();
    let fault_values = 2 * error.max(canonical).max(s[10]).max(s[11]) + reports;
    let phase = fault_values + s[2] + s[3] + s[4] + s[9] + std::mem::size_of::<libc::statfs>() + 512;
    eprintln!("Linux stage layout={s:?} error={error} canonical={canonical} preparing_control={phase}");
    assert!(phase <= 16384);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Same fixed allocator-independent protocol evidence under test.
fn named_publication_rejects_written_u_without_original_input_completion_before_metadata() {
    let mut fixture = file_fixture_ready(crate::extract::Overwrite::Always, Some(b"prior"), false);
    let mut checks = 0;
    let error = fixture
        .stage
        .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
            checks += 1;
            fixture.session.check_source(c)
        })
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(checks, 0);
    assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
    assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
    assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
    assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Fixed terminal error preserves callback and owned-cleanup evidence.
fn named_source_boundaries_refuse_prior_noop_and_foreign_owner_observations() {
    for noop in [1, 2] {
        let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
        fixture.session.check_source(&mut fixture.context).unwrap(); // stale successful proof cannot be replayed.
        let mut checks = 0;
        let error = fixture
            .stage
            .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                checks += 1;
                if checks == noop { Ok(()) } else { fixture.session.check_source(c) }
            })
            .unwrap_err();
        assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
        assert_eq!(checks, noop);
        assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
        assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
        assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
        assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
    }
    let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
    let mut foreign = ProjectedReadSession::open(fixture._source.path(), &Cancellation::default()).unwrap();
    let error = fixture
        .stage
        .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
            foreign.check_source(c)
        })
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Actual post-metadata/post-close source faults stay inline through cleanup.
fn named_source_replacement_after_metadata_and_close_preserves_prior_target() {
    for change_at in [1, 2] {
        let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
        let len = fixture._source.as_file().metadata().unwrap().len();
        let mut checks = 0;
        let error = fixture
            .stage
            .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                checks += 1;
                if checks == change_at {
                    fixture._source.as_file().set_len(len - 1).unwrap();
                }
                fixture.session.check_source(c)
            })
            .unwrap_err();
        assert!(error.is_source_changed());
        assert_eq!(checks, change_at);
        assert_eq!(error.publication_state(), PublicationState::NotPublished);
        assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
        assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
        assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
        assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Ownership/action proof cannot be replaced by a successful foreign ledger observation.
fn named_dropped_owner_and_same_owner_new_action_cannot_authorize_publication() {
    let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
    drop(fixture.session);
    let error = fixture
        .stage
        .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |_| Ok(()))
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
    let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
    let mut replacement = Some(
        EncryptedReadContext::for_projected(
            &mut fixture.session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::StagedFiles { destination: fixture.root.path() },
            None,
            &Default::default(),
            &Cancellation::default(),
        )
        .unwrap(),
    );
    let error = fixture
        .stage
        .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
            *c = replacement.take().unwrap();
            fixture.session.check_source(c)
        })
        .unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
    assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
    assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Fixed inline operation/source/cleanup evidence through consuming publication.
fn no_clobber_collision_false_requires_clean_retirement_and_postcleanup_source_finality() {
    for invalidate in [false, true] {
        let mut fixture = file_fixture(crate::extract::Overwrite::Skip, None);
        let target = fixture.root.path().join("entry");
        let len = fixture._source.as_file().metadata().unwrap().len();
        let mut checks = 0;
        let result =
            fixture.stage.publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                checks += 1;
                if checks == 2 {
                    std::fs::write(&target, b"racer").unwrap();
                }
                if checks == 3 && invalidate {
                    fixture._source.as_file().set_len(len - 1).unwrap();
                }
                fixture.session.check_source(c)
            });
        assert_eq!(checks, 3);
        if invalidate {
            let error = result.unwrap_err();
            assert!(error.is_source_changed());
            assert_eq!(error.publication_state(), PublicationState::NotPublished);
        } else {
            assert!(!result.unwrap());
            assert!(!fixture.context.ledger.with_state(|s| s.poisoned));
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"racer");
        assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
        assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
        assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Refused normal close remains primary even when its emergency physical close succeeds.
fn named_pre_and_postpublication_normal_close_admission_remains_primary() {
    for after_publication in [false, true] {
        let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
        let mut checks = 0;
        let error = fixture
            .stage
            .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                fixture.session.check_source(c)?;
                checks += 1;
                if checks == if after_publication { 2 } else { 1 } {
                    c.ledger.with_state(|s| {
                        let remaining = s.run_bounds().stage_finalization - s.run.usage.stage_finalization;
                        s.charge_category(RunCategory::StageFinalization, remaining - u128::from(after_publication))
                            .unwrap();
                    });
                }
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            error.operation(),
            Some(ReadFault::Limit { resource: ReadResource::Run(RunCategory::StageFinalization), .. })
        ));
        assert_eq!(
            error.publication_state(),
            if after_publication { PublicationState::Published } else { PublicationState::NotPublished }
        );
        assert_eq!(
            std::fs::read(fixture.root.path().join("entry")).unwrap(),
            if after_publication { b"data".as_slice() } else { b"prior".as_slice() }
        );
        assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
        assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
        assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
    }
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // No original metadata tuple can be forged through a successful completed input.
fn wrong_original_metadata_tuple_refuses_before_any_metadata_setter_or_callback() {
    for wrong_time in [false, true] {
        let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
        let changed = std::rc::Rc::new(std::cell::Cell::new(0));
        let setters = changed.clone();
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, _| {
                if matches!(op, ReadIoOperation::SetAcl | ReadIoOperation::SetTime | ReadIoOperation::DescriptorMode) {
                    setters.set(setters.get() + 1);
                }
                None
            }))
        });
        let mode = if wrong_time { fixture.mode } else { None };
        let mtime = if wrong_time { fixture.mtime.map(|(s, n)| (s + 1, n)) } else { fixture.mtime };
        let mut checks = 0;
        let error = fixture
            .stage
            .publish(mode, mtime, &Cancellation::default(), &mut fixture.context, |c| {
                checks += 1;
                fixture.session.check_source(c)
            })
            .unwrap_err();
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        assert!(matches!(error.operation(), Some(ReadFault::InvalidPlan)));
        assert_eq!(changed.get(), 0);
        assert_eq!(checks, 0);
        assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
        assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
        assert_eq!(fixture.context.run_usage().live_spool_bytes, 0);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn empty_move_after_real_effect_eintr_checks_both_names_and_cleans_without_retry() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("entry"), b"prior").unwrap();
    let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let options = crate::extract::Options {
        dest: root.path().to_owned(),
        overwrite: crate::extract::Overwrite::Always,
        mode: crate::extract::Mode::Extract,
        flatten: false,
        threads: None,
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        None,
        ZipReadOutput::StagedFiles { destination: root.path() },
        None,
        &Default::default(),
        &cancel,
    )
    .unwrap();
    let path = root.path().to_owned();
    let count = std::rc::Rc::new(std::cell::Cell::new(0));
    let moves = count.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, fd| {
            if op != ReadIoOperation::Publish {
                return None;
            }
            moves.set(moves.get() + 1);
            let mut dir = None;
            let mut file = None;
            for entry in std::fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    dir = Some(entry.file_name());
                } else if entry.file_name() != "entry" {
                    file = Some(entry.file_name());
                }
            }
            let file = file.unwrap();
            assert_eq!(std::fs::metadata(path.join(&file)).unwrap().len(), 0);
            let from = CString::new(file.as_bytes()).unwrap();
            let to = CString::new(Path::new(&dir.unwrap()).join(&file).as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::renameat(fd, from.as_ptr(), fd, to.as_ptr()) }, 0);
            Some(std::io::Error::from_raw_os_error(libc::EINTR))
        }))
    });
    let error = ZipReadStage::prepare_file(
        session.stage_entry(0).unwrap(),
        Path::new("entry"),
        &options,
        &cancel,
        &mut context,
    )
    .err()
    .unwrap();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert_eq!(count.get(), 1);
    assert_eq!(error.publication_state(), PublicationState::NotPublished);
    assert!(
        matches!(error.operation(),Some(ReadFault::Io {operation:ReadIoOperation::Publish,error,..}) if error.kind()==std::io::ErrorKind::Interrupted)
    );
    assert_eq!(std::fs::read(root.path().join("entry")).unwrap(), b"prior");
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    assert_eq!(context.run_usage().live_spool_bytes, 0);
    assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
}
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Post-effect error keeps Unknown plus storage liability inline.
fn final_rename_after_real_effect_eintr_is_unknown_without_target_rollback_or_retry() {
    let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
    let path = fixture.root.path().to_owned();
    let count = std::rc::Rc::new(std::cell::Cell::new(0));
    let moves = count.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, fd| {
            if op != ReadIoOperation::Publish {
                return None;
            }
            moves.set(moves.get() + 1);
            let directory = std::fs::read_dir(&path)
                .unwrap()
                .map(Result::unwrap)
                .find(|e| e.file_type().unwrap().is_dir())
                .unwrap()
                .file_name();
            let file = std::fs::read_dir(path.join(&directory)).unwrap().next().unwrap().unwrap().file_name();
            let from = CString::new(Path::new(&directory).join(file).as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::renameat(fd, from.as_ptr(), fd, c"entry".as_ptr()) }, 0);
            Some(std::io::Error::from_raw_os_error(libc::EINTR))
        }))
    });
    let error = fixture
        .stage
        .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
            fixture.session.check_source(c)
        })
        .unwrap_err();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert_eq!(count.get(), 1);
    assert_eq!(error.publication_state(), PublicationState::Unknown);
    assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"data");
    assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 1);
    assert_eq!(
        fixture.context.run_usage().live_spool_bytes,
        4,
        "ambiguous transfer retains quota, not a rollback/success claim"
    );
    assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
    assert!(error.cleanup_errors().any(|f| f.object == OwnedObject::Output));
}

#[cfg(target_os = "macos")]
#[test]
fn fullpath_ambiguous_birth_after_parent_retarget_cannot_retire_from_old_parent_absence() {
    use std::io::Write;
    for directory_birth in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("dest");
        std::fs::create_dir(&destination).unwrap();
        let retained = root.path().join("retained");
        let path = destination.clone();
        let moved = retained.clone();
        let count = std::rc::Rc::new(std::cell::Cell::new(0));
        let calls = count.clone();
        native_policy::BIRTH_HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |kind, fd, parent, leaf| {
                if (kind == native_policy::BirthKind::Directory) != directory_birth {
                    return None;
                }
                calls.set(calls.get() + 1);
                std::fs::rename(&path, &moved).unwrap();
                std::fs::create_dir(&path).unwrap();
                if directory_birth {
                    native_policy::atomic_directory(fd, parent, leaf).unwrap();
                } else {
                    let born = native_policy::atomic_file(fd, parent, leaf).unwrap();
                    assert_eq!(unsafe { libc::close(born) }, 0);
                }
                Some(Err(std::io::Error::from_raw_os_error(libc::EINTR)))
            }))
        });
        if directory_birth {
            let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
            let mut source = tempfile::NamedTempFile::new().unwrap();
            source.write_all(&bytes).unwrap();
            let cancel = Cancellation::default();
            let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
            let options = crate::extract::Options {
                dest: destination.clone(),
                overwrite: crate::extract::Overwrite::Always,
                mode: crate::extract::Mode::Extract,
                flatten: false,
                threads: None,
                protected_paths: Default::default(),
                parallel_min: None,
            };
            let mut context = EncryptedReadContext::for_projected(
                &mut session,
                ProjectedReadScope::Entry(0),
                None,
                ZipReadOutput::StagedFiles { destination: &destination },
                None,
                &Default::default(),
                &cancel,
            )
            .unwrap();
            let error = ZipReadStage::prepare_file(
                session.stage_entry(0).unwrap(),
                Path::new("entry"),
                &options,
                &cancel,
                &mut context,
            )
            .err()
            .unwrap();
            native_policy::BIRTH_HOOK.with(|h| *h.borrow_mut() = None);
            assert!(
                error.cleanup_errors().any(|f| f.object == OwnedObject::OutputPrivateDirectory),
                "unobserved full-path directory candidate remains explicit"
            );
            assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
        } else {
            let (ledger, _) = super::spool::ledger(0);
            let cancel = Cancellation::default();
            let resolved = spool::ResolvedTempDirectory::resolve(&ledger, Some(&destination), &cancel).unwrap();
            let result = spool::OwnedCiphertext::copy(
                &ledger,
                &resolved,
                &mut std::io::Cursor::new(b"data"),
                4,
                &mut [0; 64],
                &cancel,
            );
            native_policy::BIRTH_HOOK.with(|h| *h.borrow_mut() = None);
            assert!(result.is_err());
            assert_eq!(
                ledger.with_state(|s| s.run.usage.live_spool_bytes),
                4,
                "held-name absence cannot clear a retargeted full-path candidate"
            );
            assert_eq!(ledger.with_state(|s| s.live_fds), 1);
        }
        assert_eq!(count.get(), 1);
        assert_eq!(
            std::fs::read_dir(&destination).unwrap().count(),
            1,
            "real native birth happened under the retargeted spelling"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::result_large_err)] // Actual native ACL policy is retained through the same fixed terminal path.
fn linux_actual_parent_access_default_acl_gid_and_mode_parity_survive_private_staging() {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn acl(named: u16) -> [u8; 44] {
        let id = if unsafe { libc::geteuid() } == 0 { 1 } else { 0 };
        let mut data = [0u8; 44];
        data[..4].copy_from_slice(&2u32.to_le_bytes());
        for (i, (tag, perm, id)) in
            [(1u16, 7u16, u32::MAX), (2, named, id), (4, 0, u32::MAX), (16, 6, u32::MAX), (32, 0, u32::MAX)]
                .into_iter()
                .enumerate()
        {
            let at = 4 + 8 * i;
            data[at..at + 2].copy_from_slice(&tag.to_le_bytes());
            data[at + 2..at + 4].copy_from_slice(&perm.to_le_bytes());
            data[at + 4..at + 8].copy_from_slice(&id.to_le_bytes());
        }
        data
    }
    fn native(path: &Path) -> Vec<u8> {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut data = vec![0u8; 65536];
        let n = unsafe {
            libc::getxattr(path.as_ptr(), c"system.posix_acl_access".as_ptr(), data.as_mut_ptr().cast(), data.len())
        };
        assert!(n >= 0, "{}", std::io::Error::last_os_error());
        data.truncate(n as usize);
        data
    }
    for mode in [None, Some(0u32), Some(0o644)] {
        let root = tempfile::tempdir().unwrap();
        let parent = File::open(root.path()).unwrap();
        parent.set_permissions(std::fs::Permissions::from_mode(0o2770)).unwrap();
        for (name, value) in [(c"system.posix_acl_access", acl(1)), (c"system.posix_acl_default", acl(6))] {
            assert_eq!(
                unsafe { libc::fsetxattr(parent.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), value.len(), 0) },
                0,
                "{}",
                std::io::Error::last_os_error()
            );
        }
        let reference_path = root.path().join("reference");
        let reference = std::fs::OpenOptions::new().write(true).create_new(true).open(&reference_path).unwrap();
        if let Some(mode) = mode {
            reference.set_permissions(std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let expected_mode = reference.metadata().unwrap().mode() & 0o777;
        let expected_gid = reference.metadata().unwrap().gid();
        let expected_acl = native(&reference_path);
        let mut member = fixture::Member::stored(b"entry", b"data");
        if let Some(mode) = mode {
            member.external = (0o100000 | mode) << 16;
        } else {
            member.made_by = 0x0014;
        }
        let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
        let options = crate::extract::Options {
            dest: root.path().to_owned(),
            overwrite: crate::extract::Overwrite::Always,
            mode: crate::extract::Mode::Extract,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::StagedFiles { destination: root.path() },
            None,
            &Default::default(),
            &cancel,
        )
        .unwrap();
        let entry = session.entries().next().unwrap();
        let original_mode = entry.unix_mode();
        let mtime = entry.mtime.map(|s| (s, entry.nanos));
        let mut stage = ZipReadStage::prepare_file(
            session.stage_entry(0).unwrap(),
            Path::new("entry"),
            &options,
            &cancel,
            &mut context,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            context.policy_metadata_usage().native_acl.peak_allocations,
            3,
            "two parent policies plus one child, before parent retirement"
        );
        assert_eq!(
            context.policy_metadata_usage().native_acl.live_allocations,
            1,
            "only child policy survives payload"
        );
        session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
        assert!(stage.publish(original_mode, mtime, &cancel, &mut context, |c| session.check_source(c)).unwrap());
        let actual = root.path().join("entry");
        let metadata = std::fs::metadata(&actual).unwrap();
        assert_eq!(metadata.mode() & 0o777, expected_mode);
        assert_eq!(metadata.gid(), expected_gid);
        assert_eq!(native(&actual), expected_acl);
        assert_eq!(context.policy_metadata_usage().native_acl.live_capacity, 0);
        assert_eq!(context.run_usage().live_spool_bytes, 0);
        assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
    }
}

#[cfg(target_os = "macos")]
#[test]
#[allow(clippy::result_large_err)] // Native maximum policy reconstruction keeps the same fixed terminal representation.
fn mac_native_inherited_acl_and_maximum_aces_match_incumbent_creation_after_publication() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    for entries in [1, 128] {
        let root = tempfile::tempdir().unwrap();
        for _ in 0..entries {
            let result = std::process::Command::new("/bin/chmod")
                .args(["+a#", "0", "everyone allow read,write,search,file_inherit,directory_inherit"])
                .arg(root.path())
                .output()
                .unwrap();
            assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        }
        let reference =
            std::fs::OpenOptions::new().write(true).create_new(true).open(root.path().join("reference")).unwrap();
        reference.set_permissions(std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut scratch = vec![0u8; 65536];
        let expected = native_policy::read_acl(reference.as_raw_fd(), false, &mut scratch).unwrap().unwrap().to_vec();
        assert_eq!(expected.len(), 44 + 24 * entries);
        let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
        let options = crate::extract::Options {
            dest: root.path().to_owned(),
            overwrite: crate::extract::Overwrite::Always,
            mode: crate::extract::Mode::Extract,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::StagedFiles { destination: root.path() },
            None,
            &Default::default(),
            &cancel,
        )
        .unwrap();
        let entry = session.entries().next().unwrap();
        let mode = entry.unix_mode();
        let mtime = entry.mtime.map(|s| (s, entry.nanos));
        let mut stage = ZipReadStage::prepare_file(
            session.stage_entry(0).unwrap(),
            Path::new("entry"),
            &options,
            &cancel,
            &mut context,
        )
        .unwrap()
        .unwrap();
        assert_eq!(context.policy_metadata_usage().native_acl.peak_allocations, 2);
        assert_eq!(context.policy_metadata_usage().native_acl.live_allocations, 1);
        assert_eq!(context.policy_metadata_usage().native_acl.peak_requested_bytes, 2 * expected.len() as u128);
        session.read_at_with_context(0, None, 100, &cancel, &mut context, |b| stage.write_all(b, &cancel)).unwrap();
        assert!(stage.publish(mode, mtime, &cancel, &mut context, |c| session.check_source(c)).unwrap());
        let actual = File::open(root.path().join("entry")).unwrap();
        assert_eq!(
            native_policy::read_acl(actual.as_raw_fd(), false, &mut scratch).unwrap(),
            Some(expected.as_slice())
        );
        assert_eq!(actual.metadata().unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(std::fs::read(root.path().join("entry")).unwrap(), b"data");
        assert_eq!(context.policy_metadata_usage().native_acl.live_capacity, 0);
        assert_eq!(context.ledger.with_state(|s| s.live_fds), 1);
        assert_eq!(context.run_usage().live_spool_bytes, 0);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Real partial preparation keeps fixed allocation-independent cleanup evidence.
fn preparation_each_instrumented_boundary_retires_or_reports_unobserved_empty_directory() {
    use std::cell::Cell;
    use std::io::Write;
    use std::rc::Rc;
    fn one(fail: Option<usize>, unobserved_directory: bool) -> (usize, usize) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("entry"), b"prior").unwrap();
        let bytes = fixture::build(&[fixture::Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let cancel = Cancellation::default();
        let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
        let options = crate::extract::Options {
            dest: root.path().to_owned(),
            overwrite: crate::extract::Overwrite::Always,
            mode: crate::extract::Mode::Extract,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        let mut context = EncryptedReadContext::for_projected(
            &mut session,
            ProjectedReadScope::Entry(0),
            None,
            ZipReadOutput::StagedFiles { destination: root.path() },
            None,
            &Default::default(),
            &cancel,
        )
        .unwrap();
        let count = Rc::new(Cell::new(0usize));
        let calls = count.clone();
        let consumed_close = Rc::new(Cell::new(false));
        let closed = consumed_close.clone();
        let directory_birth = Rc::new(Cell::new(0));
        let born = directory_birth.clone();
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, fd| {
                calls.set(calls.get() + 1);
                if op == ReadIoOperation::Directory && fd >= 0 {
                    born.set(calls.get());
                }
                if Some(calls.get()) != fail {
                    return None;
                }
                if op == ReadIoOperation::Close {
                    assert_eq!(unsafe { libc::close(fd) }, 0);
                    closed.set(true);
                    Some(std::io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Some(std::io::Error::from_raw_os_error(libc::EIO))
                }
            }))
        });
        let result = ZipReadStage::prepare_file(
            session.stage_entry(0).unwrap(),
            Path::new("entry"),
            &options,
            &cancel,
            &mut context,
        );
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        let observed = count.get();
        if let Some(fail) = fail {
            assert!(observed >= fail, "boundary {fail}");
            let error = result.err().expect("injected preparation failure must be terminal");
            if unobserved_directory {
                assert!(error.cleanup_errors().any(|fault| fault.object == OwnedObject::OutputPrivateDirectory
                    && matches!(fault.cause, CleanupCause::Policy(_))));
            }
            assert_eq!(error.publication_state(), PublicationState::NotPublished, "boundary {fail}");
        } else {
            let stage = result.unwrap().unwrap();
            let _ = stage.finish_error(ReadFault::InvalidPlan.into(), &mut context);
        }
        assert_eq!(std::fs::read(root.path().join("entry")).unwrap(), b"prior", "boundary {fail:?}");
        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            1 + usize::from(unobserved_directory),
            "boundary {fail:?}"
        );
        if unobserved_directory {
            let directory = std::fs::read_dir(root.path())
                .unwrap()
                .map(Result::unwrap)
                .find(|entry| entry.file_name() != "entry")
                .unwrap();
            assert!(directory.file_type().unwrap().is_dir());
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
        assert_eq!(context.run_usage().live_spool_bytes, 0, "boundary {fail:?}");
        assert_eq!(context.ledger.with_state(|s| s.live_fds), 1 + u64::from(consumed_close.get()), "boundary {fail:?}");
        assert!(context.ledger.with_state(|s| s.peak_fds) <= 5);

        assert_eq!(context.policy_metadata_usage().native_acl.live_capacity, 0);
        assert_eq!(context.policy_metadata_usage().scratch.live_capacity, 0);
        (observed, directory_birth.get())
    }
    // Instrumentation can nest around one native operation; this is a fault-site
    // sweep, not a claim that its count equals physical syscall accounting.
    let (events, birth) = one(None, false);
    assert!(events > 20 && birth > 0);
    for fail in 1..=events {
        // No captured full native identity: never guess that this name remains
        // the directory we created. Linux first opens O_PATH, then observes it.
        #[cfg(target_os = "macos")]
        let unobserved = fail == birth + 1;
        #[cfg(target_os = "linux")]
        let unobserved = [birth + 1, birth + 2].contains(&fail);
        one(Some(fail), unobserved);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Public adapters retain fixed terminal evidence through their original owners.
fn retained_and_generic_receipts_release_borrows_before_real_read_and_publication() {
    use std::io::Write;
    let bytes = fixture::build(&[fixture::Member::stored(b"dir/entry", b"data")], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    for generic in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let options = crate::extract::Options {
            dest: root.path().to_owned(),
            overwrite: crate::extract::Overwrite::Always,
            mode: crate::extract::Mode::Extract,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        };
        if generic {
            let mut selected = crate::extract::SelectedEntry::open(source.path(), 0, None, 100).unwrap();
            let relative = selected.relative_path().unwrap();
            let (mode, mtime) = (selected.unix_mode(), selected.modified());
            let mut context = selected
                .zip_read_context(None, ZipReadOutput::StagedFiles { destination: root.path() }, &Default::default())
                .unwrap()
                .unwrap();
            let mut stage = ZipReadStage::prepare_file(
                selected.zip_stage_entry().unwrap().unwrap(),
                &relative,
                &options,
                &cancel,
                &mut context,
            )
            .unwrap()
            .unwrap();
            selected.read_with_zip_context(None, &mut context, |bytes| stage.write_all(bytes, &cancel)).unwrap();
            assert!(stage.publish(mode, mtime, &cancel, &mut context, |c| selected.check_zip_source(c)).unwrap());
        } else {
            let mut retained = crate::zip::ReadSession::open(source.path()).unwrap();
            let id = retained.metadata().entry_id(0).unwrap();
            let mut context = EncryptedReadContext::for_session(
                &mut retained,
                &id,
                Some(100),
                ZipReadOutput::StagedFiles { destination: root.path() },
                None,
                &Default::default(),
                &cancel,
            )
            .unwrap();
            let mut selected = retained.select(&id, 100, cancel.clone()).unwrap();
            let relative = selected.relative_path().to_owned();
            let (mode, mtime) = (selected.unix_mode(), selected.modified());
            let mut stage =
                ZipReadStage::prepare_file(selected.stage_entry().unwrap(), &relative, &options, &cancel, &mut context)
                    .unwrap()
                    .unwrap();
            selected.read_with_context(None, &mut context, |bytes| stage.write_all(bytes, &cancel)).unwrap();
            assert!(stage.publish(mode, mtime, &cancel, &mut context, |c| retained.check_source_checked(c)).unwrap());
        }
        assert_eq!(std::fs::read(root.path().join("dir/entry")).unwrap(), b"data");
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
#[allow(clippy::result_large_err)] // Actual namespace attacks preserve bounded original-inode cleanup evidence.
fn named_actual_link_stage_replacement_and_directory_retarget_never_publish_or_unlink_foreign_names() {
    for attack in 0..3 {
        let mut fixture = file_fixture(crate::extract::Overwrite::Always, Some(b"prior"));
        let private = std::fs::read_dir(fixture.root.path())
            .unwrap()
            .map(Result::unwrap)
            .find(|entry| entry.file_type().unwrap().is_dir())
            .unwrap()
            .path();
        let stage_name = std::fs::read_dir(&private).unwrap().next().unwrap().unwrap().path();
        let moved = fixture.root.path().join("attacker-held");
        match attack {
            0 => std::fs::hard_link(&stage_name, &moved).unwrap(),
            1 => {
                std::fs::remove_file(&stage_name).unwrap();
                std::fs::write(&stage_name, b"foreign-stage").unwrap();
            }
            _ => {
                std::fs::rename(&private, &moved).unwrap();
                std::fs::create_dir(&private).unwrap();
                std::fs::write(private.join("foreign"), b"foreign-directory").unwrap();
            }
        }
        let error = fixture
            .stage
            .publish(fixture.mode, fixture.mtime, &Cancellation::default(), &mut fixture.context, |c| {
                fixture.session.check_source(c)
            })
            .unwrap_err();
        assert_eq!(error.publication_state(), PublicationState::NotPublished);
        assert_eq!(std::fs::read(fixture.root.path().join("entry")).unwrap(), b"prior");
        assert_eq!(fixture.context.ledger.with_state(|s| s.live_fds), 1);
        assert!(error.cleanup_errors().len() > 0);
        match attack {
            0 => {
                assert_eq!(std::fs::read(&moved).unwrap(), b"data");
                assert_eq!(std::fs::read(&stage_name).unwrap(), b"data");
            }
            1 => assert_eq!(std::fs::read(&stage_name).unwrap(), b"foreign-stage"),
            _ => {
                assert_eq!(std::fs::read(private.join("foreign")).unwrap(), b"foreign-directory");
                assert_eq!(std::fs::read(moved.join(stage_name.file_name().unwrap())).unwrap(), b"data");
            }
        }
        assert_eq!(fixture.context.run_usage().live_spool_bytes, if attack == 1 { 0 } else { 4 });
        assert_eq!(fixture.context.policy_metadata_usage().native_acl.live_capacity, 0);
    }
}
