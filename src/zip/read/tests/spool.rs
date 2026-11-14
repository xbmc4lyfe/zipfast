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
use std::os::fd::FromRawFd;

pub(super) fn ledger(threshold: u64) -> (shared::ContextLedger, crate::zip::session::SourceStamp) {
    let limits = EncryptedReadLimits { ciphertext_memory_bytes: threshold, ..Default::default() };
    let mut state = budget::LedgerState::new(&EncryptedReadOptions::default().with_limits(limits)).unwrap();
    let plan = budget::ActionPlan::derive(
        budget::PlanGeometry {
            records: 1,
            regular: 1,
            large_aes: 1,
            packed: 1 << 20,
            ciphertext: 1 << 20,
            decoded: 1 << 20,
            live_spool: 1 << 21,
            ..Default::default()
        },
        16,
        16,
    )
    .unwrap();
    let source = super::core::bind_plan(&mut state, plan);
    state.acquire_fds(1).unwrap();
    (shared::ContextLedger::try_new(state).unwrap(), source)
}
#[test]
fn private_file_requires_verified_unlink() {
    let (ledger, _) = ledger(0);
    let cancel = crate::extract::Cancellation::default();
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut source = std::io::Cursor::new(vec![7; 65537]);
    let mut scratch = [0; 65536];
    let mut owned =
        spool::OwnedCiphertext::copy(&ledger, &directory, &mut source, 65537, &mut scratch, &cancel).unwrap();
    assert!(owned.is_unlinked_file());
    let mut output = Vec::new();
    loop {
        let n = owned.read_chunk(&mut scratch, &cancel).unwrap();
        if n == 0 {
            break;
        }
        output.extend_from_slice(&scratch[..n]);
    }
    assert_eq!(output, vec![7; 65537]);
    owned.finish().unwrap();
    ledger.with_state(|s| {
        assert_eq!(s.live_fds, 1);
        assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
    });
}
#[test]
fn all_failures_finish_once() {
    let (ledger, _) = ledger(0);
    let cancel = crate::extract::Cancellation::default();
    let mut scratch = [0; 65536];
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    assert!(
        spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::empty(), 10, &mut scratch, &cancel).is_err()
    );
    ledger.with_state(|s| {
        assert_eq!(s.live_fds, 1);
        assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
    });
}

#[test]
fn memory_threshold_zero_exact_one_over_and_capacity() {
    let cancel = crate::extract::Cancellation::default();
    for threshold in [0, 1, 65536] {
        for len in [0, 1, 15, 16, 17, 65535, 65536, 65537, 131073] {
            let (ledger, _) = ledger(threshold);
            let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
            let baseline = ledger.with_state(|s| s.encrypted.usage.reader_capacity);
            let mut scratch = [0; 65536];
            let mut owned =
                spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(6), len, &mut scratch, &cancel)
                    .unwrap();
            assert_eq!(owned.is_unlinked_file(), len > threshold);
            assert_eq!(
                ledger.with_state(|s| s.encrypted.usage.reader_capacity),
                baseline + if len <= threshold { len } else { 0 }
            );
            let mut actual = 0;
            loop {
                let n = owned.read_chunk(&mut scratch[..17], &cancel).unwrap();
                if n == 0 {
                    break;
                }
                assert!(scratch[..n].iter().all(|&b| b == 6));
                actual += n as u64;
            }
            assert_eq!(actual, len);
            owned.finish().unwrap();
            assert_eq!(ledger.with_state(|s| s.encrypted.usage.reader_capacity), baseline);
        }
    }
}

#[test]
fn namespace_trust_and_swap_boundaries() {
    use std::os::unix::fs::PermissionsExt;
    let cancel = crate::extract::Cancellation::default();
    for mode in [0o700, 0o755, 0o777, 0o1777] {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let (ledger, _) = ledger(0);
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(temp.path()), &cancel).unwrap();
        let result =
            spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel);
        if mode == 0o777 {
            assert!(result.is_err());
        } else {
            result.unwrap().finish().unwrap();
        }
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }
    // A detected link/mode change before unlink prevents any usable owner.
    for change_links in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_owned();
        let (ledger, _) = ledger(0);
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(temp.path()), &cancel).unwrap();
        let mut changed = false;
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, fd| {
                if op == ReadIoOperation::Stat && fd >= 0 && !changed {
                    let metadata = unsafe { std::fs::File::from_raw_fd(libc::dup(fd)) }.metadata().unwrap();
                    if metadata.is_file() {
                        changed = true;
                        if change_links {
                            let name = std::fs::read_dir(&path).unwrap().next().unwrap().unwrap().path();
                            std::fs::hard_link(name, path.join("retained-link")).unwrap();
                        } else {
                            assert_eq!(unsafe { libc::fchmod(fd, 0o640) }, 0);
                        }
                    }
                }
                None
            }))
        });
        let result =
            spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel);
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        assert!(result.is_err());
        assert!(ledger.with_state(|s| s.poisoned)); // A retained name is unresolved storage.
    }
}

#[test]
fn injected_storage_failures_are_terminal_and_close_once() {
    use std::{cell::Cell, rc::Rc};
    let cancel = crate::extract::Cancellation::default();
    for (operation, code) in [
        (ReadIoOperation::Open, libc::EACCES),
        (ReadIoOperation::Create, libc::EMFILE),
        (ReadIoOperation::Unlink, libc::EACCES),
        (ReadIoOperation::Write, libc::ENOSPC),
        (ReadIoOperation::Seek, libc::EIO),
        (ReadIoOperation::Stat, libc::EIO),
    ] {
        let (ledger, _) = ledger(0);
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
        let hit = Rc::new(Cell::new(false));
        let mark = hit.clone();
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, _| {
                if op == operation && !mark.replace(true) {
                    Some(std::io::Error::from_raw_os_error(code))
                } else {
                    None
                }
            }))
        });
        let result =
            spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel);
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        assert!(result.is_err(), "{operation:?}");
        assert!(hit.get());
        assert_eq!(ledger.with_state(|s| s.live_fds), 1);
    }
    let (ledger, _) = ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let owned =
        spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel).unwrap();
    let calls = Rc::new(Cell::new(0));
    let count = calls.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, fd| {
            if op == ReadIoOperation::Close {
                count.set(count.get() + 1);
                assert_eq!(unsafe { libc::close(fd) }, 0);
                Some(std::io::Error::from_raw_os_error(libc::EINTR))
            } else {
                None
            }
        }))
    });
    let report = owned.finish().unwrap_err();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert_eq!(calls.get(), 1);
    let error = ZipReadError::from(report);
    assert!(matches!(error.cleanup_errors().next().unwrap().close, CloseDisposition::Unresolved));
    ledger.with_state(|s| {
        assert!(s.poisoned);
        assert_eq!(s.live_fds, 2);
        assert_eq!(s.encrypted.usage.live_spool_bytes, 1);
        assert!(s.acquire_fds(1).is_err());
    });
}

#[test]
fn resolver_bounds_allocation_and_preplan_charge_seam() {
    use crate::test_alloc::DENY_LAYOUT;
    use std::os::unix::ffi::OsStrExt;
    let cancel = crate::extract::Cancellation::default();
    let (ledger, _) = ledger(0);
    let exact = vec![b'x'; spool::ResolvedTempDirectory::CAPACITY - 1];
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(&exact));
    let resolved = spool::ResolvedTempDirectory::resolve(&ledger, Some(path), &cancel).unwrap();
    assert_eq!(resolved.path_bytes(), exact.len());
    drop(resolved);
    let over = vec![b'x'; spool::ResolvedTempDirectory::CAPACITY];
    assert!(
        spool::ResolvedTempDirectory::resolve(
            &ledger,
            Some(std::path::Path::new(std::ffi::OsStr::from_bytes(&over))),
            &cancel
        )
        .is_err()
    );
    DENY_LAYOUT.with(|v| v.set(Some((4096, 1))));
    assert!(matches!(
        spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel),
        Err(ReadFault::Allocation { capacity: 4096 })
    ));
    let mut calls = 0;
    let error = spool::ResolvedTempDirectory::resolve_charged(&ledger, None, &cancel, 16, |_| {
        calls += 1;
        Err(ReadFault::InvalidPlan)
    })
    .err()
    .unwrap();
    assert!(matches!(error, ReadFault::InvalidPlan));
    assert_eq!(calls, 1);
}

#[test]
fn temp_resolution_child() {
    use std::os::unix::ffi::OsStrExt;
    if std::env::var_os("ZIPFAST_TEMP_CHILD").is_none() {
        return;
    }
    let (ledger, _) = ledger(0);
    let cancel = crate::extract::Cancellation::default();
    let expected = std::env::var_os("TMPDIR");
    let result = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel);
    if expected.as_ref().is_some_and(|p| p.as_bytes().len() >= 4096) {
        assert!(result.is_err());
        return;
    }
    let resolved = result.unwrap();
    let actual = resolved.test_path();
    let expected = expected.unwrap_or_else(|| std::env::temp_dir().into_os_string());
    assert_eq!(actual, if expected.is_empty() { b".".as_slice() } else { expected.as_bytes() });
    let configured =
        spool::ResolvedTempDirectory::resolve(&ledger, Some(std::path::Path::new("/tmp")), &cancel).unwrap();
    assert_eq!(configured.test_path(), b"/tmp");
}
#[test]
fn system_temp_selection_in_child_processes() {
    use std::os::unix::ffi::OsStringExt;
    for value in [
        None,
        Some(Vec::new()),
        Some(b"/tmp".to_vec()),
        Some(vec![b'/', 255]),
        Some(vec![b'x'; 4095]),
        Some(vec![b'x'; 4096]),
    ] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "zip::read::tests::spool::temp_resolution_child", "--nocapture"])
            .env("ZIPFAST_TEMP_CHILD", "1");
        if let Some(value) = value {
            command.env("TMPDIR", std::ffi::OsString::from_vec(value));
        } else {
            command.env_remove("TMPDIR");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn synthetic_owner_type_mode_and_link_policy() {
    let mut s: libc::stat = unsafe { std::mem::zeroed() };
    let uid = unsafe { libc::geteuid() };
    s.st_uid = uid;
    s.st_mode = libc::S_IFDIR | 0o700;
    assert!(spool::trusted_dir(&s, uid));
    s.st_uid = uid.checked_add(1).unwrap_or(1);
    assert!(!spool::trusted_dir(&s, uid));
    s.st_uid = 0;
    s.st_mode = libc::S_IFDIR | 0o1777;
    assert!(spool::trusted_dir(&s, uid));
    s.st_mode = libc::S_IFREG | 0o600;
    assert!(!spool::trusted_dir(&s, uid));
    s.st_uid = uid;
    s.st_nlink = 1;
    assert!(spool::trusted_file(&s, 1, uid));
    assert!(!spool::trusted_file(&s, 0, uid));
    s.st_nlink = 0;
    assert!(spool::trusted_file(&s, 0, uid));
    s.st_mode |= 0o040;
    assert!(!spool::trusted_file(&s, 0, uid));
    s.st_mode = libc::S_IFIFO | 0o600;
    assert!(!spool::trusted_file(&s, 0, uid));
}

#[test]
fn collisions_are_exclusive_finite_and_per_namespace() {
    let cancel = crate::extract::Cancellation::default();
    let (ledger, _) = ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut creates = 0;
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, _| {
            if op == ReadIoOperation::Create {
                creates += 1;
                assert!(creates <= 16);
                Some(std::io::Error::from_raw_os_error(libc::EEXIST))
            } else {
                None
            }
        }))
    });
    let error = spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel)
        .err()
        .unwrap();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::CreateAttempts, .. })));
    ledger.with_state(|s| {
        assert_eq!(s.encrypted.usage.create_attempts, 16);
        assert_eq!(s.run.usage.temporary_groups, 1);
        assert_eq!(s.live_fds, 1);
        assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
    });
}

#[test]
fn observed_name_swap_refuses_unlink_and_preserves_replacement() {
    use std::cell::Cell;
    use std::rc::Rc;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().to_owned();
    let changed = Rc::new(Cell::new(false));
    let flag = changed.clone();
    let cancel = crate::extract::Cancellation::default();
    let (ledger, _) = ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(temp.path()), &cancel).unwrap();
    let mut regular_stats = 0;
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, fd| {
            if op == ReadIoOperation::Stat && fd >= 0 {
                let metadata = unsafe { std::fs::File::from_raw_fd(libc::dup(fd)) }.metadata().unwrap();
                if metadata.is_file() {
                    regular_stats += 1;
                }
            }
            // Before the directory-relative name stat, replace the already-verified
            // original name. Keep the moved original so inode reuse is impossible.
            if op == ReadIoOperation::Stat && fd < 0 && regular_stats == 1 && !flag.get() {
                let name = std::fs::read_dir(&path).unwrap().next().unwrap().unwrap().path();
                std::fs::rename(&name, path.join("original-held")).unwrap();
                std::fs::write(&name, b"replacement").unwrap();
                flag.set(true);
            }
            None
        }))
    });
    let result = spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel);
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert!(result.is_err());
    assert!(changed.get());
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 2);
    // No promise is made about a swap after the final check and before unlink.
    // Already-open hostile same-UID handles are excluded; unlink cannot revoke them.
}

#[test]
fn owned_resolved_path_has_same_ledger_controlled_release_and_no_borrow_trap() {
    use shared::LedgerAccess;
    let cancel = crate::extract::Cancellation::default();
    let (mut first, _) = ledger(0);
    let (second, _) = ledger(0);
    let baseline = first.with_state(|s| s.encrypted.usage.reader_capacity);
    let path = spool::ResolvedTempDirectory::resolve(&first, Some(std::path::Path::new("/tmp")), &cancel).unwrap();
    let token = first.mint_reservation().unwrap();
    assert_eq!(first.identity(), token.identity());
    assert_eq!(first.identity(), first.view().identity());
    path.finish_capacity(&token).unwrap();
    assert_eq!(first.with_state(|s| s.encrypted.usage.reader_capacity), baseline);
    let path = spool::ResolvedTempDirectory::resolve(&first, Some(std::path::Path::new("/tmp")), &cancel).unwrap();
    let second_before = second.with_state(|s| s.encrypted.usage.reader_capacity);
    assert!(path.finish_capacity(&second).is_err());
    assert_eq!(second.with_state(|s| s.encrypted.usage.reader_capacity), second_before);
    let path = spool::ResolvedTempDirectory::resolve(&first, Some(std::path::Path::new("/tmp")), &cancel).unwrap();
    drop(token);
    drop(first);
    let (later, _) = ledger(0);
    let later_before = later.with_state(|s| s.encrypted.usage.reader_capacity);
    assert!(path.finish_capacity(&later).is_err());
    assert_eq!(later.with_state(|s| s.encrypted.usage.reader_capacity), later_before);
    assert_eq!(shared::header_layout().0, 2032);
    assert_eq!(shared::role_sizes(), (16, 16, 16));
}

#[test]
fn bounded_default_response_and_preplan_resolution_have_finite_charges() {
    let cancel = crate::extract::Cancellation::default();
    let context = shared::ContextLedger::try_new(budget::LedgerState::new(&Default::default()).unwrap()).unwrap();
    let mut groups = 0;
    let mut attempts = 0;
    let mut path = spool::ResolvedTempDirectory::resolve_charged(
        &context,
        Some(std::path::Path::new("/tmp")),
        &cancel,
        16,
        |charge| {
            match charge {
                spool::ResolveCharge::Group => {
                    groups += 1;
                    assert_eq!(groups, 1);
                }
                spool::ResolveCharge::Attempt => {
                    attempts += 1;
                    assert!(attempts <= 5);
                }
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(attempts, 1); // configured path requires only the credential snapshot.
    path.test_confstr(Ok(4096)).unwrap();
    assert_eq!(path.path_bytes(), 4095);
    assert!(path.test_confstr(Ok(4097)).is_err());
    path.test_confstr(Err(std::io::Error::from_raw_os_error(libc::EIO))).unwrap();
    assert_eq!(path.test_path(), b"/tmp");
    path.test_confstr(Ok(1)).unwrap();
    assert_eq!(path.test_path(), b".");
    path.finish_capacity(&context).unwrap();
    assert_eq!(context.with_state(|s| s.encrypted.usage.reader_capacity), 2032);
}

#[test]
fn terminal_stat_and_ambiguous_close_keep_both_faults_without_allocation() {
    let cancel = crate::extract::Cancellation::default();
    let (ledger, _) = ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let owned =
        spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel).unwrap();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(|op, fd| match op {
            ReadIoOperation::Stat => Some(std::io::Error::from_raw_os_error(libc::EIO)),
            ReadIoOperation::Close => {
                assert_eq!(unsafe { libc::close(fd) }, 0);
                Some(std::io::Error::from_raw_os_error(libc::EINTR))
            }
            _ => None,
        }))
    });
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let error = owned.finish_error(ReadFault::AuthenticationFailed.into());
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(false));
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
    assert_eq!(error.cleanup_errors().len(), 2);
    assert!(ledger.with_state(|s| s.poisoned));
    assert_eq!(error.usage().live_fds, 2);
}

#[test]
fn zero_creates_refuses_before_namespace_calls_and_preserves_memory() {
    use std::{cell::Cell, rc::Rc};
    let cancel = crate::extract::Cancellation::default();
    let (ledger, _) = ledger(0);
    let directory =
        spool::ResolvedTempDirectory::resolve(&ledger, Some(std::path::Path::new("/tmp")), &cancel).unwrap();
    ledger.with_state(|s| s.encrypted.limits.create_attempts = 0);
    let calls = Rc::new(Cell::new(0));
    let count = calls.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |_, _| {
            count.set(count.get() + 1);
            None
        }))
    });
    let error = spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel)
        .err()
        .unwrap();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    assert!(matches!(error.operation(), Some(ReadFault::Limit { resource: ReadResource::CreateAttempts, .. })));
    assert_eq!(calls.get(), 0, "zero creation budget permits no namespace calls");
    ledger.with_state(|s| {
        assert_eq!(s.live_fds, 1);
        assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
        assert!(!s.poisoned);
    });
    for (len, threshold) in [(0, 0), (1, 1)] {
        ledger.with_state(|s| s.encrypted.limits.ciphertext_memory_bytes = threshold);
        let owned =
            spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), len, &mut [0; 64], &cancel)
                .unwrap();
        assert!(!owned.is_unlinked_file());
        owned.finish().unwrap();
    }
}

#[test]
fn partial_named_cleanup_preserves_stat_and_unlink_operation_labels() {
    use std::{cell::Cell, rc::Rc};
    for fail_stat in [true, false] {
        let cancel = crate::extract::Cancellation::default();
        let (ledger, _) = ledger(0);
        let temp = tempfile::tempdir().unwrap();
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(temp.path()), &cancel).unwrap();
        let unlinks = Rc::new(Cell::new(0));
        let seen_unlinks = unlinks.clone();
        let stats_after_unlink = Rc::new(Cell::new(0));
        let seen_stats = stats_after_unlink.clone();
        let closes = Rc::new(Cell::new(0));
        let seen_closes = closes.clone();
        spool::hooks::HOOK.with(|h| {
            *h.borrow_mut() = Some(Box::new(move |op, fd| {
                if op == ReadIoOperation::Unlink {
                    seen_unlinks.set(seen_unlinks.get() + 1);
                    return Some(std::io::Error::from_raw_os_error(libc::EACCES));
                }
                if op == ReadIoOperation::Stat && fd >= 0 && seen_unlinks.get() > 0 {
                    seen_stats.set(seen_stats.get() + 1);
                    if fail_stat && seen_stats.get() == 2 {
                        return Some(std::io::Error::from_raw_os_error(libc::EIO));
                    }
                }
                if op == ReadIoOperation::Close {
                    seen_closes.set(seen_closes.get() + 1);
                }
                None
            }))
        });
        let error =
            spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel)
                .err()
                .unwrap();
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        assert!(
            matches!(error.operation(), Some(ReadFault::Io { operation: ReadIoOperation::Unlink, error, .. }) if error.raw_os_error() == Some(libc::EACCES))
        );
        let cleanup = error.cleanup_errors().find(|f| f.object == OwnedObject::Ciphertext).unwrap();
        assert_eq!(cleanup.operation, if fail_stat { ReadIoOperation::Stat } else { ReadIoOperation::Unlink });
        assert!(
            matches!(&cleanup.cause, CleanupCause::Io(error) if error.raw_os_error() == Some(if fail_stat { libc::EIO } else { libc::EACCES }))
        );
        assert_eq!(unlinks.get(), if fail_stat { 1 } else { 2 });
        assert_eq!(stats_after_unlink.get(), 2);
        assert_eq!(closes.get(), 2);
        ledger.with_state(|s| {
            assert!(s.poisoned);
            assert_eq!(s.live_fds, 1);
            assert_eq!(s.encrypted.usage.live_spool_bytes, 1);
            assert_eq!(s.run.usage.emergency_cleanup, if fail_stat { 2 } else { 4 });
        });
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

#[test]
fn partial_cleanup_policy_refusal_is_a_stat_without_an_unlink_retry() {
    use std::{cell::Cell, os::unix::fs::PermissionsExt, rc::Rc};
    let cancel = crate::extract::Cancellation::default();
    let (ledger, _) = ledger(0);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().to_owned();
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, Some(temp.path()), &cancel).unwrap();
    let unlinks = Rc::new(Cell::new(0));
    let seen = unlinks.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, _| {
            if op == ReadIoOperation::Unlink {
                seen.set(seen.get() + 1);
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
                Some(std::io::Error::from_raw_os_error(libc::EACCES))
            } else {
                None
            }
        }))
    });
    let error = spool::OwnedCiphertext::copy(&ledger, &directory, &mut std::io::repeat(1), 1, &mut [0; 64], &cancel)
        .err()
        .unwrap();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let cleanup = error.cleanup_errors().find(|f| f.object == OwnedObject::Ciphertext).unwrap();
    assert_eq!(cleanup.operation, ReadIoOperation::Stat);
    assert!(matches!(cleanup.cause, CleanupCause::Policy("private storage parent changed")));
    assert_eq!(unlinks.get(), 1);
    ledger.with_state(|s| {
        assert!(s.poisoned);
        assert_eq!(s.live_fds, 1);
        assert_eq!(s.encrypted.usage.live_spool_bytes, 1);
        assert_eq!(s.run.usage.emergency_cleanup, 1);
    });
}
