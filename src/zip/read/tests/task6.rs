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

//! Task6 checks actual public entrypoints under scoped unit-test I/O seams.
use super::super::*;
use super::fixture::{self, Member};
use std::cell::Cell;
use std::io::Write;
thread_local! {
    static CAP: Cell<Option<usize>> = const { Cell::new(None) };
    static OBSERVED: Cell<[u64; 2]> = const { Cell::new([0; 2]) };
}
struct FragmentGuard {
    previous: Option<usize>,
}
impl FragmentGuard {
    fn one() -> Self {
        Self { previous: CAP.with(|s| s.replace(Some(1))) }
    }
}
impl Drop for FragmentGuard {
    fn drop(&mut self) {
        CAP.with(|s| s.set(self.previous));
    }
}
// Called only from cfg(test) production read adapters. No fabricated byte/attempt charges.
pub(in crate::zip::read) fn read_cap(length: usize, source: bool) -> usize {
    CAP.with(|s| match s.get() {
        None => length,
        Some(cap) => {
            OBSERVED.with(|v| {
                let mut n = v.get();
                n[usize::from(source)] += 1;
                v.set(n);
            });
            length.min(cap)
        }
    })
}
fn packed(method: u16, data: &[u8]) -> Vec<u8> {
    match method {
        0 => data.to_vec(),
        8 => {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        12 => {
            let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        14 => {
            let opts = liblzma::stream::LzmaOptions::new_preset(6).unwrap();
            let stream = liblzma::stream::Stream::new_lzma_encoder(&opts).unwrap();
            let mut e = liblzma::write::XzEncoder::new_stream(Vec::new(), stream);
            e.write_all(data).unwrap();
            let alone = e.finish().unwrap();
            let mut out = vec![9, 20, 5, 0];
            out.extend(&alone[..5]);
            out.extend(&alone[13..]);
            out
        }
        95 => {
            let mut e = liblzma::write::XzEncoder::new(Vec::new(), 6);
            e.write_all(data).unwrap();
            e.finish().unwrap()
        }
        93 => zstd::stream::encode_all(data, 3).unwrap(),
        _ => unreachable!(),
    }
}
#[test]
fn actual_public_projected_all_six_codecs_one_byte_clear_zipcrypto_authenticated_aes() {
    for method in [0u16, 8, 12, 14, 95, 93] {
        for size in [0, 65536, 65537] {
            let data = vec![0x6b; size];
            let packed = packed(method, &data);
            for mode in 0..4 {
                let mut frame = packed.clone();
                let mut extra = Vec::new();
                if mode == 1 {
                    frame = vec![0; 12];
                    frame[11] = (crc32fast::hash(&data) >> 24) as u8;
                    frame.extend(&packed);
                    crate::crypto::ZipCrypto::new("password").encrypt(&mut frame);
                } else if mode >= 2 {
                    frame = super::cipher::framed(1, "password", &packed);
                    let mut body = vec![2, 0, b'A', b'E', 1];
                    body.extend(method.to_le_bytes());
                    extra = fixture::extra(0x9901, &body);
                }
                let mut member = Member::stored(b"payload", &frame);
                member.decoded = Some(&data);
                member.method = if mode >= 2 { 99 } else { method };
                member.flags = if mode == 0 { 0 } else { 1 };
                if method == 14 {
                    member.flags |= 2;
                }
                member.local_extra = &extra;
                member.central_extra = &extra;
                let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
                if let Some(directory) = std::env::var_os("ZIPFAST_TASK6_EXPORT_FIXTURES") {
                    let directory = std::path::PathBuf::from(directory);
                    std::fs::create_dir_all(&directory).unwrap();
                    let path = directory.join(format!("method{method}-u{size}-mode{mode}.zip"));
                    assert!(!path.exists(), "fixture exports are append-only");
                    std::fs::write(path, &bytes).unwrap();
                }
                let mut file = tempfile::NamedTempFile::new().unwrap();
                file.write_all(&bytes).unwrap();
                let cancel = Cancellation::default();
                let mut session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
                let mut limits = EncryptedReadLimits::default();
                if mode == 3 {
                    limits.ciphertext_memory_bytes = 0;
                }
                let mut context =
                    EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
                let mut out = Vec::new();
                OBSERVED.with(|s| s.set([0; 2]));
                let guard = FragmentGuard::one();
                session
                    .read_at_with_context(0, Some("password"), 1 << 20, &cancel, &mut context, |b| {
                        out.extend_from_slice(b);
                        Ok(())
                    })
                    .unwrap();
                drop(guard);
                assert_eq!(out, data, "method{method} mode{mode} size{size}");
                let observed = OBSERVED.with(Cell::get);
                if !packed.is_empty() {
                    assert!(observed[0] > 0, "actual PlainInput seam not reached");
                }
                if !frame.is_empty() {
                    assert!(observed[1] > 0, "actual HeldSource seam not reached");
                }
                assert_eq!(context.usage().live_spool_bytes, 0);
                assert_eq!(context.usage().live_fds, 0);
            }
        }
    }
}

struct SpoolHookGuard {
    previous: Option<spool::hooks::Hook>,
}
impl SpoolHookGuard {
    fn new(hook: spool::hooks::Hook) -> Self {
        Self { previous: spool::hooks::HOOK.with(|s| s.borrow_mut().replace(hook)) }
    }
}
impl Drop for SpoolHookGuard {
    fn drop(&mut self) {
        spool::hooks::HOOK.with(|s| *s.borrow_mut() = self.previous.take());
    }
}
struct AllocationGuard;
impl Drop for AllocationGuard {
    fn drop(&mut self) {
        crate::test_alloc::DENY_LAYOUT.with(|s| s.set(None));
    }
}
fn public_aes(size: usize, disk: bool) -> (tempfile::NamedTempFile, ProjectedReadSession, EncryptedReadContext) {
    let data = vec![0x61; size];
    let frame = super::cipher::framed(1, "password", &data);
    let extra = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut member = Member::stored(b"payload", &frame);
    member.decoded = Some(&data);
    member.method = 99;
    member.flags = 1;
    member.local_extra = &extra;
    member.central_extra = &extra;
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&fixture::build(&[member], &[0], b"", b"", false).bytes).unwrap();
    let cancel = Cancellation::default();
    let session = ProjectedReadSession::open(file.path(), &cancel).unwrap();
    let mut limits = EncryptedReadLimits::default();
    if disk {
        limits.ciphertext_memory_bytes = 0;
    }
    let context = EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
    (file, session, context)
}
#[test]
fn actual_public_read_ciphertext_close_eintr_is_once_and_prevents_success() {
    use std::rc::Rc;
    let (_file, mut session, mut context) = public_aes(17, true);
    let closes = Rc::new(Cell::new(0));
    let seen = closes.clone();
    let guard = SpoolHookGuard::new(Box::new(move |op, fd| {
        if op == ReadIoOperation::Close && fd >= 0 {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
            if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFREG {
                seen.set(seen.get() + 1);
                // Simulate an ambiguous EINTR after the kernel really closed it.
                assert_eq!(unsafe { libc::close(fd) }, 0);
                return Some(std::io::Error::from_raw_os_error(libc::EINTR));
            }
        }
        None
    }));
    let mut bytes = 0;
    let error = session
        .read_at_with_context(0, Some("password"), 64, &Cancellation::default(), &mut context, |b| {
            bytes += b.len();
            Ok(())
        })
        .unwrap_err();
    drop(guard);
    assert_eq!(bytes, 17);
    assert_eq!(closes.get(), 1);
    assert!(error.cleanup_errors().any(|f| f.object == OwnedObject::Ciphertext
        && f.operation == ReadIoOperation::Close
        && f.close == CloseDisposition::Unresolved));
    assert_eq!(context.usage().live_fds, 1);
    assert!(
        session
            .read_at_with_context(0, Some("password"), 64, &Cancellation::default(), &mut context, |_| Ok(()))
            .is_err()
    );
}
#[test]
fn actual_public_read_enospc_has_no_plaintext_or_expanding_memory_fallback() {
    let (_file, mut session, mut context) = public_aes(17, true);
    let guard = SpoolHookGuard::new(Box::new(|op, _| {
        if op == ReadIoOperation::Write { Some(std::io::Error::from_raw_os_error(libc::ENOSPC)) } else { None }
    }));
    let error = session
        .read_at_with_context(0, Some("password"), 64, &Cancellation::default(), &mut context, |_| {
            panic!("no unauthenticated bytes")
        })
        .unwrap_err();
    drop(guard);
    assert!(
        matches!(error.operation(),Some(ReadFault::Io{operation:ReadIoOperation::Write,error,..}) if error.raw_os_error()==Some(libc::ENOSPC))
    );
    assert_eq!(context.usage().ciphertext_memory_bytes, 0);
    assert_eq!(context.usage().live_spool_bytes, 0);
    assert_eq!(context.usage().live_fds, 0);
}
#[test]
fn actual_public_reader_window_and_ciphertext_acquisition_failure_is_typed_before_callback() {
    for capacity in [65536, 17] {
        let (_file, mut session, mut context) = public_aes(17, false);
        let _guard = AllocationGuard;
        crate::test_alloc::DENY_LAYOUT.with(|s| s.set(Some((capacity, 1))));
        let error = session
            .read_at_with_context(0, Some("password"), 64, &Cancellation::default(), &mut context, |_| {
                panic!("acquisition before callbacks")
            })
            .unwrap_err();
        assert!(matches!(error.operation(),Some(ReadFault::Allocation{capacity:n}) if *n==capacity));
        assert_eq!(context.usage().members, 1);
        assert_eq!(context.usage().live_spool_bytes, 0);
    }
}
#[test]
fn actual_public_authenticated_callback_mutation_is_provisional_and_invalidates_owner() {
    let (file, mut session, mut context) = public_aes(17, false);
    let mut callbacks = 0;
    let error = session
        .read_at_with_context(0, Some("password"), 64, &Cancellation::default(), &mut context, |b| {
            assert_eq!(b, b"aaaaaaaaaaaaaaaaa");
            callbacks += 1;
            file.as_file().set_len(file.as_file().metadata().unwrap().len() + 1).unwrap();
            Ok(())
        })
        .unwrap_err();
    assert_eq!(callbacks, 1);
    assert!(error.source_change().is_some());
    assert!(session.check_source(&mut context).is_err());
}
