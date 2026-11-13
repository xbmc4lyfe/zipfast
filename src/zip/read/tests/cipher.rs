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
use shared::LedgerAccess;
#[test]
fn aes_authenticates_owned_object_before_plaintext() {
    let (ledger, stamp) = super::spool::ledger(65536);
    let cancel = crate::extract::Cancellation::default();
    let mut encrypted = crate::crypto::WinZipAesEncryptor::new(b"password", &[1; 8], 16).unwrap();
    let mut bytes = b"owned bytes are authenticated".to_vec();
    encrypted.encrypt(&mut bytes).unwrap();
    let tag = encrypted.tag();
    let mut framing = Vec::from([1; 8]);
    framing.extend(encrypted.verifier());
    framing.extend(&bytes);
    framing.extend(tag);
    let mut scratch = [0; 65536];
    let mut source =
        cipher::CheckedInput { reader: std::io::Cursor::new(framing), check: |_: shared::LedgerView<'_>| Ok(()) };
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let pending = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, bytes.len() as u64 + 20, bytes.len() as u64, CipherKind::Aes),
        Some("password"),
        &mut scratch,
        &cancel,
    )
    .unwrap();
    let mut authenticated = pending.authenticate(&mut scratch, &cancel).unwrap();
    let n = authenticated.read_plain_chunk(&mut scratch, &cancel).unwrap();
    assert_eq!(&scratch[..n], b"owned bytes are authenticated");
    authenticated.finish(Ok(())).unwrap();
}

fn member(
    source: crate::zip::session::SourceStamp,
    packed: u64,
    ciphertext: u64,
    cipher: CipherKind,
) -> budget::MemberPlan {
    budget::MemberPlan {
        source,
        scope: ProjectedReadScope::AllRegular,
        ordinal: 0,
        packed,
        decoded: ciphertext,
        ciphertext,
        cipher: Some(cipher),
        crc: Some(0),
        output: budget::PlannedOutput::Callback,
    }
}

struct Fragments {
    bytes: std::io::Cursor<Vec<u8>>,
    max: usize,
}
impl std::io::Read for Fragments {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = out.len().min(self.max);
        std::io::Read::read(&mut self.bytes, &mut out[..n])
    }
}
fn framed(strength: u8, password: &str, plain: &[u8]) -> Vec<u8> {
    let key_len = (strength as usize + 1) * 8;
    let salt = (1..=key_len / 2).map(|n| n as u8).collect::<Vec<_>>();
    let mut writer = crate::crypto::WinZipAesEncryptor::new(password.as_bytes(), &salt, key_len).unwrap();
    let mut ciphertext = plain.to_vec();
    writer.encrypt(&mut ciphertext).unwrap();
    let mut frame = salt;
    frame.extend(writer.verifier());
    frame.extend(ciphertext);
    frame.extend(writer.tag());
    frame
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn independent_vectors_memory_disk_and_every_ctr_split() {
    let password = format!("a native AES fixture password with UTF-8 雪 {}", "p".repeat(67));
    let cancel = crate::extract::Cancellation::default();
    for line in include_str!("../../../../tests/fixtures/winzip-aes-stream.tsv").lines().filter(|l| !l.starts_with('#'))
    {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let strength = fields[0].parse::<u8>().unwrap();
        let len = fields[1].parse::<usize>().unwrap();
        let plain = (0..len).map(|i| (i * 73 + (i >> 8) + 19) as u8).collect::<Vec<_>>();
        let frame = framed(strength, &password, &plain);
        let salt_len = (strength as usize + 1) * 4;
        assert_eq!(hex(&frame[salt_len..salt_len + 2]), fields[2]);
        assert_eq!(hex(&frame[frame.len() - 10..]), fields[4]);
        for (threshold, version, fragment, plain_chunk) in [(65536, 1, 1, 17), (0, 2, 17, 1)] {
            let (ledger, stamp) = super::spool::ledger(threshold);
            let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
            let mut source = cipher::CheckedInput {
                reader: Fragments { bytes: std::io::Cursor::new(frame.clone()), max: fragment },
                check: |_: shared::LedgerView<'_>| Ok(()),
            };
            let mut scratch = [0; 65536];
            let pending = cipher::PendingAes::copy(
                &ledger,
                &directory,
                &mut source,
                strength,
                version,
                member(stamp, frame.len() as u64, len as u64, CipherKind::Aes),
                Some(&password),
                &mut scratch,
                &cancel,
            )
            .unwrap();
            let mut authenticated = pending.authenticate(&mut scratch, &cancel).unwrap();
            let mut actual = Vec::new();
            assert_eq!(authenticated.plan.decoded, len as u64);
            loop {
                let n = authenticated.read_plain_chunk(&mut scratch[..plain_chunk], &cancel).unwrap();
                if n == 0 {
                    break;
                }
                actual.extend_from_slice(&scratch[..n]);
            }
            authenticated.finish(Ok(())).unwrap();
            assert_eq!(actual, plain);
            let expected = frame.len() as u128 + if len as u64 > threshold { 3 * len as u128 } else { 0 };
            ledger.with_state(|s| {
                assert_eq!(s.encrypted.usage.io_bytes, expected);
                assert_eq!(s.encrypted.usage.work_bytes, 2 * len as u128);
                assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
                assert_eq!(s.live_fds, 1);
            });
            assert_eq!(
                crate::crypto::decrypt_winzip_aes(&password, strength, &frame, Some(frame.len() as u64)).unwrap(),
                plain
            );
        }
    }
}

#[test]
fn framing_password_tamper_and_zero_plaintext_on_rejection() {
    let cancel = crate::extract::Cancellation::default();
    for strength in 1..=3 {
        let plain = vec![5; 65537];
        let original = framed(strength, "password", &plain);
        let salt_len = (strength as usize + 1) * 4;
        for mutation in 0..7 {
            let (ledger, stamp) = super::spool::ledger(0);
            let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
            let mut frame = original.clone();
            let password = match mutation {
                0 => None,
                1 => Some(""),
                2 => Some("wrong"),
                _ => Some("password"),
            };
            if mutation == 3 {
                frame[salt_len] ^= 1;
            }
            if mutation == 4 {
                frame[salt_len + 2] ^= 1;
            }
            if mutation == 5 {
                *frame.last_mut().unwrap() ^= 1;
            }
            if mutation == 6 {
                frame.truncate(salt_len + 1);
            }
            let mut source = cipher::CheckedInput {
                reader: Fragments { bytes: std::io::Cursor::new(frame), max: 1 },
                check: |_: shared::LedgerView<'_>| Ok(()),
            };
            let mut scratch = [0; 65536];
            let pending = cipher::PendingAes::copy(
                &ledger,
                &directory,
                &mut source,
                strength,
                2,
                member(stamp, original.len() as u64, plain.len() as u64, CipherKind::Aes),
                password,
                &mut scratch,
                &cancel,
            );
            let error = match pending {
                Ok(p) => p.authenticate(&mut scratch, &cancel).err().expect("bad tag"),
                Err(e) => e,
            };
            if mutation <= 3 {
                assert!(matches!(
                    error.operation(),
                    Some(ReadFault::PasswordRequired | ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes })
                ));
                assert_eq!(ledger.with_state(|s| s.encrypted.usage.create_attempts), 0);
            }
            if mutation == 4 || mutation == 5 {
                assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
            }
            ledger.with_state(|s| {
                assert_eq!(s.encrypted.usage.members, 1);
                assert_eq!(s.encrypted.usage.packed_bytes, original.len() as u128);
                assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
                assert_eq!(s.live_fds, 1);
            });
        }
        for truncated in [0, salt_len - 1, salt_len, salt_len + 1, original.len() - 11, original.len() - 1] {
            let (ledger, stamp) = super::spool::ledger(0);
            let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
            let mut source = cipher::CheckedInput {
                reader: std::io::Cursor::new(original[..truncated].to_vec()),
                check: |_: shared::LedgerView<'_>| Ok(()),
            };
            assert!(
                cipher::PendingAes::copy(
                    &ledger,
                    &directory,
                    &mut source,
                    strength,
                    1,
                    member(stamp, original.len() as u64, plain.len() as u64, CipherKind::Aes),
                    Some("password"),
                    &mut [0; 65536],
                    &cancel
                )
                .is_err()
            );
        }
    }
}

#[test]
fn source_precedence_and_snapshot_survives_source_change_restore() {
    use std::cell::Cell;
    let cancel = crate::extract::Cancellation::default();
    let frame = framed(1, "password", b"snapshot");
    for fail_at in [0, 1, 2, 3, 4] {
        let (ledger, stamp) = super::spool::ledger(0);
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
        let calls = Cell::new(0);
        let mut source = cipher::CheckedInput {
            reader: std::io::Cursor::new(frame.clone()),
            check: |view: shared::LedgerView<'_>| {
                // Proves the hook receives no outstanding RefCell guard.
                view.with_state(|_| ());
                let n = calls.get() + 1;
                calls.set(n);
                if n == fail_at { Err(io::SourceCheckError::Source(CheckedSourceFault::StampMismatch)) } else { Ok(()) }
            },
        };
        let mut scratch = [0; 65536];
        let pending = cipher::PendingAes::copy(
            &ledger,
            &directory,
            &mut source,
            1,
            2,
            member(stamp, frame.len() as u64, 8, CipherKind::Aes),
            Some("password"),
            &mut scratch,
            &cancel,
        );
        let result = match pending {
            Err(e) => Err(e),
            Ok(p) => match p.authenticate(&mut scratch, &cancel) {
                Err(e) => Err(e),
                Ok(mut a) => {
                    let n = a.read_plain_chunk(&mut scratch, &cancel).unwrap();
                    assert_eq!(&scratch[..n], b"snapshot");
                    assert_eq!(calls.get(), 3);
                    a.finish(Ok(()))
                }
            },
        };
        if fail_at == 0 {
            result.unwrap();
            assert_eq!(calls.get(), 4);
        } else {
            assert!(result.unwrap_err().is_source_changed());
        }
    }
    // Source data is overwritten/restored after copying, with source metadata
    // checks intentionally reporting equal. Authentication/decode use only the
    // owned snapshot; a source reader that panics after C+framing proves it.
    struct SnapshotSource {
        frame: Vec<u8>,
        position: usize,
    }
    impl std::io::Read for SnapshotSource {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            assert!(self.position < self.frame.len(), "original source reread");
            let n = out.len().min(self.frame.len() - self.position);
            out[..n].copy_from_slice(&self.frame[self.position..self.position + n]);
            self.position += n;
            Ok(n)
        }
    }
    impl cipher::CiphertextSource for SnapshotSource {
        fn verify_source(&mut self, _: shared::LedgerView<'_>) -> Result<(), io::SourceCheckError> {
            if self.position == self.frame.len() {
                self.frame.fill(0);
                self.frame = frame_for_restore();
            }
            Ok(())
        }
    }
    fn frame_for_restore() -> Vec<u8> {
        framed(1, "password", b"snapshot")
    }
    let (ledger, stamp) = super::spool::ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut source = SnapshotSource { frame: frame.clone(), position: 0 };
    let mut scratch = [0; 65536];
    let pending = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, frame.len() as u64, 8, CipherKind::Aes),
        Some("password"),
        &mut scratch,
        &cancel,
    )
    .unwrap();
    let mut a = pending.authenticate(&mut scratch, &cancel).unwrap();
    assert_eq!(a.read_plain_chunk(&mut scratch, &cancel).unwrap(), 8);
    assert_eq!(&scratch[..8], b"snapshot");
    a.finish(Ok(())).unwrap();
}

#[test]
fn zipcrypto_stream_header_descriptor_and_collision_evidence() {
    let cancel = crate::extract::Cancellation::default();
    for descriptor in [false, true] {
        let check = if descriptor { 0x59 } else { 0xa7 };
        let mut frame = vec![0; 12];
        frame[11] = check;
        frame.extend(b"zipcrypto streaming");
        crate::crypto::ZipCrypto::new("password").encrypt(&mut frame);
        for password in [None, Some(""), Some("wrong"), Some("password")] {
            let (ledger, stamp) = super::spool::ledger(0);
            ledger.with_state(|s| s.encrypted.limits.member_spool_bytes = 0);
            let mut plan = member(stamp, frame.len() as u64, 0, CipherKind::ZipCrypto);
            plan.crc = Some(0xa7000000);
            plan.decoded = 18;
            let mut source = cipher::CheckedInput {
                reader: Fragments { bytes: std::io::Cursor::new(frame.clone()), max: 1 },
                check: |_: shared::LedgerView<'_>| Ok(()),
            };
            let result = cipher::ZipCryptoInput::open(&ledger, &mut source, password, plan, descriptor, 0x59, &cancel);
            if password == Some("password") {
                let mut input = result.unwrap();
                let mut actual = Vec::new();
                let mut out = [0; 17];
                loop {
                    let n = input.read_plain_chunk(&mut out, &cancel).unwrap();
                    if n == 0 {
                        break;
                    }
                    actual.extend_from_slice(&out[..n]);
                }
                input.finish(Ok(())).unwrap();
                assert_eq!(actual, b"zipcrypto streaming");
            } else {
                assert!(result.is_err());
            }
            assert_eq!(ledger.with_state(|s| s.encrypted.usage.kdf_calls), 0);
        }
    }
}

#[test]
fn cancellation_copy_auth_ctr_and_source_dominance_keep_cleanup() {
    let frame = framed(1, "password", &vec![4; 65537]);
    for phase in 0..4 {
        let (ledger, stamp) = super::spool::ledger(0);
        let cancel = crate::extract::Cancellation::default();
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
        let mut source = cipher::CheckedInput {
            reader: std::io::Cursor::new(frame.clone()),
            check: |_: shared::LedgerView<'_>| Ok(()),
        };
        let mut scratch = [0; 65536];
        if phase == 0 {
            cancel.cancel();
        }
        if phase == 1 || phase == 2 {
            let signal = cancel.clone();
            spool::hooks::HOOK.with(|h| {
                *h.borrow_mut() = Some(Box::new(move |op, fd| {
                    if (phase == 1 && op == ReadIoOperation::Write)
                        || (phase == 2 && op == ReadIoOperation::Read && fd >= 0)
                    {
                        signal.cancel();
                    }
                    None
                }))
            });
        }
        let result = cipher::PendingAes::copy(
            &ledger,
            &directory,
            &mut source,
            1,
            2,
            member(stamp, frame.len() as u64, 65537, CipherKind::Aes),
            Some("password"),
            &mut scratch,
            &cancel,
        );
        let error = match result {
            Err(e) => e,
            Ok(p) => match p.authenticate(&mut scratch, &cancel) {
                Err(e) => e,
                Ok(mut a) => {
                    cancel.cancel();
                    let error = a.read_plain_chunk(&mut scratch, &cancel).unwrap_err();
                    a.finish(Err(error)).unwrap_err()
                }
            },
        };
        spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
        assert!(matches!(error.operation(), Some(ReadFault::Cancelled)));
        ledger.with_state(|s| {
            assert_eq!(s.live_fds, 1);
            assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
        });
    }
    let (ledger, stamp) = super::spool::ledger(0);
    let cancel = crate::extract::Cancellation::default();
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut bad = frame.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut calls = 0;
    let mut source = cipher::CheckedInput {
        reader: std::io::Cursor::new(bad),
        check: |_: shared::LedgerView<'_>| {
            calls += 1;
            if calls == 3 { Err(io::SourceCheckError::Source(CheckedSourceFault::StampMismatch)) } else { Ok(()) }
        },
    };
    let mut scratch = [0; 65536];
    let p = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, frame.len() as u64, 65537, CipherKind::Aes),
        Some("password"),
        &mut scratch,
        &cancel,
    )
    .unwrap();
    let error = p.authenticate(&mut scratch, &cancel).err().unwrap();
    assert!(error.is_source_changed());
    assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
    // A Pending owner can also be explicitly abandoned without dropping faults.
    let (ledger, stamp) = super::spool::ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut source =
        cipher::CheckedInput { reader: std::io::Cursor::new(frame.clone()), check: |_: shared::LedgerView<'_>| Ok(()) };
    let p = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, frame.len() as u64, 65537, CipherKind::Aes),
        Some("password"),
        &mut scratch,
        &cancel,
    )
    .unwrap();
    assert!(matches!(p.finish(Err(ReadFault::Cancelled.into())).unwrap_err().operation(), Some(ReadFault::Cancelled)));
}

#[test]
fn early_spool_work_io_and_allocation_refusal() {
    let frame = framed(1, "password", &[4; 17]);
    let cancel = crate::extract::Cancellation::default();
    for bound in 0..3 {
        let (ledger, stamp) = super::spool::ledger(0);
        let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
        ledger.with_state(|s| match bound {
            0 => s.encrypted.limits.member_spool_bytes = 0,
            1 => s.encrypted.limits.work_bytes = 0,
            _ => s.encrypted.limits.io_bytes = 0,
        });
        let mut source = cipher::CheckedInput {
            reader: std::io::Cursor::new(frame.clone()),
            check: |_: shared::LedgerView<'_>| Ok(()),
        };
        assert!(
            cipher::PendingAes::copy(
                &ledger,
                &directory,
                &mut source,
                1,
                2,
                member(stamp, frame.len() as u64, 17, CipherKind::Aes),
                Some("password"),
                &mut [0; 65536],
                &cancel
            )
            .is_err()
        );
        ledger.with_state(|s| {
            assert_eq!(s.encrypted.usage.members, 1);
            assert_eq!(s.encrypted.usage.kdf_calls, 0);
            assert_eq!(s.encrypted.usage.create_attempts, 0);
        });
    }
    let (ledger, stamp) = super::spool::ledger(65536);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let baseline = ledger.with_state(|s| s.encrypted.usage.reader_capacity);
    crate::test_alloc::DENY_LAYOUT.with(|v| v.set(Some((17, 1))));
    let mut source =
        cipher::CheckedInput { reader: std::io::Cursor::new(frame.clone()), check: |_: shared::LedgerView<'_>| Ok(()) };
    let error = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, frame.len() as u64, 17, CipherKind::Aes),
        Some("password"),
        &mut [0; 65536],
        &cancel,
    )
    .err()
    .unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Allocation { capacity: 17 })));
    assert_eq!(ledger.with_state(|s| s.encrypted.usage.reader_capacity), baseline);
}

#[test]
fn forced_verifier_and_zipcrypto_header_matches_do_not_authenticate() {
    let cancel = crate::extract::Cancellation::default();
    let original = framed(1, "password", b"collision evidence");
    let mut collision = framed(1, "other", b"collision evidence");
    collision[8..10].copy_from_slice(&original[8..10]);
    let (ledger, stamp) = super::spool::ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut scratch = [0; 65536];
    let mut source =
        cipher::CheckedInput { reader: std::io::Cursor::new(collision), check: |_: shared::LedgerView<'_>| Ok(()) };
    let pending = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, original.len() as u64, 18, CipherKind::Aes),
        Some("password"),
        &mut scratch,
        &cancel,
    )
    .unwrap();
    assert!(matches!(
        pending.authenticate(&mut scratch, &cancel).err().unwrap().operation(),
        Some(ReadFault::AuthenticationFailed)
    ));
    let mut frame = vec![0; 12];
    frame[11] = 0x59;
    crate::crypto::ZipCrypto::new("wrong").encrypt(&mut frame);
    let mut payload = b"collision evidence".to_vec();
    crate::crypto::ZipCrypto::new("password").encrypt(&mut payload);
    frame.extend(payload);
    let (ledger, stamp) = super::spool::ledger(0);
    let plan = member(stamp, frame.len() as u64, 18, CipherKind::ZipCrypto);
    let mut source =
        cipher::CheckedInput { reader: std::io::Cursor::new(frame), check: |_: shared::LedgerView<'_>| Ok(()) };
    let mut input =
        cipher::ZipCryptoInput::open(&ledger, &mut source, Some("wrong"), plan, true, 0x59, &cancel).unwrap();
    let mut bytes = [0; 18];
    assert_eq!(input.read_plain_chunk(&mut bytes, &cancel).unwrap(), 18);
    assert_ne!(&bytes, b"collision evidence");
    let error = input
        .finish(Err(ReadFault::Integrity {
            reason: IntegrityReason::Checksum,
            password_evidence: PasswordEvidence::HeaderMatched,
        }
        .into()))
        .unwrap_err();
    assert!(matches!(
        error.operation(),
        Some(ReadFault::Integrity { password_evidence: PasswordEvidence::HeaderMatched, .. })
    ));
}

#[test]
fn source_admission_does_not_invalidate_or_replace_original_auth_fault() {
    let cancel = crate::extract::Cancellation::default();
    let mut frame = framed(1, "password", b"bytes");
    *frame.last_mut().unwrap() ^= 1;
    let (ledger, stamp) = super::spool::ledger(0);
    let directory = spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap();
    let mut calls = 0;
    let mut source = cipher::CheckedInput {
        reader: std::io::Cursor::new(frame.clone()),
        check: |_: shared::LedgerView<'_>| {
            calls += 1;
            if calls == 3 { Err(io::SourceCheckError::Admission(ReadFault::InvalidPlan)) } else { Ok(()) }
        },
    };
    let mut scratch = [0; 65536];
    let p = cipher::PendingAes::copy(
        &ledger,
        &directory,
        &mut source,
        1,
        2,
        member(stamp, frame.len() as u64, 5, CipherKind::Aes),
        Some("password"),
        &mut scratch,
        &cancel,
    )
    .unwrap();
    let error = p.authenticate(&mut scratch, &cancel).err().unwrap();
    assert!(!error.is_source_changed());
    assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
}
