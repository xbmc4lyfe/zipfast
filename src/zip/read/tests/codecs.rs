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
use std::{cell::Cell, io::Write};
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
fn member(
    source: crate::zip::session::SourceStamp,
    data: &[u8],
    p: usize,
    c: usize,
    cipher: Option<CipherKind>,
) -> budget::MemberPlan {
    budget::MemberPlan {
        source,
        scope: ProjectedReadScope::AllRegular,
        ordinal: 0,
        packed: p as u64,
        decoded: data.len() as u64,
        ciphertext: c as u64,
        cipher,
        crc: Some(crc32fast::hash(data)),
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
#[allow(clippy::result_large_err)] // Test returns the same allocator-independent inline evidence as production.
fn run(method: u16, data: &[u8], bytes: Vec<u8>, fragment: usize, flags: u16) -> ZipReadResult<Vec<u8>> {
    let (ledger, stamp) = super::spool::ledger(65536);
    let checks = Cell::new(0);
    let plan = member(stamp, data, bytes.len(), bytes.len(), None);
    let mut source = cipher::CheckedInput {
        reader: Fragments { bytes: std::io::Cursor::new(bytes), max: fragment },
        check: |_: shared::LedgerView<'_>| {
            checks.set(checks.get() + 1);
            Ok(())
        },
    };
    let admitted = cipher::Admission::new(&ledger, &mut source, plan, None, cipher::InputKind::Clear)?;
    let (admitted, mut workspace) = admitted.workspace()?;
    let mut out = Vec::new();
    let receipt = codecs::decode(
        admitted.clear()?,
        &mut workspace,
        method,
        flags,
        &Default::default(),
        &Default::default(),
        &mut |b| {
            assert!(!b.is_empty());
            out.extend(b);
            Ok(())
        },
    );
    assert_eq!(checks.get(), 2, "explicit input finish on every result");
    assert_eq!(ledger.with_state(|s| s.encrypted.usage.members), 0);
    receipt.map(|r| {
        assert_eq!(r.consumed, plan.ciphertext);
        assert_eq!(r.decoded, plan.decoded);
        out
    })
}
#[test]
fn six_codec_driver_accepts_fragmented_exact_members() {
    for method in [0, 8, 12, 14, 95, 93] {
        for data in [Vec::new(), b"codec progress ".repeat(5000)] {
            for fragment in [1, 17, 65536] {
                assert_eq!(
                    run(method, &data, packed(method, &data), fragment, 2).unwrap(),
                    data,
                    "method={method} fragment={fragment}"
                );
            }
        }
    }
}

#[test]
fn exact_terminal_tail_truncation_and_concat_policy() {
    let data = b"terminal boundary ".repeat(4096);
    for method in [0, 8, 12, 14, 95, 93] {
        let original = packed(method, &data);
        let mut tail = original.clone();
        tail.push(0x51);
        assert!(run(method, &data, tail, 1, 2).is_err(), "tail method={method}");
        let mut short = original.clone();
        short.pop();
        assert!(run(method, &data, short, 17, 2).is_err(), "truncated method={method}");
        let mut concat = original.clone();
        concat.extend(&original);
        if matches!(method, 12 | 95 | 93) {
            let mut twice = data.clone();
            twice.extend(&data);
            assert_eq!(run(method, &twice, concat, 1, 2).unwrap(), twice, "concat method={method}");
        } else {
            assert!(run(method, &data, concat, 1, 2).is_err(), "concat method={method}");
        }
    }
    assert!(run(8, b"", vec![], 1, 0).is_err());
}
#[test]
fn exactly_full_output_windows_and_lzma_known_size() {
    for size in [65535, 65536, 65537, 131072] {
        let data = (0..size).map(|i| (i * 31 + i / 17) as u8).collect::<Vec<_>>();
        for method in [0, 8, 12, 14, 95, 93] {
            assert_eq!(
                run(method, &data, packed(method, &data), 65536, 2).unwrap(),
                data,
                "method={method} size={size}"
            );
        }
        assert_eq!(run(14, &data, packed(14, &data), 1, 0).unwrap(), data);
    }
}
#[test]
fn xz_padding_zstd_skippable_and_junk() {
    let data = b"padding and skippable";
    let mut xz = packed(95, data);
    xz.extend([0; 4]);
    assert_eq!(run(95, data, xz, 1, 0).unwrap(), data);
    let mut bad = packed(95, data);
    bad.push(0);
    assert!(run(95, data, bad, 1, 0).is_err());
    let mut z = vec![0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
    z.extend(packed(93, data));
    assert_eq!(run(93, data, z, 1, 0).unwrap(), data);
}
#[test]
fn all_codecs_use_real_zipcrypto_and_authenticated_aes_inputs() {
    let data = b"authenticated codec output ".repeat(2000);
    let cancel = crate::extract::Cancellation::default();
    for method in [0, 8, 12, 14, 95, 93] {
        for mode in [0, 1, 2] {
            let payload = packed(method, &data);
            let (ledger, stamp) = super::spool::ledger(if mode == 2 { 0 } else { 65536 });
            let mut bytes;
            let kind;
            let cipher;
            if mode == 0 {
                cipher = CipherKind::ZipCrypto;
                kind = cipher::InputKind::ZipCrypto { descriptor: false, time: 0 };
                bytes = vec![0; 12];
                bytes[11] = (crc32fast::hash(&data) >> 24) as u8;
                bytes.extend(&payload);
                crate::crypto::ZipCrypto::new("password").encrypt(&mut bytes);
            } else {
                cipher = CipherKind::Aes;
                kind = cipher::InputKind::Aes { strength: 1, version: if mode == 1 { 1 } else { 2 } };
                bytes = super::cipher::framed(1, "password", &payload);
            }
            let mut plan = member(stamp, &data, bytes.len(), payload.len(), Some(cipher));
            if mode == 2 {
                plan.crc = Some(123);
            } // AE-2 ignores even a nonzero wire field.
            let checks = Cell::new(0);
            let mut source = cipher::CheckedInput {
                reader: Fragments { bytes: std::io::Cursor::new(bytes), max: 1 },
                check: |_: shared::LedgerView<'_>| {
                    checks.set(checks.get() + 1);
                    Ok(())
                },
            };
            let admitted = cipher::Admission::new(&ledger, &mut source, plan, Some("password"), kind).unwrap();
            let (admitted, mut workspace) = admitted.workspace().unwrap();
            let directory = if mode == 2 {
                Some(spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap())
            } else {
                None
            };
            let input = if mode == 0 {
                codecs::PlainInput::ZipCrypto(cipher::ZipCryptoInput::open_admitted(admitted, &cancel).unwrap())
            } else {
                let pending =
                    cipher::PendingAes::copy_admitted(admitted, directory.as_ref(), &mut workspace.input, &cancel)
                        .unwrap();
                codecs::PlainInput::Aes(pending.authenticate(&mut workspace.input, &cancel).unwrap())
            };
            let mut output: Vec<u8> = Vec::new();
            let receipt = codecs::decode(input, &mut workspace, method, 2, &Default::default(), &cancel, &mut |b| {
                output.extend(b);
                Ok(())
            })
            .unwrap();
            assert_eq!(output, data, "method={method} mode={mode}");
            assert_eq!(receipt.consumed, payload.len() as u64);
            drop(workspace);
            if let Some(directory) = directory {
                directory.finish_capacity(&ledger).unwrap();
            }
            ledger.with_state(|s| {
                assert_eq!(s.encrypted.usage.members, 1);
                assert_eq!(s.encrypted.usage.allocation_attempts, if mode == 0 { 2 } else { 3 });
                assert_eq!(s.encrypted.usage.reader_capacity, shared::SHARED_LEDGER_CAPACITY as u64);
                assert_eq!(s.live_fds, 1);
            });
            assert!(checks.get() >= 3);
        }
    }
}

#[test]
fn lzma_same_known_size_fixture_matches_legacy_with_bounded_refills() {
    use std::io::Read;
    let data = (0..65535).map(|i| (i * 31 + i / 17) as u8).collect::<Vec<_>>();
    let zip = packed(14, &data);
    let mut translated = zip[4..9].to_vec();
    translated.extend((data.len() as u64).to_le_bytes());
    translated.extend(&zip[9..]);
    let stream = liblzma::stream::Stream::new_lzma_decoder(256 << 20).unwrap();
    let mut legacy = liblzma::bufread::XzDecoder::new_stream(std::io::Cursor::new(&translated), stream);
    let mut old = Vec::new();
    legacy.read_to_end(&mut old).unwrap();
    assert_eq!(old, data);
    assert_eq!(run(14, &data, zip.clone(), 1, 0).unwrap(), data);
    // Preserve the exact diagnostic fixture and native API transition evidence
    // only when deliberately requested by the qualification command.
    if let Ok(directory) = std::env::var("ZIPFAST_TASK3_EVIDENCE") {
        std::fs::write(std::path::Path::new(&directory).join("lzma-known-size-u65535.zip-payload"), &zip).unwrap();
        let mut trace = String::new();
        for fragment in [1, 65536] {
            let mut native = liblzma::stream::Stream::new_lzma_decoder(256 << 20).unwrap();
            let mut out = [0u8; 65536];
            let header = native.process(&translated[..13], &mut out, liblzma::stream::Action::Run);
            trace.push_str(&format!(
                "fragment={fragment} synthetic13={header:?} real9=9 total_in={} total_out={}\n",
                native.total_in(),
                native.total_out()
            ));
            let mut at = 13;
            while at < translated.len() {
                let end = (at + fragment).min(translated.len());
                let action = if end == translated.len() {
                    liblzma::stream::Action::Finish
                } else {
                    liblzma::stream::Action::Run
                };
                let before = native.total_in();
                let status = native.process(&translated[at..end], &mut out, action);
                let n = (native.total_in() - before) as usize;
                trace.push_str(&format!(
                    "input={at}..{end} action={action:?} out_capacity={} consumed={n} total_out={} status={status:?}\n",
                    out.len(),
                    native.total_out()
                ));
                at += n;
                if status.is_err() || matches!(status, Ok(liblzma::stream::Status::StreamEnd)) || n == 0 {
                    break;
                }
            }
        }
        std::fs::write(std::path::Path::new(&directory).join("lzma-native-trace.log"), trace).unwrap();
    }
}

#[test]
fn genuine_no_eos_lzma_uses_known_size_and_requires_exact_terminal() {
    use std::io::Read;
    let data = (0..65535).map(|i| (i * 31 + i / 17) as u8).collect::<Vec<_>>();
    let bytes = include_bytes!("../../../../tests/fixtures/lzma-no-eos-u65535.bin");
    let mut alone = bytes[4..9].to_vec();
    alone.extend((data.len() as u64).to_le_bytes());
    alone.extend(&bytes[9..]);
    let stream = liblzma::stream::Stream::new_lzma_decoder(256 << 20).unwrap();
    let mut legacy = liblzma::bufread::XzDecoder::new_stream(std::io::Cursor::new(alone), stream);
    let mut old = Vec::new();
    legacy.read_to_end(&mut old).unwrap();
    assert_eq!(old, data);
    for fragment in [1, 17, 65536] {
        assert_eq!(run(14, &data, bytes.to_vec(), fragment, 0).unwrap(), data);
    }
    assert!(run(14, &data, bytes.to_vec(), 1, 2).is_err(), "EOS flag requires marker");
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(run(14, &data, trailing, 1, 0).is_err());
    let mut short = bytes.to_vec();
    short.pop();
    assert!(run(14, &data, short, 1, 0).is_err());
}
#[test]
fn actual_sink_failure_first_middle_final_preserves_source_terminal_evidence() {
    let data = (0..196608).map(|i| (i * 73 + i / 11) as u8).collect::<Vec<_>>();
    for method in [0, 8, 12, 14, 95, 93] {
        for fail in [1, 2, 3] {
            for changed in [false, true] {
                let (ledger, stamp) = super::spool::ledger(65536);
                let bytes = packed(method, &data);
                let plan = member(stamp, &data, bytes.len(), bytes.len(), None);
                let cancel = crate::extract::Cancellation::default();
                let failed = Cell::new(false);
                let checks = Cell::new(0);
                let mut source = cipher::CheckedInput {
                    reader: std::io::Cursor::new(bytes),
                    check: |_: shared::LedgerView<'_>| {
                        checks.set(checks.get() + 1);
                        if failed.get() {
                            if changed {
                                Err(io::SourceCheckError::Source(CheckedSourceFault::StampMismatch))
                            } else {
                                Err(io::SourceCheckError::Admission(ReadFault::Cancelled))
                            }
                        } else {
                            Ok(())
                        }
                    },
                };
                let admitted =
                    cipher::Admission::new(&ledger, &mut source, plan, None, cipher::InputKind::Clear).unwrap();
                let (admitted, mut workspace) = admitted.workspace().unwrap();
                let mut calls = 0;
                let error = codecs::decode(
                    admitted.clear().unwrap(),
                    &mut workspace,
                    method,
                    2,
                    &Default::default(),
                    &cancel,
                    &mut |b| {
                        assert!(!b.is_empty());
                        calls += 1;
                        if calls == fail {
                            failed.set(true);
                            cancel.cancel();
                            Err(ZipSinkFault::StageChanged)
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
                assert_eq!(calls, fail, "no callback retry method={method}");
                assert_eq!(checks.get(), 2);
                assert!(matches!(error.sink_fault(), Some(ZipSinkFault::StageChanged)));
                if changed {
                    assert!(error.is_source_changed());
                } else {
                    assert_eq!(error.kind(), ZipReadErrorKind::Sink);
                    assert!(matches!(
                        &error.cleanup_errors().next().unwrap().cause,
                        CleanupCause::Admission(ReadFault::Cancelled)
                    ));
                }
            }
        }
    }
}
#[test]
fn clear_zero_encrypted_limits_keep_finite_shared_and_run_bounds() {
    let (ledger, stamp) = super::spool::ledger(65536);
    ledger.with_state(|s| {
        let l = &mut s.encrypted.limits;
        l.member_packed_bytes = 0;
        l.member_decoded_bytes = 0;
        l.members = 0;
        l.packed_bytes = 0;
        l.decoded_bytes = 0;
        l.source_bytes = 0;
        l.io_bytes = 0;
        l.work_bytes = 0;
        l.io_attempts = 0;
        l.codec_steps = 0;
        l.kdf_calls = 0;
        l.password_bytes = 0;
        l.allocation_attempts = 0;
    });
    let data = b"clear independent work";
    let bytes = packed(8, data);
    let plan = member(stamp, data, bytes.len(), bytes.len(), None);
    let mut source =
        cipher::CheckedInput { reader: std::io::Cursor::new(bytes), check: |_: shared::LedgerView<'_>| Ok(()) };
    let admitted = cipher::Admission::new(&ledger, &mut source, plan, None, cipher::InputKind::Clear).unwrap();
    let (admitted, mut workspace) = admitted.workspace().unwrap();
    codecs::decode(
        admitted.clear().unwrap(),
        &mut workspace,
        8,
        0,
        &Default::default(),
        &Default::default(),
        &mut |_| Ok(()),
    )
    .unwrap();
    drop(workspace);
    ledger.with_state(|s| {
        let u = s.encrypted.usage;
        assert_eq!(u.allocation_attempts, 0);
        assert_eq!(u.members, 0);
        assert_eq!(u.work_bytes, 0);
        assert_eq!(u.io_attempts, 0);
        assert_eq!(u.decoded_bytes, 0);
        assert!(s.run.usage.decode_steps > 0);
        assert!(s.run.usage.io_bytes > 0);
    });
}
#[test]
fn known_policy_and_workspace_failures_spend_one_attempt_before_allocation() {
    for known in [false, true] {
        let (ledger, stamp) = super::spool::ledger(65536);
        ledger.with_state(|s| {
            if known {
                s.encrypted.limits.member_packed_bytes = 1;
            } else {
                s.encrypted.limits.allocation_attempts = 1;
            }
        });
        let bytes = super::cipher::framed(1, "password", b"x");
        let plan = member(stamp, b"x", bytes.len(), 1, Some(CipherKind::Aes));
        let mut source =
            cipher::CheckedInput { reader: std::io::Cursor::new(bytes), check: |_: shared::LedgerView<'_>| Ok(()) };
        let result = cipher::Admission::new(
            &ledger,
            &mut source,
            plan,
            Some("password"),
            cipher::InputKind::Aes { strength: 1, version: 1 },
        );
        if known {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().workspace().is_err());
        }
        ledger.with_state(|s| {
            assert_eq!(s.encrypted.usage.members, 1);
            assert_eq!(s.encrypted.usage.packed_bytes, 21);
            assert_eq!(s.encrypted.usage.allocation_attempts, if known { 0 } else { 1 });
            assert_eq!(s.encrypted.usage.reader_capacity, shared::SHARED_LEDGER_CAPACITY as u64);
            assert_eq!(s.encrypted.usage.source_bytes, 0);
        });
    }
}
#[test]
fn native_policy_limits_precede_window_allocation() {
    let data = b"x";
    let mut l = packed(14, data);
    l[5..9].copy_from_slice(&(512u32 << 20).to_le_bytes());
    assert!(run(14, data, l, 1, 2).is_err());
    let z = vec![0x28, 0xb5, 0x2f, 0xfd, 0, 0x90, 0x09, 0, 0, b'x'];
    assert!(run(93, data, z, 1, 0).is_err());
}

#[test]
fn encrypted_codec_sink_crc_and_cancel_errors_finish_inputs() {
    let data = b"finish every capability ".repeat(500);
    let cancel = crate::extract::Cancellation::default();
    for method in [0, 8, 12, 14, 95, 93] {
        for mode in [0, 1, 2] {
            for fault in [0, 1, 2] {
                let payload = packed(method, &data);
                let (ledger, stamp) = super::spool::ledger(if mode == 2 { 0 } else { 65536 });
                let (bytes, kind, cipher) = if mode == 0 {
                    let mut bytes = vec![0; 12];
                    bytes[11] = (crc32fast::hash(&data) >> 24) as u8;
                    bytes.extend(&payload);
                    crate::crypto::ZipCrypto::new("password").encrypt(&mut bytes);
                    (bytes, cipher::InputKind::ZipCrypto { descriptor: false, time: 0 }, CipherKind::ZipCrypto)
                } else {
                    (
                        super::cipher::framed(1, "password", &payload),
                        cipher::InputKind::Aes { strength: 1, version: 1 },
                        CipherKind::Aes,
                    )
                };
                let mut plan = member(stamp, &data, bytes.len(), payload.len(), Some(cipher));
                if fault == 0 {
                    plan.crc = Some(plan.crc.unwrap() ^ 1);
                }
                // ZipCrypto header still matches the deliberately changed CRC high byte.
                let checks = Cell::new(0);
                let mut source = cipher::CheckedInput {
                    reader: std::io::Cursor::new(bytes),
                    check: |_: shared::LedgerView<'_>| {
                        checks.set(checks.get() + 1);
                        Ok(())
                    },
                };
                let admitted = cipher::Admission::new(&ledger, &mut source, plan, Some("password"), kind).unwrap();
                let (admitted, mut workspace) = admitted.workspace().unwrap();
                let directory = if mode == 2 {
                    Some(spool::ResolvedTempDirectory::resolve(&ledger, None, &cancel).unwrap())
                } else {
                    None
                };
                let input = if mode == 0 {
                    codecs::PlainInput::ZipCrypto(cipher::ZipCryptoInput::open_admitted(admitted, &cancel).unwrap())
                } else {
                    let pending =
                        cipher::PendingAes::copy_admitted(admitted, directory.as_ref(), &mut workspace.input, &cancel)
                            .unwrap();
                    codecs::PlainInput::Aes(pending.authenticate(&mut workspace.input, &cancel).unwrap())
                };
                let before = checks.get();
                let cancellation = crate::extract::Cancellation::default();
                let mut calls = 0;
                let error =
                    codecs::decode(input, &mut workspace, method, 2, &Default::default(), &cancellation, &mut |_| {
                        calls += 1;
                        if fault == 1 {
                            Err(ZipSinkFault::StageChanged)
                        } else if fault == 2 {
                            cancellation.cancel();
                            Ok(())
                        } else {
                            Ok(())
                        }
                    })
                    .unwrap_err();
                if let Some(directory) = directory {
                    directory.finish_capacity(&ledger).unwrap();
                }
                assert_eq!(checks.get(), before + 1);
                if fault == 0 {
                    assert!(
                        matches!(error.operation(),Some(ReadFault::Integrity {reason:IntegrityReason::Checksum,password_evidence}) if *password_evidence==if mode==0 {PasswordEvidence::HeaderMatched} else {PasswordEvidence::Authenticated})
                    );
                }
                if fault == 1 {
                    assert_eq!(calls, 1);
                    assert!(error.sink_fault().is_some());
                }
                if fault == 2 {
                    assert!(matches!(error.operation(), Some(ReadFault::Cancelled)));
                }
                ledger.with_state(|s| {
                    assert_eq!(s.live_fds, 1);
                    assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
                });
            }
        }
    }
}
#[test]
fn actual_workspace_allocation_failure_preserves_attempt_and_source_completion() {
    let (ledger, stamp) = super::spool::ledger(65536);
    let bytes = super::cipher::framed(1, "password", b"x");
    let plan = member(stamp, b"x", bytes.len(), 1, Some(CipherKind::Aes));
    let checks = Cell::new(0);
    let mut source = cipher::CheckedInput {
        reader: std::io::Cursor::new(bytes),
        check: |_: shared::LedgerView<'_>| {
            checks.set(checks.get() + 1);
            Ok(())
        },
    };
    let admitted = cipher::Admission::new(
        &ledger,
        &mut source,
        plan,
        Some("password"),
        cipher::InputKind::Aes { strength: 1, version: 1 },
    )
    .unwrap();
    crate::test_alloc::DENY_LAYOUT.with(|v| v.set(Some((65536, 1))));
    let error = admitted.workspace().err().unwrap();
    assert!(matches!(error.operation(), Some(ReadFault::Allocation { capacity: 65536 })));
    assert_eq!(checks.get(), 2);
    ledger.with_state(|s| {
        assert_eq!(s.encrypted.usage.members, 1);
        assert_eq!(s.encrypted.usage.packed_bytes, 21);
        assert_eq!(s.encrypted.usage.allocation_attempts, 1);
        assert_eq!(s.encrypted.usage.reader_capacity, shared::SHARED_LEDGER_CAPACITY as u64);
    });
}
#[test]
fn stored_aes_work_and_codec_step_limits_are_exact() {
    let data = b"work accounting";
    let cancel = crate::extract::Cancellation::default();
    let mut successful_steps = 0;
    for attempt in [0, 1, 2, 3] {
        let (ledger, stamp) = super::spool::ledger(65536);
        ledger.with_state(|s| {
            s.encrypted.limits.work_bytes = data.len() as u128 * 5 - if attempt == 1 { 1 } else { 0 };
            if attempt >= 2 {
                s.encrypted.limits.codec_steps = successful_steps - if attempt == 3 { 1 } else { 0 };
            }
        });
        let bytes = super::cipher::framed(1, "password", data);
        let plan = member(stamp, data, bytes.len(), data.len(), Some(CipherKind::Aes));
        let mut source =
            cipher::CheckedInput { reader: std::io::Cursor::new(bytes), check: |_: shared::LedgerView<'_>| Ok(()) };
        let admitted = cipher::Admission::new(
            &ledger,
            &mut source,
            plan,
            Some("password"),
            cipher::InputKind::Aes { strength: 1, version: 1 },
        );
        if attempt == 1 {
            assert!(matches!(
                admitted.err().unwrap().operation(),
                Some(ReadFault::Limit { resource: ReadResource::WorkBytes, .. })
            ));
            ledger.with_state(|s| {
                assert_eq!(s.encrypted.usage.allocation_attempts, 0);
                assert_eq!(s.encrypted.usage.source_bytes, 0);
                assert_eq!(s.encrypted.usage.kdf_calls, 0);
                assert_eq!(s.encrypted.usage.work_bytes, 0);
                assert_eq!(s.encrypted.usage.io_bytes, 0);
                assert_eq!(s.encrypted.usage.codec_steps, 0);
                assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
                assert_eq!(s.live_fds, 1);
                assert_eq!(s.encrypted.usage.members, 1);
                assert_eq!(s.encrypted.usage.packed_bytes, plan.packed as u128);
            });
            continue;
        }
        let admitted = admitted.unwrap();
        let (admitted, mut workspace) = admitted.workspace().unwrap();
        let pending = cipher::PendingAes::copy_admitted(admitted, None, &mut workspace.input, &cancel).unwrap();
        let input = codecs::PlainInput::Aes(pending.authenticate(&mut workspace.input, &cancel).unwrap());
        let result = codecs::decode(input, &mut workspace, 0, 0, &Default::default(), &cancel, &mut |_| Ok(()));
        if attempt == 0 {
            result.unwrap();
            successful_steps = ledger.with_state(|s| {
                assert_eq!(s.encrypted.usage.work_bytes, data.len() as u128 * 5);
                s.encrypted.usage.codec_steps
            });
        } else if attempt == 2 {
            result.unwrap();
        } else {
            assert!(
                matches!(result.unwrap_err().operation(),Some(ReadFault::Limit {resource,..}) if *resource==if attempt==1 {ReadResource::WorkBytes} else {ReadResource::CodecSteps})
            );
        }
    }
}

#[test]
fn lzma_known_size_marker_crossing_native_window_is_exact() {
    let mut seed = 0x8135_712du32;
    let random = (0..66000)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        })
        .collect::<Vec<_>>();
    let mut low = 63000;
    let mut high = random.len();
    while low < high {
        let mid = (low + high) / 2;
        if packed(14, &random[..mid]).len() - 9 < 65539 {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    let data = &random[..low];
    let payload = packed(14, data);
    assert!((65539..65548).contains(&(payload.len() - 9)));
    if let Ok(directory) = std::env::var("ZIPFAST_TASK3_EVIDENCE") {
        use std::io::Read;
        let mut translated = payload[4..9].to_vec();
        translated.extend((data.len() as u64).to_le_bytes());
        translated.extend(&payload[9..]);
        std::fs::write(std::path::Path::new(&directory).join("lzma-known-size-native-window.zip-payload"), &payload)
            .unwrap();
        let mut trace = String::new();
        for finish in [false, true] {
            let mut native = liblzma::stream::Stream::new_lzma_decoder(256 << 20).unwrap();
            let mut out = [0u8; 65536];
            trace.push_str(&format!(
                "U={} realC={} header={:?}\n",
                data.len(),
                payload.len(),
                native.process(&translated[..13], &mut out, liblzma::stream::Action::Run)
            ));
            let mut at = 13;
            while at < translated.len() {
                let end = (at + 65536).min(translated.len());
                let action = if finish && end == translated.len() {
                    liblzma::stream::Action::Finish
                } else {
                    liblzma::stream::Action::Run
                };
                let before = native.total_in();
                let status = native.process(&translated[at..end], &mut out, action);
                let n = (native.total_in() - before) as usize;
                trace.push_str(&format!(
                    "range={at}..{end} action={action:?} consumed={n} out_capacity={} output={} status={status:?}\n",
                    out.len(),
                    native.total_out()
                ));
                at += n;
                if status.is_err() || matches!(status, Ok(liblzma::stream::Status::StreamEnd)) || n == 0 {
                    break;
                }
            }
        }
        for fragment in [8192, 65536, 131072] {
            let stream = liblzma::stream::Stream::new_lzma_decoder(256 << 20).unwrap();
            let source = std::io::BufReader::with_capacity(fragment, std::io::Cursor::new(&translated));
            let mut legacy = liblzma::bufread::XzDecoder::new_stream(source, stream);
            let mut old = Vec::new();
            let result = legacy.read_to_end(&mut old);
            trace.push_str(&format!("legacy_capacity={fragment} output={} result={result:?}\n", old.len()));
        }
        std::fs::write(std::path::Path::new(&directory).join("lzma-native-window-action-trace.log"), trace).unwrap();
    }
    assert_eq!(run(14, data, payload, 1, 0).unwrap(), data);
}

#[test]
fn missing_crc_repeated_refusals_and_pre_cipher_abort_are_explicit() {
    let (ledger, stamp) = super::spool::ledger(65536);
    for _ in 0..3 {
        let bytes = super::cipher::framed(1, "password", b"x");
        let mut plan = member(stamp, b"x", bytes.len(), 1, Some(CipherKind::Aes));
        plan.crc = None;
        let mut source =
            cipher::CheckedInput { reader: std::io::Cursor::new(bytes), check: |_: shared::LedgerView<'_>| Ok(()) };
        assert!(
            cipher::Admission::new(
                &ledger,
                &mut source,
                plan,
                Some("password"),
                cipher::InputKind::Aes { strength: 1, version: 1 }
            )
            .is_err()
        );
    }
    ledger.with_state(|s| {
        assert_eq!(s.encrypted.usage.members, 3);
        assert_eq!(s.encrypted.usage.packed_bytes, 63);
        assert_eq!(s.encrypted.usage.allocation_attempts, 0);
        assert_eq!(s.encrypted.usage.kdf_calls, 0);
    });
    let plan = member(stamp, b"", 0, 0, None);
    let checks = Cell::new(0);
    let mut source = cipher::CheckedInput {
        reader: std::io::empty(),
        check: |_: shared::LedgerView<'_>| {
            checks.set(checks.get() + 1);
            Ok(())
        },
    };
    let admitted = cipher::Admission::new(&ledger, &mut source, plan, None, cipher::InputKind::Clear).unwrap();
    let error = admitted.finish(Err(ReadFault::Cancelled.into())).unwrap_err();
    assert!(matches!(error.operation(), Some(ReadFault::Cancelled)));
    assert_eq!(checks.get(), 2);
}
#[test]
fn rejected_aes_never_constructs_codec_and_retains_one_attempt() {
    for method in [0, 8, 12, 14, 95, 93] {
        let (ledger, stamp) = super::spool::ledger(65536);
        let payload = packed(method, b"no decoder before HMAC");
        let mut bytes = super::cipher::framed(1, "password", &payload);
        *bytes.last_mut().unwrap() ^= 1;
        let plan = member(stamp, b"no decoder before HMAC", bytes.len(), payload.len(), Some(CipherKind::Aes));
        let mut source =
            cipher::CheckedInput { reader: std::io::Cursor::new(bytes), check: |_: shared::LedgerView<'_>| Ok(()) };
        let admitted = cipher::Admission::new(
            &ledger,
            &mut source,
            plan,
            Some("password"),
            cipher::InputKind::Aes { strength: 1, version: 1 },
        )
        .unwrap();
        let (admitted, mut workspace) = admitted.workspace().unwrap();
        let pending =
            cipher::PendingAes::copy_admitted(admitted, None, &mut workspace.input, &Default::default()).unwrap();
        let error = pending.authenticate(&mut workspace.input, &Default::default()).err().unwrap();
        assert!(matches!(error.operation(), Some(ReadFault::AuthenticationFailed)));
        ledger.with_state(|s| {
            assert_eq!(s.encrypted.usage.codec_steps, 0);
            assert_eq!(s.run.usage.decode_steps, 0);
            assert_eq!(s.encrypted.usage.members, 1);
            assert_eq!(s.encrypted.usage.live_spool_bytes, 0);
        });
    }
}

#[test]
fn fixed_control_and_reader_capacity_receipt() {
    let sizes = codecs::control_layout();
    let error = std::mem::size_of::<ZipReadError>();
    let result = std::mem::size_of::<ZipReadResult<()>>();
    let report = std::mem::size_of::<ObjectCleanupReport>();
    // Conservatively cover two moving terminal values/reports, every capability
    // state (even phases that are exclusive), both LZMA headers, fixed scalars.
    let control = 2 * error + 2 * report + sizes[..6].iter().sum::<usize>() + 22 + 512;
    assert!(control <= sizes[6]);
    assert_eq!(error, 4352);
    assert_eq!(result, 4352);
    assert_eq!(report, 656);
    let total = shared::SHARED_LEDGER_CAPACITY + 4096 + 2 * 65536 + 65536 + sizes[6];
    assert!(total <= 256 << 10);
    eprintln!(
        "header={} error={error} result={result} report={report} engine/input/workspace/pending/admission/crc/control={sizes:?} conservative_typed_control={control} capacity_with_path_and_max_default_ciphertext={total}",
        shared::SHARED_LEDGER_CAPACITY
    );
}

#[test]
fn real_authenticated_sink_and_source_error_need_no_wrapper_allocation() {
    let (ledger, stamp) = super::spool::ledger(65536);
    let data = b"inline errors";
    let bytes = super::cipher::framed(1, "password", data);
    let plan = member(stamp, data, bytes.len(), data.len(), Some(CipherKind::Aes));
    let failed = Cell::new(false);
    let mut source = cipher::CheckedInput {
        reader: std::io::Cursor::new(bytes),
        check: |_: shared::LedgerView<'_>| {
            if failed.get() {
                Err(io::SourceCheckError::Source(CheckedSourceFault::Unavailable {
                    stage: IoStage::SourceHandle,
                    error: std::io::Error::from_raw_os_error(5),
                }))
            } else {
                Ok(())
            }
        },
    };
    let admitted = cipher::Admission::new(
        &ledger,
        &mut source,
        plan,
        Some("password"),
        cipher::InputKind::Aes { strength: 1, version: 1 },
    )
    .unwrap();
    let (admitted, mut workspace) = admitted.workspace().unwrap();
    let pending = cipher::PendingAes::copy_admitted(admitted, None, &mut workspace.input, &Default::default()).unwrap();
    let input = codecs::PlainInput::Aes(pending.authenticate(&mut workspace.input, &Default::default()).unwrap());
    let options = EncryptedReadOptions::default();
    let cancel = crate::extract::Cancellation::default();
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(true));
    let result = codecs::decode(input, &mut workspace, 0, 0, &options, &cancel, &mut |_| {
        failed.set(true);
        Err(ZipSinkFault::StageChanged)
    });
    crate::test_alloc::REFUSE_ALLOCATIONS.with(|v| v.set(false));
    let error = result.unwrap_err();
    assert!(error.is_source_changed());
    assert!(matches!(error.sink_fault(), Some(ZipSinkFault::StageChanged)));
}
