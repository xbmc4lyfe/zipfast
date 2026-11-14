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

//! Legacy RAR5 callback, summary, and destination behavior using generated archives.
mod common;

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use common::*;
use zipfast::Error;
use zipfast::crypto::{derive_rar5_key, encrypt_cbc};
use zipfast::extract::{self, Mode, Options, Overwrite, Summary};
use zipfast::rar5::testenc::{self, Op};

const PASSWORD: &str = "correct-test-password";
const SALT: [u8; 16] = [0x53; 16];
const IV: [u8; 16] = [0x49; 16];
const KDF_COUNT: u8 = 4;
// Python hashlib: PBKDF2-HMAC-SHA256 at 2^4 + 32 iterations, folded to eight bytes,
// followed by the first four bytes of SHA-256 of the folded check.
const CHECK: [u8; 12] = [0xfa, 0x6b, 0x0b, 0xa5, 0x09, 0x0c, 0xec, 0x2b, 0x1c, 0xce, 0xa7, 0x29];

fn options(dest: &Path, threads: usize) -> Options {
    Options {
        mode: Mode::Extract,
        dest: dest.into(),
        overwrite: Overwrite::Always,
        flatten: false,
        threads: Some(threads),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

fn counters(s: &Summary) -> (u64, u64, u64, u64, u64) {
    (s.files, s.dirs, s.bytes, s.skipped, s.volumes)
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

fn encrypted_record(iv: Option<&[u8; 16]>) -> Vec<u8> {
    let mut fields = vec![0, 1, KDF_COUNT]; // encryption version, verifier flag, KDF exponent
    fields.extend(SALT);
    if let Some(iv) = iv {
        fields.extend(iv);
    }
    fields.extend(CHECK);
    fields
}

fn extra_record(kind: u8, fields: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    vint((1 + fields.len()) as u64, &mut record);
    record.push(kind);
    record.extend(fields);
    record
}

fn stored_block(spec: &FileSpec<'_>) -> Vec<u8> {
    file_block(spec, spec.data, crc32fast::hash(spec.data), false, false)
}

// FileSpec encodes algorithm zero. Build a method 3 header using algorithm 1.
fn unsupported_block(stream: &[u8], plain: &[u8]) -> Vec<u8> {
    let name = b"unsupported";
    let mut fields = vec![4]; // CRC flag
    vint(plain.len() as u64, &mut fields);
    vint(0x20, &mut fields); // attributes
    fields.extend(crc32fast::hash(plain).to_le_bytes());
    vint((3 << 7) | 1, &mut fields);
    vint(0, &mut fields); // host OS
    vint(name.len() as u64, &mut fields);
    fields.extend(name);
    block(2, 0, &fields, &[], stream, true)
}

#[test]
fn mixed_members_keep_exact_reports_and_counts_in_extract_and_test() {
    let scratch = tempfile::tempdir().unwrap();
    let arc = scratch.path().join("mixed.rar");
    let key = derive_rar5_key(PASSWORD, KDF_COUNT, &SALT, None).unwrap();
    let secret = b"secret payload!!";
    let ciphertext = encrypt_cbc(&key, &IV, secret).unwrap();
    let (packed_data, plain) = packed("good", &[Op::Lit(b'a'), Op::Match(9, 1)]);
    let good = FileSpec { method: 3, size: Some(plain.len() as u64), ..FileSpec::new("good", &packed_data) };
    let old = FileSpec { extra: extra_record(4, &[0, 2]), ..FileSpec::new("versioned", b"old") };
    let dir = FileSpec { dir: true, unix_mode: Some(0o755), ..FileSpec::new("folder", b"") };
    let encrypted =
        FileSpec { extra: extra_record(1, &encrypted_record(Some(&IV))), ..FileSpec::new("encrypted", &ciphertext) };
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    bytes.extend(file_block(&FileSpec::new("keep", b"damaged"), b"damaged", 0, false, false));
    bytes.extend(stored_block(&dir));
    bytes.extend(stored_block(&old));
    bytes.extend(stored_block(&FileSpec::new("versioned", b"new")));
    bytes.extend(file_block(&encrypted, &ciphertext, crc32fast::hash(secret), false, false));
    bytes.extend(stored_block(&FileSpec::new("exists", b"replacement")));
    bytes.extend(stored_block(&FileSpec::new("empty", b"")));
    bytes.extend(unsupported_block(&packed_data, &plain));
    bytes.extend(file_block(&good, &packed_data, crc32fast::hash(&plain), false, false));
    bytes.extend(file_block(&FileSpec::new("remove", b"broken"), b"broken", 0, false, false));
    bytes.extend(end_block(false));
    fs::write(&arc, &bytes).unwrap();

    for threads in [1, 4] {
        for (mode, overwrite) in
            [(Mode::Extract, Overwrite::Skip), (Mode::Extract, Overwrite::Always), (Mode::Test, Overwrite::Always)]
        {
            let out = scratch.path().join(format!("{threads}-{mode:?}-{overwrite:?}"));
            fs::create_dir(&out).unwrap();
            fs::write(out.join("keep"), b"original keep").unwrap();
            fs::write(out.join("exists"), b"original exists").unwrap();
            let opts = Options { mode, overwrite, ..options(&out, threads) };
            let mut lines = Vec::new();
            let summary = extract::run_with_password(&arc, &opts, Some("wrong-password"), |line| {
                lines.push(line.to_owned());
            })
            .unwrap();

            let tail = "remove: checksum error";
            let unsupported = "unsupported: RAR 7 compression is not supported yet";
            let wrong = "encrypted: wrong password";
            let bad = "keep: checksum error";
            let older = "versioned: older version 2, skipped";
            match (mode, overwrite) {
                (Mode::Extract, Overwrite::Skip) => {
                    assert_eq!(
                        lines,
                        ["keep: exists, skipped", older, wrong, "exists: exists, skipped", unsupported, tail]
                    );
                    assert_eq!(summary.errors, [wrong, unsupported, tail]);
                    assert_eq!(counters(&summary), (3, 1, 13, 3, 1));
                    assert_eq!(fs::read(out.join("exists")).unwrap(), b"original exists");
                }
                (Mode::Extract, Overwrite::Always) => {
                    assert_eq!(lines, [bad, older, wrong, unsupported, tail]);
                    assert_eq!(summary.errors, [bad, wrong, unsupported, tail]);
                    assert_eq!(counters(&summary), (4, 1, 24, 1, 1));
                    assert_eq!(fs::read(out.join("exists")).unwrap(), b"replacement");
                }
                (Mode::Test, _) => {
                    assert_eq!(lines, [bad, wrong, unsupported, tail]);
                    assert_eq!(summary.errors, [bad, wrong, unsupported, tail]);
                    assert_eq!(counters(&summary), (5, 1, 27, 0, 1));
                    assert_eq!(names(&out), ["exists", "keep"]);
                    assert_eq!(fs::read(out.join("exists")).unwrap(), b"original exists");
                }
            }
            assert_eq!(fs::read(out.join("keep")).unwrap(), b"original keep");
            if mode == Mode::Extract {
                assert_eq!(names(&out), ["empty", "exists", "folder", "good", "keep", "versioned"]);
                assert!(out.join("folder").is_dir());
                assert_eq!(fs::read(out.join("versioned")).unwrap(), b"new");
                assert_eq!(fs::read(out.join("empty")).unwrap(), b"");
                assert_eq!(fs::read(out.join("good")).unwrap(), plain);
            }
        }
        let out = scratch.path().join(format!("right-password-{threads}"));
        let mut lines = Vec::new();
        let summary = extract::run_with_password(&arc, &options(&out, threads), Some(PASSWORD), |line| {
            lines.push(line.to_owned());
        })
        .unwrap();
        assert_eq!(
            lines,
            [
                "keep: checksum error",
                "versioned: older version 2, skipped",
                "unsupported: RAR 7 compression is not supported yet",
                "remove: checksum error",
            ]
        );
        assert_eq!(
            summary.errors,
            ["keep: checksum error", "unsupported: RAR 7 compression is not supported yet", "remove: checksum error",]
        );
        assert_eq!(counters(&summary), (5, 1, 40, 1, 1));
        assert_eq!(fs::read(out.join("encrypted")).unwrap(), secret);
    }
    assert_eq!(fs::read(arc).unwrap(), bytes);
}

#[test]
fn orphan_is_silent_and_mismatched_continuation_starts_a_member() {
    let scratch = tempfile::tempdir().unwrap();
    let first = scratch.path().join("split.part1.rar");
    let second = scratch.path().join("split.part2.rar");
    let mut a = SIG.to_vec();
    a.extend(main_block(true, None));
    a.extend(file_block(&FileSpec::new("orphan", b"tail"), b"tail", 0, true, false));
    let interrupted = FileSpec { size: Some(8), ..FileSpec::new("keep", b"head") };
    a.extend(file_block(&interrupted, b"head", crc32fast::hash(b"head"), false, true));
    a.extend(end_block(true));
    let mut b = SIG.to_vec();
    b.extend(main_block(true, Some(1)));
    let other = FileSpec::new("other", b"whole");
    b.extend(file_block(&other, other.data, crc32fast::hash(other.data), true, false));
    b.extend(end_block(false));
    fs::write(&first, &a).unwrap();
    fs::write(&second, &b).unwrap();

    for threads in [1, 4] {
        let out = scratch.path().join(format!("out-{threads}"));
        fs::create_dir(&out).unwrap();
        fs::write(out.join("keep"), b"original").unwrap();
        let mut lines = Vec::new();
        let s = extract::run(&first, &options(&out, threads), |line| lines.push(line.to_owned())).unwrap();
        assert_eq!(lines, ["keep: next part is missing"]);
        assert_eq!(s.errors, lines);
        assert_eq!(counters(&s), (1, 0, 5, 1, 2));
        assert_eq!(names(&out), ["keep", "other"]);
        assert_eq!(fs::read(out.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read(out.join("other")).unwrap(), b"whole");
    }
    assert_eq!(fs::read(first).unwrap(), a);
    assert_eq!(fs::read(second).unwrap(), b);
}

#[test]
fn solid_members_and_stored_file_report_in_order_and_keep_history() {
    let scratch = tempfile::tempdir().unwrap();
    let arc = scratch.path().join("solid.rar");
    let start = testenc::block(&[Op::Lit(b'z')], true, true);
    let continuation = testenc::block(&[Op::Match(12, 1)], false, true);
    let specs = [
        (FileSpec { method: 6, size: Some(1), ..FileSpec::new("start", &start) }, crc32fast::hash(b"z")),
        (FileSpec { method: 3, size: Some(12), solid: true, ..FileSpec::new("keep", &continuation) }, 0),
        (FileSpec::new("stored", b"damaged"), 0),
        (
            FileSpec { method: 7, size: Some(12), solid: true, ..FileSpec::new("last", &continuation) },
            crc32fast::hash(&[b'z'; 12]),
        ),
    ];
    let bytes = archive_with(&specs, true);
    fs::write(&arc, &bytes).unwrap();

    for threads in [1, 4] {
        let out = scratch.path().join(format!("out-{threads}"));
        fs::create_dir(&out).unwrap();
        fs::write(out.join("keep"), b"original").unwrap();
        let mut lines = Vec::new();
        let s = extract::run(&arc, &options(&out, threads), |line| lines.push(line.to_owned())).unwrap();
        assert_eq!(lines, ["keep: checksum error", "stored: checksum error"]);
        assert_eq!(s.errors, lines);
        assert_eq!(counters(&s), (2, 0, 13, 0, 1));
        assert_eq!(names(&out), ["keep", "last", "start"]);
        assert_eq!(fs::read(out.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read(out.join("last")).unwrap(), [b'z'; 12]);
        assert_eq!(fs::read(out.join("start")).unwrap(), b"z");
    }
    assert_eq!(fs::read(arc).unwrap(), bytes);
}

#[test]
fn corrupt_header_after_batch_jobs_drains_in_archive_order() {
    let scratch = tempfile::tempdir().unwrap();
    let arc = scratch.path().join("fatal.rar");
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    bytes.extend(file_block(&FileSpec::new("keep", b"damaged"), b"damaged", 0, false, false));
    bytes.extend(stored_block(&FileSpec::new("good", b"verified")));
    bytes.extend(file_block(&FileSpec::new("remove", b"broken"), b"broken", 0, false, false));
    let mut bad_end = end_block(false);
    bad_end[0] ^= 1;
    bytes.extend(bad_end);
    fs::write(&arc, &bytes).unwrap();

    for threads in [1, 4] {
        let out = scratch.path().join(format!("out-{threads}"));
        fs::create_dir(&out).unwrap();
        fs::write(out.join("keep"), b"original").unwrap();
        let mut lines = Vec::new();
        let error = extract::run(&arc, &options(&out, threads), |line| lines.push(line.to_owned())).unwrap_err();
        assert!(matches!(error, Error::Corrupt("header checksum mismatch")), "{error:?}");
        assert_eq!(lines, ["keep: checksum error", "remove: checksum error"]);
        assert_eq!(names(&out), ["good", "keep"]);
        assert_eq!(fs::read(out.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read(out.join("good")).unwrap(), b"verified");
    }
    assert_eq!(fs::read(arc).unwrap(), bytes);
}

#[test]
fn terminal_header_password_rejection_has_no_member_reports() {
    let scratch = tempfile::tempdir().unwrap();
    let arc = scratch.path().join("encrypted-headers.rar");
    let key = derive_rar5_key(PASSWORD, KDF_COUNT, &SALT, None).unwrap();
    let mut bytes = SIG.to_vec();
    bytes.extend(block(4, 0, &encrypted_record(None), &[], &[], false));
    for mut header in [main_block(false, None), stored_block(&FileSpec::new("empty", b"")), end_block(false)] {
        header.resize(header.len().next_multiple_of(16), 0);
        bytes.extend(IV);
        bytes.extend(encrypt_cbc(&key, &IV, &header).unwrap());
    }
    fs::write(&arc, &bytes).unwrap();

    for threads in [1, 4] {
        let out = scratch.path().join(format!("out-{threads}"));
        let opts = options(&out, threads);
        let mut lines = Vec::new();
        for password in [None, Some("wrong-password")] {
            let error =
                extract::run_with_password(&arc, &opts, password, |line| lines.push(line.to_owned())).unwrap_err();
            assert!(matches!(error, Error::Encrypted), "{error:?}");
            assert!(lines.is_empty(), "{lines:?}");
            assert!(names(&out).is_empty());
        }
        let s = extract::run_with_password(&arc, &opts, Some(PASSWORD), |line| lines.push(line.to_owned())).unwrap();
        assert!(lines.is_empty(), "{lines:?}");
        assert!(s.errors.is_empty(), "{:?}", s.errors);
        assert_eq!(counters(&s), (1, 0, 0, 0, 1));
        assert_eq!(names(&out), ["empty"]);
        assert_eq!(fs::read(out.join("empty")).unwrap(), b"");
    }
    assert_eq!(fs::read(arc).unwrap(), bytes);
}

#[test]
fn terminal_destination_io_preserves_error_kind_and_input() {
    let scratch = tempfile::tempdir().unwrap();
    let arc = scratch.path().join("io.rar");
    let bytes = archive(&[FileSpec::new("file", b"payload")]);
    fs::write(&arc, &bytes).unwrap();
    let out = scratch.path().join("out");
    fs::write(&out, b"original").unwrap();
    let os_error = fs::create_dir_all(&out).unwrap_err();

    for threads in [1, 4] {
        let mut lines = Vec::new();
        let error = extract::run(&arc, &options(&out, threads), |line| lines.push(line.to_owned())).unwrap_err();
        let Error::Io(cause) = error else { panic!("expected destination I/O error, got {error:?}") };
        assert_eq!(cause.kind(), ErrorKind::AlreadyExists);
        assert_eq!(cause.raw_os_error(), os_error.raw_os_error());
        assert!(lines.is_empty(), "{lines:?}");
        assert_eq!(fs::read(&out).unwrap(), b"original");
    }
    assert_eq!(fs::read(arc).unwrap(), bytes);
}

#[test]
fn methods_six_and_seven_decode_valid_algorithm_zero_streams() {
    let scratch = tempfile::tempdir().unwrap();
    let arc = scratch.path().join("methods.rar");
    let (stream, plain) = packed("method", &[Op::Lit(b'!'), Op::Match(30, 1)]);
    let crc = crc32fast::hash(&plain);
    let spec = |name, method| FileSpec { method, size: Some(plain.len() as u64), ..FileSpec::new(name, &stream) };
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    bytes.extend(file_block(&spec("six", 6), &stream, crc, false, false));
    bytes.extend(unsupported_block(&stream, &plain));
    bytes.extend(file_block(&spec("seven", 7), &stream, crc, false, false));
    bytes.extend(end_block(false));
    fs::write(&arc, &bytes).unwrap();
    let entries = extract::list(&arc).unwrap();
    let methods: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.method)).collect();
    assert_eq!(methods, [("six", 6), ("unsupported", 3), ("seven", 7)]);

    for threads in [1, 4] {
        for mode in [Mode::Test, Mode::Extract] {
            let out = scratch.path().join(format!("out-{threads}-{mode:?}"));
            let opts = Options { mode, ..options(&out, threads) };
            let mut lines = Vec::new();
            let s = extract::run(&arc, &opts, |line| lines.push(line.to_owned())).unwrap();
            assert_eq!(lines, ["unsupported: RAR 7 compression is not supported yet"]);
            assert_eq!(s.errors, lines);
            assert_eq!(counters(&s), (2, 0, 62, 0, 1));
            if mode == Mode::Extract {
                assert_eq!(names(&out), ["seven", "six"]);
                assert_eq!(fs::read(out.join("six")).unwrap(), plain);
                assert_eq!(fs::read(out.join("seven")).unwrap(), plain);
            } else {
                assert!(!out.exists());
            }
        }
    }
    assert_eq!(fs::read(arc).unwrap(), bytes);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn whole_wave_generic_legacy_errors_preserve_quiet_silent_normal_and_stops() {
    use zipfast::zip::{EncryptedReadOverrides, ZipRunEvent, ZipSinkFault};
    let root = tempfile::tempdir().unwrap();
    let arc = root.path().join("legacy.rar");
    let mut bytes = SIG.to_vec();
    bytes.extend(main_block(false, None));
    bytes.extend(stored_block(&FileSpec::new("exists", b"replacement")));
    for name in ["bad-first", "bad-middle", "bad-last"] {
        bytes.extend(file_block(&FileSpec::new(name, b"bad"), b"bad", 0, false, false));
    }
    bytes.extend(stored_block(&FileSpec::new("good", b"good")));
    bytes.extend(end_block(false));
    fs::write(&arc, &bytes).unwrap();
    let setup = |label: &str| {
        let out = root.path().join(label);
        fs::create_dir(&out).unwrap();
        fs::write(out.join("exists"), b"original").unwrap();
        Options { overwrite: Overwrite::Skip, ..options(&out, 1) }
    };
    let legacy_opts = setup("legacy");
    let mut baseline_lines = Vec::new();
    let summary =
        extract::run_with_password(&arc, &legacy_opts, None, |line| baseline_lines.push(line.to_owned())).unwrap();
    assert_eq!(summary.errors, ["bad-first: checksum error", "bad-middle: checksum error", "bad-last: checksum error"]);
    assert_eq!(baseline_lines[0], "exists: exists, skipped");
    assert_eq!((summary.files, summary.skipped), (1, 1));
    for mode in ["quiet", "silent", "normal"] {
        let opts = setup(mode);
        let (mut mixed, mut errors, mut displayed, mut ended) = (Vec::new(), Vec::new(), Vec::new(), 0);
        let report = extract::run_with_zip_policy(
            &arc,
            &opts,
            None,
            &extract::Cancellation::default(),
            &EncryptedReadOverrides::default(),
            |event: ZipRunEvent<'_>| {
                match event {
                    ZipRunEvent::LegacyDiagnostic { message } => {
                        mixed.push(message.to_owned());
                        if mode == "normal" {
                            displayed.push(message.to_owned());
                        }
                    }
                    ZipRunEvent::LegacyError { message, .. } => {
                        errors.push(message.to_owned());
                        if mode == "quiet" {
                            displayed.push(message.to_owned());
                        }
                    }
                    ZipRunEvent::RunEnded { .. } => ended += 1,
                    _ => panic!("non-ZIP route emitted checked member event"),
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(mixed, baseline_lines);
        assert_eq!(errors, summary.errors);
        assert_eq!(ended, 1);
        assert_eq!((report.files(), report.skipped(), report.failed()), (1, 1, 3));
        assert_eq!(
            displayed,
            if mode == "normal" {
                baseline_lines.clone()
            } else if mode == "quiet" {
                summary.errors.clone()
            } else {
                Vec::new()
            }
        );
        assert_eq!(fs::read(opts.dest.join("exists")).unwrap(), b"original");
        assert_eq!(fs::read(opts.dest.join("good")).unwrap(), b"good");
    }
    // Structured legacy observers never prepare or obtain checked emit authority.
    struct Quiet<'a> {
        out: &'a mut Vec<u8>,
        ended: &'a mut usize,
    }
    impl zipfast::zip::ZipRunObserver for Quiet<'_> {
        fn prepare(&mut self, _: &mut zipfast::zip::ZipDiagnosticScope<'_>) -> zipfast::zip::ZipObserverResult<()> {
            panic!("legacy prepare must remain skipped");
        }
        fn observe(
            &mut self,
            e: ZipRunEvent<'_>,
            _: &mut zipfast::zip::ZipDiagnosticScope<'_>,
        ) -> zipfast::zip::ZipObserverResult<()> {
            if let ZipRunEvent::LegacyError { message, .. } = e {
                self.out.extend_from_slice(message.as_bytes());
                self.out.push(b'\n');
            } else if matches!(e, ZipRunEvent::RunEnded { .. }) {
                *self.ended += 1;
            }
            Ok(())
        }
    }
    let opts = setup("structured-context");
    let (mut quiet_output, mut ended) = (Vec::new(), 0);
    let mut context = zipfast::zip::EncryptedReadContext::new(Default::default()).unwrap();
    let report = extract::run_with_zip_context(
        &arc,
        &opts,
        None,
        &extract::Cancellation::default(),
        &mut context,
        Quiet { out: &mut quiet_output, ended: &mut ended },
    )
    .unwrap();
    assert_eq!(quiet_output, (summary.errors.join("\n") + "\n").as_bytes());
    assert_eq!(ended, 1);
    assert_eq!(
        (report.files(), report.dirs(), report.skipped(), report.failed(), report.decoded_bytes(), report.volumes()),
        (summary.files, summary.dirs, summary.skipped, 3, u128::from(summary.bytes), summary.volumes)
    );
    struct Reject<'a> {
        out: &'a mut std::fs::File,
        calls: &'a mut usize,
    }
    impl zipfast::zip::ZipRunObserver for Reject<'_> {
        fn prepare(&mut self, _: &mut zipfast::zip::ZipDiagnosticScope<'_>) -> zipfast::zip::ZipObserverResult<()> {
            panic!("legacy prepare must remain skipped");
        }
        fn observe(
            &mut self,
            _: ZipRunEvent<'_>,
            s: &mut zipfast::zip::ZipDiagnosticScope<'_>,
        ) -> zipfast::zip::ZipObserverResult<()> {
            *self.calls += 1;
            let _ = s.emit(zipfast::zip::ZipDiagnosticSink::Stderr, self.out, |_, w| {
                w.write_fmt(format_args!("must refuse"))
            });
            Ok(())
        }
    }
    let opts = setup("unbound-checked-emit");
    let mut sink = tempfile::tempfile().unwrap();
    let mut calls = 0;
    let error = extract::run_with_zip_policy(
        &arc,
        &opts,
        None,
        &extract::Cancellation::default(),
        &EncryptedReadOverrides::default(),
        Reject { out: &mut sink, calls: &mut calls },
    )
    .unwrap_err();
    assert_eq!(calls, 1);
    assert_eq!(sink.metadata().unwrap().len(), 0);
    assert!(error.diagnostic_boundary_fault().is_some());
    assert_eq!(error.partial_run().unwrap().failed(), 3);
    for fail_at in [0, baseline_lines.len() / 2, baseline_lines.len() - 1] {
        let opts = setup(&format!("mixed-stop-{fail_at}"));
        let (mut calls, mut replayed, mut ended) = (0, 0, 0);
        let error = extract::run_with_zip_policy(
            &arc,
            &opts,
            None,
            &extract::Cancellation::default(),
            &EncryptedReadOverrides::default(),
            |event: ZipRunEvent<'_>| {
                match event {
                    ZipRunEvent::LegacyDiagnostic { .. } => {
                        let n = calls;
                        calls += 1;
                        if n == fail_at {
                            return Err(ZipSinkFault::StageChanged);
                        }
                    }
                    ZipRunEvent::LegacyError { .. } => replayed += 1,
                    ZipRunEvent::RunEnded { .. } => ended += 1,
                    _ => {}
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!((calls, replayed, ended), (fail_at + 1, 0, 0));
        assert_eq!((error.partial_run().unwrap().files(), error.partial_run().unwrap().failed()), (1, 3));
    }
    for fail_at in 0..3 {
        let opts = setup(&format!("stop-{fail_at}"));
        let (mut replayed, mut ended) = (0, 0);
        let error = extract::run_with_zip_policy(
            &arc,
            &opts,
            None,
            &extract::Cancellation::default(),
            &EncryptedReadOverrides::default(),
            |event: ZipRunEvent<'_>| {
                match event {
                    ZipRunEvent::LegacyError { .. } => {
                        let n = replayed;
                        replayed += 1;
                        if n == fail_at {
                            return Err(ZipSinkFault::StageChanged);
                        }
                    }
                    ZipRunEvent::RunEnded { .. } => ended += 1,
                    _ => {}
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!((replayed, ended), (fail_at + 1, 0));
        assert!(matches!(error.diagnostic_fault(), Some(ZipSinkFault::StageChanged)));
        let report = error.partial_run().unwrap();
        assert_eq!((report.files(), report.skipped(), report.failed()), (1, 1, 3));
    }
}
