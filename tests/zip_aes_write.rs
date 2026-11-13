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

use std::io::Cursor;
use zipfast::zip::write::{
    AesStrength, AesVariant, DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions,
    WinZipAesRequest, WriterOptions, ZipStreamWriter,
};
use zipfast::zip::{Archive, ReadSession};

fn options(name: &str, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"member",
    }
}
fn u16at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn u32at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

#[test]
fn all_strengths_and_variants_write_stored_deflate_and_empty_regular_members() {
    for (strength, salt_len) in [(AesStrength::Aes128, 8), (AesStrength::Aes192, 12), (AesStrength::Aes256, 16)] {
        for variant in [AesVariant::Ae1, AesVariant::Ae2] {
            let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
            writer.add_directory(options("dir/", Method::Stored)).unwrap();
            let data = b"AES payload across encoder chunks\n".repeat(3000);
            let mut receipts = Vec::new();
            for (name, method, payload, length) in [
                ("dir/stored", Method::Stored, data.as_slice(), InputLength::Exact(data.len() as u64)),
                ("deflated", Method::Deflate(DeflateLevel::new(6).unwrap()), data.as_slice(), InputLength::Unknown),
                ("empty", Method::Deflate(DeflateLevel::new(9).unwrap()), b"".as_slice(), InputLength::Exact(0)),
                ("empty-unknown", Method::Deflate(DeflateLevel::new(9).unwrap()), b"".as_slice(), InputLength::Unknown),
            ] {
                let request = WinZipAesRequest::new("aes-test-password", strength, variant).unwrap();
                let receipt = writer
                    .add_winzip_aes_file(options(name, method), &mut Cursor::new(payload), length, request, |salt| {
                        assert_eq!(salt.len(), salt_len);
                        for (i, byte) in salt.iter_mut().enumerate() {
                            *byte = i as u8 + 1;
                        }
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(receipt.strength, strength);
                assert_eq!(receipt.variant, variant);
                assert_eq!(receipt.entry.crc32, if variant == AesVariant::Ae1 { crc32fast::hash(payload) } else { 0 });
                assert!(!format!("{receipt:?}").contains("plaintext_crc32"));
                receipts.push(receipt);
            }
            let finished = writer.finish().unwrap();
            assert_eq!(finished.summary.usage.entries, 5);
            assert_eq!(receipts[0].entry.packed_size, data.len() as u64 + salt_len as u64 + 12);
            assert_eq!(receipts[2].entry.packed_size, salt_len as u64 + 12);
            let mut file = tempfile::NamedTempFile::new().unwrap();
            std::io::Write::write_all(&mut file, &finished.sink).unwrap();
            let metadata = ReadSession::open(file.path()).unwrap().metadata();
            for (index, entry) in metadata.entries().enumerate() {
                assert_eq!(entry.encrypted(), index != 0);
                if index != 0 {
                    assert_eq!(entry.header().method, 99);
                    assert_eq!(entry.header().crc32, receipts[index - 1].entry.crc32);
                }
            }
            let mut archive = Archive::open(file.path()).unwrap();
            for (index, wanted) in
                [(1, data.as_slice()), (2, data.as_slice()), (3, b"".as_slice()), (4, b"".as_slice())]
            {
                let mut bytes = Vec::new();
                archive
                    .read_at(index, Some("aes-test-password"), 1 << 20, |chunk| {
                        bytes.extend_from_slice(chunk);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(bytes, wanted);
                assert!(archive.read_at(index, Some("wrong"), 1 << 20, |_| Ok(())).is_err());
            }
            let local = receipts[0].entry.local_offset as usize;
            assert_eq!(u16at(&finished.sink, local + 8), 99);
            assert_eq!(u16at(&finished.sink, local + 6) & 9, 9);
            let data_at =
                local + 30 + u16at(&finished.sink, local + 26) as usize + u16at(&finished.sink, local + 28) as usize;
            let descriptor = data_at + receipts[0].entry.packed_size as usize;
            assert_eq!(&finished.sink[descriptor..descriptor + 4], b"PK\x07\x08");
            assert_eq!(u32at(&finished.sink, descriptor + 4), receipts[0].entry.crc32);
        }
    }
}

#[test]
fn aes_request_bounds_and_formatting_keep_passwords_private() {
    for password in ["".to_string(), "private-credential\0unique".to_string(), "x".repeat(65536)] {
        let error = WinZipAesRequest::new(&password, AesStrength::Aes256, AesVariant::Ae2).unwrap_err();
        assert!(!format!("{error:?}").contains("private-credential"));
    }
    let password = "password-that-must-not-leak";
    let request = WinZipAesRequest::new(password, AesStrength::Aes192, AesVariant::Ae1).unwrap();
    for printed in [format!("{request:?}"), format!("{request:#?}")] {
        assert!(!printed.contains(password));
        assert!(printed.contains("REDACTED"));
    }
    assert!(WinZipAesRequest::new(&"x".repeat(65535), AesStrength::Aes128, AesVariant::Ae2).is_ok());
    assert!(WinZipAesRequest::new(&"雪".repeat(21845), AesStrength::Aes128, AesVariant::Ae2).is_ok());
    assert!(WinZipAesRequest::new(&"雪".repeat(21846), AesStrength::Aes128, AesVariant::Ae2).is_err());
}

#[test]
fn aes_mandatory_attempts_and_source_overflow_refuse_before_entropy() {
    use std::io::Read;
    use zipfast::zip::write::{Limit, WriteError, WriteLimits};
    struct Unread;
    impl Read for Unread {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("refused input was read")
        }
    }
    for limits in
        [WriteLimits { io_attempts: 7, ..Default::default() }, WriteLimits { source_bytes: 0, ..Default::default() }]
    {
        let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions { limits, ..Default::default() }).unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let error = writer
            .add_winzip_aes_file(options("a", Method::Stored), &mut Unread, InputLength::Exact(0), request, |_| {
                panic!("refused entry requested entropy")
            })
            .unwrap_err();
        assert!(matches!(error, WriteError::Limit(Limit::IoAttempts | Limit::SourceBytes)));
        assert_eq!(writer.usage().io_attempts, 0);
    }
    let mut writer = ZipStreamWriter::new(
        Vec::new(),
        WriterOptions { limits: WriteLimits { io_attempts: 8, ..Default::default() }, ..Default::default() },
    )
    .unwrap();
    let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    writer
        .add_winzip_aes_file(
            options("a", Method::Stored),
            &mut b"".as_slice(),
            InputLength::Exact(0),
            request,
            |salt| {
                salt.fill(1);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!((writer.usage().entries, writer.usage().io_attempts), (1, 8));
    assert!(matches!(writer.finish(), Err(WriteError::Limit(Limit::IoAttempts))));
}

#[test]
fn aes_entropy_refusal_is_reusable_and_exact_source_overrun_is_poisoned() {
    use zipfast::zip::write::{IoStage, WriteError};
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    let mut source = Cursor::new(b"x".as_slice());
    let error = writer
        .add_winzip_aes_file(options("a", Method::Stored), &mut source, InputLength::Exact(1), request, |_| {
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
    assert!(matches!(error, WriteError::Io { stage: IoStage::EncryptionEntropy, .. }));
    assert_eq!((source.position(), writer.usage().io_attempts, writer.usage().output_bytes), (0, 1, 0));
    writer.add_file(options("clear", Method::Stored), &mut source, InputLength::Exact(1)).unwrap();
    writer.finish().unwrap();
    for (declared, prefix) in [(0, 0), (1, 53)] {
        let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let mut entry = options("a", Method::Stored);
        entry.comment = b"";
        assert!(
            matches!(writer.add_winzip_aes_file(entry,&mut b"xy".as_slice(),InputLength::Exact(declared),request,|salt|{salt.fill(1);Ok(())}),Err(WriteError::SizeOverrun{expected}) if expected==declared)
        );
        assert_eq!(writer.usage().output_bytes, prefix);
        assert_eq!(writer.usage().entries, 0);
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    }
}

struct FaultSink {
    bytes: Vec<u8>,
    fail_at: usize,
    flush_fails: bool,
    interrupted: bool,
}

#[test]
fn aes_source_errors_and_underrun_preserve_truthful_usage_and_poison() {
    use std::io::{ErrorKind, Read};
    use zipfast::zip::write::{IoStage, WriteError};
    struct Source {
        first: bool,
        fail: bool,
    }
    impl Read for Source {
        fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
            if self.first {
                self.first = false;
                bytes[0] = b'x';
                return Ok(1);
            }
            if self.fail { Err(ErrorKind::PermissionDenied.into()) } else { Ok(0) }
        }
    }
    for (first, fail, accepted, source_bytes) in [(false, true, 0, 0), (true, true, 53, 1), (true, false, 53, 1)] {
        let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let error = writer
            .add_winzip_aes_file(
                options("a", Method::Stored),
                &mut Source { first, fail },
                InputLength::Exact(2),
                request,
                |salt| {
                    salt.fill(1);
                    Ok(())
                },
            )
            .unwrap_err();
        if fail {
            assert!(matches!(error, WriteError::Io { stage: IoStage::SourceRead, .. }));
        } else {
            assert!(matches!(error, WriteError::SizeUnderrun { expected: 2, actual: 1 }));
        }
        let usage = writer.usage();
        assert_eq!((usage.entries, usage.decoded_bytes, usage.packed_bytes), (0, 0, 0));
        assert_eq!((usage.output_bytes, usage.archive_extent, usage.source_bytes), (accepted, accepted, source_bytes));
        assert_eq!(usage.io_attempts, if first { 8 } else { 2 });
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
    }
}
impl std::io::Write for FaultSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.interrupted {
            self.interrupted = false;
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        if self.bytes.len() == self.fail_at {
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        let count = bytes.len().min(3).min(self.fail_at - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.flush_fails { Err(std::io::ErrorKind::PermissionDenied.into()) } else { Ok(()) }
    }
}

#[test]
fn aes_tag_and_descriptor_short_write_failures_preserve_accepted_bytes() {
    use zipfast::zip::write::{IoStage, WriteError};
    for (at, stage) in [
        (55, IoStage::AuthenticationTag),
        (60, IoStage::AuthenticationTag),
        (65, IoStage::DataDescriptor),
        (70, IoStage::DataDescriptor),
    ] {
        let mut sink = FaultSink { bytes: Vec::new(), fail_at: at, flush_fails: false, interrupted: true };
        let mut writer = ZipStreamWriter::new(&mut sink, WriterOptions::default()).unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let mut entry = options("a", Method::Stored);
        entry.comment = b"";
        let error = writer
            .add_winzip_aes_file(entry, &mut b"xyz".as_slice(), InputLength::Exact(3), request, |salt| {
                salt.fill(1);
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(error,WriteError::Io{stage:actual,..} if actual==stage));
        assert_eq!(writer.usage().output_bytes, at as u64);
        assert_eq!(writer.usage().archive_extent, at as u64);
        assert_eq!(writer.usage().entries, 0);
        assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
        assert_eq!(sink.bytes.len(), at);
    }
    let mut sink = FaultSink { bytes: Vec::new(), fail_at: usize::MAX, flush_fails: true, interrupted: true };
    let mut writer = ZipStreamWriter::new(&mut sink, WriterOptions::default()).unwrap();
    let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    let mut entry = options("a", Method::Stored);
    entry.comment = b"";
    writer
        .add_winzip_aes_file(entry, &mut b"xyz".as_slice(), InputLength::Exact(3), request, |salt| {
            salt.fill(1);
            Ok(())
        })
        .unwrap();
    assert!(matches!(writer.finish(), Err(WriteError::Io { stage: IoStage::Flush, .. })));
    assert_eq!(sink.bytes.len(), 161);
}

#[test]
fn aes_byte_limits_include_header_tag_and_descriptor_at_exact_boundary() {
    use zipfast::zip::write::WriteLimits;
    for maximum in [160, 161] {
        let mut writer = ZipStreamWriter::new(
            Vec::new(),
            WriterOptions {
                limits: WriteLimits { output_bytes: maximum, archive_extent: maximum, ..Default::default() },
                ..Default::default()
            },
        )
        .unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
        let mut entry = options("a", Method::Stored);
        entry.comment = b"";
        let mut entropy = 0;
        let result =
            writer.add_winzip_aes_file(entry, &mut b"xyz".as_slice(), InputLength::Exact(3), request, |salt| {
                entropy += 1;
                salt.fill(1);
                Ok(())
            });
        if maximum == 160 {
            assert!(result.is_err());
            assert_eq!(entropy, 0);
            assert_eq!(writer.usage().output_bytes, 0);
        } else {
            result.unwrap();
            let done = writer.finish().unwrap();
            assert_eq!(done.summary.usage.output_bytes, 161);
            assert_eq!(entropy, 1);
        }
    }
}

#[test]
fn aes_short_writes_and_interruption_are_byte_identical_to_full_writes() {
    for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
        let data = (0..=255).cycle().take(65537).collect::<Vec<_>>();
        let mut ordinary = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes256, AesVariant::Ae2).unwrap();
        ordinary
            .add_winzip_aes_file(
                options("a", method),
                &mut data.as_slice(),
                InputLength::Exact(data.len() as u64),
                request,
                |salt| {
                    salt.fill(7);
                    Ok(())
                },
            )
            .unwrap();
        let expected = ordinary.finish().unwrap().sink;
        let mut sink = FaultSink { bytes: Vec::new(), fail_at: usize::MAX, flush_fails: false, interrupted: true };
        let mut writer = ZipStreamWriter::new(&mut sink, WriterOptions::default()).unwrap();
        let request = WinZipAesRequest::new("test-password", AesStrength::Aes256, AesVariant::Ae2).unwrap();
        writer
            .add_winzip_aes_file(
                options("a", method),
                &mut data.as_slice(),
                InputLength::Exact(data.len() as u64),
                request,
                |salt| {
                    salt.fill(7);
                    Ok(())
                },
            )
            .unwrap();
        writer.finish().unwrap();
        assert_eq!(sink.bytes, expected);
    }
}

#[test]
fn aes_cancellation_after_entropy_poisoned_the_admitted_writer() {
    use zipfast::zip::write::WriteError;
    let cancel = zipfast::extract::Cancellation::default();
    let mut writer =
        ZipStreamWriter::new(Vec::new(), WriterOptions { cancel: Some(cancel.clone()), ..Default::default() }).unwrap();
    let request = WinZipAesRequest::new("test-password", AesStrength::Aes128, AesVariant::Ae2).unwrap();
    assert!(matches!(
        writer.add_winzip_aes_file(
            options("a", Method::Stored),
            &mut b"x".as_slice(),
            InputLength::Exact(1),
            request,
            |salt| {
                salt.fill(1);
                cancel.cancel();
                Ok(())
            }
        ),
        Err(WriteError::Canceled)
    ));
    assert_eq!(writer.usage().output_bytes, 0);
    assert_eq!(writer.usage().io_attempts, 1);
    assert!(matches!(writer.finish(), Err(WriteError::Failed(_))));
}

#[test]
#[ignore = "exports deterministic AES fixtures for pinned external readers"]
fn export_aes_reference_fixtures() {
    let root = std::path::PathBuf::from(std::env::var_os("ZIPFAST_AES_REFERENCE_DIR").unwrap());
    for (strength, label) in [(AesStrength::Aes128, "128"), (AesStrength::Aes192, "192"), (AesStrength::Aes256, "256")]
    {
        for (variant, version) in [(AesVariant::Ae1, "ae1"), (AesVariant::Ae2, "ae2")] {
            let directory = root.join(format!("aes{label}-{version}"));
            std::fs::create_dir_all(directory.join("expected/dir")).unwrap();
            let mut writer = ZipStreamWriter::new(
                Vec::new(),
                WriterOptions { comment: b"AES fixture comment", ..Default::default() },
            )
            .unwrap();
            writer.add_directory(options("dir/", Method::Stored)).unwrap();
            let data = b"A predictable fixture with raw Deflate content\0".repeat(2000);
            let cases = [
                ("dir/stored", Method::Stored, InputLength::Exact(data.len() as u64)),
                ("unknown-stored", Method::Stored, InputLength::Unknown),
                ("level1", Method::Deflate(DeflateLevel::new(1).unwrap()), InputLength::Exact(data.len() as u64)),
                ("level6", Method::Deflate(DeflateLevel::new(6).unwrap()), InputLength::Unknown),
                ("雪.txt", Method::Deflate(DeflateLevel::new(9).unwrap()), InputLength::Exact(data.len() as u64)),
                ("rawé", Method::Stored, InputLength::Exact(data.len() as u64)),
                ("empty", Method::Deflate(DeflateLevel::new(9).unwrap()), InputLength::Exact(0)),
                ("empty-unknown", Method::Stored, InputLength::Unknown),
            ];
            for (name, method, length) in cases {
                let bytes = if name.starts_with("empty") { b"".as_slice() } else { data.as_slice() };
                let mut entry = options(name, method);
                entry.extended_mtime = Some(1_577_934_244);
                if name == "rawé" {
                    entry.name = EntryName::Raw(b"raw\x82");
                    entry.comment = b"raw\xff";
                }
                let request = WinZipAesRequest::new("password", strength, variant).unwrap();
                let mut input = bytes;
                writer
                    .add_winzip_aes_file(entry, &mut input, length, request, |salt| {
                        for (i, byte) in salt.iter_mut().enumerate() {
                            *byte = (i + 1) as u8;
                        }
                        Ok(())
                    })
                    .unwrap();
                std::fs::write(directory.join("expected").join(name), bytes).unwrap();
            }
            std::fs::write(directory.join("fixture.zip"), writer.finish().unwrap().sink).unwrap();
        }
    }
}

#[test]
fn aes_unrepresentable_lengths_and_invalid_metadata_request_no_entropy() {
    use zipfast::zip::write::{WriteError, WriteLimits};
    let mut writer = ZipStreamWriter::new(
        Vec::new(),
        WriterOptions {
            limits: WriteLimits {
                source_bytes: u64::MAX,
                entry_decoded_bytes: u64::MAX,
                archive_extent: u64::MAX,
                output_bytes: u64::MAX,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let request = WinZipAesRequest::new("test-password", AesStrength::Aes256, AesVariant::Ae2).unwrap();
    assert!(matches!(
        writer.add_winzip_aes_file(
            options("a", Method::Stored),
            &mut Cursor::new(b""),
            InputLength::Exact(u64::MAX),
            request,
            |_| panic!("overflow requested entropy")
        ),
        Err(WriteError::Overflow)
    ));
    let request = WinZipAesRequest::new("test-password", AesStrength::Aes256, AesVariant::Ae2).unwrap();
    let mut invalid = options("a", Method::Stored);
    invalid.comment = b"\xff";
    assert!(matches!(
        writer.add_winzip_aes_file(invalid, &mut Cursor::new(b""), InputLength::Exact(0), request, |_| panic!(
            "invalid UTF-8 metadata requested entropy"
        )),
        Err(WriteError::InvalidMetadata(_))
    ));
    assert_eq!(writer.usage().io_attempts, 0);
    writer.add_directory(options("dir/", Method::Stored)).unwrap();
    writer.finish().unwrap();
}
