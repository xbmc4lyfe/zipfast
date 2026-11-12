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

mod common;
#[allow(dead_code)]
#[path = "common/zip_parity_fixture.rs"]
mod zip_fixture;

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::io::{Seek, SeekFrom};
use std::path::Path;

use zipfast::Error;
use zipfast::extract::{self, Entry, Inspection};
#[cfg(unix)]
use zipfast::zip::ReadSession;
use zipfast::zip::SessionError;

fn zip_bytes(prefix: &[u8]) -> Vec<u8> {
    zip_fixture::build(&[zip_fixture::Member::stored(b"zip-entry", b"abc")], &[0], prefix, b"", false).bytes
}

fn other(path: &Path, password: Option<&str>) -> Vec<Entry> {
    match extract::inspect_with_password(path, password).unwrap() {
        Inspection::Other(entries) => entries,
        Inspection::Zip(_) => panic!("expected a non-ZIP listing"),
    }
}

#[cfg(unix)]
fn zip(path: &Path) -> ReadSession {
    match extract::inspect(path).unwrap() {
        Inspection::Zip(session) => session,
        Inspection::Other(_) => panic!("expected a ZIP session"),
    }
}

#[cfg(unix)]
#[test]
fn zip_head_and_sfx_prefix_publish_a_selectable_session_with_exact_probe_charges() {
    let source = tempfile::NamedTempFile::new().unwrap();
    for prefix in [b"".as_slice(), b"launcher"] {
        let bytes = zip_bytes(prefix);
        fs::write(source.path(), &bytes).unwrap();
        assert_eq!(extract::list(source.path()).unwrap()[0].name, "zip-entry");
        let mut session = zip(source.path());
        assert_eq!(session.dispatch_bytes(), bytes.len() as u64 * if prefix.is_empty() { 1 } else { 2 });
        let metadata = session.metadata();
        let direct = ReadSession::open(source.path()).unwrap();
        assert_eq!(direct.dispatch_bytes(), 0);
        assert_eq!(metadata.parser_usage(), direct.metadata().parser_usage());
        assert_eq!(metadata.prefix_shift(), prefix.len() as u64);
        let id = metadata.entry_id(0).unwrap();
        assert_eq!(metadata.entry(&id).unwrap().name(), "zip-entry");
        let mut actual = Vec::new();
        session
            .select(&id, 3, Default::default())
            .unwrap()
            .read(None, |chunk| {
                actual.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert_eq!(actual, b"abc");
    }
}

#[test]
fn recognized_tar_and_gzip_keep_priority_over_a_valid_zip_tail() {
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("first.tar");
    let mut tar_bytes = [0; 2048];
    tar_bytes[..9].copy_from_slice(b"tar-entry");
    tar_bytes[100..108].copy_from_slice(b"0000644\0");
    tar_bytes[124..136].copy_from_slice(b"00000000003\0");
    tar_bytes[148..156].fill(b' ');
    tar_bytes[156] = b'0';
    tar_bytes[257..263].copy_from_slice(b"ustar\0");
    tar_bytes[512..515].copy_from_slice(b"tar");
    let checksum: u64 = tar_bytes[..512].iter().map(|&byte| u64::from(byte)).sum();
    tar_bytes[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    fs::write(&tar, zip_bytes(&tar_bytes)).unwrap();
    #[cfg(unix)]
    assert_eq!(ReadSession::open(&tar).unwrap().metadata().len(), 1);
    assert_eq!(extract::list(&tar).unwrap()[0].name, "tar-entry");
    assert_eq!(other(&tar, None)[0].name, "tar-entry");

    let gzip = dir.path().join("payload.gz");
    let mut writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    writer.write_all(b"gzip payload").unwrap();
    let bytes = writer.finish().unwrap();
    fs::write(&gzip, &bytes).unwrap();
    assert_eq!(other(&gzip, None)[0].size, 12);

    fs::write(&gzip, zip_bytes(&bytes)).unwrap();
    #[cfg(unix)]
    assert_eq!(ReadSession::open(&gzip).unwrap().metadata().len(), 1);
    let legacy = extract::list(&gzip).unwrap_err();
    let inspected = extract::inspect(&gzip);
    assert!(matches!(inspected, Err(SessionError::Archive(error)) if error.to_string() == legacy.to_string()));
}

#[test]
fn sfx_rar_wins_at_the_search_boundary_but_a_signature_one_byte_beyond_it_does_not() {
    let source = tempfile::NamedTempFile::new().unwrap();
    let archive = common::archive(&[common::FileSpec::new("rar-entry", b"rar")]);
    let mut prefix = vec![b'x'; 1 << 20];
    prefix.extend(&archive);
    fs::write(source.path(), zip_bytes(&prefix)).unwrap();
    assert_eq!(extract::list(source.path()).unwrap()[0].name, "rar-entry");
    assert_eq!(other(source.path(), None)[0].name, "rar-entry");

    prefix.insert(0, b'x');
    fs::write(source.path(), zip_bytes(&prefix)).unwrap();
    assert_eq!(extract::list(source.path()).unwrap()[0].name, "zip-entry");
    #[cfg(unix)]
    {
        let inspected = zip(source.path());
        assert_eq!(inspected.dispatch_bytes(), 1024 + (1 << 20) + 8);
        assert_eq!(inspected.metadata().entries().next().unwrap().name(), "zip-entry");
    }
    #[cfg(not(unix))]
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::UnsupportedIdentity)));
}

#[test]
fn raw_rar4_refusal_and_corrupt_sfx_rar_are_terminal() {
    let source = tempfile::NamedTempFile::new().unwrap();
    let mut prefix = b"Rar!\x1a\x07\x00".to_vec();
    prefix.extend(common::archive(&[])); // RAR4 at byte zero overrides a later valid RAR5.
    fs::write(source.path(), zip_bytes(&prefix)).unwrap();
    assert!(matches!(extract::list(source.path()), Err(Error::Unsupported(message)) if message.contains("RAR 4.x")));
    assert!(matches!(
        extract::inspect(source.path()),
        Err(SessionError::Archive(Error::Unsupported(message))) if message.contains("RAR 4.x")
    ));

    let mut prefix = b"launcher".to_vec();
    let mut rar = common::archive(&[]);
    rar[8] ^= 1; // Main-header CRC.
    prefix.extend(rar);
    fs::write(source.path(), zip_bytes(&prefix)).unwrap();
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::Archive(Error::Corrupt(_)))));
}

#[test]
fn sfx_rar_header_password_errors_do_not_fall_through_to_zip() {
    use zipfast::crypto::{derive_rar5_key, encrypt_cbc};

    const PASSWORD: &str = "inspection test";
    let salt = [7; 16];
    let key = derive_rar5_key(PASSWORD, 3, &salt, None).unwrap();
    let mut fields = vec![0, 0, 3]; // Version, flags, KDF exponent.
    fields.extend(salt);
    let mut prefix = b"launcher".to_vec();
    prefix.extend(common::SIG);
    prefix.extend(common::block(4, 0, &fields, &[], &[], false));
    for (i, mut header) in [common::main_block(false, None), common::end_block(false)].into_iter().enumerate() {
        let iv = [i as u8; 16];
        header.resize(header.len().next_multiple_of(16), 0);
        prefix.extend(iv);
        prefix.extend(encrypt_cbc(&key, &iv, &header).unwrap());
    }
    let source = tempfile::NamedTempFile::new().unwrap();
    fs::write(source.path(), zip_bytes(&prefix)).unwrap();
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::Archive(Error::Encrypted))));
    assert!(matches!(
        extract::inspect_with_password(source.path(), Some("wrong")),
        Err(SessionError::Archive(Error::Encrypted))
    ));
    assert!(other(source.path(), Some(PASSWORD)).is_empty());
    assert!(extract::list_with_password(source.path(), Some(PASSWORD)).unwrap().is_empty());
}

#[test]
fn recognized_rar_keeps_later_volume_errors_even_with_a_valid_zip_tail() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("multi.part1.rar");
    let next = dir.path().join("multi.part2.rar");
    let mut prefix = b"launcher".to_vec();
    prefix.extend(common::SIG);
    prefix.extend(common::main_block(true, None));
    prefix.extend(common::end_block(true));
    let bytes = zip_bytes(&prefix);
    fs::write(&first, &bytes).unwrap();
    assert!(matches!(extract::inspect(&first), Err(SessionError::Archive(Error::MissingVolume(_)))));
    fs::write(&next, b"not a rar volume").unwrap();
    assert_eq!(extract::list(&first).unwrap()[0].name, "zip-entry");
    assert!(matches!(extract::inspect(&first), Err(SessionError::Archive(Error::NotAnArchive))));
}

#[cfg(unix)]
#[test]
fn known_zip_errors_do_not_fall_through_to_valid_sfx_rar() {
    let mut source = tempfile::NamedTempFile::new().unwrap();
    let rar = common::archive(&[]);
    let mut archive = zip_fixture::build(&[zip_fixture::Member::stored(b"zip-entry", &rar)], &[0], b"", b"", false);
    fs::write(source.path(), &archive.bytes).unwrap();
    assert_eq!(zip(source.path()).metadata().entries().next().unwrap().name(), "zip-entry");
    let central = archive.central[0];
    archive.bytes[central + 42..central + 46].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
    fs::write(source.path(), &archive.bytes).unwrap();
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::Archive(Error::Corrupt(_)))));

    source.as_file().set_len(0).unwrap();
    source.write_all(b"PK\x03\x04").unwrap();
    source.write_all(&rar).unwrap();
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::Archive(Error::NotAnArchive))));

    let directory_size = (128u32 << 20) + 1;
    source.seek(SeekFrom::Start(u64::from(directory_size))).unwrap();
    let mut end = [0u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[12..16].copy_from_slice(&directory_size.to_le_bytes());
    source.write_all(&end).unwrap();
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::Archive(Error::Unsupported(_)))));
}

#[cfg(not(unix))]
#[test]
fn recognized_zip_requires_supported_identity_even_when_malformed() {
    let source = tempfile::NamedTempFile::new().unwrap();
    fs::write(source.path(), b"PK\x03\x04").unwrap();
    assert!(matches!(extract::inspect(source.path()), Err(SessionError::UnsupportedIdentity)));
}

#[cfg(unix)]
#[test]
fn sfx_probes_count_toward_the_exact_default_fetch_ceiling() {
    const MAX_FETCH: u64 = 129 << 20;
    const PROBE_BYTES: u64 = 1024 + (1 << 20) + 8;
    for excess in [0, 1] {
        let mut source = tempfile::NamedTempFile::new().unwrap();
        let directory_bytes = (MAX_FETCH - PROBE_BYTES - 22 + excess) as u32;
        write_large_directory(source.as_file_mut(), directory_bytes);

        let direct = ReadSession::open(source.path()).unwrap();
        assert_eq!(direct.metadata().parser_usage().fetched_bytes, MAX_FETCH - PROBE_BYTES + excess);
        let result = extract::inspect(source.path());
        if excess == 0 {
            let Inspection::Zip(session) = result.unwrap() else { panic!("expected SFX ZIP") };
            assert_eq!(session.dispatch_bytes(), PROBE_BYTES);
            assert_eq!(session.dispatch_bytes() + session.metadata().parser_usage().fetched_bytes, MAX_FETCH);
        } else {
            assert!(matches!(result, Err(SessionError::Archive(Error::Unsupported(_)))));
        }
    }
}

#[cfg(unix)]
fn write_large_directory(file: &mut fs::File, directory_bytes: u32) {
    // Declare physical offsets to keep the parser fetch span exactly the
    // central directory through EOCD. Sparse unknown extras fill most of it.
    file.write_all(b"MZ launcher").unwrap();
    let start = file.stream_position().unwrap() as u32;
    let mut remaining = directory_bytes;
    let mut entries = 0u16;
    while remaining > 0 {
        let mut record_len = remaining.min(47 + u32::from(u16::MAX));
        let leftover = remaining - record_len;
        if (1..51).contains(&leftover) {
            record_len -= 51 - leftover;
        }
        let extra_len = (record_len - 47) as u16;
        let mut central = [0; 47];
        central[..4].copy_from_slice(b"PK\x01\x02");
        central[28..30].copy_from_slice(&1u16.to_le_bytes());
        central[30..32].copy_from_slice(&extra_len.to_le_bytes());
        central[46] = b'x';
        file.write_all(&central).unwrap();
        file.write_all(&0xaaaa_u16.to_le_bytes()).unwrap();
        file.write_all(&(extra_len - 4).to_le_bytes()).unwrap();
        file.seek(SeekFrom::Current(i64::from(extra_len - 4))).unwrap();
        entries += 1;
        remaining -= record_len;
    }
    let mut end = [0u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&entries.to_le_bytes());
    end[10..12].copy_from_slice(&entries.to_le_bytes());
    end[12..16].copy_from_slice(&directory_bytes.to_le_bytes());
    end[16..20].copy_from_slice(&start.to_le_bytes());
    file.write_all(&end).unwrap();
}
