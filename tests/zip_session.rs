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

//! ZIP archives, read from PKWARE's published APPNOTE: the end of central directory record (and its ZIP64 form),

#[cfg(unix)]
#[path = "common/zip_parity_fixture.rs"]
mod fixture;

#[cfg(unix)]
mod unix {

    use std::fs::{self, File, FileTimes, OpenOptions};
    use std::io::{self, Seek, SeekFrom, Write};
    use std::path::Path;

    use tempfile::{NamedTempFile, TempDir};
    use zipfast::Error;
    use zipfast::extract::Cancellation;
    use zipfast::zip::{Archive, ReadSession, SessionError, SourceChange};

    use super::fixture::{Member, build, extra};

    fn open_fixture(bytes: &[u8]) -> (NamedTempFile, ReadSession) {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        let session = ReadSession::open(file.path()).unwrap();
        (file, session)
    }

    fn read(session: &mut ReadSession, ordinal: usize) -> Vec<u8> {
        let id = session.metadata().entry_id(ordinal).unwrap();
        let mut out = Vec::new();
        session
            .select(&id, 64, Cancellation::default())
            .unwrap()
            .read(None, |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        out
    }

    #[test]
    fn ids_follow_central_ordinals_and_outlive_the_reader() {
        let members = [Member::stored(b"same", b"one"), Member::stored(b"same", b"two"), Member::stored(b"", b"x")];
        let (file, mut session) = open_fixture(&build(&members, &[1, 0, 0, 2], b"", b"", false).bytes);
        let metadata = session.metadata();
        assert_eq!(metadata.entries().map(|entry| entry.name()).collect::<Vec<_>>(), ["same", "same", "same", ""]);
        assert!(metadata.entry_id(4).is_none());
        let id = metadata.entry_id(2).unwrap();
        let identical = metadata.entry_id(1).unwrap();
        assert_eq!(metadata.entry(&id).unwrap().header(), metadata.entry(&identical).unwrap().header());

        let mut legacy = Archive::open(file.path()).unwrap();
        legacy.entries.reverse();
        legacy.entries[0].name = String::from("replaced");
        legacy.entries.clear();

        assert_eq!(read(&mut session, 0), b"two");
        assert_eq!(read(&mut session, 1), b"one");
        assert_eq!(read(&mut session, 2), b"one");
        assert_eq!(read(&mut session, 0), b"two");
        assert!(matches!(
            session.select(&metadata.entry_id(3).unwrap(), 64, Cancellation::default()),
            Err(SessionError::Archive(Error::UnsafePath(_)))
        ));

        let mut other = ReadSession::open(file.path()).unwrap();
        assert!(matches!(other.metadata().entry(&id), Err(SessionError::ForeignEntryId)));
        drop(session);
        assert_eq!(metadata.entry(&id.clone()).unwrap().name(), "same");
        drop(metadata);
        fs::remove_file(file.path()).unwrap();
        // Foreign IDs fail before the now-missing path is checked.
        assert!(matches!(other.select(&id, 64, Cancellation::default()), Err(SessionError::ForeignEntryId)));
        assert!(matches!(other.check_source(), Err(SessionError::SourceChanged { .. })));
    }

    #[test]
    fn replacement_is_detected_before_read_and_invalidation_is_sticky() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("data.zip");
        let saved = dir.path().join("saved.zip");
        let replacement = dir.path().join("replacement.zip");
        let bytes = build(&[Member::stored(b"entry", b"original")], &[0], b"", b"", false).bytes;
        fs::write(&path, &bytes).unwrap();
        fs::write(&replacement, &bytes).unwrap();
        let mut session = ReadSession::open(&path).unwrap();
        let id = session.metadata().entry_id(0).unwrap();
        let selected = session.select(&id, 64, Cancellation::default()).unwrap();
        fs::hard_link(&path, &saved).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(matches!(
            selected.read(None, |_| panic!("replacement must prevent sink delivery")),
            Err(SessionError::SourceChanged { change: SourceChange::StampMismatch, .. })
        ));
        fs::rename(saved, &path).unwrap();
        assert!(matches!(session.check_source(), Err(SessionError::SourceChanged { .. })));
        assert_eq!(session.metadata().entry(&id).unwrap().name(), "entry");
        assert_eq!(read(&mut ReadSession::open(&path).unwrap(), 0), b"original");
    }

    #[test]
    fn retained_symlink_path_tracks_replacement_of_its_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("target.zip");
        let alias = dir.path().join("alias.zip");
        let replacement = dir.path().join("replacement.zip");
        let bytes = build(&[Member::stored(b"entry", b"data")], &[0], b"", b"", false).bytes;
        fs::write(&target, &bytes).unwrap();
        std::os::unix::fs::symlink("target.zip", &alias).unwrap();
        let mut session = ReadSession::open(&alias).unwrap();
        assert_eq!(read(&mut session, 0), b"data");
        fs::write(&replacement, bytes).unwrap();
        fs::rename(replacement, target).unwrap();
        assert!(matches!(session.check_source(), Err(SessionError::SourceChanged { .. })));
    }

    fn assert_changed(path: &Path, edit: impl FnOnce()) {
        let mut session = ReadSession::open(path).unwrap();
        edit();
        assert!(matches!(
            session.check_source(),
            Err(SessionError::SourceChanged { change: SourceChange::StampMismatch, .. })
        ));
    }

    #[test]
    fn detects_in_place_append_truncate_and_restored_mtime() {
        let fixture = build(&[Member::stored(b"entry", b"original")], &[0], b"", b"", false);
        let (file, _) = open_fixture(&fixture.bytes);
        let original = file.as_file().metadata().unwrap();
        assert_changed(file.path(), || {
            use std::os::unix::fs::{FileExt, MetadataExt};
            let source = OpenOptions::new().write(true).open(file.path()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            // A filesystem can coalesce closely spaced timestamps. Poll
            // actual ctime so the test proves it differs independently.
            let modified = loop {
                source.write_all_at(b"new-data", fixture.payload[0].start as u64).unwrap();
                source.set_times(FileTimes::new().set_modified(original.modified().unwrap())).unwrap();
                let observed = source.metadata().unwrap();
                if (observed.ctime(), observed.ctime_nsec()) != (original.ctime(), original.ctime_nsec()) {
                    break observed;
                }
                assert!(std::time::Instant::now() < deadline, "filesystem did not update ctime");
                std::thread::yield_now();
            };
            assert_eq!(modified.len(), original.len());
            assert_eq!(modified.modified().unwrap(), original.modified().unwrap());
        });
        assert_changed(file.path(), || {
            OpenOptions::new().append(true).open(file.path()).unwrap().write_all(b"+").unwrap();
        });
        assert_changed(file.path(), || file.as_file().set_len(original.len() - 1).unwrap());
    }

    #[test]
    fn missing_path_and_sink_error_keep_both_diagnostics() {
        let (file, mut session) = open_fixture(&build(&[Member::stored(b"x", b"abc")], &[0], b"", b"", false).bytes);
        let id = session.metadata().entry_id(0).unwrap();
        let err = session
            .select(&id, 64, Cancellation::default())
            .unwrap()
            .read(None, |bytes| {
                assert_eq!(bytes, b"abc");
                fs::remove_file(file.path()).unwrap();
                Err(Error::Io(io::Error::other("staging failed")))
            })
            .unwrap_err();
        assert!(matches!(
            err,
            SessionError::SourceChanged { change: SourceChange::Unverifiable(_), context: Some(Error::Io(_)) }
        ));
        assert!(err.to_string().contains("staging failed"));
        assert!(matches!(
            session.check_source(),
            Err(SessionError::SourceChanged { change: SourceChange::Unverifiable(_), .. })
        ));
    }

    #[test]
    fn recoverable_cancellation_and_sink_errors_allow_a_fresh_selection() {
        let bytes = vec![b'a'; (1 << 20) + 4];
        let (file, mut session) = open_fixture(&build(&[Member::stored(b"x", &bytes)], &[0], b"", b"", false).bytes);
        let id = session.metadata().entry_id(0).unwrap();
        let cancel = Cancellation::default();
        cancel.cancel();
        assert!(matches!(
            ReadSession::open_cancelable(file.path(), &cancel),
            Err(SessionError::Archive(Error::Io(err))) if err.kind() == io::ErrorKind::ConnectionAborted
        ));
        assert!(matches!(
            session.select(&id, u64::MAX, cancel),
            Err(SessionError::Archive(Error::Io(err))) if err.kind() == io::ErrorKind::ConnectionAborted
        ));
        let selected = session.select(&id, u64::MAX, Cancellation::default()).unwrap();
        assert!(matches!(
            selected.read(None, |_| Err(Error::Io(io::Error::other("sink failure")))),
            Err(SessionError::Archive(Error::Io(err))) if err.to_string() == "sink failure"
        ));
        let cancel = Cancellation::default();
        let selected = session.select(&id, u64::MAX, cancel.clone()).unwrap();
        let mut calls = 0;
        let result = selected.read(None, |_| {
            calls += 1;
            cancel.cancel();
            Ok(())
        });
        assert!(
            matches!(result, Err(SessionError::Archive(Error::Io(err))) if err.kind() == io::ErrorKind::ConnectionAborted)
        );
        assert_eq!(calls, 1);
        let mut len = 0;
        session
            .select(&id, u64::MAX, Cancellation::default())
            .unwrap()
            .read(None, |chunk| {
                len += chunk.len();
                Ok(())
            })
            .unwrap();
        assert_eq!(len, bytes.len());
    }

    #[test]
    fn source_change_overrides_success_after_the_final_sink_call() {
        let (file, mut session) = open_fixture(&build(&[Member::stored(b"x", b"abc")], &[0], b"", b"", false).bytes);
        let id = session.metadata().entry_id(0).unwrap();
        let selected = session.select(&id, 3, Cancellation::default()).unwrap();
        assert!(matches!(
            selected.read(None, |_| {
                OpenOptions::new().append(true).open(file.path()).unwrap().write_all(b"x").unwrap();
                Ok(())
            }),
            Err(SessionError::SourceChanged { context: None, .. })
        ));
    }

    #[test]
    fn late_crc_failure_rejects_a_staged_prefix() {
        let bytes = vec![b'a'; 4097];
        let bad = Member { crc: Some(1), ..Member::stored(b"bad", &bytes) };
        let good = Member::stored(b"good", b"data");
        let (_file, mut session) = open_fixture(&build(&[bad, good], &[0, 1], b"", b"", false).bytes);
        let id = session.metadata().entry_id(0).unwrap();
        let mut prefix = Vec::new();
        let result = session.select(&id, 4097, Cancellation::default()).unwrap().read(None, |chunk| {
            prefix.extend_from_slice(&chunk[..chunk.len().min(4096 - prefix.len())]);
            Ok(())
        });
        assert!(matches!(result, Err(SessionError::Archive(Error::BadChecksum(name))) if name == "bad"));
        assert_eq!(prefix, vec![b'a'; 4096]);
        assert_eq!(read(&mut session, 1), b"data");
    }

    #[test]
    fn selection_checks_both_limits_and_the_root_path_policy() {
        let packed = [0x03, 0x00];
        let members = [
            Member::deflated(b"decoded", &packed, b"aaa"),
            Member::deflated(b"packed", &packed, b""),
            Member::stored(b"dir/", b""),
            Member { external: 0o120777 << 16, ..Member::stored(b"link", b"") },
            Member::stored(b"../escape", b""),
            Member { made_by: 20, ..Member::stored(b"one\\two", b"") },
        ];
        let (_file, mut session) = open_fixture(&build(&members, &[0, 1, 2, 3, 4, 5], b"", b"", false).bytes);
        let metadata = session.metadata();
        for (ordinal, limit) in [(0, 2), (1, 1), (2, 0), (3, 0)] {
            assert!(matches!(
                session.select(&metadata.entry_id(ordinal).unwrap(), limit, Cancellation::default()),
                Err(SessionError::Archive(Error::Unsupported(_)))
            ));
        }
        assert!(matches!(
            session.select(&metadata.entry_id(4).unwrap(), 0, Cancellation::default()),
            Err(SessionError::Archive(Error::UnsafePath(_)))
        ));
        let selected = session.select(&metadata.entry_id(5).unwrap(), 0, Cancellation::default()).unwrap();
        assert_eq!(selected.name(), "one\\two");
        assert_eq!(selected.relative_path(), Path::new("one/two"));
        assert_eq!(selected.unix_mode(), None);
        assert_eq!(selected.modified(), Some((1_577_934_246, 0)));
        selected.read(None, |_| panic!("empty entry should not call sink")).unwrap();
    }

    #[test]
    fn raw_and_root_display_metadata_survive_a_prefixed_zip64_open() {
        let mut unicode = vec![1];
        unicode.extend_from_slice(&crc32fast::hash(b"wire").to_le_bytes());
        unicode.extend_from_slice("雪".as_bytes());
        let extras = [extra(0x7075, &unicode), extra(0x5455, &[1, 0xff, 0xff, 0xff, 0xff])].concat();
        let members = [
            Member {
                made_by: 0x1314,
                external: 0,
                crc: Some(0x1234),
                comment: b"\xff\x1b",
                ..Member::stored(b"dir/", b"")
            },
            Member { zip64: true, central_extra: &extras, ..Member::stored(b"wire", b"x") },
            Member::stored(b"caf\x82", b""),
            Member { flags: 0x800, ..Member::stored(b"bad\xff", b"") },
        ];
        let fixture = build(&members, &[0, 1, 2, 3], b"stub", b"note\x1b\xe2\x80\xae", true);
        let (_file, mut session) = open_fixture(&fixture.bytes);
        let metadata = session.metadata();
        let entries: Vec<_> = metadata.entries().collect();
        assert_eq!(entries.iter().map(|e| e.name()).collect::<Vec<_>>(), ["dir/", "雪", "café", "bad�"]);
        let dir = entries[0];
        assert!(dir.is_dir());
        assert_eq!(dir.listing_crc32(), None);
        assert_eq!(dir.raw_crc32(), 0x1234);
        assert_eq!(dir.extraction_unix_mode(), None);
        assert_eq!(dir.display_unix_mode(), Some(0));
        assert_eq!((dir.creator_host(), dir.creator_version()), (19, 20));
        assert_eq!(dir.raw_comment(), b"\xff\x1b");
        assert_eq!(dir.header().version_made_by, 0x1314);

        let entry = entries[1];
        assert_eq!(entry.raw_name(), b"wire");
        assert_eq!(entry.raw_unicode_path(), Some("雪".as_bytes()));
        assert_eq!(entry.modified(), Some((-1, 0)));
        assert!(matches!(entry.raw_mtime_override(), Some(zipfast::zip::ExtraMtime::UnixSeconds(-1))));
        assert_eq!((entry.header().mod_date, entry.header().mod_time), (0x5022, 0x1883));
        assert_eq!(entry.extraction_unix_mode(), Some(0o100644));
        assert_eq!(entry.header().local_header_offset, u32::MAX);
        assert_eq!(entry.header().packed_size, u32::MAX);
        assert_eq!(entry.resolved().packed_size, 1);
        assert!(!entry.resolved().unresolved.local_header_offset);
        assert_eq!(entry.stored_local_header_offset(), fixture.local[1] as u64 - 4);
        assert_eq!(entry.physical_local_header_offset(), fixture.local[1] as u64);
        let source = entry.source();
        let name = source.name_range();
        assert_eq!(entry.fixed_header_range(), fixture.central[1] as u64..name.start);
        assert_eq!(&fixture.bytes[name.start as usize..name.end as usize], b"wire");
        assert_eq!(source.extra_range().end, source.comment_range().start);
        assert_eq!(source.declared_range(), source.raw_range());
        assert_eq!(metadata.source_len(), fixture.bytes.len() as u64);
        assert_eq!(metadata.prefix_shift(), 4);
        assert_eq!(metadata.end_record().source.start, fixture.eocd as u64);
        assert_eq!(metadata.zip64_end().unwrap().declaration.entries, 4);
        assert_eq!(metadata.zip64_locator().unwrap().total_disks, 1);
        assert_eq!(metadata.raw_comment(), b"note\x1b\xe2\x80\xae");
        assert_eq!(metadata.comment_range().start, fixture.eocd as u64 + 22);
        assert_eq!(metadata.declaration().entries, 4);
        assert_eq!(metadata.directory_range().start, fixture.central[0] as u64);
        assert_eq!(metadata.observed_range(), metadata.logical_range());
        assert_eq!(read(&mut session, 1), b"x");
    }

    #[test]
    fn all_compression_labels_use_the_raw_method() {
        let cases = [
            (0, "Stored"),
            (1, "Shrunk"),
            (6, "Imploded"),
            (8, "Deflate"),
            (9, "Deflate64"),
            (12, "Bzip2"),
            (14, "LZMA"),
            (93, "Zstd"),
            (95, "XZ"),
            (96, "Jpeg"),
            (97, "WavPack"),
            (98, "PPMd"),
            (99, "AES"),
            (360, "Unknown"),
        ];
        let extras =
            [extra(0x9901, &[1, 0, b'X', b'Y', 2, 8, 0]), extra(0x9901, &[2, 0, b'A', b'E', 3, 0, 0])].concat();
        let members: Vec<_> = cases
            .iter()
            .map(|&(method, _)| Member {
                method,
                central_extra: if method == 99 { &extras } else { &[] },
                ..Member::stored(b"x", b"")
            })
            .collect();
        let order: Vec<_> = (0..members.len()).collect();
        let (_file, session) = open_fixture(&build(&members, &order, b"", b"", false).bytes);
        for (entry, (raw, label)) in session.metadata().entries().zip(cases) {
            assert_eq!(entry.header().method, raw);
            assert_eq!(entry.listing_method(), raw.min(255) as u8);
            assert_eq!(entry.compression_name(), label);
            assert!(!entry.is_solid());
            if raw == 99 {
                assert_eq!(entry.effective_method(), 8);
                assert_eq!(entry.aes_info(), Some((2, 1, 8)));
                assert_eq!(entry.raw_aes_fields().unwrap().vendor_id, *b"XY");
                assert!(entry.encrypted());
            } else {
                assert_eq!(entry.effective_method(), raw);
            }
        }
    }

    #[test]
    fn nonregular_files_are_rejected() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            ReadSession::open(dir.path()),
            Err(SessionError::SourceChanged { change: SourceChange::Unverifiable(_), .. })
        ));
        let fifo = dir.path().join("source");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            send.send(matches!(
                ReadSession::open(&fifo),
                Err(SessionError::SourceChanged { change: SourceChange::Unverifiable(_), .. })
            ))
            .unwrap();
        });
        assert!(receive.recv_timeout(std::time::Duration::from_secs(5)).expect("FIFO open blocked"));
        reader.join().unwrap();
    }

    #[test]
    fn restoring_the_original_symlink_target_cannot_revive_an_invalid_session() {
        let dir = TempDir::new().unwrap();
        let alias = dir.path().join("alias.zip");
        let first = dir.path().join("first.zip");
        let bytes = build(&[Member::stored(b"x", b"original")], &[0], b"", b"", false).bytes;
        fs::write(&first, &bytes).unwrap();
        fs::write(dir.path().join("other.zip"), &bytes).unwrap();
        let symlink = |target| std::os::unix::fs::symlink(target, &alias).unwrap();
        symlink("first.zip");
        let mut session = ReadSession::open(&alias).unwrap();
        fs::remove_file(&alias).unwrap();
        assert!(matches!(
            session.check_source(),
            Err(SessionError::SourceChanged { change: SourceChange::Unverifiable(error), .. })
                if error.kind() == io::ErrorKind::NotFound
        ));

        symlink("other.zip");
        let mut other = ReadSession::open(&alias).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink("first.zip");
        assert!(matches!(
            other.check_source(),
            Err(SessionError::SourceChanged { change: SourceChange::StampMismatch, .. })
        ));
        assert!(matches!(
            session.check_source(),
            Err(SessionError::SourceChanged { change: SourceChange::Unverifiable(error), .. })
                if error.kind() == io::ErrorKind::NotFound
        ));
        assert_eq!(read(&mut ReadSession::open(&alias).unwrap(), 0), b"original");
    }

    #[test]
    fn full_aes_authentication_and_password_failures_allow_reselection() {
        // AES-128 fixture independently generated in the root crypto tests.
        let payload = [
            49, 50, 51, 52, 53, 54, 55, 56, 153, 191, 197, 64, 79, 101, 103, 92, 73, 178, 222, 207, 22, 192, 51, 16,
            127, 189, 76, 25, 140,
        ];
        let mut damaged = payload;
        damaged[28] ^= 1; // Corrupt the end of the authentication tag.
        let ae1 = extra(0x9901, &[1, 0, b'A', b'E', 1, 0, 0]);
        let ae2 = extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
        let member = Member {
            flags: 1,
            method: 99,
            decoded: Some(b"hello pry"),
            crc: Some(1),
            central_extra: &ae2,
            ..Member::stored(b"aes", &payload)
        };
        let bad_tag = Member { payload: &damaged, ..member };
        let bad_crc = Member { central_extra: &ae1, ..member };
        let (_file, mut session) = open_fixture(&build(&[bad_tag, bad_crc, member], &[0, 1, 2], b"", b"", false).bytes);
        let metadata = session.metadata();
        let mut decode = |ordinal, password| {
            let id = metadata.entry_id(ordinal).unwrap();
            let mut out = Vec::new();
            let result = session.select(&id, 29, Cancellation::default()).unwrap().read(Some(password), |chunk| {
                out.extend_from_slice(chunk);
                Ok(())
            });
            (result, out)
        };
        let (bad_tag, out) = decode(0, "prybar-fixture");
        assert!(matches!(bad_tag, Err(SessionError::Archive(Error::Corrupt(_)))));
        assert!(out.is_empty());
        let (bad_crc, out) = decode(1, "prybar-fixture");
        assert!(matches!(bad_crc, Err(SessionError::Archive(Error::BadChecksum(_)))));
        assert_eq!(out, b"hello pry");
        let (wrong_password, out) = decode(2, "incorrect");
        assert!(matches!(wrong_password, Err(SessionError::Archive(Error::Corrupt(_)))));
        assert!(out.is_empty());
        let (ae2_result, out) = decode(2, "prybar-fixture");
        ae2_result.unwrap();
        assert_eq!(out, b"hello pry");
    }

    #[test]
    fn encrypted_packed_ceiling_is_independent_of_selection_limit() {
        let ceiling = 128_u32 << 20;
        for (packed, message) in [(ceiling, "password required"), (ceiling + 1, "128 MiB packed limit")] {
            let member = Member { flags: 1, ..Member::stored(b"x", b"") };
            let mut fixture = build(&[member], &[0], b"", b"", false);
            let cd = fixture.central[0];
            fixture.bytes[18..22].copy_from_slice(&packed.to_le_bytes());
            fixture.bytes[cd + 20..cd + 24].copy_from_slice(&packed.to_le_bytes());
            fixture.bytes[fixture.eocd + 16..fixture.eocd + 20]
                .copy_from_slice(&(u32::try_from(cd).unwrap() + packed).to_le_bytes());
            let mut file = NamedTempFile::new().unwrap();
            file.write_all(&fixture.bytes[..cd]).unwrap();
            file.seek(SeekFrom::Current(i64::from(packed))).unwrap();
            file.write_all(&fixture.bytes[cd..]).unwrap();
            let mut session = ReadSession::open(file.path()).unwrap();
            let id = session.metadata().entry_id(0).unwrap();
            let selected = session.select(&id, u64::from(packed), Cancellation::default()).unwrap();
            assert!(matches!(
                selected.read(None, |_| panic!("unreadable encrypted payload")),
                Err(SessionError::Archive(Error::Unsupported(reason))) if reason.contains(message)
            ));
        }
    }

    #[test]
    fn strict_session_rejects_split_and_overflowing_offsets() {
        let member = Member { zip64: true, ..Member::stored(b"x", b"") };
        let mut fixture = build(&[member], &[0], b"prefix", b"", true);
        let central = fixture.central[0];
        let mut file = NamedTempFile::new().unwrap();
        fixture.bytes[central + 34..central + 36].copy_from_slice(&1u16.to_le_bytes());
        file.write_all(&fixture.bytes).unwrap();
        assert!(matches!(
            ReadSession::open(file.path()),
            Err(SessionError::Archive(Error::Unsupported(message))) if message.contains("split")
        ));

        fixture.bytes[central + 34..central + 36].copy_from_slice(&0u16.to_le_bytes());
        let offset = central + 46 + 1 + 4 + 16;
        fixture.bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        file.rewind().unwrap();
        file.write_all(&fixture.bytes).unwrap();
        assert!(matches!(
            ReadSession::open(file.path()),
            Err(SessionError::Archive(Error::Corrupt("local header offset")))
        ));
    }

    #[test]
    fn selection_handles_truncated_local_layout_and_huge_payload_claims() {
        let member = Member::stored(b"x", b"abc");
        let mut fixture = build(&[member], &[0], b"", b"", false);
        let cd = fixture.central[0];
        let local = (fixture.bytes.len() - 5) as u32;
        fixture.bytes[cd + 42..cd + 46].copy_from_slice(&local.to_le_bytes());
        let (_file, mut session) = open_fixture(&fixture.bytes);
        let id = session.metadata().entry_id(0).unwrap();
        assert!(matches!(
            session.select(&id, 3, Cancellation::default()).unwrap().read(None, |_| panic!("truncated header")),
            Err(SessionError::Archive(Error::Truncated))
        ));

        fixture.bytes[cd + 42..cd + 46].copy_from_slice(&0u32.to_le_bytes());
        fixture.bytes[cd + 20..cd + 28].copy_from_slice(&[0xff; 8]);
        let (_file, mut session) = open_fixture(&fixture.bytes);
        let id = session.metadata().entry_id(0).unwrap();
        assert!(matches!(
            session.select(&id, 3, Cancellation::default()),
            Err(SessionError::Archive(Error::Unsupported(_)))
        ));
        assert!(matches!(
            session.select(&id, u64::MAX, Cancellation::default()).unwrap().read(None, |_| panic!("truncated payload")),
            Err(SessionError::Archive(Error::Truncated))
        ));
    }

    #[test]
    fn short_deflate_output_remains_provisional_until_size_verification() {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(b"abc").unwrap();
        let packed = encoder.finish().unwrap();
        let member = Member::deflated(b"x", &packed, b"four");
        let (_file, mut session) = open_fixture(&build(&[member], &[0], b"", b"", false).bytes);
        let id = session.metadata().entry_id(0).unwrap();
        let mut bytes = Vec::new();
        let result = session.select(&id, 64, Cancellation::default()).unwrap().read(None, |chunk| {
            bytes.extend_from_slice(chunk);
            Ok(())
        });
        assert!(matches!(result, Err(SessionError::Archive(Error::Corrupt("less data than the directory says")))));
        assert_eq!(bytes, b"abc");
        session.check_source().unwrap();
    }

    #[test]
    fn short_and_invalid_known_extras_follow_the_root_selection_policy() {
        let ntfs_ticks = 116_444_736_000_000_017u64;
        let mut ntfs = [0u8; 32];
        ntfs[4..8].copy_from_slice(&[1, 0, 24, 0]);
        ntfs[8..16].copy_from_slice(&ntfs_ticks.to_le_bytes());
        let mut unicode = vec![1];
        unicode.extend_from_slice(&crc32fast::hash(b"wire").to_le_bytes());
        unicode.extend_from_slice(b"bad\xff");
        let extras = [
            extra(0x9901, &[1, 0]),
            extra(0x9901, &[1, 0, b'A', b'E', 0, 8, 0]),
            extra(0x9901, &[2, 0, b'A', b'E', 3, 0, 0]),
            extra(0x000a, &ntfs),
            extra(0x7075, &unicode),
        ]
        .concat();
        let member = Member { made_by: 0x1314, method: 99, central_extra: &extras, ..Member::stored(b"wire", b"") };
        let (_file, session) = open_fixture(&build(&[member], &[0], b"", b"", false).bytes);
        let metadata = session.metadata();
        let entry = metadata.entries().next().unwrap();
        assert_eq!(entry.name(), "bad�");
        assert_eq!(entry.raw_name(), b"wire");
        assert_eq!(entry.raw_unicode_path(), Some(&b"bad\xff"[..]));
        assert_eq!(entry.modified(), Some((0, 1700)));
        assert!(
            matches!(entry.raw_mtime_override(), Some(zipfast::zip::ExtraMtime::NtfsFiletime(ticks)) if ticks == ntfs_ticks)
        );
        assert_eq!(entry.raw_aes_fields().unwrap().strength, 0);
        assert_eq!(entry.aes_info(), None);
        assert_eq!(entry.effective_method(), 99);
        assert_eq!(entry.extraction_unix_mode(), None);
        assert_eq!(entry.display_unix_mode(), Some(0o100644));
        let mut edited = entry.header();
        edited.method = 8;
        assert_eq!(edited.method, 8);
        assert_eq!(metadata.entry(&metadata.entry_id(0).unwrap()).unwrap().header().method, 99);
    }

    #[test]
    fn unchanged_bytes_can_be_read_from_an_exclusively_borrowed_session() {
        let fixture = build(&[Member::stored(b"entry", b"yes")], &[0], b"", b"", false);
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("one.zip");
        File::create(&file).unwrap().write_all(&fixture.bytes).unwrap();
        let session = ReadSession::open(&file).unwrap();
        assert_eq!(std::thread::spawn(move || read(&mut { session }, 0)).join().unwrap(), b"yes");
    }
}

#[cfg(not(unix))]
#[test]
fn session_identity_is_explicitly_unsupported() {
    use std::path::Path;
    use zipfast::zip::{Archive, ReadSession, SessionError};
    let path = Path::new("missing.zip");
    assert!(matches!(ReadSession::open(path), Err(SessionError::UnsupportedIdentity)));
    assert!(Archive::open(path).is_err());
}
