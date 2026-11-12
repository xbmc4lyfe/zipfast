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

use std::cell::RefCell;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::rc::Rc;

use tempfile::NamedTempFile;

use super::*;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    Opened,
    DirectoryRead(Range<u64>),
    PayloadRead(Range<u64>),
    AfterDecoder,
}

type Observer = Box<dyn FnMut(Event)>;

thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

pub(super) fn observe(event: Event) {
    OBSERVER.with_borrow_mut(|observer| {
        if let Some(observer) = observer {
            observer(event);
        }
    });
}

fn observing<T>(observer: impl FnMut(Event) + 'static, test: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            OBSERVER.with_borrow_mut(|observer| *observer = None);
        }
    }
    OBSERVER.with_borrow_mut(|slot| *slot = Some(Box::new(observer)));
    let _reset = Reset;
    test()
}

fn archive(payload_len: u32) -> NamedTempFile {
    let mut source = NamedTempFile::new().unwrap();
    let mut local = [0; 30];
    local[..4].copy_from_slice(b"PK\x03\x04");
    local[14..18].copy_from_slice(&0x3524_41c2_u32.to_le_bytes()); // CRC-32 of "abc"
    local[18..22].copy_from_slice(&3u32.to_le_bytes());
    local[22..26].copy_from_slice(&3u32.to_le_bytes());
    local[26..28].copy_from_slice(&1u16.to_le_bytes());
    source.write_all(&local).unwrap();
    source.write_all(b"xabc").unwrap();

    let mut central = [0; 47];
    central[..4].copy_from_slice(b"PK\x01\x02");
    central[16..28].copy_from_slice(&local[14..26]);
    central[28..30].copy_from_slice(&1u16.to_le_bytes());
    central[46] = b'x';
    source.seek(SeekFrom::Start(u64::from(payload_len) + 31)).unwrap();
    source.write_all(&central).unwrap();

    let mut end = [0; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&1u16.to_le_bytes());
    end[10..12].copy_from_slice(&1u16.to_le_bytes());
    end[12..16].copy_from_slice(&47u32.to_le_bytes());
    end[16..20].copy_from_slice(&(payload_len + 31).to_le_bytes());
    source.write_all(&end).unwrap();
    source
}

fn canceled(result: SessionResult<()>) -> bool {
    matches!(result, Err(SessionError::Archive(Error::Io(error))) if error.kind() == io::ErrorKind::ConnectionAborted)
}

#[test]
fn replacement_between_open_and_initial_stamp_is_rejected_without_parsing() {
    let source = archive(3);
    let replacement = archive(3);
    let path = source.path().to_path_buf();
    let result = observing(
        move |event| match event {
            Event::Opened => fs::rename(replacement.path(), &path).unwrap(),
            _ => panic!("source bytes were read after a failed initial stamp"),
        },
        || ReadSession::open(source.path()),
    );
    assert!(matches!(result, Err(SessionError::SourceChanged { change: SourceChange::StampMismatch, .. })));
}

#[test]
fn parse_mutation_wins_over_the_original_cancellation_error() {
    let source = archive(3);
    let path = source.path().to_path_buf();
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let mut changed = false;
    let result = observing(
        move |event| {
            if matches!(event, Event::DirectoryRead(_)) && !changed {
                changed = true;
                OpenOptions::new().append(true).open(&path).unwrap().write_all(b"x").unwrap();
                signal.cancel();
            }
        },
        || ReadSession::open_cancelable(source.path(), &cancel),
    );
    assert!(matches!(
        result,
        Err(SessionError::SourceChanged {
            change: SourceChange::StampMismatch,
            context: Some(Error::Io(error)),
        }) if error.kind() == io::ErrorKind::ConnectionAborted
    ));
}

#[test]
fn parse_mutation_prevents_publication_even_with_an_intact_directory() {
    let source = archive(3);
    let path = source.path().to_path_buf();
    let mut changed = false;
    let result = observing(
        move |event| {
            if matches!(event, Event::DirectoryRead(_)) && !changed {
                changed = true;
                OpenOptions::new().append(true).open(&path).unwrap().write_all(b"x").unwrap();
            }
        },
        || ReadSession::open(source.path()),
    );
    assert!(matches!(result, Err(SessionError::SourceChanged { context: None, .. })));
}

#[test]
fn cancellation_before_open_or_during_parse_keeps_metadata_private() {
    let source = archive(3);
    let cancel = Cancellation::default();
    cancel.cancel();
    assert!(canceled(observing(
        |_| panic!("pre-canceled open must issue no data opens or reads"),
        || ReadSession::open_cancelable(source.path(), &cancel).map(drop),
    )));
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let mut reads = 0;
    let result = observing(
        move |event| {
            if matches!(event, Event::DirectoryRead(_)) {
                reads += 1;
                assert_eq!(reads, 1, "parse must stop at the canceled chunk");
                signal.cancel();
            }
        },
        || ReadSession::open_cancelable(source.path(), &cancel).map(drop),
    );
    assert!(canceled(result));
}

#[test]
fn cancellation_between_selection_and_read_skips_payload_io() {
    let source = archive(3);
    let mut session = ReadSession::open(source.path()).unwrap();
    let id = session.metadata().entry_id(0).unwrap();
    let cancel = Cancellation::default();
    let selected = session.select(&id, 3, cancel.clone()).unwrap();
    cancel.cancel();
    assert!(canceled(observing(
        |event| assert_eq!(event, Event::AfterDecoder),
        || selected.read(None, |_| panic!("pre-canceled read must not call sink")),
    )));
    session.check_source().unwrap();
}

#[test]
fn cancellation_while_input_is_read_prevents_sink_delivery() {
    let source = archive(3);
    let mut session = ReadSession::open(source.path()).unwrap();
    let id = session.metadata().entry_id(0).unwrap();
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let result = observing(
        move |event| {
            if event == Event::PayloadRead(31..34) {
                signal.cancel();
            }
        },
        || session.select(&id, 3, cancel).unwrap().read(None, |_| panic!("canceled decoder called sink")),
    );
    assert!(canceled(result));
    session.check_source().unwrap();
}

#[test]
fn cancellation_after_decoder_rejects_provisional_output() {
    let source = archive(3);
    let mut session = ReadSession::open(source.path()).unwrap();
    let id = session.metadata().entry_id(0).unwrap();
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let mut provisional = Vec::new();
    let result = observing(
        move |event| {
            if event == Event::AfterDecoder {
                signal.cancel();
            }
        },
        || {
            session.select(&id, 3, cancel).unwrap().read(None, |chunk| {
                provisional.extend_from_slice(chunk);
                Ok(())
            })
        },
    );
    assert!(canceled(result));
    assert_eq!(provisional, b"abc");
    session.check_source().unwrap();
}

#[test]
fn mutation_during_payload_io_overrides_decoder_error() {
    let source = archive(3);
    let path = source.path().to_path_buf();
    let mut session = ReadSession::open(source.path()).unwrap();
    let id = session.metadata().entry_id(0).unwrap();
    let result = observing(
        move |event| {
            if event == Event::PayloadRead(0..30) {
                OpenOptions::new().write(true).open(&path).unwrap().set_len(31).unwrap();
            }
        },
        || session.select(&id, 3, Cancellation::default()).unwrap().read(None, |_| panic!("truncated payload")),
    );
    assert!(matches!(result, Err(SessionError::SourceChanged { context: Some(Error::Truncated), .. })));
}

#[test]
fn repeated_tiny_reads_reuse_one_open_without_reparse_or_prescan() {
    // Keep a multi-MiB sparse gap between the selected bytes and the directory
    // so a read of the discovery tail cannot hide a payload prescan.
    let source = archive(3 << 20);
    let events = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&events);
    observing(
        move |event| recorded.borrow_mut().push(event),
        || {
            let mut session = ReadSession::open(source.path()).unwrap();
            let id = session.metadata().entry_id(0).unwrap();
            let open_events = std::mem::take(&mut *events.borrow_mut());
            assert_eq!(open_events.first(), Some(&Event::Opened));
            assert!(open_events.len() > 1);
            assert!(open_events[1..].iter().all(|event| {
                matches!(event, Event::DirectoryRead(range) if range.start > (2 << 20) && range.end - range.start <= (64 << 10))
            }));
            assert_eq!(session.metadata().parser_usage().owned.entries, 1);
            for _ in 0..3 {
                let mut out = Vec::new();
                session
                    .select(&id, 3, Cancellation::default())
                    .unwrap()
                    .read(None, |chunk| {
                        out.extend_from_slice(chunk);
                        Ok(())
                    })
                    .unwrap();
                assert_eq!(out, b"abc");
                assert_eq!(
                    *events.borrow(),
                    [Event::PayloadRead(0..30), Event::PayloadRead(31..34), Event::AfterDecoder,]
                );
                events.borrow_mut().clear();
            }
        },
    );
}

#[test]
fn decoded_name_charges_the_expansion_before_allocation() {
    let mut budget = DecodedNameBudget(3);
    let name = decode_invalid_name(b"\xff", true, |len| budget.charge(len)).unwrap();
    assert_eq!(name, "�");
    assert!(matches!(
        decode_invalid_name(b"\x82", false, |len| budget.charge(len)),
        Err(DirectoryError::Limit(LimitKind::NameBytes))
    ));
    assert_eq!(budget.0, 0);
}

#[test]
fn directory_admission_enforces_each_shared_budget() {
    let mut source = archive(3);
    let mut bytes = Vec::new();
    source.rewind().unwrap();
    source.read_to_end(&mut bytes).unwrap();
    let central = 34;
    let mut extra = Vec::new();
    extra.extend_from_slice(&[0x75, 0x70, 7, 0, 1]);
    extra.extend_from_slice(&crate::crc32::hash(b"x").to_le_bytes());
    extra.extend_from_slice("β".as_bytes());
    bytes[central + 30..central + 32].copy_from_slice(&(extra.len() as u16).to_le_bytes());
    bytes[central + 32..central + 34].copy_from_slice(&2u16.to_le_bytes());
    let extra_len = extra.len();
    bytes.splice(central + 47..central + 47, extra.into_iter().chain(*b"ok"));
    let end = bytes.len() - 22;
    bytes[end + 12..end + 16].copy_from_slice(&((47 + extra_len + 2) as u32).to_le_bytes());
    bytes[end + 20..end + 22].copy_from_slice(&3u16.to_le_bytes());
    bytes.extend_from_slice(b"eoc");
    source.rewind().unwrap();
    source.write_all(&bytes).unwrap();
    let len = bytes.len() as u64;
    let mut parse = |limits| {
        let parser = DirectoryParser::with_name_crc32(len, Profile::Zipfast, limits, crate::crc32::hash)
            .map_err(directory_error)?;
        read_directory(source.as_file_mut(), len, parser, Some(&Cancellation::default()))
    };

    let directory = parse(Limits::default()).unwrap();
    let exact = Limits {
        directory_bytes: directory.declaration.size,
        entries: 1,
        fetched_bytes: directory.usage.fetched_bytes,
        work_units: directory.usage.work_units,
        name_bytes: 1,
        extra_bytes: 2,
        comment_bytes: 5,
        ..Limits::default()
    };
    assert_eq!(parse(exact).unwrap(), directory);
    for (budget, limits) in [
        ("directory", Limits { directory_bytes: exact.directory_bytes - 1, ..exact }),
        ("entry count", Limits { entries: 0, ..exact }),
        ("fetch", Limits { fetched_bytes: exact.fetched_bytes - 1, ..exact }),
        ("work", Limits { work_units: exact.work_units - 1, ..exact }),
        ("name", Limits { name_bytes: 0, ..exact }),
        ("extra", Limits { extra_bytes: 1, ..exact }),
        ("comment", Limits { comment_bytes: 4, ..exact }),
    ] {
        assert!(matches!(parse(limits), Err(Error::Unsupported(_))), "{budget} exceeded");
    }
}

#[test]
fn default_session_directory_limit_accepts_exact_and_rejects_one_over() {
    for directory_size in [128_u32 << 20, (128_u32 << 20) + 1] {
        let mut source = NamedTempFile::new().unwrap();
        source.seek(SeekFrom::Start(u64::from(directory_size))).unwrap();
        let mut end = [0u8; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[12..16].copy_from_slice(&directory_size.to_le_bytes());
        source.write_all(&end).unwrap();
        let opened = ReadSession::open(source.path());
        if directory_size == 128 << 20 {
            let metadata = opened.unwrap().metadata();
            assert!(metadata.is_empty());
            assert_eq!(metadata.declaration().size, u64::from(directory_size));
        } else {
            assert!(matches!(opened, Err(SessionError::Archive(Error::Unsupported(_)))));
        }
    }
}

pub(super) struct ObservedFile<'a> {
    pub(super) file: &'a mut File,
    pub(super) position: u64,
    pub(super) event: fn(Range<u64>) -> Event,
}

impl Read for ObservedFile<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let start = self.position;
        let read = self.file.read(bytes)?;
        self.position += read as u64;
        observe((self.event)(start..self.position));
        Ok(read)
    }
}

impl Seek for ObservedFile<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = self.file.seek(position)?;
        Ok(self.position)
    }
}
