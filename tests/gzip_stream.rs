// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5

use std::io::{self, Read};

use zipfast::stream::gzip::{self, Control, DecodeOptions, DecodeOutcome, TailPolicy};

const STRICT: DecodeOptions = DecodeOptions { tail: TailPolicy::Strict };

#[test]
fn initial_lone_magic_byte_is_available_for_passthrough() {
    let mut input = &b"\x1f"[..];
    let mut output = Vec::new();
    let outcome =
        gzip::decode(&mut input, &mut output, STRICT, Control::default(), |_| panic!("unexpected gzip event")).unwrap();
    let DecodeOutcome::NotGzip { prefix, prefix_len } = outcome else {
        panic!("expected non-gzip input");
    };
    assert!(output.is_empty());
    let mut replay = prefix[..usize::from(prefix_len)].chain(input);
    io::copy(&mut replay, &mut output).unwrap();
    assert_eq!(output, b"\x1f");
}

use std::cell::Cell;
use std::io::{BufRead, BufReader, Write};

use gzip::{EncodeOptions, Failure, FailureKind, Limit, Limits, MemberEvent, Metadata, Phase, Progress, Tail, Totals};

const PERMISSIVE: DecodeOptions = DecodeOptions { tail: TailPolicy::TerminalPaddingAndGarbage };

fn options() -> EncodeOptions<'static> {
    EncodeOptions { level: 6, metadata: Metadata::default() }
}

// Independent wire fixture using one final, stored DEFLATE block.
fn member(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(payload.len()).unwrap();
    let mut bytes = b"\x1f\x8b\x08\0\0\0\0\0\0\xff\x01".to_vec();
    bytes.extend(len.to_le_bytes());
    bytes.extend((!len).to_le_bytes());
    bytes.extend(payload);
    bytes.extend(crc32fast::hash(payload).to_le_bytes());
    bytes.extend(u32::from(len).to_le_bytes());
    bytes
}

fn verify(bytes: &[u8], options: DecodeOptions, limits: Limits) -> Result<DecodeOutcome, Failure> {
    gzip::decode(&mut &bytes[..], &mut io::sink(), options, Control { limits, cancelled: None }, |_| Ok(()))
}

fn verified(outcome: DecodeOutcome) -> gzip::DecodeReport {
    match outcome {
        DecodeOutcome::Verified(report) => report,
        other => panic!("expected verified gzip, got {other:?}"),
    }
}

#[test]
fn format_detection_replays_the_exact_prefix_and_keeps_prefetch() {
    for (bytes, prefix_len) in [(&b""[..], 0), (b"x\x1f\x8b", 1), (b"\x1fxhello", 2), (b"\x1f", 1)] {
        for capacity in [1, 64] {
            let mut input = BufReader::with_capacity(capacity, bytes);
            let DecodeOutcome::NotGzip { prefix, prefix_len: len } =
                gzip::decode(&mut input, &mut io::sink(), STRICT, Control::default(), |_| {
                    panic!("unexpected gzip event")
                })
                .unwrap()
            else {
                panic!("unexpected gzip outcome");
            };
            assert_eq!(len, prefix_len);
            if bytes.len() > 2 && capacity == 64 {
                assert_eq!(input.buffer(), &bytes[usize::from(len)..]);
                assert!(input.get_ref().is_empty());
            }
            let mut replay = Vec::new();
            prefix[..usize::from(len)].chain(input).read_to_end(&mut replay).unwrap();
            assert_eq!(replay, bytes);
        }
    }
}

#[test]
fn concatenated_members_report_wire_offsets_and_only_verified_trailers() {
    let mut first = member(b"ABC");
    first[3] = 0x1e; // FHCRC, FEXTRA, FNAME, FCOMMENT
    first[4..8].copy_from_slice(&42u32.to_le_bytes());
    first[9] = 3;
    first.splice(10..10, [1, 0, 7, 0xff, 0, 0]);
    let fhcrc = (crc32fast::hash(&first[..16]) as u16).to_le_bytes();
    first.splice(16..16, fhcrc);
    let bytes = [first.as_slice(), &member(b""), &member(b"def")].concat();

    for capacity in [1, 2, 4096] {
        let mut input = BufReader::with_capacity(capacity, bytes.as_slice());
        let mut output = Vec::new();
        let mut sequence = Vec::new();
        let report = verified(
            gzip::decode(&mut input, &mut output, STRICT, Control::default(), |event| {
                let (header, is_verified) = match event {
                    MemberEvent::Header(header) => (header, false),
                    MemberEvent::Verified { header, compressed_bytes, decoded_bytes } => {
                        let expected = [(34, 3), (23, 0), (26, 3)];
                        assert_eq!((compressed_bytes, decoded_bytes), expected[header.index as usize]);
                        (header, true)
                    }
                };
                let expected = [(0, 18), (34, 10), (57, 10)];
                assert_eq!((header.compressed_offset, header.header_bytes), expected[header.index as usize]);
                if header.index == 0 {
                    assert_eq!(
                        header.metadata,
                        Metadata { mtime: 42, os: 3, filename: Some(b"\xff"), comment: Some(b""), extra: Some(&[7]) }
                    );
                } else {
                    assert_eq!(header.metadata, Metadata::default());
                }
                sequence.push((header.index, is_verified));
                Ok(())
            })
            .unwrap(),
        );
        assert_eq!(output, b"ABCdef");
        assert_eq!(sequence, [(0, false), (0, true), (1, false), (1, true), (2, false), (2, true)]);
        assert_eq!(report.totals, Totals { compressed_bytes: 83, decoded_bytes: 6, members: 3, framing_bytes: 62 });
        assert_eq!(report.source_consumed, 83);
        assert_eq!(report.tail, Tail::Clean);
    }
}

#[test]
fn every_committed_truncation_fails_decode_test_and_listing() {
    let mut bytes = member(b"payload");
    bytes[3] = 0x1e;
    bytes.splice(10..10, [2, 0, 0, 1, b'f', 0, b'c', 0]);
    let crc = (crc32fast::hash(&bytes[..18]) as u16).to_le_bytes();
    bytes.splice(18..18, crc);
    assert!(verify(&bytes, STRICT, Limits::default()).is_ok());
    for end in 2..bytes.len() {
        assert!(
            matches!(verify(&bytes[..end], STRICT, Limits::default()).unwrap_err().kind, FailureKind::Format(_)),
            "{end}"
        );
        let mut output = Vec::new();
        let failure = gzip::decode(&mut &bytes[..end], &mut output, STRICT, Control::default(), |event| {
            assert!(matches!(event, MemberEvent::Header(_)));
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Format(_)), "{end}");
        assert_eq!(failure.progress.source_consumed, end as u64);
        assert_eq!(failure.progress.sink_accepted, output.len() as u64);
    }

    for (offset, replacement) in [(2, 0), (3, 0x80), (18, bytes[18] ^ 1)] {
        let mut damaged = bytes.clone();
        damaged[offset] = replacement;
        let failure = gzip::decode(&mut damaged.as_slice(), &mut io::sink(), PERMISSIVE, Control::default(), |_| {
            panic!("invalid header emitted an event")
        })
        .unwrap_err();
        assert_eq!(failure.phase, Phase::Header);
        assert!(matches!(failure.kind, FailureKind::Format(_)));
    }
}

#[test]
fn second_member_crc_and_size_errors_preserve_only_first_verified_totals() {
    let first = member(b"first");
    for trailer_offset in [8, 4] {
        let mut second = member(b"second");
        let damaged = second.len() - trailer_offset;
        second[damaged] ^= 1;
        let joined = [first.as_slice(), &second].concat();
        let mut output = Vec::new();
        let mut headers = 0;
        let mut complete = 0;
        let failure = gzip::decode(&mut joined.as_slice(), &mut output, PERMISSIVE, Control::default(), |event| {
            match event {
                MemberEvent::Header(_) => headers += 1,
                MemberEvent::Verified { .. } => complete += 1,
            }
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Format(_)));
        assert_eq!((headers, complete), (2, 1));
        assert_eq!(
            failure.progress,
            Progress {
                source_consumed: joined.len() as u64,
                codec_produced: 11,
                sink_accepted: 11,
                verified: Totals { compressed_bytes: 28, decoded_bytes: 5, members: 1, framing_bytes: 18 },
            }
        );
        assert_eq!(output, b"firstsecond");
    }
}

#[test]
fn metadata_maxima_round_trip_and_larger_strings_are_rejected() {
    let field = vec![b'X'; u16::MAX as usize];
    let metadata = Metadata { mtime: 123, os: 13, filename: Some(&field), comment: Some(&field), extra: Some(&field) };
    let mut bytes = Vec::new();
    let report =
        gzip::encode(&mut &b""[..], &mut bytes, EncodeOptions { level: 0, metadata }, Control::default()).unwrap();
    assert_eq!(report.totals.framing_bytes, 196_627);
    for capacity in [1, 256 * 1024] {
        let mut input = BufReader::with_capacity(capacity, bytes.as_slice());
        let mut events = 0;
        gzip::decode(&mut input, &mut io::sink(), STRICT, Control::default(), |event| {
            let header = match event {
                MemberEvent::Header(header) | MemberEvent::Verified { header, .. } => header,
            };
            assert_eq!(header.header_bytes, 196_619);
            assert_eq!(header.metadata, metadata);
            events += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(events, 2);
    }

    for terminator in [12 + field.len() * 2, 13 + field.len() * 3] {
        let mut too_long = bytes.clone();
        too_long.insert(terminator, b'X');
        assert_eq!(verify(&too_long, STRICT, Limits::default()).unwrap_err().phase, Phase::Header);
        let missing = &bytes[..terminator];
        assert_eq!(verify(missing, STRICT, Limits::default()).unwrap_err().phase, Phase::Header);
    }
}

#[test]
fn tail_policy_counts_all_terminal_bytes_but_never_resumes_after_padding() {
    let body = member(b"content");
    let zero_then_member = [&[0, 0][..], body.as_slice()].concat();
    let cases = [
        (&b""[..], Tail::Clean),
        (b"\0\0", Tail::Zeros { bytes: 2 }),
        (b"trash", Tail::Garbage { bytes: 5, leading_zeros: 0 }),
        (b"\0\0x\0", Tail::Garbage { bytes: 4, leading_zeros: 2 }),
        (b"\x1f\0", Tail::Garbage { bytes: 2, leading_zeros: 0 }),
        (&zero_then_member, Tail::Garbage { bytes: 32, leading_zeros: 2 }),
    ];
    for (tail, expected) in cases {
        let bytes = [body.as_slice(), tail].concat();
        let report = verified(verify(&bytes, PERMISSIVE, Limits::default()).unwrap());
        assert_eq!(report.tail, expected);
        assert_eq!(report.totals.compressed_bytes, 30);
        assert_eq!(report.totals.members, 1);
        assert_eq!(report.source_consumed, 30 + tail.len() as u64);
        if !tail.is_empty() {
            assert!(matches!(verify(&bytes, STRICT, Limits::default()).unwrap_err().kind, FailureKind::TrailingData));
        }
    }

    for broken in [&b"\x1f"[..], b"\x1f\x8b", b"\x1f\x8b\0\0\0\0\0\0\0\0"] {
        let bytes = [body.as_slice(), broken].concat();
        for policy in [STRICT, PERMISSIVE] {
            assert!(matches!(verify(&bytes, policy, Limits::default()).unwrap_err().kind, FailureKind::Format(_)));
        }
    }
}

#[test]
fn invalid_encode_options_touch_neither_input_nor_sink() {
    struct Untouchable;
    impl Read for Untouchable {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("unexpected source read")
        }
    }
    impl BufRead for Untouchable {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            panic!("unexpected source fill")
        }
        fn consume(&mut self, _: usize) {
            panic!("unexpected source consume")
        }
    }
    impl Write for Untouchable {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("unexpected sink write")
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("unexpected sink flush")
        }
    }

    let oversized = vec![b'X'; 65_536];
    let defaults = Metadata::default();
    for invalid in [
        EncodeOptions { level: 10, metadata: defaults },
        EncodeOptions { level: 1, metadata: Metadata { extra: Some(&oversized), ..defaults } },
        EncodeOptions { level: 1, metadata: Metadata { filename: Some(&oversized), ..defaults } },
        EncodeOptions { level: 1, metadata: Metadata { comment: Some(&oversized), ..defaults } },
        EncodeOptions { level: 1, metadata: Metadata { filename: Some(b"x\0"), ..defaults } },
        EncodeOptions { level: 1, metadata: Metadata { comment: Some(b"\0x"), ..defaults } },
    ] {
        let failure = gzip::encode(&mut Untouchable, &mut Untouchable, invalid, Control::default()).unwrap_err();
        assert!(matches!(failure.kind, FailureKind::InvalidOptions(_)));
        assert_eq!(failure.progress, Progress::default());
    }
}

#[test]
fn exact_quotas_allow_eof_and_empty_members_without_extra_output() {
    let bytes = [member(b"abc"), member(b""), b"\0\0".to_vec()].concat();
    let exact = Limits { source_bytes: Some(51), decoded_bytes: Some(3), members: Some(2), ..Limits::default() };
    assert_eq!(verified(verify(&bytes, PERMISSIVE, exact).unwrap()).source_consumed, 51);

    for (limits, kind, delivered, verified_members) in [
        (Limits { source_bytes: Some(50), ..exact }, Limit::SourceBytes, 3, 2),
        (Limits { decoded_bytes: Some(2), ..exact }, Limit::DecodedBytes, 2, 0),
        (Limits { members: Some(1), ..exact }, Limit::Members, 3, 1),
    ] {
        let mut output = Vec::new();
        let failure =
            gzip::decode(&mut bytes.as_slice(), &mut output, PERMISSIVE, Control { limits, cancelled: None }, |_| {
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Limit(found) if found == kind));
        assert_eq!(failure.progress.sink_accepted, delivered);
        assert_eq!(failure.progress.verified.members, verified_members);
        assert_eq!(output, &b"abc"[..delivered as usize]);
        assert_eq!(failure.progress.codec_produced, if kind == Limit::DecodedBytes { 3 } else { delivered });
    }
}

#[test]
fn encoded_quota_preserves_accepted_prefix_without_flushing() {
    let mut full = Vec::new();
    gzip::encode(&mut &b"abc"[..], &mut full, options(), Control::default()).unwrap();
    let size = full.len() as u64;
    for cap in [0, 1, 9, size - 1, size] {
        let mut output = Sink { data: Vec::new(), end: usize::MAX, error: None, interrupted: 1, attempts: 0, short: 2 };
        let limits = Limits { source_bytes: Some(3), encoded_bytes: Some(cap), ..Limits::default() };
        let result = gzip::encode(&mut &b"abc"[..], &mut output, options(), Control { limits, cancelled: None });
        if cap == size {
            let report = result.unwrap();
            assert_eq!(report.totals.compressed_bytes, size);
            assert_eq!(report.source_consumed, 3);
        } else {
            let failure = result.unwrap_err();
            assert!(matches!(failure.kind, FailureKind::Limit(Limit::EncodedBytes)));
            assert_eq!(failure.progress.sink_accepted, cap);
            assert_eq!(failure.progress.codec_produced, cap + 1);
            assert_eq!(failure.progress.verified.members, 0);
        }
        assert_eq!(output.data, full[..cap as usize]);
    }
    let mut input = &b"abc"[..];
    let limits = Limits { source_bytes: Some(2), ..Limits::default() };
    let failure =
        gzip::encode(&mut input, &mut io::sink(), options(), Control { limits, cancelled: None }).unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Limit(Limit::SourceBytes)));
    assert_eq!(input, b"c");
}

struct Sink {
    data: Vec<u8>,
    end: usize,
    error: Option<io::ErrorKind>,
    interrupted: usize,
    attempts: usize,
    short: usize,
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.attempts += 1;
        if self.interrupted > 0 {
            self.interrupted -= 1;
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.data.len() == self.end {
            return self.error.map_or(Ok(0), |kind| Err(io::Error::new(kind, "sink sentinel")));
        }
        let n = bytes.len().min(self.short).min(self.end - self.data.len());
        self.data.extend_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("unexpected writer flush")
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: &'a Cell<usize>,
    fill_calls: &'a Cell<usize>,
    max: usize,
    fault: Option<(usize, io::ErrorKind)>,
    transient: bool,
}

impl Read for Reader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let data = self.fill_buf()?;
        let n = bytes.len().min(data.len());
        bytes[..n].copy_from_slice(&data[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Reader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.fill_calls.set(self.fill_calls.get() + 1);
        let offset = self.offset.get();
        let mut end = self.bytes.len().min(offset + self.max);
        if let Some((position, kind)) = self.fault {
            if position == offset {
                if self.transient {
                    self.fault = None;
                }
                return Err(io::Error::new(kind, "source sentinel"));
            }
            end = end.min(position);
        }
        Ok(&self.bytes[offset..end])
    }

    fn consume(&mut self, n: usize) {
        self.offset.set(self.offset.get() + n);
    }
}

#[test]
fn source_failures_keep_the_original_error_at_header_body_and_trailer() {
    let bytes = member(b"abcde");
    for (position, phase, kind) in [
        (4, Phase::Header, io::ErrorKind::WouldBlock),
        (16, Phase::DecodeMember, io::ErrorKind::BrokenPipe),
        (23, Phase::DecodeMember, io::ErrorKind::PermissionDenied),
    ] {
        let mut reader = Reader {
            bytes: &bytes,
            offset: &Cell::new(0),
            fill_calls: &Cell::new(0),
            max: 1,
            fault: Some((position, kind)),
            transient: false,
        };
        let failure = gzip::decode(&mut reader, &mut io::sink(), STRICT, Control::default(), |_| Ok(())).unwrap_err();
        assert_eq!(failure.phase, phase);
        assert!(
            matches!(failure.kind, FailureKind::Source(error) if error.kind() == kind && error.to_string() == "source sentinel")
        );
        assert_eq!(failure.progress.source_consumed, position as u64);
        assert_eq!(failure.progress.verified.members, 0);
    }
}

#[test]
fn interruptions_resume_header_body_and_trailer_without_losing_bytes() {
    let bytes = member(b"abcde");
    for position in [0, 4, 16, 23] {
        let mut reader = Reader {
            bytes: &bytes,
            offset: &Cell::new(0),
            fill_calls: &Cell::new(0),
            max: 1,
            fault: Some((position, io::ErrorKind::Interrupted)),
            transient: true,
        };
        let mut output = Vec::new();
        gzip::decode(&mut reader, &mut output, STRICT, Control::default(), |_| Ok(())).unwrap();
        assert_eq!(output, b"abcde");
    }

    let mut reader = Reader {
        bytes: b"abcde",
        offset: &Cell::new(0),
        fill_calls: &Cell::new(0),
        max: 1,
        fault: Some((0, io::ErrorKind::Interrupted)),
        transient: true,
    };
    let mut bytes = Vec::new();
    gzip::encode(&mut reader, &mut bytes, options(), Control::default()).unwrap();
    let mut decoded = Vec::new();
    gzip::decode(&mut bytes.as_slice(), &mut decoded, STRICT, Control::default(), |_| Ok(())).unwrap();
    assert_eq!(decoded, b"abcde");
}

#[test]
fn sink_short_writes_are_counted_before_terminal_errors() {
    for kind in [None, Some(io::ErrorKind::BrokenPipe)] {
        let bytes = member(b"abcdefghi");
        let mut output = Sink { data: Vec::new(), end: 4, error: kind, interrupted: 1, attempts: 0, short: 2 };
        let failure =
            gzip::decode(&mut bytes.as_slice(), &mut output, STRICT, Control::default(), |_| Ok(())).unwrap_err();
        assert!(
            matches!(failure.kind, FailureKind::Sink(error) if error.kind() == kind.unwrap_or(io::ErrorKind::WriteZero))
        );
        assert_eq!(failure.phase, Phase::Sink);
        assert_eq!(failure.progress.codec_produced, 9);
        assert_eq!(failure.progress.sink_accepted, 4);
        assert_eq!(failure.progress.verified.members, 0);
        assert_eq!(output.data, b"abcd");
        assert_eq!(output.attempts, 4);
    }

    let mut encoded = Vec::new();
    gzip::encode(&mut &b"abcdefghi"[..], &mut encoded, options(), Control::default()).unwrap();
    for end in [4, 11, encoded.len() - 3] {
        let mut output = Sink {
            data: Vec::new(),
            end,
            error: Some(io::ErrorKind::BrokenPipe),
            interrupted: 0,
            attempts: 0,
            short: 1,
        };
        let failure = gzip::encode(&mut &b"abcdefghi"[..], &mut output, options(), Control::default()).unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Sink(error) if error.to_string() == "sink sentinel"));
        assert_eq!(failure.progress.sink_accepted, end as u64);
        assert_eq!(failure.progress.verified.members, 0);
        assert_eq!(output.data, encoded[..end]);
        assert_eq!(output.attempts, end + 1);
    }
}

#[test]
fn permanently_interrupted_io_is_bounded_by_attempt_budget() {
    let limits = Limits { attempts: 8, ..Limits::default() };
    let control = Control { limits, cancelled: None };
    for position in [0, 4, 16, 23] {
        let bytes = member(b"abcde");
        let mut reader = Reader {
            bytes: &bytes,
            offset: &Cell::new(0),
            fill_calls: &Cell::new(0),
            max: 4096,
            fault: Some((position, io::ErrorKind::Interrupted)),
            transient: false,
        };
        let failure = gzip::decode(&mut reader, &mut io::sink(), STRICT, control, |_| Ok(())).unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Limit(Limit::Attempts)));
        assert!(reader.fill_calls.get() <= 8);
    }
    let mut output =
        Sink { data: Vec::new(), end: usize::MAX, error: None, interrupted: usize::MAX, attempts: 0, short: 2 };
    let failure = gzip::encode(&mut &b"abc"[..], &mut output, options(), control).unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Limit(Limit::Attempts)));
    assert_eq!(failure.progress.sink_accepted, 0);
    assert_eq!(output.attempts, 6);
}

#[test]
fn callback_error_stops_at_the_matching_verification_boundary() {
    let bytes = member(b"payload");
    for stop_after_verification in [false, true] {
        let mut output = Vec::new();
        let mut input = bytes.as_slice();
        let failure = gzip::decode(&mut input, &mut output, STRICT, Control::default(), |event| {
            if matches!(event, MemberEvent::Verified { .. }) == stop_after_verification {
                Err(io::Error::other("callback sentinel"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Callback(error) if error.to_string() == "callback sentinel"));
        assert_eq!(failure.progress.verified.members, u64::from(stop_after_verification));
        if stop_after_verification {
            assert_eq!(output, b"payload");
            assert!(input.is_empty());
        } else {
            assert!(output.is_empty());
            assert_eq!(input, &bytes[10..]);
        }
    }
}

#[test]
fn cancellation_covers_metadata_trailer_tail_and_empty_member_chains() {
    let mut bytes = member(b"");
    bytes[3] = 8;
    bytes.splice(10..10, b"metadata\0".iter().copied());
    let second_start = bytes.len();
    bytes.extend([0; 50]);
    for (position, phase, members) in
        [(14, Phase::Header, 0), (second_start - 4, Phase::DecodeMember, 0), (second_start + 3, Phase::Tail, 1)]
    {
        let offset = Cell::new(0);
        let mut input =
            Reader { bytes: &bytes, offset: &offset, fill_calls: &Cell::new(0), max: 1, fault: None, transient: false };
        let cancelled = || offset.get() >= position;
        let failure = gzip::decode(
            &mut input,
            &mut io::sink(),
            PERMISSIVE,
            Control { cancelled: Some(&cancelled), ..Control::default() },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Cancelled));
        assert_eq!(failure.phase, phase);
        assert_eq!(failure.progress.verified.members, members);
        assert_eq!(offset.get(), position);
    }

    let empty = member(b"");
    let chain = empty.repeat(10);
    let limits = Limits { members: Some(3), ..Limits::default() };
    let failure = verify(&chain, STRICT, limits).unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Limit(Limit::Members)));
    assert_eq!(failure.progress.verified.members, 3);
    assert_eq!(failure.progress.source_consumed, 71);
    let stop = Cell::new(false);
    let cancelled = || stop.get();
    let failure = gzip::decode(
        &mut chain.as_slice(),
        &mut io::sink(),
        STRICT,
        Control { cancelled: Some(&cancelled), ..Control::default() },
        |event| {
            if matches!(event, MemberEvent::Verified { .. }) {
                stop.set(true);
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Cancelled));
    assert_eq!(failure.progress.verified.members, 1);
    assert_eq!(failure.progress.source_consumed, 23);
}

#[test]
fn cancellation_is_observed_after_final_source_probe_and_sink_write() {
    let flag = Cell::new(false);
    let bytes = member(b"abcdef");
    let calls = Cell::new(0);

    struct CancelAtEof<'a> {
        bytes: &'a [u8],
        flag: &'a Cell<bool>,
    }

    impl BufRead for CancelAtEof<'_> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.bytes.is_empty() {
                self.flag.set(true);
            }
            Ok(self.bytes)
        }

        fn consume(&mut self, n: usize) {
            self.bytes = &self.bytes[n..];
        }
    }

    impl Read for CancelAtEof<'_> {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("engine should use the caller's buffered interface")
        }
    }

    let cancelled = || flag.get();
    let control = Control { cancelled: Some(&cancelled), ..Control::default() };
    let mut input = CancelAtEof { bytes: &bytes, flag: &flag };
    let failure = gzip::decode(&mut input, &mut io::sink(), STRICT, control, |event| {
        if matches!(event, MemberEvent::Verified { .. }) {
            calls.set(calls.get() + 1);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Cancelled));
    assert_eq!(failure.progress.verified.members, 1);
    assert_eq!(calls.get(), 1);

    flag.set(false);
    struct CancelAtEnd<'a> {
        remaining: usize,
        flag: &'a Cell<bool>,
    }

    impl Write for CancelAtEnd<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.remaining -= bytes.len();
            if self.remaining == 0 {
                self.flag.set(true);
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("unexpected flush")
        }
    }

    let length = gzip::encode(&mut &b"abcdef"[..], &mut io::sink(), options(), Control::default())
        .unwrap()
        .totals
        .compressed_bytes;
    let mut output = CancelAtEnd { remaining: length as usize, flag: &flag };
    let failure = gzip::encode(&mut &b"abcdef"[..], &mut output, options(), control).unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Cancelled));
    assert_eq!(failure.progress.sink_accepted, length);
    assert_eq!(failure.progress.verified.members, 0);
}

#[test]
fn source_quota_at_detection_does_not_consume_beyond_the_cap() {
    let mut reader = BufReader::with_capacity(64, &b"\x1fxremainder"[..]);
    let limits = Limits { source_bytes: Some(1), ..Limits::default() };
    let failure = gzip::decode(&mut reader, &mut io::sink(), STRICT, Control { limits, cancelled: None }, |_| {
        panic!("unexpected member")
    })
    .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Limit(Limit::SourceBytes)));
    assert_eq!(failure.phase, Phase::Detect);
    assert_eq!(failure.progress.source_consumed, 1);
    assert_eq!(reader.buffer(), b"xremainder");
}

fn reference() -> std::path::PathBuf {
    std::env::var_os("ZIPFAST_GNU_GZIP").expect("ZIPFAST_GNU_GZIP must point to the pinned reference").into()
}

#[test]
#[ignore = "requires the pinned GNU gzip reference in ZIPFAST_GNU_GZIP"]
fn pinned_gnu_gzip_interoperates_in_both_directions() {
    use std::fs::{self, File};
    use std::process::Command;
    use std::time::{Duration, UNIX_EPOCH};

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("payload.dat");
    let payload = b"zipfast gzip interoperability\n\0\xff".repeat(4096);
    fs::write(&path, &payload).unwrap();
    let mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_123);
    File::options().write(true).open(&path).unwrap().set_times(fs::FileTimes::new().set_modified(mtime)).unwrap();

    let gnu = reference();
    let packed = Command::new(&gnu).arg("-Nc").arg(&path).output().unwrap();
    assert!(packed.status.success());
    let mut decoded = Vec::new();
    let report = verified(
        gzip::decode(&mut packed.stdout.as_slice(), &mut decoded, STRICT, Control::default(), |event| {
            if let MemberEvent::Header(header) = event {
                assert_eq!(header.metadata.filename, Some(&b"payload.dat"[..]));
                assert_eq!(header.metadata.comment, None);
                assert_eq!(header.metadata.mtime, 1_700_000_123);
                assert_eq!(header.metadata.os, 3);
                assert_eq!(header.header_bytes, 22);
            }
            Ok(())
        })
        .unwrap(),
    );
    assert_eq!(report.totals.decoded_bytes, payload.len() as u64);
    assert_eq!(report.totals.compressed_bytes, packed.stdout.len() as u64);
    assert_eq!(decoded, payload);

    let archive = directory.path().join("zipfast.gz");
    let mut output = File::create(&archive).unwrap();
    let metadata = Metadata { mtime: 1_700_000_123, os: 3, filename: Some(b"payload.dat"), ..Metadata::default() };
    let report =
        gzip::encode(&mut payload.as_slice(), &mut output, EncodeOptions { level: 6, metadata }, Control::default())
            .unwrap();
    drop(output);
    let header = fs::read(&archive).unwrap();
    assert_eq!(&header[..10], &[0x1f, 0x8b, 8, 8, 0x7b, 0xf1, 0x53, 0x65, 0, 3]);
    assert_eq!(&header[10..22], b"payload.dat\0");
    assert_eq!(report.totals.framing_bytes, 30);
    let tested = Command::new(&gnu).arg("-t").arg(&archive).status().unwrap();
    assert!(tested.success());
    let unpacked = Command::new(&gnu).arg("-dc").arg(&archive).output().unwrap();
    assert!(unpacked.status.success());
    assert_eq!(unpacked.stdout, payload);
}

#[test]
#[ignore = "streams over 16 GiB and requires the pinned GNU gzip reference in ZIPFAST_GNU_GZIP"]
fn streamed_large_members_keep_u64_totals_across_isize_wrap() {
    use std::fs::File;
    use std::io::{Seek, SeekFrom};
    use std::process::{Command, Stdio};

    const SIZE: u64 = (1 << 32) + 123;
    let gnu = reference();
    for member_sizes in [&[SIZE][..], &[(1 << 32) - 4096, 4219]] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large.gz");
        let mut output = File::create(&path).unwrap();
        let mut boundaries = Vec::new();
        let mut compressed = 0;
        for &size in member_sizes {
            let mut input = BufReader::with_capacity(64 * 1024, io::repeat(0).take(size));
            let report = gzip::encode(&mut input, &mut output, options(), Control::default()).unwrap();
            assert_eq!(report.source_consumed, size);
            assert_eq!(report.totals.decoded_bytes, size);
            compressed += report.totals.compressed_bytes;
            boundaries.push(compressed);
        }
        drop(output);

        let mut wire = File::open(&path).unwrap();
        assert_eq!(wire.metadata().unwrap().len(), compressed);
        for (&end, &size) in boundaries.iter().zip(member_sizes) {
            wire.seek(SeekFrom::Start(end - 4)).unwrap();
            let mut raw = [0; 4];
            wire.read_exact(&mut raw).unwrap();
            assert_eq!(u32::from_le_bytes(raw), size as u32);
        }
        wire.rewind().unwrap();
        let mut input = BufReader::new(wire);
        let mut zero_sink = ZeroSink::default();
        let report = verified(
            gzip::decode(&mut input, &mut zero_sink, STRICT, Control::default(), |event| {
                if let MemberEvent::Verified { header, decoded_bytes, .. } = event {
                    assert_eq!(decoded_bytes, member_sizes[header.index as usize]);
                }
                Ok(())
            })
            .unwrap(),
        );
        assert_eq!(report.source_consumed, compressed);
        assert_eq!(report.totals.decoded_bytes, SIZE);
        assert_eq!(report.totals.members, member_sizes.len() as u64);
        assert_eq!(zero_sink.0, SIZE);

        let mut child = Command::new(&gnu).arg("-dc").arg(&path).stdout(Stdio::piped()).spawn().unwrap();
        let mut unpacked = child.stdout.take().unwrap();
        let mut zero_sink = ZeroSink::default();
        assert_eq!(io::copy(&mut unpacked, &mut zero_sink).unwrap(), SIZE);
        assert!(child.wait().unwrap().success());
        assert_eq!(zero_sink.0, SIZE);
        eprintln!("verified {SIZE} decoded bytes in {} member(s), {compressed} packed bytes", member_sizes.len());
    }
}

#[derive(Default)]
struct ZeroSink(u64);

impl Write for ZeroSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.iter().all(|&byte| byte == 0));
        self.0 = self.0.checked_add(bytes.len() as u64).unwrap();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("unexpected flush")
    }
}

#[test]
fn empty_metadata_fields_remain_present() {
    let metadata = Metadata { filename: Some(b""), comment: Some(b""), extra: Some(b""), ..Metadata::default() };
    let mut encoded = Vec::new();
    gzip::encode(&mut &b"payload"[..], &mut encoded, EncodeOptions { level: 9, metadata }, Control::default()).unwrap();
    assert_eq!(encoded[3], 0x1c);
    assert_eq!(&encoded[10..14], &[0; 4]);
    let mut events = 0;
    gzip::decode(&mut encoded.as_slice(), &mut io::sink(), STRICT, Control::default(), |event| {
        let header = match event {
            MemberEvent::Header(header) | MemberEvent::Verified { header, .. } => header,
        };
        assert_eq!(header.metadata, metadata);
        assert_eq!(header.header_bytes, 14);
        events += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(events, 2);
}

#[test]
fn source_limits_stop_at_the_exact_logical_offset_in_header_body_and_trailer() {
    let bytes = member(b"abcdefghi");
    for (position, phase) in [(4, Phase::Header), (17, Phase::DecodeMember), (27, Phase::DecodeMember)] {
        let mut input = BufReader::with_capacity(128, bytes.as_slice());
        let limits = Limits { source_bytes: Some(position), ..Limits::default() };
        let failure =
            gzip::decode(&mut input, &mut io::sink(), STRICT, Control { limits, cancelled: None }, |_| Ok(()))
                .unwrap_err();
        assert!(matches!(failure.kind, FailureKind::Limit(Limit::SourceBytes)));
        assert_eq!(failure.phase, phase);
        assert_eq!(failure.progress.source_consumed, position);
        assert_eq!(failure.progress.verified.members, 0);
        assert_eq!(input.buffer(), &bytes[position as usize..]);
        assert!(input.get_ref().is_empty());
    }
}

#[test]
fn retry_checks_cancellation_before_retrying_a_source_or_sink() {
    let calls = Cell::new(0);
    let mut reader = Reader {
        bytes: b"abcdef",
        offset: &Cell::new(0),
        fill_calls: &calls,
        max: 4096,
        fault: Some((0, io::ErrorKind::Interrupted)),
        transient: false,
    };
    let cancelled = || calls.get() > 0;
    let failure = gzip::decode(
        &mut reader,
        &mut io::sink(),
        STRICT,
        Control { cancelled: Some(&cancelled), ..Control::default() },
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Cancelled));
    assert_eq!(failure.progress, Progress::default());
    assert_eq!(calls.get(), 1);

    struct InterruptAndCancel<'a>(&'a Cell<bool>);
    impl Write for InterruptAndCancel<'_> {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            assert!(!self.0.replace(true));
            Err(io::ErrorKind::Interrupted.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("unexpected flush")
        }
    }
    let stop = Cell::new(false);
    let cancelled = || stop.get();
    let failure = gzip::encode(
        &mut &b"abcdef"[..],
        &mut InterruptAndCancel(&stop),
        options(),
        Control { cancelled: Some(&cancelled), ..Control::default() },
    )
    .unwrap_err();
    assert!(matches!(failure.kind, FailureKind::Cancelled));
    assert_eq!(failure.phase, Phase::Sink);
    assert_eq!(failure.progress.codec_produced, 10);
    assert_eq!(failure.progress.sink_accepted, 0);
}
