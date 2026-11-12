// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5

//! Bounded gzip member encoding and verification over caller-owned buffered I/O.

use std::cell::Cell;
use std::fmt;
use std::io::{self, BufRead, Read, Write};

use flate2::bufread::GzDecoder;
use flate2::{Compression, GzBuilder, GzHeader};

const MAGIC: [u8; 2] = [0x1f, 0x8b];
const FIELD_MAX: usize = u16::MAX as usize;
const CHUNK: usize = 64 * 1024;
const TRAILER: usize = 8;

/// Default combined budget for codec calls, source fills, and sink writes.
pub const DEFAULT_ATTEMPTS: u64 = 1 << 30;

/// Wire metadata. The byte slices preserve absent and present-empty fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata<'a> {
    /// Modification time in seconds since the Unix epoch. Zero means unknown.
    pub mtime: u32,
    /// RFC 1952 operating-system code. Use 255 for unknown.
    pub os: u8,
    pub filename: Option<&'a [u8]>,
    pub comment: Option<&'a [u8]>,
    pub extra: Option<&'a [u8]>,
}

impl Default for Metadata<'_> {
    fn default() -> Self {
        Self { mtime: 0, os: 255, filename: None, comment: None, extra: None }
    }
}

impl<'a> Metadata<'a> {
    fn from_header(header: &'a GzHeader) -> Self {
        Self {
            mtime: header.mtime(),
            os: header.operating_system(),
            filename: header.filename(),
            comment: header.comment(),
            extra: header.extra(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EncodeOptions<'a> {
    /// Compression level from 0 through 9, inclusive.
    pub level: u32,
    pub metadata: Metadata<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct DecodeOptions {
    pub tail: TailPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailPolicy {
    /// Reject any nonempty remainder other than another gzip member.
    Strict,
    /// Consume and describe terminal zero padding and garbage.
    TerminalPaddingAndGarbage,
}

/// Optional logical byte/member limits and a finite combined attempt budget.
/// The decoded limit applies to decoding and the encoded limit applies to encoding.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub source_bytes: Option<u64>,
    pub decoded_bytes: Option<u64>,
    pub encoded_bytes: Option<u64>,
    pub members: Option<u64>,
    pub attempts: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { source_bytes: None, decoded_bytes: None, encoded_bytes: None, members: None, attempts: DEFAULT_ATTEMPTS }
    }
}

#[derive(Clone, Copy, Default)]
pub struct Control<'a> {
    pub limits: Limits,
    /// Called at I/O, codec, callback, and completion boundaries.
    pub cancelled: Option<&'a dyn Fn() -> bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    Clean,
    Zeros { bytes: u64 },
    Garbage { bytes: u64, leading_zeros: u64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub compressed_bytes: u64,
    pub decoded_bytes: u64,
    pub members: u64,
    pub framing_bytes: u64,
}

/// Logical progress at the point of failure. Produced bytes include an
/// unpublished one-byte output-quota probe. Verified totals cover complete
/// members only, including on failure in a verified-member callback.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub source_consumed: u64,
    pub codec_produced: u64,
    pub sink_accepted: u64,
    pub verified: Totals,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodeReport {
    pub totals: Totals,
    pub source_consumed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeReport {
    pub totals: Totals,
    pub source_consumed: u64,
    pub tail: Tail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeOutcome {
    Verified(DecodeReport),
    /// Replay the first `prefix_len` bytes before reading the same input again.
    NotGzip {
        prefix: [u8; 2],
        prefix_len: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberHeader<'a> {
    pub index: u64,
    pub compressed_offset: u64,
    pub header_bytes: u64,
    pub metadata: Metadata<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberEvent<'a> {
    /// The header is valid, including FHCRC when present. Body verification is pending.
    Header(MemberHeader<'a>),
    /// This member's trailer is valid and all its output was accepted by the sink.
    Verified { header: MemberHeader<'a>, compressed_bytes: u64, decoded_bytes: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Options,
    Detect,
    Header,
    DecodeMember,
    Tail,
    Encode,
    Sink,
    Callback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    SourceBytes,
    DecodedBytes,
    EncodedBytes,
    Members,
    Attempts,
}

#[derive(Debug)]
pub enum FailureKind {
    InvalidOptions(&'static str),
    Source(io::Error),
    Sink(io::Error),
    Callback(io::Error),
    /// Invalid gzip framing, compressed data, or integrity check.
    Format(io::Error),
    /// A backend error while encoding.
    Codec(io::Error),
    TrailingData,
    Limit(Limit),
    Cancelled,
    CounterOverflow,
}

impl fmt::Display for FailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOptions(reason) => write!(f, "invalid gzip options: {reason}"),
            Self::Source(error) => write!(f, "gzip source: {error}"),
            Self::Sink(error) => write!(f, "gzip sink: {error}"),
            Self::Callback(error) => write!(f, "gzip callback: {error}"),
            Self::Format(error) => write!(f, "invalid gzip stream: {error}"),
            Self::Codec(error) => write!(f, "gzip codec: {error}"),
            Self::TrailingData => f.write_str("unexpected trailing data after gzip member"),
            Self::Limit(limit) => write!(f, "gzip limit reached: {limit:?}"),
            Self::Cancelled => f.write_str("gzip operation cancelled"),
            Self::CounterOverflow => f.write_str("gzip byte or member count overflowed"),
        }
    }
}

#[derive(Debug)]
pub struct Failure {
    pub kind: FailureKind,
    pub phase: Phase,
    pub progress: Progress,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.kind, self.phase)
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            FailureKind::Source(error)
            | FailureKind::Sink(error)
            | FailureKind::Callback(error)
            | FailureKind::Format(error)
            | FailureKind::Codec(error) => Some(error),
            _ => None,
        }
    }
}

struct Run<'a> {
    control: Control<'a>,
    progress: Cell<Progress>,
    attempts_left: Cell<u64>,
}

impl<'a> Run<'a> {
    fn new(control: Control<'a>) -> Self {
        Self { control, progress: Cell::default(), attempts_left: Cell::new(control.limits.attempts) }
    }

    fn failure(&self, phase: Phase, kind: FailureKind) -> Failure {
        Failure { kind, phase, progress: self.progress.get() }
    }

    fn check(&self, phase: Phase) -> Result<(), Failure> {
        if self.control.cancelled.is_some_and(|cancelled| cancelled()) {
            return Err(self.failure(phase, FailureKind::Cancelled));
        }
        Ok(())
    }

    fn attempt(&self, phase: Phase) -> Result<(), Failure> {
        self.check(phase)?;
        let Some(left) = self.attempts_left.get().checked_sub(1) else {
            return Err(self.failure(phase, FailureKind::Limit(Limit::Attempts)));
        };
        self.attempts_left.set(left);
        Ok(())
    }

    fn add(&self, phase: Phase, value: u64, increment: u64) -> Result<u64, Failure> {
        value.checked_add(increment).ok_or_else(|| self.failure(phase, FailureKind::CounterOverflow))
    }

    fn member_slot(&self, phase: Phase) -> Result<(), Failure> {
        let members = self.progress.get().verified.members;
        if self.control.limits.members.is_some_and(|limit| members == limit) {
            return Err(self.failure(phase, FailureKind::Limit(Limit::Members)));
        }
        self.add(phase, members, 1)?;
        Ok(())
    }

    fn verified(&self, phase: Phase, compressed: u64, decoded: u64, framing: u64) -> Result<(), Failure> {
        let mut progress = self.progress.get();
        let prior = progress.verified;
        progress.verified = Totals {
            compressed_bytes: self.add(phase, prior.compressed_bytes, compressed)?,
            decoded_bytes: self.add(phase, prior.decoded_bytes, decoded)?,
            members: self.add(phase, prior.members, 1)?,
            framing_bytes: self.add(phase, prior.framing_bytes, framing)?,
        };
        self.progress.set(progress);
        Ok(())
    }

    fn write(&self, output: &mut impl Write, mut bytes: &[u8]) -> Result<(), Failure> {
        while !bytes.is_empty() {
            self.attempt(Phase::Sink)?;
            match output.write(bytes) {
                Ok(0) => {
                    return Err(self.failure(Phase::Sink, FailureKind::Sink(io::ErrorKind::WriteZero.into())));
                }
                Ok(n) if n <= bytes.len() => {
                    let mut progress = self.progress.get();
                    progress.sink_accepted = self.add(Phase::Sink, progress.sink_accepted, n as u64)?;
                    self.progress.set(progress);
                    bytes = &bytes[n..];
                }
                Ok(_) => {
                    let error = io::Error::new(io::ErrorKind::InvalidData, "writer returned an invalid length");
                    return Err(self.failure(Phase::Sink, FailureKind::Sink(error)));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.failure(Phase::Sink, FailureKind::Sink(error))),
            }
        }
        Ok(())
    }

    fn event(
        &self,
        callback: &mut impl FnMut(MemberEvent<'_>) -> io::Result<()>,
        event: MemberEvent<'_>,
    ) -> Result<(), Failure> {
        self.check(Phase::Callback)?;
        callback(event).map_err(|error| self.failure(Phase::Callback, FailureKind::Callback(error)))?;
        self.check(Phase::Callback)
    }
}

struct Source<'a, 'c, R> {
    input: &'a mut R,
    run: &'a Run<'c>,
    phase: Phase,
    prefix: &'a [u8],
    offered: usize,
    failure: Option<Failure>,
}

impl<'a, 'c, R: BufRead> Source<'a, 'c, R> {
    fn new(input: &'a mut R, run: &'a Run<'c>, phase: Phase) -> Self {
        Self { input, run, phase, prefix: &[], offered: 0, failure: None }
    }

    fn error(&mut self, error: io::Error) -> Failure {
        self.failure.take().unwrap_or_else(|| {
            let kind = match self.phase {
                Phase::Encode => FailureKind::Codec(error),
                _ => FailureKind::Format(error),
            };
            self.run.failure(self.phase, kind)
        })
    }

    fn consumed(&self) -> u64 {
        self.run.progress.get().source_consumed
    }

    fn read_retry(&mut self, bytes: &mut [u8]) -> Result<usize, Failure> {
        loop {
            match self.read(bytes) {
                Ok(n) => return Ok(n),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(self.error(error)),
            }
        }
    }
}

fn latch(slot: &mut Option<Failure>, failure: Failure) -> io::Error {
    *slot = Some(failure);
    // In particular, a terminal source WouldBlock must not put flate2's
    // constructor in its resumable-header state.
    io::ErrorKind::Other.into()
}

impl<R: BufRead> BufRead for Source<'_, '_, R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if let Err(failure) = self.run.attempt(self.phase) {
            return Err(latch(&mut self.failure, failure));
        }
        if !self.prefix.is_empty() {
            self.offered = self.prefix.len();
            return Ok(self.prefix);
        }

        let consumed = self.consumed();
        let limit = self.run.control.limits.source_bytes;
        let remaining = limit.unwrap_or(u64::MAX) - consumed;
        let bytes = match self.input.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => return Err(error),
            Err(error) => {
                return Err(latch(&mut self.failure, self.run.failure(self.phase, FailureKind::Source(error))));
            }
        };
        if remaining == 0 && !bytes.is_empty() {
            let kind =
                if limit.is_some() { FailureKind::Limit(Limit::SourceBytes) } else { FailureKind::CounterOverflow };
            return Err(latch(&mut self.failure, self.run.failure(self.phase, kind)));
        }

        self.offered = bytes.len().min(remaining.min(CHUNK as u64) as usize);
        Ok(&bytes[..self.offered])
    }

    fn consume(&mut self, n: usize) {
        assert!(n <= self.offered, "codec consumed bytes outside the offered input");
        self.offered -= n;
        if !self.prefix.is_empty() {
            self.prefix = &self.prefix[n..];
            return;
        }
        let mut progress = self.run.progress.get();
        // The last fill bounded the offered bytes to the remaining u64 capacity.
        progress.source_consumed = progress.source_consumed.checked_add(n as u64).unwrap();
        self.input.consume(n);
        self.run.progress.set(progress);
    }
}

impl<R: BufRead> Read for Source<'_, '_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let offered = self.fill_buf()?;
        let n = bytes.len().min(offered.len());
        bytes[..n].copy_from_slice(&offered[..n]);
        self.consume(n);
        Ok(n)
    }
}

fn pump(
    run: &Run<'_>,
    output: &mut impl Write,
    phase: Phase,
    quota: (Option<u64>, Limit),
    bytes: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<Option<usize>, Failure>,
) -> Result<(), Failure> {
    loop {
        let progress = run.progress.get();
        let remaining = quota.0.unwrap_or(u64::MAX) - progress.sink_accepted;
        let length = bytes.len().min(remaining.max(1).min(CHUNK as u64) as usize);
        run.attempt(phase)?;
        let Some(n) = read(&mut bytes[..length])? else {
            continue; // Interrupted, with the same quota and another charged attempt.
        };
        if n == 0 {
            return run.check(phase);
        }
        let mut progress = run.progress.get();
        progress.codec_produced = run.add(phase, progress.codec_produced, n as u64)?;
        run.progress.set(progress);
        if n as u64 > remaining {
            return Err(run.failure(phase, FailureKind::Limit(quota.1)));
        }
        run.write(output, &bytes[..n])?;
    }
}

fn codec_read<R: BufRead>(result: io::Result<usize>, source: &mut Source<'_, '_, R>) -> Result<Option<usize>, Failure> {
    match result {
        Ok(n) => Ok(Some(n)),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
        Err(error) => Err(source.error(error)),
    }
}

/// Encode one gzip member. The writer is left open and is never flushed.
pub fn encode<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    options: EncodeOptions<'_>,
    control: Control<'_>,
) -> Result<EncodeReport, Failure> {
    let run = Run::new(control);
    let invalid = |reason| run.failure(Phase::Options, FailureKind::InvalidOptions(reason));
    if options.level > 9 {
        return Err(invalid("compression level must be 0 through 9"));
    }
    let metadata = options.metadata;
    for field in [metadata.extra, metadata.filename, metadata.comment].into_iter().flatten() {
        if field.len() > FIELD_MAX {
            return Err(invalid("metadata field exceeds 65,535 bytes"));
        }
    }
    for field in [metadata.filename, metadata.comment].into_iter().flatten() {
        if field.contains(&0) {
            return Err(invalid("filename and comment must not contain NUL"));
        }
    }

    run.check(Phase::Options)?;
    run.member_slot(Phase::Options)?;
    run.attempt(Phase::Header)?;
    let mut header_left = 10;
    let mut builder = GzBuilder::new().mtime(metadata.mtime).operating_system(metadata.os);
    if let Some(extra) = metadata.extra {
        header_left += extra.len() + 2;
        builder = builder.extra(extra);
    }
    if let Some(name) = metadata.filename {
        header_left += name.len() + 1;
        builder = builder.filename(name);
    }
    if let Some(comment) = metadata.comment {
        header_left += comment.len() + 1;
        builder = builder.comment(comment);
    }
    let framing = (header_left + TRAILER) as u64;
    let source = Source::new(input, &run, Phase::Encode);
    let mut encoder = builder.buf_read(source, Compression::new(options.level));
    let quota = (control.limits.encoded_bytes, Limit::EncodedBytes);
    pump(&run, output, Phase::Encode, quota, &mut [0; CHUNK], |bytes| {
        // Keep header reads separate. If the backend reaches the source in a
        // read that also copied header bytes, a source error discards that count.
        let len = if header_left > 0 { bytes.len().min(header_left) } else { bytes.len() };
        let result = encoder.read(&mut bytes[..len]);
        let n = codec_read(result, encoder.get_mut())?;
        if header_left > 0 {
            header_left -= n.unwrap_or(0);
        }
        Ok(n)
    })?;

    let progress = run.progress.get();
    run.verified(Phase::Encode, progress.sink_accepted, progress.source_consumed, framing)?;
    let progress = run.progress.get();
    Ok(EncodeReport { totals: progress.verified, source_consumed: progress.source_consumed })
}

/// Verify and decode concatenated gzip members. Pass `io::sink()` to use the
/// same scanner for testing or listing. The writer is never flushed.
pub fn decode<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    options: DecodeOptions,
    control: Control<'_>,
    mut event: impl FnMut(MemberEvent<'_>) -> io::Result<()>,
) -> Result<DecodeOutcome, Failure> {
    let run = Run::new(control);
    let mut work = [0; CHUNK];
    let tail = loop {
        let mut source = Source::new(input, &run, Phase::Detect);
        let start = source.consumed();
        let index = run.progress.get().verified.members;
        let mut prefix = [0; 2];
        let mut n = source.read_retry(&mut prefix[..1])?;
        if n == 1 && prefix[0] == MAGIC[0] {
            n += source.read_retry(&mut prefix[1..])?;
        }
        run.check(Phase::Detect)?;
        if n == 2 && prefix == MAGIC {
            run.member_slot(Phase::Header)?;
            source.prefix = &prefix;
            decode_member(source, output, &mut event, &mut work, index, start)?;
            continue;
        }
        if index == 0 {
            return Ok(DecodeOutcome::NotGzip { prefix, prefix_len: n as u8 });
        }
        if n == 0 {
            break Tail::Clean;
        }
        if n == 1 && prefix[0] == MAGIC[0] {
            let error = io::Error::new(io::ErrorKind::UnexpectedEof, "truncated next gzip member");
            return Err(run.failure(Phase::Tail, FailureKind::Format(error)));
        }
        if options.tail == TailPolicy::Strict {
            return Err(run.failure(Phase::Tail, FailureKind::TrailingData));
        }
        source.phase = Phase::Tail;
        break scan_tail(&mut source, start, &prefix[..n], &mut work)?;
    };

    run.check(Phase::Tail)?;
    let progress = run.progress.get();
    Ok(DecodeOutcome::Verified(DecodeReport {
        totals: progress.verified,
        source_consumed: progress.source_consumed,
        tail,
    }))
}

fn decode_member<R: BufRead>(
    mut source: Source<'_, '_, R>,
    output: &mut impl Write,
    callback: &mut impl FnMut(MemberEvent<'_>) -> io::Result<()>,
    work: &mut [u8],
    index: u64,
    start: u64,
) -> Result<(), Failure> {
    let run = source.run;
    source.phase = Phase::Header;
    run.attempt(Phase::Header)?;
    let mut decoder = GzDecoder::new(source);
    if decoder.header().is_none() {
        let error = decoder.read(&mut work[..1]).expect_err("failed gzip constructor must return an error");
        return Err(decoder.get_mut().error(error));
    }

    let header_bytes = decoder.get_ref().consumed() - start;
    let metadata = Metadata::from_header(decoder.header().unwrap());
    run.event(callback, MemberEvent::Header(MemberHeader { index, compressed_offset: start, header_bytes, metadata }))?;
    decoder.get_mut().phase = Phase::DecodeMember;

    let decoded_start = run.progress.get().sink_accepted;
    let quota = (run.control.limits.decoded_bytes, Limit::DecodedBytes);
    pump(run, output, Phase::DecodeMember, quota, work, |bytes| {
        let result = decoder.read(bytes);
        codec_read(result, decoder.get_mut())
    })?;
    let compressed_bytes = decoder.get_ref().consumed() - start;
    let decoded_bytes = run.progress.get().sink_accepted - decoded_start;
    let framing = run.add(Phase::DecodeMember, header_bytes, TRAILER as u64)?;
    run.verified(Phase::DecodeMember, compressed_bytes, decoded_bytes, framing)?;
    run.event(
        callback,
        MemberEvent::Verified {
            header: MemberHeader {
                index,
                compressed_offset: start,
                header_bytes,
                metadata: Metadata::from_header(decoder.header().unwrap()),
            },
            compressed_bytes,
            decoded_bytes,
        },
    )
}

fn scan_tail<R: BufRead>(
    source: &mut Source<'_, '_, R>,
    start: u64,
    prefix: &[u8],
    work: &mut [u8],
) -> Result<Tail, Failure> {
    let mut leading_zeros = prefix.iter().take_while(|&&byte| byte == 0).count() as u64;
    let mut garbage = leading_zeros != prefix.len() as u64;
    loop {
        let n = source.read_retry(work)?;
        if n == 0 {
            let bytes = source.consumed() - start;
            return Ok(if garbage { Tail::Garbage { bytes, leading_zeros } } else { Tail::Zeros { bytes } });
        }
        if !garbage {
            let zeros = work[..n].iter().take_while(|&&byte| byte == 0).count();
            leading_zeros = source.run.add(Phase::Tail, leading_zeros, zeros as u64)?;
            garbage = zeros < n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_totals_cross_four_gib_and_overflow_keeps_prior_verified_totals() {
        let run = Run::new(Control::default());
        let phase = Phase::DecodeMember;
        run.verified(phase, (1 << 32) - 1, 9, 18).unwrap();
        run.verified(phase, 31, 13, 18).unwrap();
        let totals = run.progress.get().verified;
        assert_eq!(
            totals,
            Totals { compressed_bytes: (1 << 32) + 30, decoded_bytes: 22, members: 2, framing_bytes: 36 }
        );

        for (compressed, decoded, framing) in [
            (u64::MAX - totals.compressed_bytes + 1, 0, 0),
            (0, u64::MAX - totals.decoded_bytes + 1, 0),
            (0, 0, u64::MAX - totals.framing_bytes + 1),
        ] {
            let failure = run.verified(phase, compressed, decoded, framing).unwrap_err();
            assert!(matches!(failure.kind, FailureKind::CounterOverflow));
            assert_eq!(run.progress.get().verified, totals);
            assert_eq!(failure.progress.verified, totals);
        }
    }
}
