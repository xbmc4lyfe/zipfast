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

//! Bounded, serial RAR4 version-29 non-solid LZ decoding.
//! Original implementation from the SDD factual worksheet and independent vectors.
//! No external decoder implementation was copied or translated.

use super::Sink;
use crate::extract::Cancellation;

#[derive(Debug, PartialEq)]
pub(crate) enum Rar4FeedState {
    NeedInput,
    Complete,
}
#[derive(Debug, PartialEq)]
pub(crate) enum Rar4UnsupportedMode {
    Ppm,
    VmFilter,
}
#[derive(Debug)]
pub(crate) enum Rar4DecodeError {
    Unsupported(Rar4UnsupportedMode),
    Malformed(&'static str),
    DecodedSize { expected: u64, actual: u64 },
    PackedSize { expected: u64, actual: u64 },
    InvalidDictionary { requested: u64 },
    WindowLimit { requested: u64, allowed: u64 },
    Allocation { requested: u64 },
    CounterOverflow,
    Canceled,
    Sink(crate::error::Error),
}

const CHUNK: usize = 65536;
const OUTPUT: usize = 32768;

impl Rar4DecodeError {
    pub(crate) fn detailed(self, scope: crate::error::RarScope) -> crate::error::RarFault {
        use crate::error::{
            Error, IoOperation, RarFailure, RarFault, RarIntegrityReason, RarPasswordEvidence, RarResource,
            RarUnsupported,
        };
        let integrity = |reason| RarFailure::integrity(scope.clone(), reason, RarPasswordEvidence::NotEncrypted, false);
        let (failure, legacy) = match self {
            Self::Unsupported(mode) => {
                let label = match mode {
                    Rar4UnsupportedMode::Ppm => "PPM payload",
                    Rar4UnsupportedMode::VmFilter => "VM/filter payload",
                };
                // This optional legacy label is bounded (at most 17 bytes) and
                // allocated only in the consumer adaptation, never core decoding.
                let mut message = String::new();
                let legacy = if message.try_reserve_exact(label.len()).is_ok() {
                    message.push_str(label);
                    Error::Unsupported(message)
                } else {
                    Error::Io(std::io::ErrorKind::OutOfMemory.into())
                };
                (RarFailure::Unsupported(RarUnsupported::Rar4Feature(label)), legacy)
            }
            Self::Malformed(reason) => (integrity(RarIntegrityReason::Decoder(reason)), Error::Corrupt(reason)),
            Self::DecodedSize { expected, actual } => {
                (integrity(RarIntegrityReason::DecodedSize { expected, actual }), Error::Corrupt("RAR4 decoded size"))
            }
            Self::PackedSize { expected, actual } if actual < expected => {
                (integrity(RarIntegrityReason::TruncatedData), Error::Truncated)
            }
            Self::PackedSize { .. } => (
                integrity(RarIntegrityReason::Decoder("RAR4 packed extent exceeded")),
                Error::Corrupt("RAR4 packed extent exceeded"),
            ),
            Self::InvalidDictionary { requested } => {
                (integrity(RarIntegrityReason::InvalidDictionary { requested }), Error::Corrupt("RAR4 dictionary"))
            }
            Self::WindowLimit { requested, allowed } => (
                RarFailure::Limit {
                    resource: RarResource::DictionarySize,
                    requested: Some(requested),
                    allowed: Some(allowed),
                },
                Error::Corrupt("RAR4 dictionary limit"),
            ),
            Self::Allocation { requested } => (
                RarFailure::Limit {
                    resource: RarResource::DictionaryAllocation,
                    requested: Some(requested),
                    allowed: None,
                },
                Error::Corrupt("RAR4 dictionary allocation"),
            ),
            Self::CounterOverflow => (
                RarFailure::Limit { resource: RarResource::Counter, requested: None, allowed: Some(u64::MAX) },
                Error::Corrupt("RAR4 work counter overflow"),
            ),
            Self::Canceled => (RarFailure::Canceled, Error::Io(std::io::Error::from(std::io::ErrorKind::Interrupted))),
            Self::Sink(Error::Io(source)) => return RarFault::output(IoOperation::Write, None, None, source, true),
            Self::Sink(error) => return crate::batch::decoder_failure(error, scope, RarPasswordEvidence::NotEncrypted),
        };
        RarFault::new(failure, legacy)
    }
}

type DecodeResult<T> = Result<T, Rar4DecodeError>;

struct Work {
    operations: u64,
    cancel: Option<Cancellation>,
    #[cfg(test)]
    cancel_at: Option<u64>,
}
impl Work {
    fn check(&self) -> DecodeResult<()> {
        if self.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
            Err(Rar4DecodeError::Canceled)
        } else {
            Ok(())
        }
    }
    fn tick(&mut self, amount: u64) -> DecodeResult<()> {
        let before = self.operations;
        self.operations = self.operations.checked_add(amount).ok_or(Rar4DecodeError::CounterOverflow)?;
        #[cfg(test)]
        if self.cancel_at.is_some_and(|at| self.operations >= at) {
            if let Some(cancel) = &self.cancel {
                cancel.cancel();
            }
            self.cancel_at = None;
        }
        if self.operations / 256 != before / 256 {
            self.check()?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Bits {
    acc: u64,
    count: u8,
}
impl Bits {
    fn take(&mut self, n: u8, input: &mut &[u8]) -> Option<u32> {
        debug_assert!(n <= 18);
        while self.count < n {
            let (&byte, tail) = input.split_first()?;
            *input = tail;
            self.acc = (self.acc << 8) | u64::from(byte);
            self.count += 8;
        }
        self.count -= n;
        let value = (self.acc >> self.count) as u32;
        self.acc &= (1u64 << self.count) - 1;
        Some(value)
    }
    fn align(&mut self) {
        let discard = self.count % 8;
        self.count -= discard;
        self.acc &= (1u64 << self.count) - 1;
    }
}

struct Huff {
    count: [u16; 16],
    first: [u32; 16],
    offset: [usize; 16],
    symbols: [u16; 299],
    used: usize,
}
impl Huff {
    fn empty() -> Self {
        Self { count: [0; 16], first: [0; 16], offset: [0; 16], symbols: [0; 299], used: 0 }
    }
    fn build(&mut self, lengths: &[u8], work: &mut Work) -> DecodeResult<()> {
        self.count = [0; 16];
        self.used = 0;
        for &length in lengths {
            work.tick(1)?;
            if length > 15 {
                return Err(Rar4DecodeError::Malformed("code length"));
            }
            if length != 0 {
                self.count[length as usize] += 1;
                self.used += 1;
            }
        }
        let mut offset = 0;
        let mut code = 0;
        for n in 1..16 {
            work.tick(1)?;
            code = (code + u32::from(self.count[n - 1])) << 1;
            if code + u32::from(self.count[n]) > 1 << n {
                return Err(Rar4DecodeError::Malformed("oversubscribed Huffman table"));
            }
            self.first[n] = code;
            self.offset[n] = offset;
            offset += self.count[n] as usize;
        }
        let mut next = self.offset;
        for (symbol, &length) in lengths.iter().enumerate() {
            work.tick(1)?;
            if length != 0 {
                self.symbols[next[length as usize]] = symbol as u16;
                next[length as usize] += 1;
            }
        }
        work.check()
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Align,
    Mode,
    Retain,
    Bc { index: usize },
    BcRun { index: usize },
    BuildBc,
    Lengths { index: usize },
    LengthRun { index: usize, kind: u16 },
    BuildTables,
    Token,
    End,
    EndHint,
    Length { index: usize, recent: Option<usize> },
    LengthExtra { base: u64, bits: u8, recent: Option<usize> },
    RecentLength { slot: usize },
    Distance { length: u64 },
    DistanceBits { length: u64, index: usize },
    Low { length: u64, base: u64 },
    Short { index: usize },
    Copy { distance: u64, left: u64 },
    Complete,
}

pub(crate) struct Rar4Decoder {
    work: Work,
    dictionary: Vec<u8>,
    packed: u64,
    fed: u64,
    expected: u64,
    produced: u64,
    bits: Bits,
    phase: Phase,
    poisoned: bool,
    finished: bool,
    old: [u8; 404],
    lengths: [u8; 404],
    bc_lengths: [u8; 20],
    tables: [Huff; 5], // BC, LD, DD, LDD, RD
    prefix: u32,
    depth: usize,
    recent: [u64; 4], // zero explicitly means unavailable
    last_length: u64,
    low: u64,
    low_repeats: u8,
    output: [u8; OUTPUT],
    filled: usize,
    table_builds: u64,
}

impl Rar4Decoder {
    pub(crate) fn new(
        dictionary: u64,
        packed: u64,
        unpacked: u64,
        window_limit: u64,
        cancel: Cancellation,
    ) -> DecodeResult<Self> {
        Self::new_with_cancel(dictionary, packed, unpacked, window_limit, Some(cancel))
    }
    pub(crate) fn new_with_cancel(
        dictionary: u64,
        packed: u64,
        unpacked: u64,
        window_limit: u64,
        cancel: Option<Cancellation>,
    ) -> DecodeResult<Self> {
        let mut work = Work {
            operations: 0,
            cancel,
            #[cfg(test)]
            cancel_at: tests::take_init_cancel(),
        };
        work.check()?;
        if !(65536..=4194304).contains(&dictionary) || !dictionary.is_power_of_two() {
            return Err(Rar4DecodeError::InvalidDictionary { requested: dictionary });
        }
        if dictionary > window_limit {
            return Err(Rar4DecodeError::WindowLimit { requested: dictionary, allowed: window_limit });
        }
        let mut history = Vec::new();
        work.check()?;
        history
            .try_reserve_exact(dictionary as usize)
            .map_err(|_| Rar4DecodeError::Allocation { requested: dictionary })?;
        let actual = history.capacity() as u64;
        if actual > window_limit.min(4194304) {
            return Err(Rar4DecodeError::WindowLimit { requested: actual, allowed: window_limit.min(4194304) });
        }
        while history.len() < dictionary as usize {
            work.check()?;
            let next = (history.len() + CHUNK).min(dictionary as usize);
            let work_bytes = next - history.len();
            history.resize(next, 0);
            work.tick(work_bytes as u64)?;
        }
        let mut decoder = Self {
            work,
            dictionary: history,
            packed,
            fed: 0,
            expected: unpacked,
            produced: 0,
            bits: Bits::default(),
            phase: if unpacked == 0 { Phase::Complete } else { Phase::Align },
            poisoned: false,
            finished: false,
            old: [0; 404],
            lengths: [0; 404],
            bc_lengths: [0; 20],
            tables: std::array::from_fn(|_| Huff::empty()),
            prefix: 0,
            depth: 0,
            recent: [0; 4],
            last_length: 0,
            low: 0,
            low_repeats: 0,
            output: [0; OUTPUT],
            filled: 0,
            table_builds: 0,
        };
        decoder.work.tick(std::mem::size_of::<Self>() as u64)?;
        decoder.work.check()?;
        Ok(decoder)
    }
    pub(crate) fn feed(&mut self, bytes: &[u8], sink: &mut dyn Sink) -> DecodeResult<Rar4FeedState> {
        if self.poisoned || self.finished {
            return Err(Rar4DecodeError::Malformed("decoder is no longer usable"));
        }
        let result = (|| {
            self.work.check()?;
            self.fed = self.fed.checked_add(bytes.len() as u64).ok_or(Rar4DecodeError::CounterOverflow)?;
            if self.fed > self.packed {
                return Err(Rar4DecodeError::PackedSize { expected: self.packed, actual: self.fed });
            }
            let mut input = bytes;
            while self.step(&mut input, sink)? {}
            self.work.check()?;
            Ok(if matches!(self.phase, Phase::Complete) { Rar4FeedState::Complete } else { Rar4FeedState::NeedInput })
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub(crate) fn finish(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        if self.poisoned || self.finished {
            return Err(Rar4DecodeError::Malformed("decoder is no longer usable"));
        }
        let result = (|| {
            self.work.check()?;
            if self.fed != self.packed {
                return Err(Rar4DecodeError::PackedSize { expected: self.packed, actual: self.fed });
            }
            if !matches!(self.phase, Phase::Complete) {
                return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: self.produced });
            }
            self.flush(sink)?;
            self.finished = true;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn flush(&mut self, sink: &mut dyn Sink) -> DecodeResult<()> {
        self.work.check()?;
        if self.filled != 0 {
            sink.put(&self.output[..self.filled]).map_err(Rar4DecodeError::Sink)?;
            self.filled = 0;
        }
        self.work.check()
    }
    fn emit(&mut self, byte: u8, sink: &mut dyn Sink) -> DecodeResult<()> {
        let next = self.produced.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow)?;
        if next > self.expected {
            return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: next });
        }
        let index = (self.produced & (self.dictionary.len() as u64 - 1)) as usize;
        self.dictionary[index] = byte;
        self.produced = next;
        self.output[self.filled] = byte;
        self.filled += 1;
        if self.filled == OUTPUT {
            self.flush(sink)?;
        }
        Ok(())
    }
    fn symbol(&mut self, table: usize, input: &mut &[u8]) -> DecodeResult<Option<u16>> {
        if self.tables[table].used == 0 {
            return Err(Rar4DecodeError::Malformed("empty Huffman table"));
        }
        while self.depth < 15 {
            let Some(bit) = self.bits.take(1, input) else { return Ok(None) };
            self.work.tick(1)?;
            self.prefix = (self.prefix << 1) | bit;
            self.depth += 1;
            let h = &self.tables[table];
            if let Some(relative) = self.prefix.checked_sub(h.first[self.depth])
                && relative < u32::from(h.count[self.depth])
            {
                let symbol = h.symbols[h.offset[self.depth] + relative as usize];
                self.prefix = 0;
                self.depth = 0;
                return Ok(Some(symbol));
            }
        }
        Err(Rar4DecodeError::Malformed("undefined Huffman code"))
    }
    fn insert(&mut self, distance: u64) {
        self.recent.copy_within(0..3, 1);
        self.recent[0] = distance;
    }
    fn start_copy(&mut self, length: u64, distance: u64) -> DecodeResult<()> {
        if distance == 0 || distance > self.dictionary.len() as u64 || distance > self.produced {
            return Err(Rar4DecodeError::Malformed("match distance outside initialized history"));
        }
        let end = self.produced.checked_add(length).ok_or(Rar4DecodeError::CounterOverflow)?;
        if end > self.expected {
            return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: end });
        }
        self.last_length = length;
        self.phase = Phase::Copy { distance, left: length };
        Ok(())
    }
    fn length(index: usize) -> (u64, u8) {
        if index < 8 {
            (index as u64, 0)
        } else {
            let bits = ((index - 4) / 4) as u8;
            (((4 + index % 4) as u64) << bits, bits)
        }
    }
    fn distance(index: usize) -> (u64, u8) {
        match index {
            0..=3 => (index as u64, 0),
            4..=33 => {
                let bits = ((index - 2) / 2) as u8;
                (((2 + index % 2) as u64) << bits, bits)
            }
            34..=47 => (((index - 32) as u64) << 16, 16),
            48..=59 => (((index - 44) as u64) << 18, 18),
            _ => unreachable!(),
        }
    }
    fn step(&mut self, input: &mut &[u8], sink: &mut dyn Sink) -> DecodeResult<bool> {
        self.work.tick(1)?;
        macro_rules! take {
            ($bits:expr) => {
                match self.bits.take($bits, input) {
                    Some(n) => n,
                    None => return Ok(false),
                }
            };
        }
        macro_rules! symbol {
            ($table:expr) => {
                match self.symbol($table, input)? {
                    Some(n) => n,
                    None => return Ok(false),
                }
            };
        }
        match self.phase {
            Phase::Align => {
                self.bits.align();
                self.phase = Phase::Mode;
            }
            Phase::Mode => {
                if take!(1) != 0 {
                    return Err(Rar4DecodeError::Unsupported(Rar4UnsupportedMode::Ppm));
                }
                self.phase = Phase::Retain;
            }
            Phase::Retain => {
                if take!(1) == 0 {
                    self.old = [0; 404];
                }
                self.phase = Phase::Bc { index: 0 };
            }
            Phase::Bc { index } => {
                let value = take!(4) as u8;
                if value == 15 {
                    self.phase = Phase::BcRun { index };
                } else {
                    self.bc_lengths[index] = value;
                    self.phase = if index + 1 == 20 { Phase::BuildBc } else { Phase::Bc { index: index + 1 } };
                }
            }
            Phase::BcRun { index } => {
                let value = take!(4) as usize;
                let count = if value == 0 { 1 } else { value + 2 };
                if index + count > 20 {
                    return Err(Rar4DecodeError::Malformed("BC run exceeds table"));
                }
                self.bc_lengths[index..index + count].fill(if value == 0 { 15 } else { 0 });
                self.phase = if index + count == 20 { Phase::BuildBc } else { Phase::Bc { index: index + count } };
            }
            Phase::BuildBc => {
                self.tables[0].build(&self.bc_lengths, &mut self.work)?;
                if self.tables[0].used == 0 {
                    return Err(Rar4DecodeError::Malformed("empty code-length table"));
                }
                self.phase = Phase::Lengths { index: 0 };
            }
            Phase::Lengths { index } => {
                let value = symbol!(0);
                if value < 16 {
                    self.lengths[index] = (value as u8 + self.old[index]) & 15;
                    self.phase =
                        if index + 1 == 404 { Phase::BuildTables } else { Phase::Lengths { index: index + 1 } };
                } else {
                    self.phase = Phase::LengthRun { index, kind: value };
                }
            }
            Phase::LengthRun { index, kind } => {
                let count = if kind == 16 || kind == 18 { take!(3) as usize + 3 } else { take!(7) as usize + 11 };
                if index + count > 404 || (kind < 18 && index == 0) {
                    return Err(Rar4DecodeError::Malformed("invalid code-length run"));
                }
                let value = if kind < 18 { self.lengths[index - 1] } else { 0 };
                self.lengths[index..index + count].fill(value);
                self.work.tick(count as u64)?;
                self.phase =
                    if index + count == 404 { Phase::BuildTables } else { Phase::Lengths { index: index + count } };
            }
            Phase::BuildTables => {
                for (table, range) in [0..299, 299..359, 359..376, 376..404].into_iter().enumerate() {
                    self.tables[table + 1].build(&self.lengths[range], &mut self.work)?;
                }
                if self.tables[1].used == 0 {
                    return Err(Rar4DecodeError::Malformed("empty literal table"));
                }
                self.old = self.lengths;
                self.low = 0;
                self.low_repeats = 0;
                self.table_builds = self.table_builds.checked_add(1).ok_or(Rar4DecodeError::CounterOverflow)?;
                self.phase = Phase::Token;
            }
            Phase::Token => {
                let token = symbol!(1);
                self.phase = match token {
                    0..=255 => {
                        self.emit(token as u8, sink)?;
                        Phase::Token
                    }
                    256 => Phase::End,
                    257 => return Err(Rar4DecodeError::Unsupported(Rar4UnsupportedMode::VmFilter)),
                    258 => {
                        if self.last_length == 0 {
                            return Err(Rar4DecodeError::Malformed("repeat before a match"));
                        }
                        self.start_copy(self.last_length, self.recent[0])?;
                        self.phase
                    }
                    259..=262 => Phase::RecentLength { slot: (token - 259) as usize },
                    263..=270 => Phase::Short { index: (token - 263) as usize },
                    271..=298 => Phase::Length { index: (token - 271) as usize, recent: None },
                    _ => return Err(Rar4DecodeError::Malformed("literal alphabet")),
                };
                if self.produced == self.expected {
                    self.flush(sink)?;
                    self.phase = Phase::Complete;
                }
            }
            Phase::End => {
                self.phase = if take!(1) != 0 { Phase::Align } else { Phase::EndHint };
            }
            Phase::EndHint => {
                let _hint = take!(1);
                return Err(Rar4DecodeError::DecodedSize { expected: self.expected, actual: self.produced });
            }
            Phase::Length { index, recent } => {
                let (base, bits) = Self::length(index);
                self.phase = Phase::LengthExtra { base, bits, recent };
            }
            Phase::RecentLength { slot } => {
                if self.recent[slot] == 0 {
                    return Err(Rar4DecodeError::Malformed("recent distance unavailable"));
                }
                self.phase = Phase::Length { index: symbol!(4) as usize, recent: Some(slot) };
            }
            Phase::LengthExtra { base, bits, recent } => {
                let length = base + u64::from(take!(bits)) + if recent.is_some() { 2 } else { 3 };
                if let Some(slot) = recent {
                    let distance = self.recent[slot];
                    self.recent.copy_within(0..slot, 1);
                    self.recent[0] = distance;
                    self.start_copy(length, distance)?;
                } else {
                    self.phase = Phase::Distance { length };
                }
            }
            Phase::Distance { length } => {
                self.phase = Phase::DistanceBits { length, index: symbol!(2) as usize };
            }
            Phase::DistanceBits { length, index } => {
                let (base, bits) = Self::distance(index);
                if index <= 9 {
                    let distance = base + 1 + u64::from(take!(bits));
                    self.insert(distance);
                    self.start_copy(length, distance)?;
                } else {
                    let high = u64::from(take!(bits - 4)) << 4;
                    self.phase = Phase::Low { length, base: base + 1 + high };
                }
            }
            Phase::Low { length, base } => {
                let low = if self.low_repeats != 0 {
                    self.low_repeats -= 1;
                    self.low
                } else {
                    let value = symbol!(3);
                    if value == 16 {
                        self.low_repeats = 15;
                        self.low
                    } else {
                        self.low = u64::from(value);
                        self.low
                    }
                };
                let distance = base + low;
                let length = length + u64::from(distance >= 0x2000) + u64::from(distance >= 0x40000);
                self.insert(distance);
                self.start_copy(length, distance)?;
            }
            Phase::Short { index } => {
                let (base, bits) = match index {
                    0 => (0, 2),
                    1 => (4, 2),
                    2 => (8, 3),
                    3 => (16, 4),
                    4 => (32, 5),
                    5 => (64, 6),
                    6 => (128, 6),
                    7 => (192, 6),
                    _ => unreachable!(),
                };
                let distance = base + 1 + u64::from(take!(bits));
                self.insert(distance);
                self.start_copy(2, distance)?;
            }
            Phase::Copy { distance, left } => {
                let index = ((self.produced - distance) & (self.dictionary.len() as u64 - 1)) as usize;
                self.emit(self.dictionary[index], sink)?;
                self.phase = if left == 1 { Phase::Token } else { Phase::Copy { distance, left: left - 1 } };
                if self.produced == self.expected {
                    self.flush(sink)?;
                    self.phase = Phase::Complete;
                }
            }
            Phase::Complete => return Ok(false),
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests;

/// Wrap the immutable literal vector for source/output ownership unit tests.
/// This helper cannot compress data and is absent from normal builds.
#[cfg(test)]
pub(crate) fn fixed_fixture() -> Vec<u8> {
    fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0, kind];
        bytes.extend(flags.to_le_bytes());
        bytes.extend(((body.len() + 7) as u16).to_le_bytes());
        bytes.extend(body);
        let crc = crate::crc32::hash(&bytes[2..]) as u16;
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    }
    let packed = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rar4-lz/literal-a.packed"));
    let mut body = Vec::new();
    body.extend((packed.len() as u32).to_le_bytes());
    body.extend(1u32.to_le_bytes());
    body.push(3);
    body.extend(crate::crc32::hash(b"A").to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([29, 0x33]);
    body.extend(1u16.to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.push(b'x');
    [
        b"Rar!\x1a\x07\0".as_slice(),
        &block(0x73, 0, &[0; 6]),
        &block(0x74, 0x8000, &body),
        packed,
        &block(0x7b, 0x4000, &[]),
    ]
    .concat()
}
