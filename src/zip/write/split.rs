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

use std::io::{self, Write};
use std::sync::Arc;

use crate::extract::Cancellation;

const MARKER: &[u8; 4] = b"PK\x07\x08";

/// Opens fresh numbered sinks. The previous sink has been flushed and dropped.
/// A failed provider call is terminal, including an interrupted call.
pub trait VolumeProvider {
    /// A provisional forward-only volume.
    type Sink: Write;

    // Provide a fresh sink for this disk. A failed open is terminal because
    // the provider may already have created or partially initialized it.
    fn open(&mut self, disk: u32) -> io::Result<Self::Sink>;
}

#[derive(Clone, Copy, Debug)]
struct Limits {
    disk_bytes: u64,
    disks: u32,
    output_bytes: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Location {
    /// Zero-based volume number.
    pub disk: u32,
    /// Byte offset within that volume.
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Successfully opened volumes.
    pub disks: u32,
    /// Bytes accepted across all volumes, excluding unused capacity.
    pub bytes: u64,
    /// Provider calls and physical write and flush attempts.
    pub attempts: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Open,
    Reserve,
    Write,
    Flush,
    /// Member validation, source reading or payload encoding.
    Member,
    /// Central directory and end geometry.
    Finish,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Disks,
    OutputBytes,
    Attempts,
}

#[derive(Clone, Debug)]
pub enum ErrorKind {
    Io(Arc<io::Error>),
    Writer(super::WriteError),
    Limit(Limit),
    Canceled,
    RecordTooLarge { requested: u64, capacity: u64 },
    IncompleteRecord { remaining: u64 },
}

#[derive(Clone, Debug)]
pub struct Error {
    /// Operation that stopped.
    pub stage: Stage,
    /// Physical location where the operation stopped or would start.
    pub at: Location,
    /// Original failure cause.
    pub kind: ErrorKind,
    /// Physical transport accounting at failure.
    pub usage: Usage,
    /// Writer accounting at failure, including provisional payload bytes.
    pub writer: super::WriteUsage,
}

type Result<T> = std::result::Result<T, Arc<Error>>;

// Owns at most one sink. Positive writes advance both the disk-relative
// position and cumulative bytes. Rotating never writes unused tail space.
struct Transport<P: VolumeProvider> {
    provider: P,
    sink: Option<P::Sink>,
    limits: Limits,
    cancel: Option<Cancellation>,
    position: Location,
    usage: Usage,
    record_remaining: u64,
    failed: Option<Arc<Error>>,
}

impl<P: VolumeProvider> Transport<P> {
    fn new(provider: P, limits: Limits, cancel: Option<Cancellation>) -> Result<Self> {
        let mut transport = Self {
            provider,
            sink: None,
            limits,
            cancel,
            position: Location::default(),
            usage: Usage::default(),
            record_remaining: 0,
            failed: None,
        };
        let size = MARKER.len() as u64;
        transport.check_record_size(size)?;
        transport.check_output(size, Stage::Write)?;
        transport.open_next()?;
        transport.write_on_disk(MARKER)?;
        Ok(transport)
    }

    fn position(&self) -> Location {
        self.position
    }

    fn placement(&mut self, size: u64) -> Result<Location> {
        self.check_unreserved(Stage::Reserve)?;
        self.check_record_size(size)?;
        self.check_output(size, Stage::Reserve)?;
        if size > self.remaining() {
            self.check_next()?;
            Ok(self.next_location())
        } else {
            Ok(self.position)
        }
    }

    fn reserve_record(&mut self, size: u64) -> Result<Record<'_, P>> {
        self.check_unreserved(Stage::Reserve)?;
        self.check_record_size(size)?;
        self.check_output(size, Stage::Reserve)?;
        if size > self.remaining() {
            self.rotate()?;
        }
        self.record_remaining = size;
        Ok(Record { location: self.position, transport: self })
    }

    fn write_payload(&mut self, mut bytes: &[u8]) -> Result<()> {
        self.check_unreserved(Stage::Write)?;
        self.check_output(bytes.len() as u64, Stage::Write)?;
        while !bytes.is_empty() {
            if self.remaining() == 0 {
                self.rotate()?;
            }
            let count = self.remaining().min(bytes.len() as u64) as usize;
            let (head, tail) = bytes.split_at(count);
            self.write_on_disk(head)?;
            bytes = tail;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(P, Usage)> {
        self.check_unreserved(Stage::Flush)?;
        self.flush()?;
        self.check_active(Stage::Flush, self.position)?;
        drop(self.sink.take());
        Ok((self.provider, self.usage))
    }

    fn rotate(&mut self) -> Result<()> {
        self.check_next()?;
        self.flush()?;
        drop(self.sink.take());
        self.open_next()
    }

    fn next_location(&self) -> Location {
        Location { disk: self.usage.disks, offset: 0 }
    }

    fn check_next(&mut self) -> Result<()> {
        let at = self.next_location();
        self.check_active(Stage::Open, at)?;
        if self.usage.disks == self.limits.disks {
            return Err(self.fail(Stage::Open, at, ErrorKind::Limit(Limit::Disks)));
        }
        Ok(())
    }

    fn open_next(&mut self) -> Result<()> {
        self.check_next()?;
        let at = self.next_location();
        self.charge(Stage::Open, at)?;
        let sink =
            self.provider.open(at.disk).map_err(|cause| self.fail(Stage::Open, at, ErrorKind::Io(Arc::new(cause))))?;
        self.sink = Some(sink);
        self.position = at;
        self.usage.disks += 1;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.run_sink(Stage::Flush, Write::flush)
    }

    fn write_on_disk(&mut self, mut bytes: &[u8]) -> Result<()> {
        debug_assert!(bytes.len() as u64 <= self.remaining());
        while !bytes.is_empty() {
            let count = self.run_sink(Stage::Write, |sink| sink.write(bytes))?;
            if count == 0 || count > bytes.len() {
                let cause = if count == 0 {
                    io::ErrorKind::WriteZero.into()
                } else {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid split sink write count")
                };
                return Err(self.fail(Stage::Write, self.position, ErrorKind::Io(Arc::new(cause))));
            }
            // Callers checked the whole slice against both byte ceilings.
            self.position.offset += count as u64;
            self.usage.bytes += count as u64;
            bytes = &bytes[count..];
        }
        Ok(())
    }

    fn run_sink<T>(&mut self, stage: Stage, mut operation: impl FnMut(&mut P::Sink) -> io::Result<T>) -> Result<T> {
        loop {
            self.charge(stage, self.position)?;
            match operation(self.sink.as_mut().expect("active volume")) {
                Ok(value) => return Ok(value),
                Err(cause) if cause.kind() == io::ErrorKind::Interrupted => {}
                Err(cause) => return Err(self.fail(stage, self.position, ErrorKind::Io(Arc::new(cause)))),
            }
        }
    }

    fn remaining(&self) -> u64 {
        self.limits.disk_bytes - self.position.offset
    }

    fn check_record_size(&mut self, size: u64) -> Result<()> {
        let capacity = self.limits.disk_bytes;
        if size > capacity {
            return Err(self.fail(
                Stage::Reserve,
                self.position,
                ErrorKind::RecordTooLarge { requested: size, capacity },
            ));
        }
        Ok(())
    }

    fn check_output(&mut self, bytes: u64, stage: Stage) -> Result<()> {
        if bytes > self.limits.output_bytes - self.usage.bytes {
            return Err(self.fail(stage, self.position, ErrorKind::Limit(Limit::OutputBytes)));
        }
        Ok(())
    }

    fn check_unreserved(&mut self, stage: Stage) -> Result<()> {
        if self.record_remaining != 0 {
            return Err(self.fail(
                Stage::Write,
                self.position,
                ErrorKind::IncompleteRecord { remaining: self.record_remaining },
            ));
        }
        self.check_active(stage, self.position)
    }

    fn check_active(&mut self, stage: Stage, at: Location) -> Result<()> {
        if let Some(error) = &self.failed {
            return Err(Arc::clone(error));
        }
        if self.cancel.as_ref().is_some_and(Cancellation::is_canceled) {
            return Err(self.fail(stage, at, ErrorKind::Canceled));
        }
        Ok(())
    }

    fn charge(&mut self, stage: Stage, at: Location) -> Result<()> {
        self.check_active(stage, at)?;
        if self.usage.attempts == self.limits.attempts {
            return Err(self.fail(stage, at, ErrorKind::Limit(Limit::Attempts)));
        }
        self.usage.attempts += 1;
        Ok(())
    }

    fn fail(&mut self, stage: Stage, at: Location, kind: ErrorKind) -> Arc<Error> {
        Arc::clone(self.failed.get_or_insert_with(|| {
            Arc::new(Error { stage, at, kind, usage: self.usage, writer: super::WriteUsage::default() })
        }))
    }
}

// The mutable borrow pins the selected disk. The transport keeps the
// remaining length so dropping or forgetting an incomplete record cannot
// let another operation proceed.
struct Record<'a, P: VolumeProvider> {
    transport: &'a mut Transport<P>,
    location: Location,
}

impl<P: VolumeProvider> Record<'_, P> {
    fn location(&self) -> Location {
        self.location
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let transport = &mut self.transport;
        transport.check_active(Stage::Write, transport.position)?;
        let size = bytes.len() as u64;
        if size > transport.record_remaining {
            return Err(transport.fail(
                Stage::Write,
                transport.position,
                ErrorKind::RecordTooLarge { requested: size, capacity: transport.record_remaining },
            ));
        }
        transport.write_on_disk(bytes)?;
        transport.record_remaining -= size;
        Ok(())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "split ZIP {:?} on disk {} at {}: {:?}", self.stage, self.at.disk, self.at.offset, self.kind)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(error) => Some(error.as_ref()),
            ErrorKind::Writer(error) => Some(error),
            _ => None,
        }
    }
}

mod writer;
pub use writer::{EntryWritten, Finished, Options, ZipSplitWriter};

#[cfg(test)]
mod tests;
