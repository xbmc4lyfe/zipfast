// zip-container -- checked ZIP metadata primitives
// Copyright (C) 2026 zipview contributors
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

mod metadata;
mod reducers;
#[cfg(test)]
mod tests;
mod walk;

pub use metadata::{
    BufferUsage, DirectoryDeclaration, DirectoryError, EndRecord, LimitKind, Limits, Profile, SupplyError, Usage,
    Zip64End, Zip64Locator,
};

pub use walk::{
    Directory, DirectoryParser, RecordProjection, ReducedCentralRecord, parse_slice, parse_slice_projected,
};

use std::{fmt, mem, ops::Range};

use crate::header::{le16, le32, le64};
use crate::{CENTRAL_HEADER_LEN, CentralHeader, OwnershipUsage};

const END_LEN: usize = 22;
const END64_LEN: usize = 56;
const LOCATOR_LEN: usize = 20;
const END_SEARCH: usize = END_LEN + u16::MAX as usize;
const TAIL_LEN: usize = END_SEARCH + END64_LEN + LOCATOR_LEN;
const SEARCH_WINDOW: u64 = 64 * 1024;
const END_SIG: u32 = 0x0605_4b50;
const END64_SIG: [u8; 4] = *b"PK\x06\x06";
const LOCATOR_SIG: u32 = 0x0706_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const CANDIDATE_WORK: u64 = 64;
const CENTRAL_FIXED_WORK: u64 = 128;

/// A discovered ZIP layout and the source metadata needed to continue parsing.
///
/// The directory range reflects its declared size. Discovery checks the first
/// fixed header where needed and leaves verification of entries and their
/// complete extents to the directory walker.
#[derive(Clone)]
pub struct DirectoryLocation {
    candidate: Candidate,
    declaration: DirectoryDeclaration,
    directory: Range<u64>,
    shift: u64,
    comment: Vec<u8>,
    accounting: Accounting,
    tail_start: u64,
    tail: Vec<u8>,
    first_header: Option<CentralHeader>,
    first_probe: Option<FixedProbe>,
}

impl DirectoryLocation {
    /// Archive length used to check the source ranges.
    pub fn archive_len(&self) -> u64 {
        self.tail_start + self.tail.len() as u64
    }

    /// Selected classic end record and its wire fields.
    pub fn end_record(&self) -> &EndRecord {
        &self.candidate.end
    }

    /// Adjacent locator considered for this candidate, if present.
    pub fn zip64_locator(&self) -> Option<&Zip64Locator> {
        self.candidate.locator.as_ref()
    }

    /// Selected ZIP64 end record, if usable.
    pub fn zip64_end(&self) -> Option<&Zip64End> {
        self.candidate.zip64.as_ref()
    }

    /// Effective count, size, and stored directory offset.
    pub fn declaration(&self) -> DirectoryDeclaration {
        self.declaration
    }

    /// Discovered physical directory extent according to the declared size.
    pub fn directory_range(&self) -> Range<u64> {
        self.directory.clone()
    }

    /// Physical offset adjustment for stored directory and local offsets.
    pub fn prefix_shift(&self) -> u64 {
        self.shift
    }

    /// Absolute range of the available archive comment.
    pub fn comment_range(&self) -> Range<u64> {
        self.candidate.comment.clone()
    }

    /// Available archive comment bytes before decoding.
    pub fn raw_comment(&self) -> &[u8] {
        &self.comment
    }

    /// First fixed central header validated during discovery, if present.
    pub fn first_header(&self) -> Option<CentralHeader> {
        self.first_header
    }

    /// Cumulative source, work and metadata counters.
    pub fn usage(&self) -> Usage {
        self.accounting.usage
    }

    /// Retained tail and external first-header probe storage.
    pub fn buffer_usage(&self) -> BufferUsage {
        BufferUsage {
            live_bytes: self.tail.len() + self.first_probe.as_ref().map_or(0, |probe| probe.len),
            capacity_bytes: self.tail.capacity() + self.first_probe.as_ref().map_or(0, |probe| probe.bytes.len()),
        }
    }
}

impl fmt::Debug for DirectoryLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryLocation")
            .field("candidate", &self.candidate)
            .field("declaration", &self.declaration)
            .field("directory", &self.directory)
            .field("shift", &self.shift)
            .field("usage", &self.usage())
            .field("buffers", &self.buffer_usage())
            .finish_non_exhaustive()
    }
}

/// Incremental end-record discovery over an archive with a known byte length.
///
/// Requests are absolute half-open ranges. A caller can cancel by dropping the
/// state between operations. Discovery prefers an exact-EOF comment, then a
/// complete comment followed by trailing data, then a clipped comment in
/// [Profile::Zipview]. Within each rank, the latest structurally plausible
/// record wins. An embedded record with plausible geometry can win that tie.
#[derive(Clone)]
pub struct EndDiscovery {
    len: u64,
    profile: Profile,
    accounting: Accounting,
    stage: Stage,
    pending: Option<Pending>,
    tail: Vec<u8>,
    tail_start: u64,
    end_offset: Option<u64>,
    rank: Rank,
    cursor: usize,
    rejected: Option<DirectoryError>,
    candidate: Option<Candidate>,
    probe: FixedProbe,
    recovery: Recovery,
    location: Option<DirectoryLocation>,
}

impl EndDiscovery {
    /// Creates discovery state without fetching or allocating source buffers.
    pub fn new(archive_len: u64, profile: Profile, limits: Limits) -> Result<Self, DirectoryError> {
        Self::with_end_offset(archive_len, profile, limits, None)
    }

    fn with_end_offset(
        archive_len: u64,
        profile: Profile,
        limits: Limits,
        end_offset: Option<u64>,
    ) -> Result<Self, DirectoryError> {
        if let Some(offset) = end_offset {
            let comment_len = offset.checked_add(END_LEN as u64).and_then(|end| archive_len.checked_sub(end));
            if comment_len.is_none_or(|len| len > u64::from(u16::MAX)) {
                return Err(DirectoryError::MalformedEnd);
            }
        }
        if archive_len < END_LEN as u64 {
            return Err(DirectoryError::NotZip);
        }
        let tail_start = archive_len.saturating_sub(TAIL_LEN as u64);
        Ok(Self {
            len: archive_len,
            profile,
            accounting: Accounting::new(limits)?,
            stage: Stage::Tail,
            pending: None,
            tail: Vec::new(),
            tail_start,
            end_offset,
            rank: Rank::Exact,
            cursor: 0,
            rejected: None,
            candidate: None,
            probe: FixedProbe::default(),
            recovery: Recovery::default(),
            location: None,
        })
    }

    /// Returns the pending request or progresses to the next required range.
    ///
    /// Polling an unchanged request or a terminal state charges no work.
    pub fn next_read(&mut self) -> Result<Option<Range<u64>>, DirectoryError> {
        if self.pending.is_none() {
            let result = self.advance();
            self.cache_failure(result)?;
        }
        Ok(self.pending.as_ref().map(|pending| pending.next..pending.range.end))
    }

    /// Supplies a contiguous prefix of the pending request.
    ///
    /// An empty in-bounds supply is a no-op. Caller protocol errors leave the
    /// pending range, discovery state and usage intact.
    pub fn supply(&mut self, offset: u64, bytes: &[u8]) -> Result<(), DirectoryError> {
        let size = bytes.len() as u64;
        let end = offset
            .checked_add(size)
            .filter(|&end| end <= self.len)
            .ok_or(DirectoryError::Supply(SupplyError::OutOfBounds))?;
        if bytes.is_empty() {
            return Ok(());
        }
        if let Stage::Failed(error) = self.stage {
            return Err(error);
        }
        let pending = self.pending.as_ref().ok_or(DirectoryError::Supply(SupplyError::Unsolicited))?;
        if offset != pending.next {
            return Err(DirectoryError::Supply(SupplyError::UnexpectedOffset));
        }
        if end > pending.range.end {
            return Err(DirectoryError::Supply(SupplyError::Overlong));
        }
        let complete = end == pending.range.end;
        let purpose = pending.purpose;
        let range = pending.range.clone();
        self.accounting.usage.fetched_bytes += size;
        let result = match purpose {
            Purpose::Tail => self.append_tail(bytes),
            Purpose::Probe => self.append_probe(bytes),
            Purpose::Recovery => self.consume_recovery(range, offset, bytes, complete),
        };
        self.cache_failure(result)?;
        if complete {
            self.pending = None;
        } else {
            self.pending.as_mut().expect("partially supplied request").next = end;
        }
        Ok(())
    }

    /// Returns the discovered location, or an error when more source data is needed.
    pub fn finish(mut self) -> Result<DirectoryLocation, DirectoryError> {
        if self.next_read()?.is_some() {
            return Err(DirectoryError::Incomplete);
        }
        self.location.take().ok_or(DirectoryError::Incomplete)
    }

    /// Current cumulative source, work and metadata counters.
    pub fn usage(&self) -> Usage {
        self.location.as_ref().map_or(self.accounting.usage, DirectoryLocation::usage)
    }

    /// Current storage used by discovery buffers.
    pub fn buffer_usage(&self) -> BufferUsage {
        self.location.as_ref().map_or_else(
            || BufferUsage {
                live_bytes: self.tail.len() + self.probe.len + self.recovery.overlap_len + self.recovery.partial.len(),
                capacity_bytes: self.tail.capacity()
                    + self.probe.bytes.len()
                    + self.recovery.overlap.len()
                    + self.recovery.partial.capacity(),
            },
            DirectoryLocation::buffer_usage,
        )
    }

    fn cache_failure(&mut self, result: Result<(), DirectoryError>) -> Result<(), DirectoryError> {
        if let Err(error) = result {
            self.stage = Stage::Failed(error);
            self.pending = None;
        }
        result
    }

    fn advance(&mut self) -> Result<(), DirectoryError> {
        while self.pending.is_none() {
            match self.stage {
                Stage::Tail => {
                    let next = self.tail_start + self.tail.len() as u64;
                    if next == self.len {
                        self.cursor = self
                            .end_offset
                            .map_or(self.tail.len() - END_LEN + 1, |offset| (offset - self.tail_start) as usize + 1);
                        self.stage = Stage::Candidate;
                    } else {
                        self.request_required(next..self.len, Purpose::Tail)?;
                    }
                }
                Stage::Candidate => self.scan_candidates()?,
                Stage::Pointer | Stage::Fast => self.zip64_probe()?,
                Stage::Recovery => self.recover_zip64()?,
                Stage::Declared | Stage::Anchored => self.locate_directory()?,
                Stage::FirstHeader { start, end, declaration } => self.first_header(start, end, declaration)?,
                Stage::Done => break,
                Stage::Failed(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn request_required(&mut self, range: Range<u64>, purpose: Purpose) -> Result<(), DirectoryError> {
        let len = range.end - range.start;
        self.accounting.check_fetched(len)?;
        self.accounting.check_work(len)?;
        self.request(range.start..range.start + len.min(self.accounting.limits.range_bytes), purpose)
    }

    fn request(&mut self, range: Range<u64>, purpose: Purpose) -> Result<(), DirectoryError> {
        if range.is_empty() {
            return Err(DirectoryError::Limit(LimitKind::RangeBytes));
        }
        debug_assert!(range.end <= self.len && range.end - range.start <= self.accounting.limits.range_bytes);
        self.accounting.check_fetched(range.end - range.start)?;
        self.pending = Some(Pending { next: range.start, range, purpose });
        Ok(())
    }

    fn append_tail(&mut self, bytes: &[u8]) -> Result<(), DirectoryError> {
        self.accounting.charge(bytes.len() as u64)?;
        let total = (self.len - self.tail_start) as usize;
        if self.tail.capacity() < total {
            // A clone of a partially supplied tail has only its live bytes.
            self.tail.try_reserve_exact(total - self.tail.len()).map_err(|_| DirectoryError::Allocation)?;
        }
        self.tail.extend_from_slice(bytes);
        Ok(())
    }

    fn append_probe(&mut self, bytes: &[u8]) -> Result<(), DirectoryError> {
        self.accounting.charge(bytes.len() as u64)?;
        self.probe.append(bytes);
        Ok(())
    }

    fn scan_candidates(&mut self) -> Result<(), DirectoryError> {
        let minimum = self
            .end_offset
            .map_or(self.tail.len().saturating_sub(END_SEARCH), |offset| (offset - self.tail_start) as usize);
        while self.cursor > minimum {
            self.accounting.charge(1)?;
            self.cursor -= 1;
            let at = self.cursor;
            if le32(&self.tail, at) != END_SIG {
                continue;
            }
            self.accounting.charge(CANDIDATE_WORK)?;
            let comment_start = at + END_LEN;
            let comment_len = le16(&self.tail, at + 20);
            let available = self.tail.len() - comment_start;
            let rank = match usize::from(comment_len).cmp(&available) {
                std::cmp::Ordering::Equal => Rank::Exact,
                std::cmp::Ordering::Less => Rank::Trailing,
                std::cmp::Ordering::Greater => Rank::Clipped,
            };
            if self.rank != rank {
                continue;
            }
            let at64 = self.tail_start + at as u64;
            let comment_start = at64 + END_LEN as u64;
            let end = EndRecord {
                source: at64..comment_start,
                disk: le16(&self.tail, at + 4),
                directory_disk: le16(&self.tail, at + 6),
                disk_entries: le16(&self.tail, at + 8),
                entries: le16(&self.tail, at + 10),
                size: le32(&self.tail, at + 12),
                offset: le32(&self.tail, at + 16),
                comment_len,
            };
            let saturated = end.entries == u16::MAX || end.size == u32::MAX || end.offset == u32::MAX;
            let locator = if self.profile == Profile::Zipfast || saturated { self.locator(at) } else { None };
            let available_len = u64::from(comment_len).min(available as u64);
            let comment = comment_start..comment_start + available_len;
            let inspect = locator.is_some();
            self.candidate = Some(Candidate { end, locator, zip64: None, comment });
            if inspect {
                self.stage = Stage::Pointer;
            } else {
                self.begin_directory();
            }
            return Ok(());
        }
        if self.end_offset.is_some() {
            return Err(DirectoryError::MalformedEnd);
        }
        self.rank = match (self.rank, self.profile) {
            (Rank::Exact, _) => Rank::Trailing,
            (Rank::Trailing, Profile::Zipview) => Rank::Clipped,
            _ => return Err(self.rejected.unwrap_or(DirectoryError::NotZip)),
        };
        self.cursor = self.tail.len() - END_LEN + 1;
        Ok(())
    }

    fn locator(&self, end: usize) -> Option<Zip64Locator> {
        let at = end.checked_sub(LOCATOR_LEN)?;
        let bytes = &self.tail[at..end];
        if le32(bytes, 0) != LOCATOR_SIG {
            return None;
        }
        Some(Zip64Locator {
            source: self.tail_start + at as u64..self.tail_start + end as u64,
            disk: le32(bytes, 4),
            record_offset: le64(bytes, 8),
            total_disks: le32(bytes, 16),
        })
    }

    fn begin_directory(&mut self) {
        self.recovery = Recovery::default();
        self.stage = if self.profile == Profile::Zipview { Stage::Declared } else { Stage::Anchored };
    }

    fn candidate(&self) -> &Candidate {
        self.candidate.as_ref().expect("candidate selected for probing")
    }

    fn zip64_probe(&mut self) -> Result<(), DirectoryError> {
        let locator = self.candidate().locator.as_ref().expect("ZIP64 locator");
        let anchor = locator.source.start;
        let stored = locator.record_offset;
        let Some(fast) = anchor.checked_sub(END64_LEN as u64).filter(|&fast| stored <= fast) else {
            return self.missing_zip64();
        };
        let start = if self.stage == Stage::Pointer { stored } else { fast };
        if !self.fixed(start, END64_LEN)? {
            return Ok(());
        }
        self.accounting.charge(CANDIDATE_WORK)?;
        if let Some(record) = framed_zip64(self.fixed_bytes(start, END64_LEN), start, anchor) {
            self.found_zip64(record);
        } else if start == fast {
            if start == stored {
                return self.missing_zip64();
            }
            self.recovery.end = fast;
            self.stage = Stage::Recovery;
        } else {
            self.stage = Stage::Fast;
        }
        Ok(())
    }

    fn found_zip64(&mut self, record: Zip64End) {
        self.candidate.as_mut().expect("ZIP64 candidate").zip64 = Some(record);
        self.begin_directory();
    }

    fn missing_zip64(&mut self) -> Result<(), DirectoryError> {
        if self.profile == Profile::Zipview {
            self.begin_directory();
            Ok(())
        } else {
            self.reject(DirectoryError::MalformedZip64)
        }
    }

    fn recover_zip64(&mut self) -> Result<(), DirectoryError> {
        let locator = self.candidate().locator.as_ref().expect("ZIP64 locator");
        let lower = locator.record_offset + 1; // The recorded offset was already probed.
        let anchor = locator.source.start;
        let end = self.recovery.end;
        if end <= lower {
            return self.missing_zip64();
        }
        if end > self.tail_start {
            let start = self.tail_start.max(lower);
            for at in (start..end).rev() {
                self.accounting.charge(1)?;
                let at_in_tail = (at - self.tail_start) as usize;
                let bytes = &self.tail[at_in_tail..at_in_tail + END64_LEN];
                if bytes.starts_with(&END64_SIG) {
                    self.accounting.charge(CANDIDATE_WORK)?;
                    if let Some(record) = framed_zip64(bytes, at, anchor) {
                        self.found_zip64(record);
                        return Ok(());
                    }
                }
            }
            self.recovery.end = start;
            return Ok(());
        }

        if self.recovery.overlap_len == 0 {
            self.accounting.charge((END64_LEN - 1) as u64)?;
            self.recovery.overlap.copy_from_slice(&self.tail[..END64_LEN - 1]);
            self.recovery.overlap_len = END64_LEN - 1;
        }

        // Reuse the original pointer probe at the lower edge of the search.
        let probe_end = self.probe.start + self.probe.len as u64;
        if self.probe.start == lower - 1 && end <= probe_end {
            let mut bytes = [0; END64_LEN - 1];
            let len = (end - lower) as usize;
            self.accounting.charge(len as u64)?;
            bytes[..len].copy_from_slice(&self.probe.bytes[1..1 + len]);
            return self.scan_recovery_window(lower, &bytes[..len]);
        }

        self.accounting.check_fetched(1)?;
        self.accounting.check_work(1)?;
        let max = SEARCH_WINDOW
            .min(self.accounting.limits.range_bytes)
            .min(self.accounting.limits.fetched_bytes - self.accounting.usage.fetched_bytes)
            .min(self.accounting.limits.work_units - self.accounting.usage.work_units);
        let lower = if self.probe.start == lower - 1 { lower.max(probe_end) } else { lower };
        self.request(end.saturating_sub(max).max(lower)..end, Purpose::Recovery)
    }

    fn consume_recovery(
        &mut self,
        range: Range<u64>,
        offset: u64,
        bytes: &[u8],
        complete: bool,
    ) -> Result<(), DirectoryError> {
        // Charge each admitted window byte once for the driver. A full
        // window can be lent directly; a fragmented one is copied once.
        // Candidate-position scans and boundary copies are charged separately.
        self.accounting.charge(bytes.len() as u64)?;
        if complete && offset == range.start {
            return self.scan_recovery_window(offset, bytes);
        }

        let total = (range.end - range.start) as usize;
        if self.recovery.partial.capacity() < total {
            self.recovery
                .partial
                .try_reserve_exact(total - self.recovery.partial.len())
                .map_err(|_| DirectoryError::Allocation)?;
        }
        self.recovery.partial.extend_from_slice(bytes);
        if complete {
            let mut window = mem::take(&mut self.recovery.partial);
            self.scan_recovery_window(range.start, &window)?;
            if self.stage == Stage::Recovery {
                window.clear();
                self.recovery.partial = window;
            }
        }
        Ok(())
    }

    fn scan_recovery_window(&mut self, start: u64, bytes: &[u8]) -> Result<(), DirectoryError> {
        let anchor = self.candidate().locator.as_ref().expect("ZIP64 locator").source.start;
        let overlap = &self.recovery.overlap[..self.recovery.overlap_len];
        for i in (0..bytes.len()).rev() {
            self.accounting.charge(1)?;
            let suffix = &bytes[i..];
            let sig_bytes = suffix.len().min(END64_SIG.len());
            if suffix[..sig_bytes] != END64_SIG[..sig_bytes] || !overlap.starts_with(&END64_SIG[sig_bytes..]) {
                continue;
            }
            self.accounting.charge(CANDIDATE_WORK)?;
            let mut split = [0; END64_LEN];
            let fixed = if suffix.len() < END64_LEN {
                self.accounting.charge(END64_LEN as u64)?;
                split[..suffix.len()].copy_from_slice(suffix);
                split[suffix.len()..].copy_from_slice(&overlap[..END64_LEN - suffix.len()]);
                &split
            } else {
                &suffix[..END64_LEN]
            };
            if let Some(record) = framed_zip64(fixed, start + i as u64, anchor) {
                self.found_zip64(record);
                return Ok(());
            }
        }

        let kept = bytes.len().min(END64_LEN - 1);
        let prior = overlap.len().min(END64_LEN - 1 - kept);
        self.accounting.charge((kept + prior) as u64)?;
        self.recovery.overlap.copy_within(..prior, kept);
        self.recovery.overlap[..kept].copy_from_slice(&bytes[..kept]);
        self.recovery.overlap_len = kept + prior;
        self.recovery.end = start;
        Ok(())
    }

    fn fixed(&mut self, start: u64, len: usize) -> Result<bool, DirectoryError> {
        let end = start.checked_add(len as u64).filter(|&end| end <= self.len).ok_or(DirectoryError::MalformedEnd)?;
        if start >= self.tail_start {
            return Ok(true);
        }
        if self.probe.start != start {
            self.reposition_probe(start)?;
        }
        let loaded = start + self.probe.len as u64;
        if loaded < end.min(self.tail_start) {
            self.request_required(loaded..end.min(self.tail_start), Purpose::Probe)?;
            return Ok(false);
        }
        if loaded < end {
            self.accounting.charge(end - loaded)?;
            let from = (loaded - self.tail_start) as usize;
            let to = (end - self.tail_start) as usize;
            self.probe.append(&self.tail[from..to]);
        }
        Ok(true)
    }

    fn reposition_probe(&mut self, start: u64) -> Result<(), DirectoryError> {
        let overlap = start.checked_sub(self.probe.start).filter(|&skip| skip < self.probe.len as u64);
        if let Some(skip) = overlap {
            let skip = skip as usize;
            self.accounting.charge((self.probe.len - skip) as u64)?;
            self.probe.bytes.copy_within(skip..self.probe.len, 0);
            self.probe.len -= skip;
        } else {
            self.probe.len = 0;
        }
        self.probe.start = start;
        Ok(())
    }

    fn fixed_bytes(&self, start: u64, len: usize) -> &[u8] {
        if start >= self.tail_start {
            let i = (start - self.tail_start) as usize;
            &self.tail[i..i + len]
        } else {
            debug_assert_eq!(self.probe.start, start);
            &self.probe.bytes[..len]
        }
    }

    fn locate_directory(&mut self) -> Result<(), DirectoryError> {
        let candidate = self.candidate();
        let declaration = candidate.declaration();
        let anchor = candidate.anchor();
        if candidate.zip64.is_none() && declaration.offset == u64::from(u32::MAX) {
            return self.reject(DirectoryError::MalformedZip64);
        }

        self.accounting.check_directory(declaration)?;
        let empty = declaration.entries == 0;
        let start = if self.stage == Stage::Declared && !empty {
            declaration.offset
        } else {
            let Some(start) = anchor.checked_sub(declaration.size).filter(|&start| start >= declaration.offset) else {
                return self.reject(candidate.geometry_error());
            };
            start
        };

        // A tolerant declared-first lookup can use an undersold size. Its
        // first fixed header must still fit before the end records.
        let Some(end) = start.checked_add(declaration.size).filter(|&end| end <= anchor) else {
            return self.bad_central(empty);
        };
        if empty {
            return self.select_directory(start..end, declaration, None);
        }
        let bound = if self.profile == Profile::Zipfast { end } else { anchor };
        if start.checked_add(CENTRAL_HEADER_LEN as u64).is_none_or(|end| end > bound) {
            return self.bad_central(false);
        }

        if !self.fixed(start, 4)? {
            return Ok(());
        }
        self.accounting.charge(CANDIDATE_WORK)?;
        if le32(self.fixed_bytes(start, 4), 0) == CENTRAL_SIG {
            self.stage = Stage::FirstHeader { start, end, declaration };
            Ok(())
        } else {
            self.bad_central(false)
        }
    }

    fn first_header(&mut self, start: u64, end: u64, declaration: DirectoryDeclaration) -> Result<(), DirectoryError> {
        if !self.fixed(start, CENTRAL_HEADER_LEN)? {
            return Ok(());
        }
        self.accounting.charge(CENTRAL_FIXED_WORK)?;
        let header = CentralHeader::parse(self.fixed_bytes(start, CENTRAL_HEADER_LEN))?;
        self.select_directory(start..end, declaration, Some(header))
    }

    fn bad_central(&mut self, empty: bool) -> Result<(), DirectoryError> {
        let candidate = self.candidate();
        let alternate = self.stage == Stage::Declared
            && !empty
            && candidate.anchor().checked_sub(candidate.declaration().size) != Some(candidate.declaration().offset);
        if alternate {
            self.stage = Stage::Anchored;
            Ok(())
        } else {
            self.reject(candidate.geometry_error())
        }
    }

    fn reject(&mut self, error: DirectoryError) -> Result<(), DirectoryError> {
        if self.end_offset.is_some() || self.candidate().zip64.is_some() {
            return Err(error);
        }
        if self.rejected.is_none() {
            self.rejected = Some(error);
        }
        self.candidate = None;
        self.stage = Stage::Candidate;
        self.recovery = Recovery::default();
        Ok(())
    }

    fn select_directory(
        &mut self,
        directory: Range<u64>,
        declaration: DirectoryDeclaration,
        first_header: Option<CentralHeader>,
    ) -> Result<(), DirectoryError> {
        if self.profile == Profile::Zipfast && self.candidate().unsupported_disk() {
            return Err(DirectoryError::UnsupportedDisk);
        }
        let comment = self.candidate().comment.clone();
        let start = (comment.start - self.tail_start) as usize;
        let end = (comment.end - self.tail_start) as usize;
        let comment = self.accounting.own_comment(&self.tail[start..end])?;
        let first_probe =
            (first_header.is_some() && directory.start < self.tail_start).then(|| mem::take(&mut self.probe));
        let shift = directory.start - declaration.offset;
        self.location = Some(DirectoryLocation {
            candidate: self.candidate.take().expect("selected candidate"),
            declaration,
            directory,
            shift,
            comment,
            accounting: self.accounting,
            tail_start: self.tail_start,
            tail: mem::take(&mut self.tail),
            first_header,
            first_probe,
        });
        self.stage = Stage::Done;
        Ok(())
    }
}

impl fmt::Debug for EndDiscovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndDiscovery")
            .field("len", &self.len)
            .field("profile", &self.profile)
            .field("stage", &self.stage)
            .field("pending", &self.pending)
            .field("usage", &self.usage())
            .field("buffers", &self.buffer_usage())
            .finish_non_exhaustive()
    }
}

/// Discovers a ZIP directory from a slice using the incremental source protocol.
///
/// The driver lends borrowed subslices directly and accounts for the same
/// source ranges as a range caller supplying complete requests.
///
/// ```
/// use zip_container::{Limits, Profile, discover_slice};
///
/// let mut archive = [0; 22];
/// archive[..4].copy_from_slice(b"PK\x05\x06");
/// let directory = discover_slice(&archive, Profile::Zipfast, Limits::default())?;
/// assert_eq!(directory.directory_range(), 0..0);
/// # Ok::<(), zip_container::DirectoryError>(())
/// ```
pub fn discover_slice(bytes: &[u8], profile: Profile, limits: Limits) -> Result<DirectoryLocation, DirectoryError> {
    let mut discovery = EndDiscovery::new(bytes.len() as u64, profile, limits)?;
    while let Some(range) = discovery.next_read()? {
        discovery.supply(range.start, &bytes[range.start as usize..range.end as usize])?;
    }
    discovery.finish()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Tail,
    Candidate,
    Pointer,
    Fast,
    Recovery,
    Declared,
    Anchored,
    FirstHeader { start: u64, end: u64, declaration: DirectoryDeclaration },
    Done,
    Failed(DirectoryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rank {
    Exact,
    Trailing,
    Clipped,
}

#[derive(Clone, Copy, Debug)]
enum Purpose {
    Tail,
    Probe,
    Recovery,
}

#[derive(Clone, Debug)]
struct Pending {
    range: Range<u64>,
    next: u64,
    purpose: Purpose,
}

#[derive(Clone, Debug)]
struct Candidate {
    end: EndRecord,
    locator: Option<Zip64Locator>,
    zip64: Option<Zip64End>,
    comment: Range<u64>,
}

impl Candidate {
    fn declaration(&self) -> DirectoryDeclaration {
        self.zip64.as_ref().map_or(
            DirectoryDeclaration {
                entries: self.end.entries.into(),
                size: self.end.size.into(),
                offset: self.end.offset.into(),
            },
            |record| record.declaration,
        )
    }

    fn anchor(&self) -> u64 {
        self.zip64.as_ref().map_or(self.end.source.start, |record| record.source.start)
    }

    fn geometry_error(&self) -> DirectoryError {
        if self.zip64.is_some() { DirectoryError::MalformedZip64 } else { DirectoryError::MalformedEnd }
    }

    fn unsupported_disk(&self) -> bool {
        self.end.disk != 0
            || self.end.directory_disk != 0
            || self.locator.as_ref().is_some_and(|locator| locator.total_disks > 1)
            || self.zip64.as_ref().is_some_and(|record| record.disk != 0 || record.directory_disk != 0)
    }
}

#[derive(Clone, Debug)]
struct FixedProbe {
    start: u64,
    len: usize,
    bytes: [u8; END64_LEN],
}

impl Default for FixedProbe {
    fn default() -> Self {
        Self { start: 0, len: 0, bytes: [0; END64_LEN] }
    }
}

impl FixedProbe {
    fn append(&mut self, bytes: &[u8]) {
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
    }
}

#[derive(Clone, Debug)]
struct Recovery {
    end: u64,
    overlap: [u8; END64_LEN - 1],
    overlap_len: usize,
    partial: Vec<u8>,
}

impl Default for Recovery {
    fn default() -> Self {
        Self { end: 0, overlap: [0; END64_LEN - 1], overlap_len: 0, partial: Vec::new() }
    }
}

fn framed_zip64(bytes: &[u8], start: u64, locator: u64) -> Option<Zip64End> {
    if !bytes.starts_with(&END64_SIG) {
        return None;
    }
    let body_size = le64(bytes, 4);
    if body_size < 44 || start.checked_add(12)?.checked_add(body_size)? != locator {
        return None;
    }
    Some(Zip64End {
        source: start..locator,
        extension: start + END64_LEN as u64..locator,
        body_size,
        version_made_by: le16(bytes, 12),
        version_needed: le16(bytes, 14),
        disk: le32(bytes, 16),
        directory_disk: le32(bytes, 20),
        disk_entries: le64(bytes, 24),
        declaration: DirectoryDeclaration { entries: le64(bytes, 32), size: le64(bytes, 40), offset: le64(bytes, 48) },
    })
}

#[derive(Clone, Copy, Debug)]
struct Accounting {
    limits: Limits,
    ownership_limits: OwnershipUsage,
    usage: Usage,
}

impl Accounting {
    fn new(limits: Limits) -> Result<Self, DirectoryError> {
        let capacity = |value, kind| usize::try_from(value).map_err(|_| DirectoryError::Limit(kind));
        let ownership_limits = OwnershipUsage {
            entries: capacity(limits.entries, LimitKind::Entries)?,
            name_bytes: capacity(limits.name_bytes, LimitKind::NameBytes)?,
            extra_bytes: capacity(limits.extra_bytes, LimitKind::ExtraBytes)?,
            comment_bytes: capacity(limits.comment_bytes, LimitKind::CommentBytes)?,
        };
        Ok(Self { limits, ownership_limits, usage: Usage::default() })
    }

    fn check_fetched(&self, additional: u64) -> Result<(), DirectoryError> {
        check_remaining(self.usage.fetched_bytes, additional, self.limits.fetched_bytes, LimitKind::FetchedBytes)
    }

    fn check_work(&self, additional: u64) -> Result<(), DirectoryError> {
        check_remaining(self.usage.work_units, additional, self.limits.work_units, LimitKind::WorkUnits)
    }

    fn charge(&mut self, additional: u64) -> Result<(), DirectoryError> {
        self.check_work(additional)?;
        self.usage.work_units += additional;
        Ok(())
    }

    fn check_directory(&self, declaration: DirectoryDeclaration) -> Result<(), DirectoryError> {
        check_remaining(0, declaration.size, self.limits.directory_bytes, LimitKind::DirectoryBytes)?;
        check_remaining(0, declaration.entries, self.limits.entries, LimitKind::Entries)
    }

    fn own_comment(&mut self, bytes: &[u8]) -> Result<Vec<u8>, DirectoryError> {
        if bytes.len() > self.ownership_limits.comment_bytes - self.usage.owned.comment_bytes {
            return Err(DirectoryError::Limit(LimitKind::CommentBytes));
        }
        self.charge(bytes.len() as u64)?;
        let mut comment = Vec::new();
        comment.try_reserve_exact(bytes.len()).map_err(|_| DirectoryError::Allocation)?;
        comment.extend_from_slice(bytes);
        self.usage.owned.comment_bytes += bytes.len();
        Ok(comment)
    }
}

fn check_remaining(used: u64, additional: u64, limit: u64, kind: LimitKind) -> Result<(), DirectoryError> {
    if additional > limit - used { Err(DirectoryError::Limit(kind)) } else { Ok(()) }
}
