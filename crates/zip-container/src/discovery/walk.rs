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

use std::{fmt, mem, ops::Range};

use crate::header::{add_offset, le32};
use crate::{
    CentralLocation, CentralRecord, CentralView, KnownExtrasView, OwnershipBudget, OwnershipUsage, ParseError,
    ResolvedFields, central_layout,
};

use super::{
    Accounting, BufferUsage, CENTRAL_FIXED_WORK, CENTRAL_HEADER_LEN, CENTRAL_SIG, CentralHeader, DirectoryDeclaration,
    DirectoryError, DirectoryLocation, EndDiscovery, EndRecord, LimitKind, Limits, Profile, SupplyError, Usage,
    Zip64End, Zip64Locator, reducers,
};

/// Ordered central metadata and checked geometry for one archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory<T = CentralRecord> {
    /// Central records in wire order, including duplicate names.
    pub entries: Vec<T>,
    /// Byte length of the source used for this parse.
    pub archive_len: u64,
    /// Raw fields and source range of the selected classic end record.
    pub end_record: EndRecord,
    /// Adjacent ZIP64 locator considered by discovery, if present.
    pub zip64_locator: Option<Zip64Locator>,
    /// Selected ZIP64 end record, if present.
    pub zip64_end: Option<Zip64End>,
    /// Effective directory count, size, and offset as stored.
    pub declaration: DirectoryDeclaration,
    /// Declared directory range at the selected physical start.
    pub directory_range: Range<u64>,
    /// Available bytes of the central records actually parsed.
    pub observed_range: Range<u64>,
    /// Parsed record extent including any unavailable declared comment suffix.
    pub logical_range: Range<u64>,
    /// Adjustment from stored ZIP-relative offsets to physical offsets.
    pub prefix_shift: u64,
    /// Source range of the available archive comment.
    pub comment_range: Range<u64>,
    /// Available archive comment bytes before decoding.
    pub raw_comment: Vec<u8>,
    /// Final cumulative discovery and walk usage.
    pub usage: Usage,
    profile: Profile,
}

impl<T> Directory<T> {
    /// Whether the archive-level disk declarations use one address space.
    ///
    /// Each entry's own disk number and offset still need validation.
    pub fn local_addresses_are_single_disk(&self) -> bool {
        self.end_record.disk == 0
            && self.end_record.directory_disk == 0
            && self.end_record.disk_entries == self.end_record.entries
            && self.zip64_locator.as_ref().is_none_or(|locator| locator.disk == 0 && locator.total_disks <= 1)
            && self.zip64_end.as_ref().is_none_or(|record| {
                record.disk == 0 && record.directory_disk == 0 && record.disk_entries == record.declaration.entries
            })
    }
}

impl Directory<CentralRecord> {
    /// Checks the physical start address of the indexed record's local header.
    ///
    /// Zipview can list split or unresolved entries without a usable address.
    /// Reading a local header or payload still requires validating its ranges
    /// and checking the resolved lengths needed by the operation.
    pub fn physical_local_header_offset(&self, index: usize) -> Option<u64> {
        let entry = self.entries.get(index)?;
        if self.profile == Profile::Zipview
            && (entry.resolved.unresolved.disk_start
                || entry.resolved.disk_start != 0
                || !self.local_addresses_are_single_disk())
        {
            return None;
        }
        physical_offset(entry.resolved, self.prefix_shift, self.archive_len)
    }
}

fn physical_offset(resolved: ResolvedFields, shift: u64, archive_len: u64) -> Option<u64> {
    if resolved.unresolved.local_header_offset {
        return None;
    }
    resolved.local_header_offset.checked_add(shift).filter(|&offset| offset < archive_len)
}

/// One borrowed central record after the walk's structural and profile checks.
pub struct ReducedCentralRecord<'a> {
    view: CentralView<'a>,
    resolved: ResolvedFields,
    known: KnownExtrasView<'a>,
}

impl<'a> ReducedCentralRecord<'a> {
    /// Original header, raw body fields and source location.
    pub fn view(&self) -> &CentralView<'a> {
        &self.view
    }

    /// Central values resolved according to the selected profile.
    pub fn resolved(&self) -> ResolvedFields {
        self.resolved
    }

    /// Known extras selected according to the profile.
    pub fn known(&self) -> KnownExtrasView<'a> {
        self.known
    }
}

/// Trusted function that converts a checked, borrowed record to owned output.
///
/// Allocate only the returned record, report allocation failures, and avoid
/// external side effects. The parser bounds its own work and storage. A
/// projection controls its own allocation and work, and the parser cannot
/// roll back its effects. The result cannot borrow the supplied input window.
pub type RecordProjection<T> = for<'a> fn(ReducedCentralRecord<'a>) -> Result<T, DirectoryError>;

/// Incrementally discovers and walks a ZIP directory over a source of known length.
///
/// Requests are absolute half-open ranges. Supply a contiguous prefix of the
/// current request, or drop the parser to cancel between requests. Complete
/// central records are consumed directly from the borrowed input.
#[derive(Clone)]
pub struct DirectoryParser<T = CentralRecord> {
    state: State<T>,
    profile: Profile,
    name_crc32: fn(&[u8]) -> u32,
    projection: RecordProjection<T>,
}

impl<T> fmt::Debug for DirectoryParser<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectoryParser")
            .field("state", &self.state)
            .field("profile", &self.profile)
            .field("name_crc32", &self.name_crc32)
            .finish()
    }
}

// Both live variants are small and kept inline so startup needs no heap allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum State<T> {
    Discovery(EndDiscovery),
    Walk(Walk<T>),
    HandoffFailure(DirectoryError, Usage),
}

impl<T> fmt::Debug for State<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(discovery) => f.debug_tuple("Discovery").field(discovery).finish(),
            Self::Walk(walk) => f.debug_tuple("Walk").field(walk).finish(),
            Self::HandoffFailure(error, usage) => f.debug_tuple("HandoffFailure").field(error).field(usage).finish(),
        }
    }
}

impl DirectoryParser<CentralRecord> {
    /// Creates a parser using the built-in IEEE CRC-32 for Unicode path extras.
    pub fn new(archive_len: u64, profile: Profile, limits: Limits) -> Result<Self, DirectoryError> {
        Self::with_name_crc32(archive_len, profile, limits, reducers::ieee_crc32)
    }

    /// Creates a strict parser that considers only the classic end record at
    /// `end_offset`, an absolute byte offset. That record's complete comment
    /// must end at `archive_len`. The normal ZIP64 and directory validation
    /// still apply, and an invalid anchor cannot select a different end record.
    pub fn at_eocd(archive_len: u64, end_offset: u64, limits: Limits) -> Result<Self, DirectoryError> {
        let profile = Profile::Zipfast;
        Ok(Self {
            state: State::Discovery(EndDiscovery::with_end_offset(archive_len, profile, limits, Some(end_offset))?),
            profile,
            name_crc32: reducers::ieee_crc32,
            projection: materialize_record,
        })
    }

    /// Creates a parser using the supplied IEEE CRC-32 function for raw names.
    ///
    /// The function is used at most once per raw name with an eligible Unicode
    /// path candidate under Zipfast. Zipview retains the raw extra source range
    /// and skips the Unicode path projection. The callback never checks payloads.
    pub fn with_name_crc32(
        archive_len: u64,
        profile: Profile,
        limits: Limits,
        name_crc32: fn(&[u8]) -> u32,
    ) -> Result<Self, DirectoryError> {
        Self::with_projection_and_name_crc32(archive_len, profile, limits, name_crc32, materialize_record)
    }
}

impl<T> DirectoryParser<T> {
    /// Creates a parser that owns one projected value per admitted record.
    ///
    /// Records become available through [`Self::finish`] after the directory
    /// walk completes. See [`RecordProjection`] for the callback contract.
    pub fn with_projection(
        archive_len: u64,
        profile: Profile,
        limits: Limits,
        projection: RecordProjection<T>,
    ) -> Result<Self, DirectoryError> {
        Self::with_projection_and_name_crc32(archive_len, profile, limits, reducers::ieee_crc32, projection)
    }

    /// Creates a projected parser using the supplied IEEE CRC-32 for raw names.
    ///
    /// The CRC function follows [`DirectoryParser::with_name_crc32`]'s policy.
    pub fn with_projection_and_name_crc32(
        archive_len: u64,
        profile: Profile,
        limits: Limits,
        name_crc32: fn(&[u8]) -> u32,
        projection: RecordProjection<T>,
    ) -> Result<Self, DirectoryError> {
        Ok(Self {
            state: State::Discovery(EndDiscovery::new(archive_len, profile, limits)?),
            profile,
            name_crc32,
            projection,
        })
    }

    /// Progresses until the parser needs source bytes or reaches completion.
    ///
    /// Polling an unchanged pending request or a terminal state does no work.
    pub fn next_read(&mut self) -> Result<Option<Range<u64>>, DirectoryError> {
        if let State::Discovery(discovery) = &mut self.state {
            if let Some(request) = discovery.next_read()? {
                return Ok(Some(request));
            }
            let location = discovery.location.take().expect("completed discovery has a location");
            let usage = location.usage();
            self.state = match Walk::new(location, self.profile, self.name_crc32, self.projection) {
                Ok(walk) => State::Walk(walk),
                Err(error) => State::HandoffFailure(error, usage),
            };
        }
        match &mut self.state {
            State::Walk(walk) => walk.next_read(),
            State::HandoffFailure(error, _) => Err(*error),
            State::Discovery(_) => unreachable!("discovery has completed"),
        }
    }

    /// Supplies a contiguous prefix of the pending request.
    ///
    /// An empty in-bounds supply is a no-op. Rejected caller input leaves the
    /// pending request, parse progress, and usage unchanged.
    pub fn supply(&mut self, offset: u64, bytes: &[u8]) -> Result<(), DirectoryError> {
        match &mut self.state {
            State::Discovery(discovery) => discovery.supply(offset, bytes),
            State::Walk(walk) => walk.supply(offset, bytes),
            State::HandoffFailure(error, _) => Err(*error),
        }
    }

    /// Returns the owned directory if parsing can finish with the bytes supplied.
    pub fn finish(mut self) -> Result<Directory<T>, DirectoryError> {
        if self.next_read()?.is_some() {
            return Err(DirectoryError::Incomplete);
        }
        match self.state {
            State::Walk(walk) => Ok(walk.directory),
            State::Discovery(_) | State::HandoffFailure(..) => unreachable!("walk has completed"),
        }
    }

    /// Current cumulative source, work and metadata counters.
    pub fn usage(&self) -> Usage {
        match &self.state {
            State::Discovery(discovery) => discovery.usage(),
            State::Walk(walk) => walk.accounting.usage,
            State::HandoffFailure(_, usage) => *usage,
        }
    }

    /// Current scratch lengths and capacities, excluding output and caller storage.
    pub fn buffer_usage(&self) -> BufferUsage {
        match &self.state {
            State::Discovery(discovery) => discovery.buffer_usage(),
            State::Walk(walk) => BufferUsage {
                live_bytes: walk.tail.len() + walk.scratch.len(),
                capacity_bytes: walk.tail.capacity() + walk.scratch.capacity(),
            },
            State::HandoffFailure(..) => BufferUsage::default(),
        }
    }
}

/// Parses a ZIP directory using borrowed subslices and the same range protocol.
///
/// ```
/// use zip_container::{Limits, Profile, parse_slice};
///
/// let mut empty = [0; 22];
/// empty[..4].copy_from_slice(b"PK\x05\x06");
/// let directory = parse_slice(&empty, Profile::Zipfast, Limits::default())?;
/// assert!(directory.entries.is_empty());
/// # Ok::<(), zip_container::DirectoryError>(())
/// ```
pub fn parse_slice(bytes: &[u8], profile: Profile, limits: Limits) -> Result<Directory, DirectoryError> {
    parse_slice_projected(bytes, profile, limits, materialize_record)
}

/// Parses a ZIP directory from a slice, projecting each admitted central record.
///
/// Uses the same requests, checks and raw admission charges as [`parse_slice`].
/// See [`RecordProjection`] for the callback contract.
pub fn parse_slice_projected<T>(
    bytes: &[u8],
    profile: Profile,
    limits: Limits,
    projection: RecordProjection<T>,
) -> Result<Directory<T>, DirectoryError> {
    let mut parser = DirectoryParser::with_projection(bytes.len() as u64, profile, limits, projection)?;
    while let Some(range) = parser.next_read()? {
        parser.supply(range.start, &bytes[range.start as usize..range.end as usize])?;
    }
    parser.finish()
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    First(CentralHeader),
    Signature,
    Fixed,
    Body { header: CentralHeader, source: CentralLocation },
    Done,
    Failed(DirectoryError),
}

struct Walk<T> {
    directory: Directory<T>,
    accounting: Accounting,
    ownership: OwnershipBudget,
    name_crc32: fn(&[u8]) -> u32,
    projection: RecordProjection<T>,
    phase: Phase,
    next: u64,
    pending: Option<Range<u64>>,
    tail_start: u64,
    tail: Vec<u8>,
    scratch: Vec<u8>,
}

impl<T: Clone> Clone for Walk<T> {
    fn clone(&self) -> Self {
        // Scratch capacity decides whether the next partial supply preflights
        // the cost of growing it. Preserve that decision across a clone.
        let mut scratch = Vec::with_capacity(self.scratch.capacity());
        scratch.extend_from_slice(&self.scratch);
        Self {
            directory: self.directory.clone(),
            accounting: self.accounting,
            ownership: self.ownership.clone(),
            name_crc32: self.name_crc32,
            projection: self.projection,
            phase: self.phase,
            next: self.next,
            pending: self.pending.clone(),
            tail_start: self.tail_start,
            tail: self.tail.clone(),
            scratch,
        }
    }
}

impl<T> Walk<T> {
    fn new(
        location: DirectoryLocation,
        profile: Profile,
        name_crc32: fn(&[u8]) -> u32,
        projection: RecordProjection<T>,
    ) -> Result<Self, DirectoryError> {
        let archive_len = location.archive_len();
        let DirectoryLocation {
            candidate,
            declaration,
            directory,
            shift,
            comment,
            accounting,
            tail_start,
            tail,
            first_header,
            ..
        } = location;
        let start = directory.start;
        let ownership = OwnershipBudget::resume(accounting.ownership_limits, accounting.usage.owned)?;
        Ok(Self {
            directory: Directory {
                entries: Vec::new(),
                archive_len,
                end_record: candidate.end,
                zip64_locator: candidate.locator,
                zip64_end: candidate.zip64,
                declaration,
                directory_range: directory,
                observed_range: start..start,
                logical_range: start..start,
                prefix_shift: shift,
                comment_range: candidate.comment,
                raw_comment: comment,
                usage: Usage::default(),
                profile,
            },
            accounting,
            ownership,
            name_crc32,
            projection,
            phase: first_header.map_or(Phase::Signature, Phase::First),
            next: start,
            pending: None,
            tail_start,
            tail,
            scratch: Vec::new(),
        })
    }

    fn next_read(&mut self) -> Result<Option<Range<u64>>, DirectoryError> {
        if self.pending.is_none() {
            let result = self.advance();
            self.cache_failure(result)?;
        }
        Ok(self.pending.clone())
    }

    fn supply(&mut self, offset: u64, bytes: &[u8]) -> Result<(), DirectoryError> {
        let size = bytes.len() as u64;
        let end = offset
            .checked_add(size)
            .filter(|&end| end <= self.directory.archive_len)
            .ok_or(DirectoryError::Supply(SupplyError::OutOfBounds))?;
        if bytes.is_empty() {
            return Ok(());
        }
        if let Phase::Failed(error) = self.phase {
            return Err(error);
        }
        let pending = self.pending.as_ref().ok_or(DirectoryError::Supply(SupplyError::Unsolicited))?;
        if offset != pending.start {
            return Err(DirectoryError::Supply(SupplyError::UnexpectedOffset));
        }
        if end > pending.end {
            return Err(DirectoryError::Supply(SupplyError::Overlong));
        }
        let pending_end = pending.end;
        debug_assert_eq!(self.next, offset);
        let result = self.accounting.charge(size);
        self.cache_failure(result)?;
        self.accounting.usage.fetched_bytes += size;
        let result = self.consume_window(bytes, false);
        self.cache_failure(result)?;
        self.pending = (end < pending_end && !matches!(self.phase, Phase::Done)).then_some(end..pending_end);
        Ok(())
    }

    fn cache_failure(&mut self, result: Result<(), DirectoryError>) -> Result<(), DirectoryError> {
        if let Err(error) = result {
            self.phase = Phase::Failed(error);
            self.pending = None;
            self.release_scratch();
        }
        result
    }

    fn advance(&mut self) -> Result<(), DirectoryError> {
        if let Phase::First(header) = self.phase {
            // Discovery already decoded the fixed header and charged its work.
            // Advance past it, including any portion in the external probe.
            self.next += CENTRAL_HEADER_LEN as u64;
            self.start_body(header)?;
        }
        loop {
            let Some(need) = self.required_part()? else {
                return Ok(());
            };
            let missing = (need - self.scratch.len()) as u64;
            if missing == 0 {
                self.consume_window(&[], false)?;
            } else if self.next >= self.tail_start {
                let from = (self.next - self.tail_start) as usize;
                let to = (self.available_end() - self.tail_start) as usize;
                let tail = mem::take(&mut self.tail);
                self.consume_window(&tail[from..to], true)?;
            } else {
                self.request(missing)?;
                return Ok(());
            }
        }
    }

    fn request(&mut self, required: u64) -> Result<(), DirectoryError> {
        let required_end = add_offset(self.next, required)?.min(self.tail_start);
        let external = required_end - self.next;
        let limits = self.accounting.limits;
        self.accounting.check_fetched(external)?;
        let needs_scratch = !self.scratch.is_empty() || external < required || limits.range_bytes < external;
        let part_work = self.minimum_part_work() + if needs_scratch { required } else { 0 };
        self.accounting.check_work(required + part_work)?;
        let usage = self.accounting.usage;
        let available = limits
            .range_bytes
            .min(limits.fetched_bytes - usage.fetched_bytes)
            .min(limits.work_units - usage.work_units - part_work);
        if available == 0 {
            return Err(DirectoryError::Limit(LimitKind::RangeBytes));
        }
        let entries_left = self.directory.declaration.entries - self.directory.entries.len() as u64;
        let end = match (self.phase, entries_left) {
            // Once the final body is known, request at most its bytes and then
            // the strict profile's single trailer signature.
            (Phase::Body { .. }, 1) | (Phase::Signature, 0) => required_end,
            _ => self.directory.directory_range.end.max(required_end).min(self.tail_start),
        };
        let end = self.next + (end - self.next).min(available);
        self.charge_extent(end)?;
        self.pending = Some(self.next..end);
        Ok(())
    }

    fn consume_window(&mut self, mut bytes: &[u8], cached: bool) -> Result<(), DirectoryError> {
        while let Some(need) = self.required_part()? {
            if self.scratch.is_empty() && bytes.len() >= need {
                if matches!(self.phase, Phase::Signature) && bytes.len() >= CENTRAL_HEADER_LEN {
                    bytes = self.consume_contiguous_record(bytes, cached)?;
                } else {
                    let (part, remainder) = bytes.split_at(need);
                    self.advance_borrowed(need, cached)?;
                    self.consume_part(part)?;
                    bytes = remainder;
                }
            } else {
                let missing = need - self.scratch.len();
                let take = missing.min(bytes.len());
                if take == 0 {
                    break;
                }
                // Before growing scratch, check the work needed for all its
                // copies, the remaining input pass and the known work on completion.
                let driver_bytes = if cached { missing } else { missing - take };
                let charge = (take + if cached { take } else { 0 }) as u64;
                if need > self.scratch.capacity() {
                    self.accounting.check_work((missing + driver_bytes) as u64 + self.minimum_part_work())?;
                    self.accounting.charge(charge)?;
                    self.scratch.try_reserve_exact(missing).map_err(|_| DirectoryError::Allocation)?;
                } else {
                    self.accounting.charge(charge)?;
                }
                self.scratch.extend_from_slice(&bytes[..take]);
                self.next += take as u64;
                bytes = &bytes[take..];
                if take != missing {
                    break;
                }
                let mut scratch = mem::take(&mut self.scratch);
                self.consume_part(&scratch)?;
                scratch.clear();
                if !matches!(self.phase, Phase::Done) {
                    self.scratch = scratch;
                }
            }
        }
        Ok(())
    }

    // Keep the checked fixed header and layout local when the record is
    // borrowed. Store them in the phase only when a later supply is needed.
    fn consume_contiguous_record<'a>(&mut self, bytes: &'a [u8], cached: bool) -> Result<&'a [u8], DirectoryError> {
        let (fixed, remainder) = bytes.split_at(CENTRAL_HEADER_LEN);
        self.advance_borrowed(4, cached)?;
        if !self.check_signature(&fixed[..4])? {
            self.complete();
            return Ok(&[]);
        }
        self.advance_borrowed(CENTRAL_HEADER_LEN - 4, cached)?;
        let header = self.decode_fixed(&fixed[4..])?;
        let source = self.check_body(header)?;
        let need = self.body_len(source);
        if remainder.len() < need {
            self.phase = Phase::Body { header, source };
            return Ok(remainder);
        }
        let (body, remainder) = remainder.split_at(need);
        self.advance_borrowed(need, cached)?;
        self.consume_body(header, source, body)?;
        Ok(remainder)
    }

    fn advance_borrowed(&mut self, len: usize, cached: bool) -> Result<(), DirectoryError> {
        if cached {
            self.accounting.charge(len as u64)?;
        }
        self.next += len as u64;
        Ok(())
    }

    // Each input part has a fixed target length once its phase begins. Progress
    // through a partial part uses only its current length and these scalars.
    fn required_part(&mut self) -> Result<Option<usize>, DirectoryError> {
        let start = self.directory.logical_range.end;
        let bound = self.available_end();
        let need = match self.phase {
            Phase::Signature => {
                let reached = self.directory.entries.len() as u64 == self.directory.declaration.entries;
                let available = bound.saturating_sub(start);
                if reached && (self.directory.profile == Profile::Zipview || available < 4) {
                    self.complete();
                    return Ok(None);
                }
                if available < 4 {
                    return if self.directory.profile == Profile::Zipfast {
                        Err(self.count_error(false))
                    } else {
                        Err(ParseError::Truncated { offset: start, needed: 4, available }.into())
                    };
                }
                self.charge_extent(start + 4)?;
                4
            }
            Phase::Fixed => CENTRAL_HEADER_LEN - 4,
            Phase::Body { source, .. } => self.body_len(source),
            Phase::Done => return Ok(None),
            Phase::Failed(error) => return Err(error),
            Phase::First(_) => unreachable!("first header is supplied by discovery"),
        };
        Ok(Some(need))
    }

    fn consume_part(&mut self, bytes: &[u8]) -> Result<(), DirectoryError> {
        match self.phase {
            Phase::Signature => {
                if self.check_signature(bytes)? {
                    self.phase = Phase::Fixed;
                } else {
                    self.complete();
                }
            }
            Phase::Fixed => {
                let header = self.decode_fixed(bytes)?;
                self.start_body(header)?;
            }
            Phase::Body { header, source } => self.consume_body(header, source, bytes)?,
            _ => unreachable!("only walk input phases consume bytes"),
        }
        Ok(())
    }

    fn check_signature(&mut self, bytes: &[u8]) -> Result<bool, DirectoryError> {
        let central = le32(bytes, 0) == CENTRAL_SIG;
        let reached = self.directory.entries.len() as u64 == self.directory.declaration.entries;
        if self.directory.profile == Profile::Zipfast && central == reached {
            return Err(self.count_error(central));
        }
        if central {
            let start = self.directory.logical_range.end;
            let available = self.available_end() - start;
            if available < CENTRAL_HEADER_LEN as u64 {
                return Err(
                    ParseError::Truncated { offset: start, needed: CENTRAL_HEADER_LEN as u64, available }.into()
                );
            }
            self.charge_extent(start + CENTRAL_HEADER_LEN as u64)?;
        }
        Ok(central)
    }

    fn decode_fixed(&mut self, bytes: &[u8]) -> Result<CentralHeader, DirectoryError> {
        self.accounting.charge(CENTRAL_FIXED_WORK)?;
        Ok(CentralHeader::decode_fields(bytes))
    }

    fn body_len(&self, source: CentralLocation) -> usize {
        (source.raw_range().end - self.directory.logical_range.end) as usize - CENTRAL_HEADER_LEN
    }

    fn start_body(&mut self, header: CentralHeader) -> Result<(), DirectoryError> {
        let source = self.check_body(header)?;
        self.phase = Phase::Body { header, source };
        Ok(())
    }

    fn check_body(&mut self, header: CentralHeader) -> Result<CentralLocation, DirectoryError> {
        let start = self.directory.logical_range.end;
        let bound = self.available_end();
        let source = central_layout(header, start, bound)?;
        let logical_end = source.declared_range().end;
        if self.directory.profile == Profile::Zipfast && logical_end > bound {
            return Err(ParseError::Truncated {
                offset: source.comment_range().start,
                needed: u64::from(header.comment_len),
                available: u64::from(source.available_comment_len()),
            }
            .into());
        }
        self.charge_extent(logical_end)?;
        self.ownership.check(OwnershipUsage {
            entries: 1,
            name_bytes: usize::from(header.name_len),
            comment_bytes: usize::from(source.available_comment_len()),
            extra_bytes: 0,
        })?;
        Ok(source)
    }

    fn consume_body(
        &mut self,
        header: CentralHeader,
        source: CentralLocation,
        bytes: &[u8],
    ) -> Result<(), DirectoryError> {
        let view = CentralView::from_layout(header, source, bytes);
        self.project_record(view)?;
        self.directory.observed_range.end = source.raw_range().end;
        self.directory.logical_range.end = source.declared_range().end;
        self.phase = Phase::Signature;
        Ok(())
    }

    fn minimum_part_work(&self) -> u64 {
        match self.phase {
            Phase::Fixed => CENTRAL_FIXED_WORK,
            Phase::Body { header, source } => u64::from(header.name_len) + u64::from(source.available_comment_len()),
            _ => 0,
        }
    }

    fn project_record(&mut self, view: CentralView<'_>) -> Result<(), DirectoryError> {
        let profile = self.directory.profile;
        let (resolved, known) = reducers::reduce(&view, profile, self.name_crc32, &mut self.accounting)?;
        if profile == Profile::Zipfast {
            if !matches!(view.header().disk_start, 0 | u16::MAX) {
                return Err(DirectoryError::UnsupportedDisk);
            }
            if physical_offset(resolved, self.directory.prefix_shift, self.directory.archive_len).is_none() {
                return Err(DirectoryError::InvalidLocalOffset);
            }
        }
        let charge = view.ownership_charge(known);
        let owned_bytes = charge.name_bytes + charge.comment_bytes + charge.extra_bytes;
        self.accounting.charge(owned_bytes as u64)?;
        let next_owned = self.ownership.check(charge)?;
        let entry = (self.projection)(ReducedCentralRecord { view, resolved, known })?;
        self.reserve_entry()?;
        self.directory.entries.push(entry);
        self.ownership.commit(next_owned);
        self.accounting.usage.owned = next_owned;
        Ok(())
    }

    fn reserve_entry(&mut self) -> Result<(), DirectoryError> {
        let len = self.directory.entries.len();
        if len == self.directory.entries.capacity() {
            // A declaration is a ceiling on incremental growth. Even the
            // tolerated directory cannot hold more fixed headers than fit.
            let plausible = (self.available_end() - self.directory.directory_range.start) / CENTRAL_HEADER_LEN as u64;
            let ceiling = self.directory.declaration.entries.min(plausible) as usize;
            let next = len.saturating_mul(2).max(4).min(ceiling);
            debug_assert!(next > len);
            #[cfg(test)]
            if tests::FAIL_OUTPUT_RESERVATION.replace(false) {
                return Err(DirectoryError::Allocation);
            }
            self.directory.entries.try_reserve_exact(next - len).map_err(|_| DirectoryError::Allocation)?;
        }
        Ok(())
    }

    fn count_error(&self, excess_signature: bool) -> DirectoryError {
        DirectoryError::EntryCount {
            declared: self.directory.declaration.entries,
            observed: self.directory.entries.len() as u64 + u64::from(excess_signature),
        }
    }

    fn charge_extent(&mut self, end: u64) -> Result<(), DirectoryError> {
        let extent = end - self.directory.directory_range.start;
        if extent > self.accounting.limits.directory_bytes {
            return Err(DirectoryError::Limit(LimitKind::DirectoryBytes));
        }
        self.accounting.usage.directory_bytes = self.accounting.usage.directory_bytes.max(extent);
        Ok(())
    }

    fn available_end(&self) -> u64 {
        match self.directory.profile {
            Profile::Zipfast => self.directory.directory_range.end,
            Profile::Zipview => self.directory.archive_len,
        }
    }

    fn complete(&mut self) {
        self.phase = Phase::Done;
        self.directory.usage = self.accounting.usage;
        self.release_scratch();
    }

    fn release_scratch(&mut self) {
        self.tail = Vec::new();
        self.scratch = Vec::new();
    }
}

fn materialize_record(record: ReducedCentralRecord<'_>) -> Result<CentralRecord, DirectoryError> {
    Ok(record.view.materialize(record.resolved, record.known)?)
}

impl<T> fmt::Debug for Walk<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Walk")
            .field("phase", &self.phase)
            .field("next", &self.next)
            .field("pending", &self.pending)
            .field("usage", &self.accounting.usage)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    thread_local! {
        pub(super) static FAIL_OUTPUT_RESERVATION: Cell<bool> = const { Cell::new(false) };
        static OUTPUT_DROPS: Cell<usize> = const { Cell::new(0) };
    }

    struct Output(u8);

    impl Drop for Output {
        fn drop(&mut self) {
            OUTPUT_DROPS.set(OUTPUT_DROPS.get() + 1);
        }
    }

    #[test]
    fn failed_output_reservation_drops_only_the_temporary_before_commit() {
        let mut bytes = Vec::new();
        for i in 0..5u8 {
            let mut fixed = [0; CENTRAL_HEADER_LEN];
            fixed[..4].copy_from_slice(b"PK\x01\x02");
            fixed[28] = 1; // name length
            bytes.extend(fixed);
            bytes.push(i);
        }
        let mut end = [0; 22];
        end[..4].copy_from_slice(b"PK\x05\x06");
        end[8] = 5;
        end[10] = 5;
        end[12..16].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        bytes.extend(end);

        let mut parser =
            DirectoryParser::with_projection(bytes.len() as u64, Profile::Zipfast, Limits::default(), |record| {
                let id = record.view().raw_name()[0];
                if id == 4 {
                    FAIL_OUTPUT_RESERVATION.set(true);
                }
                Ok(Output(id))
            })
            .unwrap();
        assert!(format!("{parser:?}").contains("Discovery"));
        assert_eq!(parser.next_read(), Ok(Some(0..bytes.len() as u64)));
        parser.supply(0, &bytes).unwrap();
        let error = DirectoryError::Allocation;
        assert_eq!(parser.next_read(), Err(error));
        assert_eq!(OUTPUT_DROPS.get(), 1);
        let State::Walk(walk) = &parser.state else { panic!("expected failed walk") };
        assert_eq!(walk.directory.entries.iter().map(|entry| entry.0).collect::<Vec<_>>(), [0, 1, 2, 3]);
        assert_eq!(walk.ownership.used(), OwnershipUsage { entries: 4, name_bytes: 4, ..OwnershipUsage::default() });
        assert_eq!(parser.usage().owned, walk.ownership.used());
        assert_eq!(parser.next_read(), Err(error));
        assert_eq!(parser.finish().err(), Some(error));
        assert_eq!(OUTPUT_DROPS.get(), 5);
    }
}
