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

use crate::{
    AesFields, CentralHeader, CentralLocation, CentralView, OwnershipError, OwnershipKind, UnicodePathView, Zip64Fields,
};

/// Central values widened or resolved by the caller's ZIP64 policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedFields {
    /// Uncompressed size.
    pub unpacked_size: u64,
    /// Compressed size.
    pub packed_size: u64,
    /// Stored relative local header offset, before any directory prefix shift.
    pub local_header_offset: u64,
    /// Start disk number.
    pub disk_start: u32,
    /// Which original sentinels still require resolution, independent of value.
    pub unresolved: Zip64Fields,
}

impl ResolvedFields {
    /// Widens wire values and marks each original ZIP64 sentinel as unresolved.
    pub fn from_header(header: CentralHeader) -> Self {
        Self {
            unpacked_size: u64::from(header.unpacked_size),
            packed_size: u64::from(header.packed_size),
            local_header_offset: u64::from(header.local_header_offset),
            disk_start: u32::from(header.disk_start),
            unresolved: Zip64Fields {
                unpacked_size: header.unpacked_size == u32::MAX,
                packed_size: header.packed_size == u32::MAX,
                local_header_offset: header.local_header_offset == u32::MAX,
                disk_start: header.disk_start == u16::MAX,
            },
        }
    }
}

/// One raw modification timestamp selected by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtraMtime {
    /// NTFS modification FILETIME.
    NtfsFiletime(u64),
    /// Signed seconds from the Unix epoch.
    UnixSeconds(i32),
}

/// Caller-selected known metadata, with a Unicode candidate from the same view.
#[derive(Clone, Copy, Debug, Default)]
pub struct KnownExtrasView<'a> {
    /// Selected raw AES fields.
    pub aes: Option<AesFields>,
    /// Selected modification timestamp.
    pub mtime_override: Option<ExtraMtime>,
    /// Selected borrowed Unicode path candidate.
    pub unicode_path: Option<UnicodePathView<'a>>,
}

/// Owned summary of the known extras selected by the caller.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KnownExtras {
    /// Selected raw AES fields.
    pub aes: Option<AesFields>,
    /// Selected modification timestamp.
    pub mtime_override: Option<ExtraMtime>,
    /// Bytes of the selected Unicode path, without its version and CRC prefix.
    pub unicode_path: Option<Box<[u8]>>,
}

/// Bounded owned central record with its raw source location.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CentralRecord {
    /// Original scalar header fields.
    pub header: CentralHeader,
    /// Caller-projected sizes, offset, and start disk.
    pub resolved: ResolvedFields,
    /// Absolute location of the original wire record.
    pub source: CentralLocation,
    /// Raw central name bytes.
    pub raw_name: Box<[u8]>,
    /// Available raw file comment bytes.
    pub raw_comment: Box<[u8]>,
    /// Caller-projected known extras.
    pub known: KnownExtras,
}

/// Entry count and per-category totals for variable-length owned bytes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OwnershipUsage {
    /// Number of records. This bounds fixed-size fields and summaries.
    pub entries: usize,
    /// Total bytes in owned raw names.
    pub name_bytes: usize,
    /// Total bytes in owned variable-length known extra summaries.
    pub extra_bytes: usize,
    /// Total bytes in owned raw comments.
    pub comment_bytes: usize,
}

/// Cumulative limits and usage for converting borrowed central records.
#[derive(Clone, Debug)]
pub struct OwnershipBudget {
    limits: OwnershipUsage,
    used: OwnershipUsage,
}

impl OwnershipBudget {
    /// Starts with no records or bytes charged.
    pub fn new(limits: OwnershipUsage) -> Self {
        Self { limits, used: OwnershipUsage::default() }
    }

    /// Returns the cumulative charge for successful conversions.
    pub fn used(&self) -> OwnershipUsage {
        self.used
    }

    pub(crate) fn resume(limits: OwnershipUsage, used: OwnershipUsage) -> Result<Self, OwnershipError> {
        let mut budget = Self::new(limits);
        budget.used = budget.check(used)?;
        Ok(budget)
    }

    // The caller commits a checked total after all related allocations succeed.
    pub(crate) fn commit(&mut self, checked: OwnershipUsage) {
        self.used = checked;
    }

    pub(crate) fn check(&self, charge: OwnershipUsage) -> Result<OwnershipUsage, OwnershipError> {
        let used = self.used;
        let limits = self.limits;
        Ok(OwnershipUsage {
            entries: checked_charge(OwnershipKind::Entries, used.entries, charge.entries, limits.entries)?,
            name_bytes: checked_charge(
                OwnershipKind::NameBytes,
                used.name_bytes,
                charge.name_bytes,
                limits.name_bytes,
            )?,
            extra_bytes: checked_charge(
                OwnershipKind::ExtraBytes,
                used.extra_bytes,
                charge.extra_bytes,
                limits.extra_bytes,
            )?,
            comment_bytes: checked_charge(
                OwnershipKind::CommentBytes,
                used.comment_bytes,
                charge.comment_bytes,
                limits.comment_bytes,
            )?,
        })
    }
}

fn checked_charge(kind: OwnershipKind, used: usize, charge: usize, limit: usize) -> Result<usize, OwnershipError> {
    let needed = used.checked_add(charge).ok_or(OwnershipError::CounterOverflow { kind })?;
    if needed > limit {
        return Err(OwnershipError::LimitExceeded { kind, needed, limit });
    }
    Ok(needed)
}

impl<'a> CentralView<'a> {
    /// Converts a borrowed view and the caller's projections into one record.
    ///
    /// The Unicode candidate, if any, should come from this record's extra
    /// block. It stays borrowed until this call. Raw names, available comments,
    /// and the one selected path are copied after all budget checks and
    /// reservations succeed. Errors leave all counters unchanged.
    pub fn into_owned(
        self,
        resolved: ResolvedFields,
        known: KnownExtrasView<'a>,
        budget: &mut OwnershipBudget,
    ) -> Result<CentralRecord, OwnershipError> {
        let next = budget.check(self.ownership_charge(known))?;
        let record = self.materialize(resolved, known)?;
        budget.commit(next);
        Ok(record)
    }

    pub(crate) fn ownership_charge(&self, known: KnownExtrasView<'a>) -> OwnershipUsage {
        OwnershipUsage {
            entries: 1,
            name_bytes: self.raw_name().len(),
            extra_bytes: known.unicode_path.map_or(0, |path| path.path_bytes().len()),
            comment_bytes: self.raw_comment().len(),
        }
    }

    pub(crate) fn materialize(
        self,
        resolved: ResolvedFields,
        known: KnownExtrasView<'a>,
    ) -> Result<CentralRecord, OwnershipError> {
        let path = known.unicode_path.map(UnicodePathView::path_bytes);
        let name = reserve(OwnershipKind::NameBytes, self.raw_name().len())?;
        let comment = reserve(OwnershipKind::CommentBytes, self.raw_comment().len())?;
        let path = path
            .map(|bytes| reserve(OwnershipKind::ExtraBytes, bytes.len()).map(|buffer| (buffer, bytes)))
            .transpose()?;

        Ok(CentralRecord {
            header: self.header(),
            resolved,
            source: self.location(),
            raw_name: copy_to_box(name, self.raw_name()),
            raw_comment: copy_to_box(comment, self.raw_comment()),
            known: KnownExtras {
                aes: known.aes,
                mtime_override: known.mtime_override,
                unicode_path: path.map(|(buffer, bytes)| copy_to_box(buffer, bytes)),
            },
        })
    }
}

fn reserve(kind: OwnershipKind, len: usize) -> Result<Vec<u8>, OwnershipError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(len).map_err(|_| OwnershipError::Allocation { kind })?;
    Ok(buffer)
}

fn copy_to_box(mut buffer: Vec<u8>, bytes: &[u8]) -> Box<[u8]> {
    buffer.extend_from_slice(bytes);
    buffer.into_boxed_slice()
}
