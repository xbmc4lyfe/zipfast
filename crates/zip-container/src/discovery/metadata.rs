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

use std::{fmt, ops::Range};

use crate::{OwnershipError, OwnershipUsage, ParseError};

/// Compatibility policy applied during end discovery and directory parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Require checked relocation and single-disk metadata.
    Zipfast,
    /// Allow clipped comments and prefer a valid declared directory position.
    Zipview,
}

/// Independent component limits for directory parsing.
///
/// These limits bound input, work and raw metadata admission. Peak process
/// memory also includes parser scratch, allocator overhead, and caller buffers.
/// Projected records can have different allocation sizes from raw records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Declared and visited directory bytes.
    pub directory_bytes: u64,
    /// Declared and visited central records.
    pub entries: u64,
    /// Cumulative bytes accepted from the source.
    pub fetched_bytes: u64,
    /// Maximum length of one request.
    pub range_bytes: u64,
    /// Maximum work units charged to discovery and parsing.
    pub work_units: u64,
    /// Raw entry name bytes, including when projection expands a decoded name.
    pub name_bytes: u64,
    /// Selected variable-length known-extra bytes, even if a projection discards them.
    pub extra_bytes: u64,
    /// Raw archive and available entry comment bytes, even if a projection discards entry comments.
    pub comment_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        const METADATA: u64 = 128 * 1024 * 1024;
        const FETCHED: u64 = 129 * 1024 * 1024;
        const ENTRIES: u64 = 1_000_000;
        Self {
            directory_bytes: METADATA,
            entries: ENTRIES,
            fetched_bytes: FETCHED,
            range_bytes: 16 * 1024 * 1024,
            work_units: 32 * FETCHED + 256 * ENTRIES + 65_536,
            name_bytes: METADATA,
            extra_bytes: METADATA,
            comment_bytes: METADATA,
        }
    }
}

/// Cumulative usage from the start of end discovery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Bytes accepted through the source protocol, including discovery.
    pub fetched_bytes: u64,
    /// Deterministic units charged before scans, checks and copies.
    pub work_units: u64,
    /// Furthest requested or logically traversed directory extent in bytes.
    pub directory_bytes: u64,
    /// Successfully admitted raw metadata, including the owned archive comment.
    ///
    /// For the default output this counts owned metadata. For projected output
    /// it records the equivalent raw charge and can differ from allocation.
    pub owned: OwnershipUsage,
}

/// Byte-buffer usage excluding owned metadata, caller buffers and allocator overhead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BufferUsage {
    /// Bytes currently retained in parser scratch.
    pub live_bytes: usize,
    /// Allocated capacity of parser scratch, including fixed inline buffers.
    pub capacity_bytes: usize,
}

/// Component associated with an exhausted or unrepresentable limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// Declared or visited directory extent.
    DirectoryBytes,
    /// Declared or visited record count.
    Entries,
    /// Cumulative accepted source bytes.
    FetchedBytes,
    /// Length of an individual source request.
    RangeBytes,
    /// Deterministic work budget.
    WorkUnits,
    /// Owned raw names.
    NameBytes,
    /// Owned variable-length known extras.
    ExtraBytes,
    /// Owned raw archive and entry comments.
    CommentBytes,
}

/// Invalid source supply, which leaves parser progress and counters intact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupplyError {
    /// The supplied range exceeds the source length or overflows u64.
    OutOfBounds,
    /// No source request is pending.
    Unsolicited,
    /// Supply starts before or after the start of the pending range.
    UnexpectedOffset,
    /// Supply extends past the end of the pending range.
    Overlong,
}

/// Failure to discover or parse a ZIP directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    /// No eligible end-of-central-directory record was found.
    NotZip,
    /// A classic end record has impossible directory geometry.
    MalformedEnd,
    /// ZIP64 framing, declarations, or directory geometry are invalid.
    MalformedZip64,
    /// The strict walk encountered a central signature beyond the declared count
    /// or stopped at a noncentral signature before reaching it.
    EntryCount {
        /// Effective entry declaration.
        declared: u64,
        /// Complete entries, plus an immediately following excess signature when present.
        observed: u64,
    },
    /// A required local header address could not be resolved inside the archive.
    InvalidLocalOffset,
    /// The selected profile disallows the archive's disk declarations.
    UnsupportedDisk,
    /// A configured component budget was exhausted or unrepresentable.
    Limit(LimitKind),
    /// Fallible parser scratch or output allocation failed.
    Allocation,
    /// The caller supplied bytes outside the source protocol.
    Supply(SupplyError),
    /// The parser still needs more source bytes.
    Incomplete,
    /// A wire record or range failed a primitive structural check.
    Parse(ParseError),
    /// A primitive could not retain bounded metadata.
    Ownership(OwnershipError),
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotZip => f.write_str("ZIP end record not found"),
            Self::MalformedEnd => f.write_str("invalid ZIP end record geometry"),
            Self::MalformedZip64 => f.write_str("invalid ZIP64 end record geometry"),
            Self::EntryCount { declared, observed } => {
                write!(f, "invalid ZIP directory count (declared {declared}, observed {observed})")
            }
            Self::InvalidLocalOffset => f.write_str("invalid ZIP local header offset"),
            Self::UnsupportedDisk => f.write_str("unsupported split ZIP directory"),
            Self::Limit(kind) => write!(f, "ZIP directory limit exceeded: {kind:?}"),
            Self::Allocation => f.write_str("cannot reserve ZIP directory buffer"),
            Self::Supply(kind) => write!(f, "invalid ZIP source supply: {kind:?}"),
            Self::Incomplete => f.write_str("ZIP directory parsing still needs source bytes"),
            Self::Parse(error) => error.fmt(f),
            Self::Ownership(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::Ownership(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ParseError> for DirectoryError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<OwnershipError> for DirectoryError {
    fn from(error: OwnershipError) -> Self {
        Self::Ownership(error)
    }
}

/// Wire fields of the selected classic end-of-central-directory record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndRecord {
    /// Absolute fixed record range, excluding the comment.
    pub source: Range<u64>,
    /// Number of this disk.
    pub disk: u16,
    /// Disk containing the start of the central directory.
    pub directory_disk: u16,
    /// Number of entries declared on this disk.
    pub disk_entries: u16,
    /// Total entries declared in the classic record.
    pub entries: u16,
    /// Directory byte count declared in the classic record.
    pub size: u32,
    /// Directory offset declared in the classic record.
    pub offset: u32,
    /// Length of the declared comment, which may be clipped by the source end.
    pub comment_len: u16,
}

/// Wire fields of an adjacent ZIP64 end-record locator considered by discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zip64Locator {
    /// Absolute locator range.
    pub source: Range<u64>,
    /// Disk containing the ZIP64 end record.
    pub disk: u32,
    /// Stored offset of the ZIP64 end record.
    pub record_offset: u64,
    /// Number of disks declared in the locator.
    pub total_disks: u32,
}

/// Wire fields and checked extent of a selected ZIP64 end record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zip64End {
    /// Entire absolute record range, including any opaque extension.
    pub source: Range<u64>,
    /// Absolute range of the opaque extension.
    pub extension: Range<u64>,
    /// Body length, excluding the signature and size field.
    pub body_size: u64,
    /// Creator version and host as written in the fixed record.
    pub version_made_by: u16,
    /// Version required to extract.
    pub version_needed: u16,
    /// Number of this disk.
    pub disk: u32,
    /// Disk containing the start of the central directory.
    pub directory_disk: u32,
    /// Number of entries declared on this disk.
    pub disk_entries: u64,
    /// Directory declaration in the ZIP64 record.
    pub declaration: DirectoryDeclaration,
}

/// Effective directory declaration after checking adjacent ZIP64 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryDeclaration {
    /// Declared total number of entries.
    pub entries: u64,
    /// Declared size in bytes.
    pub size: u64,
    /// Stored directory offset before any relocation.
    pub offset: u64,
}
