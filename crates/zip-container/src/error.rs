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

use std::fmt;

/// A structural error reading a ZIP header, layout, or extra field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// The end of a range exceeds the addressable u64 source space.
    OffsetOverflow,
    /// The fixed header's signature does not match its expected record type.
    BadSignature {
        /// Byte offset of the signature.
        offset: u64,
    },
    /// A required byte range was not fully available.
    Truncated {
        /// Start of the required range.
        offset: u64,
        /// Required bytes beginning at the offset.
        needed: u64,
        /// Available bytes beginning at the offset.
        available: u64,
    },
    /// An extra field's four-byte ID and length header was incomplete.
    TruncatedExtraHeader {
        /// Absolute offset of the extra field header.
        offset: u64,
        /// Bytes remaining in the extra block at that offset.
        available: u16,
    },
    /// An extra field body extended beyond the available extra block.
    TruncatedExtraBody {
        /// Absolute offset of the extra field body, just after its header.
        offset: u64,
        /// ID from the extra field header.
        id: u16,
        /// Body length from the extra field header.
        advertised: u16,
        /// Bytes remaining in the extra block at that offset.
        available: u16,
    },
    /// An independently supplied body exceeds a ZIP extra field's u16 length.
    ExtraBodyTooLong {
        /// Length of the supplied body.
        len: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OffsetOverflow => f.write_str("ZIP source range overflows u64"),
            Self::BadSignature { offset } => write!(f, "invalid ZIP signature at {offset}"),
            Self::Truncated { offset, needed, available } => {
                write!(f, "truncated ZIP field at {offset} (need {needed} bytes, have {available})")
            }
            Self::TruncatedExtraHeader { offset, available } => {
                write!(f, "truncated ZIP extra field header at {offset} ({available} of 4 bytes)")
            }
            Self::TruncatedExtraBody { offset, id, advertised, available } => {
                write!(f, "truncated ZIP extra field {id:#06x} body at {offset} ({available} of {advertised} bytes)")
            }
            Self::ExtraBodyTooLong { len } => write!(f, "ZIP extra field body is too long ({len} bytes)"),
        }
    }
}

impl std::error::Error for ParseError {}

/// The ownership counter associated with a budget or allocation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipKind {
    /// Number of successfully owned central records.
    Entries,
    /// Bytes in owned raw names.
    NameBytes,
    /// Bytes in owned variable-length known extras.
    ExtraBytes,
    /// Bytes in owned raw comments.
    CommentBytes,
}

/// Failure to convert a borrowed central view into a bounded owned record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipError {
    /// Adding the record would overflow a counter.
    CounterOverflow {
        /// Counter that overflowed.
        kind: OwnershipKind,
    },
    /// Adding the record would exceed a counter's configured limit.
    LimitExceeded {
        /// Counter that would exceed its limit.
        kind: OwnershipKind,
        /// Counter total if the record were added.
        needed: usize,
        /// Configured maximum for this counter.
        limit: usize,
    },
    /// Memory could not be reserved for one of the record's byte buffers.
    Allocation {
        /// Buffer whose reservation failed.
        kind: OwnershipKind,
    },
}

impl fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterOverflow { kind } => write!(f, "ZIP ownership counter {kind:?} overflows"),
            Self::LimitExceeded { kind, needed, limit } => {
                write!(f, "ZIP ownership counter {kind:?} needs {needed}, above limit {limit}")
            }
            Self::Allocation { kind } => write!(f, "cannot reserve ZIP ownership buffer {kind:?}"),
        }
    }
}

impl std::error::Error for OwnershipError {}
