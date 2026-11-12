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

// Fixed header offsets and local payload layout adapted from zipview's
// src/lib.rs and src/index.rs.

use std::ops::Range;

use crate::{ExtraIter, ParseError};

/// Fixed central directory file-header length, including its signature.
pub const CENTRAL_HEADER_LEN: usize = 46;
/// Fixed local file-header length, including its signature.
pub const LOCAL_HEADER_LEN: usize = 30;

const CENTRAL_HEADER_SIG: u32 = 0x0201_4b50;
const LOCAL_HEADER_SIG: u32 = 0x0403_4b50;

/// Unresolved scalar fields in a central directory file header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CentralHeader {
    /// Creator host and version as packed in the wire field.
    pub version_made_by: u16,
    /// Minimum extraction version.
    pub version_needed: u16,
    /// General purpose bit flags.
    pub flags: u16,
    /// Compression method as written, including AES marker methods.
    pub method: u16,
    /// Raw DOS modification time.
    pub mod_time: u16,
    /// Raw DOS modification date.
    pub mod_date: u16,
    /// Wire CRC-32.
    pub crc32: u32,
    /// Wire compressed size or ZIP64 sentinel.
    pub packed_size: u32,
    /// Wire uncompressed size or ZIP64 sentinel.
    pub unpacked_size: u32,
    /// Raw name length.
    pub name_len: u16,
    /// Raw extra block length.
    pub extra_len: u16,
    /// Declared raw file comment length.
    pub comment_len: u16,
    /// Wire start disk number or ZIP64 sentinel.
    pub disk_start: u16,
    /// Internal file attributes.
    pub internal_attributes: u16,
    /// External file attributes.
    pub external_attributes: u32,
    /// Wire offset of the local header or ZIP64 sentinel.
    pub local_header_offset: u32,
}

impl CentralHeader {
    /// Reads a complete fixed header at the start of a slice.
    ///
    /// Error offsets are slice-relative. Variable data may follow the header.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        Self::parse_at(bytes, 0)
    }

    fn parse_at(bytes: &[u8], start: u64) -> Result<Self, ParseError> {
        require_prefix(bytes, CENTRAL_HEADER_LEN, start)?;
        if le32(bytes, 0) != CENTRAL_HEADER_SIG {
            return Err(ParseError::BadSignature { offset: start });
        }
        Ok(Self {
            version_made_by: le16(bytes, 4),
            version_needed: le16(bytes, 6),
            flags: le16(bytes, 8),
            method: le16(bytes, 10),
            mod_time: le16(bytes, 12),
            mod_date: le16(bytes, 14),
            crc32: le32(bytes, 16),
            packed_size: le32(bytes, 20),
            unpacked_size: le32(bytes, 24),
            name_len: le16(bytes, 28),
            extra_len: le16(bytes, 30),
            comment_len: le16(bytes, 32),
            disk_start: le16(bytes, 34),
            internal_attributes: le16(bytes, 36),
            external_attributes: le32(bytes, 38),
            local_header_offset: le32(bytes, 42),
        })
    }
}

/// Scalar fields in a local file header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalHeader {
    /// Minimum extraction version.
    pub version_needed: u16,
    /// General purpose bit flags.
    pub flags: u16,
    /// Compression method as written, including AES marker methods.
    pub method: u16,
    /// Raw DOS modification time.
    pub mod_time: u16,
    /// Raw DOS modification date.
    pub mod_date: u16,
    /// Wire CRC-32, which may be a placeholder.
    pub crc32: u32,
    /// Wire compressed size, which may be a placeholder or ZIP64 sentinel.
    pub packed_size: u32,
    /// Wire uncompressed size, which may be a placeholder or ZIP64 sentinel.
    pub unpacked_size: u32,
    /// Raw name length.
    pub name_len: u16,
    /// Raw extra block length.
    pub extra_len: u16,
}

impl LocalHeader {
    /// Reads a complete fixed local header at the start of a slice.
    ///
    /// Error offsets are slice-relative. Variable data may follow the header.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        require_prefix(bytes, LOCAL_HEADER_LEN, 0)?;
        if le32(bytes, 0) != LOCAL_HEADER_SIG {
            return Err(ParseError::BadSignature { offset: 0 });
        }
        Ok(Self {
            version_needed: le16(bytes, 4),
            flags: le16(bytes, 6),
            method: le16(bytes, 8),
            mod_time: le16(bytes, 10),
            mod_date: le16(bytes, 12),
            crc32: le32(bytes, 14),
            packed_size: le32(bytes, 18),
            unpacked_size: le32(bytes, 22),
            name_len: le16(bytes, 26),
            extra_len: le16(bytes, 28),
        })
    }
}

/// Absolute source location of a central record with validated range arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CentralLocation {
    start: u64,
    name_len: u16,
    extra_len: u16,
    comment_len: u16,
    available_comment_len: u16,
}

impl CentralLocation {
    /// Absolute range of the raw central name.
    pub fn name_range(self) -> Range<u64> {
        let start = self.start + CENTRAL_HEADER_LEN as u64;
        start..start + u64::from(self.name_len)
    }

    /// Absolute range of all original extra records, in wire order.
    pub fn extra_range(self) -> Range<u64> {
        let start = self.name_range().end;
        start..start + u64::from(self.extra_len)
    }

    /// Absolute range of the available comment bytes.
    pub fn comment_range(self) -> Range<u64> {
        let start = self.extra_range().end;
        start..start + u64::from(self.available_comment_len)
    }

    /// Absolute range of the whole available record, including its signature.
    pub fn raw_range(self) -> Range<u64> {
        self.start..self.comment_range().end
    }

    /// Absolute record range including the entire declared comment.
    ///
    /// Its end can exceed the available source when the comment is incomplete.
    pub fn declared_range(self) -> Range<u64> {
        self.start..self.extra_range().end + u64::from(self.comment_len)
    }

    /// Comment length declared in the central header.
    pub fn declared_comment_len(self) -> u16 {
        self.comment_len
    }

    /// Number of comment bytes available in the input.
    pub fn available_comment_len(self) -> u16 {
        self.available_comment_len
    }
}

/// Computes a central record's location given an exclusive source end.
///
/// The fixed header, name, and extra block must fit. A short comment remains
/// visible as distinct declared and available lengths for the caller to handle.
pub fn central_layout(
    header: CentralHeader,
    physical_start: u64,
    available_end: u64,
) -> Result<CentralLocation, ParseError> {
    let comment_start =
        variable_end(physical_start, CENTRAL_HEADER_LEN, header.name_len, header.extra_len, available_end)?;
    let declared_end = add_offset(comment_start, u64::from(header.comment_len))?;
    let available_comment_len = (available_end.min(declared_end) - comment_start) as u16;
    Ok(CentralLocation {
        start: physical_start,
        name_len: header.name_len,
        extra_len: header.extra_len,
        comment_len: header.comment_len,
        available_comment_len,
    })
}

/// Absolute source layout of the local header and its variable fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalLayout {
    start: u64,
    name_len: u16,
    extra_len: u16,
}

impl LocalLayout {
    /// Absolute range of the raw local name.
    pub fn name_range(self) -> Range<u64> {
        let start = self.start + LOCAL_HEADER_LEN as u64;
        start..start + u64::from(self.name_len)
    }

    /// Absolute range of the local extra block.
    pub fn extra_range(self) -> Range<u64> {
        let start = self.name_range().end;
        start..start + u64::from(self.extra_len)
    }

    /// Absolute range of the complete local header, up to the start of data.
    pub fn raw_range(self) -> Range<u64> {
        self.start..self.extra_range().end
    }

    /// Computes the bounded payload range from the supplied packed byte count.
    ///
    /// The caller supplies the authoritative compressed length, typically from
    /// the central directory. The local header may have placeholder sizes.
    pub fn payload_range(self, packed_size: u64, available_end: u64) -> Result<Range<u64>, ParseError> {
        let start = self.extra_range().end;
        Ok(start..require_range(start, packed_size, available_end)?)
    }
}

/// Validates the fixed and variable local header against an exclusive source end.
pub fn local_layout(header: LocalHeader, physical_start: u64, available_end: u64) -> Result<LocalLayout, ParseError> {
    variable_end(physical_start, LOCAL_HEADER_LEN, header.name_len, header.extra_len, available_end)?;
    Ok(LocalLayout { start: physical_start, name_len: header.name_len, extra_len: header.extra_len })
}

/// A central record borrowed from one contiguous input window.
#[derive(Debug)]
pub struct CentralView<'a> {
    header: CentralHeader,
    location: CentralLocation,
    name: &'a [u8],
    extra: &'a [u8],
    comment: &'a [u8],
}

impl<'a> CentralView<'a> {
    /// Reads one central record starting at the first byte of the window.
    ///
    /// `physical_start` is the absolute source offset of that byte. A short
    /// comment yields a partial view with both comment lengths recorded.
    pub fn parse(bytes: &'a [u8], physical_start: u64) -> Result<Self, ParseError> {
        let available_end = add_offset(physical_start, bytes.len() as u64)?;
        let header = CentralHeader::parse_at(bytes, physical_start)?;
        let location = central_layout(header, physical_start, available_end)?;

        let (name, tail) = bytes[CENTRAL_HEADER_LEN..].split_at(usize::from(header.name_len));
        let (extra, tail) = tail.split_at(usize::from(header.extra_len));
        let comment = &tail[..usize::from(location.available_comment_len)];
        Ok(Self { header, location, name, extra, comment })
    }

    /// Scalar fields as written in the central header.
    pub fn header(&self) -> CentralHeader {
        self.header
    }

    /// Absolute location and raw ranges of the record.
    pub fn location(&self) -> CentralLocation {
        self.location
    }

    /// Undecoded central name bytes.
    pub fn raw_name(&self) -> &'a [u8] {
        self.name
    }

    /// Available, undecoded central comment bytes.
    pub fn raw_comment(&self) -> &'a [u8] {
        self.comment
    }

    /// Iterates extra fields in wire order within the validated extra block.
    pub fn extras(&self) -> ExtraIter<'a> {
        ExtraIter::from_checked_range(self.extra, self.location.extra_range().start)
    }
}

fn variable_end(
    start: u64,
    fixed_len: usize,
    name_len: u16,
    extra_len: u16,
    available_end: u64,
) -> Result<u64, ParseError> {
    let name_start = require_range(start, fixed_len as u64, available_end)?;
    let extra_start = require_range(name_start, u64::from(name_len), available_end)?;
    require_range(extra_start, u64::from(extra_len), available_end)
}

pub(crate) fn add_offset(start: u64, len: u64) -> Result<u64, ParseError> {
    start.checked_add(len).ok_or(ParseError::OffsetOverflow)
}

fn require_range(start: u64, len: u64, available_end: u64) -> Result<u64, ParseError> {
    let end = add_offset(start, len)?;
    if end > available_end {
        return Err(ParseError::Truncated {
            offset: start,
            needed: len,
            available: available_end.saturating_sub(start),
        });
    }
    Ok(end)
}

pub(crate) fn require_prefix(bytes: &[u8], len: usize, offset: u64) -> Result<(), ParseError> {
    if bytes.len() < len {
        return Err(ParseError::Truncated { offset, needed: len as u64, available: bytes.len() as u64 });
    }
    Ok(())
}

// Each caller verifies its fixed prefix before indexing known field offsets.
pub(crate) fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

pub(crate) fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("checked four-byte field"))
}

pub(crate) fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("checked eight-byte field"))
}
