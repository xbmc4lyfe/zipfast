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

// Extra framing and ZIP64/AES field offsets adapted from zipview's
// src/lib.rs. Unicode and timestamp offsets follow zipfast's src/zip.rs.

use std::{iter::FusedIterator, ops::Range};

use crate::{
    ParseError,
    header::{add_offset, le16, le32, le64, require_prefix},
};

/// One extra field borrowed from its enclosing extra block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extra<'a> {
    /// Field ID as written, including unrecognized IDs.
    pub id: u16,
    /// Absolute range including the four-byte extra header and the body.
    pub range: Range<u64>,
    /// Body bounded by the advertised field length.
    pub body: &'a [u8],
}

/// Iterates a ZIP extra block without filtering or reordering fields.
///
/// The iterator yields one error and ends if a field's header or body is short.
#[derive(Debug)]
pub struct ExtraIter<'a> {
    remaining: &'a [u8],
    offset: u64,
}

impl<'a> ExtraIter<'a> {
    /// Creates an iterator over an extra block beginning at an absolute offset.
    pub fn new(bytes: &'a [u8], physical_start: u64) -> Result<Self, ParseError> {
        add_offset(physical_start, bytes.len() as u64)?;
        Ok(Self::from_checked_range(bytes, physical_start))
    }

    pub(crate) fn from_checked_range(bytes: &'a [u8], offset: u64) -> Self {
        Self { remaining: bytes, offset }
    }
}

impl<'a> Iterator for ExtraIter<'a> {
    type Item = Result<Extra<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = std::mem::take(&mut self.remaining);
        let start = self.offset;
        if bytes.is_empty() {
            return None;
        }
        if bytes.len() < 4 {
            return Some(Err(ParseError::TruncatedExtraHeader { offset: start, available: bytes.len() as u16 }));
        }
        let id = le16(bytes, 0);
        let advertised = le16(bytes, 2);
        let body_start = start + 4;
        let Some((body, remaining)) = bytes[4..].split_at_checked(usize::from(advertised)) else {
            return Some(Err(ParseError::TruncatedExtraBody {
                offset: body_start,
                id,
                advertised,
                available: (bytes.len() - 4) as u16,
            }));
        };
        let end = body_start + u64::from(advertised);
        self.offset = end;
        self.remaining = remaining;
        Some(Ok(Extra { id, range: start..end, body }))
    }
}

impl FusedIterator for ExtraIter<'_> {}

/// Selects which ZIP64 fields are present in an extra body.
///
/// The caller selects fields from the header's sentinel state. Unselected
/// fields occupy no space in the body.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Zip64Fields {
    /// Uncompressed size precedes other requested values.
    pub unpacked_size: bool,
    /// Compressed size.
    pub packed_size: bool,
    /// Stored relative local header offset.
    pub local_header_offset: bool,
    /// Disk on which the entry starts.
    pub disk_start: bool,
}

/// One selected ZIP64 value in the order it was read from the extra body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Zip64Value {
    /// Uncompressed size.
    UnpackedSize(u64),
    /// Compressed size.
    PackedSize(u64),
    /// Stored relative local header offset.
    LocalHeaderOffset(u64),
    /// Disk on which the entry starts.
    DiskStart(u32),
}

/// Borrowed ZIP64 extended information extra body (ID `0x0001`).
#[derive(Clone, Copy, Debug)]
pub struct Zip64View<'a> {
    body: &'a [u8],
}

impl<'a> Zip64View<'a> {
    /// Borrows the body. Validation happens as the requested fields are read.
    pub fn new(body: &'a [u8]) -> Self {
        Self { body }
    }

    /// Returns the complete borrowed body.
    pub fn body(self) -> &'a [u8] {
        self.body
    }

    /// Reads only the requested fields in their prescribed ZIP64 order.
    ///
    /// Earlier complete values are yielded before a short-field error. Error
    /// offsets are relative to the body.
    pub fn fields(self, requested: Zip64Fields) -> Zip64FieldIter<'a> {
        let fields = [
            requested.unpacked_size.then_some(Zip64Field::UnpackedSize),
            requested.packed_size.then_some(Zip64Field::PackedSize),
            requested.local_header_offset.then_some(Zip64Field::LocalHeaderOffset),
            requested.disk_start.then_some(Zip64Field::DiskStart),
        ];
        Zip64FieldIter { body: self.body, fields: fields.into_iter(), offset: 0 }
    }
}

enum Zip64Field {
    UnpackedSize,
    PackedSize,
    LocalHeaderOffset,
    DiskStart,
}

/// Iterator over the requested fields of one ZIP64 body.
pub struct Zip64FieldIter<'a> {
    body: &'a [u8],
    fields: std::array::IntoIter<Option<Zip64Field>, 4>,
    offset: usize,
}

impl Iterator for Zip64FieldIter<'_> {
    type Item = Result<Zip64Value, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let field = self.fields.by_ref().flatten().next()?;
        let bytes = &self.body[self.offset..];
        let len = if matches!(field, Zip64Field::DiskStart) { 4 } else { 8 };
        if let Err(error) = require_prefix(bytes, len, self.offset as u64) {
            self.fields = [None, None, None, None].into_iter();
            return Some(Err(error));
        }
        self.offset += len;
        Some(Ok(match field {
            Zip64Field::UnpackedSize => Zip64Value::UnpackedSize(le64(bytes, 0)),
            Zip64Field::PackedSize => Zip64Value::PackedSize(le64(bytes, 0)),
            Zip64Field::LocalHeaderOffset => Zip64Value::LocalHeaderOffset(le64(bytes, 0)),
            Zip64Field::DiskStart => Zip64Value::DiskStart(le32(bytes, 0)),
        }))
    }
}

impl FusedIterator for Zip64FieldIter<'_> {}

/// Raw fields of a complete WinZip AES extra prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AesFields {
    /// Vendor version, for example 1 for AE-1 or 2 for AE-2.
    pub vendor_version: u16,
    /// Raw two-byte vendor identifier.
    pub vendor_id: [u8; 2],
    /// Raw encryption strength byte.
    pub strength: u8,
    /// Underlying wire compression method.
    pub method: u16,
}

/// Borrowed WinZip AES extra body (ID `0x9901`).
#[derive(Clone, Copy, Debug)]
pub struct AesView<'a> {
    body: &'a [u8],
}

impl<'a> AesView<'a> {
    /// Checks that the seven-byte prefix is available. Vendor, strength, and
    /// method values are left for the caller to interpret.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        require_prefix(body, 7, 0)?;
        Ok(Self { body })
    }

    /// Returns the complete borrowed body, including any trailing bytes.
    pub fn body(self) -> &'a [u8] {
        self.body
    }

    /// Returns the raw AES scalar fields.
    pub fn fields(self) -> AesFields {
        AesFields {
            vendor_version: le16(self.body, 0),
            vendor_id: [self.body[2], self.body[3]],
            strength: self.body[4],
            method: le16(self.body, 5),
        }
    }
}

/// Borrowed Info-ZIP Unicode Path extra body (ID `0x7075`).
#[derive(Clone, Copy, Debug)]
pub struct UnicodePathView<'a> {
    body: &'a [u8],
}

impl<'a> UnicodePathView<'a> {
    /// Checks the version and CRC fields are present and the body fits its wire
    /// length field. The caller interprets the version, CRC, and path bytes.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        require_prefix(body, 5, 0)?;
        if body.len() > usize::from(u16::MAX) {
            return Err(ParseError::ExtraBodyTooLong { len: body.len() });
        }
        Ok(Self { body })
    }

    /// Version byte written in the extra.
    pub fn version(self) -> u8 {
        self.body[0]
    }

    /// CRC of the raw name as written in the extra.
    pub fn name_crc32(self) -> u32 {
        le32(self.body, 1)
    }

    /// Undecoded bytes after the version and CRC.
    pub fn path_bytes(self) -> &'a [u8] {
        &self.body[5..]
    }
}

/// Borrowed NTFS extra body (ID `0x000a`) and its first attribute.
#[derive(Clone, Copy, Debug)]
pub struct NtfsMtimeView<'a> {
    body: &'a [u8],
}

impl<'a> NtfsMtimeView<'a> {
    /// Checks the reserved field and first attribute header are available.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        require_prefix(body, 8, 0)?;
        Ok(Self { body })
    }

    /// Reserved value at the beginning of the NTFS body.
    pub fn reserved(self) -> u32 {
        le32(self.body, 0)
    }

    /// Tag of the first attribute.
    pub fn first_tag(self) -> u16 {
        le16(self.body, 4)
    }

    /// First attribute length as declared in its header.
    pub fn declared_attribute_len(self) -> u16 {
        le16(self.body, 6)
    }

    /// Body bytes after the first attribute header, including any later attributes.
    pub fn attribute_bytes(self) -> &'a [u8] {
        &self.body[8..]
    }

    /// First attribute payload bounded by its length and the supplied bytes.
    pub fn available_attribute_data(self) -> &'a [u8] {
        let bytes = self.attribute_bytes();
        &bytes[..bytes.len().min(usize::from(self.declared_attribute_len()))]
    }

    /// Raw modification FILETIME when present in the first tag-1 attribute.
    ///
    /// The caller decides which attribute lengths and values it accepts.
    pub fn filetime(self) -> Option<u64> {
        let data = self.available_attribute_data();
        (self.first_tag() == 1 && data.len() >= 8).then(|| le64(data, 0))
    }
}

/// Borrowed extended timestamp extra body (ID `0x5455`).
#[derive(Clone, Copy, Debug)]
pub struct ExtendedMtimeView<'a> {
    body: &'a [u8],
}

impl<'a> ExtendedMtimeView<'a> {
    /// Checks that the flags byte is available.
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        require_prefix(body, 1, 0)?;
        Ok(Self { body })
    }

    /// Raw flags byte.
    pub fn flags(self) -> u8 {
        self.body[0]
    }

    /// Raw timestamp bytes following the flags.
    pub fn timestamp_data(self) -> &'a [u8] {
        &self.body[1..]
    }

    /// Raw modification timestamp in signed Unix seconds when flagged and present.
    pub fn unix_seconds(self) -> Option<i32> {
        let data = self.timestamp_data();
        (self.flags() & 1 != 0 && data.len() >= 4).then(|| le32(data, 0) as i32)
    }
}
