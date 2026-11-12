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

use super::{DosDateTime, InputLength, Method, WriteError, add};
use crate::zip::{HOST_UNIX, METHOD_DEFLATE, METHOD_STORED};

const SIZE_SENTINEL: u64 = u32::MAX as u64;
const COUNT_SENTINEL: u64 = u16::MAX as u64;
const LOCAL_LEN: u64 = 30;
const CENTRAL_LEN: u64 = 46;
const END_LEN: u64 = 22;
const ZIP64_TAIL_LEN: u64 = 76;

#[derive(Clone, Copy)]
pub(super) struct Width {
    pub sizes: bool,
    offset: bool,
}

impl Width {
    pub(super) fn new(method: Method, length: InputLength, local_at: u64, empty: bool) -> Self {
        let sizes = !empty
            && match (method, length) {
                (Method::Stored, InputLength::Exact(size)) => size >= SIZE_SENTINEL,
                _ => true,
            };
        Self { sizes, offset: local_at >= SIZE_SENTINEL }
    }

    pub(super) fn is_wide(self) -> bool {
        self.sizes || self.offset
    }

    fn version(self) -> u16 {
        if self.is_wide() { 45 } else { 20 }
    }

    fn size32(self, size: u64) -> Result<u32, WriteError> {
        if self.sizes {
            Ok(u32::MAX)
        } else if size < SIZE_SENTINEL {
            Ok(size as u32)
        } else {
            Err(WriteError::Overflow)
        }
    }
}

// Each instance is one fixed header or one complete block of owned extras.
// Names and comments are written separately.
pub(super) struct Record<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Record<N> {
    fn new() -> Self {
        Self { bytes: [0; N], len: 0 }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn put(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }

    fn u16(&mut self, value: u16) {
        self.put(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.put(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.put(&value.to_le_bytes());
    }
}

pub(super) struct Member {
    pub width: Width,
    pub method: Method,
    pub flags: u16,
    pub dos: DosDateTime,
    pub name_len: u16,
    pub comment_len: u16,
    pub external: u32,
    pub mtime: Option<i32>,
    pub local_at: u64,
}

impl Member {
    pub(super) fn local_len(&self) -> u64 {
        LOCAL_LEN + u64::from(self.name_len) + u64::from(self.extra_len(false))
    }

    pub(super) fn central_len(&self) -> u64 {
        CENTRAL_LEN + u64::from(self.name_len) + u64::from(self.extra_len(true)) + u64::from(self.comment_len)
    }

    pub(super) fn patch_len(&self) -> u64 {
        if self.width.sizes { 20 } else { 12 }
    }

    fn zip64_len(&self, central: bool) -> u16 {
        16 * u16::from(self.width.sizes) + 8 * u16::from(central && self.width.offset)
    }

    fn extra_len(&self, central: bool) -> u16 {
        let zip64 = self.zip64_len(central);
        zip64 + 4 * u16::from(zip64 != 0) + 9 * u16::from(self.mtime.is_some())
    }

    fn common<const N: usize>(&self, r: &mut Record<N>, crc: u32, decoded: u32, packed: u32) {
        r.u16(self.width.version());
        r.u16(self.flags);
        r.u16(match self.method {
            Method::Stored => METHOD_STORED,
            Method::Deflate(_) => METHOD_DEFLATE,
        });
        r.u16(self.dos.time);
        r.u16(self.dos.date);
        r.u32(crc);
        r.u32(packed);
        r.u32(decoded);
        r.u16(self.name_len);
    }

    pub(super) fn local(&self) -> Record<30> {
        let mut r = Record::new();
        r.u32(0x0403_4b50);
        let initial_size = if self.width.sizes { u32::MAX } else { 0 };
        self.common(&mut r, 0, initial_size, initial_size);
        r.u16(self.extra_len(false));
        r
    }

    pub(super) fn central(&self, crc: u32, decoded: u64, packed: u64) -> Result<Record<46>, WriteError> {
        let mut r = Record::new();
        r.u32(0x0201_4b50);
        r.u16(u16::from(HOST_UNIX) << 8 | self.width.version());
        self.common(&mut r, crc, self.width.size32(decoded)?, self.width.size32(packed)?);
        r.u16(self.extra_len(true));
        r.u16(self.comment_len);
        r.u16(0); // disk start
        r.u16(0); // internal attributes
        r.u32(self.external);
        r.u32(if self.width.offset { u32::MAX } else { self.local_at as u32 });
        Ok(r)
    }

    fn extras(&self, central: bool, decoded: u64, packed: u64) -> Record<37> {
        let mut r = Record::new();
        let zip64 = self.zip64_len(central);
        if zip64 != 0 {
            r.u16(0x0001);
            r.u16(zip64);
            if self.width.sizes {
                r.u64(decoded);
                r.u64(packed);
            }
            if central && self.width.offset {
                r.u64(self.local_at);
            }
        }
        if let Some(mtime) = self.mtime {
            r.u16(0x5455);
            r.u16(5);
            r.put(&[1]); // mtime only
            r.put(&mtime.to_le_bytes());
        }
        r
    }

    pub(super) fn local_extra(&self) -> Record<37> {
        self.extras(false, 0, 0)
    }

    pub(super) fn central_extra(&self, decoded: u64, packed: u64) -> Record<37> {
        self.extras(true, decoded, packed)
    }

    pub(super) fn patch(&self, crc: u32, decoded: u64, packed: u64) -> Result<Record<12>, WriteError> {
        let mut r = Record::new();
        r.u32(crc);
        if !self.width.sizes {
            r.u32(self.width.size32(packed)?);
            r.u32(self.width.size32(decoded)?);
        }
        Ok(r)
    }

    pub(super) fn crc_at(&self) -> Result<u64, WriteError> {
        add(self.local_at, 14)
    }

    pub(super) fn zip64_sizes_at(&self) -> Result<u64, WriteError> {
        add(self.local_at, LOCAL_LEN + u64::from(self.name_len) + 4)
    }
}

#[derive(Clone, Copy)]
pub(super) struct End {
    entries: u64,
    size: u64,
    at: u64,
    wide: bool,
    comment_len: u16,
}

impl End {
    pub(super) fn new(entries: u64, size: u64, at: u64, wide_member: bool, comment_len: u16) -> Self {
        let wide = wide_member || entries >= COUNT_SENTINEL || size >= SIZE_SENTINEL || at >= SIZE_SENTINEL;
        Self { entries, size, at, wide, comment_len }
    }

    fn len(&self) -> u64 {
        END_LEN + ZIP64_TAIL_LEN * u64::from(self.wide) + u64::from(self.comment_len)
    }

    pub(super) fn is_wide(&self) -> bool {
        self.wide
    }

    pub(super) fn trailer_len(&self) -> Result<u64, WriteError> {
        add(self.size, self.len())
    }

    pub(super) fn archive_extent(&self) -> Result<u64, WriteError> {
        add(self.at, self.trailer_len()?)
    }

    pub(super) fn record(&self) -> Result<Record<98>, WriteError> {
        let zip64_at = add(self.at, self.size)?;
        self.archive_extent()?;
        let mut r = Record::new();
        let (count, size, offset) = if self.wide {
            r.u32(0x0606_4b50);
            r.u64(44);
            r.u16(u16::from(HOST_UNIX) << 8 | 45);
            r.u16(45);
            r.u32(0);
            r.u32(0);
            r.u64(self.entries);
            r.u64(self.entries);
            r.u64(self.size);
            r.u64(self.at);
            r.u32(0x0706_4b50);
            r.u32(0);
            r.u64(zip64_at);
            r.u32(1);
            (u16::MAX, u32::MAX, u32::MAX)
        } else {
            (self.entries as u16, self.size as u32, self.at as u32)
        };
        r.u32(0x0605_4b50);
        r.u16(0);
        r.u16(0);
        r.u16(count);
        r.u16(count);
        r.u32(size);
        r.u32(offset);
        r.u16(self.comment_len);
        Ok(r)
    }
}
