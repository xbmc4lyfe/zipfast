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

use std::ops::Range;

pub struct Member<'a> {
    pub name: &'a [u8],
    pub payload: &'a [u8],
    pub decoded: Option<&'a [u8]>,
    pub flags: u16,
    pub method: u16,
    pub made_by: u16,
    pub external: u32,
    pub dos_date: u16,
    pub dos_time: u16,
    pub local_name: Option<&'a [u8]>,
    pub local_extra: &'a [u8],
    pub central_extra: &'a [u8],
    pub comment: &'a [u8],
    pub crc: Option<u32>,
    pub zip64: bool,
}

impl<'a> Member<'a> {
    pub fn stored(name: &'a [u8], payload: &'a [u8]) -> Self {
        Self {
            name,
            payload,
            decoded: None,
            flags: 0,
            method: 0,
            made_by: 0x0314,
            external: 0o100644 << 16,
            dos_date: 0x5022, // 2020-01-02
            dos_time: 0x1883, // 03:04:06
            local_name: None,
            local_extra: &[],
            central_extra: &[],
            comment: &[],
            crc: None,
            zip64: false,
        }
    }

    pub fn deflated(name: &'a [u8], packed: &'a [u8], decoded: &'a [u8]) -> Self {
        Self { method: 8, decoded: Some(decoded), ..Self::stored(name, packed) }
    }

    fn decoded(&self) -> &'a [u8] {
        self.decoded.unwrap_or(self.payload)
    }

    fn crc(&self) -> u32 {
        self.crc.unwrap_or_else(|| crc32fast::hash(self.decoded()))
    }
}

pub struct Fixture {
    pub bytes: Vec<u8>,
    pub local: Vec<usize>,
    pub payload: Vec<Range<usize>>,
    pub central: Vec<usize>,
    pub eocd: usize,
}

pub fn extra(id: u16, body: &[u8]) -> Vec<u8> {
    let mut field = Vec::new();
    put16(&mut field, id);
    put16(&mut field, short(body.len()));
    field.extend(body);
    field
}

/// Local records follow member order. Directory order is specified independently.
/// Offsets are ZIP-relative so adding a prefix exercises offset correction.
pub fn build(
    members: &[Member<'_>],
    central_order: &[usize],
    prefix: &[u8],
    comment: &[u8],
    zip64_end: bool,
) -> Fixture {
    let mut bytes = prefix.to_vec();
    let mut local = Vec::new();
    let mut payload = Vec::new();
    let mut central = Vec::new();
    for member in members {
        local.push(bytes.len());
        let name = member.local_name.unwrap_or(member.name);
        let crc = member.crc();
        let packed = word(member.payload.len());
        let size = word(member.decoded().len());
        let descriptor = member.flags & 8 != 0;
        let mut local_extra = member.local_extra.to_vec();
        if member.zip64 {
            let mut body = Vec::new();
            put64(&mut body, u64::from(size));
            put64(&mut body, u64::from(packed));
            local_extra.extend(extra(1, &body));
        }
        let local_size = |value| {
            if descriptor {
                0
            } else if member.zip64 {
                u32::MAX
            } else {
                value
            }
        };
        put32(&mut bytes, 0x04034b50);
        put16(&mut bytes, if member.zip64 { 45 } else { 20 });
        put16(&mut bytes, member.flags);
        put16(&mut bytes, member.method);
        put16(&mut bytes, member.dos_time);
        put16(&mut bytes, member.dos_date);
        put32(&mut bytes, if descriptor { 0 } else { crc });
        put32(&mut bytes, local_size(packed));
        put32(&mut bytes, local_size(size));
        put16(&mut bytes, short(name.len()));
        put16(&mut bytes, short(local_extra.len()));
        bytes.extend(name);
        bytes.extend(local_extra);
        let payload_start = bytes.len();
        bytes.extend(member.payload);
        payload.push(payload_start..bytes.len());
        if descriptor {
            assert!(!member.zip64, "fixture uses a classic descriptor");
            put32(&mut bytes, 0x08074b50);
            put32(&mut bytes, crc);
            put32(&mut bytes, packed);
            put32(&mut bytes, size);
        }
    }
    let directory = bytes.len();
    for &member_index in central_order {
        let member = &members[member_index];
        central.push(bytes.len());
        let offset = word(local[member_index] - prefix.len());
        let packed = word(member.payload.len());
        let size = word(member.decoded().len());
        let mut central_extra = member.central_extra.to_vec();
        if member.zip64 {
            let mut body = Vec::new();
            put64(&mut body, u64::from(size));
            put64(&mut body, u64::from(packed));
            put64(&mut body, u64::from(offset));
            central_extra.extend(extra(1, &body));
        }
        put32(&mut bytes, 0x02014b50);
        put16(&mut bytes, member.made_by);
        put16(&mut bytes, if member.zip64 { 45 } else { 20 });
        put16(&mut bytes, member.flags);
        put16(&mut bytes, member.method);
        put16(&mut bytes, member.dos_time);
        put16(&mut bytes, member.dos_date);
        put32(&mut bytes, member.crc());
        let stored_size = |value| if member.zip64 { u32::MAX } else { value };
        put32(&mut bytes, stored_size(packed));
        put32(&mut bytes, stored_size(size));
        put16(&mut bytes, short(member.name.len()));
        put16(&mut bytes, short(central_extra.len()));
        put16(&mut bytes, short(member.comment.len()));
        put16(&mut bytes, 0); // start disk
        put16(&mut bytes, 0); // internal attributes
        put32(&mut bytes, member.external);
        put32(&mut bytes, if member.zip64 { u32::MAX } else { offset });
        bytes.extend(member.name);
        bytes.extend(central_extra);
        bytes.extend(member.comment);
    }
    let count = short(central_order.len());
    let directory_size = word(bytes.len() - directory);
    let directory_offset = word(directory - prefix.len());
    if zip64_end {
        let record_offset = (bytes.len() - prefix.len()) as u64;
        put32(&mut bytes, 0x06064b50);
        put64(&mut bytes, 44); // record body size
        put16(&mut bytes, 45);
        put16(&mut bytes, 45);
        put32(&mut bytes, 0);
        put32(&mut bytes, 0);
        put64(&mut bytes, u64::from(count));
        put64(&mut bytes, u64::from(count));
        put64(&mut bytes, u64::from(directory_size));
        put64(&mut bytes, u64::from(directory_offset));
        put32(&mut bytes, 0x07064b50);
        put32(&mut bytes, 0);
        put64(&mut bytes, record_offset);
        put32(&mut bytes, 1);
    }
    let eocd = bytes.len();
    put32(&mut bytes, 0x06054b50);
    put16(&mut bytes, 0);
    put16(&mut bytes, 0);
    let stored_count = if zip64_end { u16::MAX } else { count };
    put16(&mut bytes, stored_count);
    put16(&mut bytes, stored_count);
    put32(&mut bytes, if zip64_end { u32::MAX } else { directory_size });
    put32(&mut bytes, if zip64_end { u32::MAX } else { directory_offset });
    put16(&mut bytes, short(comment.len()));
    bytes.extend(comment);
    Fixture { bytes, local, payload, central, eocd }
}

fn short(len: usize) -> u16 {
    len.try_into().unwrap()
}

fn word(len: usize) -> u32 {
    len.try_into().unwrap()
}

fn put16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend(value.to_le_bytes());
}

fn put32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend(value.to_le_bytes());
}

fn put64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend(value.to_le_bytes());
}
