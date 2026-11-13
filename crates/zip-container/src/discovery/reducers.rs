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

// ZIP64 and AES selection follows the zipview and zipfast readers. Unicode
// and timestamp selection follows the zipfast reader. Developed with AI assistance.

use crate::header::{le32, le64};
use crate::{
    AesView, CentralView, DirectoryError, ExtendedMtimeView, ExtraMtime, KnownExtrasView, NtfsMtimeView, Profile,
    ResolvedFields, UnicodePathView, Zip64Value, Zip64View,
};

use super::Accounting;

pub(super) fn reduce<'a>(
    view: &CentralView<'a>,
    profile: Profile,
    central_ut_only: bool,
    name_crc32: fn(&[u8]) -> u32,
    accounting: &mut Accounting,
) -> Result<(ResolvedFields, KnownExtrasView<'a>), DirectoryError> {
    let mut resolved = ResolvedFields::from_header(view.header());
    let mut known = KnownExtrasView::default();
    let mut seen_aes = false;
    let mut seen_zip64 = false;
    let mut raw_crc = None;
    let mut extras = view.extras();
    let mut remaining = usize::from(view.header().extra_len);

    while remaining > 0 {
        accounting.charge(16)?;
        let Some(Ok(extra)) = extras.next() else {
            // The wire range still contains the malformed remainder.
            break;
        };
        let body = extra.body;
        remaining -= 4 + body.len();
        match extra.id {
            0x0001 if !seen_zip64 || profile == Profile::Zipfast => {
                seen_zip64 = true;
                resolve_zip64(&mut resolved, body, profile, accounting)?;
            }
            0x9901 if !seen_aes => {
                seen_aes = profile == Profile::Zipview || body.len() >= 7;
                if body.len() >= 7 {
                    accounting.charge(7)?;
                    known.aes = Some(AesView::parse(body)?.fields());
                }
            }
            0x000a if body.len() >= 32 => {
                let ntfs = NtfsMtimeView::parse(body)?;
                accounting.charge(4)?;
                if ntfs.first_tag() == 1 && ntfs.declared_attribute_len() >= 24 {
                    accounting.charge(8)?;
                    let ticks = le64(ntfs.attribute_bytes(), 0);
                    if ticks != 0 && !central_ut_only {
                        known.mtime_override = Some(ExtraMtime::NtfsFiletime(ticks));
                    }
                }
            }
            0x5455 => {
                if central_ut_only {
                    // Each framed UT field supersedes the previous one, even without mtime.
                    known.mtime_override = None;
                }
                if !body.is_empty() {
                    let timestamp = ExtendedMtimeView::parse(body)?;
                    accounting.charge(1)?;
                    if timestamp.flags() & 1 != 0 && body.len() >= 5 {
                        accounting.charge(4)?;
                        known.mtime_override =
                            Some(ExtraMtime::UnixSeconds(le32(timestamp.timestamp_data(), 0) as i32));
                    }
                }
            }
            0x7075 if profile == Profile::Zipfast && body.len() >= 5 => {
                accounting.charge(1)?;
                let path = UnicodePathView::parse(body)?;
                if path.version() != 1 {
                    continue;
                }
                accounting.charge(4)?;
                let crc = if let Some(crc) = raw_crc {
                    crc
                } else {
                    let name = view.raw_name();
                    accounting.charge(8 * name.len() as u64)?;
                    *raw_crc.insert(name_crc32(name))
                };
                if path.name_crc32() == crc {
                    known.unicode_path = Some(path);
                }
            }
            _ => {}
        }
    }
    Ok((resolved, known))
}

fn resolve_zip64(
    resolved: &mut ResolvedFields,
    body: &[u8],
    profile: Profile,
    accounting: &mut Accounting,
) -> Result<(), DirectoryError> {
    let mut requested = resolved.unresolved;
    // Zipfast's three-value policy accepts the raw disk sentinel but never
    // consumes a fourth value. Zipview preserves it for listing when present.
    requested.disk_start &= profile == Profile::Zipview;
    let wide_fields = usize::from(requested.unpacked_size)
        + usize::from(requested.packed_size)
        + usize::from(requested.local_header_offset);
    let wide_bytes = 8 * wide_fields.min(body.len() / 8);
    let disk_bytes = 4 * usize::from(requested.disk_start && body.len() >= 8 * wide_fields + 4);
    accounting.charge((wide_bytes + disk_bytes) as u64)?;
    for value in Zip64View::new(body).fields(requested) {
        match value {
            Ok(Zip64Value::UnpackedSize(value)) => {
                resolved.unpacked_size = value;
                resolved.unresolved.unpacked_size = false;
            }
            Ok(Zip64Value::PackedSize(value)) => {
                resolved.packed_size = value;
                resolved.unresolved.packed_size = false;
            }
            Ok(Zip64Value::LocalHeaderOffset(value)) => {
                resolved.local_header_offset = value;
                resolved.unresolved.local_header_offset = false;
            }
            Ok(Zip64Value::DiskStart(value)) => {
                resolved.disk_start = value;
                resolved.unresolved.disk_start = false;
            }
            Err(_) if profile == Profile::Zipfast => return Err(DirectoryError::MalformedZip64),
            Err(_) => break,
        }
    }
    Ok(())
}

pub(super) fn ieee_crc32(bytes: &[u8]) -> u32 {
    const TABLE: [u32; 256] = ieee_table();
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc = TABLE[usize::from(crc as u8 ^ byte)] ^ (crc >> 8);
    }
    !crc
}

const fn ieee_table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < table.len() {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}
