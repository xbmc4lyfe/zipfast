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

use super::*;

const CENTRAL: [u8; 46] = [
    0x50, 0x4b, 1, 2, 0x31, 3, 0x14, 0, 9, 8, 0xe9, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x21, 0x43,
    0x65, 0x87, 0xff, 0xff, 0xff, 0xff, 3, 0, 5, 0, 4, 0, 0xff, 0xff, 0x66, 0x55, 0x10, 0x32, 0x54, 0x76, 0xff, 0xff,
    0xff, 0xff,
];
const LOCAL: [u8; 30] = [
    0x50, 0x4b, 3, 4, 0x15, 0, 8, 0, 0xff, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 13, 0, 0, 0, 94, 0, 0,
    0, 2, 0, 3, 0,
];

#[test]
fn central_fixed_fields_keep_wire_values() {
    let header = CentralHeader::parse(&CENTRAL).unwrap();
    assert_eq!(header.version_made_by, 0x0331);
    assert_eq!(header.version_needed, 20);
    assert_eq!(header.flags, 0x0809);
    assert_eq!(header.method, 0x01e9);
    assert_eq!(header.mod_time, 0x2211);
    assert_eq!(header.mod_date, 0x4433);
    assert_eq!(header.crc32, 0x88776655);
    assert_eq!(header.packed_size, 0x87654321);
    assert_eq!(header.unpacked_size, u32::MAX);
    assert_eq!(header.name_len, 3);
    assert_eq!(header.extra_len, 5);
    assert_eq!(header.comment_len, 4);
    assert_eq!(header.disk_start, u16::MAX);
    assert_eq!(header.internal_attributes, 0x5566);
    assert_eq!(header.external_attributes, 0x76543210);
    assert_eq!(header.local_header_offset, u32::MAX);
}

#[test]
fn local_fixed_fields_are_independent_of_central_fields() {
    let header = LocalHeader::parse(&LOCAL).unwrap();
    assert_eq!(header.version_needed, 21);
    assert_eq!(header.flags, 8);
    assert_eq!(header.method, u16::MAX);
    assert_eq!(header.mod_time, 0x3412);
    assert_eq!(header.mod_date, 0x7856);
    assert_eq!(header.crc32, 0xf0debc9a);
    assert_eq!(header.packed_size, 13);
    assert_eq!(header.unpacked_size, 94);
    assert_eq!(header.name_len, 2);
    assert_eq!(header.extra_len, 3);
    assert_eq!(LocalHeader::parse(&CENTRAL), Err(ParseError::BadSignature { offset: 0 }));
    let mut local_prefix = CENTRAL;
    local_prefix[..4].copy_from_slice(&LOCAL[..4]);
    assert_eq!(CentralHeader::parse(&local_prefix), Err(ParseError::BadSignature { offset: 0 }));
}

#[test]
fn central_view_keeps_absolute_ranges_and_available_comment() {
    let bytes = [&CENTRAL[..], b"\xffab", b"\x55\x43\x01\x00x", b"\xfe!"].concat();
    let view = CentralView::parse(&bytes, 200).unwrap();
    let source = view.location();
    assert_eq!(source.name_range(), 246..249);
    assert_eq!(source.extra_range(), 249..254);
    assert_eq!(source.comment_range(), 254..256);
    assert_eq!(source.raw_range(), 200..256);
    assert_eq!(source.declared_range(), 200..258);
    assert_eq!(source.declared_comment_len(), 4);
    assert_eq!(source.available_comment_len(), 2);
    assert_eq!(view.raw_name(), b"\xffab");
    assert_eq!(view.raw_comment(), b"\xfe!");
    let extra = view.extras().next().unwrap().unwrap();
    assert_eq!(extra.id, 0x4355);
    assert_eq!(extra.range, 249..254);
    assert_eq!(extra.body, b"x");
}

#[test]
fn central_view_requires_complete_fixed_name_and_extra_bytes() {
    let bytes = [&CENTRAL[..], b"abc", b"12345", b"xyz!"].concat();
    for (len, offset, needed, available) in [(45, 100, 46, 45), (48, 146, 3, 2), (53, 149, 5, 4)] {
        assert_eq!(
            CentralView::parse(&bytes[..len], 100).unwrap_err(),
            ParseError::Truncated { offset, needed, available }
        );
    }
    assert_eq!(CentralView::parse(&bytes, 100).unwrap().raw_comment(), b"xyz!");
    assert_eq!(LocalHeader::parse(&LOCAL[..29]), Err(ParseError::Truncated { offset: 0, needed: 30, available: 29 }));
}

#[test]
fn maximum_u16_lengths_keep_full_absolute_ranges() {
    let mut central = CENTRAL;
    central[28..34].fill(0xff);
    let mut bytes = vec![0; 196651];
    bytes[..46].copy_from_slice(&central);
    let source = CentralView::parse(&bytes, 512).unwrap().location();
    assert_eq!(source.name_range(), 558..66093);
    assert_eq!(source.extra_range(), 66093..131628);
    assert_eq!(source.comment_range(), 131628..197163);
    assert_eq!(source.raw_range(), 512..197163);
    let mut local = LOCAL;
    local[26..30].fill(0xff);
    let layout = local_layout(LocalHeader::parse(&local).unwrap(), 7, 131107).unwrap();
    assert_eq!(layout.name_range(), 37..65572);
    assert_eq!(layout.extra_range(), 65572..131107);
}

#[test]
fn absolute_offsets_are_checked_even_for_unavailable_comments() {
    let header = CentralHeader::parse(&CENTRAL).unwrap();
    assert_eq!(central_layout(header, u64::MAX - 45, u64::MAX), Err(ParseError::OffsetOverflow));
    assert_eq!(central_layout(header, u64::MAX - 54, u64::MAX), Err(ParseError::OffsetOverflow));
    assert_eq!(CentralView::parse(&CENTRAL, u64::MAX - 45).unwrap_err(), ParseError::OffsetOverflow);
    assert_eq!(ExtraIter::new(&[0], u64::MAX).unwrap_err(), ParseError::OffsetOverflow);
}

#[test]
fn local_payload_uses_supplied_packed_size_after_local_variable_fields() {
    let header = LocalHeader::parse(&LOCAL).unwrap();
    let layout = local_layout(header, 19, 54).unwrap();
    assert_eq!(layout.raw_range(), 19..54);
    assert_eq!(layout.name_range(), 49..51);
    assert_eq!(layout.extra_range(), 51..54);
    assert_eq!(layout.payload_range(u64::from(header.packed_size), 67), Ok(54..67));
    assert_eq!(layout.payload_range(0, 54), Ok(54..54));
    assert_eq!(layout.payload_range(13, 66), Err(ParseError::Truncated { offset: 54, needed: 13, available: 12 }));
    assert_eq!(layout.payload_range(u64::MAX, u64::MAX), Err(ParseError::OffsetOverflow));
    assert_eq!(local_layout(header, u64::MAX - 34, u64::MAX), Err(ParseError::OffsetOverflow));
    assert_eq!(local_layout(header, 19, 53), Err(ParseError::Truncated { offset: 51, needed: 3, available: 2 }));
}

#[test]
fn extras_keep_unknown_and_duplicate_records_in_wire_order() {
    let bytes = [0xfe, 0x7f, 1, 0, 1, 1, 0, 0, 0, 0xfe, 0x7f, 2, 0, 2, 3];
    let extras = ExtraIter::new(&bytes, 20).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(extras.len(), 3);
    assert_eq!((extras[0].id, extras[0].range.clone(), extras[0].body), (0x7ffe, 20..25, &bytes[4..5]));
    assert_eq!((extras[1].id, extras[1].range.clone(), extras[1].body), (1, 25..29, &[][..]));
    assert_eq!((extras[2].id, extras[2].range.clone(), extras[2].body), (0x7ffe, 29..35, &bytes[13..15]));
}

#[test]
fn truncated_extra_reports_exact_offset_and_stops() {
    for (bytes, expected) in [
        (&[1, 0, 0, 0, 2, 0, 1][..], ParseError::TruncatedExtraHeader { offset: 109, available: 3 }),
        (
            &[1, 0, 0, 0, 2, 0, 0xff, 0xff, 7][..],
            ParseError::TruncatedExtraBody { offset: 113, id: 2, advertised: u16::MAX, available: 1 },
        ),
    ] {
        let mut extras = ExtraIter::new(bytes, 105).unwrap();
        assert_eq!(extras.next().unwrap().unwrap().range, 105..109);
        assert_eq!(extras.next().unwrap().unwrap_err(), expected);
        assert!(extras.next().is_none());
        assert!(extras.next().is_none());
    }
}

#[test]
fn zip64_reads_only_requested_fields_in_wire_order() {
    let mut body = [0; 28];
    body[..8].copy_from_slice(&0xffff_ffff_u64.to_le_bytes());
    body[8..16].copy_from_slice(&0x2_0000_0001_u64.to_le_bytes());
    body[16..24].copy_from_slice(&0x3_0000_0002_u64.to_le_bytes());
    body[24..].copy_from_slice(&0x4_0003_u32.to_le_bytes());
    for (request, expected) in [
        (Zip64Fields::default(), vec![]),
        (Zip64Fields { unpacked_size: true, ..Default::default() }, vec![Zip64Value::UnpackedSize(0xffff_ffff)]),
        (Zip64Fields { packed_size: true, ..Default::default() }, vec![Zip64Value::PackedSize(0xffff_ffff)]),
        (
            Zip64Fields { local_header_offset: true, ..Default::default() },
            vec![Zip64Value::LocalHeaderOffset(0xffff_ffff)],
        ),
        (Zip64Fields { disk_start: true, ..Default::default() }, vec![Zip64Value::DiskStart(0xffff_ffff)]),
        (
            Zip64Fields { packed_size: true, disk_start: true, ..Default::default() },
            vec![Zip64Value::PackedSize(0xffff_ffff), Zip64Value::DiskStart(1)],
        ),
        (
            Zip64Fields { unpacked_size: true, packed_size: true, local_header_offset: true, disk_start: true },
            vec![
                Zip64Value::UnpackedSize(0xffff_ffff),
                Zip64Value::PackedSize(0x2_0000_0001),
                Zip64Value::LocalHeaderOffset(0x3_0000_0002),
                Zip64Value::DiskStart(0x4_0003),
            ],
        ),
    ] {
        let view = Zip64View::new(&body);
        assert_eq!(view.body(), &body);
        assert_eq!(view.fields(request).collect::<Result<Vec<_>, _>>().unwrap(), expected);
    }
}

#[test]
fn zip64_short_field_reports_missing_bytes_after_successful_prefix() {
    let body = [9, 0, 0, 0, 0, 0, 0, 0, 6, 5];
    let mut fields = Zip64View::new(&body).fields(Zip64Fields {
        unpacked_size: true,
        local_header_offset: true,
        disk_start: true,
        ..Default::default()
    });
    assert_eq!(fields.next(), Some(Ok(Zip64Value::UnpackedSize(9))));
    assert_eq!(fields.next(), Some(Err(ParseError::Truncated { offset: 8, needed: 8, available: 2 })));
    assert_eq!(fields.next(), None);
}

#[test]
fn aes_view_preserves_all_fields_without_acceptance_policy() {
    let body = [0x34, 0x12, b'X', b'Y', 0xfe, 0x78, 0x56, 99];
    let aes = AesView::parse(&body).unwrap();
    assert_eq!(aes.body(), &body);
    assert_eq!(aes.fields(), AesFields { vendor_version: 0x1234, vendor_id: *b"XY", strength: 0xfe, method: 0x5678 });
    assert!(AesView::parse(&body[..6]).is_err());
}

#[test]
fn unicode_path_view_leaves_version_crc_and_text_raw() {
    let body = [5, 0x11, 0x22, 0x33, 0x44, 0xff, b'x'];
    let unicode = UnicodePathView::parse(&body).unwrap();
    assert_eq!(unicode.version(), 5);
    assert_eq!(unicode.name_crc32(), 0x44332211);
    assert_eq!(unicode.path_bytes(), b"\xffx");
    assert!(UnicodePathView::parse(&body[..4]).is_err());
    assert_eq!(UnicodePathView::parse(&body[..5]).unwrap().path_bytes(), b"");
}

#[test]
fn ntfs_and_extended_timestamp_views_leave_raw_values_and_flags() {
    let ntfs = [7, 0, 0, 0, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff];
    let view = NtfsMtimeView::parse(&ntfs).unwrap();
    assert_eq!(view.reserved(), 7);
    assert_eq!(view.first_tag(), 1);
    assert_eq!(view.declared_attribute_len(), 24);
    assert_eq!(view.available_attribute_data(), &ntfs[8..]);
    assert_eq!(view.filetime(), Some(0));
    assert!(NtfsMtimeView::parse(&ntfs[..7]).is_err());
    let ntfs = [0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 8, 0, 7, 0, 0, 0, 0, 0, 0, 0];
    let view = NtfsMtimeView::parse(&ntfs).unwrap();
    assert_eq!(view.first_tag(), 2);
    assert_eq!(view.available_attribute_data(), &[]);
    assert_eq!(view.filetime(), None);
    let ut = [0x85, 0xfe, 0xff, 0xff, 0xff, 4, 5];
    let view = ExtendedMtimeView::parse(&ut).unwrap();
    assert_eq!(view.flags(), 0x85);
    assert_eq!(view.timestamp_data(), &ut[1..]);
    assert_eq!(view.unix_seconds(), Some(-2));
    assert_eq!(ExtendedMtimeView::parse(&ut[..4]).unwrap().unix_seconds(), None);
    assert_eq!(ExtendedMtimeView::parse(&[4, 1, 2, 3, 4]).unwrap().unix_seconds(), None);
    assert!(ExtendedMtimeView::parse(&[]).is_err());
}

fn owned_fixture() -> Vec<u8> {
    let mut header = CENTRAL;
    header[30] = 24;
    [
        &header[..],
        b"\xffab",
        b"\x75\x70\x06\x00\x01\0\0\0\0x",
        b"\xfe\x7f\x00\x00",
        b"\x75\x70\x06\x00\x01\0\0\0\0y",
        b"\xfe!",
    ]
    .concat()
}

#[test]
fn ownership_copies_only_projected_unicode_and_preserves_source_range() {
    let bytes = owned_fixture();
    let view = CentralView::parse(&bytes, 200).unwrap();
    let mut known = KnownExtrasView {
        aes: Some(AesFields { vendor_version: 2, vendor_id: *b"AE", strength: 3, method: 8 }),
        mtime_override: Some(ExtraMtime::NtfsFiletime(42)),
        ..Default::default()
    };
    for extra in view.extras().map(Result::unwrap).filter(|extra| extra.id == 0x7075) {
        known.unicode_path = Some(UnicodePathView::parse(extra.body).unwrap());
    }
    let winner = known.unicode_path.unwrap().path_bytes();
    assert!(std::ptr::eq(winner, &bytes[72..73]));
    let mut resolved = ResolvedFields::from_header(view.header());
    assert!(resolved.unresolved.unpacked_size);
    assert!(!resolved.unresolved.packed_size);
    assert!(resolved.unresolved.local_header_offset);
    assert!(resolved.unresolved.disk_start);
    assert_eq!(resolved.packed_size, 0x87654321);
    assert_eq!(resolved.disk_start, 0xffff);
    resolved.unresolved.unpacked_size = false;
    let exact = OwnershipUsage { entries: 1, name_bytes: 3, extra_bytes: 1, comment_bytes: 2 };
    let mut budget = OwnershipBudget::new(exact);
    let record = view.into_owned(resolved, known, &mut budget).unwrap();
    assert_eq!(budget.used(), exact);
    assert_eq!(record.raw_name.as_ref(), b"\xffab");
    assert_eq!(record.raw_comment.as_ref(), b"\xfe!");
    assert_eq!(record.known.unicode_path.as_deref(), Some(&b"y"[..]));
    assert!(!std::ptr::eq(record.known.unicode_path.as_deref().unwrap(), winner));
    assert_eq!(record.known.aes, known.aes);
    assert_eq!(record.known.mtime_override, known.mtime_override);
    assert_eq!(record.source.extra_range(), 249..273);
    assert_eq!(record.source.raw_range(), 200..275);
    assert_eq!(record.source.declared_range(), 200..277);
    assert_eq!(record.header.unpacked_size, u32::MAX);
    assert_eq!(record.resolved.unpacked_size, u64::from(u32::MAX));
    assert!(!record.resolved.unresolved.unpacked_size);
    drop(bytes);
    assert_eq!(record.known.unicode_path.as_deref(), Some(&b"y"[..]));
}

#[test]
fn ownership_limit_failure_is_atomic_for_each_counter() {
    let bytes = owned_fixture();
    let make_record = |budget: &mut OwnershipBudget| {
        let view = CentralView::parse(&bytes, 0).unwrap();
        let winner = UnicodePathView::parse(&bytes[67..73]).unwrap();
        let resolved = ResolvedFields::from_header(view.header());
        view.into_owned(resolved, KnownExtrasView { unicode_path: Some(winner), ..Default::default() }, budget)
    };
    let exact = OwnershipUsage { entries: 1, name_bytes: 3, extra_bytes: 1, comment_bytes: 2 };
    for (limits, kind, needed, limit) in [
        (OwnershipUsage { entries: 0, ..exact }, OwnershipKind::Entries, 1, 0),
        (OwnershipUsage { name_bytes: 2, ..exact }, OwnershipKind::NameBytes, 3, 2),
        (OwnershipUsage { extra_bytes: 0, ..exact }, OwnershipKind::ExtraBytes, 1, 0),
        (OwnershipUsage { comment_bytes: 1, ..exact }, OwnershipKind::CommentBytes, 2, 1),
    ] {
        let mut budget = OwnershipBudget::new(limits);
        assert_eq!(make_record(&mut budget).unwrap_err(), OwnershipError::LimitExceeded { kind, needed, limit });
        assert_eq!(budget.used(), OwnershipUsage::default());
    }
    let limits = OwnershipUsage { entries: 3, name_bytes: 6, extra_bytes: 2, comment_bytes: 4 };
    let mut budget = OwnershipBudget::new(limits);
    make_record(&mut budget).unwrap();
    make_record(&mut budget).unwrap();
    let usage = budget.used();
    assert_eq!(usage, OwnershipUsage { entries: 2, ..limits });
    assert_eq!(
        make_record(&mut budget).unwrap_err(),
        OwnershipError::LimitExceeded { kind: OwnershipKind::NameBytes, needed: 9, limit: 6 }
    );
    assert_eq!(budget.used(), usage);
}
