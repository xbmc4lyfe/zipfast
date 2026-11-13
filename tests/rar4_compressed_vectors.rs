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

//! Local RED checkpoint for independently specified fixed RAR4 bit vectors.
//! Provenance and bit-by-bit derivation are in the shared SDD worksheet.
//! This wraps fixed bytes with headers and does not compress arbitrary data.

#![cfg(unix)]

use zipfast::crc32::hash;
use zipfast::rar5::session::{RarDecodeLimits, RarPrintOptions, RarSession, RarSessionOptions};

fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0, 0, kind];
    bytes.extend(flags.to_le_bytes());
    bytes.extend(((body.len() + 7) as u16).to_le_bytes());
    bytes.extend(body);
    let crc = hash(&bytes[2..]) as u16;
    bytes[..2].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn fixed_archive(packed: &[u8], expected: &[u8]) -> Vec<u8> {
    let name = b"vector";
    let mut body = Vec::new();
    body.extend((packed.len() as u32).to_le_bytes());
    body.extend((expected.len() as u32).to_le_bytes());
    body.push(3);
    body.extend(hash(expected).to_le_bytes());
    body.extend(0x50221884u32.to_le_bytes());
    body.extend([29, 0x33]);
    body.extend((name.len() as u16).to_le_bytes());
    body.extend(0o100644u32.to_le_bytes());
    body.extend(name);
    let mut bytes = b"Rar!\x1a\x07\0".to_vec();
    bytes.extend(block(0x73, 0, &[0; 6]));
    bytes.extend(block(0x74, 0x8000, &body));
    bytes.extend(packed);
    bytes.extend(block(0x7b, 0x4000, &[]));
    bytes
}

fn verify(packed: &[u8], expected: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixed.rar");
    std::fs::write(&path, fixed_archive(packed, expected)).unwrap();
    let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
    let selection = session.select(|_| true).unwrap();
    let mut events = Vec::new();
    let result = session
        .test_selected(&selection, RarDecodeLimits::default(), |event| events.push(format!("{event:?}")))
        .unwrap();
    assert_eq!((result.files, result.failed), (1, 0), "fixed version-29 LZ vector must verify. Events {events:?}");
    let mut stdout = Vec::new();
    session.print_selected(&selection, &mut stdout, &RarPrintOptions::default(), |_| {}).unwrap();
    assert_eq!(stdout, expected);
}

#[test]
fn literal_a() {
    verify(include_bytes!("fixtures/rar4-lz/literal-a.packed"), b"A");
}

#[test]
fn initial_delta_zero_baseline() {
    verify(include_bytes!("fixtures/rar4-lz/initial-delta-zero-baseline.packed"), b"A");
}

#[test]
fn table_reuse_delta() {
    verify(include_bytes!("fixtures/rar4-lz/table-reuse-delta.packed"), b"AA");
}

#[test]
fn code_length_nibble_zero_run() {
    verify(include_bytes!("fixtures/rar4-lz/code-length-nibble-zero-run.packed"), b"A");
}

#[test]
fn new_match_repeat_last() {
    verify(include_bytes!("fixtures/rar4-lz/new-match-repeat-last.packed"), b"AAAAAAA");
}

#[test]
fn recent_distance_repeat() {
    verify(include_bytes!("fixtures/rar4-lz/recent-distance-repeat.packed"), b"AAAAAA");
}

#[test]
fn short_distance_match() {
    verify(include_bytes!("fixtures/rar4-lz/short-distance-match.packed"), b"AAA");
}

#[test]
fn zero_length_runs() {
    verify(include_bytes!("fixtures/rar4-lz/zero-length-runs.packed"), b"A");
}

#[test]
fn previous_length_runs() {
    verify(include_bytes!("fixtures/rar4-lz/previous-length-runs.packed"), b"AP");
}
