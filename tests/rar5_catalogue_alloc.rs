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

#![cfg(unix)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::{env, fs, path::Path, ptr};

use common::{SIG, block, end_block, main_block, vint};
use zipfast::error::{RarFailure, RarResource};
use zipfast::rar5::session::{RarSession, RarSessionOptions};

const CHILD_MODE: &str = "ZIPFAST_TEST_CATALOGUE_ALLOC_MODE";
const CHILD_PATH: &str = "ZIPFAST_TEST_CATALOGUE_ALLOC_PATH";
const WIDTH: usize = 13_337;
static SIZE: AtomicUsize = AtomicUsize::new(0);
static ALIGN: AtomicUsize = AtomicUsize::new(1);
static REMAINING: AtomicUsize = AtomicUsize::new(0);

struct FaultAllocator;

// SAFETY: Every accepted request uses System with the original layout.
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == SIZE.load(Relaxed)
            && layout.align() == ALIGN.load(Relaxed)
            && REMAINING.try_update(Relaxed, Relaxed, |value| value.checked_sub(1)) == Ok(1)
        {
            return ptr::null_mut();
        }
        // SAFETY: The caller supplies a valid allocation layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The allocation was accepted by System with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[test]
fn catalogue_string_allocation_refusal_returns_typed_error() {
    if let Some(mode) = env::var_os(CHILD_MODE) {
        let path = env::var_os(CHILD_PATH).unwrap();
        let (size, request) = match mode.to_str().unwrap() {
            "display" | "target" => (WIDTH, 1),
            "raw" => (WIDTH, 2),
            "lossy-display" | "lossy-target" => (WIDTH + 2, 1),
            "issue" | "incomplete" => (2 * size_of::<RarFailure>(), 1),
            _ => panic!("unknown test mode"),
        };
        if matches!(mode.to_str().unwrap(), "issue" | "incomplete") {
            ALIGN.store(align_of::<RarFailure>(), Relaxed);
        }
        REMAINING.store(request, Relaxed);
        SIZE.store(size, Relaxed);
        let result = RarSession::open(Path::new(&path), None, RarSessionOptions::default());
        SIZE.store(0, Relaxed);
        assert_eq!(REMAINING.load(Relaxed), 0, "allocation fault did not run");
        let failure = result.err().expect("allocation refusal must stop the catalogue");
        assert!(matches!(
            failure.failure.as_ref(),
            RarFailure::Limit { resource: RarResource::CatalogueAllocation, .. }
        ));
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    for (mode, target, lossy) in [
        ("display", false, false),
        ("raw", false, false),
        ("target", true, false),
        ("lossy-display", false, true),
        ("lossy-target", true, true),
    ] {
        let archive = dir.path().join(format!("{mode}.rar"));
        let mut text = vec![b'a'; WIDTH];
        if lossy {
            text[WIDTH - 1] = 0xff;
        }
        let name = if target { b"link".as_slice() } else { text.as_slice() };
        let mut fields = vec![0, 0, 0, 0, 1];
        vint(name.len() as u64, &mut fields);
        fields.extend(name);
        let mut extra = Vec::new();
        if target {
            let mut record = vec![5, 1, 0];
            vint(text.len() as u64, &mut record);
            record.extend(&text);
            vint(record.len() as u64, &mut extra);
            extra.extend(record);
        }
        let mut bytes = SIG.to_vec();
        bytes.extend(main_block(false, None));
        bytes.extend(block(2, 0, &fields, &extra, b"", false));
        bytes.extend(end_block(false));
        fs::write(&archive, &bytes).unwrap();
        let session = RarSession::open(&archive, None, RarSessionOptions::default()).unwrap();
        let member = session.entries().next().unwrap();
        if target {
            assert!(matches!(member.redirection(), Some(zipfast::rar5::Redirection::UnixSymlink(value))
                if value == &String::from_utf8_lossy(&text)));
        } else {
            assert_eq!(member.name(), String::from_utf8_lossy(&text));
        }
        assert_eq!(fs::read(&archive).unwrap(), bytes);

        let child = Command::new(env::current_exe().unwrap())
            .args(["--exact", "catalogue_string_allocation_refusal_returns_typed_error", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_PATH, archive)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{mode} fault exited with {}\nstdout:\n{}\nstderr:\n{}",
            child.status,
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr),
        );
    }
}

#[test]
fn catalogue_payload_issue_allocation_refusal_returns_typed_error() {
    let dir = tempfile::tempdir().unwrap();
    let name = "member";
    for (mode, extra, flags) in [("issue", &[2, 1, 0][..], 0), ("incomplete", &[][..], 16)] {
        let path = dir.path().join(format!("{mode}.rar"));
        let mut fields = vec![0, 0, 0, 0, 1, name.len() as u8];
        fields.extend(name.as_bytes());
        let mut bytes = SIG.to_vec();
        bytes.extend(main_block(false, None));
        bytes.extend(block(2, 0, &fields, &[2, 1, 0], b"", false));
        bytes.extend(block(2, flags, &fields, extra, b"", false));
        bytes.extend(end_block(false));
        fs::write(&path, bytes).unwrap();
        let session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        assert!(session.entries().all(|member| member.payload_issue().is_some()));
        let child = Command::new(env::current_exe().unwrap())
            .args(["--exact", "catalogue_string_allocation_refusal_returns_typed_error", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env(CHILD_PATH, path)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{mode} fault exited with {}\nstdout:\n{}\nstderr:\n{}",
            child.status,
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr),
        );
    }
}
