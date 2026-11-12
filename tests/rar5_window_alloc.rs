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

//! Dictionary allocation faults in a separate test process.
mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{env, fs, ptr};

use common::{FileSpec, archive_with};
use zipfast::error::{RarFailure, RarResource};
use zipfast::extract::{Mode, Options, Overwrite, RarOutcome, RarOutput, run_rar_with_outcomes};
use zipfast::rar5::testenc::{Op, block};
use zipfast::rar5::unpack::{Unpacker, Window, window_for};

const WINDOW_BYTES: usize = 128 * 1024;
const CHILD_ENV: &str = "ZIPFAST_TEST_REFUSE_RAR_DICTIONARY";
static REFUSE_WINDOW: AtomicBool = AtomicBool::new(false);

struct WindowFaultAllocator;

// SAFETY: The allocator delegates all successful allocations and deallocations to System.
unsafe impl GlobalAlloc for WindowFaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if layout.size() == WINDOW_BYTES && layout.align() == 1 && REFUSE_WINDOW.load(Ordering::Relaxed) {
            return ptr::null_mut();
        }
        // SAFETY: The caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, allocation: *mut u8, layout: Layout) {
        // SAFETY: All successful allocations came from System with this layout.
        unsafe { System.dealloc(allocation, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: WindowFaultAllocator = WindowFaultAllocator;

#[test]
fn dictionary_allocation_refusal_is_reported_by_bulk_rar() {
    if let Some(archive) = env::var_os(CHILD_ENV) {
        check_archive(Path::new(&archive), true);
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("window.rar");
    let packed = block(&[Op::Lit(b'x')], true, true);
    let compressed = FileSpec { method: 3, size: Some(1), ..FileSpec::new("compressed", &packed) };
    let later = FileSpec::new("later", b"ok");
    fs::write(&archive, archive_with(&[(compressed, crc32fast::hash(b"x")), (later, crc32fast::hash(b"ok"))], false))
        .unwrap();

    check_archive(&archive, false);
    let child = Command::new(env::current_exe().unwrap())
        .args(["--exact", "dictionary_allocation_refusal_is_reported_by_bulk_rar", "--nocapture"])
        .env(CHILD_ENV, &archive)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "dictionary refusal subprocess exited with {}\nstdout:\n{}\nstderr:\n{}",
        child.status,
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr),
    );
}

fn check_archive(archive: &Path, refuse: bool) {
    let opts = Options {
        mode: Mode::Test,
        dest: archive.parent().unwrap().to_path_buf(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let mut seen = 0;
    REFUSE_WINDOW.store(refuse, Ordering::Relaxed);
    let result = run_rar_with_outcomes(archive, &opts, None, |entry| {
        match (seen, refuse, &entry.outcome) {
            (0, true, RarOutcome::Failed(failure)) => assert!(
                matches!(
                    failure.as_ref(),
                    RarFailure::Limit {
                        resource: RarResource::DictionaryAllocation,
                        requested: Some(131_072),
                        allowed: None,
                        ..
                    }
                ),
                "{failure:?}"
            ),
            (0, false, RarOutcome::Verified { bytes: 1, output: RarOutput::Tested, .. })
            | (1, _, RarOutcome::Verified { bytes: 2, output: RarOutput::Tested, .. }) => {}
            _ => panic!("unexpected RAR outcome {entry:?}"),
        }
        seen += 1;
    });
    REFUSE_WINDOW.store(false, Ordering::Relaxed);
    let summary = result.unwrap();
    assert_eq!(seen, 2);
    assert_eq!((summary.files, summary.bytes, summary.failed), if refuse { (1, 2, 1) } else { (2, 3, 0) });
}

#[test]
fn invalid_dictionary_and_capacity_keep_their_legacy_errors() {
    let Err(zipfast::Error::Unsupported(message)) = window_for(3, Some(1), false) else {
        panic!("invalid dictionary was accepted");
    };
    assert_eq!(message, "dictionary size 3");

    const TOO_LARGE: u64 = 1 << 63;
    let Err(zipfast::Error::Unsupported(message)) = Unpacker::new(Window::full(TOO_LARGE)) else {
        panic!("out-of-range capacity was accepted");
    };
    if usize::try_from(TOO_LARGE).is_ok() {
        assert_eq!(message, format!("can't allocate a {TOO_LARGE} byte window"));
    } else {
        assert_eq!(message, "dictionary too large");
    }
}
