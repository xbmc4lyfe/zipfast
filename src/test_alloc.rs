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

//! Shared allocation controls for independent library test suites.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    pub(crate) static REFUSE_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    pub(crate) static TRACK_ALLOC: Cell<bool> = const { Cell::new(false) };
    pub(crate) static ALLOC_REQUESTS: Cell<usize> = const { Cell::new(0) };
    pub(crate) static DEALLOC_REQUESTS: Cell<usize> = const { Cell::new(0) };
    pub(crate) static DENY_LAYOUT: Cell<Option<(usize, usize)>> = const { Cell::new(None) };
    pub(crate) static DENY_DICTIONARY: Cell<bool> = const { Cell::new(false) };
}

struct TestAllocator;
#[global_allocator]
static ALLOCATOR: TestAllocator = TestAllocator;

fn allowed(layout: Layout) -> bool {
    if REFUSE_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
        return false;
    }
    if TRACK_ALLOC.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOC_REQUESTS.try_with(|count| count.set(count.get().saturating_add(1)));
    }
    if DENY_LAYOUT
        .try_with(|control| {
            if control.get() == Some((layout.size(), layout.align())) {
                control.set(None);
                true
            } else {
                false
            }
        })
        .unwrap_or(false)
    {
        return false;
    }
    !(layout.size() == 65536
        && layout.align() == 1
        && DENY_DICTIONARY.try_with(|flag| flag.replace(false)).unwrap_or(false))
}

// SAFETY: admitted requests preserve the original layout and pointer when
// delegated to System. Refused requests return null. Deallocation always
// delegates. Constant-initialized controls affect only the calling test thread.
unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if allowed(layout) { unsafe { System.alloc(layout) } } else { std::ptr::null_mut() }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if allowed(layout) { unsafe { System.alloc_zeroed(layout) } } else { std::ptr::null_mut() }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Ok(resized) = Layout::from_size_align(size, layout.align()) else {
            return std::ptr::null_mut();
        };
        if allowed(resized) { unsafe { System.realloc(pointer, layout, size) } } else { std::ptr::null_mut() }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if TRACK_ALLOC.try_with(Cell::get).unwrap_or(false) {
            let _ = DEALLOC_REQUESTS.try_with(|count| count.set(count.get().saturating_add(1)));
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}
