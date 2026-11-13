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

//! Exactly two role-specific owners of a single fallibly allocated header.
use super::{ReadFault, ZipReadResult, budget::LedgerState};
use std::{
    alloc::{Layout, alloc, dealloc},
    cell::{Cell, RefCell},
    marker::PhantomData,
    ptr::NonNull,
    rc::Rc,
};
struct SharedHeader {
    context_alive: Cell<bool>,
    token_alive: Cell<bool>,
    owners: Cell<u8>,
    state: RefCell<LedgerState>,
    _local: PhantomData<Rc<()>>,
}
pub(super) const SHARED_LEDGER_CAPACITY: usize = std::mem::size_of::<SharedHeader>();
#[cfg(test)]
pub(super) fn header_layout() -> (usize, usize) {
    (SHARED_LEDGER_CAPACITY, std::mem::align_of::<SharedHeader>())
}
pub(super) struct ContextLedger {
    pointer: NonNull<SharedHeader>,
    _local: PhantomData<Rc<()>>,
}
pub(super) struct ReservationLedger {
    pointer: NonNull<SharedHeader>,
    _local: PhantomData<Rc<()>>,
}

// SAFETY INVARIANT: alloc(Layout::new::<SharedHeader>()) initializes exactly one
// header, and its original provenance/layout is retained in both non-Clone role
// handles. Context starts as the sole owner; mint creates at most one token.
// Every handle is !Send + !Sync through Rc PhantomData, so Cell role transitions
// cannot race. Each drop clears only its own live role and decrements 1..=2.
// The final role alone drops the initialized header and deallocates its pointer.
// No pointer/reference or RefMut escapes with_state; every application callback
// and syscall occurs after it returns. Context-first drop leaves token ownership
// and unresolved-resource poison intact until the final token drops.
impl ContextLedger {
    #[allow(clippy::result_large_err)] // Fixed inline evidence must survive allocator refusal.
    pub(super) fn try_new(state: LedgerState) -> ZipReadResult<Self> {
        let layout = Layout::new::<SharedHeader>();
        // SAFETY: checked null before initialization; layout is nonzero and valid.
        let pointer = NonNull::new(unsafe { alloc(layout) }.cast::<SharedHeader>())
            .ok_or(ReadFault::Allocation { capacity: SHARED_LEDGER_CAPACITY })?;
        unsafe {
            pointer.as_ptr().write(SharedHeader {
                context_alive: Cell::new(true),
                token_alive: Cell::new(false),
                owners: Cell::new(1),
                state: RefCell::new(state),
                _local: PhantomData,
            });
        }
        Ok(Self { pointer, _local: PhantomData })
    }
    fn header(&self) -> &SharedHeader {
        unsafe { self.pointer.as_ref() }
    }
    #[allow(clippy::result_large_err)] // Fixed inline evidence; mint itself never allocates.
    pub(super) fn mint_reservation(&mut self) -> ZipReadResult<ReservationLedger> {
        let header = self.header();
        assert!(header.context_alive.get());
        if header.token_alive.get() || header.state.borrow().poisoned {
            return Err(ReadFault::InvalidPlan.into());
        }
        assert_eq!(header.owners.get(), 1);
        header.token_alive.set(true);
        header.owners.set(2);
        Ok(ReservationLedger { pointer: self.pointer, _local: PhantomData })
    }
    pub(super) fn with_state<T>(&self, f: impl FnOnce(&mut LedgerState) -> T) -> T {
        f(&mut self.header().state.borrow_mut())
    }
}
impl ReservationLedger {
    pub(super) fn with_state<T>(&self, f: impl FnOnce(&mut LedgerState) -> T) -> T {
        // SAFETY: this live token retains its role's initialized allocation.
        let header = unsafe { self.pointer.as_ref() };
        assert!(header.token_alive.get());
        f(&mut header.state.borrow_mut())
    }
}
unsafe fn release(pointer: NonNull<SharedHeader>, context: bool) {
    // SAFETY: caller owns the unique role being retired; header lives until last role.
    let header = unsafe { pointer.as_ref() };
    let role = if context { &header.context_alive } else { &header.token_alive };
    assert!(role.replace(false), "role retired exactly once");
    let owners = header.owners.get();
    assert!((1..=2).contains(&owners));
    header.owners.set(owners - 1);
    if owners == 1 {
        unsafe {
            std::ptr::drop_in_place(pointer.as_ptr());
            dealloc(pointer.as_ptr().cast(), Layout::new::<SharedHeader>());
        }
    }
}
impl Drop for ContextLedger {
    fn drop(&mut self) {
        unsafe { release(self.pointer, true) }
    }
}
impl Drop for ReservationLedger {
    fn drop(&mut self) {
        unsafe { release(self.pointer, false) }
    }
}
