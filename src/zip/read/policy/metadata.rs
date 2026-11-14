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

//! Fallible separately scoped allocation, with lexical construction and explicit owned transfer.
use super::*;
use crate::zip::read::shared::{LedgerAccess, LedgerIdentity, LedgerView};
use std::ops::{Deref, DerefMut};

pub(in crate::zip::read) struct MetadataLease<'a, T> {
    bytes: Vec<T>,
    ledger: LedgerView<'a>,
    kind: PolicyComponent,
    requested: usize,
    capacity: usize,
    elements: usize,
}
#[derive(Debug)]
pub(in crate::zip::read) struct OwnedMetadata<T> {
    bytes: Vec<T>,
    identity: LedgerIdentity,
    kind: PolicyComponent,
    requested: usize,
    capacity: usize,
}
impl<'a, T> MetadataLease<'a, T> {
    pub(in crate::zip::read) fn new(
        ledger: LedgerView<'a>,
        kind: PolicyComponent,
        elements: usize,
    ) -> Result<Self, ReadFault> {
        let unit = std::mem::size_of::<T>();
        if unit == 0 {
            return Err(ReadFault::InvalidPlan);
        }
        let requested = elements.checked_mul(unit).ok_or(ReadFault::CounterOverflow)?;
        let mut bytes = Vec::new();
        let mut capacity = 0;
        if requested != 0 {
            ledger.with_state(|s| s.begin_policy_allocation(kind, requested))?;
            if bytes.try_reserve_exact(elements).is_err() {
                return Err(ReadFault::Allocation { capacity: requested });
            }
            capacity = bytes.capacity().checked_mul(unit).ok_or(ReadFault::CounterOverflow)?;
            ledger.with_state(|s| s.acquired_policy_allocation(kind, requested, capacity))?;
            if kind == PolicyComponent::Scratch && capacity > 65536 {
                ledger.with_state(|s| s.release_policy_allocation(kind, requested, capacity));
                return Err(ReadFault::Limit {
                    resource: ReadResource::PolicyScratchBytes,
                    limit: 65536,
                    attempted: capacity as u128,
                });
            }
        }
        Ok(Self { bytes, ledger, kind, requested, capacity, elements })
    }
    pub(in crate::zip::read) fn push(&mut self, value: T) -> Result<(), ReadFault> {
        if self.bytes.len() == self.elements {
            return Err(ReadFault::InvalidPlan);
        }
        self.bytes.push(value);
        Ok(())
    }
    pub(in crate::zip::read) fn pop(&mut self) -> Option<T> {
        self.bytes.pop()
    }
    pub(in crate::zip::read) fn into_owned(mut self) -> OwnedMetadata<T> {
        let bytes = std::mem::take(&mut self.bytes);
        let owned = OwnedMetadata {
            bytes,
            identity: self.ledger.identity(),
            kind: self.kind,
            requested: self.requested,
            capacity: self.capacity,
        };
        self.capacity = 0;
        owned
    }
}
impl<'a> MetadataLease<'a, u8> {
    pub(in crate::zip::read) fn zeroed(
        ledger: LedgerView<'a>,
        kind: PolicyComponent,
        bytes: usize,
    ) -> Result<Self, ReadFault> {
        let mut lease = Self::new(ledger, kind, bytes)?;
        lease.bytes.resize(bytes, 0);
        Ok(lease)
    }
}
impl<T> OwnedMetadata<T> {
    pub(in crate::zip::read) fn push_bounded(&mut self, value: T) -> Result<(), ReadFault> {
        let bytes = self
            .bytes
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(std::mem::size_of::<T>()))
            .ok_or(ReadFault::CounterOverflow)?;
        if bytes > self.requested || self.bytes.len() == self.bytes.capacity() {
            return Err(ReadFault::InvalidPlan);
        }
        self.bytes.push(value);
        Ok(())
    }

    pub(in crate::zip::read) fn pop(&mut self) -> Option<T> {
        self.bytes.pop()
    }
    pub(in crate::zip::read) fn finish(self, ledger: &impl LedgerAccess) -> Result<(), (Self, ReadFault)> {
        if self.identity != ledger.identity() {
            return Err((self, ReadFault::InvalidPlan));
        }
        if self.capacity != 0 {
            ledger.with_state(|s| s.release_policy_allocation(self.kind, self.requested, self.capacity));
        }
        drop(self);
        Ok(())
    }
}
impl<T> Drop for MetadataLease<'_, T> {
    fn drop(&mut self) {
        if self.capacity != 0 {
            self.ledger.with_state(|s| s.release_policy_allocation(self.kind, self.requested, self.capacity));
        }
    }
}
impl<T> Deref for MetadataLease<'_, T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.bytes
    }
}
impl<T> DerefMut for MetadataLease<'_, T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.bytes
    }
}
impl<T> Deref for OwnedMetadata<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.bytes
    }
}
impl<T> DerefMut for OwnedMetadata<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.bytes
    }
}

/// The sole phase window has native alignment even with a minimal global allocator.
pub(in crate::zip::read) struct PolicyScratch<'a> {
    storage: MetadataLease<'a, u128>,
}
impl<'a> PolicyScratch<'a> {
    pub(in crate::zip::read) fn new(ledger: LedgerView<'a>) -> Result<Self, ReadFault> {
        let mut storage = MetadataLease::new(ledger, PolicyComponent::Scratch, 65536 / 16)?;
        storage.bytes.resize(65536 / 16, 0u128);
        Ok(Self { storage })
    }
}
impl Deref for PolicyScratch<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: initialized u128 storage has native alignment, all bit patterns
        // are valid, and the immutable byte view covers exactly its initialized size.
        unsafe { std::slice::from_raw_parts(self.storage.bytes.as_ptr().cast(), self.storage.bytes.len() * 16) }
    }
}
impl DerefMut for PolicyScratch<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: this unique borrow excludes typed/byte aliases; every byte
        // pattern written by native metadata APIs remains a valid u128 value.
        unsafe { std::slice::from_raw_parts_mut(self.storage.bytes.as_mut_ptr().cast(), self.storage.bytes.len() * 16) }
    }
}
