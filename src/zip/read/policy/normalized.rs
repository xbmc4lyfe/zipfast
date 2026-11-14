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

//! One fallibly charged ephemeral path spelling, never another name catalogue.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use std::os::unix::ffi::OsStrExt;
pub(in crate::zip::read) enum PathFailure {
    Unsafe,
    Fault(ReadFault),
}
pub(in crate::zip::read) struct PolicyPath {
    bytes: OwnedMetadata<u8>,
    len: usize,
}
impl PolicyPath {
    pub(in crate::zip::read) fn normalized(
        ledger: &impl LedgerAccess,
        name: &str,
        windows: bool,
        cancel: &Cancellation,
    ) -> Result<Self, PathFailure> {
        let capacity = name.len().checked_add(1).ok_or(PathFailure::Fault(ReadFault::CounterOverflow))?;
        let mut bytes =
            MetadataLease::zeroed(ledger.view(), PolicyComponent::Caller, capacity).map_err(PathFailure::Fault)?;
        let mut at = 0;
        for (i, part) in name.split(|c| c == '/' || windows && c == '\\').enumerate() {
            io::canceled(Some(cancel)).map_err(PathFailure::Fault)?;
            match part {
                "" if i == 0 && !name.is_empty() => return Err(PathFailure::Unsafe),
                "" | "." => continue,
                ".." => return Err(PathFailure::Unsafe),
                _ => {}
            }
            if part.contains('\0') || windows && i == 0 && part.len() == 2 && part.ends_with(':') {
                return Err(PathFailure::Unsafe);
            }
            if at != 0 {
                bytes[at] = b'/';
                at += 1;
            }
            for c in part.chars() {
                if windows && matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
                    bytes[at] = b'_';
                    at += 1;
                } else {
                    let mut utf8 = [0; 4];
                    let encoded = c.encode_utf8(&mut utf8).as_bytes();
                    bytes[at..at + encoded.len()].copy_from_slice(encoded);
                    at += encoded.len();
                }
            }
        }
        if at == 0 {
            return Err(PathFailure::Unsafe);
        }
        Ok(Self { bytes: bytes.into_owned(), len: at })
    }
    pub(in crate::zip::read) fn joined(
        ledger: &impl LedgerAccess,
        root: &Path,
        relative: &Path,
    ) -> Result<Self, ReadFault> {
        let root = root.as_os_str().as_bytes();
        let rel = relative.as_os_str().as_bytes();
        let separator = usize::from(!root.is_empty());
        let capacity = root
            .len()
            .checked_add(rel.len())
            .and_then(|n| n.checked_add(separator + 1))
            .ok_or(ReadFault::CounterOverflow)?;
        let mut bytes = MetadataLease::zeroed(ledger.view(), PolicyComponent::Caller, capacity)?;
        bytes[..root.len()].copy_from_slice(root);
        if separator != 0 {
            bytes[root.len()] = b'/';
        }
        bytes[root.len() + separator..capacity - 1].copy_from_slice(rel);
        Ok(Self { bytes: bytes.into_owned(), len: capacity - 1 })
    }
    pub(in crate::zip::read) fn cstr(&self) -> Result<&std::ffi::CStr, ReadFault> {
        std::ffi::CStr::from_bytes_with_nul(&self.bytes[..=self.len]).map_err(|_| ReadFault::InvalidPlan)
    }
    pub(in crate::zip::read) fn path(&self) -> &Path {
        Path::new(std::ffi::OsStr::from_bytes(&self.bytes[..self.len]))
    }
    pub(in crate::zip::read) fn finish(self, ledger: &impl LedgerAccess) -> Result<(), ReadFault> {
        self.bytes.finish(ledger).map_err(|(_, fault)| fault)
    }
}
