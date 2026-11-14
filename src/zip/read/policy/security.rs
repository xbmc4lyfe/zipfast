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

//! Read-only native parent security snapshots, distinct from namespace timestamps.
use super::*;
use crate::zip::read::shared::LedgerAccess;
use std::os::fd::RawFd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Security {
    identity: CanonicalIdentity,
    uid: libc::uid_t,
    gid: libc::gid_t,
    mode: libc::mode_t,
    ctime: (i64, i64),
}
#[allow(clippy::unnecessary_cast)] // stat field widths vary by target.
impl Security {
    fn of(stat: &libc::stat) -> Self {
        Self {
            identity: CanonicalIdentity::of(stat),
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            ctime: (stat.st_ctime as i64, stat.st_ctime_nsec as i64),
        }
    }
    fn same_policy(self, other: Self) -> bool {
        self.identity == other.identity && self.uid == other.uid && self.gid == other.gid && self.mode == other.mode
    }
}
fn operation<T>(
    ledger: &impl LedgerAccess,
    fd: RawFd,
    category: Option<RunCategory>,
    operation: ReadIoOperation,
    cancel: &Cancellation,
    mut call: impl FnMut(RawFd) -> std::io::Result<T>,
) -> Result<T, ReadFault> {
    match category {
        Some(category) => io::operation(ledger, false, category, IoStage::Output, operation, Some(cancel), || {
            spool::syscall(operation, fd, || call(fd))
        }),
        None => io::attempted_operation(ledger, false, IoStage::Output, operation, Some(cancel), || {
            spool::syscall(operation, fd, || call(fd))
        }),
    }
}
fn observe(
    ledger: &impl LedgerAccess,
    fd: RawFd,
    category: Option<RunCategory>,
    cancel: &Cancellation,
) -> Result<Security, ReadFault> {
    operation(ledger, fd, category, ReadIoOperation::Stat, cancel, native_policy::stat).map(|s| Security::of(&s))
}
pub(super) fn retained<'a>(
    ledger: shared::LedgerView<'a>,
    fd: RawFd,
    default: bool,
    category: RunCategory,
    scratch: &mut [u8],
    cancel: &Cancellation,
) -> Result<Option<MetadataLease<'a, u8>>, ReadFault> {
    // Allocate only the validated present representation, never a maximum-size
    // retained buffer for an absent ACL. The phase window is reused by reads.
    let length = operation(&ledger, fd, Some(category), ReadIoOperation::ReadAcl, cancel, |fd| {
        native_policy::read_acl(fd, default, scratch).map(|acl| acl.map(<[u8]>::len))
    })?;
    length
        .map(|len| {
            let mut bytes = MetadataLease::zeroed(ledger, PolicyComponent::NativeAcl, len)?;
            // read_acl's checked view can begin after its native attribute header.
            #[cfg(target_os = "macos")]
            let value = native_policy::parse_mac_acl(scratch)
                .map_err(|_| ReadFault::CheckedFormat { reason: "malformed retained parent ACL" })?
                .ok_or(ReadFault::InvalidPlan)?;
            #[cfg(target_os = "linux")]
            let value = &scratch[..len];
            bytes.copy_from_slice(value);
            Ok(bytes)
        })
        .transpose()
}
pub(in crate::zip::read) struct ParentPolicy {
    security: Security,
    access: Option<OwnedMetadata<u8>>,
    #[cfg(target_os = "linux")]
    default: Option<OwnedMetadata<u8>>,
}
pub(super) fn same_snapshot(a: &libc::stat, b: &libc::stat) -> bool {
    Security::of(a) == Security::of(b) && a.st_nlink == b.st_nlink && a.st_size == b.st_size
}
impl ParentPolicy {
    pub(super) fn identity(&self) -> CanonicalIdentity {
        self.security.identity
    }

    pub(in crate::zip::read) fn capture(
        ledger: &impl LedgerAccess,
        fd: RawFd,
        category: RunCategory,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<Self, ReadFault> {
        let before = observe(ledger, fd, Some(category), cancel)?;
        if before.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(ReadFault::CheckedFormat { reason: "output parent is not a directory" });
        }
        let access = retained(ledger.view(), fd, false, category, scratch, cancel)?;
        #[cfg(target_os = "linux")]
        let default = retained(ledger.view(), fd, true, category, scratch, cancel)?;
        let after = observe(ledger, fd, Some(category), cancel)?;
        if before != after {
            return Err(ReadFault::CheckedFormat { reason: "parent policy changed during snapshot" });
        }
        Ok(Self {
            security: before,
            access: access.map(MetadataLease::into_owned),
            #[cfg(target_os = "linux")]
            default: default.map(MetadataLease::into_owned),
        })
    }
    pub(in crate::zip::read) fn matches(
        &self,
        ledger: &impl LedgerAccess,
        fd: RawFd,
        category: RunCategory,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<(), ReadFault> {
        self.matches_in(ledger, fd, Some(category), scratch, cancel)
    }
    pub(in crate::zip::read) fn matches_namespace(
        &self,
        ledger: &impl LedgerAccess,
        fd: RawFd,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<(), ReadFault> {
        self.matches_in(ledger, fd, None, scratch, cancel)
    }
    fn matches_in(
        &self,
        ledger: &impl LedgerAccess,
        fd: RawFd,
        category: Option<RunCategory>,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<(), ReadFault> {
        let before = observe(ledger, fd, category, cancel)?;
        let access = operation(ledger, fd, category, ReadIoOperation::ReadAcl, cancel, |fd| {
            native_policy::read_acl(fd, false, scratch).map(|value| value == self.access.as_deref())
        })?;
        #[cfg(target_os = "linux")]
        let default = operation(ledger, fd, category, ReadIoOperation::ReadAcl, cancel, |fd| {
            native_policy::read_acl(fd, true, scratch).map(|value| value == self.default.as_deref())
        })?;
        #[cfg(not(target_os = "linux"))]
        let default = true;
        let after = observe(ledger, fd, category, cancel)?;
        if before != after || !self.security.same_policy(before) || !access || !default {
            return Err(ReadFault::CheckedFormat { reason: "output parent security policy changed" });
        }
        Ok(())
    }
    pub(in crate::zip::read) fn finish(self, ledger: &impl LedgerAccess) -> Result<(), ReadFault> {
        let access = self.access.map(|bytes| bytes.finish(ledger).map_err(|(_, fault)| fault)).transpose();
        #[cfg(target_os = "linux")]
        let default = self.default.map(|bytes| bytes.finish(ledger).map_err(|(_, fault)| fault)).transpose();
        access?;
        #[cfg(target_os = "linux")]
        default?;
        Ok(())
    }
}
