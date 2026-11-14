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

//! Exact native namespace evidence. Policy metadata is separate from payload scratch.
use super::*;
#[cfg(target_os = "macos")]
mod mac;
#[cfg(target_os = "macos")]
pub(super) use mac::canonicalize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CanonicalIdentity {
    pub(super) dev: u64,
    pub(super) ino: u64,
    pub(super) kind: u32,
}
#[allow(clippy::unnecessary_cast)] // dev/mode ABI widths differ between supported Unix targets.
impl CanonicalIdentity {
    pub(in crate::zip::read) fn of(s: &libc::stat) -> Self {
        Self { dev: s.st_dev as u64, ino: s.st_ino as u64, kind: s.st_mode as u32 & libc::S_IFMT as u32 }
    }
}
#[derive(Debug)]
#[cfg_attr(target_os = "linux", allow(clippy::large_enum_variant))] // A Linux metadata close can fail under allocator refusal; its fixed cleanup evidence cannot be boxed.
pub(super) enum CanonicalFailure {
    /// Only an ordinary first-pass resolution failure can omit an optional key.
    Ordinary(ReadFault),
    Terminal(ReadFault),
    #[cfg(target_os = "linux")]
    Cleanup(ZipReadError),
}
impl CanonicalFailure {
    pub(super) fn into_error(self) -> ZipReadError {
        match self {
            Self::Ordinary(fault) | Self::Terminal(fault) => fault.into(),
            #[cfg(target_os = "linux")]
            Self::Cleanup(error) => error,
        }
    }
}
#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy, Debug)]
pub(super) enum CanonicalOperation {
    RootStat,
    ComponentName,
    ComponentStat,
    ReadLink,
    MountInfo,
    MountRootStat,
    MountPrefixStat,
    TerminalRequestedStat,
    TerminalStat,
}
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub(super) enum CanonicalOperation {
    Open,
    HeldStat,
    OriginalStat,
    ProcStat,
    ReadLink,
    CanonicalStat,
    FinalStat,
}
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::{CanonicalRequest, canonicalize};
pub(super) struct CanonicalEvidence {
    pub(super) identity: CanonicalIdentity,
    start: usize,
    len: usize,
}
impl CanonicalEvidence {
    pub(super) fn bytes<'a>(&self, scratch: &'a [u8]) -> &'a [u8] {
        &scratch[self.start..self.start + self.len]
    }
}

#[cfg(all(test, target_os = "macos"))]
pub(super) fn between_passes(hook: Option<Box<dyn FnMut()>>) {
    mac::BETWEEN_PASSES.with(|state| *state.borrow_mut() = hook);
}
#[cfg(all(test, target_os = "macos"))]
pub(super) fn canonical_layout() -> [usize; 4] {
    mac::layout()
}

mod metadata;
pub(super) use budget::PolicyComponent;
pub(super) use metadata::{MetadataLease, OwnedMetadata, PolicyScratch};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod frozen;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) use frozen::FrozenPolicy;

mod security;
pub(super) use security::ParentPolicy;

mod probe;
pub(super) use probe::{ChildPolicy, probe};

mod normalized;
pub(super) use normalized::{PathFailure, PolicyPath};

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(super) mod cwd;
