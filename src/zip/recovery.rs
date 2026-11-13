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

//! Central-directed recovery into a new, verified ZIP.
//!
//! Requires an unambiguous single-disk central directory. Stored and raw
//! Deflate candidates are verified individually; unsupported or damaged
//! members are reported as omissions. Special Unix entry kinds are omitted;
//! directories must be structurally empty. Local-signature scanning and split
//! recovery are separate operations and are not provided here.
//!
//! Publication never replaces an existing destination. Keep source and
//! destination namespaces under caller control through completion.

use super::create::Durability;
use super::rewrite::{RewriteFailure, RewriteLimits, RewriteUsage, RewrittenArchive};
use crate::extract::Cancellation;

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use super::rewrite::native::recovery::RecoveryPlan;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub use unsupported::RecoveryPlan;

/// Recovery budgets and publication policy. Component limits do not bound RSS.
#[derive(Clone)]
pub struct RecoveryOptions {
    pub limits: RewriteLimits,
    pub durability: Durability,
    pub output_permissions: u16,
    pub cancel: Cancellation,
}
impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            limits: RewriteLimits::default(),
            durability: Durability::VisibilityOnly,
            output_permissions: 0o644,
            cancel: Cancellation::default(),
        }
    }
}

/// A member-local reason for omission. Infrastructure and source changes
/// terminate the run instead of becoming omissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryIssue {
    UnsupportedPayload,
    UnsupportedEntryKind,
    Framing(&'static str),
    Payload(&'static str),
}

/// Verification result for one source central-directory occurrence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRecovery {
    Verified { descriptor_repaired: bool },
    Omitted(RecoveryIssue),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryEntry {
    pub source_ordinal: usize,
    pub outcome: MemberRecovery,
}

/// Publication is separate from the member recovery results.
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// No member survived; no stage or destination was created.
    NoMembers {
        usage: RewriteUsage,
    },
    Published(RewrittenArchive),
}

/// Completed member assessments survive a later terminal failure. Their
/// ordinals refer to the original snapshot; published verification is in
/// output central order. Names are available from the plan's metadata.
#[derive(Debug)]
#[must_use]
pub struct RecoveryReport {
    pub entries: Vec<RecoveryEntry>,
    pub outcome: Result<RecoveryOutcome, RewriteFailure>,
}
