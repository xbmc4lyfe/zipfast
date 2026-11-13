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

//! Stage and verify a ZIP replacement while preserving retained wire records.
//! Publication uses explicit last-writer-wins semantics on qualified local
//! filesystems. Keep the parent and source namespaces under caller control.
//!
//! If a tracked directory is also the destination's parent, it follows the
//! same stage-creation stamp checks and stability requirement as [creation](super::create).
//!
//! ```no_run
//! use std::path::Path;
//! use zipfast::zip::rewrite::{Replacement, RewriteOptions, RewritePlan};
//!
//! let options = RewriteOptions::new(Replacement::LastWriterWins);
//! let mut plan = RewritePlan::open(Path::new("archive.zip"), options)?;
//! if let Some(first) = plan.metadata().entry_id(0) {
//!     plan.remove(&first)?;
//! }
//! let outcome = plan.publish()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::{fmt, path::PathBuf};

use zip_container::{DirectoryError, Limits, Profile};

use crate::extract::Cancellation;

use super::create::{
    CleanupState, CollisionPolicy, CreateError, CreateLimits, CreateUsage, Durability, DurabilityState, Publication,
    VerificationUsage,
};
use super::write::{EntryWritten, WriteError};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod layout;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(in crate::zip) mod native;
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod tests;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod verify;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use native::RewritePlan;
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
pub(super) use tests::{Event, source_read_cap as test_source_read_cap, test_event};
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub use unsupported::RewritePlan;

/// Payload verification policy for retained members.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Verification {
    /// Compare retained wire bytes and fully verify all new payloads.
    #[default]
    PreserveAndVerifyNew,
    /// Also verify retained unencrypted Stored and Deflate payloads.
    Full,
}

/// Native replacement policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replacement {
    /// Detect observed source changes. A competitor after the final check can
    /// be overwritten by the single native replacement.
    LastWriterWins,
}

/// Where an admitted input will appear in the output central directory.
#[derive(Clone, Debug)]
pub enum Placement {
    Append,
    Replace(super::EntryId),
}

/// Options for opening and replacing an existing archive.
#[derive(Clone)]
pub struct RewriteOptions {
    pub replacement: Replacement,
    pub verification: Verification,
    pub collisions: CollisionPolicy,
    pub durability: Durability,
    /// Ordinary permission bits. By default carry forward the old rwx bits.
    pub output_permissions: Option<u16>,
    pub limits: RewriteLimits,
    pub cancel: Cancellation,
}

impl RewriteOptions {
    /// Start with the default budgets and an explicit replacement policy.
    pub fn new(replacement: Replacement) -> Self {
        Self {
            replacement,
            verification: Verification::default(),
            collisions: CollisionPolicy::Exact,
            durability: Durability::VisibilityOnly,
            output_permissions: None,
            limits: RewriteLimits::default(),
            cancel: Cancellation::default(),
        }
    }
}

/// Independent component ceilings. They do not bound process RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RewriteLimits {
    pub common: CreateLimits,
    pub source_directory: Limits,
    pub source_scratch: u64,
    pub source_records: u64,
    pub source_metadata: u64,
    pub layout_read_bytes: u64,
    pub raw_copy_bytes: u64,
    pub prefix_bytes: u64,
}

impl Default for RewriteLimits {
    fn default() -> Self {
        Self {
            common: CreateLimits::default(),
            source_directory: Limits::default(),
            source_scratch: 16 << 20,
            source_records: 128 << 20,
            source_metadata: 128 << 20,
            layout_read_bytes: 512 << 20,
            raw_copy_bytes: 3 << 40,
            prefix_bytes: 64 << 20,
        }
    }
}

/// Bounded resources particular to rewriting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RewriteLimit {
    SourceRecords,
    SourceMetadata,
    LayoutReadBytes,
    RawCopyBytes,
    RetainedComparisonBytes,
    PrefixBytes,
}

/// Why a plan or rewrite stopped.
#[derive(Debug)]
#[non_exhaustive]
pub enum RewriteError {
    Infrastructure(CreateError),
    Directory(DirectoryError),
    Metadata(crate::Error),
    Writer(WriteError),
    SourceChanged,
    InputChanged { input: usize },
    InputAliasesArchive { input: usize },
    InputAliasesStage { input: usize },
    UnsupportedLayout(&'static str),
    AmbiguousDirectory { profile: Profile },
    ForeignEntryId,
    DuplicateEdit,
    ReplacementName,
    NameConflict,
    CannotFullyVerify { source_ordinal: usize },
    Verification(&'static str),
    Limit(RewriteLimit),
}

impl fmt::Display for RewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Infrastructure(error) => error.fmt(f),
            Self::Directory(error) => error.fmt(f),
            Self::Metadata(error) => error.fmt(f),
            Self::Writer(error) => error.fmt(f),
            Self::SourceChanged => f.write_str("the original ZIP changed"),
            Self::InputChanged { input } => write!(f, "ZIP rewrite input {input} changed"),
            Self::InputAliasesArchive { input } => write!(f, "ZIP rewrite input {input} aliases the original ZIP"),
            Self::InputAliasesStage { input } => write!(f, "ZIP rewrite input {input} aliases the stage"),
            Self::UnsupportedLayout(reason) => write!(f, "unsupported ZIP rewrite layout: {reason}"),
            Self::AmbiguousDirectory { profile } => write!(f, "{profile:?} discovery disagrees with the ZIP directory"),
            Self::ForeignEntryId => f.write_str("ZIP entry ID belongs to another snapshot"),
            Self::DuplicateEdit => f.write_str("ZIP entry already has an edit"),
            Self::ReplacementName => f.write_str("replacement must use the original raw name and encoding"),
            Self::NameConflict => f.write_str("introduced ZIP member name conflict"),
            Self::CannotFullyVerify { source_ordinal } => {
                write!(f, "cannot fully verify retained ZIP member {source_ordinal}")
            }
            Self::Verification(reason) => write!(f, "ZIP rewrite verification failed: {reason}"),
            Self::Limit(limit) => write!(f, "ZIP rewrite limit exceeded: {limit:?}"),
        }
    }
}

impl std::error::Error for RewriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Infrastructure(error) => Some(error),
            Self::Directory(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::Writer(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RewriteError {
    fn from(error: std::io::Error) -> Self {
        CreateError::from(error).into()
    }
}

impl From<CreateError> for RewriteError {
    fn from(error: CreateError) -> Self {
        Self::Infrastructure(error)
    }
}

impl From<DirectoryError> for RewriteError {
    fn from(error: DirectoryError) -> Self {
        Self::Directory(error)
    }
}

impl From<std::collections::TryReserveError> for RewriteError {
    fn from(error: std::collections::TryReserveError) -> Self {
        CreateError::from(error).into()
    }
}

/// Resource usage, including partially completed work on a failure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RewriteUsage {
    pub common: CreateUsage,
    /// Source parser accounting, separate from stage verification.
    pub source: VerificationUsage,
    pub source_payload: VerificationUsage,
    pub source_projection_capacity: u64,
    pub source_projection_bytes: u64,
    pub layout_read_bytes: u64,
    pub raw_copy_bytes: u64,
    pub retained_comparison_bytes: u64,
    pub retained_structural_only: u64,
    pub retained_payload_verified: u64,
}

/// Result for one output ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryVerification {
    NewVerified,
    RetainedPayloadVerified,
    RetainedDirectoryVerified,
    PreservedStructurally,
}

/// Results in output central order.
#[derive(Debug, Default)]
pub struct VerificationSummary {
    pub new_verified: u64,
    pub retained_payload_verified: u64,
    pub retained_structural_only: u64,
    pub retained_directories_verified: u64,
    pub entries: Vec<EntryVerification>,
}

/// The archive name was either left untouched or replaced.
#[derive(Debug)]
pub enum RewriteOutcome {
    Unchanged { source: PathBuf, verification: VerificationSummary, usage: RewriteUsage },
    Replaced(RewrittenArchive),
}

/// Rewrite result with opt-in member write receipts.
#[derive(Debug)]
#[must_use]
pub struct RewriteReport {
    pub outcome: std::result::Result<RewriteOutcome, RewriteFailure>,
    /// Newly written members in output central-directory order, including
    /// replacements and appends. Each ordinal refers to the output after
    /// removals. Raw retained entries have no write receipt.
    ///
    /// Receipts require confirmed publication. They are also available when
    /// publication succeeded and finalization returned an error.
    pub written: Vec<EntryWritten>,
}

/// Receipt for a completed replacement.
#[derive(Debug)]
pub struct RewrittenArchive {
    pub destination: PathBuf,
    pub verification: VerificationSummary,
    pub publication: Publication,
    pub durability: DurabilityState,
    pub cleanup: CleanupState,
    pub usage: RewriteUsage,
}

/// Stage where a rewrite stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RewriteStage {
    Planning,
    StageCreate,
    SourceRead,
    Write,
    Finish,
    Verify,
    Permissions,
    FileSync,
    Precommit,
    Publish,
    Cleanup,
    DirectorySync,
}

/// A filesystem identity observed through a held directory or file handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
}

/// Observation made during recovery accounting after an uncertain rename.
#[derive(Debug)]
pub enum DestinationObservation {
    Missing,
    Regular(FileIdentity),
    Other,
    Unavailable(CreateError),
}

/// Information for reconciling an uncertain publication.
#[derive(Debug)]
pub struct Recovery {
    pub stage_identity: FileIdentity,
    pub destination: DestinationObservation,
}

/// A stopped rewrite and its publication and cleanup consequences.
#[derive(Debug)]
pub struct RewriteFailure {
    pub stage: RewriteStage,
    pub cause: RewriteError,
    pub publication: Publication,
    pub durability: DurabilityState,
    pub cleanup: CleanupState,
    pub usage: Box<RewriteUsage>,
    /// Present if verification succeeded and the replacement committed.
    pub verification: Option<Box<VerificationSummary>>,
    /// Present when the native publication outcome is uncertain.
    pub recovery: Option<Box<Recovery>>,
}

impl RewriteOutcome {
    /// Result of requested synchronization. An unchanged archive is left
    /// in its existing durability state.
    pub fn durability(&self) -> DurabilityState {
        match self {
            Self::Unchanged { .. } => DurabilityState::NotRequested,
            Self::Replaced(archive) => archive.durability,
        }
    }
}

impl fmt::Display for RewriteFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZIP rewrite {:?} ({:?}): {}", self.stage, self.publication, self.cause)
    }
}

impl std::error::Error for RewriteFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
type Result<T> = std::result::Result<T, RewriteError>;
