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

//! Plan, verify, and publish a fresh ZIP with native no-replace semantics.
//!
//! The destination parent and source namespaces must remain controlled and
//! stable. Concurrent creation of the destination is supported. See the
//! repository's creation guide for filesystem qualification and failure states.
//!
//! A tracked directory can also be the destination's parent. In that case,
//! stage creation changes its stamp. The plan checks the original stamp
//! before staging and takes a new baseline from the held parent immediately
//! after creating the stage. Concurrent changes to the parent's times or
//! size between those checks can be attributed to stage creation. Keep the
//! directory stable throughout that interval.
//!
//! ```no_run
//! use std::path::Path;
//! use zipfast::zip::create::{CreateOptions, CreatePlan};
//! use zipfast::zip::write::{DosDateTime, EntryName, EntryOptions, Method, Permissions};
//!
//! let mut plan = CreatePlan::new(Path::new("archive.zip"), CreateOptions::default())?;
//! plan.add_file(
//!     Path::new("report.txt"),
//!     EntryOptions {
//!         name: EntryName::Utf8("report.txt"),
//!         method: Method::Stored,
//!         modified: DosDateTime::default(),
//!         extended_mtime: None,
//!         permissions: Permissions::new(0o640)?,
//!         comment: b"",
//!     },
//!     None,
//! )?;
//! let receipt = plan.publish()?;
//! assert_eq!(receipt.summary.verification.payloads, 1);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//

use std::collections::TryReserveError;
use std::fmt;
use std::io;
use std::path::PathBuf;

use super::write::{EntryWritten, WriteError, WriteLimits, WriteUsage};
use crate::extract::Cancellation;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) mod native;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use native::CreatePlan;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::CreatePlan;

const MIB: u64 = 1 << 20;
const TIB: u64 = 1 << 40;
const FINALIZATION_RESERVE: u64 = 64;
const MAX_FIELD: usize = u16::MAX as usize;
pub(super) type Result<T> = std::result::Result<T, CreateError>;

/// Options for a verified new archive.
#[derive(Clone)]
pub struct CreateOptions {
    /// Arbitrary bytes written in the archive comment.
    pub archive_comment: Vec<u8>,
    /// Ordinary rwx permission bits applied before publication.
    pub output_permissions: u16,
    /// Archive member collision policy.
    pub collisions: CollisionPolicy,
    /// File and directory synchronization policy.
    pub durability: Durability,
    /// Independent component ceilings.
    pub limits: CreateLimits,
    /// Cooperative cancellation signal.
    pub cancel: Cancellation,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            archive_comment: Vec::new(),
            output_permissions: 0o600,
            collisions: CollisionPolicy::Exact,
            durability: Durability::VisibilityOnly,
            limits: CreateLimits::default(),
            cancel: Cancellation::default(),
        }
    }
}

/// Policy for detecting conflicting member paths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CollisionPolicy {
    /// Compare encoded member paths byte for byte.
    #[default]
    Exact,
    /// Also compare caller-supplied component identities.
    CallerKeys,
}

/// Requested synchronization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Durability {
    /// Atomically publish the complete verified archive.
    #[default]
    VisibilityOnly,
    /// Synchronize the stage and then the parent directory after publication.
    SyncFileAndDirectory,
}

/// Finite component ceilings for creation. Capacities exclude allocator and
/// codec overhead. See [the module documentation](crate::zip::create) for the defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateLimits {
    /// Number of admitted entries.
    pub entries: u64,
    /// Count of retained caller-supplied handles.
    pub retained_handles: u64,
    /// Capacity in bytes for the plan, receipts and sort indices.
    pub plan_capacity: u64,
    /// Bytes scanned or compared, plus operations, in plan validation.
    pub plan_work: u64,
    /// Existing seekable writer limits.
    pub writer: WriteLimits,
    /// Shared strict parser limits.
    pub directory: zip_container::Limits,
    /// Equivalent raw metadata capacity across parser ownership classes.
    pub verification_metadata: u64,
    /// Maximum requested parser scratch capacity, including retained inline buffers.
    pub verification_scratch: u64,
    /// Capacity of the parser's fixed central records.
    pub verification_records: u64,
    /// Cumulative reads of the stage during verification.
    pub verification_read_bytes: u64,
    /// Maximum decoded payload for any verified member.
    pub verification_entry_bytes: u64,
    /// Maximum aggregate decoded payload during verification.
    pub verification_decoded_bytes: u64,
    /// Aggregate native and raw I/O attempts, plus verification codec steps.
    /// An independent fixed finalization reserve covers cleanup and sync.
    pub transaction_attempts: u64,
}

impl Default for CreateLimits {
    fn default() -> Self {
        Self {
            entries: 1_000_000,
            retained_handles: 4096,
            plan_capacity: 128 * MIB,
            plan_work: 1 << 32,
            writer: WriteLimits::default(),
            directory: zip_container::Limits::default(),
            verification_metadata: 128 * MIB,
            verification_scratch: 16 * MIB,
            verification_records: 128 * MIB,
            verification_read_bytes: 4 * TIB,
            verification_entry_bytes: TIB,
            verification_decoded_bytes: 2 * TIB,
            transaction_attempts: (1 << 32) - FINALIZATION_RESERVE,
        }
    }
}

/// One opaque comparison key per encoded archive path component.
#[derive(Debug)]
pub struct CollisionPath(Vec<u8>);

impl CollisionPath {
    /// Copy validated keys into one bounded allocation. The aggregate encoded
    /// length, including separators, must fit in 65,535 bytes.
    pub fn new(components: &[&[u8]]) -> Result<Self> {
        if components.is_empty() || components.len() > MAX_FIELD.div_ceil(2) {
            return Err(CreateError::InvalidName("invalid collision key count"));
        }
        let mut len = components.len() - 1;
        for key in components {
            len = len.checked_add(key.len()).ok_or(CreateError::Overflow)?;
            if len > MAX_FIELD || key.is_empty() || key.iter().any(|&b| matches!(b, 0 | b'/')) {
                return Err(CreateError::InvalidName("invalid collision key component"));
            }
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(len)?;
        for (index, key) in components.iter().enumerate() {
            if index != 0 {
                bytes.push(b'/');
            }
            bytes.extend_from_slice(key);
        }
        Ok(Self(bytes))
    }
}

/// A member's zero-based admission ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateEntryId(pub(super) usize);

impl CreateEntryId {
    /// Return the position of the member in the planned archive.
    pub fn ordinal(self) -> usize {
        self.0
    }
}

/// An exhausted creation component budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CreateLimit {
    Entries,
    RetainedHandles,
    PlanCapacity,
    PlanWork,
    VerificationMetadata,
    VerificationScratch,
    VerificationRecords,
    VerificationReadBytes,
    VerificationEntryBytes,
    VerificationDecodedBytes,
    TransactionAttempts,
    FinalizationAttempts,
    StageAttempts,
}

/// Why planning or creation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum CreateError {
    InvalidDestination,
    InvalidOptions(&'static str),
    InvalidName(&'static str),
    NameConflict { first: CreateEntryId, second: CreateEntryId },
    Conflict,
    UnsupportedPlatform,
    UnsupportedFilesystem,
    UnsupportedPublication(io::Error),
    DescriptorExhaustion(io::Error),
    SourceNotRegular,
    SourceChanged(CreateEntryId),
    SourceAliasesStage(CreateEntryId),
    ParentChanged,
    StageChanged,
    CleanupIncomplete,
    Canceled,
    Overflow,
    Limit(CreateLimit),
    Allocation(TryReserveError),
    Writer(WriteError),
    Directory(zip_container::DirectoryError),
    Verification(&'static str),
    AmbiguousDirectory { profile: zip_container::Profile },
    Io(io::Error),
}

impl From<TryReserveError> for CreateError {
    fn from(error: TryReserveError) -> Self {
        Self::Allocation(error)
    }
}

impl From<io::Error> for CreateError {
    fn from(error: io::Error) -> Self {
        #[cfg(unix)]
        if matches!(error.raw_os_error(), Some(libc::EMFILE | libc::ENFILE)) {
            return Self::DescriptorExhaustion(error);
        }
        Self::Io(error)
    }
}

impl From<WriteError> for CreateError {
    fn from(error: WriteError) -> Self {
        match error {
            WriteError::Canceled => Self::Canceled,
            other => Self::Writer(other),
        }
    }
}

impl fmt::Display for CreateError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDestination => out.write_str("destination must have a normal final filename"),
            Self::InvalidOptions(reason) | Self::InvalidName(reason) | Self::Verification(reason) => {
                out.write_str(reason)
            }
            Self::NameConflict { first, second } => {
                write!(out, "archive paths conflict at entries {} and {}", first.0, second.0)
            }
            Self::Conflict => out.write_str("destination already exists"),
            Self::UnsupportedPlatform => out.write_str("native no-replace publication is unavailable on this platform"),
            Self::UnsupportedFilesystem => {
                out.write_str("destination filesystem is outside the native publication policy")
            }
            Self::UnsupportedPublication(error) => write!(out, "native no-replace publication is unavailable: {error}"),
            Self::DescriptorExhaustion(error) => write!(out, "file descriptor exhaustion: {error}"),
            Self::SourceNotRegular => out.write_str("source is not a regular file"),
            Self::SourceChanged(entry) => write!(out, "source binding changed at entry {}", entry.0),
            Self::SourceAliasesStage(entry) => write!(out, "source aliases the stage at entry {}", entry.0),
            Self::ParentChanged => out.write_str("destination parent binding changed"),
            Self::StageChanged => out.write_str("stage binding changed"),
            Self::CleanupIncomplete => out.write_str("stage cleanup did not complete"),
            Self::Canceled => out.write_str("ZIP creation canceled"),
            Self::Overflow => out.write_str("ZIP creation accounting overflow"),
            Self::Limit(limit) => write!(out, "ZIP creation limit exceeded: {limit:?}"),
            Self::Allocation(error) => write!(out, "ZIP creation allocation failed: {error}"),
            Self::Writer(error) => error.fmt(out),
            Self::Directory(error) => error.fmt(out),
            Self::AmbiguousDirectory { profile } => {
                write!(out, "default ZIP discovery ({profile:?}) disagrees with the created archive")
            }
            Self::Io(error) => error.fmt(out),
        }
    }
}

impl std::error::Error for CreateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedPublication(error) | Self::DescriptorExhaustion(error) | Self::Io(error) => Some(error),
            Self::Allocation(error) => Some(error),
            Self::Writer(error) => Some(error),
            Self::Directory(error) => Some(error),
            _ => None,
        }
    }
}

/// Plan resource usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PlanUsage {
    /// Admitted entries.
    pub entries: u64,
    /// Retained caller-supplied files.
    pub retained_handles: u64,
    /// Peak charged plan capacity including preflight scratch.
    pub capacity: u64,
    /// Charged validation work.
    pub work: u64,
}

/// Verification resource usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VerificationUsage {
    /// Cumulative raw bytes read from the stage.
    pub read_bytes: u64,
    /// Cumulative decoded bytes.
    pub decoded_bytes: u64,
    /// Number of verified regular payloads.
    pub payloads: u64,
    /// Number of verified central records, including directories.
    pub entries: u64,
    /// Equivalent bytes for raw central names, comments and extras.
    pub metadata_bytes: u64,
    /// Strict parser accounting.
    pub directory: zip_container::Usage,
    /// Default-profile discovery bytes, additional to the strict parse.
    pub discovery_bytes: u64,
    /// Default-profile discovery work, additional to the strict parse.
    pub discovery_work: u64,
    /// Peak parser scratch capacity.
    pub scratch_capacity: u64,
    /// Capacity of the parser's fixed records.
    pub record_capacity: u64,
}

/// Creation accounting. Failed operations can include partial work.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CreateUsage {
    /// Plan accounting.
    pub plan: PlanUsage,
    /// Seekable writer accounting.
    pub writer: WriteUsage,
    /// Strict verification accounting.
    pub verification: VerificationUsage,
    /// Counted transaction attempts before cleanup and directory sync.
    pub transaction_attempts: u64,
    /// Counted cleanup and directory synchronization attempts.
    pub finalization_attempts: u64,
    /// Exclusive stage-name attempts.
    pub stage_attempts: u64,
}

/// Stage at which planning or execution stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CreateStage {
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

/// What is known about the native publication operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publication {
    /// The transaction did not publish the destination.
    NotPublished,
    /// Native publication succeeded.
    Published,
    /// The native error does not establish whether publication occurred.
    Unknown,
}

/// Result of the requested synchronization calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityState {
    NotRequested,
    Synced,
    Unconfirmed,
}

/// What remains at the original stage name.
#[derive(Debug)]
pub enum CleanupState {
    /// No stage remains to clean.
    Clean,
    /// No unlink was attempted. The path is the last known owned stage name
    /// and might require a new ownership check before recovery.
    RetainedOwnedStage { path: PathBuf },
    /// A different object occupied the stage name and was left untouched.
    ForeignStageName { path: PathBuf },
    /// The ownership lookup or explicit unlink failed.
    Failed { path: PathBuf, error: io::Error },
}

/// A stopped creation, including any publication and cleanup consequences.
#[derive(Debug)]
pub struct CreateFailure {
    pub stage: CreateStage,
    pub cause: CreateError,
    pub publication: Publication,
    pub durability: DurabilityState,
    pub cleanup: CleanupState,
    pub summary: CreateUsage,
}

impl fmt::Display for CreateFailure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "ZIP creation {:?} ({:?}): {}", self.stage, self.publication, self.cause)
    }
}

impl std::error::Error for CreateFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Receipt for a successfully published, verified archive.
#[derive(Debug)]
pub struct CreatedArchive {
    /// Absolute destination spelling captured during planning.
    pub destination: PathBuf,
    /// Successful publication.
    pub publication: Publication,
    /// Result of the requested synchronization calls.
    pub durability: DurabilityState,
    /// Successful stage-name cleanup.
    pub cleanup: CleanupState,
    /// Plan, writer, and full-payload verification accounting.
    pub summary: CreateUsage,
}

/// Creation result with opt-in member write receipts.
#[derive(Debug)]
#[must_use]
pub struct CreateReport {
    pub outcome: std::result::Result<CreatedArchive, CreateFailure>,
    /// Actual writer results in central-directory order. Each zero-based
    /// ordinal equals the corresponding [`CreateEntryId::ordinal`].
    ///
    /// Receipts require confirmed publication. They are also available when
    /// publication succeeded and finalization returned an error.
    pub written: Vec<EntryWritten>,
}

/// Binding to a verified archive captured through its held publication file.
///
/// Obtain fresh no-follow metadata from the intended destination to check
/// it against this receipt. Namespace checks and subsequent operations
/// remain separate.
#[derive(Debug)]
pub struct PublishedArchiveBinding {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    file: std::fs::File,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    stamp: native::unix::Stamp,
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    unsupported: std::convert::Infallible,
}

impl PublishedArchiveBinding {
    /// Compare fresh metadata with the verified file's final stamp.
    pub fn matches(&self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // Retain the handle to prevent inode reuse while the receipt lives.
            native::unix::Stamp::regular(metadata).is_ok_and(|stamp| stamp == self.stamp)
                && self.file.metadata().ok().and_then(|meta| native::unix::Stamp::regular(&meta).ok())
                    == Some(self.stamp)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = metadata;
            match self.unsupported {}
        }
    }
}
