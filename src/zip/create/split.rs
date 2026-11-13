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

//! Native split transaction observations and component limits.
//!
//! [`super::CreatePlan::publish_split_with_receipts`] consumes the existing input
//! plan and creates clear Stored/Deflate physical volumes on qualified Linux and
//! macOS filesystems. The final leaf must end in ASCII-case-insensitive `.zip`.
//! Numbered leaves use the raw stem followed by `.z01`, through `.z99`, then
//! `.z100` and higher. The final extension keeps its original bytes and case.
//! Every actual destination must be absent. No existing volume is overwritten.
//!
//! All stages remain held through independent disk-relative framing, decoded
//! size and CRC verification. Numbered volumes are published in order, followed
//! by the final ZIP. The set has per-name visibility, not an atomic set rename.
//! Commit records syscall history; visibility is a later pointwise observation.
//! An ambiguous rename stays Unknown even if every final name subsequently matches.
//! Receipts are exposed in `written` only for confirmed Complete history.
//!
//! VisibilityOnly promises no crash durability. SyncFileAndDirectory requests
//! every stage-file barrier, a parent barrier before final ZIP publication and
//! another afterward. A failure after confirmed final publication retains the
//! complete published set. Definite earlier failures attempt bounded cleanup
//! using fresh held/name identity checks. Foreign substitutions are preserved.
//! Unknown publication or unresolved ownership retains closing-only evidence.
//! Dropping that evidence performs no retry, rename, unlink or synchronization.
//!
//! Defaults allow 64 MiB volumes, 4,096 volumes, 8,192 live engine-owned handles,
//! 128 MiB preparation capacity, 1 MiB verifier scratch, 2^32 transport attempts
//! and 64 stage-name attempts per volume. Descriptor admission counts actual
//! retained input/directory handles, one parent, held stages, the active writer
//! clone and any transient source. Unused possible volumes consume reserved
//! metadata capacity but no descriptor allowance. Native preparation and split
//! scratch are separate ceilings; ordinary parser scratch policy is unchanged.
//! Existing source, writer, verification, directory and cancellation limits apply.
//! Fixed/allocator and codec overhead are not a process-wide RSS guarantee.
//!
//! Snapshots and paths are historical observations under the existing controlled
//! namespace contract. They do not authorize source deletion or future pathname
//! mutation. A reconciliation object owns the existing descriptors and provisional
//! receipts without interpreting them as a published success. Split encryption,
//! rewriting, source deletion and CLI routing are outside this API.
//!
//! Pinned reader qualification uses direct lowercase-final 7-Zip extraction.
//! On case-sensitive filesystems, that reader seeks uppercase parts for `.ZIP`
//! even though Info-ZIP emits lowercase numbered suffixes. Raw names also depend
//! on the qualified filesystem accepting their bytes. Native naming does not
//! change to disguise those reader/filesystem restrictions.
use super::{CreateError, DurabilityState, PlanUsage};
use crate::zip::write::{self, WriteUsage};
use std::{collections::TryReserveError, fmt, fs::Metadata, path::PathBuf, sync::Arc};

#[derive(Debug)]
#[non_exhaustive]
pub struct SplitCreateOptions {
    pub volume_bytes: u64,
    pub limits: SplitCreateLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitCreateLimits {
    pub volumes: u32,
    pub open_handles: u64,
    pub native_capacity: u64,
    pub verification_scratch: u64,
    pub transport_attempts: u64,
    pub stage_attempts_per_volume: u32,
}

#[must_use]
#[derive(Debug)]
#[non_exhaustive]
pub struct SplitCreateReport {
    pub outcome: std::result::Result<SplitCreatedArchive, SplitCreateFailure>,
    pub destination: PathBuf,
    pub commit: SplitCommitState,
    pub visibility: SplitVisibility,
    pub durability: DurabilityState,
    pub barriers: SplitBarrierReport,
    pub volumes: Vec<SplitVolumeReport>,
    pub written: Vec<write::split::EntryWritten>,
    pub summary: SplitCreateUsage,
    pub additional_problems: Vec<SplitProblem>,
    pub writer_failure: Option<Arc<write::split::Error>>,
    pub reconciliation: Option<SplitReconciliation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitCreatedArchive {
    pub volume_count: u32,
    pub physical_bytes: u64,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct SplitCreateFailure {
    pub stage: SplitCreateStage,
    pub at: Option<write::split::Location>,
    pub cause: SplitCreateError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitCommitState {
    NonePublished,
    PrefixPublished,
    Complete,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitVisibility {
    NotChecked,
    NoneMatch,
    PartialMatch,
    AllMatch,
    Unresolved,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitVolumePublication {
    NotAttempted,
    NotPublished,
    Published,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitVolumeRole {
    Unassigned,
    Numbered,
    FinalZip,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct SplitVolumeReport {
    pub disk: u32,
    pub role: SplitVolumeRole,
    pub final_path: Option<PathBuf>,
    pub stage_path: Option<PathBuf>,
    pub stage_created: bool,
    pub writer_opened: bool,
    pub accepted_bytes: u64,
    pub stage_open_attempts: u64,
    pub verified: Option<SplitFileSnapshot>,
    pub terminal_held: Option<SplitFileSnapshot>,
    pub stage_name: SplitNameObservation,
    pub final_name: SplitNameObservation,
    pub publication: SplitVolumePublication,
    pub cleanup: SplitVolumeCleanup,
    pub data_sync: SplitBarrierState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitFileIdentity {
    pub device: u64,
    pub inode: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitFileSnapshot {
    pub identity: SplitFileIdentity,
    pub bytes: u64,
    pub modified: (i64, i64), // seconds, nanoseconds
    pub changed: (i64, i64),
    pub permissions: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitNameObservation {
    pub state: SplitNameState,
    pub identity: Option<SplitFileIdentity>,
    pub regular: Option<SplitFileSnapshot>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitNameState {
    NotChecked,
    Absent,
    MatchesHeld,
    ChangedHeld,
    Foreign,
    Unresolved(SplitProblemRef),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitVolumeCleanup {
    NotNeeded,
    Removed,
    Retained,
    ForeignPreserved,
    Unresolved(SplitProblemRef),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitBarrierState {
    NotRequested,
    NotAttempted,
    Complete,
    Failed(SplitProblemRef),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SplitBarrierReport {
    pub prefix_parent: SplitBarrierState,
    pub final_parent: SplitBarrierState,
    pub aftermath_parent: SplitBarrierState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitProblemRef {
    Primary,
    Additional(u64),
}
#[derive(Debug)]
#[non_exhaustive]
pub struct SplitProblem {
    pub stage: SplitCreateStage,
    pub at: Option<write::split::Location>,
    pub cause: SplitCreateError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitCreateLimit {
    Volumes,
    OpenHandles,
    NativeCapacity,
    VerificationScratch,
    TransportAttempts,
    StageNameAttempts,
    FinalizationAttempts,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SplitCreateError {
    InvalidOptions(&'static str),
    InvalidFinalLeaf,
    NameTooLong { disk: u32, bytes: u64, maximum: Option<u64> },
    Limit(SplitCreateLimit),
    Allocation(TryReserveError),
    Create(CreateError),
    Write(Arc<write::split::Error>),
    Verification { disk: Option<u32>, member: Option<u64>, kind: SplitVerificationError },
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitCreateStage {
    Planning,
    StageCreate,
    SourceRead,
    Write,
    Finish,
    Verify,
    Permissions,
    FileSync,
    NamePreflight,
    NumberedPublish,
    PreFinalSync,
    FinalPublish,
    Cleanup,
    DirectorySync,
    Reconcile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SplitVerificationError {
    VolumeCount,
    VolumeOrder,
    VolumeLength,
    Marker,
    Receipt,
    LocalHeader,
    CentralHeader,
    Extras,
    Descriptor,
    EndGroup,
    PackedExtent,
    CodecCompletion,
    DecodedLength,
    Checksum,
    Stamp,
}

#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SplitCreateUsage {
    pub plan: PlanUsage,
    pub writer: WriteUsage,
    pub transport: write::split::Usage,
    pub verification: SplitVerificationUsage,
    pub native_attempts: u64,
    pub stage_open_attempts: u64,
    pub stage_files_created: u64,
    pub finalization_attempts: u64,
    pub finalization_reserve: u64,
    pub preparation_capacity: u64,
    pub open_handles_peak: u64,
    pub reconciliation_handles: u64,
}
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SplitVerificationUsage {
    pub read_bytes: u64,
    pub decoded_bytes: u64,
    pub members: u64,
    pub central_rows: u64,
    pub raw_metadata_bytes: u64,
    pub metadata_work: u64,
    pub record_capacity: u64,
    pub scratch_capacity: u64,
}

impl Default for SplitCreateOptions {
    fn default() -> Self {
        Self { volume_bytes: 64 << 20, limits: SplitCreateLimits::default() }
    }
}
impl Default for SplitCreateLimits {
    fn default() -> Self {
        Self {
            volumes: 4096,
            open_handles: 8192,
            native_capacity: 128 << 20,
            verification_scratch: 1 << 20,
            transport_attempts: 1 << 32,
            stage_attempts_per_volume: 64,
        }
    }
}
/// Retained evidence only. Dropping it closes handles and never mutates names.
#[non_exhaustive]
pub struct SplitReconciliation {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) inner: super::native::split::Evidence,
}
impl fmt::Debug for SplitReconciliation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitReconciliation").finish_non_exhaustive()
    }
}
impl SplitReconciliation {
    /// Provisional completed member framing, without publication authority.
    pub fn staged_members(&self) -> &[write::split::EntryWritten] {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            &self.inner.receipts
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            &[]
        }
    }
    /// Compare an observed identity to a retained volume. This is no namespace lock.
    pub fn matches_volume(&self, disk: u32, metadata: &Metadata) -> bool {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.inner.matches(disk, metadata)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (disk, metadata);
            false
        }
    }
}
impl From<CreateError> for SplitCreateError {
    fn from(e: CreateError) -> Self {
        match e {
            CreateError::Limit(super::CreateLimit::FinalizationAttempts) => {
                Self::Limit(SplitCreateLimit::FinalizationAttempts)
            }
            CreateError::Allocation(error) => Self::Allocation(error),
            other => Self::Create(other),
        }
    }
}
impl From<TryReserveError> for SplitCreateError {
    fn from(e: TryReserveError) -> Self {
        Self::Allocation(e)
    }
}
impl fmt::Display for SplitCreateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "split ZIP creation failed ({self:?})")
    }
}
impl std::error::Error for SplitCreateError {}

impl fmt::Display for SplitCreateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "split ZIP {:?} failed: {}", self.stage, self.cause)
    }
}
impl std::error::Error for SplitCreateFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
