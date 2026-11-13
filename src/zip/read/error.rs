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

//! Fixed, allocation-free checked-read terminal evidence.
use super::{EncryptedReadUsage, RunUsage, ZipRunReport};
use crate::{Error, zip::SessionError};
use std::{fmt, io};

pub type ZipReadResult<T> = Result<T, ZipReadError>;
pub type ZipSinkResult<T> = Result<T, ZipSinkFault>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IoStage {
    Source,
    SourcePath,
    SourceHandle,
    Ciphertext,
    Output,
    ExternalOutput,
    Bootstrap,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadIoOperation {
    DescriptorMode,
    Read,
    Write,
    Seek,
    Stat,
    Open,
    Create,
    Flush,
    Close,
    Unlink,
    Publish,
    Directory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SourceInvalidationCode {
    StampMismatch,
    Unavailable,
    LegacyUnavailable,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum CheckedSourceFault {
    StampMismatch,
    Unavailable { stage: IoStage, error: io::Error },
    PreviouslyInvalidated { code: SourceInvalidationCode, raw_os_error: Option<i32> },
}
impl CheckedSourceFault {
    pub(crate) fn invalidation(&self) -> (SourceInvalidationCode, Option<i32>) {
        match self {
            Self::StampMismatch => (SourceInvalidationCode::StampMismatch, None),
            Self::Unavailable { error, .. } => (SourceInvalidationCode::Unavailable, error.raw_os_error()),
            Self::PreviouslyInvalidated { code, raw_os_error } => (*code, *raw_os_error),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CipherKind {
    Aes,
    ZipCrypto,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PasswordEvidence {
    NotEncrypted,
    HeaderMatched,
    Authenticated,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IntegrityReason {
    Checksum,
    DecodedSize,
    Truncated,
    TrailingData,
    Decoder,
    Framing,
    Stalled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ReadResource {
    BootstrapMetadata,
    BootstrapAttempts,
    MemberPackedBytes,
    MemberDecodedBytes,
    CiphertextMemoryBytes,
    MemberSpoolBytes,
    LiveSpoolBytes,
    SourceBytes,
    PackedBytes,
    DecodedBytes,
    IoBytes,
    WorkBytes,
    Members,
    PasswordBytes,
    KdfCalls,
    IoAttempts,
    CodecSteps,
    InterruptedRetries,
    CreateAttempts,
    ReaderCapacity,
    AllocationAttempts,
    LiveFds,
    Run(RunCategory),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RunCategory {
    Records,
    SourceCheckGroups,
    PathSteps,
    TemporaryGroups,
    PositiveTransfers,
    TerminalProbes,
    StageFinalization,
    DirectoryFinalization,
    FinalOperations,
    DecodeSteps,
    EmergencyCleanup,
    IoAttempts,
    IoBytes,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadFault {
    PasswordRequired,
    PasswordCheckFailed { cipher: CipherKind },
    AuthenticationFailed,
    Integrity { reason: IntegrityReason, password_evidence: PasswordEvidence },
    Limit { resource: ReadResource, limit: u128, attempted: u128 },
    Allocation { capacity: usize },
    Io { stage: IoStage, operation: ReadIoOperation, offset: u64, error: io::Error },
    UnsupportedIdentity,
    UnsupportedMethod { method: u16 },
    CheckedFormat { reason: &'static str },
    InvalidPlan,
    CounterOverflow,
    Cancelled,
    Legacy(Error),
    Session(SessionError),
}
#[derive(Debug)]
#[non_exhaustive]
pub enum ZipSinkFault {
    Caller(Error),
    Io { operation: ReadIoOperation, offset: u64, error: io::Error },
    Limit { resource: ReadResource, limit: u128, attempted: u128 },
    Allocation { capacity: usize },
    Cancelled,
    StageChanged,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum PublicationState {
    #[default]
    NotPublished,
    Published,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CloseDisposition {
    Closed,
    Unresolved,
    NotApplicable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OwnedObject {
    Source,
    Output,
    OutputParent,
    Ciphertext,
    CiphertextDirectory,
}
#[derive(Debug)]
#[non_exhaustive]
pub enum CleanupCause {
    /// Required final source observation could not be admitted. This records
    /// terminal evidence without claiming a physical observation/invalidation.
    Admission(ReadFault),
    Io(io::Error),
    Policy(&'static str),
}
#[derive(Debug)]
#[non_exhaustive]
pub struct CleanupFault {
    pub object: OwnedObject,
    pub operation: ReadIoOperation,
    pub offset: Option<u64>,
    pub cause: CleanupCause,
    pub close: CloseDisposition,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ZipReadErrorKind {
    Operation,
    Sink,
    Diagnostic,
    SourceChanged,
    Cleanup,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OperationUsage {
    pub(crate) encrypted: EncryptedReadUsage,
    pub(crate) run: RunUsage,
}

/// Owned terminal evidence, with forty fixed cleanup slots and no recursive errors.
///
/// A payload sink must return its own bounded fault, not a recursive read error:
/// ```compile_fail
/// use zipfast::zip::{ZipReadError, ZipSinkFault};
/// fn recursive(error: ZipReadError) -> ZipSinkFault { error.into() }
/// ```
#[derive(Debug)]
pub struct ZipReadError {
    primary: ZipReadErrorKind,
    operation: Option<ReadFault>,
    sink: Option<ZipSinkFault>,
    diagnostic: Option<ZipSinkFault>,
    source_change: Option<CheckedSourceFault>,
    cleanup: [Option<CleanupFault>; 40],
    cleanup_len: u8,
    partial_run: Option<ZipRunReport>,
    publication: PublicationState,
    accepted_output_bytes: u64,
    usage: OperationUsage,
}
impl ZipReadError {
    fn empty(primary: ZipReadErrorKind) -> Self {
        Self {
            primary,
            operation: None,
            sink: None,
            diagnostic: None,
            source_change: None,
            cleanup: std::array::from_fn(|_| None),
            cleanup_len: 0,
            partial_run: None,
            publication: PublicationState::NotPublished,
            accepted_output_bytes: 0,
            usage: OperationUsage::default(),
        }
    }
    pub fn kind(&self) -> ZipReadErrorKind {
        self.primary
    }
    pub fn operation(&self) -> Option<&ReadFault> {
        self.operation.as_ref()
    }
    pub fn sink_fault(&self) -> Option<&ZipSinkFault> {
        self.sink.as_ref()
    }
    pub fn diagnostic_fault(&self) -> Option<&ZipSinkFault> {
        self.diagnostic.as_ref()
    }
    pub fn source_change(&self) -> Option<&CheckedSourceFault> {
        self.source_change.as_ref()
    }
    pub fn cleanup_errors(&self) -> impl ExactSizeIterator<Item = &CleanupFault> {
        self.cleanup[..usize::from(self.cleanup_len)].iter().map(|v| v.as_ref().expect("occupied cleanup slot"))
    }
    pub fn partial_run(&self) -> Option<&ZipRunReport> {
        self.partial_run.as_ref()
    }
    pub fn publication_state(&self) -> PublicationState {
        self.publication
    }
    pub fn accepted_output_bytes(&self) -> u64 {
        self.accepted_output_bytes
    }
    pub fn usage(&self) -> EncryptedReadUsage {
        self.usage.encrypted
    }
    pub fn run_usage(&self) -> RunUsage {
        self.usage.run
    }
    pub fn is_source_changed(&self) -> bool {
        self.source_change.is_some()
            || matches!(self.operation, Some(ReadFault::Session(SessionError::SourceChanged { .. })))
    }
    pub(crate) fn merge_source(mut self, fault: CheckedSourceFault) -> Self {
        self.primary = ZipReadErrorKind::SourceChanged;
        if self.source_change.is_none() {
            self.source_change = Some(fault);
        }
        self
    }
    #[allow(dead_code)] // Task3/5 attach a callback fault without losing a later operation observation.
    pub(crate) fn merge_sink(mut self, fault: ZipSinkFault) -> Self {
        if !self.is_source_changed() && self.diagnostic.is_none() {
            self.primary = ZipReadErrorKind::Sink;
        }
        if self.sink.is_none() {
            self.sink = Some(fault);
        }
        self
    }
    #[allow(dead_code)] // Task5 records publication before fallible parent/namespace retirement.
    pub(crate) fn with_publication(mut self, publication: PublicationState, accepted: u64) -> Self {
        self.publication = publication;
        self.accepted_output_bytes = accepted;
        self
    }
    // Task5 consumes these fixed terminal assembly seams; tested here to preserve precedence.
    #[allow(dead_code)]
    pub(crate) fn merge_diagnostic(mut self, fault: ZipSinkFault) -> Self {
        if !self.is_source_changed() {
            self.primary = ZipReadErrorKind::Diagnostic;
        }
        if self.diagnostic.is_none() {
            self.diagnostic = Some(fault);
        }
        self
    }
    pub(crate) fn merge_cleanup(mut self, report: ObjectCleanupReport) -> Self {
        for fault in report.slots.into_iter().flatten() {
            let existing = self.cleanup_errors().filter(|old| old.object == fault.object).count();
            assert!(existing < 8, "eight terminal operations per object exceeded");
            let index = usize::from(self.cleanup_len);
            assert!(index < self.cleanup.len(), "five object cleanup bound exceeded");
            self.cleanup[index] = Some(fault);
            self.cleanup_len += 1;
        }
        self
    }
    #[allow(dead_code)] // Task5 adds the runner that produces the already-fixed inline report.
    pub(crate) fn with_partial(mut self, report: ZipRunReport) -> Self {
        self.partial_run = Some(report);
        self
    }
    pub(crate) fn with_usage(mut self, encrypted: EncryptedReadUsage, run: RunUsage) -> Self {
        self.usage = OperationUsage { encrypted, run };
        self
    }
    pub(crate) fn accepted(mut self, bytes: u64) -> Self {
        self.accepted_output_bytes = bytes;
        self
    }
}
impl From<ObjectCleanupReport> for ZipReadError {
    fn from(report: ObjectCleanupReport) -> Self {
        assert!(report.len > 0, "cleanup error requires a fault");
        Self::empty(ZipReadErrorKind::Cleanup).merge_cleanup(report)
    }
}
impl From<ReadFault> for ZipReadError {
    fn from(fault: ReadFault) -> Self {
        let primary = if matches!(fault, ReadFault::Session(SessionError::SourceChanged { .. })) {
            ZipReadErrorKind::SourceChanged
        } else {
            ZipReadErrorKind::Operation
        };
        let mut error = Self::empty(primary);
        error.operation = Some(fault);
        error
    }
}
impl From<CheckedSourceFault> for ZipReadError {
    fn from(fault: CheckedSourceFault) -> Self {
        Self::empty(ZipReadErrorKind::SourceChanged).merge_source(fault)
    }
}
impl From<ZipSinkFault> for ZipReadError {
    fn from(fault: ZipSinkFault) -> Self {
        let mut error = Self::empty(ZipReadErrorKind::Sink);
        error.sink = Some(fault);
        error
    }
}
impl fmt::Display for ZipReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZIP checked read {:?}", self.primary)
    }
}
impl std::error::Error for ZipReadError {}
impl fmt::Display for ZipSinkFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ZIP sink {self:?}")
    }
}
impl std::error::Error for ZipSinkFault {}

/// Exactly one owned object's terminal operations; exceeding eight is an invariant failure.
#[derive(Debug)]
pub(crate) struct ObjectCleanupReport {
    object: OwnedObject,
    slots: [Option<CleanupFault>; 8],
    len: u8,
}
impl ObjectCleanupReport {
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(crate) fn new(object: OwnedObject) -> Self {
        Self { object, slots: std::array::from_fn(|_| None), len: 0 }
    }
    pub(crate) fn push(&mut self, fault: CleanupFault) {
        assert_eq!(fault.object, self.object, "one object per cleanup report");
        assert!(usize::from(self.len) < self.slots.len(), "eight terminal operations per object exceeded");
        self.slots[usize::from(self.len)] = Some(fault);
        self.len += 1;
    }
}
