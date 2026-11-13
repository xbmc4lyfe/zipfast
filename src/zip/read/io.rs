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

//! Application transfers are bounded, charged before calls, and never retry callbacks.
use super::{
    budget::LedgerState,
    shared::{LedgerAccess, LedgerView},
    *,
};
use crate::extract::Cancellation;
use std::io::{self, Read, Seek, SeekFrom, Write};
pub(super) const WINDOW: usize = 64 << 10;

pub(super) fn canceled(cancel: Option<&Cancellation>) -> Result<(), ReadFault> {
    if cancel.is_some_and(Cancellation::is_canceled) { Err(ReadFault::Cancelled) } else { Ok(()) }
}
fn attempt(
    ledger: &(impl LedgerAccess + ?Sized),
    encrypted: bool,
    cancel: Option<&Cancellation>,
) -> Result<(), ReadFault> {
    canceled(cancel)?;
    ledger.with_state(|s| s.attempt(encrypted))
}
fn interrupted(ledger: &(impl LedgerAccess + ?Sized), retries: &mut u64) -> Result<(), ReadFault> {
    *retries = retries.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
    ledger.with_state(|s| {
        budget::admit(
            ReadResource::InterruptedRetries,
            s.encrypted.limits.interrupted_retries.into(),
            (*retries).into(),
        )
    })
}
fn request(s: &mut LedgerState, encrypted: bool, source: bool, wanted: usize) -> Result<usize, ReadFault> {
    let (available, resource, limit, used) = s.transfer_allowance(encrypted, source)?;
    let count = (wanted.min(WINDOW) as u128).min(available) as usize;
    if count == 0 && wanted > 0 {
        return Err(ReadFault::Limit { resource, limit, attempted: budget::checked_sum(used, 1)? });
    }
    Ok(count)
}
pub(super) fn read(
    ledger: &(impl LedgerAccess + ?Sized),
    encrypted: bool,
    reader: &mut (impl Read + ?Sized),
    stage: IoStage,
    offset: u64,
    bytes: &mut [u8],
    cancel: &Cancellation,
) -> Result<usize, ReadFault> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let source = matches!(stage, IoStage::Source);
    let mut retries = 0;
    loop {
        let count = ledger.with_state(|s| request(s, encrypted, source, bytes.len()))?;
        attempt(ledger, encrypted, Some(cancel))?;
        let result = reader.read(&mut bytes[..count]);
        match result {
            Ok(n) => {
                if n > count {
                    return Err(ReadFault::CheckedFormat { reason: "reader exceeded requested slice" });
                }
                ledger.with_state(|s| s.transferred(encrypted, source, n as u64))?;
                return Ok(n);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => interrupted(ledger, &mut retries)?,
            Err(error) => return Err(ReadFault::Io { stage, operation: ReadIoOperation::Read, offset, error }),
        }
    }
}
pub(super) fn write(
    ledger: &(impl LedgerAccess + ?Sized),
    encrypted: bool,
    writer: &mut impl Write,
    stage: IoStage,
    offset: u64,
    bytes: &[u8],
    cancel: &Cancellation,
) -> Result<usize, ReadFault> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut retries = 0;
    loop {
        let count = ledger.with_state(|s| request(s, encrypted, false, bytes.len()))?;
        attempt(ledger, encrypted, Some(cancel))?;
        match writer.write(&bytes[..count]) {
            Ok(0) => {
                return Err(ReadFault::Io {
                    stage,
                    operation: ReadIoOperation::Write,
                    offset,
                    error: io::ErrorKind::WriteZero.into(),
                });
            }
            Ok(n) => {
                if n > count {
                    return Err(ReadFault::CheckedFormat { reason: "writer exceeded requested slice" });
                }
                ledger.with_state(|s| s.transferred(encrypted, false, n as u64))?;
                return Ok(n);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => interrupted(ledger, &mut retries)?,
            Err(error) => return Err(ReadFault::Io { stage, operation: ReadIoOperation::Write, offset, error }),
        }
    }
}
/// One finite namespace acquisition group, independently of name collisions.
/// Each callback performs exactly one create syscall, outside any shared borrow.
/// Every actual call, including EINTR, spends one creation attempt and ordinary
/// I/O attempt. AlreadyExists permits another name in this same group; success
/// or any other terminal outcome forbids further acquisition through the group.
/// Tasks2/5 separately meter their bounded auxiliary namespace operations and
/// prove their fixed per-try count fits the plan's twelve-operation envelope.
pub(super) struct CreationGroup<'a> {
    ledger: LedgerView<'a>,
    encrypted: bool,
    stage: IoStage,
    limit: u64,
    retry_limit: u64,
    attempts: u64,
    terminal: bool,
}
impl<'a> CreationGroup<'a> {
    pub(super) fn new(
        ledger: &'a (impl LedgerAccess + ?Sized),
        encrypted: bool,
        stage: IoStage,
        cancel: &Cancellation,
    ) -> Result<Self, ReadFault> {
        canceled(Some(cancel))?;
        let (limit, retry_limit) = ledger.with_state(|s| {
            let policy = s.creation_policy(encrypted)?;
            s.charge_category(RunCategory::TemporaryGroups, 1)?;
            if encrypted {
                s.encrypted.usage.create_attempts = 0;
            }
            Ok(policy)
        })?;
        Ok(Self { ledger: ledger.view(), encrypted, stage, limit, retry_limit, attempts: 0, terminal: false })
    }
    pub(super) fn create<T>(
        &mut self,
        cancel: &Cancellation,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, ReadFault> {
        if self.terminal {
            return Err(ReadFault::InvalidPlan);
        }
        let result = (|| {
            let mut interrupted = 0u64;
            loop {
                canceled(Some(cancel))?;
                let next = budget::next_creation_attempt(self.attempts, self.limit)?;
                self.ledger.with_state(|s| {
                    if s.poisoned {
                        return Err(ReadFault::InvalidPlan);
                    }
                    s.attempt(self.encrypted)?;
                    if self.encrypted {
                        s.encrypted.usage.create_attempts = next;
                    }
                    Ok(())
                })?;
                self.attempts = next;
                match call() {
                    Ok(value) => return Ok(value),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        interrupted = interrupted.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
                        budget::admit(ReadResource::InterruptedRetries, self.retry_limit.into(), interrupted.into())?;
                    }
                    Err(error) => {
                        return Err(ReadFault::Io {
                            stage: self.stage,
                            operation: ReadIoOperation::Create,
                            offset: 0,
                            error,
                        });
                    }
                }
            }
        })();
        self.terminal =
            !matches!(&result, Err(ReadFault::Io { error, .. }) if error.kind() == io::ErrorKind::AlreadyExists);
        result
    }
}

/// One finite metadata/seek/namespace operation. Callers select and consume the
/// concrete category before entering; Interrupted consumes another ordinary attempt.
pub(super) fn operation<T>(
    ledger: &(impl LedgerAccess + ?Sized),
    encrypted: bool,
    category: RunCategory,
    stage: IoStage,
    operation: ReadIoOperation,
    cancel: Option<&Cancellation>,
    mut call: impl FnMut() -> io::Result<T>,
) -> Result<T, ReadFault> {
    // Creation must use CreationGroup so callers cannot accidentally bypass its
    // per-namespace limit or charge one object group per collision.
    if operation == ReadIoOperation::Create {
        return Err(ReadFault::InvalidPlan);
    }
    ledger.with_state(|s| s.charge_category(category, 1))?;
    let mut retries = 0;
    loop {
        attempt(ledger, encrypted, cancel)?;
        match call() {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => interrupted(ledger, &mut retries)?,
            Err(error) => return Err(ReadFault::Io { stage, operation, offset: 0, error }),
        }
    }
}
pub(super) fn rewind(
    ledger: &(impl LedgerAccess + ?Sized),
    encrypted: bool,
    file: &mut impl Seek,
    cancel: &Cancellation,
) -> Result<(), ReadFault> {
    operation(
        ledger,
        encrypted,
        RunCategory::StageFinalization,
        IoStage::Output,
        ReadIoOperation::Seek,
        Some(cancel),
        || file.seek(SeekFrom::Start(0)),
    )
    .map(|_| ())
}
pub(super) fn sink(fault: ReadFault) -> ZipSinkFault {
    match fault {
        ReadFault::Limit { resource, limit, attempted } => ZipSinkFault::Limit { resource, limit, attempted },
        ReadFault::Allocation { capacity } => ZipSinkFault::Allocation { capacity },
        ReadFault::Cancelled => ZipSinkFault::Cancelled,
        ReadFault::Io { operation, offset, error, .. } => ZipSinkFault::Io { operation, offset, error },
        _ => ZipSinkFault::StageChanged,
    }
}

#[derive(Debug)]
pub(crate) enum SourceCheckError {
    Admission(ReadFault),
    Source(CheckedSourceFault),
}
impl From<SourceCheckError> for ZipReadError {
    fn from(error: SourceCheckError) -> Self {
        match error {
            SourceCheckError::Admission(fault) => fault.into(),
            SourceCheckError::Source(fault) => fault.into(),
        }
    }
}
/// Phase-local observations. Each physical phase is reported once, separately
/// from the later action's encrypted and run accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BootstrapPhase {
    /// Only the opportunistic identity attempt in a legacy constructor. Legacy
    /// open/dispatch/parser calls are outside this partial snapshot.
    LegacySourceProof,
    SourceOpen,
    ActionPlan,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct BootstrapUsage {
    phase: BootstrapPhase,
    attempts: u128,
    bytes: u64,
    metadata: u64,
    dispatch_bytes: u64,
    seeks: u64,
    path_operations: u64,
    opens: u64,
    acquired_fds: u64,
    acquisition_attempts: u64,
    capacity: u64,
    configuration_bytes: usize,
    configuration_acquisitions: u64,
    retirement: Option<CloseDisposition>,
    source_retirement: Option<CloseDisposition>,
    cwd_retirement: Option<CloseDisposition>,
}
impl BootstrapUsage {
    pub fn phase(self) -> BootstrapPhase {
        self.phase
    }
    pub fn attempts(self) -> u128 {
        self.attempts
    }
    pub fn bytes(self) -> u64 {
        self.bytes
    }
    pub fn metadata(self) -> u64 {
        self.metadata
    }
    pub fn dispatch_bytes(self) -> u64 {
        self.dispatch_bytes
    }
    pub fn seeks(self) -> u64 {
        self.seeks
    }
    pub fn path_operations(self) -> u64 {
        self.path_operations
    }
    pub fn opens(self) -> u64 {
        self.opens
    }
    pub fn acquired_fds(self) -> u64 {
        self.acquired_fds
    }
    pub fn acquisition_attempts(self) -> u64 {
        self.acquisition_attempts
    }
    /// Sum of requested capacities for actual phase-local allocation attempts;
    /// this is neither retained heap bytes nor process RSS.
    pub fn capacity(self) -> u64 {
        self.capacity
    }
    /// Requested caller-configuration metadata bytes, separate from payload scratch.
    pub fn configuration_bytes(self) -> usize {
        self.configuration_bytes
    }
    pub fn configuration_acquisitions(self) -> u64 {
        self.configuration_acquisitions
    }
    pub fn source_retirement(self) -> Option<CloseDisposition> {
        self.source_retirement
    }
    pub fn cwd_retirement(self) -> Option<CloseDisposition> {
        self.cwd_retirement
    }
    pub fn retirement(self) -> Option<CloseDisposition> {
        self.retirement
    }
}
#[cfg(test)]
#[derive(Clone, Copy)]
pub(super) struct BootstrapTestFault {
    pub(super) stage: Option<IoStage>,
    pub(super) operation: ReadIoOperation,
    pub(super) remaining: u64,
    pub(super) errno: i32,
    pub(super) deny_allocations: bool,
}
#[cfg(test)]
thread_local! {pub(super) static BOOTSTRAP_FAULT:std::cell::Cell<Option<BootstrapTestFault>>=const {std::cell::Cell::new(None)};}
#[cfg(test)]
fn injected(stage: Option<IoStage>, operation: ReadIoOperation) -> Option<io::Error> {
    BOOTSTRAP_FAULT.with(|s| {
        let mut fault = s.get()?;
        if fault.stage != stage || fault.operation != operation {
            return None;
        }
        fault.remaining -= 1;
        if fault.deny_allocations {
            crate::test_alloc::REFUSE_ALLOCATIONS.with(|s| s.set(true));
        }
        s.set(if fault.remaining == 0 { None } else { Some(fault) });
        Some(io::Error::from_raw_os_error(fault.errno))
    })
}
/// Finite pre-catalogue accounting, independent of any encrypted quota.
pub(crate) struct BootstrapIo {
    remaining_bytes: u64,
    fetch_limit: u64,
    max_attempts: u128,
    retries: u64,
    usage: BootstrapUsage,
    eof: u8,
    path_groups: u8,
    resolution_attempts: u128,
    retired_objects: u8,
}
impl BootstrapIo {
    pub(crate) fn new(fetch_bytes: u64, retries: u64) -> Result<Self, ReadFault> {
        let max_attempts = u128::from(fetch_bytes)
            .checked_mul(2)
            .and_then(|v| v.checked_add(15))
            .and_then(|v| v.checked_mul(u128::from(retries) + 1))
            .ok_or(ReadFault::CounterOverflow)?;
        Ok(Self {
            remaining_bytes: fetch_bytes,
            fetch_limit: fetch_bytes,
            max_attempts,
            retries,
            usage: BootstrapUsage {
                phase: BootstrapPhase::ActionPlan,
                attempts: 0,
                bytes: 0,
                metadata: 0,
                dispatch_bytes: 0,
                seeks: 0,
                path_operations: 0,
                opens: 0,
                acquired_fds: 0,
                acquisition_attempts: 0,
                capacity: 0,
                configuration_bytes: 0,
                configuration_acquisitions: 0,
                retirement: None,
                source_retirement: None,
                cwd_retirement: None,
            },
            eof: 0,
            path_groups: 0,
            resolution_attempts: 0,
            retired_objects: 0,
        })
    }
    pub(super) fn legacy_proof() -> Result<Self, ReadFault> {
        let mut state = Self::new(0, 16)?;
        state.usage.phase = BootstrapPhase::LegacySourceProof;
        Ok(state)
    }
    pub(super) fn opening() -> Result<Self, ReadFault> {
        let mut state = Self::new(129 << 20, 16)?;
        state.usage.phase = BootstrapPhase::SourceOpen;
        Ok(state)
    }
    pub(super) fn usage(&self) -> BootstrapUsage {
        self.usage
    }
    fn attempt(&mut self) -> Result<(), ReadFault> {
        let attempted = self.usage.attempts.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        budget::admit(ReadResource::BootstrapAttempts, self.max_attempts, attempted)?;
        self.usage.attempts = attempted;
        Ok(())
    }
    pub(super) fn resolve_charge(&mut self, charge: spool::ResolveCharge) -> Result<(), ReadFault> {
        match charge {
            spool::ResolveCharge::Group => {
                self.path_groups = self.path_groups.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
                budget::admit(ReadResource::BootstrapMetadata, 5, self.path_groups.into())
            }
            spool::ResolveCharge::Attempt => {
                let next = self.resolution_attempts.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
                budget::admit(ReadResource::BootstrapAttempts, 3 * (u128::from(self.retries) + 1), next)?;
                self.resolution_attempts = next;
                self.attempt()
            }
        }
    }
    pub(super) fn configuration_acquisition(&mut self, bytes: usize) -> Result<(), ReadFault> {
        self.usage.configuration_acquisitions =
            self.usage.configuration_acquisitions.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        self.usage.configuration_bytes =
            self.usage.configuration_bytes.checked_add(bytes).ok_or(ReadFault::CounterOverflow)?;
        Ok(())
    }
    pub(super) fn acquisition(&mut self, capacity: usize) -> Result<(), ReadFault> {
        self.usage.acquisition_attempts =
            self.usage.acquisition_attempts.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        self.usage.capacity = self.usage.capacity.checked_add(capacity as u64).ok_or(ReadFault::CounterOverflow)?;
        Ok(())
    }
    /// Separate one-shot cwd/source close reservations, admitted before call.
    pub(super) fn retire_once(
        &mut self,
        object: OwnedObject,
        close: impl FnOnce() -> io::Result<()>,
    ) -> Result<(), CleanupFault> {
        let bit = match object {
            OwnedObject::Source => 1,
            OwnedObject::SourcePathDirectory => 2,
            _ => 0,
        };
        let admitted = if bit == 0 || self.retired_objects & bit != 0 {
            Err(ReadFault::InvalidPlan)
        } else {
            self.usage.attempts.checked_add(1).ok_or(ReadFault::CounterOverflow).map(|next| {
                self.usage.attempts = next;
                self.retired_objects |= bit;
            })
        };
        let result = admitted.map_err(CleanupCause::Admission).and_then(|()| close().map_err(CleanupCause::Io));
        let disposition = if result.is_ok() { CloseDisposition::Closed } else { CloseDisposition::Unresolved };
        self.usage.retirement = Some(disposition);
        match object {
            OwnedObject::Source => self.usage.source_retirement = Some(disposition),
            OwnedObject::SourcePathDirectory => self.usage.cwd_retirement = Some(disposition),
            _ => {}
        }
        result.map_err(|cause| CleanupFault {
            object,
            operation: ReadIoOperation::Close,
            offset: None,
            cause,
            close: disposition,
        })
    }
    pub(super) fn dispatch(&mut self, bytes: u64) -> Result<(), ReadFault> {
        let next = self.usage.dispatch_bytes.checked_add(bytes).ok_or(ReadFault::CounterOverflow)?;
        budget::admit(ReadResource::BootstrapBytes, self.usage.bytes.into(), next.into())?;
        self.usage.dispatch_bytes = next;
        Ok(())
    }
    pub(super) fn call<T>(
        &mut self,
        operation: ReadIoOperation,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, ReadFault> {
        let mut retries = 0u128;
        loop {
            self.attempt()?;
            #[cfg(test)]
            let result = match injected(None, operation) {
                Some(error) => Err(error),
                None => call(),
            };
            #[cfg(not(test))]
            let result = call();
            match result {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    retries = retries.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
                    budget::admit(ReadResource::InterruptedRetries, self.retries.into(), retries)?;
                }
                Err(error) => return Err(ReadFault::Io { stage: IoStage::Bootstrap, operation, offset: 0, error }),
            }
        }
    }
    pub(super) fn path<T>(&mut self, call: impl FnMut() -> io::Result<T>) -> Result<T, ReadFault> {
        budget::admit(ReadResource::BootstrapAttempts, 3, u128::from(self.usage.path_operations) + 1)?;
        self.usage.path_operations += 1;
        self.call(ReadIoOperation::Directory, call)
    }
    pub(super) fn opened<T>(&mut self, call: impl FnMut() -> io::Result<T>) -> Result<T, ReadFault> {
        budget::admit(ReadResource::BootstrapAttempts, 1, u128::from(self.usage.opens) + 1)?;
        self.usage.opens += 1;
        let result = self.call(ReadIoOperation::Open, call);
        if result.is_ok() {
            self.usage.acquired_fds += 1;
        }
        result
    }
    pub(crate) fn stat<T>(
        &mut self,
        stage: IoStage,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, SourceCheckError> {
        budget::admit(ReadResource::BootstrapMetadata, 6, u128::from(self.usage.metadata) + 1)
            .map_err(SourceCheckError::Admission)?;
        self.usage.metadata += 1;
        let mut retries = 0u64;
        loop {
            self.attempt().map_err(SourceCheckError::Admission)?;
            #[cfg(test)]
            let result = match injected(Some(stage), ReadIoOperation::Stat) {
                Some(error) => Err(error),
                None => call(),
            };
            #[cfg(not(test))]
            let result = call();
            match result {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    retries = retries.checked_add(1).ok_or(SourceCheckError::Admission(ReadFault::CounterOverflow))?;
                    budget::admit(ReadResource::InterruptedRetries, self.retries.into(), retries.into())
                        .map_err(SourceCheckError::Admission)?;
                }
                Err(error) => return Err(SourceCheckError::Source(CheckedSourceFault::Unavailable { stage, error })),
            }
        }
    }
    pub(super) fn seek(&mut self, file: &mut impl Seek, at: u64, cancel: &Cancellation) -> Result<(), ReadFault> {
        canceled(Some(cancel))?;
        budget::admit(
            ReadResource::BootstrapAttempts,
            u128::from(self.fetch_limit) + 2,
            u128::from(self.usage.seeks) + 1,
        )?;
        self.usage.seeks += 1;
        let actual = self.call(ReadIoOperation::Seek, || file.seek(SeekFrom::Start(at)))?;
        if actual != at {
            return Err(ReadFault::CheckedFormat { reason: "incorrect source seek" });
        }
        Ok(())
    }
    pub(super) fn read(
        &mut self,
        reader: &mut (impl Read + ?Sized),
        bytes: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<usize, ReadFault> {
        canceled(Some(cancel))?;
        if self.eof >= 3 {
            return Err(ReadFault::Limit { resource: ReadResource::BootstrapAttempts, limit: 3, attempted: 4 });
        }
        let count = bytes.len().min(WINDOW).min(self.remaining_bytes.min(WINDOW as u64) as usize);
        if count == 0 {
            return Err(ReadFault::Limit {
                resource: ReadResource::BootstrapBytes,
                limit: self.fetch_limit.into(),
                attempted: u128::from(self.usage.bytes) + 1,
            });
        }
        let n = self.call(ReadIoOperation::Read, || reader.read(&mut bytes[..count]))?;
        if n > count {
            return Err(ReadFault::CheckedFormat { reason: "reader exceeded requested slice" });
        }
        if n == 0 {
            self.eof += 1;
            budget::admit(ReadResource::BootstrapAttempts, 3, self.eof.into())?;
        }
        self.remaining_bytes -= n as u64;
        self.usage.bytes += n as u64;
        Ok(n)
    }
}

/// Retires one already-owned raw handle exactly once. The owner must have
/// transferred ownership out of any automatic-close wrapper before this call.
/// Both ordinary and emergency accounting are finite; EINTR is ambiguous and
/// is never retried. Exhaustion leaves unresolved usage rather than making an
/// uncharged syscall or reconstructing an OwnedFd.
pub(super) fn retire_once(
    ledger: &(impl LedgerAccess + ?Sized),
    encrypted: bool,
    object: OwnedObject,
    close: impl FnOnce() -> std::io::Result<()>,
) -> Result<(), CleanupFault> {
    let ordinary = ledger.with_state(|s| s.close_attempt(encrypted));
    let admitted =
        ordinary.is_ok() || ledger.with_state(|s| s.charge_category(RunCategory::EmergencyCleanup, 1)).is_ok();
    if !admitted {
        ledger.with_state(|s| s.retire_fd(false));
        return Err(CleanupFault {
            object,
            operation: ReadIoOperation::Close,
            offset: None,
            cause: CleanupCause::Policy("finite close allowance exhausted"),
            close: CloseDisposition::Unresolved,
        });
    }
    match close() {
        Ok(()) => {
            ledger.with_state(|s| s.retire_fd(true));
            Ok(())
        }
        Err(error) => {
            ledger.with_state(|s| s.retire_fd(false));
            Err(CleanupFault {
                object,
                operation: ReadIoOperation::Close,
                offset: None,
                cause: CleanupCause::Io(error),
                close: CloseDisposition::Unresolved,
            })
        }
    }
}
