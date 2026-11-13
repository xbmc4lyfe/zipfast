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
use super::{budget::LedgerState, shared::ReservationLedger, *};
use crate::extract::Cancellation;
use std::io::{self, Read, Seek, SeekFrom, Write};
pub(super) const WINDOW: usize = 64 << 10;

pub(super) fn canceled(cancel: Option<&Cancellation>) -> Result<(), ReadFault> {
    if cancel.is_some_and(Cancellation::is_canceled) { Err(ReadFault::Cancelled) } else { Ok(()) }
}
fn attempt(ledger: &ReservationLedger, encrypted: bool, cancel: Option<&Cancellation>) -> Result<(), ReadFault> {
    canceled(cancel)?;
    ledger.with_state(|s| s.attempt(encrypted))
}
fn interrupted(ledger: &ReservationLedger, retries: &mut u64) -> Result<(), ReadFault> {
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
    ledger: &ReservationLedger,
    encrypted: bool,
    reader: &mut impl Read,
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
    ledger: &ReservationLedger,
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
    ledger: &'a ReservationLedger,
    encrypted: bool,
    stage: IoStage,
    limit: u64,
    retry_limit: u64,
    attempts: u64,
    terminal: bool,
}
impl<'a> CreationGroup<'a> {
    #[allow(dead_code)] // Task2 spool / Task5 stage acquisition consumes one namespace group.
    pub(super) fn new(
        ledger: &'a ReservationLedger,
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
        Ok(Self { ledger, encrypted, stage, limit, retry_limit, attempts: 0, terminal: false })
    }
    #[allow(dead_code)] // Task2/5 supply one actual create syscall per callback; no hidden retries.
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
    ledger: &ReservationLedger,
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
    ledger: &ReservationLedger,
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
/// Finite pre-catalogue accounting, independent of any encrypted quota.
pub(crate) struct BootstrapIo {
    remaining_bytes: u64,
    attempts: u128,
    max_attempts: u128,
    metadata: u8,
    retries: u64,
}
impl BootstrapIo {
    pub(crate) fn new(fetch_bytes: u64, retries: u64) -> Result<Self, ReadFault> {
        let max_attempts = u128::from(fetch_bytes)
            .checked_add(7)
            .and_then(|v| v.checked_mul(u128::from(retries) + 1))
            .ok_or(ReadFault::CounterOverflow)?;
        Ok(Self { remaining_bytes: fetch_bytes, attempts: 0, max_attempts, metadata: 6, retries })
    }
    pub(crate) fn stat<T>(
        &mut self,
        stage: IoStage,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, SourceCheckError> {
        if self.metadata == 0 {
            return Err(SourceCheckError::Admission(ReadFault::Limit {
                resource: ReadResource::BootstrapMetadata,
                limit: 6,
                attempted: 7,
            }));
        }
        self.metadata -= 1;
        let mut retries = 0;
        loop {
            if self.attempts >= self.max_attempts {
                return Err(SourceCheckError::Admission(ReadFault::Limit {
                    resource: ReadResource::BootstrapAttempts,
                    limit: self.max_attempts,
                    attempted: self
                        .attempts
                        .checked_add(1)
                        .ok_or(SourceCheckError::Admission(ReadFault::CounterOverflow))?,
                }));
            }
            self.attempts += 1;
            match call() {
                Ok(value) => return Ok(value),
                Err(error) if error.kind() == io::ErrorKind::Interrupted && retries < self.retries => {
                    retries += 1;
                }
                Err(error) => return Err(SourceCheckError::Source(CheckedSourceFault::Unavailable { stage, error })),
            }
        }
    }
    #[allow(dead_code)] // Task4 parser bootstrap will consume this finite fetch wrapper.
    pub(super) fn read(
        &mut self,
        reader: &mut impl Read,
        bytes: &mut [u8],
        cancel: &Cancellation,
    ) -> Result<usize, ReadFault> {
        let count = bytes.len().min(WINDOW).min(self.remaining_bytes.min(WINDOW as u64) as usize);
        if count == 0 {
            return Err(ReadFault::InvalidPlan);
        }
        let mut retries = 0;
        loop {
            canceled(Some(cancel))?;
            if self.attempts >= self.max_attempts {
                return Err(ReadFault::InvalidPlan);
            }
            self.attempts += 1;
            match reader.read(&mut bytes[..count]) {
                Ok(n) => {
                    self.remaining_bytes -= n as u64;
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted && retries < self.retries => retries += 1,
                Err(error) => {
                    return Err(ReadFault::Io {
                        stage: IoStage::Bootstrap,
                        operation: ReadIoOperation::Read,
                        offset: 0,
                        error,
                    });
                }
            }
        }
    }
}

/// Retires one already-owned raw handle exactly once. The owner must have
/// transferred ownership out of any automatic-close wrapper before this call.
/// Both ordinary and emergency accounting are finite; EINTR is ambiguous and
/// is never retried. Exhaustion leaves unresolved usage rather than making an
/// uncharged syscall or reconstructing an OwnedFd.
#[allow(dead_code)] // Task2 spool and Task5 stage owners consume this tested close primitive.
pub(super) fn retire_once(
    ledger: &ReservationLedger,
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
