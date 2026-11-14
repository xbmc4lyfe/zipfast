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

//! Controlled named-file preparation; lexical reservations precede acquisition.
use super::*;
use crate::zip::read::shared::{LedgerAccess, LedgerView};
use std::os::fd::AsRawFd;

pub(super) struct PreparedNamed {
    pub(super) parent: parent::HeldParent,
    pub(super) directory: directory::PrivateDirectory,
    pub(super) inode: named::NamedFile,
    pub(super) child: policy::ChildPolicy,
    pub(super) mode: Option<u32>,
    pub(super) mtime: Option<(i64, u32)>,
    pub(super) overwrite: crate::extract::Overwrite,
}
fn merge(error: &mut Option<ZipReadError>, report: ObjectCleanupReport) {
    if !report.is_empty() {
        *error = Some(match error.take() {
            Some(error) => error.merge_cleanup(report),
            None => report.into(),
        });
    }
}
fn merge_error(error: &mut Option<ZipReadError>, next: ZipReadError) {
    *error = Some(match error.take() {
        Some(error) => error.merge_cleanup_only(next),
        None => next,
    });
}
fn metadata_fault(error: &mut Option<ZipReadError>, fault: ReadFault) {
    let mut report = ObjectCleanupReport::new(OwnedObject::Output);
    report.push(CleanupFault {
        object: OwnedObject::Output,
        operation: ReadIoOperation::Stat,
        offset: None,
        close: CloseDisposition::NotApplicable,
        cause: CleanupCause::Admission(fault),
    });
    merge(error, report);
}
impl PreparedNamed {
    #[allow(clippy::result_large_err)]
    fn finish_published(
        mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        cancel: &Cancellation,
    ) -> ZipReadResult<()> {
        let mut result = self.directory.close_final(ledger, encrypted);
        if result.is_ok() {
            result = self.directory.remove_empty_normal(ledger, &self.parent, encrypted, cancel);
        }
        let mut error = result.err();
        if error.is_some() {
            ledger.with_state(|s| s.poisoned = true);
            let parent_ok = match self.parent.verify_cleanup_name(ledger) {
                Ok(()) => true,
                Err(fault) => {
                    let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                    report.push(fault);
                    merge(&mut error, report);
                    false
                }
            };
            let report = if parent_ok {
                self.directory.cleanup(ledger, &self.parent, encrypted)
            } else {
                self.directory.cleanup_blocked(ledger, encrypted)
            };
            merge(&mut error, report);
        }
        if let Err(fault) = self.child.finish(ledger) {
            metadata_fault(&mut error, fault);
        }
        if let Err(next) = self.parent.finish_observed(ledger, error.is_none(), encrypted) {
            if error.is_some() {
                merge_error(&mut error, next);
            } else {
                error = Some(next);
            }
        }
        error.map_or(Ok(()), Err)
    }
    fn finish_unpublished(
        mut self,
        ledger: &impl LedgerAccess,
        encrypted: bool,
        normal_output_close: bool,
    ) -> (bool, Option<ZipReadError>) {
        let mut error = None;
        let parent_ok = match self.parent.verify_cleanup_name(ledger) {
            Ok(()) => true,
            Err(fault) => {
                let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                report.push(fault);
                merge(&mut error, report);
                false
            }
        };
        let (clear, report) = if parent_ok {
            if normal_output_close {
                self.inode.retire_normal(ledger, &self.parent, &self.directory, encrypted)
            } else {
                self.inode.retire(ledger, &self.parent, &self.directory, encrypted)
            }
        } else {
            self.inode.retire_blocked(ledger, &self.parent, &self.directory, encrypted)
        };
        merge(&mut error, report);
        // Normal-success admission remains required even though no-clobber
        // collision/Skip transfers no target. One actual close, no retry.
        if let Err(next) = self.directory.close_final(ledger, encrypted) {
            let next =
                if normal_output_close { next.retirement_cleanup(OwnedObject::OutputPrivateDirectory) } else { next };
            error = Some(match error.take() {
                Some(prior) => prior.merge_cleanup_only(next.retirement_cleanup(OwnedObject::OutputPrivateDirectory)),
                None => next,
            });
        }
        let report = if parent_ok {
            self.directory.cleanup(ledger, &self.parent, encrypted)
        } else {
            self.directory.cleanup_blocked(ledger, encrypted)
        };
        merge(&mut error, report);
        if let Err(fault) = self.child.finish(ledger) {
            metadata_fault(&mut error, fault);
        }
        if let Err(next) = self.parent.finish_observed(ledger, error.is_none(), encrypted) {
            let next = if normal_output_close { next.retirement_cleanup(OwnedObject::OutputParent) } else { next };
            if error.is_some() {
                merge_error(&mut error, next);
            } else {
                error = Some(next);
            }
        }
        if error.is_some() || !clear {
            ledger.with_state(|s| s.poisoned = true);
        }
        (clear, error)
    }
    fn cleanup(
        mut self,
        ledger: &impl LedgerAccess,
        file: Option<File>,
        encrypted: bool,
    ) -> (bool, Option<ZipReadError>) {
        ledger.with_state(|s| s.poisoned = true);
        self.inode.file = file;
        let mut error = None;
        let parent_ok = match self.parent.verify_cleanup_name(ledger) {
            Ok(()) => true,
            Err(fault) => {
                let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                report.push(fault);
                merge(&mut error, report);
                false
            }
        };
        let directory_ok = if parent_ok {
            match self.directory.reopen_cleanup(ledger, &self.parent) {
                Ok(()) => true,
                Err(fault) => {
                    let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
                    report.push(fault);
                    merge(&mut error, report);
                    false
                }
            }
        } else {
            false
        };
        let (clear, report) = if parent_ok && directory_ok {
            self.inode.retire(ledger, &self.parent, &self.directory, encrypted)
        } else {
            self.inode.retire_blocked(ledger, &self.parent, &self.directory, encrypted)
        };
        merge(&mut error, report);
        let directory = if parent_ok && directory_ok {
            self.directory.cleanup(ledger, &self.parent, encrypted)
        } else {
            self.directory.cleanup_blocked(ledger, encrypted)
        };
        merge(&mut error, directory);
        if let Err(fault) = self.child.finish(ledger) {
            metadata_fault(&mut error, fault);
        }
        if let Err(next) = self.parent.finish_observed(ledger, false, encrypted) {
            merge_error(&mut error, next);
        }
        (clear, error)
    }
}
struct Preparing<'a> {
    ledger: LedgerView<'a>,
    encrypted: bool,
    bytes: u64,
    parent: Option<parent::HeldParent>,
    directory: Option<directory::PrivateDirectory>,
    inode: Option<named::NamedFile>,
    child: Option<policy::ChildPolicy>,
    snapshot: Option<policy::ParentPolicy>,
    parent_unbound: bool,
    parent_observed: Option<bool>,
    stage_unbound: bool,
    storage_clear: bool,
    finished: bool,
}
impl Preparing<'_> {
    fn cleanup(&mut self) -> Option<ZipReadError> {
        if self.finished {
            return None;
        }
        self.finished = true;
        self.ledger.with_state(|s| s.poisoned = true);
        let mut error = None;
        if let Some(snapshot) = self.snapshot.take()
            && let Err(fault) = snapshot.finish(&self.ledger)
        {
            metadata_fault(&mut error, fault);
        }
        if let Some(parent) = self.parent.take() {
            let parent_ok = match self.parent_observed.take() {
                Some(valid) => valid,
                None => match parent.verify_cleanup_name(&self.ledger) {
                    Ok(()) => true,
                    Err(fault) => {
                        let mut report = ObjectCleanupReport::new(OwnedObject::OutputParent);
                        report.push(fault);
                        merge(&mut error, report);
                        false
                    }
                },
            };
            if let Some(mut directory) = self.directory.take() {
                if let Some(mut inode) = self.inode.take() {
                    let ready = parent_ok
                        && directory
                            .reopen_cleanup(&self.ledger, &parent)
                            .map_err(|fault| {
                                let mut report = ObjectCleanupReport::new(OwnedObject::OutputPrivateDirectory);
                                report.push(fault);
                                merge(&mut error, report);
                            })
                            .is_ok();
                    let (clear, report) = if ready {
                        inode.retire(&self.ledger, &parent, &directory, self.encrypted)
                    } else {
                        inode.retire_blocked(&self.ledger, &parent, &directory, self.encrypted)
                    };
                    self.storage_clear = clear;
                    merge(&mut error, report);
                    let report = if ready {
                        directory.cleanup(&self.ledger, &parent, self.encrypted)
                    } else {
                        directory.cleanup_blocked(&self.ledger, self.encrypted)
                    };
                    merge(&mut error, report);
                } else {
                    let report = if parent_ok {
                        directory.cleanup(&self.ledger, &parent, self.encrypted)
                    } else {
                        directory.cleanup_blocked(&self.ledger, self.encrypted)
                    };
                    merge(&mut error, report);
                }
            }
            if let Err(next) = parent.finish_observed(&self.ledger, false, self.encrypted) {
                merge_error(&mut error, next);
            }
        }
        if let Some(child) = self.child.take()
            && let Err(fault) = child.finish(&self.ledger)
        {
            metadata_fault(&mut error, fault);
        }
        if self.parent_unbound {
            self.ledger.with_state(|s| s.retire_fd(true));
            self.parent_unbound = false;
        }
        if self.stage_unbound {
            self.ledger.with_state(|s| s.retire_fd(true));
            self.stage_unbound = false;
        }
        if self.storage_clear {
            self.ledger.with_state(|s| s.release_bytes(self.encrypted, self.bytes));
        }
        error
    }
}
impl Drop for Preparing<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cleanup();
        }
    }
}
#[allow(clippy::result_large_err)]
fn acquire(
    ledger: LedgerView<'_>,
    binding: &FileBinding<'_>,
    options: &crate::extract::Options,
    context: &EncryptedReadContext,
    cancel: &Cancellation,
    blocked: &mut Option<target::Refusal>,
    allow_blocked: bool,
) -> ZipReadResult<Option<PreparedNamed>> {
    ledger.with_state(|s| s.reserve(binding.encrypted, binding.bytes, 2))?;
    let mut preparing = Preparing {
        ledger,
        encrypted: binding.encrypted,
        bytes: binding.bytes,
        parent: None,
        directory: None,
        inode: None,
        child: None,
        snapshot: None,
        parent_unbound: true,
        parent_observed: None,
        stage_unbound: true,
        storage_clear: true,
        finished: false,
    };
    let result = (|| -> ZipReadResult<bool> {
        let frozen = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?;
        let relative = binding.relative;
        preparing.parent_unbound = false;
        preparing.parent = Some(parent::open_parent(&ledger, &options.dest, relative, frozen.cwd(), cancel)?);
        let parent = preparing.parent.as_mut().unwrap();
        let mut scratch = policy::PolicyScratch::new(ledger)?;
        match target::inspect(&ledger, parent, frozen, options.overwrite, RunCategory::PathSteps, &mut scratch, cancel)?
        {
            target::Target::Skip => return Ok(false),
            target::Target::Blocked(refusal) if allow_blocked => {
                *blocked = Some(refusal);
                return Ok(false);
            }
            target::Target::Blocked(refusal) => return Err(refusal.fault().into()),
            _ => {}
        }
        io::operation(
            &ledger,
            binding.encrypted,
            RunCategory::StorageBackendOperations,
            IoStage::Output,
            ReadIoOperation::Stat,
            Some(cancel),
            || {
                spool::syscall(ReadIoOperation::Stat, parent.file.as_raw_fd(), || {
                    native_policy::backend(parent.file.as_raw_fd())
                })
            },
        )
        .map_err(|fault| match fault {
            ReadFault::Io { error, .. } if error.kind() == std::io::ErrorKind::Unsupported => {
                ReadFault::UnsupportedStorage
            }
            fault => fault,
        })?;
        let tilde = !parent.target().to_bytes().contains(&b'~');
        let (snapshot, child) = policy::probe(&ledger, &parent.file, frozen.uid, tilde, &mut scratch, cancel)?;
        preparing.snapshot = Some(snapshot);
        preparing.child = Some(child);
        match directory::PrivateDirectory::create(
            &ledger,
            parent,
            binding.encrypted,
            frozen.uid,
            tilde,
            &mut scratch,
            cancel,
        ) {
            Ok(directory) => preparing.directory = Some(directory),
            Err(failure) => {
                preparing.parent_observed = Some(failure.parent_valid);
                return Err(failure.error);
            }
        }
        let mut group = io::CreationGroup::new(&ledger, binding.encrypted, IoStage::Output, cancel)?;
        preparing.stage_unbound = false;
        preparing.storage_clear = false;
        match named::NamedFile::create_and_place(
            &ledger,
            parent,
            preparing.directory.as_ref().unwrap(),
            preparing.snapshot.as_ref().unwrap(),
            preparing.child.as_ref().unwrap(),
            binding.encrypted,
            binding.bytes,
            tilde,
            &mut group,
            &mut scratch,
            cancel,
        ) {
            Ok(inode) => preparing.inode = Some(inode),
            Err(failure) => {
                preparing.storage_clear = failure.retired;
                preparing.parent_observed = Some(failure.parent_valid);
                return Err(failure.error);
            }
        }
        preparing.directory.as_mut().unwrap().close_before_payload(&ledger, binding.encrypted)?;
        preparing.snapshot.take().unwrap().finish(&ledger)?;
        Ok(true)
    })();
    match result {
        Ok(true) => {
            let ready = PreparedNamed {
                parent: preparing.parent.take().unwrap(),
                directory: preparing.directory.take().unwrap(),
                inode: preparing.inode.take().unwrap(),
                child: preparing.child.take().unwrap(),
                mode: binding.mode,
                mtime: binding.mtime,
                overwrite: options.overwrite,
            };
            preparing.finished = true;
            Ok(Some(ready))
        }
        Ok(false) => {
            // Skip is a successful no-storage outcome. Retire the held parent
            // normally without poisoning this completed selected action.
            let parent = preparing.parent.take().unwrap();
            preparing.finished = true;
            ledger.with_state(|s| {
                s.retire_fd(true);
                s.release_bytes(binding.encrypted, binding.bytes);
            });
            parent.finish(&ledger)?;
            Ok(None)
        }
        Err(error) => Err(match preparing.cleanup() {
            Some(cleanup) => error.merge_cleanup_only(cleanup),
            None => error,
        }),
    }
}
#[allow(clippy::result_large_err)]
impl ZipReadStage {
    /// Prepares one original regular entry in its actual destination parent.
    /// The returned stage owns no borrow of the original source or entry.
    pub fn prepare_file(
        entry: ZipStageEntry<'_>,
        relative: &Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<Option<Self>> {
        Self::prepare_file_inner(entry, relative, options, cancel, context, &mut None, false)
    }
    pub(in crate::zip::read) fn prepare_run_file(
        entry: ZipStageEntry<'_>,
        relative: &Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<(Option<Self>, Option<ReadFault>)> {
        let mut blocked = None;
        let ready = Self::prepare_file_inner(entry, relative, options, cancel, context, &mut blocked, true)?;
        Ok((ready, blocked.map(target::Refusal::fault)))
    }
    #[allow(clippy::too_many_arguments)]
    fn prepare_file_inner(
        mut entry: ZipStageEntry<'_>,
        relative: &Path,
        options: &crate::extract::Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        blocked: &mut Option<target::Refusal>,
        allow_blocked: bool,
    ) -> ZipReadResult<Option<Self>> {
        if allow_blocked
            && !context.action.as_ref().is_some_and(|a| a.run_bound && a.scope == ProjectedReadScope::AllRegular)
        {
            return Err(ReadFault::InvalidPlan.into());
        }
        let binding = entry.bind_file(relative, options, cancel, context)?;
        let token = context.ledger.mint_reservation()?;
        let result = acquire(token.view(), &binding, options, context, cancel, blocked, allow_blocked);
        let boundary = entry.observe_source(context);
        let result = match (result, boundary) {
            (Ok(ready), Ok(())) => Ok(ready),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(boundary)) => Err(error.merge_source_boundary(boundary)),
            (Ok(ready), Err(error)) => {
                let mut error = error;
                if let Some(mut ready) = ready {
                    let file = ready.inode.file.take();
                    let (clear, cleanup) = ready.cleanup(&token, file, binding.encrypted);
                    if clear {
                        token.with_state(|s| s.release_bytes(binding.encrypted, binding.bytes));
                    }
                    if let Some(cleanup) = cleanup {
                        error = error.merge_cleanup_only(cleanup);
                    }
                }
                Err(error)
            }
        };
        match result {
            Ok(None) => Ok(None),
            Ok(Some(mut ready)) => {
                let file = ready.inode.file.take().ok_or(ReadFault::InvalidPlan)?;
                let identity = ready.inode.identity.ok_or(ReadFault::InvalidPlan)?;
                let handle = file_handle(&file);
                let uid = ready.child.uid;
                Ok(Some(Self {
                    file: Some(file),
                    reservation: OutputReservation {
                        ledger: token,
                        encrypted: binding.encrypted,
                        bytes: binding.bytes,
                        written: 0,
                        fds: 1,
                        identity,
                        handle,
                        retired: false,
                    },
                    source: binding.source,
                    uid,
                    descriptor: (0, 0, 0, 0),
                    terminal: false,
                    named: Some(ready),
                }))
            }
            Err(error) => {
                context.ledger.with_state(|s| s.poisoned = true);
                Err(token.with_state(|s| {
                    error.with_usage(s.encrypted.usage, s.run.usage).with_policy_usage(s.policy_metadata)
                }))
            }
        }
    }
    /// The whole-run normal member-error route never clears an emergency poison.
    pub(in crate::zip::read) fn finish_member_error(
        mut self,
        mut error: ZipReadError,
        context: &mut EncryptedReadContext,
        cancel: &Cancellation,
        mut source: impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadError {
        let valid = context.action.as_ref().is_some_and(|a| {
            a.run_bound
                && a.scope == ProjectedReadScope::AllRegular
                && a.active_ordinal.is_some()
                && a.controlled_output
        }) && self.reservation.ledger.identity() == context.ledger.identity()
            && !context.ledger.with_state(|s| s.poisoned);
        if !valid {
            return self.finish_error_with_final_source(error, context, &mut source);
        }
        if let Err(boundary) = self.source.observe(context, &mut source) {
            return self.finish_error_with_final_source(error.merge_source_boundary(boundary), context, &mut source);
        }
        let reopened = (|| -> ZipReadResult<()> {
            let ready = self.named.as_mut().ok_or(ReadFault::InvalidPlan)?;
            let mut scratch = policy::PolicyScratch::new(self.reservation.ledger.view())?;
            ready.directory.reopen_normal(
                &self.reservation.ledger,
                &ready.parent,
                self.reservation.encrypted,
                &mut scratch,
                cancel,
            )
        })();
        if let Err(boundary) = reopened {
            return self.finish_error_with_final_source(
                error.merge_cleanup_only(
                    boundary.owned_boundary_error(OwnedObject::OutputPrivateDirectory, ReadIoOperation::Open),
                ),
                context,
                &mut source,
            );
        }
        self.terminal = true;
        let mut ready = self.named.take().unwrap();
        ready.inode.file = self.file.take();
        let (clear, cleanup) = ready.finish_unpublished(&self.reservation.ledger, self.reservation.encrypted, true);
        if clear {
            self.reservation.ledger.with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
        }
        self.reservation.retired = true;
        if let Some(cleanup) = cleanup {
            error = error.merge_cleanup_only(cleanup);
        }
        if let Err(boundary) = self.source.observe(context, &mut source) {
            error = error.merge_source_boundary(boundary);
        }
        self.usage(error)
    }
    fn finish_error_with_final_source(
        self,
        error: ZipReadError,
        context: &mut EncryptedReadContext,
        source: &mut impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadError {
        let mut error = self.finish_error(error, context);
        if let Err(boundary) = source(context) {
            error = error.merge_source_boundary(boundary);
        }
        error.with_usage(context.usage(), context.run_usage()).with_policy_usage(context.policy_metadata_usage())
    }
    pub(super) fn retire_named(&mut self) -> Option<ZipReadError> {
        let ready = self.named.take()?;
        let (clear, error) = ready.cleanup(&self.reservation.ledger, self.file.take(), self.reservation.encrypted);
        if clear && !self.reservation.retired {
            self.reservation.ledger.with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
        }
        self.reservation.retired = true;
        error
    }
}

fn same_time(a: Option<(i64, u32)>, b: Option<(i64, u32)>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some((a, b)), Some((c, d))) => crate::extract::archive_time(a, b) == crate::extract::archive_time(c, d),
        _ => false,
    }
}
#[allow(clippy::result_large_err)] // Two fixed5120-byte terminal values merge without allocation.
fn boundary<T>(result: ZipReadResult<T>, observed: ZipReadResult<()>) -> ZipReadResult<T> {
    match (result, observed) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(observed)) => Err(error.merge_source_boundary(observed)),
    }
}

#[allow(clippy::result_large_err)]
impl ZipReadStage {
    fn validate_file(
        &self,
        mode: Option<u32>,
        mtime: Option<(i64, u32)>,
        context: &EncryptedReadContext,
    ) -> Result<(), ReadFault> {
        if self.reservation.ledger.identity() != context.ledger.identity()
            || self.reservation.ledger.with_state(|s| s.poisoned)
        {
            return Err(ReadFault::InvalidPlan);
        }
        context.verify_identity(self.source.owner)?;
        let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
        let ready = self.named.as_ref().ok_or(ReadFault::InvalidPlan)?;
        if !action.controlled_output
            || action.raw_output
            || !action.consumed
            || !action.completed
            || action.output != budget::PlannedOutput::StagedFiles
            || self.reservation.written != self.reservation.bytes
            || mode.map(|m| m & 0o777) != ready.mode.map(|m| m & 0o777)
            || !same_time(mtime, ready.mtime)
            || self.file.as_ref().is_none_or(|file| file_handle(file) != self.reservation.handle)
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    /// Publishes only after exact original read completion and fresh successful
    /// checked-source observations at both final boundaries.
    pub fn publish(
        mut self,
        mode: Option<u32>,
        mtime: Option<(i64, u32)>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut final_check: impl FnMut(&mut EncryptedReadContext) -> ZipReadResult<()>,
    ) -> ZipReadResult<bool> {
        if let Err(fault) = self.validate_file(mode, mtime, context) {
            return Err(self.finish_error(fault.into(), context));
        }
        let mut publication = PublicationState::NotPublished;
        let result = (|| -> ZipReadResult<bool> {
            let ledger = &self.reservation.ledger;
            let encrypted = self.reservation.encrypted;
            let mut scratch = policy::PolicyScratch::new(ledger.view())?;
            let ready = self.named.as_mut().ok_or(ReadFault::InvalidPlan)?;
            let metadata = (|| -> ZipReadResult<()> {
                ready.directory.reopen_normal(ledger, &ready.parent, encrypted, &mut scratch, cancel)?;
                metadata::restore(
                    ledger,
                    encrypted,
                    self.file.as_ref().ok_or(ReadFault::InvalidPlan)?,
                    &metadata::MetadataPlan {
                        identity: self.reservation.identity,
                        uid: ready.child.uid,
                        gid: ready.child.gid,
                        bytes: self.reservation.bytes,
                        baseline: ready.child.mode,
                        mode,
                        mtime,
                        acl: ready.child.acl.as_deref(),
                    },
                    &mut scratch,
                    cancel,
                )?;
                Ok(())
            })();
            boundary(metadata, self.source.observe(context, &mut final_check))?;
            let closed =
                ready.inode.close_for_publish(ledger, self.file.take().ok_or(ReadFault::InvalidPlan)?, encrypted);
            if let Err(error) = closed {
                return boundary(Err(error), self.source.observe(context, &mut final_check));
            }
            let eligible = (|| -> ZipReadResult<bool> {
                ready.parent.verify_normal_name(ledger, encrypted, cancel)?;
                ready.inode.check_inside(ledger, &ready.directory, ready.child.gid, encrypted, cancel)?;
                let frozen = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?;
                let target = target::inspect(
                    ledger,
                    &mut ready.parent,
                    frozen,
                    ready.overwrite,
                    RunCategory::StageFinalization,
                    &mut scratch,
                    cancel,
                )?;
                match target {
                    target::Target::Skip => Ok(false),
                    target::Target::Blocked(refusal) => Err(refusal.fault().into()),
                    _ => Ok(true),
                }
            })();
            let eligible = boundary(eligible, self.source.observe(context, &mut final_check))?;
            if !eligible {
                return Ok(false);
            }
            // The source proof immediately precedes this one-shot mutation.
            ledger.with_state(|s| s.charge_category(RunCategory::StageFinalization, 1))?;
            io::canceled(Some(cancel))?;
            ledger.with_state(|s| s.attempt(encrypted))?;
            let dir = ready.directory.file.as_ref().ok_or(ReadFault::InvalidPlan)?.as_raw_fd();
            let moved = spool::syscall(ReadIoOperation::Publish, ready.parent.file.as_raw_fd(), || {
                native_policy::rename_file(
                    dir,
                    ready.inode.leaf(),
                    ready.parent.file.as_raw_fd(),
                    ready.parent.target(),
                    ready.overwrite == crate::extract::Overwrite::Always,
                )
            });
            match moved {
                Ok(_) => {
                    publication = PublicationState::Published;
                    ready.inode.published();
                    Ok(true)
                }
                Err(error)
                    if ready.overwrite == crate::extract::Overwrite::Skip
                        && error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    Ok(false)
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::Interrupted
                        || error.raw_os_error() == Some(libc::EIO)
                        || error.raw_os_error().is_none()
                    {
                        publication = PublicationState::Unknown;
                    }
                    Err(ReadFault::Io { stage: IoStage::Output, operation: ReadIoOperation::Publish, offset: 0, error }
                        .into())
                }
            }
        })();
        match result {
            Err(error) => Err(self.finish_error(error.with_publication(publication, 0), context)),
            Ok(true) => {
                self.terminal = true;
                self.reservation.retired = true;
                self.reservation
                    .ledger
                    .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
                let ready = self.named.take().ok_or(ReadFault::InvalidPlan)?;
                ready
                    .finish_published(&self.reservation.ledger, self.reservation.encrypted, cancel)
                    .map(|_| true)
                    .map_err(|error| self.usage(error.with_publication(PublicationState::Published, 0)))
            }
            Ok(false) => {
                self.terminal = true;
                let ready = self.named.take().ok_or(ReadFault::InvalidPlan)?;
                let (clear, cleanup) =
                    ready.finish_unpublished(&self.reservation.ledger, self.reservation.encrypted, false);
                if clear {
                    self.reservation
                        .ledger
                        .with_state(|s| s.release_bytes(self.reservation.encrypted, self.reservation.bytes));
                }
                self.reservation.retired = true;
                let finality = self.source.observe(context, &mut final_check);
                let result = boundary(cleanup.map_or(Ok(false), Err), finality);
                if result.is_err() {
                    self.reservation.ledger.with_state(|s| s.poisoned = true);
                }
                result.map_err(|error| self.usage(error.with_publication(PublicationState::NotPublished, 0)))
            }
        }
    }
}

#[cfg(test)]
pub(super) fn control_layout() -> [usize; 12] {
    use std::mem::size_of;
    [
        size_of::<ZipReadStage>(),
        size_of::<PreparedNamed>(),
        size_of::<Preparing<'_>>(),
        size_of::<ZipStageEntry<'_>>(),
        size_of::<FileBinding<'_>>(),
        size_of::<parent::HeldParent>(),
        size_of::<directory::PrivateDirectory>(),
        size_of::<named::NamedFile>(),
        size_of::<metadata::MetadataPlan<'_>>(),
        size_of::<policy::PolicyScratch<'_>>(),
        size_of::<directory::DirectoryFailure>(),
        size_of::<named::PlacementFailure>(),
    ]
}
