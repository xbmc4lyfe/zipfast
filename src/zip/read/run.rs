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

//! One original catalogue, one frozen action, and borrowed synchronous outcomes.
use super::diagnostic::{DiagnosticState, Evidence};
use super::shared::LedgerAccess;
use super::*;
use crate::extract::{Mode, Options};

fn continued(error: &ZipReadError) -> bool {
    error.source_change().is_none()
        && error.sink_fault().is_none()
        && error.diagnostic_fault().is_none()
        && error.diagnostic_boundary_fault().is_none()
        && error.cleanup_errors().next().is_none()
        && matches!(
            error.operation(),
            Some(
                ReadFault::PasswordRequired
                    | ReadFault::PasswordCheckFailed { .. }
                    | ReadFault::AuthenticationFailed
                    | ReadFault::Integrity { .. }
                    | ReadFault::UnsupportedMethod { .. }
                    | ReadFault::Limit {
                        resource: ReadResource::MemberPackedBytes
                            | ReadResource::MemberDecodedBytes
                            | ReadResource::MemberSpoolBytes,
                        ..
                    }
            )
        )
}
fn add(counter: &mut u64) -> Result<(), ReadFault> {
    *counter = counter.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
    Ok(())
}

struct Completion {
    report: ZipRunReport,
    terminal: Option<ZipReadError>,
    observer_failed: bool,
}
fn snapshot(report: &mut ZipRunReport, context: &EncryptedReadContext, diagnostics: &DiagnosticState) {
    report.usage = context.usage();
    report.run_usage = context.run_usage();
    report.diagnostic_usage = diagnostics.usage;
}
impl Completion {
    fn merge(&mut self, evidence: Evidence) {
        if evidence.failed() {
            self.terminal = Some(evidence.merge(self.terminal.take().unwrap_or_else(|| ReadFault::InvalidPlan.into())));
        }
    }
    #[allow(clippy::result_large_err)] // Fixed evidence survives allocator refusal.
    fn finish(mut self, context: &EncryptedReadContext, diagnostics: &DiagnosticState) -> ZipReadResult<ZipRunReport> {
        snapshot(&mut self.report, context, diagnostics);
        match self.terminal {
            Some(error) => Err(error.with_usage(self.report.usage, self.report.run_usage).with_partial(self.report)),
            None => Ok(self.report),
        }
    }
}
#[cfg(test)]
type OwnedHook = Option<Box<dyn FnMut(u8, Option<&Path>)>>;
#[cfg(test)]
type DirectoryHook = Option<Box<dyn FnMut(usize)>>;
#[cfg(test)]
thread_local! {pub(super) static DIRECTORY_HOOK:std::cell::RefCell<DirectoryHook>=const{std::cell::RefCell::new(None)};pub(super) static OWNED_CLOSE_BOUND:std::cell::Cell<Option<u128>>=const{std::cell::Cell::new(None)};pub(super) static OWNED_CLOSE_CALLS:std::cell::Cell<u64>=const{std::cell::Cell::new(0)};pub(super) static OWNED_HOOK:std::cell::RefCell<OwnedHook>=const{std::cell::RefCell::new(None)};}
#[cfg(test)]
type FinalizationHook = Option<Box<dyn FnMut()>>;
#[cfg(test)]
thread_local! { pub(super) static FINALIZATION_HOOK: std::cell::RefCell<FinalizationHook> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
fn owned_hook(phase: u8, path: Option<&Path>) {
    let mut hook = OWNED_HOOK.with(|s| s.borrow_mut().take());
    if let Some(hook) = &mut hook {
        hook(phase, path);
    }
    OWNED_HOOK.with(|s| *s.borrow_mut() = hook);
}
pub(super) fn retire_owned_source(file: File, context: &EncryptedReadContext, normal: bool) -> Option<ZipReadError> {
    use std::os::fd::IntoRawFd;
    let fd = file.into_raw_fd();
    #[cfg(test)]
    if let Some(bound) = OWNED_CLOSE_BOUND.with(|s| s.take()) {
        context.ledger.with_state(|s| s.test_limit_category(RunCategory::FinalOperations, bound));
    }
    let retired =
        io::retire_in(&context.ledger, false, OwnedObject::Source, Some(RunCategory::FinalOperations), normal, || {
            #[cfg(test)]
            OWNED_CLOSE_CALLS.with(|s| s.set(s.get() + 1));
            projected::close_raw_once(fd)
        });
    let mut cleanup = ObjectCleanupReport::new(OwnedObject::Source);
    if let Some(fault) = retired.admission {
        cleanup.push(CleanupFault {
            object: OwnedObject::Source,
            operation: ReadIoOperation::Close,
            offset: None,
            cause: CleanupCause::Admission(fault),
            close: CloseDisposition::NotApplicable,
        });
    }
    if let Some(fault) = retired.fault {
        cleanup.push(fault);
    }
    if cleanup.is_empty() { None } else { Some(cleanup.into()) }
}

#[allow(clippy::result_large_err)] // Fixed forty-slot evidence; layout is pinned in diagnostic tests.
impl ProjectedReadSession {
    /// Runs the original AllRegular receipt with immutable options for its whole lifetime.
    #[allow(clippy::result_large_err)]
    pub fn run_with_context(
        &mut self,
        options: &Options,
        password: Option<&str>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut observe: impl ZipRunObserver,
    ) -> ZipReadResult<ZipRunReport> {
        let mut diagnostics = DiagnosticState::default();
        let mut completion = self.run_steps(options, password, cancel, context, &mut diagnostics, &mut observe)?;
        if !completion.observer_failed {
            let projected::ProjectedOwner { file, source, entries, .. } = &mut self.owner;
            let mut scope = ZipDiagnosticScope::from_parts(
                file,
                source,
                entries,
                options,
                context,
                &mut diagnostics,
                cancel,
                None,
            )?;
            let result = observe.observe(
                ZipRunEvent::RunEnded { report: &completion.report, error: completion.terminal.as_ref() },
                &mut scope,
            );
            let evidence = scope.finish(result);
            completion.merge(evidence);
        }
        completion.finish(context, &diagnostics)
    }
    #[allow(clippy::too_many_arguments)]
    fn run_steps(
        &mut self,
        options: &Options,
        password: Option<&str>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        diagnostics: &mut DiagnosticState,
        observe: &mut impl ZipRunObserver,
    ) -> ZipReadResult<Completion> {
        context.verify_identity(self.owner.identity)?;
        let action = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?;
        let expected = if options.mode == Mode::Extract {
            budget::PlannedOutput::StagedFiles
        } else {
            budget::PlannedOutput::Discard
        };
        if action.scope != ProjectedReadScope::AllRegular
            || action.output != expected
            || action.run_bound
            || action.consumed
            || action.password_bytes != password.map_or(0, str::len) as u64
            || action.destination.as_ref().is_some_and(|p| p.as_os_str() != options.dest.as_os_str())
        {
            return Err(ReadFault::InvalidPlan.into());
        }
        let records = self.owner.entries.len() as u128;
        context.ledger.with_state(|s| {
            s.bind_diagnostics(
                records,
                records,
                options.protected_paths.len() as u128,
                options.mode == Mode::Test && options.protected_paths.iter().any(|p| p.is_relative()),
            )
        })?;
        let mut report = ZipRunReport { volumes: 1, ..Default::default() };
        let mut terminal = self.bind_run(options, cancel, context).err();
        let mut observer_failed;
        {
            let mut scope = ZipDiagnosticScope::new(&mut self.owner, options, context, diagnostics, cancel, None)?;
            let result = observe.prepare(&mut scope);
            let evidence = scope.finish(result);
            observer_failed = evidence.observer_failed();
            if evidence.failed() {
                terminal = Some(evidence.merge(terminal.take().unwrap_or_else(|| ReadFault::InvalidPlan.into())));
            }
        }
        if terminal.is_none() {
            for ordinal in 0..self.owner.entries.len() {
                if cancel.is_canceled() {
                    terminal = Some(ReadFault::Cancelled.into());
                    break;
                }
                if self.owner.entries[ordinal].is_dir() {
                    if let Err(fault) = context.ledger.with_state(|s| s.charge_category(RunCategory::Records, 1)) {
                        terminal = Some(fault.into());
                        break;
                    }
                    if let Err(error) = self.directory(ordinal, options, cancel, context, false) {
                        terminal = Some(error);
                        break;
                    }
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    if let Some(index) = context.action.as_mut().and_then(|a| a.directories.as_mut()) {
                        let entry = &self.owner.entries[ordinal];
                        let depth = entry
                            .name
                            .split(|c| c == '/' || entry.host != 3 && c == '\\')
                            .filter(|part| !part.is_empty() && *part != ".")
                            .count();
                        index.push_bounded((ordinal, depth))?;
                    }
                    add(&mut report.dirs)?;
                    continue;
                }
                let (result, skipped, local_refusal) = self.member(ordinal, options, password, cancel, context);
                let bytes = self.owner.entries[ordinal].size;
                let mut fault = result.err().map(|error| {
                    let local = (continued(&error) || local_refusal)
                        && error.cleanup_errors().len() == 0
                        && error.source_change().is_none()
                        && error.sink_fault().is_none()
                        && error.diagnostic_fault().is_none()
                        && error.diagnostic_boundary_fault().is_none()
                        && !context.ledger.with_state(|s| s.poisoned);
                    error.with_member_local(local)
                });
                if fault.is_some() {
                    add(&mut report.failed)?;
                } else if skipped {
                    add(&mut report.skipped)?;
                } else {
                    add(&mut report.files)?;
                    report.decoded_bytes =
                        report.decoded_bytes.checked_add(bytes as u128).ok_or(ReadFault::CounterOverflow)?;
                }
                let evidence = self.member_event(
                    ordinal,
                    skipped,
                    bytes,
                    fault.as_ref(),
                    options,
                    cancel,
                    context,
                    diagnostics,
                    observe,
                )?;
                observer_failed = evidence.observer_failed();
                if evidence.failed() {
                    terminal = Some(evidence.merge(fault.take().unwrap_or_else(|| {
                        ZipReadError::from(ReadFault::InvalidPlan).with_publication(
                            if options.mode == Mode::Extract && !skipped {
                                PublicationState::Published
                            } else {
                                PublicationState::NotPublished
                            },
                            if skipped { 0 } else { bytes },
                        )
                    })));
                    break;
                }
                if let Some(error) = fault
                    && (!(continued(&error)
                        || local_refusal
                            && error.cleanup_errors().len() == 0
                            && error.source_change().is_none()
                            && error.diagnostic_boundary_fault().is_none())
                        || context.ledger.with_state(|s| s.poisoned))
                {
                    terminal = Some(error);
                    break;
                }
            }
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(mut index) = context.action.as_mut().and_then(|a| a.directories.take()) {
            if !cancel.is_canceled() && !context.ledger.with_state(|s| s.poisoned) {
                index.sort_unstable_by_key(|&(ordinal, depth)| (std::cmp::Reverse(depth), ordinal));
                #[cfg(test)]
                FINALIZATION_HOOK.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().as_mut() {
                        hook();
                    }
                });
                for &(ordinal, _) in index.iter() {
                    if cancel.is_canceled() {
                        if terminal.is_none() {
                            terminal = Some(ReadFault::Cancelled.into());
                        }
                        break;
                    }
                    if let Err(error) = self.directory(ordinal, options, cancel, context, true) {
                        terminal = Some(match terminal.take() {
                            Some(prior) => prior.merge_source_boundary(error),
                            None => error,
                        });
                        break;
                    }
                }
            }
            if let Err((_, fault)) = index.finish(&context.ledger) {
                terminal = Some(match terminal.take() {
                    Some(prior) => prior.merge_source_boundary(fault.into()),
                    None => fault.into(),
                });
            }
        }
        if let Some(action) = context.action.as_mut() {
            action.active_ordinal = None;
            action.active_record_charged = false;
        }
        if let Some(cwd) = diagnostics.cwd.take()
            && let Err((_, fault)) = cwd.finish(&context.ledger)
        {
            terminal = Some(match terminal.take() {
                Some(error) => error.merge_cleanup_only(
                    ZipReadError::from(fault).owned_boundary_error(OwnedObject::PolicyPath, ReadIoOperation::Stat),
                ),
                None => fault.into(),
            });
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(policy) = context.action.as_mut().and_then(|a| a.policy.take())
            && let Err(fault) = policy.finish(&context.ledger)
        {
            terminal = Some(match terminal.take() {
                Some(prior) => prior.merge_source_boundary(fault.into()),
                None => fault.into(),
            });
        }
        if let Err(boundary) = self.check_source(context) {
            terminal = Some(match terminal.take() {
                Some(error) => error.merge_source_boundary(boundary),
                None => boundary,
            });
        }
        if cancel.is_canceled() && terminal.is_none() {
            terminal = Some(ReadFault::Cancelled.into());
        }
        snapshot(&mut report, context, diagnostics);
        Ok(Completion { report, terminal, observer_failed })
    }
    fn run_owned(
        mut self,
        options: &Options,
        password: Option<&str>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        mut observe: impl ZipRunObserver,
    ) -> ZipReadResult<ZipRunReport> {
        let mut diagnostics = DiagnosticState::default();
        let mut completion = match self.run_steps(options, password, cancel, context, &mut diagnostics, &mut observe) {
            Ok(c) => c,
            Err(error) => return Err(self.owner.reject(error)),
        };
        #[cfg(test)]
        owned_hook(0, self.owner.source.as_ref().ok().map(|s| s.path.as_path()));
        let final_source = self.check_source(context);
        let source_valid = final_source.is_ok();
        if let Err(error) = final_source {
            completion.terminal = Some(match completion.terminal.take() {
                Some(prior) => prior.merge_source_boundary(error),
                None => error,
            });
        }
        if !context.ledger.with_state(|s| s.source_registered()) {
            return Err(self
                .owner
                .reject(completion.terminal.unwrap_or_else(|| ReadFault::InvalidPlan.into()))
                .with_partial(completion.report));
        }
        let close = retire_owned_source(self.owner.file, context, source_valid);
        let confirmed = close.is_none() && source_valid;
        if let Some(error) = close {
            completion.terminal = Some(match completion.terminal.take() {
                Some(prior) => prior.merge_cleanup_only(error),
                None => error,
            });
        }
        let mut retired = diagnostic::RetiredSource {
            binding: self.owner.source,
            owner: self.owner.identity,
            action: context.ledger.identity(),
            safe_only: !confirmed || completion.terminal.is_some(),
            confirmed_close: confirmed,
        };
        #[cfg(test)]
        owned_hook(1, retired.binding.as_ref().ok().map(|s| s.path.as_path()));
        snapshot(&mut completion.report, context, &diagnostics);
        if !completion.observer_failed {
            let mut scope = ZipDiagnosticScope::retired(
                &mut retired,
                &self.owner.entries,
                options,
                context,
                &mut diagnostics,
                cancel,
            )?;
            let result = observe.observe(
                ZipRunEvent::RunEnded { report: &completion.report, error: completion.terminal.as_ref() },
                &mut scope,
            );
            completion.merge(scope.finish(result));
        }
        completion.finish(context, &diagnostics)
    }
    fn bind_run(
        &mut self,
        options: &Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> ZipReadResult<()> {
        context.ledger.with_state(|s| s.register_controlled_source())?;
        self.check_source(context)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if options.mode == Mode::Extract {
            let binding = self.owner.source.as_ref().map_err(|_| ReadFault::InvalidPlan)?;
            let ceiling = context.action.as_ref().ok_or(ReadFault::InvalidPlan)?.attempt_ceiling;
            let policy = policy::FrozenPolicy::bind(
                &context.ledger,
                options,
                &binding.path,
                &self.owner.file,
                binding.stamp,
                ceiling,
                cancel,
            )?;
            context.options.limits.io_attempts = context.ledger.with_state(|s| s.encrypted.limits.io_attempts);
            context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.policy = Some(policy);
        }
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if options.mode == Mode::Extract && !options.flatten {
            let count = self.owner.entries.iter().filter(|e| e.is_dir()).count();
            if count != 0 {
                context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.directories = Some(
                    policy::MetadataLease::new(context.ledger.view(), budget::PolicyComponent::Caller, count)?
                        .into_owned(),
                );
            }
        }
        context.action.as_mut().ok_or(ReadFault::InvalidPlan)?.run_bound = true;
        Ok(())
    }
    fn member(
        &mut self,
        ordinal: usize,
        options: &Options,
        password: Option<&str>,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
    ) -> (ZipReadResult<()>, bool, bool) {
        context.ledger.with_state(|s| s.active_encrypted = Some(self.owner.entries[ordinal].encrypted()));
        let Some(action) = context.action.as_mut() else { return (Err(ReadFault::InvalidPlan.into()), false, false) };
        action.active_ordinal = Some(ordinal);
        action.consumed = false;
        action.completed = false;
        action.controlled_output = false;
        action.raw_output = false;
        action.output_descriptor = None;
        action.active_record_charged = false;
        if let Err(fault) = context.ledger.with_state(|s| s.charge_category(RunCategory::Records, 1)) {
            return (Err(fault.into()), false, false);
        }
        action.active_record_charged = true;
        let max = action.caller_max.unwrap_or(u64::MAX);
        let e = &self.owner.entries[ordinal];
        if e.is_link() {
            return (Err(ReadFault::CheckedFormat { reason: "links are not supported yet" }.into()), false, true);
        }
        let relative = match policy::PolicyPath::normalized(&context.ledger, &e.name, e.host != 3, cancel) {
            Ok(path) => path,
            Err(policy::PathFailure::Unsafe) => {
                return (Err(ReadFault::CheckedFormat { reason: "invalid ZIP target name" }.into()), false, true);
            }
            Err(policy::PathFailure::Fault(f)) => return (Err(f.into()), false, false),
        };
        let mut local_refusal = false;
        let mut result = (|| -> ZipReadResult<bool> {
            let e = &self.owner.entries[ordinal];
            if options.mode == Mode::Test
                || e.encrypted() && password.is_none_or(str::is_empty)
                || !crate::zip::supported(e.effective_method())
                || e.encrypted()
                    && (e.packed > context.options.limits.member_packed_bytes
                        || e.size > context.options.limits.member_decoded_bytes)
            {
                return self.read_at_with_context(ordinal, password, max, cancel, context, |_| Ok(())).map(|()| false);
            }
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                let mode = e.unix_mode();
                let mtime = e.mtime.map(|s| (s, e.nanos));
                let (stage, blocked) = ZipReadStage::prepare_run_file(
                    self.stage_entry(ordinal)?,
                    relative.path(),
                    options,
                    cancel,
                    context,
                )?;
                if let Some(fault) = blocked {
                    local_refusal = true;
                    return Err(fault.into());
                }
                let Some(mut stage) = stage else {
                    return Ok(true);
                };
                if let Err(error) =
                    self.read_at_with_context(ordinal, password, max, cancel, context, |b| stage.write_all(b, cancel))
                {
                    return Err(if continued(&error) {
                        stage.finish_member_error(error, context, cancel, |cx| self.check_source(cx))
                    } else {
                        stage.finish_error(error, context)
                    });
                }
                stage.publish(mode, mtime, cancel, context, |cx| self.check_source(cx)).map(|published| !published)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            Err(ReadFault::UnsupportedIdentity.into())
        })();
        if let Err(fault) = relative.finish(&context.ledger) {
            result = Err(match result {
                Err(error) => error.merge_source_boundary(fault.into()),
                Ok(_) => fault.into(),
            });
        }
        match result {
            Ok(skipped) => (Ok(()), skipped, false),
            Err(error) => (
                Err(error
                    .with_usage(context.usage(), context.run_usage())
                    .with_policy_usage(context.policy_metadata_usage())),
                false,
                local_refusal,
            ),
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn directory(
        &mut self,
        ordinal: usize,
        options: &Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        finalizing: bool,
    ) -> ZipReadResult<()> {
        if options.mode != Mode::Extract || options.flatten {
            return Ok(());
        }
        self.check_source(context)?;
        let entry = &self.owner.entries[ordinal];
        let relative = policy::PolicyPath::normalized(&context.ledger, &entry.name, entry.host != 3, cancel).map_err(
            |failure| match failure {
                policy::PathFailure::Unsafe => ReadFault::CheckedFormat { reason: "invalid ZIP directory name" },
                policy::PathFailure::Fault(f) => f,
            },
        )?;
        let mut result = self.directory_path(ordinal, relative.path(), options, cancel, context, finalizing);
        if let Err(fault) = relative.finish(&context.ledger) {
            result = Err(match result {
                Err(error) => error.merge_source_boundary(fault.into()),
                Ok(()) => fault.into(),
            });
        }
        let boundary = self.check_source(context);
        match (result, boundary) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) => Err(e),
            (Ok(()), Err(e)) => Err(e),
            (Err(e), Err(b)) => Err(e.merge_source_boundary(b)),
        }
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn directory_path(
        &self,
        ordinal: usize,
        relative: &Path,
        options: &Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        finalizing: bool,
    ) -> ZipReadResult<()> {
        use std::os::fd::{FromRawFd, IntoRawFd};
        if !finalizing {
            let dummy =
                policy::PolicyPath::joined(&context.ledger, relative, Path::new(".zipfast-directory-observation"))?;
            context.ledger.with_state(|s| s.acquire_fds(1))?;
            let cwd = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?.cwd();
            let result = output::parent::open_parent(&context.ledger, &options.dest, dummy.path(), cwd, cancel)
                .and_then(|parent| parent.finish_in(&context.ledger, true, false, RunCategory::DirectoryFinalization));
            let released = dummy.finish(&context.ledger).map_err(ZipReadError::from);
            return match (result, released) {
                (Err(e), _) => Err(e),
                (Ok(()), r) => r,
            };
        }
        #[cfg(test)]
        {
            let mut hook = DIRECTORY_HOOK.with(|s| s.borrow_mut().take());
            if let Some(hook) = &mut hook {
                hook(ordinal);
            }
            DIRECTORY_HOOK.with(|s| *s.borrow_mut() = hook);
        }
        let cwd = context.action.as_ref().and_then(|a| a.policy.as_ref()).ok_or(ReadFault::InvalidPlan)?.cwd();
        let target = policy::PolicyPath::joined_frozen(&context.ledger, &options.dest, relative, cwd)?;
        let result = (|| -> ZipReadResult<()> {
            let path = target.cstr()?;
            let real = io::operation(
                &context.ledger,
                false,
                RunCategory::DirectoryFinalization,
                IoStage::Output,
                ReadIoOperation::Stat,
                Some(cancel),
                || {
                    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                    native_policy::cvt(unsafe { libc::lstat(path.as_ptr(), stat.as_mut_ptr()) })?;
                    Ok(unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR)
                },
            );
            match real {
                Ok(true) => {}
                Ok(false) | Err(ReadFault::Io { .. }) => return Ok(()),
                Err(f) => return Err(f.into()),
            }
            let op = |kind, call: &mut dyn FnMut() -> std::io::Result<i32>| {
                io::operation(
                    &context.ledger,
                    false,
                    RunCategory::DirectoryFinalization,
                    IoStage::Output,
                    kind,
                    Some(cancel),
                    call,
                )
            };
            let entry = &self.owner.entries[ordinal];
            context.ledger.with_state(|s| s.acquire_fds(1))?;
            let opened = op(ReadIoOperation::Open, &mut || {
                native_policy::cvt(unsafe {
                    libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                })
            });
            let file = match opened {
                Ok(fd) => Some(unsafe { File::from_raw_fd(fd) }),
                Err(ReadFault::Io { .. }) => {
                    context.ledger.with_state(|s| s.retire_fd(true));
                    None
                }
                Err(f) => {
                    context.ledger.with_state(|s| s.retire_fd(true));
                    return Err(f.into());
                }
            };
            let body = (|| -> ZipReadResult<()> {
                if let Some(file) = &file
                    && let Some(at) = entry.mtime.and_then(|s| {
                        crate::extract::archive_time(s, entry.nanos)
                            .map(|_| libc::timespec { tv_sec: s as libc::time_t, tv_nsec: entry.nanos as libc::c_long })
                    })
                {
                    use std::os::fd::AsRawFd;
                    let times = [at, at];
                    match op(ReadIoOperation::SetTime, &mut || {
                        native_policy::cvt(unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) })
                    }) {
                        Ok(_) | Err(ReadFault::Io { .. }) => {}
                        Err(f) => return Err(f.into()),
                    }
                }
                if let Some(mode) = entry.unix_mode().map(|m| m & 0o777) {
                    match op(ReadIoOperation::DescriptorMode, &mut || {
                        native_policy::cvt(unsafe { libc::chmod(path.as_ptr(), mode as libc::mode_t) })
                    }) {
                        Ok(_) | Err(ReadFault::Io { .. }) => {}
                        Err(f) => return Err(f.into()),
                    }
                }
                Ok(())
            })();
            let Some(file) = file else { return body };
            let fd = file.into_raw_fd();
            let retired = io::retire_in(
                &context.ledger,
                false,
                OwnedObject::OutputParent,
                Some(RunCategory::DirectoryFinalization),
                body.is_ok(),
                || native_policy::cvt(unsafe { libc::close(fd) }).map(|_| ()),
            );
            let mut error = body.err().or_else(|| retired.admission.map(ZipReadError::from));
            if let Some(fault) = retired.fault {
                let mut cleanup = ObjectCleanupReport::new(OwnedObject::OutputParent);
                cleanup.push(fault);
                error = Some(match error {
                    Some(e) => e.merge_cleanup(cleanup),
                    None => cleanup.into(),
                });
            }
            error.map_or(Ok(()), Err)
        })();
        let release = target.finish(&context.ledger).map_err(ZipReadError::from);
        match (result, release) {
            (Err(e), _) => Err(e),
            (Ok(()), r) => r,
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn directory(
        &mut self,
        _ordinal: usize,
        _options: &Options,
        _cancel: &Cancellation,
        _context: &mut EncryptedReadContext,
        _finalizing: bool,
    ) -> ZipReadResult<()> {
        Err(ReadFault::UnsupportedIdentity.into())
    }
    #[allow(clippy::too_many_arguments)]
    fn member_event(
        &mut self,
        ordinal: usize,
        skipped: bool,
        bytes: u64,
        error: Option<&ZipReadError>,
        options: &Options,
        cancel: &Cancellation,
        context: &mut EncryptedReadContext,
        state: &mut DiagnosticState,
        observe: &mut impl ZipRunObserver,
    ) -> ZipReadResult<Evidence> {
        let projected::ProjectedOwner { file, source, entries, .. } = &mut self.owner;
        let event = match error {
            Some(error) => ZipRunEvent::MemberFailed { ordinal: ordinal as u64, name: &entries[ordinal].name, error },
            None if skipped => ZipRunEvent::MemberSkipped { ordinal: ordinal as u64, name: &entries[ordinal].name },
            None => ZipRunEvent::MemberSucceeded {
                ordinal: ordinal as u64,
                name: &entries[ordinal].name,
                decoded_bytes: bytes,
            },
        };
        let mut scope =
            ZipDiagnosticScope::from_parts(file, source, entries, options, context, state, cancel, Some(ordinal))?;
        let result = observe.observe(event, &mut scope);
        Ok(scope.finish(result))
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn with_opened_policy(
    mut session: ProjectedReadSession,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    overrides: &EncryptedReadOverrides,
    observe: impl ZipRunObserver,
) -> ZipReadResult<ZipRunReport> {
    let output = if options.mode == Mode::Extract {
        ZipReadOutput::StagedFiles { destination: &options.dest }
    } else {
        ZipReadOutput::Discard
    };
    let mut context = match EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::AllRegular,
        None,
        output,
        password,
        overrides,
        cancel,
    ) {
        Ok(c) => c,
        Err(error) => return Err(session.owner.reject(error)),
    };
    session.run_owned(options, password, cancel, &mut context, observe)
}
#[allow(clippy::result_large_err)]
pub(crate) fn with_opened_context(
    mut session: ProjectedReadSession,
    options: &Options,
    password: Option<&str>,
    cancel: &Cancellation,
    context: &mut EncryptedReadContext,
    observe: impl ZipRunObserver,
) -> ZipReadResult<ZipRunReport> {
    let binding_result = (|| -> ZipReadResult<()> {
        if !context.has_action_plan() {
            let owner = &mut session.owner;
            let binding = owner.source.as_mut().map_err(|_| ReadFault::InvalidPlan)?;
            binding
                .verify_with(&owner.file, |stage, call| context.bootstrap.stat(stage, call))
                .map_err(ZipReadError::from)?;
            let output = if options.mode == Mode::Extract {
                ZipReadOutput::StagedFiles { destination: &options.dest }
            } else {
                ZipReadOutput::Discard
            };
            let result = projected::factory(
                context,
                false,
                owner.entries.iter().map(|e| (e.read_description(), e.is_dir(), e.is_link())),
                owner.identity,
                binding.stamp,
                binding.path.as_os_str().len(),
                ProjectedReadScope::AllRegular,
                None,
                output,
                password,
                &Default::default(),
                cancel,
            );
            let boundary = binding
                .verify_with(&owner.file, |stage, call| context.bootstrap.stat(stage, call))
                .map_err(ZipReadError::from);
            match (result, boundary) {
                (Ok(()), Ok(())) => {}
                (Err(e), Ok(())) => return Err(e),
                (Ok(()), Err(e)) => return Err(e),
                (Err(e), Err(b)) => return Err(e.merge_source_boundary(b)),
            }
        }
        Ok(())
    })();
    if let Err(error) = binding_result {
        return Err(session.owner.reject(error));
    }
    session.run_owned(options, password, cancel, context, observe)
}
