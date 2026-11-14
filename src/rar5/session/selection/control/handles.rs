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

use super::*;
use std::os::fd::{FromRawFd, IntoRawFd};

impl RarExtractControl {
    fn close_usage(&mut self, kind: RarControlHandleKind) -> (&mut RarCloseUsage, &mut u64) {
        match kind {
            RarControlHandleKind::Guard => (&mut self.usage.teardown.guards, &mut self.usage.diagnostics.open_handles),
            RarControlHandleKind::DecisionParent => {
                (&mut self.usage.teardown.decision_parents, &mut self.usage.decision_parent_handles)
            }
        }
    }
    pub(super) fn handle_admission(&self, kind: RarControlHandleKind) -> Result<(), RarExtractControlError> {
        if self.usage.teardown.accounting_poisoned {
            return Err(RarExtractControlError::CounterOverflow);
        }
        let (pool, owned, allowed) = match kind {
            RarControlHandleKind::Guard => {
                (self.usage.teardown.guards, self.usage.diagnostics.open_handles, self.limits.diagnostics.open_handles)
            }
            RarControlHandleKind::DecisionParent => {
                (self.usage.teardown.decision_parents, self.usage.decision_parent_handles, 1)
            }
        };
        let closed =
            pool.confirmed_closed.checked_add(pool.uncertain).ok_or(RarExtractControlError::CounterOverflow)?;
        if closed != pool.close_attempts || closed.checked_add(owned) != Some(pool.successful_acquires) {
            return Err(RarExtractControlError::CounterOverflow);
        }
        let requested = owned
            .checked_add(pool.uncertain)
            .and_then(|n| n.checked_add(1))
            .ok_or(RarExtractControlError::CounterOverflow)?;
        pool.successful_acquires.checked_add(1).ok_or(RarExtractControlError::CounterOverflow)?;
        // Partition reserves exactly one future close ticket per acquisition.
        if pool.close_attempts.checked_add(owned).and_then(|n| n.checked_add(1)).is_none() {
            return Err(RarExtractControlError::CounterOverflow);
        }
        if requested > allowed {
            return Err(RarExtractControlError::Limit {
                resource: RarResource::ExtractControlHandles,
                requested,
                allowed,
            });
        }
        Ok(())
    }
    pub(super) fn acquired(&mut self, kind: RarControlHandleKind) {
        let (pool, owned) = self.close_usage(kind);
        if let (Some(acquires), Some(handles)) = (pool.successful_acquires.checked_add(1), owned.checked_add(1)) {
            pool.successful_acquires = acquires;
            *owned = handles;
        } else {
            self.usage.teardown.accounting_poisoned = true;
            self.teardown_failure.get_or_insert(RarTeardownFailure::AccountingOverflow);
            return;
        }

        match kind {
            RarControlHandleKind::Guard => {
                self.usage.diagnostics.open_handles_peak =
                    self.usage.diagnostics.open_handles_peak.max(self.usage.diagnostics.open_handles)
            }
            RarControlHandleKind::DecisionParent => {
                self.usage.decision_parent_handles_peak =
                    self.usage.decision_parent_handles_peak.max(self.usage.decision_parent_handles)
            }
        }
    }
    fn close(&mut self, file: File, kind: RarControlHandleKind) {
        // Consume unique ownership before the one direct call. Never retain the number.
        let result = close_once(file);
        let (pool, owned) = self.close_usage(kind);
        let update = (|| {
            let closed = pool.confirmed_closed.checked_add(pool.uncertain)?;
            if closed != pool.close_attempts || closed.checked_add(*owned) != Some(pool.successful_acquires) {
                return None;
            }
            let remaining = owned.checked_sub(1)?;
            let attempts = pool.close_attempts.checked_add(1)?;
            let result_count =
                if result.is_ok() { pool.confirmed_closed.checked_add(1)? } else { pool.uncertain.checked_add(1)? };
            *owned = remaining;
            pool.close_attempts = attempts;
            if result.is_ok() {
                pool.confirmed_closed = result_count;
            } else {
                pool.uncertain = result_count;
            }
            Some(())
        })();
        if update.is_none() {
            self.usage.teardown.accounting_poisoned = true;
            self.teardown_failure.get_or_insert(RarTeardownFailure::AccountingOverflow);
        }
        if let Err(raw_os_error) = result {
            self.teardown_failure.get_or_insert(RarTeardownFailure::Close { kind, raw_os_error });
        }
    }
    pub(super) fn close_parent(&mut self) {
        if let Some(file) = self.decision_parent.take() {
            self.close(file, RarControlHandleKind::DecisionParent);
        }
    }
    pub(super) fn release_guard(&mut self) {
        let mut guard = std::mem::take(&mut self.guard);
        if let Some(file) = guard.anchor.take() {
            self.close(file, RarControlHandleKind::Guard);
        }
        drop(guard);
        self.usage.diagnostics.capacity = 0;
        self.usage.diagnostics.targets = 0;
        self.usage.diagnostics.parents = 0;
        if (self.usage.teardown.guards.uncertain != 0 || self.usage.teardown.accounting_poisoned)
            && self.failure.is_none()
        {
            self.state = RarDiagnosticState::Muted(RarDiagnosticFailureKind::TeardownUncertain);
            self.failure = Some(RarDiagnosticFailure::TeardownUncertain);
        }
    }
}
fn close_once(file: File) -> Result<(), i32> {
    let raw = file.into_raw_fd();
    // libc 0.2.191 selects the platform close symbol. Read errno immediately.
    let result = unsafe { libc::close(raw) };
    let error = if result == 0 { None } else { Some(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)) };
    #[cfg(test)]
    let error = CLOSE_ERROR.with(|slot| slot.take()).or(error);
    error.map_or(Ok(()), Err)
}
pub(super) fn open_search(path: &[u8]) -> io::Result<File> {
    debug_assert_eq!(path.last(), Some(&0));
    #[cfg(test)]
    if let Some(errno) = OPEN_ERROR.with(|slot| slot.take()) {
        return Err(io::Error::from_raw_os_error(errno));
    }
    from_open(unsafe { libc::open(path.as_ptr().cast(), super::guard::search_flags()) })
}
#[cfg(test)]
thread_local! {pub(super) static OPEN_ERROR:std::cell::Cell<Option<i32>>=const{std::cell::Cell::new(None)};}
pub(super) fn from_open(raw: libc::c_int) -> io::Result<File> {
    if raw < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { File::from_raw_fd(raw) }) }
}
#[cfg(test)]
thread_local! {pub(super) static CLOSE_ERROR:std::cell::Cell<Option<i32>>=const{std::cell::Cell::new(None)};}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_close_never_retries_or_resets() {
        for errno in [libc::EINTR, libc::EIO, libc::EBADF] {
            let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
            c.handle_admission(RarControlHandleKind::DecisionParent).unwrap();
            c.decision_parent = Some(File::open(".").unwrap());
            c.acquired(RarControlHandleKind::DecisionParent);
            CLOSE_ERROR.with(|slot| slot.set(Some(errno)));
            c.close_parent();
            assert_eq!(c.usage.decision_parent_handles, 0);
            assert_eq!(c.usage.teardown.decision_parents.uncertain, 1);
            assert!(matches!(
                c.handle_admission(RarControlHandleKind::DecisionParent),
                Err(RarExtractControlError::Limit { requested: 2, allowed: 1, .. })
            ));
            for _ in 0..2 {
                assert!(c.reset().is_err());
                assert_eq!(c.teardown().usage.decision_parents.close_attempts, 1);
            }
            assert!(
                matches!(c.into_diagnostic().aftermath.teardown.first_failure,Some(RarTeardownFailure::Close{raw_os_error,..}) if raw_os_error==errno)
            );
        }
    }
    #[test]
    fn guard_close_failure_does_not_replace_alias_or_poison_native_pool() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.guard.anchor = Some(File::open(".").unwrap());
        c.acquired(RarControlHandleKind::Guard);
        CLOSE_ERROR.with(|s| s.set(Some(libc::EIO)));
        c.mute(RarDiagnosticFailure::AliasTarget { ordinal: 7 });
        assert!(matches!(c.diagnostic_failure(), Some(RarDiagnosticFailure::AliasTarget { ordinal: 7 })));
        assert_eq!(c.teardown().usage.guards.uncertain, 1);
        assert!(c.handle_admission(RarControlHandleKind::DecisionParent).is_ok());
    }
    #[test]
    fn confirmed_close_releases_slot_and_overflow_refuses_acquire() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.decision_parent = Some(File::open(".").unwrap());
        c.acquired(RarControlHandleKind::DecisionParent);
        c.close_parent();
        assert_eq!(c.teardown().usage.decision_parents.confirmed_closed, 1);
        assert!(c.reset().is_ok());
        c.usage.teardown.decision_parents.successful_acquires = u64::MAX;
        assert!(matches!(
            c.handle_admission(RarControlHandleKind::DecisionParent),
            Err(RarExtractControlError::CounterOverflow)
        ));
    }
}

#[cfg(test)]
mod fault_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    #[test]
    fn fd_reuse_after_uncertain_close_is_never_touched_again() {
        // Descriptor numbers are process-wide. A dedicated process prevents
        // reuse from colliding with another parallel test's File ownership.
        if std::env::var_os("ZIPFAST_CLOSE_REUSE_CHILD").is_none() {
            let status=std::process::Command::new(std::env::current_exe().unwrap()).args(["rar5::session::selection::control::handles::fault_tests::fd_reuse_after_uncertain_close_is_never_touched_again","--exact"]).env("ZIPFAST_CLOSE_REUSE_CHILD","1").status().unwrap();
            assert!(status.success());
            return;
        }

        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.handle_admission(RarControlHandleKind::DecisionParent).unwrap();
        let file = File::open(".").unwrap();
        let old = file.as_raw_fd();
        c.decision_parent = Some(file);
        c.acquired(RarControlHandleKind::DecisionParent);
        CLOSE_ERROR.with(|s| s.set(Some(libc::EINTR)));
        c.close_parent();
        // The injected error is after a real successful close. Install a foreign
        // descriptor at that number, exactly the case a retry must not damage.
        let source = File::open(".").unwrap();
        assert_eq!(source.as_raw_fd(), old);
        assert!(c.reset().is_err());
        assert!(c.reset().is_err());
        let recovery = c.into_diagnostic();
        assert_eq!(recovery.aftermath.teardown.usage.decision_parents.close_attempts, 1);
        assert_ne!(unsafe { libc::fcntl(old, libc::F_GETFD) }, -1);
        drop(source);
    }
    #[test]
    fn poisoned_cleanup_closes_once_without_overflow_or_new_admission() {
        let mut c = RarExtractControl::new(None, RarOverwriteMode::Ask, RarExtractControlLimits::default());
        c.decision_parent = Some(File::open(".").unwrap());
        c.acquired(RarControlHandleKind::DecisionParent);
        c.usage.teardown.decision_parents.close_attempts = u64::MAX;
        c.close_parent();
        assert!(c.teardown().usage.accounting_poisoned);
        assert_eq!(c.teardown().first_failure, Some(RarTeardownFailure::AccountingOverflow));
        assert!(c.reset().is_err());
        assert!(c.handle_admission(RarControlHandleKind::Guard).is_err());
    }
}
