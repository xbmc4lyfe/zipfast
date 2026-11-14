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

//! Once-created exact caller policy and native namespace indexes.
use super::*;
use crate::extract::{Mode, Options, Overwrite};
use crate::zip::read::shared::{LedgerAccess, LedgerView};
use crate::zip::session::SourceStamp;
use std::os::unix::ffi::OsStrExt;

#[derive(Clone, Copy)]
struct Config {
    mode: Mode,
    overwrite: Overwrite,
    flatten: bool,
    threads: Option<usize>,
    parallel_min: Option<u64>,
}
impl Config {
    fn of(o: &Options) -> Self {
        Self {
            mode: o.mode,
            overwrite: o.overwrite,
            flatten: o.flatten,
            threads: o.threads,
            parallel_min: o.parallel_min,
        }
    }
    fn matches(self, o: &Options) -> bool {
        self.mode == o.mode
            && self.overwrite == o.overwrite
            && self.flatten == o.flatten
            && self.threads == o.threads
            && self.parallel_min == o.parallel_min
    }
}
#[derive(Clone, Copy)]
struct Key {
    offset: usize,
    len: usize,
}
struct CanonicalKey {
    bytes: OwnedMetadata<u8>,
    identity: CanonicalIdentity,
}
fn path(bytes: &[u8]) -> &Path {
    Path::new(std::ffi::OsStr::from_bytes(bytes))
}
fn key<'a>(bytes: &'a [u8], key: &Key) -> &'a Path {
    path(&bytes[key.offset..key.offset + key.len])
}
fn identity_key(id: CanonicalIdentity) -> (u64, u64, u32) {
    (id.dev, id.ino, id.kind)
}

pub(in crate::zip::read) struct FrozenPolicy {
    raw: OwnedMetadata<u8>,
    entries: OwnedMetadata<Key>,
    canonical: OwnedMetadata<CanonicalKey>,
    identities: OwnedMetadata<CanonicalIdentity>,
    cwd: OwnedMetadata<u8>,
    config: Config,
    pub(in crate::zip::read) uid: u32,
}
struct Builder<'a> {
    ledger: LedgerView<'a>,
    raw: Option<MetadataLease<'a, u8>>,
    entries: Option<MetadataLease<'a, Key>>,
    canonical: Option<MetadataLease<'a, CanonicalKey>>,
    identities: Option<MetadataLease<'a, CanonicalIdentity>>,
    cwd: Option<MetadataLease<'a, u8>>,
}
impl Drop for Builder<'_> {
    fn drop(&mut self) {
        if let Some(canonical) = self.canonical.as_mut() {
            while let Some(item) = canonical.pop() {
                let result = item.bytes.finish(&self.ledger);
                debug_assert!(result.is_ok(), "same-owner canonical policy capacity");
            }
        }
    }
}
impl<'a> Builder<'a> {
    fn finish(mut self, config: Config, uid: u32) -> FrozenPolicy {
        FrozenPolicy {
            raw: self.raw.take().unwrap().into_owned(),
            entries: self.entries.take().unwrap().into_owned(),
            canonical: self.canonical.take().unwrap().into_owned(),
            identities: self.identities.take().unwrap().into_owned(),
            cwd: self.cwd.take().unwrap().into_owned(),
            config,
            uid,
        }
    }
}
#[allow(clippy::result_large_err)] // Fixed inline source/cleanup evidence, including allocation refusal.
fn cwd<'a>(
    ledger: LedgerView<'a>,
    scratch: &mut PolicyScratch<'a>,
    cancel: &Cancellation,
) -> ZipReadResult<MetadataLease<'a, u8>> {
    super::cwd::capture(ledger, scratch, cancel, &mut || Ok(())).map_err(super::cwd::CwdFailure::into_stage_error)
}
#[allow(clippy::result_large_err)] // Linux metadata FD failures retain fixed inline cleanup evidence.
fn canonical_key(
    ledger: LedgerView<'_>,
    name: &Path,
    cwd: &Path,
    scratch: &mut PolicyScratch<'_>,
    retries: u64,
    cancel: &Cancellation,
    held: Option<&File>,
) -> Result<CanonicalKey, CanonicalFailure> {
    let mut charge = |_, first| {
        ledger.with_state(|s| {
            if first {
                s.charge_category(RunCategory::CanonicalMetadataOperations, 1)?;
            }
            s.attempt(false)
        })
    };
    #[cfg(target_os = "macos")]
    let result = {
        let _ = held;
        canonicalize(name, cwd, scratch, retries, cancel, &mut charge)
    }?;
    #[cfg(target_os = "linux")]
    let result =
        canonicalize(&ledger, CanonicalRequest { input: name, cwd, held }, scratch, retries, cancel, &mut charge)?;
    let bytes = result.bytes(scratch);
    let mut copy =
        MetadataLease::zeroed(ledger, PolicyComponent::Caller, bytes.len()).map_err(CanonicalFailure::Terminal)?;
    copy.copy_from_slice(bytes);
    Ok(CanonicalKey { bytes: copy.into_owned(), identity: result.identity })
}
#[allow(clippy::result_large_err)] // No allocation while assembling terminal policy/source evidence.
impl FrozenPolicy {
    pub(in crate::zip::read) fn bind(
        ledger: &impl LedgerAccess,
        o: &Options,
        source: &Path,
        source_file: &File,
        stamp: SourceStamp,
        ceiling: u128,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let config = Config::of(o); // Copy scalar policy before any acquisition.
        if config.mode != Mode::Extract {
            return Err(ReadFault::InvalidPlan.into());
        }
        ledger.with_state(|s| s.verify_source(stamp))?;
        let p = o.protected_paths.len();
        let mut raw_bytes = 0usize;
        let mut relative = 0usize;
        for item in &o.protected_paths {
            io::canceled(Some(cancel))?;
            raw_bytes = raw_bytes.checked_add(item.as_os_str().as_bytes().len()).ok_or(ReadFault::CounterOverflow)?;
            relative = relative.checked_add(usize::from(item.is_relative())).ok_or(ReadFault::CounterOverflow)?;
        }
        let packed = raw_bytes.checked_add(p).ok_or(ReadFault::CounterOverflow)?;
        let count = p.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let view = ledger.view();
        let mut b = Builder {
            ledger: view,
            raw: Some(MetadataLease::zeroed(view, PolicyComponent::Caller, packed)?),
            entries: Some(MetadataLease::new(view, PolicyComponent::Caller, p)?),
            canonical: Some(MetadataLease::new(view, PolicyComponent::Caller, count)?),
            identities: Some(MetadataLease::new(view, PolicyComponent::Caller, count)?),
            cwd: None,
        };
        let mut at = 0usize;
        for item in &o.protected_paths {
            let bytes = item.as_os_str().as_bytes();
            let end = at.checked_add(bytes.len()).ok_or(ReadFault::CounterOverflow)?;
            b.raw.as_mut().unwrap()[at..end].copy_from_slice(bytes);
            b.entries.as_mut().unwrap().push(Key { offset: at, len: bytes.len() })?;
            at = end + 1;
        }
        let raw = b.raw.as_ref().unwrap();
        b.entries.as_mut().unwrap().sort_unstable_by(|a, b| key(raw, a).cmp(key(raw, b)));
        let mut scratch = PolicyScratch::new(view)?;
        let needs_cwd = o.dest.is_relative() || relative != 0;
        b.cwd = Some(if needs_cwd {
            cwd(view, &mut scratch, cancel)?
        } else {
            MetadataLease::zeroed(view, PolicyComponent::Caller, 0)?
        });
        let frozen_cwd = b.cwd.as_ref().unwrap();
        let w = if frozen_cwd.is_empty() { 0 } else { frozen_cwd.len() - 1 };
        let absolute = (packed as u128)
            .checked_add((relative as u128).checked_mul((w as u128) + 1).ok_or(ReadFault::CounterOverflow)?)
            .ok_or(ReadFault::CounterOverflow)?;
        let bound = ledger.with_state(|s| {
            s.bind_policy_geometry(budget::PolicyGeometry {
                protected: p as u128,
                raw_bytes: raw_bytes as u128,
                absolute_bytes: absolute,
                cwd_bytes: w as u128,
                relative: needs_cwd,
            })
        })?;
        ledger.with_state(|s| s.encrypted.limits.io_attempts = bound.min(ceiling));
        ledger.with_state(|s| s.charge_category(RunCategory::PathSteps, 1))?;
        let uid =
            io::attempted_operation(ledger, false, IoStage::SourcePath, ReadIoOperation::Stat, Some(cancel), || {
                Ok(unsafe { libc::geteuid() })
            })?;
        let frozen_cwd = if w == 0 { Path::new("/") } else { path(&frozen_cwd[..w]) };
        let retries = ledger.with_state(|s| s.creation_policy(false).map(|p| p.1))?;
        let source_key = canonical_key(view, source, frozen_cwd, &mut scratch, retries, cancel, Some(source_file))
            .map_err(CanonicalFailure::into_error)?;
        if source_key.identity.dev != stamp.dev || source_key.identity.ino != stamp.ino {
            source_key.bytes.finish(ledger).map_err(|(_, f)| f)?;
            return Err(ReadFault::CheckedFormat { reason: "canonical source differs from original held ZIP" }.into());
        }
        b.identities.as_mut().unwrap().push(source_key.identity)?;
        b.canonical.as_mut().unwrap().push(source_key)?;
        for entry in b.entries.as_ref().unwrap().iter() {
            let name = key(b.raw.as_ref().unwrap(), entry);
            match canonical_key(view, name, frozen_cwd, &mut scratch, retries, cancel, None) {
                Ok(found) => {
                    b.identities.as_mut().unwrap().push(found.identity)?;
                    b.canonical.as_mut().unwrap().push(found)?;
                }
                Err(CanonicalFailure::Ordinary(_)) => {}
                Err(CanonicalFailure::Terminal(f)) => return Err(f.into()),
                #[cfg(target_os = "linux")]
                Err(CanonicalFailure::Cleanup(error)) => return Err(error),
            }
        }
        b.canonical.as_mut().unwrap().sort_unstable_by(|a, b| path(&a.bytes).cmp(path(&b.bytes)));
        b.identities.as_mut().unwrap().sort_unstable_by_key(|id| identity_key(*id));
        drop(scratch);
        Ok(b.finish(config, uid))
    }
    pub(in crate::zip::read) fn matches(&self, o: &Options, destination: &Path) -> bool {
        self.config.matches(o)
            && o.dest.as_os_str() == destination.as_os_str()
            && o.protected_paths.len() == self.entries.len()
            && o.protected_paths.iter().all(|p| {
                self.entries.binary_search_by(|k| key(&self.raw, k).cmp(p)).is_ok_and(|i| {
                    self.raw[self.entries[i].offset..self.entries[i].offset + self.entries[i].len]
                        == *p.as_os_str().as_bytes()
                })
            })
    }
    pub(in crate::zip::read) fn protects(&self, name: &Path, id: CanonicalIdentity) -> bool {
        self.entries.binary_search_by(|k| key(&self.raw, k).cmp(name)).is_ok()
            || self.canonical.binary_search_by(|k| path(&k.bytes).cmp(name)).is_ok()
            || self.identities.binary_search_by_key(&identity_key(id), |id| identity_key(*id)).is_ok()
    }
    pub(in crate::zip::read) fn cwd(&self) -> &Path {
        if self.cwd.is_empty() { Path::new("/") } else { path(&self.cwd[..self.cwd.len() - 1]) }
    }
    pub(in crate::zip::read) fn finish(mut self, ledger: &impl LedgerAccess) -> Result<(), ReadFault> {
        while let Some(item) = self.canonical.pop() {
            item.bytes.finish(ledger).map_err(|(_, f)| f)?;
        }
        for result in [
            self.raw.finish(ledger).map_err(|(_, f)| f),
            self.entries.finish(ledger).map_err(|(_, f)| f),
            self.canonical.finish(ledger).map_err(|(_, f)| f),
            self.identities.finish(ledger).map_err(|(_, f)| f),
            self.cwd.finish(ledger).map_err(|(_, f)| f),
        ] {
            result?;
        }
        Ok(())
    }
}
