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

use crate::batch::{self, PositionReadError, read_at_detailed};
use crate::blake2sp::Blake2sp;
use crate::error::RarInternal;
use crate::extract::{
    EntryContext, Pending, RarEntryIdentity, RarEntryOutcome, RarMatchState, RarOutcome, RarOutput, RarVerification,
};
use crate::rar5::unpack::{Sink, Unpacker, window_for_detailed};

use super::*;

#[cfg(unix)]
mod extraction;
mod printing;
pub use printing::RarPrintOptions;

const WINDOW_MAX: u64 = 256 << 20;
const CHUNK: usize = 64 << 10;
type DecodedOutput<'a> = &'a mut dyn FnMut(&[u8]) -> RarResult<()>;

pub(super) struct SessionToken {
    pub(super) _private: u8,
}

/// A selection made against one session's logical member ordinals.
pub struct RarSelection {
    token: Arc<SessionToken>,
    bits: Vec<u64>,
    matched: u64,
}

/// Cumulative packed and decoded work, and the maximum decoder window.
#[derive(Clone, Copy, Debug)]
pub struct RarDecodeLimits {
    pub packed_bytes: u64,
    pub decoded_bytes: u64,
    pub window_bytes: u64,
}

impl Default for RarDecodeLimits {
    fn default() -> Self {
        Self { packed_bytes: 8 << 30, decoded_bytes: 8 << 30, window_bytes: WINDOW_MAX }
    }
}

impl RarSession {
    /// Evaluate each logical member in archive order and record the matches.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn select(&self, mut include: impl FnMut(RarMember<'_>) -> bool) -> Result<RarSelection, RarRunError> {
        let result = (|| {
            check_cancel(&self.options.cancel)?;
            let words = self.members.len().div_ceil(64);
            let capacity = self.options.limits.capacity;
            let check_capacity = |words| {
                limit(add(self.usage.capacity, vector_bytes::<u64>(words)?)?, capacity, RarResource::CatalogueCapacity)
            };
            check_capacity(words)?;
            let mut bits = Vec::new();
            bits.try_reserve_exact(words).map_err(|_| allocation())?;
            check_capacity(bits.capacity())?;
            bits.resize(words, 0);
            let mut matched = 0;
            for (index, member) in self.entries().enumerate() {
                check_cancel(&self.options.cancel)?;
                if include(member) {
                    bits[index / 64] |= 1 << (index % 64);
                    matched = add(matched, 1)?;
                }
            }
            check_cancel(&self.options.cancel)?;
            Ok(RarSelection { token: Arc::clone(&self.token), bits, matched })
        })();
        result.map_err(|fault: RarFault| run_error(self.summary(0), None, Arc::from(fault.failure)))
    }

    /// Verify selected members and the solid predecessors they require.
    /// Events refer to logical catalogue ordinals and run on the caller's thread.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn test_selected(
        &mut self,
        selection: &RarSelection,
        limits: RarDecodeLimits,
        on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        self.execute_selected(selection, limits, |run, session, index| run.test(session, index, None), on_entry)
    }

    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    fn execute_selected(
        &mut self,
        selection: &RarSelection,
        limits: RarDecodeLimits,
        mut member: impl FnMut(&mut SelectedRun, &mut RarSession, usize) -> Result<RarOutcome, Arc<RarFailure>>,
        mut on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        if !Arc::ptr_eq(&self.token, &selection.token) {
            return Err(run_error(self.summary(0), None, Arc::new(RarFailure::ForeignSelection)));
        }
        let mut summary = self.summary(selection.matched);
        self.check_run_sources(&mut summary)?;
        if selection.matched == 0 {
            return Ok(summary);
        }
        let mut run = match SelectedRun::new(limits) {
            Ok(run) => run,
            Err(fault) => return Err(run_error(summary, None, Arc::from(fault.failure))),
        };
        for (word, mut bits) in selection.bits.iter().copied().enumerate() {
            while bits != 0 {
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                let header = &self.members[index].header;
                let context = EntryContext {
                    entry: RarEntryIdentity {
                        index: Some(index as u64),
                        order: index as u64,
                        name: header.name.clone(),
                    },
                    method: header.method,
                    password: RarPasswordEvidence::NotEncrypted,
                };
                match member(&mut run, self, index) {
                    Ok(outcome) => {
                        if let Err(fault) = count_outcome(&mut summary, &outcome) {
                            return Err(run_error(summary, Some(context.entry), Arc::from(fault.failure)));
                        }
                        on_entry(&context.event(outcome));
                    }
                    Err(failure) => {
                        if let Err(fault) = count_outcome(&mut summary, &RarOutcome::Failed(Arc::clone(&failure))) {
                            return Err(run_error(summary, Some(context.entry), Arc::from(fault.failure)));
                        }
                        on_entry(&context.event(RarOutcome::Failed(Arc::clone(&failure))));
                        return Err(run_error(summary, Some(context.entry), failure));
                    }
                }
            }
        }
        Ok(summary)
    }

    fn summary(&self, matched: u64) -> RarRunSummary {
        RarRunSummary {
            encountered: self.usage.entries,
            matched,
            volumes: self.usage.volumes,
            match_state: if matched == 0 { RarMatchState::NoMatch } else { RarMatchState::Matched },
            ..RarRunSummary::default()
        }
    }

    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    fn check_run_sources(&mut self, summary: &mut RarRunSummary) -> Result<(), RarRunError> {
        if let Err(fault) = check_cancel(&self.options.cancel) {
            return Err(run_error(std::mem::take(summary), None, Arc::from(fault.failure)));
        }
        for index in 0..self.volumes.len() {
            if let Err(failure) = self.check_volume(index) {
                return Err(run_error(std::mem::take(summary), None, failure));
            }
        }
        Ok(())
    }

    fn check_volume(&mut self, index: usize) -> Result<(), Arc<RarFailure>> {
        if let Some(failure) = &self.invalid_binding {
            return Err(Arc::clone(failure));
        }
        let volume = &self.volumes[index];
        if let Err(fault) = volume.stamp.check(&volume.file, &volume.path) {
            let failure = Arc::from(fault.failure);
            self.invalid_binding = Some(Arc::clone(&failure));
            return Err(failure);
        }
        Ok(())
    }
}

fn run_error(partial: RarRunSummary, entry: Option<RarEntryIdentity>, failure: Arc<RarFailure>) -> RarRunError {
    RarRunError { partial, entry, failure, partial_member_bytes: 0 }
}

fn count_outcome(summary: &mut RarRunSummary, outcome: &RarOutcome) -> RarResult<()> {
    match outcome {
        RarOutcome::Verified { bytes, .. } => {
            let files = add(summary.files, 1)?;
            summary.bytes = add(summary.bytes, *bytes)?;
            summary.files = files;
        }
        RarOutcome::Directory => summary.dirs = add(summary.dirs, 1)?,
        RarOutcome::Skipped(_) => summary.skipped = add(summary.skipped, 1)?,
        RarOutcome::Failed(_) => summary.failed = add(summary.failed, 1)?,
    }
    Ok(())
}

struct SelectedRun {
    limits: RarDecodeLimits,
    packed: u64,
    decoded: u64,
    chain: Option<usize>,
    next: usize,
    failed: Option<(usize, Arc<RarFailure>)>,
    decoder: Option<Unpacker>,
    history_volumes: VolumeSet,
    buffer: Vec<u8>,
    decrypted: Vec<u8>,
}

impl SelectedRun {
    fn new(limits: RarDecodeLimits) -> RarResult<Self> {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(CHUNK).map_err(|_| allocation())?;
        buffer.resize(CHUNK, 0);
        let mut decrypted = Vec::new();
        decrypted.try_reserve_exact(CHUNK + 15).map_err(|_| allocation())?;
        Ok(Self {
            limits,
            packed: 0,
            decoded: 0,
            chain: None,
            next: 0,
            failed: None,
            decoder: None,
            history_volumes: [0; VOLUME_WORDS],
            buffer,
            decrypted,
        })
    }

    fn test(
        &mut self,
        session: &mut RarSession,
        index: usize,
        output: Option<DecodedOutput<'_>>,
    ) -> Result<RarOutcome, Arc<RarFailure>> {
        check_cancel(&session.options.cancel).map_err(|fault| Arc::from(fault.failure))?;
        let member = &session.members[index];
        if member.header.is_dir() || member.header.redirection.is_some() {
            let outcome = match (member.issue, &member.header.redirection) {
                (Some(issue), _) => RarOutcome::Failed(Arc::new(copy_catalogue_issue(&session.issues[issue]))),
                (None, Some(link)) => {
                    let kind = match link {
                        Redirection::UnixSymlink(_) => 1,
                        Redirection::WindowsSymlink(_) => 2,
                        Redirection::Junction(_) => 3,
                        Redirection::HardLink(_) => 4,
                        Redirection::FileCopy(_) => 5,
                        Redirection::Unknown(kind) => *kind,
                    };
                    RarOutcome::Failed(Arc::new(RarFailure::Unsupported(RarUnsupported::Redirection { kind })))
                }
                (None, None) => RarOutcome::Directory,
            };
            let mut volumes = [0; VOLUME_WORDS];
            mark_volumes(&mut volumes, &session.parts[member.parts.clone()]);
            check_volumes(session, &volumes)?;
            return Ok(outcome);
        }
        let compressed = member.header.method != 0;
        if compressed {
            let Some(chain) = member.chain else {
                return Ok(RarOutcome::Failed(history_failure(None)));
            };
            if self.chain != Some(chain) {
                self.chain = Some(chain);
                self.next = chain;
                self.failed = None;
                self.history_volumes.fill(0);
            }
            if let Some(failed) = &self.failed {
                return Ok(RarOutcome::Failed(history_failure(Some(failed))));
            }
            for predecessor in self.next..index {
                if session.members[predecessor].chain != Some(chain) {
                    continue;
                }
                if let Err(failure) = self.decode(session, predecessor, true, None) {
                    if is_terminal(&failure) {
                        return Err(failure);
                    }
                    self.decoder = None;
                    self.failed = Some((predecessor, failure));
                    return Ok(RarOutcome::Failed(history_failure(self.failed.as_ref())));
                }
            }
            self.next = index + 1;
        }
        match self.decode(session, index, compressed, output) {
            Ok((bytes, checks)) => Ok(RarOutcome::Verified { bytes, checks, output: RarOutput::Tested }),
            Err(failure) if is_terminal(&failure) => Err(failure),
            Err(failure) => {
                if compressed {
                    self.decoder = None;
                    self.failed = Some((index, Arc::clone(&failure)));
                }
                Ok(RarOutcome::Failed(failure))
            }
        }
    }

    fn decode(
        &mut self,
        session: &mut RarSession,
        index: usize,
        compressed: bool,
        output: Option<DecodedOutput<'_>>,
    ) -> Result<(u64, RarVerification), Arc<RarFailure>> {
        check_cancel(&session.options.cancel).map_err(|fault| Arc::from(fault.failure))?;
        let member = &session.members[index];
        let mut used_volumes = if compressed { self.history_volumes } else { [0; VOLUME_WORDS] };
        mark_volumes(&mut used_volumes, &session.parts[member.parts.clone()]);
        check_volumes(session, &used_volumes)?;
        let result = self.decode_bound(session, index, output).map_err(Arc::new);
        if result
            .as_ref()
            .is_err_and(|failure| matches!(failure.as_ref(), RarFailure::Output { .. } | RarFailure::PrintSpool { .. }))
        {
            // Record any observed binding loss without replacing the original
            // output failure returned to this run.
            let _ = check_volumes(session, &used_volumes);
            return result;
        }
        #[cfg(test)]
        AFTER_DECODE.with_borrow_mut(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
        check_volumes(session, &used_volumes)?;
        check_cancel(&session.options.cancel).map_err(|fault| Arc::from(fault.failure))?;
        if compressed && result.is_ok() {
            self.history_volumes = used_volumes;
        }
        result
    }

    fn decode_bound(
        &mut self,
        session: &RarSession,
        index: usize,
        mut output: Option<DecodedOutput<'_>>,
    ) -> Result<(u64, RarVerification), RarFailure> {
        let member = &session.members[index];
        if let Some(issue) = member.issue {
            return Err(copy_catalogue_issue(&session.issues[issue]));
        }
        // Check known totals before key derivation or dictionary allocation.
        // Actual work is still charged at each part and decoded chunk.
        charge(self.packed, member.packed_size, self.limits.packed_bytes, RarResource::SelectedPackedBytes)?;
        if let Some(size) = member.unpacked_size {
            charge(self.decoded, size, self.limits.decoded_bytes, RarResource::SelectedDecodedBytes)?;
        }
        let header = &member.header;
        let parts = &session.parts[member.parts.clone()];
        let context = EntryContext {
            entry: RarEntryIdentity { index: Some(index as u64), order: index as u64, name: String::new() },
            method: header.method,
            password: RarPasswordEvidence::NotEncrypted,
        };
        let mut pending = Pending::new(header, context);
        if header.encrypted {
            let Some(password) = Some(session.password.as_str()).filter(|pw| !pw.is_empty()) else {
                return Err(RarFailure::PasswordRequired { scope: pending.context().scope() });
            };
            let params = parts[0]
                .crypt
                .and_then(Result::ok)
                .ok_or_else(|| pending.context().integrity(RarIntegrityReason::MalformedEncryptionRecord, false))?;
            pending.start_selected_cipher(params, password, member.unpacked_size)?;
        }
        let compressed = header.method != 0;
        if compressed {
            self.prepare_decoder(session, member, pending.context())?;
        }
        for (part_index, part) in parts.iter().enumerate() {
            check_cancel(&session.options.cancel).map_err(|fault| *fault.failure)?;
            let final_part = part_index + 1 == parts.len();
            self.packed =
                charge(self.packed, part.packed_size, self.limits.packed_bytes, RarResource::SelectedPackedBytes)?;
            let volume = &session.volumes[part.volume];
            let mut part_crc = crate::crc32::Hasher::new();
            let mut part_blake = (!final_part && part.checks.blake2sp.is_some()).then(Blake2sp::new);
            let mut left = part.packed_size;
            let mut offset = part.data_offset;
            while left != 0 {
                check_cancel(&session.options.cancel).map_err(|fault| *fault.failure)?;
                let len = left.min(CHUNK as u64) as usize;
                let chunk = &mut self.buffer[..len];
                read_at_detailed(&volume.file, chunk, offset).map_err(|error| match error {
                    PositionReadError::Eof => RarFailure::Input {
                        operation: IoOperation::Read,
                        path: Some(volume.path.clone()),
                        offset: Some(offset),
                        source: io::Error::from(io::ErrorKind::UnexpectedEof),
                    },
                    PositionReadError::Io { offset, source } => RarFailure::Input {
                        operation: IoOperation::Read,
                        path: Some(volume.path.clone()),
                        offset: Some(offset),
                        source,
                    },
                })?;
                if !final_part {
                    part_crc.update(chunk);
                    if let Some(hash) = &mut part_blake {
                        hash.update(chunk);
                    }
                }
                let mut blocks = None;
                let plaintext = if let Some(cipher) = pending.selected_cipher() {
                    cipher.decrypt_selected(chunk, &mut self.decrypted);
                    blocks = cipher.take_blocks();
                    self.decrypted.as_slice()
                } else {
                    chunk
                };
                let mut sink = SelectedSink {
                    pending: &mut pending,
                    decoded: &mut self.decoded,
                    limit: self.limits.decoded_bytes,
                    cancel: &session.options.cancel,
                    failure: None,
                    output: &mut output,
                };
                let decoder = self.decoder.as_mut().filter(|_| compressed);
                match decoder {
                    Some(decoder) => {
                        let result = match &mut blocks {
                            Some(blocks) => blocks.feed(plaintext, decoder, &mut sink),
                            None => decoder.feed(plaintext, &mut sink),
                        };
                        sink.finish(result, decoder.take_size_failure())?;
                    }
                    None => {
                        let result = sink.put(plaintext);
                        sink.finish(result, None)?;
                    }
                }
                if let Some(cipher) = pending.selected_cipher() {
                    cipher.put_blocks(blocks);
                }
                left -= len as u64;
                offset += len as u64;
            }
            if !final_part {
                verify_part(&pending, part.checks, part_crc, part_blake)?;
            }
        }
        let context = pending.context().clone();
        if let Some(cipher) = pending.selected_cipher() {
            cipher.finish_selected(&context)?;
        }
        if let Some(decoder) = self.decoder.as_mut().filter(|_| compressed) {
            let mut sink = SelectedSink {
                pending: &mut pending,
                decoded: &mut self.decoded,
                limit: self.limits.decoded_bytes,
                cancel: &session.options.cancel,
                failure: None,
                output: &mut output,
            };
            let result = decoder.finish(&mut sink);
            sink.finish(result, decoder.take_size_failure())?;
        }
        let final_checks = parts.last().expect("catalogue members have a part").checks;
        let checks = pending.verify_selected(
            member.unpacked_size,
            final_checks.crc32,
            final_checks.blake2sp,
            final_checks.keyed,
        )?;
        Ok((pending.verified_size(), checks))
    }

    fn prepare_decoder(
        &mut self,
        session: &RarSession,
        member: &Member,
        context: &EntryContext,
    ) -> Result<(), RarFailure> {
        let header = &member.header;
        if header.solid {
            let decoder = self.decoder.as_mut().expect("solid predecessors decoded");
            if header.dictionary > decoder.reach() {
                return Err(RarFailure::Limit {
                    resource: RarResource::DictionarySize,
                    requested: Some(header.dictionary),
                    allowed: Some(decoder.reach()),
                });
            }
            decoder.next_file(member.unpacked_size);
            return Ok(());
        }
        let first = &session.parts[member.parts.start];
        let solid = member.has_successor || session.volumes[first.volume].metadata.main.is_solid();
        let window = window_for_detailed(header.dictionary, member.unpacked_size, solid)
            .map_err(|error| *error.detailed(context.scope()).failure)?;
        let allowed = self.limits.window_bytes.min(WINDOW_MAX);
        if window.size > allowed {
            return Err(RarFailure::Limit {
                resource: RarResource::DictionarySize,
                requested: Some(window.size),
                allowed: Some(allowed),
            });
        }
        if let Some(decoder) = self.decoder.as_mut().filter(|decoder| decoder.fits(window)) {
            decoder.restart(window, member.unpacked_size);
        } else {
            self.decoder = None;
            let mut decoder =
                Unpacker::new_detailed(window).map_err(|error| *error.detailed(context.scope()).failure)?;
            decoder.set_threads(0, decoder.parallel_min());
            decoder.reset(member.unpacked_size);
            self.decoder = Some(decoder);
        }
        Ok(())
    }
}

const VOLUME_WORDS: usize = (MAX_VOLUMES as usize).div_ceil(64);
type VolumeSet = [u64; VOLUME_WORDS];

fn mark_volumes(words: &mut VolumeSet, parts: &[Part]) {
    for part in parts {
        words[part.volume / 64] |= 1 << (part.volume % 64);
    }
}

fn check_volumes(session: &mut RarSession, words: &VolumeSet) -> Result<(), Arc<RarFailure>> {
    for (word, mut bits) in words.iter().copied().enumerate() {
        while bits != 0 {
            let index = word * 64 + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            session.check_volume(index)?;
        }
    }
    Ok(())
}

fn charge(current: u64, count: u64, allowed: u64, resource: RarResource) -> Result<u64, RarFailure> {
    let requested = current.checked_add(count);
    match requested {
        Some(value) if value <= allowed => Ok(value),
        _ => Err(RarFailure::Limit { resource, requested, allowed: Some(allowed) }),
    }
}

fn copy_catalogue_issue(failure: &RarFailure) -> RarFailure {
    match failure {
        RarFailure::Integrity { scope, reason, password } => {
            RarFailure::Integrity { scope: scope.clone(), reason: reason.clone(), password: *password }
        }
        RarFailure::Unsupported(reason) => RarFailure::Unsupported(reason.clone()),
        RarFailure::Limit { resource, requested, allowed } => {
            RarFailure::Limit { resource: resource.clone(), requested: *requested, allowed: *allowed }
        }
        _ => RarFailure::Internal(RarInternal::Invariant("unexpected retained catalogue issue")),
    }
}

fn is_terminal(failure: &RarFailure) -> bool {
    matches!(
        failure,
        RarFailure::Input { .. }
            | RarFailure::Output { .. }
            | RarFailure::PrintSpool { .. }
            | RarFailure::SourceChanged { .. }
            | RarFailure::Canceled
            | RarFailure::Internal(_)
            | RarFailure::Limit {
                resource: RarResource::Counter
                    | RarResource::CatalogueAllocation
                    | RarResource::SelectedPackedBytes
                    | RarResource::SelectedDecodedBytes
                    | RarResource::PrintMemberSpoolBytes
                    | RarResource::PrintLiveSpoolBytes
                    | RarResource::PrintIoAttempts,
                ..
            }
    )
}

fn history_failure(failed: Option<&(usize, Arc<RarFailure>)>) -> Arc<RarFailure> {
    Arc::new(RarFailure::SolidHistoryUnavailable {
        predecessor: failed.map(|(index, _)| *index as u64),
        cause: failed.map(|(_, failure)| Arc::clone(failure)),
    })
}

fn verify_part(
    pending: &Pending,
    checks: RarChecks,
    crc: crate::crc32::Hasher,
    blake: Option<Blake2sp>,
) -> Result<(), RarFailure> {
    let key = pending.hash_key(checks.keyed);
    let crc_bad = checks.crc32.is_some_and(|want| {
        let actual = crc.finalize();
        key.map_or(actual, |key| crate::crypto::rar5_tweak_crc32(actual, key)) != want
    });
    let blake_bad = checks.blake2sp.zip(blake).is_some_and(|(want, actual)| {
        let actual = actual.finish();
        key.map_or(actual, |key| crate::crypto::rar5_tweak_blake2sp(&actual, key)) != want
    });
    if crc_bad || blake_bad {
        let keyed = key.is_some();
        return Err(pending
            .context()
            .integrity(RarIntegrityReason::PackedPiece { crc32: crc_bad, blake2sp: blake_bad, keyed }, keyed));
    }
    Ok(())
}

struct SelectedSink<'a, 'out> {
    pending: &'a mut Pending,
    decoded: &'a mut u64,
    limit: u64,
    cancel: &'a Cancellation,
    failure: Option<RarFailure>,
    output: &'a mut Option<DecodedOutput<'out>>,
}

impl SelectedSink<'_, '_> {
    fn finish(self, result: crate::Result<()>, size: Option<(u64, u64)>) -> Result<(), RarFailure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        result.map_err(|error| {
            let ctx = self.pending.context();
            *batch::decoder_failure_with_size(error, ctx.scope(), ctx.password, size).failure
        })
    }

    fn take(&mut self, bytes: &[u8]) -> Result<(), RarFailure> {
        check_cancel(self.cancel).map_err(|fault| *fault.failure)?;
        self.pending
            .take_with(bytes, |chunk| {
                *self.decoded =
                    charge(*self.decoded, chunk.len() as u64, self.limit, RarResource::SelectedDecodedBytes)
                        .map_err(|failure| RarFault::new(failure, Error::Corrupt("selected RAR decoded work limit")))?;
                if let Some(output) = &mut self.output {
                    output(chunk)?;
                }
                Ok(())
            })
            .map_err(|fault| *fault.failure)
    }
}

impl Sink for SelectedSink<'_, '_> {
    fn put(&mut self, bytes: &[u8]) -> crate::Result<()> {
        if self.failure.is_none() {
            self.failure = self.take(bytes).err();
        }
        if self.failure.is_some() { Err(Error::Corrupt("selected RAR sink stopped")) } else { Ok(()) }
    }

    fn wants_crc(&self) -> bool {
        self.pending.wants_crc()
    }

    fn crc(&mut self, crc: u32) {
        self.pending.crc(crc);
    }
}

#[cfg(test)]
thread_local! {
    static AFTER_DECODE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn verifies_using_held_descriptors_and_rechecks_sources_after_decode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.rar");
        let replacement = dir.path().join("replacement");
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        let body = [2, 2, 1, 0, 1, 0, 0, 1, 1, b'a'];
        let mut framed = vec![body.len() as u8];
        framed.extend(body);
        let crc = crate::crc32::hash(&framed).to_le_bytes();
        let bytes = [super::super::super::SIGNATURE.as_slice(), &main, &crc, &framed, b"x", &end].concat();
        fs::write(&path, &bytes).unwrap();
        fs::write(&replacement, &bytes).unwrap();
        OPENED.set(0);
        super::super::super::reader::VOLUME_OPENS.set(0);
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let summary = session.test_selected(&selection, RarDecodeLimits::default(), |_| {}).unwrap();
        assert_eq!(summary.bytes, 1);
        assert_eq!(OPENED.get(), 1);
        assert_eq!(super::super::super::reader::VOLUME_OPENS.get(), 0);

        let target = path.clone();
        AFTER_DECODE.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move || fs::rename(replacement, target).unwrap()));
        });
        let result = session
            .test_selected(&selection, RarDecodeLimits::default(), |event| {
                assert!(matches!(event.outcome, RarOutcome::Failed(_)));
            })
            .unwrap_err();
        assert_eq!(result.partial.files, 0);
        assert!(matches!(result.failure.as_ref(), RarFailure::SourceChanged { path: actual } if actual == &path));
        assert!(Arc::ptr_eq(session.invalid_binding.as_ref().unwrap(), &result.failure));
    }
}
