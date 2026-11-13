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

//! Separate encrypted admission and all-record finite run accounting.
use super::*;
use crate::zip::session::SourceStamp;
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct EncryptedReadLimits {
    pub member_packed_bytes: u64,
    pub member_decoded_bytes: u64,
    pub ciphertext_memory_bytes: u64,
    pub member_spool_bytes: u64,
    pub live_spool_bytes: u128,
    pub source_bytes: u128,
    pub packed_bytes: u128,
    pub decoded_bytes: u128,
    pub io_bytes: u128,
    pub work_bytes: u128,
    pub members: u64,
    pub password_bytes: u64,
    pub kdf_calls: u64,
    pub io_attempts: u128,
    pub codec_steps: u128,
    pub interrupted_retries: u64,
    pub create_attempts: u64,
    pub reader_capacity: u64,
    pub allocation_attempts: u64,
    pub live_fds: u64,
}
impl Default for EncryptedReadLimits {
    fn default() -> Self {
        Self {
            member_packed_bytes: 8 << 30,
            member_decoded_bytes: 8 << 30,
            ciphertext_memory_bytes: 64 << 10,
            member_spool_bytes: 8 << 30,
            live_spool_bytes: 16 << 30,
            source_bytes: (1 << 40) + (64 << 20),
            packed_bytes: 1 << 40,
            decoded_bytes: 1 << 40,
            io_bytes: (6 << 40) + (64 << 20),
            work_bytes: 8 << 40,
            members: 100_000,
            password_bytes: 65_535,
            kdf_calls: 100_000,
            io_attempts: 16_777_216,
            codec_steps: 16_777_216,
            interrupted_retries: 16,
            create_attempts: 16,
            reader_capacity: 256 << 10,
            allocation_attempts: 32,
            live_fds: 5,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct EncryptedReadUsage {
    pub member_packed_bytes: u64,
    pub member_decoded_bytes: u64,
    pub ciphertext_memory_bytes: u64,
    pub member_spool_bytes: u64,
    pub live_spool_bytes: u128,
    pub source_bytes: u128,
    pub packed_bytes: u128,
    pub decoded_bytes: u128,
    pub io_bytes: u128,
    pub work_bytes: u128,
    pub members: u64,
    pub password_bytes: u64,
    pub kdf_calls: u64,
    pub io_attempts: u128,
    pub codec_steps: u128,
    pub interrupted_retries: u64,
    pub create_attempts: u64,
    pub reader_capacity: u64,
    pub allocation_attempts: u64,
    pub live_fds: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RunUsage {
    pub records: u128,
    pub source_check_groups: u128,
    pub path_steps: u128,
    pub temporary_groups: u128,
    pub positive_transfers: u128,
    pub terminal_probes: u128,
    pub stage_finalization: u128,
    pub directory_finalization: u128,
    pub final_operations: u128,
    pub decode_steps: u128,
    pub emergency_cleanup: u128,
    pub io_attempts: u128,
    pub io_bytes: u128,
    pub live_spool_bytes: u128,
}
impl RunUsage {
    fn counter(&mut self, category: RunCategory) -> &mut u128 {
        match category {
            RunCategory::Records => &mut self.records,
            RunCategory::SourceCheckGroups => &mut self.source_check_groups,
            RunCategory::PathSteps => &mut self.path_steps,
            RunCategory::TemporaryGroups => &mut self.temporary_groups,
            RunCategory::PositiveTransfers => &mut self.positive_transfers,
            RunCategory::TerminalProbes => &mut self.terminal_probes,
            RunCategory::StageFinalization => &mut self.stage_finalization,
            RunCategory::DirectoryFinalization => &mut self.directory_finalization,
            RunCategory::FinalOperations => &mut self.final_operations,
            RunCategory::DecodeSteps => &mut self.decode_steps,
            RunCategory::EmergencyCleanup => &mut self.emergency_cleanup,
            RunCategory::IoAttempts => &mut self.io_attempts,
            RunCategory::IoBytes => &mut self.io_bytes,
        }
    }
}
pub(super) fn checked_sum(a: u128, b: u128) -> Result<u128, ReadFault> {
    a.checked_add(b).ok_or(ReadFault::CounterOverflow)
}
fn product(a: u128, b: u128) -> Result<u128, ReadFault> {
    a.checked_mul(b).ok_or(ReadFault::CounterOverflow)
}
pub(super) fn admit(resource: ReadResource, limit: u128, attempted: u128) -> Result<(), ReadFault> {
    if attempted > limit { Err(ReadFault::Limit { resource, limit, attempted }) } else { Ok(()) }
}
fn charge(counter: &mut u128, amount: u128, limit: u128, resource: ReadResource) -> Result<(), ReadFault> {
    let next = checked_sum(*counter, amount)?;
    admit(resource, limit, next)?;
    *counter = next;
    Ok(())
}
pub(super) fn next_creation_attempt(current: u64, limit: u64) -> Result<u64, ReadFault> {
    let next = current.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
    admit(ReadResource::CreateAttempts, limit.into(), next.into())?;
    Ok(next)
}
fn charge64(counter: &mut u64, amount: u64, limit: u64, resource: ReadResource) -> Result<(), ReadFault> {
    let next = counter.checked_add(amount).ok_or(ReadFault::CounterOverflow)?;
    admit(resource, u128::from(limit), u128::from(next))?;
    *counter = next;
    Ok(())
}
pub(super) struct EncryptedReadLedger {
    pub(super) limits: EncryptedReadLimits,
    pub(super) usage: EncryptedReadUsage,
    member_expected: u64,
}
impl EncryptedReadLedger {
    pub(super) fn work(&mut self, bytes: u64) -> Result<(), ReadFault> {
        charge(&mut self.usage.work_bytes, bytes.into(), self.limits.work_bytes, ReadResource::WorkBytes)
    }
    #[cfg(test)] // Original Task1/2 admission controls; production supplies the now-known CRC policy.
    pub(super) fn begin_member(
        &mut self,
        packed: u64,
        decoded: u64,
        ciphertext: u64,
        password: u64,
        aes: bool,
    ) -> Result<(), ReadFault> {
        self.begin_member_with_crc(packed, decoded, ciphertext, password, aes, false)
    }
    pub(super) fn begin_member_with_crc(
        &mut self,
        packed: u64,
        decoded: u64,
        ciphertext: u64,
        password: u64,
        aes: bool,
        crc: bool,
    ) -> Result<(), ReadFault> {
        // Attempts and declared P are spent even when later policy/framing rejects the member.
        self.charge_member_attempt(packed)?;
        admit(ReadResource::MemberPackedBytes, self.limits.member_packed_bytes.into(), packed.into())?;
        admit(ReadResource::MemberDecodedBytes, self.limits.member_decoded_bytes.into(), decoded.into())?;
        if aes && ciphertext > self.limits.ciphertext_memory_bytes {
            admit(ReadResource::MemberSpoolBytes, self.limits.member_spool_bytes.into(), ciphertext.into())?;
        }
        admit(ReadResource::PasswordBytes, self.limits.password_bytes.into(), password.into())?;
        self.usage.password_bytes = password;
        self.usage.member_packed_bytes = packed;
        self.usage.member_decoded_bytes = 0;
        self.member_expected = decoded;
        self.usage.member_spool_bytes =
            if aes && ciphertext > self.limits.ciphertext_memory_bytes { ciphertext } else { 0 };
        self.usage.allocation_attempts = 0;
        let disk = aes && ciphertext > self.limits.ciphertext_memory_bytes;
        let io = u128::from(packed)
            .checked_add(if disk { product(ciphertext.into(), 3)? } else { 0 })
            .ok_or(ReadFault::CounterOverflow)?;
        admit(ReadResource::IoBytes, self.limits.io_bytes, checked_sum(self.usage.io_bytes, io)?)?;
        admit(
            ReadResource::SourceBytes,
            self.limits.source_bytes,
            checked_sum(self.usage.source_bytes, packed.into())?,
        )?;
        let work = if aes {
            checked_sum(product(ciphertext.into(), 3)?, decoded.into())?
        } else {
            checked_sum(checked_sum(packed.into(), ciphertext.into())?, decoded.into())?
        };
        if aes && !disk {
            admit(
                ReadResource::ReaderCapacity,
                self.limits.reader_capacity.into(),
                checked_sum(self.usage.reader_capacity.into(), ciphertext.into())?,
            )?;
        }
        if disk {
            admit(
                ReadResource::LiveSpoolBytes,
                self.limits.live_spool_bytes,
                checked_sum(self.usage.live_spool_bytes, ciphertext.into())?,
            )?;
        }
        let work = if crc { checked_sum(work, decoded.into())? } else { work };
        admit(ReadResource::WorkBytes, self.limits.work_bytes, checked_sum(self.usage.work_bytes, work)?)?;
        if aes {
            charge64(&mut self.usage.kdf_calls, 1, self.limits.kdf_calls, ReadResource::KdfCalls)?;
        }
        Ok(())
    }
    fn charge_member_attempt(&mut self, packed: u64) -> Result<(), ReadFault> {
        // Member refusal takes priority over packed refusal; a spent member charge
        // is retained if declared P subsequently exhausts the cumulative budget.
        charge64(&mut self.usage.members, 1, self.limits.members, ReadResource::Members)?;
        charge(&mut self.usage.packed_bytes, packed.into(), self.limits.packed_bytes, ReadResource::PackedBytes)
    }
    /// Terminal admission for malformed/unsupported encrypted records. The caller
    /// returns this fault directly, rather than calling begin_member afterward:
    /// both paths spend exactly one member/P attempt, without KDF or payload work.
    pub(super) fn reject_member(&mut self, packed: u64, rejection: ReadFault) -> ReadFault {
        match self.charge_member_attempt(packed) {
            Ok(()) => rejection,
            Err(exhausted) => exhausted,
        }
    }
    pub(super) fn allocation(&mut self, capacity: u64) -> Result<(), ReadFault> {
        charge64(
            &mut self.usage.allocation_attempts,
            1,
            self.limits.allocation_attempts,
            ReadResource::AllocationAttempts,
        )?;
        charge64(&mut self.usage.reader_capacity, capacity, self.limits.reader_capacity, ReadResource::ReaderCapacity)
    }
    pub(super) fn decode(&mut self, output: u64, work: u128) -> Result<(), ReadFault> {
        charge(&mut self.usage.codec_steps, 1, self.limits.codec_steps, ReadResource::CodecSteps)?;
        self.decode_bytes(output, work)
    }
    pub(super) fn decode_bytes(&mut self, output: u64, work: u128) -> Result<(), ReadFault> {
        let actual = self.usage.member_decoded_bytes.checked_add(output).ok_or(ReadFault::CounterOverflow)?;
        admit(
            ReadResource::MemberDecodedBytes,
            self.member_expected.min(self.limits.member_decoded_bytes).into(),
            actual.into(),
        )?;
        charge(&mut self.usage.decoded_bytes, output.into(), self.limits.decoded_bytes, ReadResource::DecodedBytes)?;
        charge(&mut self.usage.work_bytes, work, self.limits.work_bytes, ReadResource::WorkBytes)?;
        self.usage.member_decoded_bytes = actual;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PlanGeometry {
    pub(super) records: u128,
    pub(super) regular: u128,
    pub(super) directories: u128,
    pub(super) packed: u128,
    pub(super) decoded: u128,
    pub(super) large_aes: u128,
    pub(super) ciphertext: u128,
    pub(super) path_bytes: u128,
    pub(super) live_spool: u128,
    pub(super) output_passes: u128,
    pub(super) output_encrypted: bool,
}
// Task4 alone binds immutable source/scope identity after borrowed catalogue derivation.
#[derive(Debug)]
pub(super) struct ActionPlan {
    bounds: RunUsage,
    pub(super) live_spool: u128,
    output_encrypted: bool,
    binding: Option<PlanBinding>,
    pub(super) output_passes: u128,
    namespace_creates: u64,
    namespace_retries: u64,
}
#[derive(Debug)]
pub(super) struct PlanBinding {
    pub(super) source: SourceStamp,
    pub(super) scope: ProjectedReadScope,
    pub(super) output: PlannedOutput,
    // Exact paths remain in their original owners; their per-action identity is
    // fixed by the catalogue factory and cannot be changed through the context.
    #[allow(dead_code)] // Task4 factories tie retained exact path owners to this action identity.
    pub(super) configuration_id: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Task4 fixes output mode before deriving all-record envelopes.
pub(super) enum PlannedOutput {
    Discard,
    Callback,
    StagedFiles,
    VerifiedStdout,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MemberPlan {
    pub(super) source: SourceStamp,
    pub(super) scope: ProjectedReadScope,
    pub(super) ordinal: u64,
    pub(super) packed: u64,
    pub(super) decoded: u64,
    pub(super) ciphertext: u64,
    pub(super) cipher: Option<CipherKind>,
    pub(super) crc: Option<u32>,
    pub(super) output: PlannedOutput,
}
impl ActionPlan {
    #[allow(dead_code)] // Task4 supplies binding after deriving geometry from the same catalogue pass.
    pub(super) fn with_binding(mut self, binding: PlanBinding) -> Result<Self, ReadFault> {
        let passes = match binding.output {
            PlannedOutput::Discard | PlannedOutput::Callback => 0,
            PlannedOutput::StagedFiles => 1,
            PlannedOutput::VerifiedStdout => 3,
        };
        if self.binding.is_some()
            || self.output_passes != passes
            || matches!(binding.scope, ProjectedReadScope::Entry(_)) && self.bounds.records != 1
        {
            return Err(ReadFault::InvalidPlan);
        }
        self.binding = Some(binding);
        Ok(self)
    }
    #[allow(dead_code)] // Task4 catalogue factories will invoke this checked geometry derivation.
    pub(super) fn derive(g: PlanGeometry, creates: u64, retries: u64) -> Result<Self, ReadFault> {
        if checked_sum(g.regular, g.directories)? > g.records
            || g.large_aes > g.regular
            || g.ciphertext > g.packed
            || !matches!(g.output_passes, 0 | 1 | 3)
        {
            return Err(ReadFault::InvalidPlan);
        }
        let r1 = checked_sum(g.records, 1)?;
        let rg1 = checked_sum(g.regular, 1)?;
        let rd1 = checked_sum(g.directories, 1)?;
        let j = checked_sum(
            checked_sum(g.packed, product(30, g.regular)?)?,
            checked_sum(product(3, g.ciphertext)?, product(g.output_passes, g.decoded)?)?,
        )?;
        let l = checked_sum(product(4, g.path_bytes)?, product(4, r1)?)?;
        let t = checked_sum(g.regular, g.large_aes)?;
        let source = product(8, r1)?;
        let terminal = product(4, rg1)?;
        let stage = product(16, rg1)?;
        let dirs = product(12, rd1)?;
        let m =
            [product(3, source)?, product(5, l)?, product(product(12, creates.into())?, t)?, terminal, stage, dirs, 16]
                .into_iter()
                .try_fold(0, checked_sum)?;
        let attempts = product(checked_sum(checked_sum(j, m)?, 1)?, checked_sum(retries.into(), 1)?)?;
        let decode =
            product(4, checked_sum(checked_sum(g.packed, g.decoded)?, checked_sum(product(64, g.regular)?, 1)?)?)?;
        Ok(Self {
            bounds: RunUsage {
                records: g.records,
                source_check_groups: source,
                path_steps: l,
                temporary_groups: t,
                positive_transfers: j,
                terminal_probes: terminal,
                stage_finalization: stage,
                directory_finalization: dirs,
                final_operations: 16,
                decode_steps: decode,
                emergency_cleanup: product(40, r1)?,
                io_attempts: attempts,
                io_bytes: j,
                live_spool_bytes: g.live_spool,
            },
            live_spool: g.live_spool,
            output_encrypted: g.output_encrypted,
            binding: None,
            output_passes: g.output_passes,
            namespace_creates: creates,
            namespace_retries: retries,
        })
    }
}
#[derive(Debug)]
pub(super) struct RunLedger {
    pub(super) usage: RunUsage,
    plan: Option<ActionPlan>,
}
impl RunLedger {
    fn charge(&mut self, category: RunCategory, count: u128) -> Result<(), ReadFault> {
        let plan = self.plan.as_mut().ok_or(ReadFault::InvalidPlan)?;
        let limit = *plan.bounds.counter(category);
        charge(self.usage.counter(category), count, limit, ReadResource::Run(category))
    }
}
pub(super) struct LedgerState {
    pub(super) encrypted: EncryptedReadLedger,
    pub(super) run: RunLedger,
    pub(super) live_fds: u64,
    pub(super) poisoned: bool,
    pub(super) active_encrypted: Option<bool>,
}
impl LedgerState {
    pub(super) fn new(options: &EncryptedReadOptions) -> Result<Self, ReadFault> {
        let limits = options.limits.clone();
        admit(ReadResource::CiphertextMemoryBytes, 1 << 20, limits.ciphertext_memory_bytes.into())?;
        let scratch = limits.ciphertext_memory_bytes.checked_add(3 * (64 << 10)).ok_or(ReadFault::CounterOverflow)?;
        admit(ReadResource::ReaderCapacity, limits.reader_capacity.into(), scratch.into())?;
        if options.lzma_memory_bytes == 0
            || options.lzma_memory_bytes > 256 << 20
            || options.zstd_window_log_max > 27
            || options.zstd_window_log_max < 10
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(Self {
            encrypted: EncryptedReadLedger {
                limits,
                usage: EncryptedReadUsage {
                    reader_capacity: super::shared::SHARED_LEDGER_CAPACITY as u64,
                    ..Default::default()
                },
                member_expected: 0,
            },
            run: RunLedger { usage: RunUsage::default(), plan: None },
            live_fds: 0,
            poisoned: false,
            active_encrypted: None,
        })
    }
    #[allow(dead_code)] // Task4 catalogue factories own the sole production bind site.
    pub(super) fn bind(&mut self, plan: ActionPlan) -> Result<(), ReadFault> {
        if self.run.plan.is_some() || self.poisoned || plan.binding.is_none() {
            return Err(ReadFault::InvalidPlan);
        }
        self.run.plan = Some(plan);
        Ok(())
    }
    pub(super) fn charge_category(&mut self, category: RunCategory, count: u128) -> Result<(), ReadFault> {
        self.run.charge(category, count)
    }
    pub(super) fn creation_policy(&self, encrypted: bool) -> Result<(u64, u64), ReadFault> {
        if self.poisoned {
            return Err(ReadFault::InvalidPlan);
        }
        let plan = self.run.plan.as_ref().ok_or(ReadFault::InvalidPlan)?;
        let (creates, retries) = (plan.namespace_creates, plan.namespace_retries);
        if encrypted {
            Ok((
                creates.min(self.encrypted.limits.create_attempts),
                retries.min(self.encrypted.limits.interrupted_retries),
            ))
        } else {
            Ok((creates, retries))
        }
    }
    pub(super) fn verify_member_kind(&self, member: &MemberPlan, cipher: Option<CipherKind>) -> Result<(), ReadFault> {
        self.verify_source(member.source)?;
        let binding = self.run.plan.as_ref().and_then(|p| p.binding.as_ref()).ok_or(ReadFault::InvalidPlan)?;
        if member.scope != binding.scope
            || member.output != binding.output
            || member.cipher != cipher
            || matches!(member.scope, ProjectedReadScope::Entry(n) if n as u64 != member.ordinal)
        {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    pub(super) fn verify_source(&self, source: SourceStamp) -> Result<(), ReadFault> {
        let binding = self.run.plan.as_ref().and_then(|plan| plan.binding.as_ref()).ok_or(ReadFault::InvalidPlan)?;
        if binding.source != source {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    pub(super) fn output_encrypted(&self) -> Result<bool, ReadFault> {
        let plan = self.run.plan.as_ref().ok_or(ReadFault::InvalidPlan)?;
        let binding = plan.binding.as_ref().ok_or(ReadFault::InvalidPlan)?;
        if let Some(encrypted) = self.active_encrypted {
            return Ok(encrypted);
        }
        match binding.scope {
            ProjectedReadScope::Entry(_) => Ok(plan.output_encrypted),
            _ => Err(ReadFault::InvalidPlan),
        }
    }
    pub(super) fn bound(&self) -> bool {
        self.run.plan.is_some()
    }
    pub(super) fn acquire_fds(&mut self, count: u64) -> Result<(), ReadFault> {
        if self.poisoned {
            return Err(ReadFault::InvalidPlan);
        }
        let limit = self.encrypted.limits.live_fds.min(5);
        charge64(&mut self.live_fds, count, limit, ReadResource::LiveFds)?;
        self.encrypted.usage.live_fds = self.live_fds;
        Ok(())
    }
    pub(super) fn retire_fd(&mut self, confirmed_closed: bool) {
        if confirmed_closed {
            self.live_fds = self.live_fds.checked_sub(1).expect("owned live fd");
            self.encrypted.usage.live_fds = self.live_fds;
        } else {
            self.poisoned = true;
        }
    }
    pub(super) fn reserve(&mut self, encrypted: bool, bytes: u64, fds: u64) -> Result<(), ReadFault> {
        if self.poisoned {
            return Err(ReadFault::InvalidPlan);
        }
        let next = checked_sum(self.run.usage.live_spool_bytes, bytes.into())?;
        let plan = self.run.plan.as_ref().ok_or(ReadFault::InvalidPlan)?;
        admit(ReadResource::Run(RunCategory::IoBytes), plan.live_spool, next)?;
        if encrypted {
            admit(
                ReadResource::LiveSpoolBytes,
                self.encrypted.limits.live_spool_bytes,
                checked_sum(self.encrypted.usage.live_spool_bytes, bytes.into())?,
            )?;
        }
        self.acquire_fds(fds)?;
        self.run.usage.live_spool_bytes = next;
        if encrypted {
            self.encrypted.usage.live_spool_bytes = checked_sum(self.encrypted.usage.live_spool_bytes, bytes.into())?;
        }
        Ok(())
    }
    pub(super) fn release_bytes(&mut self, encrypted: bool, bytes: u64) {
        self.run.usage.live_spool_bytes =
            self.run.usage.live_spool_bytes.checked_sub(bytes.into()).expect("reserved run bytes");
        if encrypted {
            self.encrypted.usage.live_spool_bytes =
                self.encrypted.usage.live_spool_bytes.checked_sub(bytes.into()).expect("reserved encrypted bytes");
        }
    }
    pub(super) fn reserve_capacity(&mut self, capacity: u64) -> Result<(), ReadFault> {
        charge64(
            &mut self.encrypted.usage.reader_capacity,
            capacity,
            self.encrypted.limits.reader_capacity,
            ReadResource::ReaderCapacity,
        )
    }
    pub(super) fn release_capacity(&mut self, capacity: u64) {
        self.encrypted.usage.reader_capacity =
            self.encrypted.usage.reader_capacity.checked_sub(capacity).expect("reserved reader capacity");
    }
    pub(super) fn close_attempt(&mut self, encrypted: bool) -> Result<(), ReadFault> {
        let plan = self.run.plan.as_mut().ok_or(ReadFault::InvalidPlan)?;
        for category in [RunCategory::StageFinalization, RunCategory::IoAttempts] {
            let next = checked_sum(*self.run.usage.counter(category), 1)?;
            admit(ReadResource::Run(category), *plan.bounds.counter(category), next)?;
        }
        if encrypted {
            admit(
                ReadResource::IoAttempts,
                self.encrypted.limits.io_attempts,
                checked_sum(self.encrypted.usage.io_attempts, 1)?,
            )?;
        }
        self.charge_category(RunCategory::StageFinalization, 1)?;
        self.attempt(encrypted)
    }
    pub(super) fn attempt(&mut self, encrypted: bool) -> Result<(), ReadFault> {
        self.charge_category(RunCategory::IoAttempts, 1)?;
        if encrypted {
            charge(
                &mut self.encrypted.usage.io_attempts,
                1,
                self.encrypted.limits.io_attempts,
                ReadResource::IoAttempts,
            )?;
        }
        Ok(())
    }
    pub(super) fn transfer_allowance(
        &self,
        encrypted: bool,
        source: bool,
    ) -> Result<(u128, ReadResource, u128, u128), ReadFault> {
        let plan = self.run.plan.as_ref().ok_or(ReadFault::InvalidPlan)?;
        let mut selected = (
            plan.bounds.io_bytes.checked_sub(self.run.usage.io_bytes).ok_or(ReadFault::CounterOverflow)?,
            ReadResource::Run(RunCategory::IoBytes),
            plan.bounds.io_bytes,
            self.run.usage.io_bytes,
        );
        if encrypted {
            let limits = &self.encrypted.limits;
            let usage = self.encrypted.usage;
            for (enabled, resource, limit, used) in [
                (true, ReadResource::IoBytes, limits.io_bytes, usage.io_bytes),
                (source, ReadResource::SourceBytes, limits.source_bytes, usage.source_bytes),
            ] {
                if enabled {
                    let left = limit.checked_sub(used).ok_or(ReadFault::CounterOverflow)?;
                    if left <= selected.0 {
                        selected = (left, resource, limit, used);
                    }
                }
            }
        }
        Ok(selected)
    }
    pub(super) fn charge_io(&mut self, encrypted: bool, bytes: u64) -> Result<(), ReadFault> {
        self.charge_category(RunCategory::IoBytes, bytes.into())?;
        if encrypted {
            charge(
                &mut self.encrypted.usage.io_bytes,
                bytes.into(),
                self.encrypted.limits.io_bytes,
                ReadResource::IoBytes,
            )?;
        }
        Ok(())
    }
    pub(super) fn transferred(&mut self, encrypted: bool, source: bool, bytes: u64) -> Result<(), ReadFault> {
        if bytes > 0 {
            self.charge_category(RunCategory::PositiveTransfers, 1)?;
        }
        self.charge_io(encrypted, bytes)?;
        if encrypted && source {
            charge(
                &mut self.encrypted.usage.source_bytes,
                bytes.into(),
                self.encrypted.limits.source_bytes,
                ReadResource::SourceBytes,
            )?;
        }
        Ok(())
    }
}
