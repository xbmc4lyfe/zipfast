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
    pub diagnostic_source_groups: u128,
    pub diagnostic_admission_operations: u128,
    pub canonical_metadata_operations: u128,
    pub policy_probe_operations: u128,
    pub output_directory_operations: u128,
    pub storage_backend_operations: u128,
    pub source_seeks: u128,
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
            RunCategory::DiagnosticSourceGroups => &mut self.diagnostic_source_groups,
            RunCategory::DiagnosticAdmissionOperations => &mut self.diagnostic_admission_operations,
            RunCategory::CanonicalMetadataOperations => &mut self.canonical_metadata_operations,
            RunCategory::PolicyProbeOperations => &mut self.policy_probe_operations,
            RunCategory::OutputDirectoryOperations => &mut self.output_directory_operations,
            RunCategory::StorageBackendOperations => &mut self.storage_backend_operations,
            RunCategory::SourceSeeks => &mut self.source_seeks,
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
/// Actual separately scoped policy allocation observations; allocator overhead is not capacity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct PolicyAllocationUsage {
    pub allocation_attempts: u64,
    pub allocations: u64,
    pub releases: u64,
    pub live_allocations: u64,
    pub peak_allocations: u64,
    pub requested_bytes: u128,
    pub allocated_bytes: u128,
    pub live_requested_bytes: u128,
    pub live_capacity: u128,
    pub peak_requested_bytes: u128,
    pub peak_capacity: u128,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct PolicyMetadataUsage {
    pub caller: PolicyAllocationUsage,
    pub native_acl: PolicyAllocationUsage,
    pub scratch: PolicyAllocationUsage,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PolicyComponent {
    Caller,
    NativeAcl,
    Scratch,
}
impl PolicyMetadataUsage {
    fn component(&mut self, kind: PolicyComponent) -> &mut PolicyAllocationUsage {
        match kind {
            PolicyComponent::Caller => &mut self.caller,
            PolicyComponent::NativeAcl => &mut self.native_acl,
            PolicyComponent::Scratch => &mut self.scratch,
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
    /// Post-native observation is irreversible: retain actual production even
    /// when it crosses a quota. Admission charges remain side-effect-free on
    /// refusal; this seam deliberately records work already performed.
    pub(super) fn observe_native(&mut self, output: u64, work: u64) -> Result<(), ReadFault> {
        let member = checked_sum(self.usage.member_decoded_bytes.into(), output.into())?;
        let cumulative = checked_sum(self.usage.decoded_bytes, output.into())?;
        self.usage.decoded_bytes = cumulative;
        if let Ok(actual) = u64::try_from(member) {
            self.usage.member_decoded_bytes = actual;
        }
        self.usage.work_bytes = checked_sum(self.usage.work_bytes, work.into())?;
        // All representable post-native counters are retained, even when more
        // than one quota refuses. Cumulative decoded refusal stays terminal.
        admit(ReadResource::DecodedBytes, self.limits.decoded_bytes, cumulative)?;
        admit(ReadResource::MemberDecodedBytes, self.limits.member_decoded_bytes.into(), member)?;
        admit(ReadResource::WorkBytes, self.limits.work_bytes, self.usage.work_bytes)
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
/// Checked processed caller-policy geometry; this is not allocated payload memory.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PolicyGeometry {
    pub(super) protected: u128,
    pub(super) raw_bytes: u128,
    pub(super) absolute_bytes: u128,
    pub(super) cwd_bytes: u128,
    pub(super) relative: bool,
}
// Task4 alone binds immutable source/scope identity after borrowed catalogue derivation.
#[derive(Debug)]
pub(super) struct ActionPlan {
    geometry: PlanGeometry,
    policy_bound: bool,
    diagnostic_attempts: u128,
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
    pub(super) configuration_id: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    fn bind_policy_geometry(&mut self, policy: PolicyGeometry) -> Result<u128, ReadFault> {
        if self.policy_bound || self.output_passes != 1 {
            return Err(ReadFault::InvalidPlan);
        }
        let g = self.geometry;
        let r1 = checked_sum(g.records, 1)?;
        let rg1 = checked_sum(g.regular, 1)?;
        let raw = checked_sum(policy.raw_bytes, policy.protected)?;
        if policy.absolute_bytes < raw {
            return Err(ReadFault::InvalidPlan);
        }
        let w1 = checked_sum(policy.cwd_bytes, 1)?;
        let qraw = checked_sum(checked_sum(raw, policy.absolute_bytes)?, checked_sum(w1, product(r1, w1)?)?)?;
        let canonical = checked_sum(checked_sum(policy.protected, 1)?, product(2, g.regular)?)?;
        #[cfg(target_os = "macos")]
        let (canonical_ops, qcanon, probe_tail) = {
            let h = libc::PATH_MAX as u128;
            let visits = product(34, checked_sum(h, 1)?)?;
            let n = checked_sum(product(checked_sum(h, 4)?, visits)?, 41)?;
            (product(product(2, n)?, canonical)?, product(product(2, canonical)?, visits)?, 15u128)
        };
        #[cfg(target_os = "linux")]
        let (canonical_ops, qcanon, probe_tail) =
            (product(8, canonical)?, product(canonical, checked_sum(libc::PATH_MAX as u128, 1)?)?, 17u128);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        return Err(ReadFault::UnsupportedIdentity);
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let qdir = checked_sum(product(2, g.path_bytes)?, product(210, rg1)?)?;
            let dlraw = checked_sum(checked_sum(policy.protected, 1)?, u128::from(policy.relative))?;
            let dl = checked_sum(product(4, checked_sum(checked_sum(qraw, qcanon)?, qdir)?)?, dlraw)?;
            let twice_c = product(2, self.namespace_creates.into())?;
            let probe = product(g.regular, checked_sum(twice_c, probe_tail)?)?;
            let private_dir = product(g.regular, checked_sum(twice_c, 9)?)?;
            let final_extra = checked_sum(product(11, g.regular)?, g.large_aes)?;
            let named_create = product(twice_c, g.regular)?;
            let dm = [canonical_ops, probe, private_dir, final_extra, named_create, g.regular, product(5, dl)?]
                .into_iter()
                .try_fold(0, checked_sum)?;
            let extra_attempts = product(dm, checked_sum(self.namespace_retries.into(), 1)?)?;
            let mut bounds = self.bounds;
            bounds.canonical_metadata_operations = checked_sum(bounds.canonical_metadata_operations, canonical_ops)?;
            bounds.policy_probe_operations = checked_sum(bounds.policy_probe_operations, probe)?;
            bounds.output_directory_operations = checked_sum(bounds.output_directory_operations, private_dir)?;
            bounds.storage_backend_operations = checked_sum(bounds.storage_backend_operations, g.regular)?;
            bounds.temporary_groups = checked_sum(bounds.temporary_groups, product(2, g.regular)?)?;
            bounds.path_steps = checked_sum(bounds.path_steps, dl)?;
            bounds.stage_finalization = checked_sum(bounds.stage_finalization, final_extra)?;
            bounds.io_attempts = checked_sum(bounds.io_attempts, extra_attempts)?;
            self.bounds = bounds;
            self.policy_bound = true;
            bounds.io_attempts.checked_sub(self.diagnostic_attempts).ok_or(ReadFault::CounterOverflow)
        }
    }
    pub(super) fn attempt_bound(&self) -> u128 {
        self.bounds.io_attempts
    }
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
        // Task5B actual staged AES inventory needs nine groups per regular member;
        // retain the old envelope elsewhere and reserve one staged-only group.
        let source = checked_sum(product(8, r1)?, if g.output_passes == 1 { g.regular } else { 0 })?;
        let anonymous = checked_sum(g.large_aes, if g.output_passes == 3 { g.regular } else { 0 })?;
        let anonymous_delta = if cfg!(target_os = "macos") { product(creates.into(), anonymous)? } else { 0 };
        let terminal = product(4, rg1)?;
        let stage = product(16, rg1)?;
        let dirs = product(12, rd1)?;
        let m = [
            product(3, source)?,
            product(5, l)?,
            product(product(12, creates.into())?, t)?,
            terminal,
            stage,
            dirs,
            16,
            product(2, g.regular)?,
            anonymous_delta,
        ]
        .into_iter()
        .try_fold(0, checked_sum)?;
        let attempts = product(checked_sum(checked_sum(j, m)?, 1)?, checked_sum(retries.into(), 1)?)?;
        let decode =
            product(4, checked_sum(checked_sum(g.packed, g.decoded)?, checked_sum(product(64, g.regular)?, 1)?)?)?;
        Ok(Self {
            geometry: g,
            policy_bound: false,
            diagnostic_attempts: 0,
            bounds: RunUsage {
                diagnostic_source_groups: 0,
                diagnostic_admission_operations: 0,
                canonical_metadata_operations: 0,
                policy_probe_operations: 0,
                output_directory_operations: 0,
                storage_backend_operations: anonymous,
                source_seeks: product(2, g.regular)?,
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
    pub(super) policy_metadata: PolicyMetadataUsage,
    pub(super) encrypted: EncryptedReadLedger,
    pub(super) run: RunLedger,
    pub(super) live_fds: u64,
    pub(super) peak_fds: u64,
    // The controlled engine reserves the caller's original source once. This is
    // borrowed occupancy, never authority to close or reconstruct that File.
    controlled_source: bool,
    pub(super) poisoned: bool,
    pub(super) active_encrypted: Option<bool>,
    pub(super) diagnostic_identities: [Option<(u64, u64)>; 2],
}
#[cfg(test)]
thread_local! {pub(super) static DIAGNOSTIC_BOUNDS:std::cell::Cell<Option<(u128,u128)>>=const{std::cell::Cell::new(None)};}
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
            policy_metadata: PolicyMetadataUsage::default(),
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
            peak_fds: 0,
            controlled_source: false,
            poisoned: false,
            active_encrypted: None,
            diagnostic_identities: [None; 2],
        })
    }
    pub(super) fn begin_policy_allocation(&mut self, kind: PolicyComponent, requested: usize) -> Result<(), ReadFault> {
        if self.poisoned {
            return Err(ReadFault::InvalidPlan);
        }
        let component = self.policy_metadata.component(kind);
        let next_live = component.live_allocations.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        match kind {
            PolicyComponent::Caller => {}
            PolicyComponent::Scratch => {
                admit(ReadResource::PolicyScratchAllocations, 1, next_live.into())?;
                admit(ReadResource::PolicyScratchBytes, 65536, requested as u128)?;
            }
            PolicyComponent::NativeAcl => {
                #[cfg(target_os = "macos")]
                let (count, bytes) = (2, 44 + 128 * 24);
                #[cfg(target_os = "linux")]
                let (count, bytes) = (3, 65536);
                #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                return Err(ReadFault::UnsupportedIdentity);
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                {
                    admit(ReadResource::PolicyNativeAllocations, count, next_live.into())?;
                    admit(ReadResource::PolicyNativeBytes, bytes, requested as u128)?;
                }
            }
        }
        let attempts = component.allocation_attempts.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let bytes = checked_sum(component.requested_bytes, requested as u128)?;
        component.allocations.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        component.releases.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        checked_sum(component.allocated_bytes, usize::MAX as u128)?;
        checked_sum(component.live_capacity, usize::MAX as u128)?;
        checked_sum(component.live_requested_bytes, requested as u128)?;
        component.allocation_attempts = attempts;
        component.requested_bytes = bytes;
        Ok(())
    }
    pub(super) fn acquired_policy_allocation(
        &mut self,
        kind: PolicyComponent,
        requested: usize,
        capacity: usize,
    ) -> Result<(), ReadFault> {
        let component = self.policy_metadata.component(kind);
        let allocations = component.allocations.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let live = component.live_allocations.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let allocated = checked_sum(component.allocated_bytes, capacity as u128)?;
        let live_capacity = checked_sum(component.live_capacity, capacity as u128)?;
        let live_requested = checked_sum(component.live_requested_bytes, requested as u128)?;
        component.allocations = allocations;
        component.live_allocations = live;
        component.allocated_bytes = allocated;
        component.live_capacity = live_capacity;
        component.live_requested_bytes = live_requested;
        component.peak_allocations = component.peak_allocations.max(live);
        component.peak_capacity = component.peak_capacity.max(live_capacity);
        component.peak_requested_bytes = component.peak_requested_bytes.max(live_requested);
        Ok(())
    }
    pub(super) fn release_policy_allocation(&mut self, kind: PolicyComponent, requested: usize, capacity: usize) {
        let component = self.policy_metadata.component(kind);
        component.live_allocations = component.live_allocations.checked_sub(1).expect("owned policy allocation");
        component.live_capacity = component.live_capacity.checked_sub(capacity as u128).expect("owned policy capacity");
        component.live_requested_bytes =
            component.live_requested_bytes.checked_sub(requested as u128).expect("owned policy request");
        component.releases = component.releases.checked_add(1).expect("prechecked policy release");
    }
    pub(super) fn bind(&mut self, plan: ActionPlan) -> Result<(), ReadFault> {
        if self.run.plan.is_some() || self.poisoned || plan.binding.is_none() {
            return Err(ReadFault::InvalidPlan);
        }
        self.run.plan = Some(plan);
        Ok(())
    }
    pub(super) fn bind_listing_diagnostics(&mut self) -> Result<(), ReadFault> {
        let plan = self.run.plan.as_mut().ok_or(ReadFault::InvalidPlan)?;
        if self.run.usage != RunUsage::default() || plan.bounds.diagnostic_source_groups != 0 {
            return Err(ReadFault::InvalidPlan);
        }
        plan.bounds.diagnostic_source_groups = 2;
        plan.bounds.diagnostic_admission_operations = 4;
        let attempts = product(10, checked_sum(plan.namespace_retries.into(), 1)?)?;
        plan.diagnostic_attempts = attempts;
        plan.bounds.io_attempts = checked_sum(plan.bounds.io_attempts, attempts)?;
        Ok(())
    }
    pub(super) fn bind_diagnostics(
        &mut self,
        records: u128,
        candidates: u128,
        protected: u128,
        cwd: bool,
    ) -> Result<(), ReadFault> {
        let plan = self.run.plan.as_mut().ok_or(ReadFault::InvalidPlan)?;
        if self.run.usage != RunUsage::default() || plan.bounds.diagnostic_source_groups != 0 {
            return Err(ReadFault::InvalidPlan);
        }
        let events = checked_sum(records, 2)?;
        let groups = checked_sum(2, product(2, events)?)?;
        let operations =
            [4, product(4, events)?, product(2, candidates)?, product(2, protected)?, product(2, records)?]
                .into_iter()
                .try_fold(0, checked_sum)?;
        let metadata = checked_sum(checked_sum(product(3, groups)?, operations)?, if cwd { 5 } else { 0 })?;
        if cwd {
            plan.bounds.path_steps = checked_sum(plan.bounds.path_steps, 1)?;
        }
        let attempts = product(metadata, checked_sum(plan.namespace_retries.into(), 1)?)?;
        plan.diagnostic_attempts = attempts;
        plan.bounds.diagnostic_source_groups = groups;
        plan.bounds.diagnostic_admission_operations = operations;
        plan.bounds.io_attempts = checked_sum(plan.bounds.io_attempts, attempts)?;
        #[cfg(test)]
        if let Some((groups, operations)) = DIAGNOSTIC_BOUNDS.with(|s| s.take()) {
            plan.bounds.diagnostic_source_groups = groups;
            plan.bounds.diagnostic_admission_operations = operations;
        }
        Ok(())
    }
    pub(super) fn bind_policy_geometry(&mut self, policy: PolicyGeometry) -> Result<u128, ReadFault> {
        if self.poisoned {
            return Err(ReadFault::InvalidPlan);
        }
        let result = self.run.plan.as_mut().ok_or(ReadFault::InvalidPlan)?.bind_policy_geometry(policy);
        if result.is_err() {
            self.poisoned = true;
        }
        result
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
    pub(super) fn verify_action(&self, action: &super::projected::Action) -> Result<(), ReadFault> {
        self.verify_configuration(action.identity)?;
        let binding = self.run.plan.as_ref().and_then(|p| p.binding.as_ref()).ok_or(ReadFault::InvalidPlan)?;
        if binding.scope != action.scope || binding.output != action.output {
            return Err(ReadFault::InvalidPlan);
        }
        Ok(())
    }
    pub(super) fn verify_configuration(&self, identity: u64) -> Result<(), ReadFault> {
        let binding = self.run.plan.as_ref().and_then(|p| p.binding.as_ref()).ok_or(ReadFault::InvalidPlan)?;
        if binding.configuration_id != identity {
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
    #[cfg(test)]
    pub(super) fn run_bounds(&self) -> RunUsage {
        self.run.plan.as_ref().unwrap().bounds
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
        self.peak_fds = self.peak_fds.max(self.live_fds);
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn test_limit_category(&mut self, category: RunCategory, limit: u128) {
        *self.run.plan.as_mut().unwrap().bounds.counter(category) = limit;
    }
    pub(super) fn source_registered(&self) -> bool {
        self.controlled_source
    }
    pub(super) fn register_controlled_source(&mut self) -> Result<(), ReadFault> {
        if !self.controlled_source {
            self.acquire_fds(1)?;
            self.controlled_source = true;
        }
        Ok(())
    }
    /// Cleanup-only acquisition: one already-reserved terminal operation, with
    /// existing actual/unresolved charges included and no poison reset.
    pub(super) fn acquire_cleanup_fd(&mut self) -> Result<(), ReadFault> {
        if !self.poisoned {
            return Err(ReadFault::InvalidPlan);
        }
        let next = self.live_fds.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
        let limit = self.encrypted.limits.live_fds.min(5);
        admit(ReadResource::LiveFds, limit.into(), next.into())?;
        self.charge_category(RunCategory::EmergencyCleanup, 1)?;
        self.live_fds = next;
        self.encrypted.usage.live_fds = next;
        self.peak_fds = self.peak_fds.max(next);
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
    pub(super) fn close_attempt_in(&mut self, encrypted: bool, category: Option<RunCategory>) -> Result<(), ReadFault> {
        if category.is_some_and(|c| {
            !matches!(
                c,
                RunCategory::StageFinalization
                    | RunCategory::FinalOperations
                    | RunCategory::DirectoryFinalization
                    | RunCategory::PathSteps
                    | RunCategory::CanonicalMetadataOperations
                    | RunCategory::PolicyProbeOperations
                    | RunCategory::OutputDirectoryOperations
            )
        }) {
            return Err(ReadFault::InvalidPlan);
        }
        let plan = self.run.plan.as_mut().ok_or(ReadFault::InvalidPlan)?;
        for category in [category, Some(RunCategory::IoAttempts)].into_iter().flatten() {
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
        if let Some(category) = category {
            self.charge_category(category, 1)?;
        }
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
