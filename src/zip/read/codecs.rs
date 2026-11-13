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

//! Exact bounded codec pumps. Native codec state has its own memory policy.
use super::{
    budget::MemberPlan,
    cipher::{self, AuthenticatedAes, CiphertextSource, ZipCryptoInput},
    shared::{LedgerAccess, LedgerView},
    *,
};

// Conservatively reserved fixed Rust control scratch: inline terminal error/report,
// synthetic LZMA header, codec control state and bounded call-local scalars.
const CONTROL_CAPACITY: u64 = 16 << 10;
pub(super) struct Workspace<'a> {
    ledger: LedgerView<'a>,
    pub(super) input: Vec<u8>,
    output: Vec<u8>,
    reserved: u64,
    plan: MemberPlan,
}
impl<'a> Workspace<'a> {
    #[allow(clippy::result_large_err)] // Fixed inline terminal evidence must not allocate.
    pub(super) fn acquire(view: LedgerView<'a>, plan: &MemberPlan) -> ZipReadResult<Self> {
        view.with_state(|s| s.verify_member_kind(plan, plan.cipher))?;
        let encrypted = plan.cipher.is_some();
        let mut workspace = Self { ledger: view, input: Vec::new(), output: Vec::new(), reserved: 0, plan: *plan };
        let result = (|| -> Result<(), ReadFault> {
            view.with_state(|s| s.reserve_capacity(CONTROL_CAPACITY))?;
            workspace.reserved += CONTROL_CAPACITY;
            for buffer in [&mut workspace.input, &mut workspace.output] {
                view.with_state(|s| {
                    if encrypted {
                        s.encrypted.allocation(io::WINDOW as u64)
                    } else {
                        s.reserve_capacity(io::WINDOW as u64)
                    }
                })?;
                workspace.reserved += io::WINDOW as u64;
                buffer.try_reserve_exact(io::WINDOW).map_err(|_| ReadFault::Allocation { capacity: io::WINDOW })?;
                assert_eq!(buffer.capacity(), io::WINDOW);
                buffer.resize(io::WINDOW, 0);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(workspace),
            Err(error) => Err(error.into()),
        }
    }
}
impl Drop for Workspace<'_> {
    fn drop(&mut self) {
        self.ledger.with_state(|s| {
            s.release_capacity(self.reserved);
        });
    }
}
pub(super) struct ClearInput<'a, 's> {
    pub(super) ledger: LedgerView<'a>,
    pub(super) source: &'s mut dyn CiphertextSource,
    pub(super) plan: MemberPlan,
    pub(super) remaining: u64,
}
#[allow(clippy::large_enum_variant)] // Inline authenticated capability (528 bytes); no extra owner/allocation.
pub(super) enum PlainInput<'a, 's> {
    Clear(ClearInput<'a, 's>),
    ZipCrypto(ZipCryptoInput<'a, 's>),
    Aes(AuthenticatedAes<'a, 's>),
}
impl PlainInput<'_, '_> {
    fn ledger(&self) -> LedgerView<'_> {
        match self {
            Self::Clear(v) => v.ledger,
            Self::ZipCrypto(v) => v.ledger,
            Self::Aes(v) => v.ledger,
        }
    }
    fn crc(&self) -> Option<u32> {
        match self {
            Self::Aes(v) if !v.crc_required => None,
            _ => self.plan().crc,
        }
    }
    fn plan(&self) -> MemberPlan {
        match self {
            Self::Clear(v) => v.plan,
            Self::ZipCrypto(v) => v.plan,
            Self::Aes(v) => v.plan,
        }
    }
    #[allow(clippy::result_large_err)] // Inline 4352-byte terminal evidence; no failure allocation.
    fn read(&mut self, bytes: &mut [u8], cancel: &Cancellation) -> ZipReadResult<usize> {
        match self {
            Self::Aes(v) => v.read_plain_chunk(bytes, cancel),
            Self::ZipCrypto(v) => v.read_plain_chunk(bytes, cancel),
            Self::Clear(v) => {
                io::canceled(Some(cancel))?;
                if v.remaining == 0 {
                    return Ok(0);
                }
                let count = bytes.len().min(v.remaining.min(io::WINDOW as u64) as usize);
                if count == 0 {
                    return Err(ReadFault::InvalidPlan.into());
                }
                let n = io::read(
                    &v.ledger,
                    false,
                    v.source,
                    IoStage::Source,
                    v.plan.packed - v.remaining,
                    &mut bytes[..count],
                    cancel,
                )?;
                if n == 0 {
                    return Err(ReadFault::Io {
                        stage: IoStage::Source,
                        operation: ReadIoOperation::Read,
                        offset: v.plan.packed - v.remaining,
                        error: std::io::ErrorKind::UnexpectedEof.into(),
                    }
                    .into());
                }
                v.remaining -= n as u64;
                Ok(n)
            }
        }
    }
    #[allow(clippy::result_large_err)] // Inline terminal evidence includes explicit source/input finalization.
    fn finish(self, result: ZipReadResult<()>) -> ZipReadResult<()> {
        match self {
            Self::Aes(v) => v.finish(result),
            Self::ZipCrypto(v) => v.finish(result),
            Self::Clear(v) => {
                let result =
                    result.and_then(|()| if v.remaining == 0 { Ok(()) } else { Err(ReadFault::InvalidPlan.into()) });
                cipher::checked(result, v.source, v.ledger)
            }
        }
    }
}
#[path = "codec/mod.rs"]
mod native;
use native::Engine;
fn step_charge(ledger: LedgerView<'_>, encrypted: bool, cancel: &Cancellation) -> Result<(), ReadFault> {
    io::canceled(Some(cancel))?;
    ledger.with_state(|s| {
        s.charge_category(RunCategory::DecodeSteps, 1)?;
        if encrypted {
            s.encrypted.decode(0, 0)?;
        }
        Ok(())
    })
}
fn byte_charge(
    ledger: LedgerView<'_>,
    encrypted: bool,
    consumed: usize,
    produced: usize,
    crc: bool,
) -> Result<(), ReadFault> {
    if encrypted {
        // Steps are charged independently before native calls/refill/compaction.
        ledger.with_state(|s| {
            s.encrypted.decode_bytes(produced as u64, consumed as u128 + produced as u128 * if crc { 2 } else { 1 })
        })?;
    }
    Ok(())
}
fn output_allowance(decoded: u64, declared: u64) -> Result<usize, ReadFault> {
    let remaining = u128::from(declared).checked_sub(decoded.into()).ok_or(ReadFault::CounterOverflow)?;
    let probe = remaining.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
    Ok(probe.min(io::WINDOW as u128) as usize)
}
fn observe_native(ledger: LedgerView<'_>, encrypted: bool, produced: usize, work: usize) -> Result<(), ReadFault> {
    if encrypted {
        ledger.with_state(|s| s.encrypted.observe_native(produced as u64, work as u64))?;
    }
    Ok(())
}
#[derive(Debug)]
pub(super) struct DecodeReceipt {
    pub(super) consumed: u64,
    pub(super) decoded: u64,
}
#[allow(clippy::result_large_err)] // Fixed inline terminal evidence; includes input cleanup errors.
pub(super) fn decode(
    mut input: PlainInput<'_, '_>,
    workspace: &mut Workspace<'_>,
    method: u16,
    flags: u16,
    options: &EncryptedReadOptions,
    cancel: &Cancellation,
    sink: &mut impl FnMut(&[u8]) -> ZipSinkResult<()>,
) -> ZipReadResult<DecodeReceipt> {
    let plan = input.plan();
    let encrypted = plan.cipher.is_some();
    let expected_crc = input.crc();
    let evidence = match &input {
        PlainInput::Clear(_) => PasswordEvidence::NotEncrypted,
        PlainInput::ZipCrypto(_) => PasswordEvidence::HeaderMatched,
        PlainInput::Aes(_) => PasswordEvidence::Authenticated,
    };
    let integrity = |reason| ZipReadError::from(ReadFault::Integrity { reason, password_evidence: evidence });
    let mut consumed = 0u64;
    let mut decoded = 0u64;
    let mut accepted = 0u64;
    let result = (|| -> ZipReadResult<()> {
        if input.ledger().identity() != workspace.ledger.identity() || plan != workspace.plan {
            return Err(ReadFault::InvalidPlan.into());
        }
        // Do not use policy setters on unvalidated Options assembled internally.
        if options.lzma_memory_bytes == 0
            || options.lzma_memory_bytes > 256 << 20
            || !(10..=27).contains(&options.zstd_window_log_max)
        {
            return Err(ReadFault::InvalidPlan.into());
        }
        if !matches!(method, 0 | 8 | 12 | 14 | 95 | 93) {
            return Err(ReadFault::UnsupportedMethod { method }.into());
        }
        step_charge(workspace.ledger, encrypted, cancel)?;
        let mut engine = Engine::new(method, options).map_err(integrity)?;
        let mut fetched = 0u64;
        let mut begin = 0usize;
        let mut end = 0usize;
        let mut crc = crc32fast::Hasher::new();
        if method == 14 {
            // Nine real ZIP bytes become thirteen synthetic .lzma header bytes.
            let mut header = [0u8; 9];
            let mut have = 0;
            while have < header.len() {
                step_charge(workspace.ledger, encrypted, cancel)?;
                if fetched == plan.ciphertext {
                    return Err(integrity(IntegrityReason::Truncated));
                }
                let n = input.read(&mut header[have..], cancel)?;
                if n == 0 {
                    return Err(integrity(IntegrityReason::Truncated));
                }
                have += n;
                fetched += n as u64;
                byte_charge(workspace.ledger, encrypted, n, 0, false)?;
            }
            if header[2..4] != [5, 0] {
                return Err(integrity(IntegrityReason::Framing));
            }
            let mut synthetic = [0u8; 13];
            synthetic[..5].copy_from_slice(&header[4..]);
            synthetic[5..].copy_from_slice(&if flags & 2 != 0 { u64::MAX } else { plan.decoded }.to_le_bytes());
            step_charge(workspace.ledger, encrypted, cancel)?;
            let output_limit = output_allowance(decoded, plan.decoded)?;
            let p = engine.step(&synthetic, &mut workspace.output[..output_limit], false);
            observe_native(workspace.ledger, encrypted, p.produced, p.consumed + p.produced)?;
            if p.fault.is_some() || p.consumed != synthetic.len() || p.produced != 0 || p.end {
                return Err(integrity(IntegrityReason::Framing));
            }
            // Synthetic translation work is distinct from real compressed C.
            consumed = 9;
        }
        let mut refill = true;
        loop {
            if refill && fetched < plan.ciphertext {
                step_charge(workspace.ledger, encrypted, cancel)?;
                if begin != 0 {
                    step_charge(workspace.ledger, encrypted, cancel)?;
                    workspace.input.copy_within(begin..end, 0);
                    end -= begin;
                    begin = 0;
                }
                if end == workspace.input.len() {
                    return Err(integrity(IntegrityReason::Stalled));
                }
                let count =
                    (workspace.input.len() - end).min((plan.ciphertext - fetched).min(io::WINDOW as u64) as usize);
                let mut remaining = count;
                while remaining != 0 {
                    step_charge(workspace.ledger, encrypted, cancel)?;
                    let n = input.read(&mut workspace.input[end..end + remaining], cancel)?;
                    if n == 0 {
                        return Err(integrity(IntegrityReason::Truncated));
                    }
                    fetched += n as u64;
                    end += n;
                    remaining -= n;
                }
            }
            step_charge(workspace.ledger, encrypted, cancel)?;
            // For ZIP LZMA preserve the entire final fixed input window until
            // it can be offered with Finish. In particular an optional marker
            // after known U must not be split across a Run/Finish boundary.
            let remaining_real = plan.ciphertext - consumed;
            let offered = if method == 14 && remaining_real > io::WINDOW as u64 {
                (end - begin).min((remaining_real - io::WINDOW as u64).min(io::WINDOW as u64) as usize)
            } else {
                end - begin
            };
            let output_limit = output_allowance(decoded, plan.decoded)?;
            let p = engine.step(
                &workspace.input[begin..begin + offered],
                &mut workspace.output[..output_limit],
                fetched == plan.ciphertext,
            );
            if p.consumed > offered || p.produced > output_limit {
                return Err(ReadFault::InvalidPlan.into());
            }
            observe_native(workspace.ledger, encrypted, p.produced, p.consumed + p.produced)?;
            begin += p.consumed;
            consumed = consumed.checked_add(p.consumed as u64).ok_or(ReadFault::CounterOverflow)?;
            let next = u128::from(decoded).checked_add(p.produced as u128).ok_or(ReadFault::CounterOverflow)?;
            if next > u128::from(plan.decoded) {
                return Err(integrity(IntegrityReason::DecodedSize));
            }
            if let Some(reason) = p.fault {
                return Err(integrity(reason));
            }
            decoded = u64::try_from(next).map_err(|_| ReadFault::CounterOverflow)?;
            if p.produced != 0 {
                io::canceled(Some(cancel))?;
                if expected_crc.is_some() {
                    if encrypted {
                        workspace.ledger.with_state(|s| s.encrypted.work(p.produced as u64))?;
                    }
                    crc.update(&workspace.output[..p.produced]);
                }
                sink(&workspace.output[..p.produced]).map_err(ZipReadError::from)?;
                accepted = decoded;
                // Cancellation from the callback is observed only after its first
                // actual failure has been given priority above.
                io::canceled(Some(cancel))?;
            }
            if p.end {
                step_charge(workspace.ledger, encrypted, cancel)?;
                if consumed == plan.ciphertext {
                    break;
                }
                if matches!(method, 12 | 93) {
                    engine.next_frame();
                    refill = begin == end;
                    continue;
                }
                return Err(integrity(IntegrityReason::TrailingData));
            }
            if p.consumed == 0 && p.produced == 0 {
                if fetched == plan.ciphertext {
                    return Err(integrity(IntegrityReason::Truncated));
                }
                refill = true;
            } else {
                refill = begin == end
                    || (method == 14 && fetched < plan.ciphertext && plan.ciphertext - consumed <= io::WINDOW as u64);
            }
        }
        engine.finish_exact(consumed, plan.ciphertext).map_err(integrity)?;
        if decoded != plan.decoded {
            return Err(integrity(IntegrityReason::DecodedSize));
        }
        if expected_crc.is_some_and(|expected| crc.finalize() != expected) {
            return Err(integrity(IntegrityReason::Checksum));
        }
        Ok(())
    })();
    input.finish(result).map_err(|error| {
        let retained = error.accepted_output_bytes().max(accepted);
        error.accepted(retained)
    })?;
    Ok(DecodeReceipt { consumed, decoded })
}

#[cfg(test)]
pub(super) fn control_layout() -> [usize; 7] {
    [
        std::mem::size_of::<Engine>(),
        std::mem::size_of::<PlainInput<'_, '_>>(),
        std::mem::size_of::<Workspace<'_>>(),
        std::mem::size_of::<cipher::PendingAes<'_, '_>>(),
        std::mem::size_of::<cipher::Admission<'_, '_, '_>>(),
        std::mem::size_of::<crc32fast::Hasher>(),
        CONTROL_CAPACITY as usize,
    ]
}
