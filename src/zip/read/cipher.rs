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

//! The only AES plaintext capability is constructed after owned-byte HMAC.
use super::{
    shared::{LedgerAccess, LedgerView},
    spool::{OwnedCiphertext, ResolvedTempDirectory},
    *,
};
use crate::{
    crypto::{HmacSha1, WinZipCtr, ZipCrypto, derive_winzip_cancellable},
    extract::Cancellation,
};
use std::io::Read;
use subtle::ConstantTimeEq;

/// A retained source, with a checked final observation; never a reopened path.
pub(super) trait CiphertextSource: Read {
    fn verify_source(&mut self, ledger: LedgerView<'_>) -> Result<(), io::SourceCheckError>;
}
/// Adapter for the retained Session/SourceBinding check in Task4. The closure
/// may inspect the borrowed context because no ledger RefMut crosses a call.
#[cfg_attr(not(test), allow(dead_code))] // Task4 retained source adapter; tests provide real checked sources.
pub(super) struct CheckedInput<R, F> {
    pub(super) reader: R,
    pub(super) check: F,
}
impl<R: Read, F> Read for CheckedInput<R, F> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(bytes)
    }
}
impl<R: Read, F: FnMut(LedgerView<'_>) -> Result<(), io::SourceCheckError>> CiphertextSource for CheckedInput<R, F> {
    fn verify_source(&mut self, ledger: LedgerView<'_>) -> Result<(), io::SourceCheckError> {
        (self.check)(ledger)
    }
}

pub(super) struct PendingAes<'a, 's> {
    owned: OwnedCiphertext<'a>,
    ledger: LedgerView<'a>,
    source: &'s mut dyn CiphertextSource,
    plan: budget::MemberPlan,
    crc_required: bool,
    hmac: HmacSha1,
    key: [u8; 32],
    key_len: usize,
    tag: [u8; 10],
}
pub(super) struct AuthenticatedAes<'a, 's> {
    owned: OwnedCiphertext<'a>,
    pub(super) ledger: LedgerView<'a>,
    source: &'s mut dyn CiphertextSource,
    pub(super) plan: budget::MemberPlan,
    pub(super) crc_required: bool,
    ctr: WinZipCtr,
    remaining: u64,
}
#[allow(clippy::result_large_err)] // Fixed inline failure evidence; never Box on failure.
pub(super) fn checked<T>(
    result: ZipReadResult<T>,
    source: &mut dyn CiphertextSource,
    ledger: LedgerView<'_>,
) -> ZipReadResult<T> {
    let result = match source.verify_source(ledger) {
        Ok(()) => result,
        Err(io::SourceCheckError::Source(fault)) => Err(match result {
            Ok(_) => fault.into(),
            Err(error) => error.merge_source(fault),
        }),
        Err(io::SourceCheckError::Admission(fault)) => match result {
            Ok(_) => Err(fault.into()),
            Err(error) => {
                // A source check that could not run is not SourceChanged, but
                // its refusal must stop continuation of a recoverable member
                // error. The existing Source finalization slots expose this
                // typed evidence while preserving primary/sink precedence.
                let mut report = ObjectCleanupReport::new(OwnedObject::Source);
                report.push(CleanupFault {
                    object: OwnedObject::Source,
                    operation: ReadIoOperation::Stat,
                    offset: None,
                    cause: CleanupCause::Admission(fault),
                    close: CloseDisposition::NotApplicable,
                });
                Err(error.merge_cleanup(report))
            }
        },
    };
    result.map_err(|error| ledger.with_state(|s| error.with_usage(s.encrypted.usage, s.run.usage)))
}
#[derive(Clone, Copy)]
pub(super) enum InputKind {
    #[cfg_attr(not(test), allow(dead_code))] // Task4 clear-member dispatcher.
    Clear,
    #[cfg_attr(not(test), allow(dead_code))] // Task4 encrypted-member dispatcher.
    ZipCrypto { descriptor: bool, time: u8 },
    #[cfg_attr(not(test), allow(dead_code))] // Task4 AES metadata dispatcher.
    Aes { strength: u8, version: u16 },
}
/// Owns one charged member attempt and the original source borrow. No decoder
/// or workspace allocation can precede admission. This proof is consumed once.
pub(super) struct Admission<'a, 's, 'p> {
    ledger: LedgerView<'a>,
    plan: budget::MemberPlan,
    source: &'s mut dyn CiphertextSource,
    password: &'p str,
    kind: InputKind,
    key_len: usize,
}
impl<'a, 's, 'p> Admission<'a, 's, 'p> {
    #[cfg_attr(not(test), allow(dead_code))] // Task4 admission precedes workspace acquisition.
    #[allow(clippy::result_large_err)] // Fixed inline terminal evidence.
    pub(super) fn new(
        ledger: &'a impl LedgerAccess,
        source: &'s mut dyn CiphertextSource,
        plan: budget::MemberPlan,
        password: Option<&'p str>,
        kind: InputKind,
    ) -> ZipReadResult<Self> {
        let view = ledger.view();
        checked(Ok(()), source, view)?;
        let result = (|| -> Result<usize, ReadFault> {
            let cipher = match kind {
                InputKind::Clear => None,
                InputKind::ZipCrypto { .. } => Some(CipherKind::ZipCrypto),
                InputKind::Aes { .. } => Some(CipherKind::Aes),
            };
            view.with_state(|s| s.verify_member_kind(&plan, cipher))?;
            if plan.crc.is_none() && !matches!(kind, InputKind::Aes { version: 2, .. }) {
                return Err(if cipher.is_some() {
                    view.with_state(|s| s.encrypted.reject_member(plan.packed, ReadFault::InvalidPlan))
                } else {
                    ReadFault::InvalidPlan
                });
            }
            if cipher.is_none() {
                return if plan.ciphertext == plan.packed { Ok(0) } else { Err(ReadFault::InvalidPlan) };
            }
            let key_len = match kind {
                InputKind::Aes { strength, version: 1 | 2 } => match strength {
                    1 => 16,
                    2 => 24,
                    3 => 32,
                    _ => 0,
                },
                _ => 0,
            };
            let framing = if cipher == Some(CipherKind::Aes) { key_len as u64 / 2 + 12 } else { 12 };
            let rejection = if cipher == Some(CipherKind::Aes) && key_len == 0 {
                Some(ReadFault::CheckedFormat { reason: "invalid AES metadata" })
            } else if plan.packed.checked_sub(framing) != Some(plan.ciphertext) {
                Some(ReadFault::CheckedFormat { reason: "invalid cipher framing" })
            } else if password.is_none_or(str::is_empty) {
                Some(ReadFault::PasswordRequired)
            } else {
                None
            };
            if let Some(rejection) = rejection {
                return Err(view.with_state(|s| s.encrypted.reject_member(plan.packed, rejection)));
            }
            view.with_state(|s| {
                s.encrypted.begin_member_with_crc(
                    plan.packed,
                    plan.decoded,
                    plan.ciphertext,
                    password.unwrap().len() as u64,
                    cipher == Some(CipherKind::Aes),
                    plan.crc.is_some() && !matches!(kind, InputKind::Aes { version: 2, .. }),
                )
            })?;
            Ok(key_len)
        })();
        let key_len = match result {
            Ok(value) => value,
            Err(fault) => return checked(Err(fault.into()), source, view),
        };
        Ok(Self { ledger: view, source, plan, password: password.unwrap_or(""), kind, key_len })
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 consumes proof before copy/auth/decode.
    #[allow(clippy::result_large_err)] // Fixed inline errors, including refused source completion.
    pub(super) fn workspace(self) -> ZipReadResult<(Self, super::codecs::Workspace<'a>)> {
        match super::codecs::Workspace::acquire(self.ledger, &self.plan) {
            Ok(workspace) => Ok((self, workspace)),
            Err(error) => checked(Err(error), self.source, self.ledger),
        }
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 aborts after lazy-directory/pre-cipher dispatch failure.
    #[allow(clippy::result_large_err)] // Same typed source finalization; admission owns no payload yet.
    pub(super) fn finish(self, result: ZipReadResult<()>) -> ZipReadResult<()> {
        checked(result, self.source, self.ledger)
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 clear dispatch consumes admitted retained source.
    #[allow(clippy::result_large_err)] // Fixed inline evidence.
    pub(super) fn clear(self) -> ZipReadResult<super::codecs::PlainInput<'a, 's>> {
        if !matches!(self.kind, InputKind::Clear) {
            return checked(Err(ReadFault::InvalidPlan.into()), self.source, self.ledger);
        }
        Ok(super::codecs::PlainInput::Clear(super::codecs::ClearInput {
            ledger: self.ledger,
            source: self.source,
            plan: self.plan,
            remaining: self.plan.packed,
        }))
    }
}
impl<'a, 's> PendingAes<'a, 's> {
    #[allow(clippy::too_many_arguments, clippy::result_large_err)] // Narrow private framing seam; fixed errors.
    #[cfg(test)] // Standalone Task2 convenience; production consumes admitted proof.
    pub(super) fn copy(
        ledger: &'a impl LedgerAccess,
        directory: &ResolvedTempDirectory,
        source: &'s mut dyn CiphertextSource,
        strength: u8,
        vendor_version: u16,
        plan: budget::MemberPlan,
        password: Option<&str>,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let admission =
            Admission::new(ledger, source, plan, password, InputKind::Aes { strength, version: vendor_version })?;
        Self::copy_admitted(admission, Some(directory), scratch, cancel)
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 consumes admitted proof after workspace acquisition.
    #[allow(clippy::result_large_err)] // Fixed inline terminal evidence.
    pub(super) fn copy_admitted(
        admission: Admission<'a, 's, '_>,
        directory: Option<&ResolvedTempDirectory>,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let Admission { ledger: view, source, plan, password, kind, key_len } = admission;
        if !matches!(kind, InputKind::Aes { .. }) {
            return checked(Err(ReadFault::InvalidPlan.into()), source, view);
        }
        let len = plan.ciphertext;
        let keys = (|| -> Result<([u8; 66], usize, u64), ReadFault> {
            io::canceled(Some(cancel))?;
            let mut salt = [0; 16];
            let mut verifier = [0; 2];
            spool::read_exact(view, source, &mut salt[..key_len / 2], IoStage::Source, cancel)?;
            spool::read_exact(view, source, &mut verifier, IoStage::Source, cancel)?;
            let keys = derive_winzip_cancellable(password.as_bytes(), &salt[..key_len / 2], key_len, || {
                io::canceled(Some(cancel))
            })?
            .ok_or(ReadFault::InvalidPlan)?;
            if !bool::from(keys[2 * key_len..2 * key_len + 2].ct_eq(&verifier)) {
                return Err(ReadFault::PasswordCheckFailed { cipher: CipherKind::Aes });
            }
            Ok((keys, key_len, len))
        })();
        let (keys, key_len, len) = match keys {
            Ok(v) => v,
            Err(e) => return checked(Err(e.into()), source, view),
        };
        // Verifier failure above never acquires owned payload storage.
        let mut owned = match OwnedCiphertext::copy_view(view, directory, source, len, scratch, cancel) {
            Ok(owned) => owned,
            Err(error) => return checked(Err(error), source, view),
        };
        let mut tag = [0; 10];
        if let Err(e) = spool::read_exact(view, source, &mut tag, IoStage::Source, cancel) {
            return checked(Err(owned.finish_error(e.into())), source, view);
        }
        // Copy completion is also a source observation boundary.
        if let Err(e) = checked(Ok(()), source, view) {
            return Err(owned.finish_error(e));
        }
        // Rewind is required even for a memory snapshot (and checked for files).
        if let Err(e) = owned.rewind(cancel) {
            return checked(Err(owned.finish_error(e.into())), source, view);
        }
        let mut key = [0; 32];
        key[..key_len].copy_from_slice(&keys[..key_len]);
        Ok(Self {
            owned,
            ledger: view,
            source,
            plan,
            crc_required: matches!(kind, InputKind::Aes { version: 1, .. }),
            hmac: HmacSha1::new(&keys[key_len..2 * key_len]),
            key,
            key_len,
            tag,
        })
    }
    #[allow(clippy::result_large_err)]
    #[cfg_attr(not(test), allow(dead_code))] // Task4 authenticates before constructing the Task3 pump.
    pub(super) fn authenticate(
        mut self,
        scratch: &mut [u8],
        cancel: &Cancellation,
    ) -> ZipReadResult<AuthenticatedAes<'a, 's>> {
        let result = (|| -> Result<(), ReadFault> {
            if scratch.is_empty() || scratch.len() > io::WINDOW {
                return Err(ReadFault::InvalidPlan);
            }
            loop {
                let n = self.owned.read_chunk(scratch, cancel)?;
                if n == 0 {
                    break;
                }
                self.ledger.with_state(|s| s.encrypted.work(n as u64))?;
                self.hmac.update(&scratch[..n]).ok_or(ReadFault::CounterOverflow)?;
            }
            if !bool::from(self.hmac.finish()[..10].ct_eq(&self.tag)) {
                return Err(ReadFault::AuthenticationFailed);
            }
            io::canceled(Some(cancel))?;
            self.owned.rewind(cancel)
        })();
        if let Err(error) = result {
            return checked(Err(self.owned.finish_error(error.into())), self.source, self.ledger);
        }
        if let Err(error) = checked(Ok(()), self.source, self.ledger) {
            return Err(self.owned.finish_error(error));
        }
        if let Err(e) = io::canceled(Some(cancel)) {
            return checked(Err(self.owned.finish_error(e.into())), self.source, self.ledger);
        }
        let remaining = self.owned.len();
        let ctr = WinZipCtr::new(&self.key[..self.key_len]).expect("validated AES key size");
        Ok(AuthenticatedAes {
            plan: self.plan,
            owned: self.owned,
            ledger: self.ledger,
            source: self.source,
            crc_required: self.crc_required,
            ctr,
            remaining,
        })
    }
    #[allow(clippy::result_large_err)]
    #[cfg_attr(not(test), allow(dead_code))] // Task4 explicit pre-authentication abort.
    pub(super) fn finish(self, result: ZipReadResult<()>) -> ZipReadResult<()> {
        let result = match self.owned.finish() {
            Ok(()) => result,
            Err(report) => Err(match result {
                Ok(()) => report.into(),
                Err(e) => e.merge_cleanup(report),
            }),
        };
        checked(result, self.source, self.ledger)
    }
}
impl AuthenticatedAes<'_, '_> {
    #[allow(clippy::result_large_err)]
    pub(super) fn read_plain_chunk(&mut self, out: &mut [u8], cancel: &Cancellation) -> ZipReadResult<usize> {
        let result = (|| -> Result<usize, ReadFault> {
            io::canceled(Some(cancel))?;
            if out.is_empty() && self.remaining > 0 {
                return Err(ReadFault::InvalidPlan);
            }
            let n = self.owned.read_chunk(out, cancel)?;
            self.ledger.with_state(|s| s.encrypted.work(n as u64))?;
            self.ctr.apply(&mut out[..n]).ok_or(ReadFault::CounterOverflow)?;
            self.remaining = self.remaining.checked_sub(n as u64).ok_or(ReadFault::CounterOverflow)?;
            Ok(n)
        })();
        result.map_err(|e| self.ledger.with_state(|s| ZipReadError::from(e).with_usage(s.encrypted.usage, s.run.usage)))
    }
    #[allow(clippy::result_large_err)]
    pub(super) fn finish(self, result: ZipReadResult<()>) -> ZipReadResult<()> {
        let result = result.and_then(|()| {
            if self.remaining == 0 {
                Ok(())
            } else {
                Err(ReadFault::CheckedFormat { reason: "ciphertext not fully consumed" }.into())
            }
        });
        let result = match self.owned.finish() {
            Ok(()) => result,
            Err(report) => Err(match result {
                Ok(()) => report.into(),
                Err(e) => e.merge_cleanup(report),
            }),
        };
        checked(result, self.source, self.ledger)
    }
}

/// Weak header evidence; this capability never claims authentication.
pub(super) struct ZipCryptoInput<'a, 's> {
    pub(super) ledger: LedgerView<'a>,
    source: &'s mut dyn CiphertextSource,
    pub(super) plan: budget::MemberPlan,
    cipher: ZipCrypto,
    remaining: u64,
}
impl<'a, 's> ZipCryptoInput<'a, 's> {
    #[allow(clippy::result_large_err, clippy::too_many_arguments)]
    #[cfg(test)] // Standalone Task2 convenience; production consumes admitted proof.
    pub(super) fn open(
        ledger: &'a impl LedgerAccess,
        source: &'s mut dyn CiphertextSource,
        password: Option<&str>,
        plan: budget::MemberPlan,
        descriptor: bool,
        local_time_high: u8,
        cancel: &Cancellation,
    ) -> ZipReadResult<Self> {
        let admission =
            Admission::new(ledger, source, plan, password, InputKind::ZipCrypto { descriptor, time: local_time_high })?;
        Self::open_admitted(admission, cancel)
    }
    #[cfg_attr(not(test), allow(dead_code))] // Task4 consumes admitted ZipCrypto proof after workspace acquisition.
    #[allow(clippy::result_large_err)] // Fixed inline terminal evidence.
    pub(super) fn open_admitted(admission: Admission<'a, 's, '_>, cancel: &Cancellation) -> ZipReadResult<Self> {
        let Admission { ledger: view, source, plan, password, kind, .. } = admission;
        let InputKind::ZipCrypto { descriptor, time: local_time_high } = kind else {
            return checked(Err(ReadFault::InvalidPlan.into()), source, view);
        };
        let result = (|| -> Result<(ZipCrypto, u64), ReadFault> {
            let remaining = plan.ciphertext;
            let mut cipher = ZipCrypto::new_cancellable(password, || io::canceled(Some(cancel)))?;
            let mut header = [0; 12];
            spool::read_exact(view, source, &mut header, IoStage::Source, cancel)?;
            view.with_state(|s| s.encrypted.work(12))?;
            cipher.decrypt(&mut header);
            if header[11]
                != if descriptor { local_time_high } else { (plan.crc.ok_or(ReadFault::InvalidPlan)? >> 24) as u8 }
            {
                return Err(ReadFault::PasswordCheckFailed { cipher: CipherKind::ZipCrypto });
            }
            Ok((cipher, remaining))
        })();
        let (cipher, remaining) = checked(result.map_err(Into::into), source, view)?;
        Ok(Self { ledger: view, source, plan, cipher, remaining })
    }
    #[allow(clippy::result_large_err)]
    pub(super) fn read_plain_chunk(&mut self, out: &mut [u8], cancel: &Cancellation) -> ZipReadResult<usize> {
        let result = (|| -> Result<usize, ReadFault> {
            io::canceled(Some(cancel))?;
            if self.remaining == 0 {
                return Ok(0);
            }
            let count = out.len().min(io::WINDOW).min(self.remaining.min(io::WINDOW as u64) as usize);
            if count == 0 {
                return Err(ReadFault::InvalidPlan);
            }
            let n = io::read(&self.ledger, true, self.source, IoStage::Source, 0, &mut out[..count], cancel)?;
            if n == 0 {
                return Err(ReadFault::Io {
                    stage: IoStage::Source,
                    operation: ReadIoOperation::Read,
                    offset: 0,
                    error: std::io::ErrorKind::UnexpectedEof.into(),
                });
            }
            self.ledger.with_state(|s| s.encrypted.work(n as u64))?;
            self.cipher.decrypt(&mut out[..n]);
            self.remaining -= n as u64;
            Ok(n)
        })();
        result.map_err(|e| self.ledger.with_state(|s| ZipReadError::from(e).with_usage(s.encrypted.usage, s.run.usage)))
    }
    #[allow(clippy::result_large_err)]
    pub(super) fn finish(self, result: ZipReadResult<()>) -> ZipReadResult<()> {
        let result = result.and_then(|()| {
            if self.remaining == 0 {
                Ok(())
            } else {
                Err(ReadFault::CheckedFormat { reason: "ZipCrypto payload not fully consumed" }.into())
            }
        });
        checked(result, self.source, self.ledger)
    }
}
