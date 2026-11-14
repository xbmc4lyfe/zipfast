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

//! Low-level progress and exact frame boundaries, with no Read erasure.
use super::{EncryptedReadOptions, IntegrityReason};
mod bzip2;
mod deflate;
mod lzma;
mod xz;
mod zstd;
enum State {
    Stored,
    Deflate(deflate::Decoder),
    Bzip(bzip2::Decoder),
    Lzma(lzma::Decoder),
    Xz(xz::Decoder),
    Zstd(zstd::Decoder),
}
pub(super) struct Engine {
    state: State,
    complete_frame: bool,
}
pub(super) struct Progress {
    pub(super) consumed: usize,
    pub(super) produced: usize,
    pub(super) fault: Option<IntegrityReason>,
    pub(super) end: bool,
}
impl Engine {
    pub(super) fn new(method: u16, options: &EncryptedReadOptions) -> Result<Self, IntegrityReason> {
        Ok(Self {
            state: match method {
                0 => State::Stored,
                8 => State::Deflate(deflate::Decoder::new(options)?),
                12 => State::Bzip(bzip2::Decoder::new(options)?),
                14 => State::Lzma(lzma::Decoder::new(options)?),
                95 => State::Xz(xz::Decoder::new(options)?),
                93 => State::Zstd(zstd::Decoder::new(options)?),
                _ => return Err(IntegrityReason::Decoder),
            },
            complete_frame: false,
        })
    }
    pub(super) fn step(&mut self, input: &[u8], output: &mut [u8], last: bool) -> Progress {
        let progress = match &mut self.state {
            State::Stored => {
                let n = input.len().min(output.len());
                output[..n].copy_from_slice(&input[..n]);
                Progress { consumed: n, produced: n, fault: None, end: last && n == input.len() }
            }
            State::Deflate(z) => z.step(input, output, last),
            State::Bzip(z) => z.step(input, output, last),
            State::Lzma(z) => z.step(input, output, last),
            State::Xz(z) => z.step(input, output, last),
            State::Zstd(z) => z.step(input, output, last),
        };
        self.complete_frame = progress.end;
        progress
    }
    /// Proves real input consumption and completed frame state independently of
    /// a full output buffer or the caller's expected decoded length.
    pub(super) fn finish_exact(&self, consumed: u64, declared: u64) -> Result<(), IntegrityReason> {
        if consumed != declared {
            return Err(IntegrityReason::TrailingData);
        }
        if !self.complete_frame {
            return Err(IntegrityReason::Truncated);
        }
        Ok(())
    }
    pub(super) fn next_frame(&mut self) {
        self.complete_frame = false;
        if let State::Bzip(z) = &mut self.state {
            z.next_frame();
        }
    }
}
