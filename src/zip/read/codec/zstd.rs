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

//! Native zstd slice progress adapter.
use super::{EncryptedReadOptions, IntegrityReason, Progress};
use zstd::stream::raw::Operation;
pub(in crate::zip::read::codecs) struct Decoder(zstd::stream::raw::Decoder<'static>);
impl Decoder {
    pub(in crate::zip::read::codecs) fn new(options: &EncryptedReadOptions) -> Result<Self, IntegrityReason> {
        let mut z = zstd::stream::raw::Decoder::new().map_err(|_| IntegrityReason::Decoder)?;
        z.set_parameter(zstd::stream::raw::DParameter::WindowLogMax(options.zstd_window_log_max))
            .map_err(|_| IntegrityReason::Decoder)?;
        Ok(Self(z))
    }
    pub(in crate::zip::read::codecs) fn step(&mut self, input: &[u8], output: &mut [u8], _last: bool) -> Progress {
        let z = &mut self.0;
        let mut source = zstd::stream::raw::InBuffer::around(input);
        let mut target = zstd::stream::raw::OutBuffer::around(output);
        let status = z.run(&mut source, &mut target);
        Progress {
            consumed: source.pos(),
            produced: target.pos(),
            end: matches!(status, Ok(0)),
            fault: status.err().map(|_| IntegrityReason::Decoder),
        }
    }
}
