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

//! Native deflate slice progress adapter.
use super::{EncryptedReadOptions, IntegrityReason, Progress};
pub(in crate::zip::read::codecs) struct Decoder(flate2::Decompress);
impl Decoder {
    pub(in crate::zip::read::codecs) fn new(_options: &EncryptedReadOptions) -> Result<Self, IntegrityReason> {
        Ok(Self(flate2::Decompress::new(false)))
    }
    pub(in crate::zip::read::codecs) fn step(&mut self, input: &[u8], output: &mut [u8], _last: bool) -> Progress {
        let z = &mut self.0;
        let (i, o) = (z.total_in(), z.total_out());
        let s = z.decompress(input, output, flate2::FlushDecompress::None);
        Progress {
            consumed: (z.total_in() - i) as usize,
            produced: (z.total_out() - o) as usize,
            fault: s.as_ref().err().map(|_| IntegrityReason::Decoder),
            end: matches!(s, Ok(flate2::Status::StreamEnd)),
        }
    }
}
