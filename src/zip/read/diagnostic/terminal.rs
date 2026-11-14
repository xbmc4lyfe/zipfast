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

//! A separate one-event phase without any fabricated catalogue/source proof.
use super::*;
#[derive(Debug)]
pub(crate) struct TerminalError {
    pub(crate) boundary: Option<DiagnosticBoundaryFault>,
    pub(crate) diagnostic: Option<ZipSinkFault>,
    pub(crate) usage: ZipDiagnosticUsage,
}
#[allow(clippy::result_large_err)] // Both independent terminal faults and exact usage stay inline.
pub(crate) fn terminal<W: Write + AsFd>(
    out: &mut W,
    cancel: &Cancellation,
    text: std::fmt::Arguments<'_>,
) -> Result<ZipDiagnosticUsage, TerminalError> {
    let mut usage = ZipDiagnosticUsage::default();
    let mut operations = 0u8;
    let mut classify_now = |usage: &mut ZipDiagnosticUsage| {
        classify(out.as_fd().as_raw_fd(), |operation, call| {
            operations = operations.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
            if operations > 6 {
                return Err(ReadFault::InvalidPlan);
            }
            for retry in 0..=16 {
                if cancel.is_canceled() {
                    return Err(ReadFault::Cancelled);
                }
                usage.metadata(1).map_err(|_| ReadFault::CounterOverflow)?;
                if usage.metadata_attempts > 102 {
                    return Err(ReadFault::InvalidPlan);
                }
                match call() {
                    Ok(v) => return Ok(v),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted && retry < 16 => {}
                    Err(error) => {
                        return Err(ReadFault::Io { stage: IoStage::ExternalOutput, operation, offset: 0, error });
                    }
                }
            }
            unreachable!()
        })
    };
    let first = match classify_now(&mut usage) {
        Ok(d) if d.safe => d,
        Ok(_) => {
            return Err(TerminalError {
                boundary: Some(DiagnosticBoundaryFault::Refused { reason: "unbound regular diagnostic" }),
                diagnostic: None,
                usage,
            });
        }
        Err(f) => return Err(TerminalError { boundary: Some(f), diagnostic: None, usage }),
    };
    let mut boundary = match classify_now(&mut usage) {
        Ok(d) if d == first => None,
        Ok(_) => Some(DiagnosticBoundaryFault::DescriptorChanged),
        Err(f) => Some(f),
    };
    drop(classify_now);
    let mut diagnostic = None;
    if boundary.is_none() {
        let mut attempted = false;
        let mut writer = ZipDiagnosticWriter {
            out,
            usage: &mut usage,
            fault: &mut diagnostic,
            cancel,
            retries: 16,
            token: Token { action: None, serial: 0 },
            remaining: 1,
            attempted: &mut attempted,
        };
        let _ = writer.write_fmt(text);
        let after = classify(out.as_fd().as_raw_fd(), |operation, call| {
            operations = operations.checked_add(1).ok_or(ReadFault::CounterOverflow)?;
            if operations > 6 {
                return Err(ReadFault::InvalidPlan);
            }
            for retry in 0..=16 {
                usage.metadata(1).map_err(|_| ReadFault::CounterOverflow)?;
                if usage.metadata_attempts > 102 {
                    return Err(ReadFault::InvalidPlan);
                }
                match call() {
                    Ok(v) => return Ok(v),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted && retry < 16 => {}
                    Err(error) => {
                        return Err(ReadFault::Io { stage: IoStage::ExternalOutput, operation, offset: 0, error });
                    }
                }
            }
            unreachable!()
        });
        boundary = match after {
            Ok(d) if d == first => None,
            Ok(_) => Some(DiagnosticBoundaryFault::DescriptorChanged),
            Err(f) => Some(f),
        };
    }
    if boundary.is_some() || diagnostic.is_some() {
        Err(TerminalError { boundary, diagnostic, usage })
    } else {
        Ok(usage)
    }
}
