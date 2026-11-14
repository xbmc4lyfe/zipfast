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

//! Two-pass formatting with bounded immediate writes and fixed live scratch.
use super::*;
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ZipDiagnosticUsage {
    pub formatted_bytes: u128,
    pub accepted_bytes: u128,
    pub write_attempts: u128,
    pub metadata_attempts: u128,
    pub source_metadata_attempts: u128,
    pub descriptor_metadata_attempts: u128,
    pub target_metadata_attempts: u128,
    pub cwd_metadata_attempts: u128,
}
impl ZipDiagnosticUsage {
    pub(super) fn metadata(&mut self, kind: u8) -> std::io::Result<()> {
        let total = self.metadata_attempts.checked_add(1).ok_or(std::io::ErrorKind::InvalidData)?;
        let field = match kind {
            0 => &mut self.source_metadata_attempts,
            1 => &mut self.descriptor_metadata_attempts,
            2 => &mut self.target_metadata_attempts,
            _ => &mut self.cwd_metadata_attempts,
        };
        let next = field.checked_add(1).ok_or(std::io::ErrorKind::InvalidData)?;
        *field = next;
        self.metadata_attempts = total;
        Ok(())
    }
}
struct Count(u128);
impl fmt::Write for Count {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0 = self.0.checked_add(text.len() as u128).ok_or(fmt::Error)?;
        Ok(())
    }
}
/// An ephemeral formatting capability. It never implements unbounded `io::Write`.
pub struct ZipDiagnosticWriter<'a, W: Write> {
    pub(super) out: &'a mut W,
    pub(super) usage: &'a mut ZipDiagnosticUsage,
    pub(super) fault: &'a mut Option<ZipSinkFault>,
    pub(super) cancel: &'a Cancellation,
    pub(super) retries: u64,
    pub(super) token: Token,
    pub(super) remaining: u128,
    pub(super) attempted: &'a mut bool,
}
impl<W: Write> ZipDiagnosticWriter<'_, W> {
    fn stop(&self) -> ZipDiagnosticStop {
        ZipDiagnosticStop { token: self.token }
    }
    pub fn write_fmt(&mut self, text: fmt::Arguments<'_>) -> ZipDiagnosticResult<()> {
        if self.fault.is_some() {
            return Err(self.stop());
        }
        if self.remaining == 0 {
            *self.fault = Some(ZipSinkFault::StageChanged);
            return Err(self.stop());
        }
        self.remaining -= 1;
        *self.attempted = true;
        let mut count = Count(0);
        if fmt::write(&mut count, text).is_err() {
            *self.fault = Some(ZipSinkFault::StageChanged);
            return Err(self.stop());
        }
        let Some(bound) =
            count.0.checked_add(1).and_then(|n| n.checked_mul(self.retries as u128 + 1)).and_then(|n| n.checked_add(1))
        else {
            *self.fault = Some(ZipSinkFault::Limit {
                resource: ReadResource::IoAttempts,
                limit: u128::MAX,
                attempted: u128::MAX,
            });
            return Err(self.stop());
        };
        if self.usage.write_attempts.checked_add(bound).is_none()
            || self.usage.accepted_bytes.checked_add(count.0).is_none()
        {
            *self.fault = Some(ZipSinkFault::Limit {
                resource: ReadResource::IoAttempts,
                limit: u128::MAX,
                attempted: u128::MAX,
            });
            return Err(self.stop());
        }
        let Some(formatted) = self.usage.formatted_bytes.checked_add(count.0) else {
            *self.fault =
                Some(ZipSinkFault::Limit { resource: ReadResource::IoBytes, limit: u128::MAX, attempted: u128::MAX });
            return Err(self.stop());
        };
        self.usage.formatted_bytes = formatted;
        let mut stream =
            Stream { writer: self, expected: count.0, supplied: 0, attempts: 0, bound, window: [0; 1024], filled: 0 };
        let formatted = fmt::write(&mut stream, text);
        if formatted.is_err() || stream.supplied != stream.expected {
            if stream.writer.fault.is_none() {
                *stream.writer.fault = Some(ZipSinkFault::StageChanged);
            }
            return Err(stream.writer.stop());
        }
        stream.flush().map_err(|_| stream.writer.stop())
    }
}
struct Stream<'a, 'b, W: Write> {
    writer: &'a mut ZipDiagnosticWriter<'b, W>,
    expected: u128,
    supplied: u128,
    attempts: u128,
    bound: u128,
    window: [u8; 1024],
    filled: usize,
}
impl<W: Write> Stream<'_, '_, W> {
    fn fail(&mut self, fault: ZipSinkFault) -> fmt::Result {
        if self.writer.fault.is_none() {
            *self.writer.fault = Some(fault);
        }
        Err(fmt::Error)
    }
    fn flush(&mut self) -> fmt::Result {
        let mut at = 0;
        let mut interrupted = 0;
        while at < self.filled {
            if self.writer.cancel.is_canceled() {
                return self.fail(ZipSinkFault::Cancelled);
            }
            self.attempts = self.attempts.checked_add(1).ok_or(fmt::Error)?;
            if self.attempts > self.bound {
                return self.fail(ZipSinkFault::StageChanged);
            }
            self.writer.usage.write_attempts = self.writer.usage.write_attempts.checked_add(1).ok_or(fmt::Error)?;
            match self.writer.out.write(&self.window[at..self.filled]) {
                Ok(0) => {
                    return self.fail(ZipSinkFault::Io {
                        operation: ReadIoOperation::Write,
                        offset: 0,
                        error: std::io::ErrorKind::WriteZero.into(),
                    });
                }
                Ok(n) if n <= self.filled - at => {
                    self.writer.usage.accepted_bytes =
                        self.writer.usage.accepted_bytes.checked_add(n as u128).ok_or(fmt::Error)?;
                    at += n;
                    interrupted = 0;
                }
                Ok(_) => return self.fail(ZipSinkFault::StageChanged),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted && interrupted < self.writer.retries => {
                    interrupted += 1
                }
                Err(error) => {
                    return self.fail(ZipSinkFault::Io { operation: ReadIoOperation::Write, offset: 0, error });
                }
            }
        }
        self.filled = 0;
        Ok(())
    }
}
impl<W: Write> fmt::Write for Stream<'_, '_, W> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.supplied = self.supplied.checked_add(text.len() as u128).ok_or(fmt::Error)?;
        if self.supplied > self.expected {
            return self.fail(ZipSinkFault::StageChanged);
        }
        let mut remaining = text.as_bytes();
        while !remaining.is_empty() {
            let n = remaining.len().min(self.window.len() - self.filled);
            self.window[self.filled..self.filled + n].copy_from_slice(&remaining[..n]);
            self.filled += n;
            remaining = &remaining[n..];
            if self.filled == self.window.len() {
                self.flush()?;
            }
        }
        Ok(())
    }
}
