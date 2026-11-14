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

//! Unbuffered diagnostic transport on an already held original stdio lock.
use std::io::{self, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
pub(super) struct FdWriter<L> {
    lock: L,
}
impl<L> FdWriter<L> {
    pub(super) fn new(lock: L) -> Self {
        Self { lock }
    }
}
impl<L: AsFd> AsFd for FdWriter<L> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.lock.as_fd()
    }
}
impl<L: AsFd> Write for FdWriter<L> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        #[cfg(test)]
        CALLS.with(|s| s.set(s.get() + 1));
        // The bounded formatter owns retries. This transport performs exactly one
        // application syscall and retains no data for a later flush or Drop.
        let n = unsafe { libc::write(self.lock.as_fd().as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
thread_local! {static CALLS:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    #[test]
    fn native_write_is_immediate_single_attempt_and_has_no_late_flush() {
        let (out, mut input) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut out = FdWriter::new(out);
        CALLS.with(|s| s.set(0));
        assert_eq!(out.write(b"now").unwrap(), 3);
        let mut bytes = [0; 3];
        input.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"now");
        out.flush().unwrap();
        assert_eq!(out.write(b"").unwrap(), 0);
        CALLS.with(|s| assert_eq!(s.get(), 1));
        drop(input);
        assert_eq!(out.write(b"failed").unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        CALLS.with(|s| assert_eq!(s.get(), 2));
        out.flush().unwrap();
        CALLS.with(|s| assert_eq!(s.get(), 2));
    }
}
