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

use std::io::{Read, Seek, Write};

use super::*;

/// Independent limits for verified printing.
#[derive(Clone, Debug)]
pub struct RarPrintOptions {
    pub decode: RarDecodeLimits,
    /// Maximum decoded bytes in one provisional spool.
    pub member_spool_bytes: u64,
    /// Maximum live spool bytes. The runner holds at most one spool.
    pub live_spool_bytes: u64,
    /// Spool and caller-writer I/O attempts, including interrupted calls.
    pub io_attempts: u64,
    /// Parent for the private temporary file. Defaults to the system temp directory.
    pub temp_dir: Option<PathBuf>,
}

impl Default for RarPrintOptions {
    fn default() -> Self {
        Self {
            decode: RarDecodeLimits::default(),
            member_spool_bytes: 8 << 30,
            live_spool_bytes: 8 << 30,
            io_attempts: 1 << 32,
            temp_dir: None,
        }
    }
}

impl RarSession {
    /// Check a caller-owned output descriptor against every held archive volume.
    ///
    /// This checks the session's source bindings and uses descriptor metadata
    /// without reopening the output or exposing input paths. It writes no bytes.
    /// Keep this descriptor as the writer and retain the source namespace
    /// contract required by print_selected().
    #[cfg(unix)]
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn check_output_file(&mut self, output: &std::fs::File) -> Result<(), RarRunError> {
        use std::os::unix::fs::MetadataExt;

        let mut summary = self.summary(0);
        self.check_run_sources(&mut summary)?;
        let metadata = match output.metadata() {
            Ok(metadata) => metadata,
            Err(source) => {
                return Err(run_error(
                    summary,
                    None,
                    Arc::new(RarFailure::Output { operation: IoOperation::Metadata, path: None, offset: None, source }),
                ));
            }
        };
        if self
            .volumes
            .iter()
            .any(|volume| metadata.dev() == volume.stamp.device && metadata.ino() == volume.stamp.inode)
        {
            return Err(run_error(summary, None, Arc::new(RarFailure::OutputAliasesInput)));
        }
        self.check_run_sources(&mut summary)
    }

    /// Verify each selected regular member and its required solid history,
    /// then copy that member to the caller's writer in archive order.
    ///
    /// The writer must be distinct from every archive input. A failed member
    /// emits no data until verified. A terminal copy error leaves any bytes
    /// already accepted by the writer visible. The returned partial summary
    /// counts completed members, and the error records current-member bytes.
    /// An entry without a checksum reports that evidence in its outcome.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn print_selected(
        &mut self,
        selection: &RarSelection,
        output: &mut (impl Write + ?Sized),
        options: &RarPrintOptions,
        on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        let cancel = self.options.cancel.clone();
        let mut attempts = PrintAttempts { used: 0, limit: options.io_attempts, cancel: &cancel };
        let mut accepted = 0;
        self.execute_selected(
            selection,
            options.decode,
            |run, session, index| {
                accepted = 0;
                let mut spool = Spool::default();
                let result = run.test(
                    session,
                    index,
                    Some(&mut |bytes| {
                        spool
                            .write(bytes, options, &mut attempts)
                            .map_err(|failure| RarFault::new(failure, Error::Corrupt("RAR print spool stopped")))
                    }),
                )?;
                match result {
                    RarOutcome::Verified { bytes, checks, .. } => {
                        spool.prepare_copy(bytes, &mut attempts).map_err(Arc::new)?;
                        let member = &session.members[index];
                        let mut volumes =
                            if member.header.method != 0 { run.history_volumes } else { [0; VOLUME_WORDS] };
                        mark_volumes(&mut volumes, &session.parts[member.parts.clone()]);
                        check_volumes(session, &volumes)?;
                        spool.copy_to(output, &mut accepted, &mut run.buffer, &mut attempts).map_err(Arc::new)?;
                        Ok(RarOutcome::Verified { bytes, checks, output: RarOutput::Printed })
                    }
                    RarOutcome::Directory => {
                        Ok(RarOutcome::Failed(Arc::new(RarFailure::Unsupported(RarUnsupported::PrintDirectory))))
                    }
                    outcome => Ok(outcome),
                }
            },
            on_entry,
        )
        .map_err(|mut error| {
            error.partial_member_bytes = accepted;
            error
        })
    }
}

struct PrintAttempts<'a> {
    used: u64,
    limit: u64,
    cancel: &'a Cancellation,
}

impl PrintAttempts<'_> {
    fn check_cancel(&self) -> Result<(), RarFailure> {
        check_cancel(self.cancel).map_err(|fault| *fault.failure)
    }

    fn run<T>(
        &mut self,
        operation: IoOperation,
        offset: u64,
        spool: bool,
        mut call: impl FnMut() -> io::Result<T>,
    ) -> Result<T, RarFailure> {
        loop {
            self.check_cancel()?;
            self.used = charge(self.used, 1, self.limit, RarResource::PrintIoAttempts)?;
            #[cfg(test)]
            let result = if spool { spool_event(operation).and_then(|()| call()) } else { call() };
            #[cfg(not(test))]
            let result = call();
            match result {
                Ok(value) => return Ok(value),
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) if spool => return Err(RarFailure::PrintSpool { operation, offset, source }),
                Err(source) => return Err(RarFailure::PrintWriter { operation, offset, source }),
            }
        }
    }
}

#[derive(Default)]
struct Spool {
    file: Option<File>,
    size: u64,
}

impl Spool {
    fn write(
        &mut self,
        mut bytes: &[u8],
        options: &RarPrintOptions,
        attempts: &mut PrintAttempts<'_>,
    ) -> Result<(), RarFailure> {
        if bytes.is_empty() {
            return Ok(());
        }
        let count = bytes.len() as u64;
        charge(self.size, count, options.member_spool_bytes, RarResource::PrintMemberSpoolBytes)?;
        charge(self.size, count, options.live_spool_bytes, RarResource::PrintLiveSpoolBytes)?;
        if self.file.is_none() {
            self.file = Some(attempts.run(IoOperation::CreateFile, 0, true, || {
                if let Some(directory) = &options.temp_dir {
                    tempfile::tempfile_in(directory)
                } else {
                    tempfile::tempfile()
                }
            })?);
        }
        let file = self.file.as_mut().expect("spool allocated for nonempty bytes");
        while !bytes.is_empty() {
            let written = attempts.run(IoOperation::Write, self.size, true, || write_some(file, bytes))?;
            self.size += written as u64;
            bytes = &bytes[written..];
        }
        Ok(())
    }

    fn prepare_copy(&mut self, verified: u64, attempts: &mut PrintAttempts<'_>) -> Result<(), RarFailure> {
        if self.size != verified {
            return Err(RarFailure::Internal(RarInternal::Invariant("verified RAR spool length differs")));
        }
        if let Some(file) = &mut self.file {
            attempts.run(IoOperation::Flush, self.size, true, || file.flush())?;
            attempts.run(IoOperation::Seek, 0, true, || file.rewind())?;
        }
        Ok(())
    }

    fn copy_to(
        &mut self,
        output: &mut (impl Write + ?Sized),
        accepted: &mut u64,
        buffer: &mut [u8],
        attempts: &mut PrintAttempts<'_>,
    ) -> Result<(), RarFailure> {
        if let Some(file) = &mut self.file {
            while *accepted < self.size {
                let want = (self.size - *accepted).min(buffer.len() as u64) as usize;
                let read = attempts.run(IoOperation::Read, *accepted, true, || {
                    let count = file.read(&mut buffer[..want])?;
                    if count == 0 { Err(io::Error::from(io::ErrorKind::UnexpectedEof)) } else { Ok(count) }
                })?;
                let mut bytes = &buffer[..read];
                while !bytes.is_empty() {
                    let written = attempts.run(IoOperation::Write, *accepted, false, || write_some(output, bytes))?;
                    *accepted += written as u64;
                    bytes = &bytes[written..];
                }
            }
        }
        attempts.run(IoOperation::Flush, *accepted, false, || output.flush())?;
        attempts.check_cancel()
    }
}

fn write_some(writer: &mut (impl Write + ?Sized), bytes: &[u8]) -> io::Result<usize> {
    match writer.write(bytes)? {
        0 => Err(io::Error::from(io::ErrorKind::WriteZero)),
        written if written > bytes.len() => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid write count")),
        written => Ok(written),
    }
}

#[cfg(test)]
type SpoolHook = Box<dyn FnMut(IoOperation) -> io::Result<()>>;
#[cfg(test)]
thread_local! {
    static SPOOL_HOOK: std::cell::RefCell<Option<SpoolHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
fn spool_event(operation: IoOperation) -> io::Result<()> {
    SPOOL_HOOK.with_borrow_mut(|hook| hook.as_mut().map_or(Ok(()), |hook| hook(operation)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn one_member(directory: &Path, name: &str) -> PathBuf {
        let path = directory.join(name);
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        let body = [2, 2, 1, 0, 1, 0, 0, 1, 1, b'a'];
        let mut framed = vec![body.len() as u8];
        framed.extend(body);
        let crc = crate::crc32::hash(&framed).to_le_bytes();
        let mut bytes = super::super::super::super::SIGNATURE.to_vec();
        bytes.extend(main);
        bytes.extend(crc);
        bytes.extend(framed);
        bytes.push(b'x');
        bytes.extend(end);
        fs::write(&path, bytes).unwrap();
        path
    }

    struct Hooks;
    impl Drop for Hooks {
        fn drop(&mut self) {
            SPOOL_HOOK.with_borrow_mut(|hook| *hook = None);
        }
    }

    #[test]
    fn spool_errors_identify_operation_and_offset_without_writing_to_caller() {
        let dir = tempfile::tempdir().unwrap();
        let path = one_member(dir.path(), "archive.rar");
        let mut session = RarSession::open(&path, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let spool_dir = tempfile::tempdir_in(dir.path()).unwrap();
        let options = RarPrintOptions { temp_dir: Some(spool_dir.path().to_owned()), ..RarPrintOptions::default() };
        for (failure_at, offset) in [
            (IoOperation::CreateFile, 0),
            (IoOperation::Write, 0),
            (IoOperation::Flush, 1),
            (IoOperation::Seek, 0),
            (IoOperation::Read, 0),
        ] {
            let _hooks = Hooks;
            SPOOL_HOOK.with_borrow_mut(|hook| {
                *hook = Some(Box::new(move |operation| {
                    if operation == failure_at { Err(io::Error::other("test spool failure")) } else { Ok(()) }
                }));
            });
            let mut output = Vec::new();
            let error = session.print_selected(&selection, &mut output, &options, |_| {}).unwrap_err();
            assert!(matches!(error.failure.as_ref(), RarFailure::PrintSpool { operation, offset: actual, source }
                if *operation == failure_at && *actual == offset && source.to_string() == "test spool failure"));
            assert!(output.is_empty());
            assert_eq!((error.partial.files, error.partial.failed, error.partial_member_bytes), (0, 1, 0));
            assert_eq!(fs::read_dir(spool_dir.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn cancellation_and_source_replacement_after_rewind_prevent_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = one_member(dir.path(), "archive.rar");
        for replace in [false, true] {
            let cancel = Cancellation::default();
            let mut session =
                RarSession::open(&path, None, RarSessionOptions { cancel: cancel.clone(), ..Default::default() })
                    .unwrap();
            let selection = session.select(|_| true).unwrap();
            let _hooks = Hooks;
            let replacement = one_member(dir.path(), "replacement.rar");
            let target = path.clone();
            SPOOL_HOOK.with_borrow_mut(|hook| {
                *hook = Some(Box::new(move |operation| {
                    if operation == IoOperation::Seek {
                        if replace {
                            fs::rename(&replacement, &target).unwrap();
                        } else {
                            cancel.cancel();
                        }
                    }
                    Ok(())
                }));
            });
            let mut output = Vec::new();
            let error =
                session.print_selected(&selection, &mut output, &RarPrintOptions::default(), |_| {}).unwrap_err();
            assert!(output.is_empty());
            assert_eq!((error.partial.files, error.partial.failed, error.partial_member_bytes), (0, 1, 0));
            if replace {
                assert!(
                    matches!(error.failure.as_ref(), RarFailure::SourceChanged { path: actual } if actual == &path)
                );
                assert!(session.invalid_binding.is_some());
            } else {
                assert!(matches!(error.failure.as_ref(), RarFailure::Canceled));
            }
        }
    }
}
