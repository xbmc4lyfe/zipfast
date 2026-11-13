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

//! An extracted file being written. A big file is written on a thread of its own, so the disk works while the
//! next stretch is decoded; a small one is written directly.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

use tempfile::{NamedTempFile, TempPath};

use crate::error::{Error, IoOperation, RarFailure, RarFault, RarInternal, RarPolicyReason};

/// Files from this size up (or of unknown size) get a writer thread.
const BACKGROUND_MIN: u64 = 4 << 20;
/// Bytes gathered before they go to the writer. With the queue below, a file being written holds at most about
/// six of these: big enough to keep the disk busy, small enough to keep memory near what a direct write uses.
const CHUNK: usize = 1 << 20;
/// Chunks that may wait for the writer before writes block.
const DEPTH: usize = 4;

pub(crate) struct Output {
    inner: Inner,
    pending: Option<PendingPath>,
}

#[derive(Debug)]
pub(crate) enum OutputError {
    Io { operation: IoOperation, path: Option<PathBuf>, source: io::Error },
    Worker(WriterFailure),
    Symlink(PathBuf),
}

impl OutputError {
    fn into_legacy(self) -> io::Error {
        match self {
            Self::Io { source, .. } => source,
            Self::Worker(failure) => failure.into_legacy(),
            Self::Symlink(_) => io::Error::new(io::ErrorKind::AlreadyExists, "a symlink is in the way"),
        }
    }

    pub(crate) fn detailed(self, preserve_eof: bool) -> RarFault {
        match self {
            Self::Io { operation, path, source } => RarFault::output(operation, path, None, source, preserve_eof),
            Self::Worker(failure) => {
                let reason = match failure {
                    WriterFailure::Panicked => RarInternal::WorkerPanic,
                    WriterFailure::MissingFile => RarInternal::Invariant("no file"),
                    _ => RarInternal::WorkerStopped,
                };
                RarFault::new(RarFailure::Internal(reason), Error::Io(failure.into_legacy()))
            }
            Self::Symlink(path) => RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::Symlink, path },
                Error::Io(io::Error::new(io::ErrorKind::AlreadyExists, "a symlink is in the way")),
            ),
        }
    }
}

#[derive(Debug)]
pub(crate) enum WriterFailure {
    Io(io::Error),
    MissingFile,
    Stopped,
    Panicked,
    AlreadyStopped,
}

impl WriterFailure {
    fn into_legacy(self) -> io::Error {
        match self {
            Self::Io(e) => e,
            Self::MissingFile => io::Error::other("no file"),
            Self::Stopped => io::Error::other("the file writer stopped"),
            Self::Panicked => io::Error::other("the file writer failed"),
            Self::AlreadyStopped => io::Error::other("the file writer already stopped"),
        }
    }

    fn detailed(self, pending: Option<&PendingPath>) -> OutputError {
        match self {
            Self::Io(source) => OutputError::Io {
                operation: IoOperation::Write,
                path: pending.and_then(PendingPath::target).map(Path::to_path_buf),
                source,
            },
            failure => OutputError::Worker(failure),
        }
    }
}

pub(crate) struct WriteFile {
    pub file: File,
    pending: Option<PendingPath>,
}

enum PendingPath {
    New(Cleanup),
    Replacement(TempPath, PathBuf),
}

struct Cleanup(Option<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Use the same default mode as a regular newly created output file.
pub(crate) fn temporary(parent: &Path) -> io::Result<NamedTempFile> {
    let builder = &mut tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o666));
    }
    builder.tempfile_in(parent)
}

pub(crate) fn replace(temporary: TempPath, target: &Path) -> io::Result<()> {
    replace_detailed(temporary, target).map_err(OutputError::into_legacy)
}

fn replace_detailed(temporary: TempPath, target: &Path) -> Result<(), OutputError> {
    let fault = |operation, source| OutputError::Io { operation, path: Some(target.to_path_buf()), source };
    // An earlier check cannot account for a symlink installed while decoding.
    match fs::symlink_metadata(target) {
        Ok(meta) if meta.file_type().is_symlink() => return Err(OutputError::Symlink(target.to_path_buf())),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(fault(IoOperation::Metadata, e)),
    }
    temporary.persist(target).map_err(|e| fault(IoOperation::Publish, e.error))
}

enum Inner {
    Direct(File),
    Background(Background),
}

struct Background {
    tx: Option<SyncSender<Vec<u8>>>,
    /// emptied buffers coming back for reuse
    spare: Receiver<Vec<u8>>,
    cur: Vec<u8>,
    handle: Option<JoinHandle<Result<File, WriterFailure>>>,
}

impl PendingPath {
    fn target(&self) -> Option<&Path> {
        match self {
            Self::New(cleanup) => cleanup.0.as_deref(),
            Self::Replacement(_, target) => Some(target),
        }
    }
}

impl WriteFile {
    pub(crate) fn target(&self) -> Option<&Path> {
        self.pending.as_ref().and_then(PendingPath::target)
    }

    #[cfg(unix)]
    pub(crate) fn publish_noclobber(self) -> Result<(), OutputError> {
        let Self { file, pending } = self;
        drop(file);
        let Some(PendingPath::Replacement(temporary, target)) = pending else {
            unreachable!("new selected output has a stage");
        };
        temporary.persist_noclobber(&target).map_err(|error| OutputError::Io {
            operation: IoOperation::Publish,
            path: Some(target),
            source: error.error,
        })
    }

    pub(crate) fn publish(self) -> Result<(), OutputError> {
        let Self { file, pending } = self;
        drop(file);
        match pending {
            Some(PendingPath::Replacement(temporary, target)) => replace_detailed(temporary, &target),
            Some(PendingPath::New(mut cleanup)) => {
                cleanup.0 = None;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

impl Output {
    /// Output to `file`, which is expected to receive `size` bytes.
    pub fn new(file: File, size: Option<u64>) -> Output {
        if size.is_some_and(|s| s < BACKGROUND_MIN) {
            return Output { inner: Inner::Direct(file), pending: None };
        }
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(DEPTH);
        let (back, spare) = mpsc::channel::<Vec<u8>>();
        // the file moves to the thread only if the thread starts; otherwise it is written directly
        let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(file)));
        let theirs = std::sync::Arc::clone(&slot);
        let spawned = thread::Builder::new().name("zipfast-write".into()).spawn(move || {
            let mut file = theirs.lock().ok().and_then(|mut f| f.take()).ok_or(WriterFailure::MissingFile)?;
            for mut buf in rx {
                file.write_all(&buf).map_err(WriterFailure::Io)?;
                buf.clear();
                let _ = back.send(buf);
            }
            Ok(file)
        });
        match spawned {
            Ok(handle) => Output {
                pending: None,
                inner: Inner::Background(Background {
                    tx: Some(tx),
                    spare,
                    cur: Vec::with_capacity(CHUNK),
                    handle: Some(handle),
                }),
            },
            Err(_) => {
                let file = slot.lock().ok().and_then(|mut f| f.take()).expect("the thread never started");
                Output { inner: Inner::Direct(file), pending: None }
            }
        }
    }

    pub fn created(file: File, size: Option<u64>, path: PathBuf) -> Self {
        let mut output = Self::new(file, size);
        output.pending = Some(PendingPath::New(Cleanup(Some(path))));
        output
    }

    pub fn staged(file: File, size: Option<u64>, temporary: TempPath, target: PathBuf) -> Self {
        let mut output = Self::new(file, size);
        output.pending = Some(PendingPath::Replacement(temporary, target));
        output
    }

    #[cfg(unix)]
    pub(crate) fn staged_direct(file: File, temporary: TempPath, target: PathBuf) -> Self {
        Self { inner: Inner::Direct(file), pending: Some(PendingPath::Replacement(temporary, target)) }
    }

    pub(crate) fn write_detailed(&mut self, data: &[u8]) -> Result<(), OutputError> {
        self.write_inner(data).map_err(|failure| failure.detailed(self.pending.as_ref()))
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.write_inner(data).map_err(WriterFailure::into_legacy)
    }

    fn write_inner(&mut self, mut data: &[u8]) -> Result<(), WriterFailure> {
        match &mut self.inner {
            Inner::Direct(file) => file.write_all(data).map_err(WriterFailure::Io),
            Inner::Background(b) => {
                while !data.is_empty() {
                    let take = (CHUNK - b.cur.len()).min(data.len());
                    b.cur.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if b.cur.len() == CHUNK {
                        b.send()?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Waits for pending writes and hands the file and its cleanup guard to a positional writer.
    pub(crate) fn handoff_detailed(self) -> Result<WriteFile, OutputError> {
        let file = (|| match self.inner {
            Inner::Direct(file) => Ok(file),
            Inner::Background(mut b) => {
                if !b.cur.is_empty() {
                    b.send()?;
                }
                b.tx = None;
                b.join()
            }
        })()
        .map_err(|failure| failure.detailed(self.pending.as_ref()))?;
        Ok(WriteFile { file, pending: self.pending })
    }

    pub fn resume(file: WriteFile, size: Option<u64>) -> Self {
        let mut output = Self::new(file.file, size);
        output.pending = file.pending;
        output
    }

    /// Prepares metadata and publishes a verified replacement after every write has finished.
    pub fn finish(self, prepare: impl FnOnce(&File)) -> io::Result<()> {
        self.finish_detailed(prepare).map_err(OutputError::into_legacy)
    }

    pub(crate) fn finish_detailed(self, prepare: impl FnOnce(&File)) -> Result<(), OutputError> {
        let output = self.handoff_detailed()?;
        prepare(&output.file);
        output.publish()
    }
}

impl Background {
    fn send(&mut self) -> Result<(), WriterFailure> {
        let next = self.spare.try_recv().unwrap_or_else(|_| Vec::with_capacity(CHUNK));
        let full = std::mem::replace(&mut self.cur, next);
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(full).is_ok());
        if sent {
            return Ok(());
        }
        // the writer stopped: its error says why
        self.tx = None;
        Err(self.join().err().unwrap_or(WriterFailure::Stopped))
    }

    fn join(&mut self) -> Result<File, WriterFailure> {
        match self.handle.take().map(JoinHandle::join) {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err(WriterFailure::Panicked),
            None => Err(WriterFailure::AlreadyStopped),
        }
    }
}

impl Drop for Background {
    /// A file given up on: whatever is queued is still written, so the caller can remove the file once this returns.
    fn drop(&mut self) {
        self.tx = None;
        let _ = self.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn writes_everything_in_order_both_ways() {
        let dir = std::env::temp_dir().join(format!("zipfast-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..(CHUNK * 3 + 12345)).map(|i| (i * 7 % 251) as u8).collect();
        for (name, size) in [("small", Some(10)), ("big", Some(data.len() as u64)), ("unknown", None)] {
            let path = dir.join(name);
            let mut out = Output::new(File::create(&path).unwrap(), size);
            for piece in data.chunks(1_000_003) {
                out.write(piece).unwrap();
            }
            out.finish(|_| {}).unwrap();
            let mut back = Vec::new();
            File::open(&path).unwrap().read_to_end(&mut back).unwrap();
            assert!(back == data, "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_staged_background_write_error_preserves_existing_output() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"original").unwrap();
        let before = fs::metadata(&target).unwrap();
        let temp = temporary(dir.path()).unwrap();
        let file = File::open(temp.path()).unwrap();
        let mut out = Output::staged(file, None, temp.into_temp_path(), target.clone());
        out.write(b"buffered bytes").unwrap();

        assert!(out.finish(|_| panic!("a failed write cannot prepare publication")).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"original");
        let after = fs::metadata(&target).unwrap();
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(after.permissions(), before.permissions());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn a_failed_staged_rename_leaves_the_target_directory_and_removes_the_temp() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let (file, temp) = temporary(dir.path()).unwrap().into_parts();
        let mut out = Output::staged(file, Some(4), temp, target.clone());
        out.write(b"data").unwrap();

        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"original").unwrap();
        assert!(out.finish(|_| {}).is_err());
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn detailed_finish_distinguishes_background_write_and_publish() {
        use crate::error::{IoOperation, RarFailure};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"original").unwrap();
        let temp = temporary(dir.path()).unwrap();
        let file = File::open(temp.path()).unwrap();
        let mut out = Output::staged(file, None, temp.into_temp_path(), target.clone());
        out.write(b"buffered").unwrap();
        let fault = out.finish_detailed(|_| panic!("failed write reached publication")).unwrap_err().detailed(false);
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::Write, path: Some(path), source, ..
        } if path == &target && source.raw_os_error() == Some(libc::EBADF)));
        assert_eq!(fs::read(&target).unwrap(), b"original");

        fs::remove_file(&target).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"original").unwrap();
        let (file, temp) = temporary(dir.path()).unwrap().into_parts();
        let mut out = Output::staged(file, Some(4), temp, target.clone());
        out.write(b"data").unwrap();
        let fault = out.finish_detailed(|_| {}).unwrap_err().detailed(false);
        assert!(matches!(fault.failure.as_ref(), RarFailure::Output {
            operation: IoOperation::Publish, path: Some(path), source, ..
        } if path == &target && source.raw_os_error().is_some()));
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"original");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
