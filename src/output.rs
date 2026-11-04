//! An extracted file being written. A big file is written on a thread of its own, so the disk works while the
//! next stretch is decoded; a small one is written directly.

use std::fs::File;
use std::io::{self, Write};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

/// Files from this size up (or of unknown size) get a writer thread.
const BACKGROUND_MIN: u64 = 4 << 20;
/// Bytes gathered before they go to the writer.
const CHUNK: usize = 4 << 20;
/// Chunks that may wait for the writer before writes block.
const DEPTH: usize = 4;

pub(crate) struct Output {
    inner: Inner,
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
    handle: Option<JoinHandle<io::Result<File>>>,
}

impl Output {
    /// Output to `file`, which is expected to receive `size` bytes.
    pub fn new(file: File, size: Option<u64>) -> Output {
        if size.is_some_and(|s| s < BACKGROUND_MIN) {
            return Output { inner: Inner::Direct(file) };
        }
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(DEPTH);
        let (back, spare) = mpsc::channel::<Vec<u8>>();
        // the file moves to the thread only if the thread starts; otherwise it is written directly
        let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(file)));
        let theirs = std::sync::Arc::clone(&slot);
        let spawned = thread::Builder::new().name("zipfast-write".into()).spawn(move || {
            let mut file = theirs.lock().ok().and_then(|mut f| f.take()).ok_or_else(|| io::Error::other("no file"))?;
            for mut buf in rx {
                file.write_all(&buf)?;
                buf.clear();
                let _ = back.send(buf);
            }
            Ok(file)
        });
        match spawned {
            Ok(handle) => Output {
                inner: Inner::Background(Background {
                    tx: Some(tx),
                    spare,
                    cur: Vec::with_capacity(CHUNK),
                    handle: Some(handle),
                }),
            },
            Err(_) => {
                let file = slot.lock().ok().and_then(|mut f| f.take()).expect("the thread never started");
                Output { inner: Inner::Direct(file) }
            }
        }
    }

    pub fn write(&mut self, mut data: &[u8]) -> io::Result<()> {
        match &mut self.inner {
            Inner::Direct(file) => file.write_all(data),
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

    /// Waits until everything is written and hands the file back, or the first write error.
    pub fn finish(self) -> io::Result<File> {
        match self.inner {
            Inner::Direct(file) => Ok(file),
            Inner::Background(mut b) => {
                if !b.cur.is_empty() {
                    b.send()?;
                }
                b.tx = None;
                b.join()
            }
        }
    }
}

impl Background {
    fn send(&mut self) -> io::Result<()> {
        let next = self.spare.try_recv().unwrap_or_else(|_| Vec::with_capacity(CHUNK));
        let full = std::mem::replace(&mut self.cur, next);
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send(full).is_ok());
        if sent {
            return Ok(());
        }
        // the writer stopped: its error says why
        self.tx = None;
        Err(self.join().err().unwrap_or_else(|| io::Error::other("the file writer stopped")))
    }

    fn join(&mut self) -> io::Result<File> {
        match self.handle.take().map(JoinHandle::join) {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err(io::Error::other("the file writer failed")),
            None => Err(io::Error::other("the file writer already stopped")),
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
            drop(out.finish().unwrap());
            let mut back = Vec::new();
            File::open(&path).unwrap().read_to_end(&mut back).unwrap();
            assert!(back == data, "{name}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
