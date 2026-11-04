//! Work spread over threads for RAR archives that aren't solid, where every file stands alone.
//!
//! Small files are read whole on the main thread and handed to workers, which decode, check and write them while
//! the next ones are read. Big stored files are checked and copied in pieces on several threads at once. Results
//! come back in archive order, so reports read the same as from a single thread.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::extract::{Meta, finish_file};
use crate::output::Output;
use crate::rar5::unpack::{Unpacker, window_for};

/// Files up to this size, packed and unpacked, go to the workers whole.
pub(crate) const JOB_MAX: u64 = 16 << 20;
/// Stored data from this size up is copied on several threads.
pub(crate) const STORED_PARALLEL_MIN: u64 = 64 << 20;
/// The piece of stored data one thread checks and copies at a time.
const PIECE: u64 = 8 << 20;
/// Bytes of files read ahead of the workers.
const BYTES_IN_FLIGHT: usize = 256 << 20;

/// One file, read whole, to be decoded, checked and written.
pub(crate) struct Job {
    pub name: String,
    pub packed: Vec<u8>,
    /// 0 for stored
    pub method: u8,
    pub dictionary: u64,
    pub size: u64,
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    pub out: Option<(File, PathBuf)>,
    pub meta: Meta,
}

/// How a file went.
pub(crate) enum Outcome {
    /// checked (and written), this many bytes
    Done(u64),
    /// this file failed, for this reason; the run goes on
    Failed(String),
    /// writing failed: the run stops
    Fatal(Error),
}

pub(crate) struct Done {
    pub name: String,
    pub outcome: Outcome,
}

pub(crate) struct Batch {
    tx: Option<Sender<(u64, Job)>>,
    rx: Receiver<(u64, Done, usize)>,
    handles: Vec<JoinHandle<()>>,
    workers: usize,
    next: u64,
    applied: u64,
    bytes: usize,
    ready: BTreeMap<u64, (Done, usize)>,
}

impl Batch {
    pub(crate) fn new(workers: usize) -> Batch {
        let (tx, jobs) = mpsc::channel::<(u64, Job)>();
        let (done_tx, rx) = mpsc::channel();
        let jobs = Arc::new(Mutex::new(jobs));
        let handles = (0..workers)
            .filter_map(|i| {
                let jobs = Arc::clone(&jobs);
                let done_tx = done_tx.clone();
                thread::Builder::new()
                    .name(format!("zipfast-file-{i}"))
                    .spawn(move || {
                        let mut unpacker: Option<Unpacker> = None;
                        loop {
                            let next = jobs.lock().map(|rx| rx.recv());
                            let Ok(Ok((seq, job))) = next else { break };
                            let weight = job.packed.len() + job.size as usize;
                            let done = run(job, &mut unpacker);
                            if done_tx.send((seq, done, weight)).is_err() {
                                break;
                            }
                        }
                    })
                    .ok()
            })
            .collect::<Vec<_>>();
        let workers = handles.len();
        Batch { tx: Some(tx), rx, handles, workers, next: 0, applied: 0, bytes: 0, ready: BTreeMap::new() }
    }

    /// Whether any worker started.
    pub(crate) fn usable(&self) -> bool {
        self.workers > 0
    }

    /// Hands `job` over, first taking back finished files while too much is waiting. Finished files go to `apply`
    /// in archive order.
    pub(crate) fn submit(&mut self, job: Job, apply: &mut dyn FnMut(Done) -> Result<()>) -> Result<()> {
        let weight = job.packed.len() + job.size as usize;
        while self.next - self.applied >= 4 * self.workers as u64
            || (self.next > self.applied && self.bytes + weight > BYTES_IN_FLIGHT)
        {
            self.take_one(apply)?;
        }
        self.bytes += weight;
        let seq = self.next;
        self.next += 1;
        let sent = self.tx.as_ref().is_some_and(|tx| tx.send((seq, job)).is_ok());
        if !sent {
            // every worker is gone; can't happen while one is alive
            return Err(Error::Io(std::io::Error::other("file workers stopped")));
        }
        Ok(())
    }

    /// Waits for every file handed over, applying them in order.
    pub(crate) fn drain(&mut self, apply: &mut dyn FnMut(Done) -> Result<()>) -> Result<()> {
        while self.applied < self.next {
            self.take_one(apply)?;
        }
        Ok(())
    }

    fn take_one(&mut self, apply: &mut dyn FnMut(Done) -> Result<()>) -> Result<()> {
        while !self.ready.contains_key(&self.applied) {
            let Ok((seq, done, weight)) = self.rx.recv() else {
                return Err(Error::Io(std::io::Error::other("file workers stopped")));
            };
            self.ready.insert(seq, (done, weight));
        }
        let (done, weight) = self.ready.remove(&self.applied).unwrap();
        self.applied += 1;
        self.bytes -= weight;
        apply(done)
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        self.tx = None;
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn run(job: Job, unpacker: &mut Option<Unpacker>) -> Done {
    let Job { name, packed, method, dictionary, size, crc32, blake2sp, out, meta } = job;
    let mut hasher = crc32fast::Hasher::new();
    let mut blake = blake2sp.map(|_| Blake2sp::new());
    let (mut out, path) = match out {
        Some((file, path)) => (Some(Output::new(file, Some(size))), Some(path)),
        None => (None, None),
    };
    let mut bytes = 0u64;
    let mut sink = |chunk: &[u8]| -> Result<()> {
        hasher.update(chunk);
        if let Some(b) = blake.as_mut() {
            b.update(chunk);
        }
        if let Some(o) = out.as_mut() {
            o.write(chunk).map_err(Error::Io)?;
        }
        bytes += chunk.len() as u64;
        Ok(())
    };
    let decoded = if method == 0 { sink(&packed) } else { decode(&packed, dictionary, size, unpacker, &mut sink) };
    let fail = |out: Option<Output>, why: Outcome| {
        drop(out);
        if let Some(p) = &path {
            let _ = std::fs::remove_file(p);
        }
        Done { name: name.clone(), outcome: why }
    };
    match decoded {
        // only writing out gives an OS error; the decoder's own are about the data
        Err(Error::Io(e)) => return fail(out, Outcome::Fatal(Error::Io(e))),
        Err(e) => return fail(out, Outcome::Failed(e.to_string())),
        Ok(()) => {}
    }
    let crc_bad = crc32.is_some_and(|want| hasher.finalize() != want);
    let blake_bad = blake2sp.zip(blake).is_some_and(|(want, got)| got.finish() != want);
    if crc_bad || blake_bad {
        return fail(out, Outcome::Failed("checksum error".into()));
    }
    if bytes != size {
        return fail(out, Outcome::Failed(format!("{bytes} bytes where the header says {size}")));
    }
    if let Some(o) = out.take() {
        match o.finish() {
            Ok(file) => finish_file(&file, &meta),
            Err(e) => return fail(None, Outcome::Fatal(Error::Io(e))),
        }
    }
    Done { name, outcome: Outcome::Done(bytes) }
}

fn decode(
    packed: &[u8],
    dictionary: u64,
    size: u64,
    unpacker: &mut Option<Unpacker>,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let window = window_for(dictionary, Some(size), false)?;
    let u = match unpacker.as_mut().filter(|u| u.window_size() == window) {
        Some(u) => u,
        None => {
            let mut u = Unpacker::new(window)?;
            // the files themselves are the parallel work; each decodes on its own thread
            u.set_threads(0, u64::MAX);
            unpacker.insert(u)
        }
    };
    u.reset(Some(size));
    u.feed(packed, sink)?;
    u.finish(sink)
}

/// Checks (and, given `out`, copies to `out` from `out_at` on) `len` stored bytes at `at` in `volume`, on
/// `threads` threads. Returns the CRC32 of the bytes.
pub(crate) fn stored(
    volume: &Path,
    at: u64,
    len: u64,
    out: Option<&File>,
    out_at: u64,
    threads: usize,
) -> Result<crc32fast::Hasher> {
    let pieces = len.div_ceil(PIECE) as usize;
    let crcs: Vec<Mutex<Option<crc32fast::Hasher>>> = (0..pieces).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_error: Mutex<Option<Error>> = Mutex::new(None);
    thread::scope(|s| {
        for _ in 0..threads.min(pieces).max(1) {
            s.spawn(|| {
                let result = (|| -> Result<()> {
                    let file = File::open(volume)?;
                    let mut buf = vec![0u8; PIECE as usize];
                    loop {
                        if stop.load(Ordering::Relaxed) {
                            return Ok(());
                        }
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= pieces {
                            return Ok(());
                        }
                        let off = i as u64 * PIECE;
                        let n = PIECE.min(len - off) as usize;
                        read_at(&file, &mut buf[..n], at + off)?;
                        let mut h = crc32fast::Hasher::new();
                        h.update(&buf[..n]);
                        if let Some(out) = out {
                            write_at(out, &buf[..n], out_at + off)?;
                        }
                        *crcs[i].lock().unwrap() = Some(h);
                    }
                })();
                if let Err(e) = result {
                    stop.store(true, Ordering::Relaxed);
                    first_error.lock().unwrap().get_or_insert(e);
                }
            });
        }
    });
    if let Some(e) = first_error.into_inner().unwrap() {
        return Err(e);
    }
    let mut total = crc32fast::Hasher::new();
    for c in crcs {
        total.combine(&c.into_inner().unwrap().expect("every piece was done"));
    }
    Ok(total)
}

fn read_at(file: &File, buf: &mut [u8], mut at: u64) -> Result<()> {
    let mut done = 0;
    while done < buf.len() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(file, &mut buf[done..], at)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(file, &mut buf[done..], at)?;
        if n == 0 {
            return Err(Error::Truncated);
        }
        done += n;
        at += n as u64;
    }
    Ok(())
}

fn write_at(file: &File, mut buf: &[u8], mut at: u64) -> Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::write_at(file, buf, at)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_write(file, buf, at)?;
        if n == 0 {
            return Err(Error::Io(std::io::ErrorKind::WriteZero.into()));
        }
        buf = &buf[n..];
        at += n as u64;
    }
    Ok(())
}
