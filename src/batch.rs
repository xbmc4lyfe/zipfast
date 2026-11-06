//! Work spread over threads for RAR archives that aren't solid, where every file stands alone.
//!
//! Small files are read whole on the main thread and handed to workers, which decode, check and write them while
//! the next ones are read. Big stored files are checked and copied in pieces on several threads at once. Results
//! come back in archive order, so reports read the same as from a single thread.

use std::collections::BTreeMap;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::extract::{Meta, Place, create_target, finish_file};
use crate::output::Output;
use crate::rar5::unpack::{Sink, Unpacker, window_for};

/// Files up to this size, packed and unpacked, go to the workers whole.
pub(crate) const JOB_MAX: u64 = 16 << 20;
/// Stored data from this size up is copied on several threads.
pub(crate) const STORED_PARALLEL_MIN: u64 = 64 << 20;
/// The piece of stored data one thread checks and copies at a time.
const PIECE: u64 = 1 << 20;
/// Threads stored data is copied on at most. The copy waits on memory, not on the processor: past this many threads
/// it goes no faster, and the extra ones only spend time in the kernel contending for the same pages.
const STORED_THREADS: usize = 6;
/// Bytes of files read ahead of the workers. Enough that the main thread gets well ahead of them: a file too big to
/// hand them, which it decodes itself, then overlaps with theirs instead of being left to the end.
const BYTES_IN_FLIGHT: usize = 256 << 20;
/// Small files go to a worker in groups of up to this many bytes (packed and unpacked)...
const GROUP_BYTES: usize = 256 << 10;
/// ...or this many files, so that handing them over, which wakes a thread, costs little next to the work.
const GROUP_FILES: usize = 64;

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
    /// where it is written, created by the worker
    pub out: Option<Place>,
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
    tx: Option<Sender<Vec<(u64, Job)>>>,
    /// files handed over but not yet sent, with their weight
    group: Vec<(u64, Job)>,
    group_bytes: usize,
    rx: Receiver<Vec<(u64, Done, usize)>>,
    handles: Vec<JoinHandle<()>>,
    workers: usize,
    next: u64,
    applied: u64,
    bytes: usize,
    ready: BTreeMap<u64, (Done, usize)>,
}

impl Batch {
    pub(crate) fn new(workers: usize) -> Batch {
        let (tx, jobs) = mpsc::channel::<Vec<(u64, Job)>>();
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
                            let Ok(Ok(group)) = next else { break };
                            // results go back as a group too, so the main thread wakes once for it
                            let mut dones = Vec::with_capacity(group.len());
                            for (seq, job) in group {
                                let weight = weight(&job);
                                dones.push((seq, run(job, &mut unpacker), weight));
                            }
                            if done_tx.send(dones).is_err() {
                                break;
                            }
                        }
                    })
                    .ok()
            })
            .collect::<Vec<_>>();
        let workers = handles.len();
        Batch {
            tx: Some(tx),
            group: Vec::new(),
            group_bytes: 0,
            rx,
            handles,
            workers,
            next: 0,
            applied: 0,
            bytes: 0,
            ready: BTreeMap::new(),
        }
    }

    /// Whether any worker started.
    pub(crate) fn usable(&self) -> bool {
        self.workers > 0
    }

    /// Hands `job` over, first taking back finished files while too much is waiting. Finished files go to `apply`
    /// in archive order.
    /// Small files wait to be sent in a group; [`Self::send`] sends what is waiting.
    pub(crate) fn submit(&mut self, job: Job, apply: &mut dyn FnMut(Done) -> Result<()>) -> Result<()> {
        let weight = weight(&job);
        while self.next - self.applied >= (4 * self.workers * GROUP_FILES) as u64
            || (self.next > self.applied && self.bytes + weight > BYTES_IN_FLIGHT)
        {
            if let Err(e) = self.take_one(apply) {
                discard(job);
                return Err(e);
            }
        }
        if self.tx.is_none() {
            discard(job);
            return Err(stopped());
        }
        self.group.push((self.next, job));
        self.group_bytes += weight;
        self.bytes += weight;
        self.next += 1;
        if self.group_bytes >= GROUP_BYTES || self.group.len() >= GROUP_FILES {
            self.send()?;
        }
        Ok(())
    }

    /// Sends the files waiting in a group to the workers.
    pub(crate) fn send(&mut self) -> Result<()> {
        if self.group.is_empty() {
            return Ok(());
        }
        let group = std::mem::take(&mut self.group);
        self.group_bytes = 0;
        let Some(tx) = self.tx.as_ref() else { return Err(stopped()) };
        if let Err(mpsc::SendError(group)) = tx.send(group) {
            // every worker is gone; can't happen while one is alive
            group.into_iter().for_each(|(_, job)| discard(job));
            return Err(stopped());
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
        // the file waited for may still be in the group
        self.send()?;
        while !self.ready.contains_key(&self.applied) {
            let Ok(dones) = self.rx.recv() else { return Err(stopped()) };
            for (seq, done, weight) in dones {
                self.ready.insert(seq, (done, weight));
            }
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

/// Drops a job no worker will see. Its file was never created.
fn discard(job: Job) {
    drop(job);
}

/// What a job counts for against [`BYTES_IN_FLIGHT`] and [`GROUP_BYTES`].
fn weight(job: &Job) -> usize {
    job.packed.len() + job.size as usize
}

fn stopped() -> Error {
    Error::Io(std::io::Error::other("file workers stopped"))
}

fn run(job: Job, unpacker: &mut Option<Unpacker>) -> Done {
    let Job { name, packed, method, dictionary, size, crc32, blake2sp, out, meta } = job;
    let mut hasher = crate::crc32::Hasher::new();
    let mut blake = blake2sp.map(|_| Blake2sp::new());
    let (mut out, path) = match out {
        Some(place) => match create_target(&place, Some(size)) {
            Ok(file) => (Some(Output::new(file, Some(size))), Some(place.path)),
            Err(e) => return Done { name, outcome: Outcome::Fatal(e) },
        },
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
    sink: &mut dyn Sink,
) -> Result<()> {
    let window = window_for(dictionary, Some(size), false)?;
    let u = match unpacker.as_mut().filter(|u| u.fits(window)) {
        Some(u) => u,
        None => {
            let mut u = Unpacker::new(window)?;
            // the files themselves are the parallel work; each decodes on its own thread
            u.set_threads(0, u64::MAX);
            unpacker.insert(u)
        }
    };
    u.restart(window, Some(size));
    u.feed(packed, sink)?;
    u.finish(sink)
}

/// Checks (and, given `out`, copies to `out` from `out_at` on) `len` stored bytes at `at` in the open `volume`, on
/// `threads` threads (no more than [`STORED_THREADS`]). Returns the CRC32 of the bytes.
pub(crate) fn stored(
    volume: &File,
    at: u64,
    len: u64,
    out: Option<&File>,
    out_at: u64,
    threads: usize,
) -> Result<crate::crc32::Hasher> {
    let pieces = len.div_ceil(PIECE) as usize;
    let crcs: Vec<Mutex<Option<crate::crc32::Hasher>>> = (0..pieces).map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let first_error: Mutex<Option<Error>> = Mutex::new(None);
    let flusher = out.filter(|f| defers_to_close(f)).map(Flusher::new);
    thread::scope(|s| {
        for _ in 0..threads.min(STORED_THREADS).min(pieces).max(1) {
            s.spawn(|| {
                let result = (|| -> Result<()> {
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
                        read_at(volume, &mut buf[..n], at + off)?;
                        let mut h = crate::crc32::Hasher::new();
                        h.update(&buf[..n]);
                        if let Some(out) = out {
                            write_at(out, &buf[..n], out_at + off)?;
                            if let Some(f) = &flusher {
                                f.wrote(n as u64);
                            }
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
    let mut total = crate::crc32::Hasher::new();
    for c in crcs {
        total.combine(&c.into_inner().unwrap().expect("every piece was done"));
    }
    Ok(total)
}

/// A big stored file's copy pushes what it has written to the disk every this many bytes. Its pieces land out of
/// order, and APFS then holds them all in memory until the file is closed, where the close spends as long writing
/// them as the copy spent reading the archive. Pushed out on the way, they are written while the reading goes on.
const FLUSH_EVERY: u64 = 64 << 20;

/// Pushes a file's data to the disk as the copy into it goes on (see [`FLUSH_EVERY`]). One copying thread at a time
/// does it, and waits for it, while the others go on copying.
struct Flusher<'a> {
    file: &'a File,
    written: AtomicU64,
    due: AtomicU64,
    busy: AtomicBool,
}

impl<'a> Flusher<'a> {
    fn new(file: &'a File) -> Self {
        Flusher { file, written: AtomicU64::new(0), due: AtomicU64::new(FLUSH_EVERY), busy: AtomicBool::new(false) }
    }

    /// `n` more bytes were written.
    fn wrote(&self, n: u64) {
        let written = self.written.fetch_add(n, Ordering::Relaxed) + n;
        if written < self.due.load(Ordering::Relaxed) || self.busy.swap(true, Ordering::Acquire) {
            return;
        }
        self.due.store(written + FLUSH_EVERY, Ordering::Relaxed);
        flush_data(self.file);
        self.busy.store(false, Ordering::Release);
    }
}

/// Whether `file` is on a file system that keeps data written out of order until the file is closed: APFS.
#[cfg(target_os = "macos")]
fn defers_to_close(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: statfs is plain data, which fstatfs fills in for an open descriptor
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 {
        return false;
    }
    let name = fs.f_fstypename.map(|c| c as u8);
    name.starts_with(b"apfs\0")
}

#[cfg(not(target_os = "macos"))]
fn defers_to_close(_file: &File) -> bool {
    false
}

/// Writes `file`'s data out now, waiting until it is on the disk; best effort.
#[cfg(target_os = "macos")]
fn flush_data(file: &File) {
    use std::os::fd::AsRawFd;
    const F_FLUSH_DATA: libc::c_int = 40;
    // SAFETY: fcntl on an open descriptor, with no argument to point at anything
    unsafe { libc::fcntl(file.as_raw_fd(), F_FLUSH_DATA) };
}

#[cfg(not(target_os = "macos"))]
fn flush_data(_file: &File) {}

pub(crate) fn read_at(file: &File, buf: &mut [u8], mut at: u64) -> Result<()> {
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn only_apfs_is_taken_to_hold_writes_until_close() {
        // the system volume is APFS on any macOS this builds for; /dev is never
        assert!(defers_to_close(&File::open("/").unwrap()));
        assert!(!defers_to_close(&File::open("/dev").unwrap()));
    }

    #[test]
    fn a_copy_is_pushed_to_the_disk_every_so_often() {
        let path = std::env::temp_dir().join(format!("zipfast-flush-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        let f = Flusher::new(&file);
        f.wrote(FLUSH_EVERY - 1);
        assert_eq!(f.due.load(Ordering::Relaxed), FLUSH_EVERY);
        f.wrote(2);
        assert_eq!(f.due.load(Ordering::Relaxed), 2 * FLUSH_EVERY + 1);
        assert!(!f.busy.load(Ordering::Relaxed));
        drop(file);
        let _ = std::fs::remove_file(&path);
    }
}
