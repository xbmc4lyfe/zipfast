//! Worker threads that read blocks' tables and symbols into tokens. The calling thread hands each block to a
//! worker and applies the workers' tokens to the window in block order, so output and errors come out exactly as if
//! it had decoded every block itself.

use super::*;
use std::sync::{Condvar, Mutex, mpsc};
use std::thread;

/// The code lengths one block with tables carries, for it and the blocks without tables after it. A worker fills it
/// once it has read them; None means they were damaged.
pub(super) struct Slot {
    lens: Mutex<Option<Option<Lengths>>>,
    ready: Condvar,
}

impl Slot {
    pub fn filled(lens: Option<Lengths>) -> Arc<Slot> {
        Arc::new(Slot { lens: Mutex::new(Some(lens)), ready: Condvar::new() })
    }

    pub fn pending() -> Arc<Slot> {
        Arc::new(Slot { lens: Mutex::new(None), ready: Condvar::new() })
    }

    fn fill(&self, lens: Option<Lengths>) {
        *self.lens.lock().unwrap_or_else(|e| e.into_inner()) = Some(lens);
        self.ready.notify_all();
    }

    /// The lengths, waiting for the worker reading them. Jobs are taken in order and a block with tables waits on
    /// nothing, so the worker that fills this is always already at work.
    pub fn wait(&self) -> Option<Lengths> {
        let mut g = self.lens.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(lens) = *g {
                return lens;
            }
            g = self.ready.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// One block in a job: where it starts in the job's bytes, where its bits end, whether it starts with tables, and
/// the slot for the lengths it is read with, which it fills itself when it has tables. A part with a boundary holds
/// no block: it marks where one file of a solid stream ends and the next begins.
pub(super) struct Part {
    pub at: usize,
    pub end_bits: usize,
    pub read_tables: bool,
    pub slot: Arc<Slot>,
    pub boundary: Option<Boundary>,
}

/// The end of one file of a solid stream and the start of the next.
#[derive(Clone, Copy)]
pub(super) struct Boundary {
    /// the next file's declared size
    pub size: Option<u64>,
    /// the file before it ended partway through a block
    pub truncated: bool,
}

/// A run of blocks for a worker, each payload with padding after it. Blocks go in runs so that handing them over
/// costs little next to decoding them.
#[derive(Default)]
pub(super) struct Job {
    pub seq: u64,
    pub buf: Vec<u8>,
    pub parts: Vec<Part>,
    pub toks: Vec<Tok>,
    pub lits: Vec<u8>,
    /// for each part the worker got to, where its tokens and literals end
    pub ends: Vec<(usize, usize)>,
}

/// A worker's output for a job: every token read before the end of its blocks, the first error, or the memory
/// budget. `result` holds the block and the bit to go on from when the budget stopped it, and `tables` the tables
/// that block was being read with.
pub(super) struct Done {
    pub job: Job,
    pub result: Result<Option<(usize, usize)>>,
    pub tables: Arc<Tables>,
}

/// A worker's tokens and literals for a block may take this many times the block's packed bytes, plus [`SLACK`].
/// Short codes can stand for far more tokens than that; past it the worker stops and the calling thread decodes the
/// rest of the block itself.
pub(super) const BUDGET: usize = 4;
const SLACK: usize = 1 << 20;

pub(super) struct Pool {
    jobs: Option<mpsc::Sender<Job>>,
    results: mpsc::Receiver<Done>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl Pool {
    pub fn new(threads: usize) -> Pool {
        let (jobs, job_rx) = mpsc::channel::<Job>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        let (done_tx, results) = mpsc::channel::<Done>();
        let mut workers = Vec::new();
        for i in 0..threads.max(1) {
            let job_rx = Arc::clone(&job_rx);
            let done_tx = done_tx.clone();
            let spawned = thread::Builder::new().name(format!("rar5-decode-{i}")).spawn(move || {
                // blocks without tables use the ones before; the tables built last are kept
                let mut cache: Option<(Arc<Slot>, Arc<Tables>)> = None;
                let mut pre = Huff::new();
                loop {
                    // the lock is held only while waiting for the next job
                    let next = job_rx.lock().map(|rx| rx.recv());
                    let Ok(Ok(mut job)) = next else { break };
                    let (result, tables) = work(&mut job, &mut cache, &mut pre);
                    if done_tx.send(Done { job, result, tables }).is_err() {
                        break;
                    }
                }
            });
            match spawned {
                Ok(handle) => workers.push(handle),
                // fewer workers than asked for still work, as long as there is one
                Err(e) if workers.is_empty() => panic!("can't start a decoder thread: {e}"),
                Err(_) => break,
            }
        }
        Pool { jobs: Some(jobs), results, workers }
    }

    pub fn submit(&self, job: Job) {
        self.jobs.as_ref().expect("pool is running").send(job).expect("decoder workers stopped");
    }

    /// The next finished block, waiting for one.
    pub fn next(&self) -> Done {
        self.results.recv().expect("decoder workers stopped")
    }

    /// A finished block, if one is ready now.
    pub fn try_next(&self) -> Option<Done> {
        self.results.try_recv().ok()
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        // closing the job channel lets each worker finish its job and stop
        self.jobs = None;
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

/// Reads a job's blocks into its tokens. Every slot the job fills is filled, even after an error or the budget
/// stops it, since later jobs may be waiting on them.
fn work(
    job: &mut Job,
    cache: &mut Option<(Arc<Slot>, Arc<Tables>)>,
    pre: &mut Huff,
) -> (Result<Option<(usize, usize)>>, Arc<Tables>) {
    job.toks.clear();
    job.lits.clear();
    job.ends.clear();
    let budget = job.buf.len() * BUDGET + SLACK;
    let mut result = Ok(None);
    let mut last = None;
    for (i, p) in job.parts.iter().enumerate() {
        if p.boundary.is_some() {
            if matches!(result, Ok(None)) {
                job.ends.push((job.toks.len(), job.lits.len()));
            }
            continue;
        }
        let mut bits = Bits::new(&job.buf[p.at..]);
        if !matches!(result, Ok(None)) {
            if p.read_tables {
                // after the budget stopped it the lengths are still good; after an error they no longer matter
                let lens = if result.is_ok() { read_lengths(pre, &mut bits, p.end_bits).ok() } else { None };
                p.slot.fill(lens);
            }
            continue;
        }
        let tables = match cache.as_ref() {
            Some((slot, t)) if !p.read_tables && Arc::ptr_eq(slot, &p.slot) => Ok(Arc::clone(t)),
            _ => {
                let lens = if p.read_tables {
                    let lens = read_lengths(pre, &mut bits, p.end_bits);
                    p.slot.fill(lens.as_ref().ok().copied());
                    lens
                } else {
                    p.slot.wait().ok_or_else(|| corrupt("the tables before this block were damaged"))
                };
                lens.and_then(|lens| {
                    let mut t = Tables::empty();
                    t.build(&lens)?;
                    let t = Arc::new(t);
                    *cache = Some((Arc::clone(&p.slot), Arc::clone(&t)));
                    Ok(t)
                })
            }
        };
        let tables = match tables {
            Ok(t) => t,
            Err(e) => {
                result = Err(e);
                job.ends.push((job.toks.len(), job.lits.len()));
                continue;
            }
        };
        let start = bits.pos();
        result = tokenize(&job.buf[p.at..], start, p.end_bits, &tables, &mut job.toks, &mut job.lits, budget)
            .map(|stop| stop.map(|bit| (i, bit)));
        job.ends.push((job.toks.len(), job.lits.len()));
        last = Some(tables);
    }
    (result, last.unwrap_or_else(|| Arc::new(Tables::empty())))
}

/// A block's symbols, from `start_bit` to `end_bits`, as tokens. Literals go to `lits`, each run of them counted
/// by one `Lits` token. On an error, what was read before it is kept. Once the tokens and literals take more than
/// `budget` bytes it stops between symbols and returns the bit to go on from.
fn tokenize(
    buf: &[u8],
    start_bit: usize,
    end_bits: usize,
    t: &Tables,
    toks: &mut Vec<Tok>,
    lits: &mut Vec<u8>,
    budget: usize,
) -> Result<Option<usize>> {
    let mut bits = Bits::at(buf, start_bit);
    lits.reserve((end_bits - start_bit) / 8);
    let mut run = 0u32;
    let mut stage = [0u8; STAGE + 8];
    macro_rules! decode {
        ($table:expr) => {
            match $table.decode(&mut bits) {
                Ok(sym) => sym,
                Err(e) => break Err(e),
            }
        };
    }
    let result = loop {
        if lits.len() + toks.len() * std::mem::size_of::<Tok>() > budget {
            break Ok(Some(bits.pos()));
        }
        let sym;
        if bits.pos() + 128 <= end_bits {
            // three codes of at most 15 bits fit in one refill
            bits.refill();
            let k = if t.main.common == 0 { 0 } else { t.main.quick_run(&mut bits, end_bits, &mut stage, STAGE) };
            if k > 0 {
                lits.extend_from_slice(&stage[..k]);
                run += k as u32;
                continue;
            }
            let s1 = decode!(t.main);
            if s1 >= 256 {
                sym = s1;
            } else {
                lits.push(s1 as u8);
                run += 1;
                let s2 = decode!(t.main);
                if s2 >= 256 {
                    sym = s2;
                } else {
                    lits.push(s2 as u8);
                    run += 1;
                    let s3 = decode!(t.main);
                    if s3 >= 256 {
                        sym = s3;
                    } else {
                        lits.push(s3 as u8);
                        run += 1;
                        continue;
                    }
                }
            }
        } else {
            if bits.pos() >= end_bits {
                break Ok(None);
            }
            bits.refill();
            let s = decode!(t.main);
            if s < 256 {
                lits.push(s as u8);
                run += 1;
                continue;
            }
            sym = s;
        }
        if run > 0 {
            toks.push(Tok::Lits(run));
            run = 0;
        }
        bits.refill();
        match read_op(sym, &mut bits, t) {
            Ok(tok) => toks.push(tok),
            Err(e) => break Err(e),
        }
    };
    if run > 0 {
        toks.push(Tok::Lits(run));
    }
    if result.as_ref().is_ok_and(Option::is_none) && bits.pos() > end_bits {
        return Err(corrupt("a symbol runs past the end of its block"));
    }
    result
}
