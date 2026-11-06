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

/// One block in a job: where it starts in the job's own bytes or in a piece of the volume it shares, where its bits
/// end, whether it starts with tables, and the slot for the lengths it is read with, which it fills itself when it
/// has tables. A part with a boundary holds no block: it marks where one file of a solid stream ends and the next
/// begins.
pub(super) struct Part {
    pub at: usize,
    /// [`OWN`], or which of the job's shared pieces the block lies in
    pub src: u32,
    pub end_bits: usize,
    pub read_tables: bool,
    pub slot: Arc<Slot>,
    pub boundary: Option<Boundary>,
}

/// A part whose block is in the job's own bytes.
pub(super) const OWN: u32 = u32::MAX;

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
    /// blocks copied in, each with its padding
    pub buf: Vec<u8>,
    /// pieces of the volume that blocks lie in whole, with their padding after them, kept rather than copied
    pub shared: Vec<Arc<Piece>>,
    /// packed bytes of all its blocks, padding included, wherever they lie
    pub packed: usize,
    pub parts: Vec<Part>,
    pub toks: Vec<Packed>,
    /// the fields of the filter records among the tokens, which don't fit in one
    pub filters: Vec<FilterFields>,
    pub lits: Vec<u8>,
    /// for each part the worker got to, where its tokens and literals end
    pub ends: Vec<(usize, usize)>,
}

impl Job {
    /// Empty for reuse, letting go of the pieces it shares.
    pub fn clear(&mut self) {
        self.buf.clear();
        self.shared.clear();
        self.packed = 0;
        self.parts.clear();
    }

    /// Where the blocks after the gathered ones will be: `piece`, if they lie in it.
    pub fn share(&mut self, piece: &Arc<Piece>) -> u32 {
        if !self.shared.last().is_some_and(|p| Arc::ptr_eq(p, piece)) {
            self.shared.push(Arc::clone(piece));
        }
        (self.shared.len() - 1) as u32
    }
}

/// A part's block, from its start to the end of what holds it.
pub(super) fn block_bytes<'a>(buf: &'a [u8], shared: &'a [Arc<Piece>], p: &Part) -> &'a [u8] {
    if p.src == OWN { &buf[p.at..] } else { &shared[p.src as usize].bytes()[p.at..] }
}

/// A worker's output for a job: every token read before the end of its blocks, the first error, or the memory
/// budget. `result` holds the block and the bit to go on from when the budget stopped it, and `tables` the tables
/// that block was being read with.
pub(super) struct Done {
    pub job: Job,
    pub result: Result<Option<(usize, usize)>>,
    pub tables: Arc<Tables>,
}

/// A token as a worker keeps it, in eight bytes: the kind in the low three bits, then its fields (a match's length in
/// 16 bits, its distance above). A filter record's fields don't fit, so they go to the job's list and the token holds
/// their place in it.
#[derive(Clone, Copy)]
pub(super) struct Packed(u64);

/// A filter record's offset, length and kind.
pub(super) type FilterFields = (u64, u64, FilterKind);

/// Where [`tokenize`] puts what it reads: tokens, filter fields, literals.
pub(super) type Out<'a> = (&'a mut Vec<Packed>, &'a mut Vec<FilterFields>, &'a mut Vec<u8>);

impl Packed {
    pub fn lits(n: u32) -> Packed {
        Packed(u64::from(n) << 3)
    }

    /// `tok` packed; a filter's fields are added to `filters`.
    pub fn new(tok: Tok, filters: &mut Vec<FilterFields>) -> Packed {
        match tok {
            Tok::Lits(n) => Packed::lits(n),
            Tok::Filter { offset, len, kind } => {
                filters.push((offset, len, kind));
                Packed(((filters.len() - 1) as u64) << 3 | 1)
            }
            Tok::Last => Packed(2),
            Tok::Rep { k, len } => Packed(u64::from(len) << 5 | u64::from(k) << 3 | 3),
            Tok::Match { len, dist } => {
                // a length is at most 4,100 and a distance under 2^33
                debug_assert!(len <= 0xffff && dist < 1 << 45);
                Packed(dist << 19 | u64::from(len & 0xffff) << 3 | 4)
            }
        }
    }

    /// The token, with a filter's fields from `filters`.
    #[inline(always)]
    pub fn get(self, filters: &[FilterFields]) -> Tok {
        let v = self.0;
        match v & 7 {
            0 => Tok::Lits((v >> 3) as u32),
            1 => {
                let (offset, len, kind) = filters[(v >> 3) as usize];
                Tok::Filter { offset, len, kind }
            }
            2 => Tok::Last,
            3 => Tok::Rep { k: ((v >> 3) & 3) as u8, len: (v >> 5) as u32 },
            _ => Tok::Match { len: ((v >> 3) & 0xffff) as u32, dist: v >> 19 },
        }
    }
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
    job.filters.clear();
    job.lits.clear();
    job.ends.clear();
    let budget = job.packed * BUDGET + SLACK;
    let mut result = Ok(None);
    let mut last = None;
    for (i, p) in job.parts.iter().enumerate() {
        if p.boundary.is_some() {
            if matches!(result, Ok(None)) {
                job.ends.push((job.toks.len(), job.lits.len()));
            }
            continue;
        }
        let mut bits = Bits::new(block_bytes(&job.buf, &job.shared, p));
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
        let out = (&mut job.toks, &mut job.filters, &mut job.lits);
        result = tokenize(block_bytes(&job.buf, &job.shared, p), start, p.end_bits, &tables, out, budget)
            .map(|stop| stop.map(|bit| (i, bit)));
        job.ends.push((job.toks.len(), job.lits.len()));
        last = Some(tables);
    }
    (result, last.unwrap_or_else(|| Arc::new(Tables::empty())))
}

/// A block's symbols, from `start_bit` to `end_bits`, as tokens. Literals go to `lits`, each run of them counted
/// by one `Lits` token. On an error, what was read before it is kept. Once the tokens and literals take more than
/// `budget` bytes it stops between symbols and returns the bit to go on from.
pub(super) fn tokenize(
    buf: &[u8],
    start_bit: usize,
    end_bits: usize,
    t: &Tables,
    (toks, filters, lits): Out<'_>,
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
        let held = lits.len() + toks.len() * size_of::<Packed>() + filters.len() * size_of::<FilterFields>();
        if held > budget {
            break Ok(Some(bits.pos()));
        }
        let sym;
        if bits.pos() + 128 <= end_bits {
            // three codes of at most 15 bits fit in one refill
            // SAFETY: 128 bits before the block's end, and a block's bytes go on for PAD past it
            unsafe { bits.refill_inside() };
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
            // SAFETY: as above: at most 45 bits have gone since the check, well inside PAD's 256
            unsafe { bits.refill_inside() };
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
            bits.refill();
        }
        if run > 0 {
            toks.push(Packed::lits(run));
            run = 0;
        }
        match read_op(sym, &mut bits, t) {
            Ok(tok) => toks.push(Packed::new(tok, filters)),
            Err(e) => break Err(e),
        }
    };
    if run > 0 {
        toks.push(Packed::lits(run));
    }
    if result.as_ref().is_ok_and(Option::is_none) && bits.pos() > end_bits {
        return Err(corrupt("a symbol runs past the end of its block"));
    }
    result
}
