//! Worker threads that read blocks' symbols into tokens. The calling thread reads each block's tables, hands the
//! block to a worker, and applies the workers' tokens to the window in block order, so output and errors come out
//! exactly as if it had decoded every block itself.

use super::*;
use std::sync::{Mutex, mpsc};
use std::thread;

/// One block for a worker: its payload with padding after it, where its symbols start, and its tables.
pub(super) struct Job {
    pub seq: u64,
    pub buf: Vec<u8>,
    pub start_bit: usize,
    pub end_bits: usize,
    pub tables: Arc<Tables>,
    pub toks: Vec<Tok>,
    pub lits: Vec<u8>,
}

/// A worker's output for one block: every token read before the end of the block, the first error, or the memory
/// budget. `result` holds the bit to go on from when the budget stopped it.
pub(super) struct Done {
    pub seq: u64,
    pub buf: Vec<u8>,
    pub toks: Vec<Tok>,
    pub lits: Vec<u8>,
    pub result: Result<Option<usize>>,
    pub tables: Arc<Tables>,
    pub end_bits: usize,
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
                loop {
                    // the lock is held only while waiting for the next job
                    let next = job_rx.lock().map(|rx| rx.recv());
                    let Ok(Ok(mut job)) = next else { break };
                    job.toks.clear();
                    job.lits.clear();
                    let budget = job.buf.len() * BUDGET + SLACK;
                    let result = tokenize(
                        &job.buf,
                        job.start_bit,
                        job.end_bits,
                        &job.tables,
                        &mut job.toks,
                        &mut job.lits,
                        budget,
                    );
                    let done = Done {
                        seq: job.seq,
                        buf: job.buf,
                        toks: job.toks,
                        lits: job.lits,
                        result,
                        tables: job.tables,
                        end_bits: job.end_bits,
                    };
                    if done_tx.send(done).is_err() {
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
            if let Some((quick, n)) = t.main.quick(&mut bits) {
                lits.extend_from_slice(&quick[..n]);
                run += n as u32;
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
