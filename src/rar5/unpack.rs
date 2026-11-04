//! RAR 5.0 decompression (algorithm version 0), written from a behavioural specification of the format.
//!
//! The decoder is fed a file's packed bytes in whatever pieces they arrive in (one volume's part at a time) and
//! decodes every compressed block as soon as all of it is in. Decoded bytes go to a sink in file order, after any
//! filters over them have run.

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::sync::Arc;

mod parallel;
use parallel::{Done, Job, Pool};

pub(crate) const NC: usize = 306;
pub(crate) const DC: usize = 64;
pub(crate) const LDC: usize = 16;
pub(crate) const RC: usize = 44;
pub(crate) const BC: usize = 20;
const TABLES: usize = NC + DC + LDC + RC;
/// Zero bytes after a block's payload, so reads near its end never need a bounds check.
const PAD: usize = 32;
const MAX_FILTERS: usize = 8192;
const MAX_FILTER_LEN: u64 = 0x40_0000;
/// Quick literals gathered before they go to the window.
const STAGE: usize = 256;
/// Bits of a code looked up in one step; longer codes take the slow path.
const LUT_BITS: u32 = 11;

fn corrupt(what: &'static str) -> Error {
    Error::Corrupt(what)
}

/// MSB-first bits over one block's payload, followed by [`PAD`] zero bytes. Bits are taken from a 64-bit
/// accumulator that [`Bits::refill`] tops up to at least 56 bits; every read must fit in what a refill guarantees.
struct Bits<'a> {
    buf: &'a [u8],
    /// the next byte not yet in `acc`
    next: usize,
    /// unread bits, left-aligned; everything below the top `cnt` bits is zero
    acc: u64,
    cnt: u32,
}

impl<'a> Bits<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let mut b = Bits { buf, next: 0, acc: 0, cnt: 0 };
        b.refill();
        b
    }

    /// Bits from bit `bit` of `buf` on.
    fn at(buf: &'a [u8], bit: usize) -> Self {
        let mut b = Bits { buf, next: bit / 8, acc: 0, cnt: 0 };
        b.refill();
        b.skip((bit % 8) as u32);
        b
    }

    /// At least 56 bits in the accumulator afterwards.
    #[inline(always)]
    fn refill(&mut self) {
        // the padding keeps `next + 8` inside the buffer while the position is within a symbol of the payload's end
        let bytes: [u8; 8] = self.buf[self.next..self.next + 8].try_into().unwrap();
        self.acc |= u64::from_be_bytes(bytes) >> self.cnt;
        self.next += ((63 - self.cnt) >> 3) as usize;
        self.cnt |= 56;
    }

    /// Bits read so far.
    #[inline(always)]
    fn pos(&self) -> usize {
        self.next * 8 - self.cnt as usize
    }

    #[inline(always)]
    fn peek16(&self) -> u32 {
        (self.acc >> 48) as u32
    }

    #[inline(always)]
    fn skip(&mut self, n: u32) {
        self.acc <<= n;
        self.cnt -= n;
    }

    /// Up to 32 bits.
    #[inline(always)]
    fn get(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = (self.acc >> (64 - n)) as u32;
        self.skip(n);
        v
    }
}

/// A canonical prefix code with a lookup table for short codes.
#[derive(Clone)]
struct Huff {
    /// symbol << 4 | length, or 0 when the code is longer than the table
    lut: Box<[u16; 1 << LUT_BITS]>,
    /// for each length, the first 16-bit left-aligned value past every code of that length or shorter
    limit: [u32; 16],
    /// for each length, the left-aligned first code of that length
    first: [u32; 16],
    /// for each length, where its symbols start in `sorted`
    start: [u16; 16],
    sorted: Vec<u16>,
    /// no codes at all
    empty: bool,
    /// the length most literals have, when it is short enough for [`Huff::quick`]; 0 otherwise
    common: u32,
}

impl Huff {
    fn new() -> Self {
        Huff {
            lut: Box::new([0; 1 << LUT_BITS]),
            limit: [0; 16],
            first: [0; 16],
            start: [0; 16],
            sorted: Vec::new(),
            empty: true,
            common: 0,
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn build(&mut self, lengths: &[u8]) -> Result<()> {
        let mut count = [0u32; 16];
        for &l in lengths {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut kraft = 0u32;
        for (l, &c) in count.iter().enumerate().skip(1) {
            kraft += c << (16 - l);
        }
        if kraft > 1 << 16 {
            return Err(corrupt("over-subscribed prefix code"));
        }
        let mut code = 0u32;
        let mut index = 0u32;
        for l in 1..16 {
            self.first[l] = code << (16 - l);
            self.start[l] = index as u16;
            code += count[l];
            index += count[l];
            self.limit[l] = code << (16 - l);
            code <<= 1;
        }
        // symbols in (length, symbol) order
        let mut next = self.start;
        self.sorted.clear();
        self.sorted.resize(index as usize, 0);
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                self.sorted[next[l as usize] as usize] = sym as u16;
                next[l as usize] += 1;
            }
        }
        self.empty = index == 0;
        // incompressible data comes out as literals nearly all of one length: worth guessing at
        let mut by_len = [0u32; 16];
        for &l in lengths.iter().take(256) {
            by_len[l as usize] += 1;
        }
        by_len[0] = 0;
        let (len, n) = by_len.iter().enumerate().max_by_key(|&(l, &n)| (n, std::cmp::Reverse(l))).unwrap();
        self.common = if lengths.len() >= 256 && *n >= 64 && len <= LUT_BITS as usize { len as u32 } else { 0 };
        self.lut.fill(0);
        for l in 1..=LUT_BITS as usize {
            let from = self.start[l] as usize;
            let first = self.first[l] >> (16 - l);
            for (rank, &sym) in self.sorted[from..from + count[l] as usize].iter().enumerate() {
                let code = first + rank as u32;
                let at = (code << (LUT_BITS as usize - l)) as usize;
                self.lut[at..at + (1 << (LUT_BITS as usize - l))].fill((sym << 4) | l as u16);
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16> {
        let peek = bits.peek16();
        let entry = self.lut[(peek >> (16 - LUT_BITS)) as usize];
        if entry != 0 {
            bits.skip(u32::from(entry & 15));
            return Ok(entry >> 4);
        }
        self.decode_slow(peek, bits)
    }

    /// Up to six literals of the common length from one refill. All the lookups are made at once, as if every
    /// code had that length, and kept for as long as that holds. Returns them with how many there are (none when
    /// the first code isn't such a literal). Needs 56 bits in the accumulator.
    #[inline(always)]
    fn quick(&self, bits: &mut Bits<'_>) -> ([u8; 6], usize) {
        let g = self.common;
        let a = bits.acc;
        let sh = 64 - LUT_BITS;
        let at = |k: u32| self.lut[((a << (k * g)) >> sh) as usize];
        // a literal (symbol below 256, so the top four bits clear) of length g
        let hit = |e: u16| u32::from(e & 0xF00F) == g;
        let e = [at(0), at(1), at(2), at(3), at(4), at(5)];
        let lits = e.map(|e| (e >> 4) as u8);
        if g == 0 || !hit(e[0]) {
            return (lits, 0);
        }
        // six codes fit in a refill only when they are short; four always do
        let most = if g <= 9 { 6 } else { 4 };
        let mut n = 1;
        while n < most && hit(e[n]) {
            n += 1;
        }
        bits.skip(n as u32 * g);
        (lits, n)
    }

    #[cold]
    fn decode_slow(&self, peek: u32, bits: &mut Bits<'_>) -> Result<u16> {
        for l in LUT_BITS as usize + 1..16 {
            if peek < self.limit[l] && peek >= self.first[l] {
                let idx = self.start[l] as u32 + ((peek - self.first[l]) >> (16 - l));
                bits.skip(l as u32);
                return self.sorted.get(idx as usize).copied().ok_or(corrupt("prefix code"));
            }
        }
        Err(corrupt(if self.empty { "symbol from an empty prefix code" } else { "bit pattern matches no code" }))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilterKind {
    Delta(u8),
    E8,
    E8E9,
    Arm,
}

#[derive(Clone, Copy, Debug)]
struct Filter {
    /// file-relative output position
    start: u64,
    len: u64,
    kind: FilterKind,
}

/// The four prefix codes a block's symbols are read with.
#[derive(Clone)]
struct Tables {
    main: Huff,
    dist: Huff,
    low: Huff,
    rep: Huff,
}

/// A decoded operation. Literals travel separately; `Lits` says how many come next.
#[derive(Clone, Copy, Debug)]
enum Tok {
    Lits(u32),
    /// `offset` is from the file position the filter record was read at
    Filter {
        offset: u64,
        len: u64,
        kind: FilterKind,
    },
    Last,
    Rep {
        k: u8,
        len: u32,
    },
    Match {
        len: u32,
        dist: u64,
    },
}

/// Packed bytes that may wait with the workers before the calling thread stops handing them more. A worker's
/// tokens for a block stay within [`parallel::BUDGET`] times its packed size, so this also bounds their memory.
const MAX_QUEUED: usize = 32 << 20;

/// Big files are decoded on worker threads from this size up, unless told otherwise.
const PARALLEL_MIN: u64 = 4 << 20;

/// The decoder's state. A solid stream keeps one of these across files.
pub struct Unpacker {
    window: Vec<u8>,
    mask: u64,
    /// bytes decoded in the whole stream
    sp: u64,
    /// `sp` when the current file started
    file_base: u64,
    /// bytes of the current file emitted to the sink
    emitted: u64,
    /// the current file's declared size, None when unknown
    size: Option<u64>,
    tables_ready: bool,
    tables: Arc<Tables>,
    history: [u64; 4],
    last_len: u32,
    filters: Vec<Filter>,
    /// filtered output for one filter at a time
    scratch: Vec<u8>,
    /// packed bytes not yet decoded: always the start of a block
    input: Vec<u8>,
    /// a whole block copied out with zero padding after it, when nothing follows it to pad it
    padded: Vec<u8>,
    /// worker threads for big files; 0 decodes everything on the calling thread
    threads: usize,
    /// the smallest file decoded on workers
    parallel_min: u64,
    /// whether the current file's blocks go to workers
    parallel: bool,
    pool: Option<Pool>,
    /// blocks handed to workers, and blocks applied to the window, both counted over the decoder's life
    submitted: u64,
    applied: u64,
    /// packed bytes of the blocks not yet applied
    queued: usize,
    /// blocks a worker stopped early on, at its memory budget, and this thread finished
    resumed: u64,
    /// finished blocks waiting for the ones before them
    ready: BTreeMap<u64, Done>,
    /// buffers from finished blocks, for reuse
    spare: Vec<(Vec<u8>, Vec<Tok>, Vec<u8>)>,
}

/// The window a file needs: its declared dictionary, but no more than twice the file when nothing before or after it
/// can refer back into it. Twice, because a filter may cover up to half the window and a filter may cover the whole
/// file.
pub fn window_for(dictionary: u64, unpacked: Option<u64>, solid_stream: bool) -> Result<u64> {
    if dictionary == 0 || !dictionary.is_power_of_two() {
        return Err(Error::Unsupported(format!("dictionary size {dictionary}")));
    }
    let need = match unpacked {
        // bounded by the dictionary first, so an absurd stated size can't overflow the rounding
        Some(size) if !solid_stream => (size.min(dictionary).max(1) * 2).next_power_of_two().max(128 * 1024),
        _ => dictionary,
    };
    Ok(need.min(dictionary))
}

impl Unpacker {
    /// A fresh stream with a window of `window` bytes (a power of two).
    pub fn new(window: u64) -> Result<Self> {
        let size = usize::try_from(window).map_err(|_| Error::Unsupported("dictionary too large".into()))?;
        let mut v = Vec::new();
        v.try_reserve_exact(size).map_err(|_| Error::Unsupported(format!("can't allocate a {window} byte window")))?;
        v.resize(size, 0);
        Ok(Unpacker {
            window: v,
            mask: window - 1,
            sp: 0,
            file_base: 0,
            emitted: 0,
            size: None,
            tables_ready: false,
            tables: Arc::new(Tables { main: Huff::new(), dist: Huff::new(), low: Huff::new(), rep: Huff::new() }),
            history: [0; 4],
            last_len: 0,
            filters: Vec::new(),
            scratch: Vec::new(),
            input: Vec::new(),
            padded: Vec::new(),
            threads: default_threads(),
            parallel_min: PARALLEL_MIN,
            parallel: false,
            pool: None,
            submitted: 0,
            applied: 0,
            queued: 0,
            resumed: 0,
            ready: BTreeMap::new(),
            spare: Vec::new(),
        })
    }

    /// How many worker threads big files are decoded on (0 for none), and from what file size.
    pub fn set_threads(&mut self, threads: usize, min_size: u64) {
        self.discard_in_flight();
        if threads != self.threads {
            self.pool = None;
        }
        self.threads = threads;
        self.parallel_min = min_size;
        self.parallel = self.wants_parallel();
    }

    /// Worker threads big files are decoded on.
    pub fn threads(&self) -> usize {
        self.threads
    }

    /// The smallest file decoded on workers.
    pub fn parallel_min(&self) -> u64 {
        self.parallel_min
    }

    fn wants_parallel(&self) -> bool {
        self.threads > 0 && self.size.is_none_or(|s| s >= self.parallel_min)
    }

    pub fn window_size(&self) -> u64 {
        self.mask + 1
    }

    /// Starts the next file of a solid stream: the window, tables and history carry on.
    pub fn next_file(&mut self, size: Option<u64>) {
        self.discard_in_flight();
        self.file_base = self.sp;
        self.emitted = 0;
        self.size = size;
        self.filters.clear();
        self.input.clear();
        self.parallel = self.wants_parallel();
    }

    /// Starts a file that stands alone in a stream this decoder already decoded into: everything resets.
    pub fn reset(&mut self, size: Option<u64>) {
        // no match may reach before the stream's first byte, so old window contents are never read
        self.sp = 0;
        self.tables_ready = false;
        self.history = [0; 4];
        self.last_len = 0;
        self.next_file(size);
    }

    fn op(&self) -> u64 {
        self.sp - self.file_base
    }

    /// Hands a block to the workers. Its tables are read here, since later blocks may reuse them; the symbols are
    /// read on a worker and applied to the window in order by [`Self::settle`].
    fn submit(
        &mut self,
        buf: &[u8],
        payload: usize,
        flags: u8,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let valid_bits = usize::from(flags & 7) + 1;
        let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
        let (mut block, toks, lits) = self.spare.pop().unwrap_or_default();
        block.clear();
        block.extend_from_slice(&buf[..payload + PAD]);
        let mut bits = Bits::new(&block);
        let tables = if flags & 0x80 != 0 {
            self.read_tables(&mut bits, end_bits)
        } else if !self.tables_ready && payload > 0 {
            Err(corrupt("block without tables at the start of a stream"))
        } else {
            Ok(())
        };
        let start_bit = bits.pos();
        if let Err(e) = tables {
            // an earlier block's error comes first
            self.settle(0, sink)?;
            return Err(e);
        }
        if start_bit >= end_bits {
            self.spare.push((block, toks, lits));
            if start_bit > end_bits {
                self.settle(0, sink)?;
                return Err(corrupt("a symbol runs past the end of its block"));
            }
            return Ok(());
        }
        if self.pool.is_none() {
            self.pool = Some(Pool::new(self.threads));
        }
        let job =
            Job { seq: self.submitted, buf: block, start_bit, end_bits, tables: Arc::clone(&self.tables), toks, lits };
        self.queued += job.buf.len();
        self.pool.as_ref().unwrap().submit(job);
        self.submitted += 1;
        self.settle(2 * self.threads as u64, sink)
    }

    /// Applies finished blocks in order until no more than `max` are still with the workers. The first error in
    /// stream order is returned; after one, the rest are collected and dropped.
    fn settle(&mut self, max: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut max = max;
        let mut failed = None;
        loop {
            while let Some(done) = self.ready.remove(&self.applied) {
                self.applied += 1;
                let Done { buf, toks, lits, result, tables, end_bits, .. } = done;
                self.queued -= buf.len();
                if failed.is_none() {
                    let mut applied = self.apply(&toks, &lits, sink).and(result);
                    // the worker stopped at its memory budget: the rest of the block is decoded here
                    if let Ok(Some(bit)) = applied {
                        let mut bits = Bits::at(&buf, bit);
                        self.resumed += 1;
                        applied = self.decode_rest(&mut bits, end_bits, &tables, sink).map(|()| None);
                    }
                    if let Err(e) = applied {
                        failed = Some(e);
                        max = 0;
                    }
                }
                self.spare.push((buf, toks, lits));
            }
            let in_flight = self.submitted - self.applied;
            if in_flight == 0 {
                break;
            }
            let Some(pool) = self.pool.as_ref() else { break };
            let done = if in_flight <= max && self.queued <= MAX_QUEUED {
                // take what's finished, but don't wait
                match pool.try_next() {
                    Some(done) => done,
                    None => break,
                }
            } else {
                pool.next()
            };
            self.ready.insert(done.seq, done);
        }
        failed.map_or(Ok(()), Err)
    }

    /// An error found reading ahead of the workers waits for theirs: an earlier block's error comes first.
    fn ordered<T>(&mut self, r: Result<T>, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<T> {
        if r.is_err() && self.submitted > self.applied {
            self.settle(0, sink)?;
        }
        r
    }

    /// Waits out blocks still with the workers and drops them: the file they belong to was abandoned.
    fn discard_in_flight(&mut self) {
        while self.applied < self.submitted {
            if !self.ready.contains_key(&self.applied) {
                let Some(pool) = self.pool.as_ref() else { break };
                let done = pool.next();
                self.ready.insert(done.seq, done);
                continue;
            }
            if let Some(Done { buf, toks, lits, .. }) = self.ready.remove(&self.applied) {
                self.queued -= buf.len();
                self.spare.push((buf, toks, lits));
            }
            self.applied += 1;
        }
        self.applied = self.submitted;
        self.ready.clear();
        self.queued = 0;
    }

    /// One block's tokens, applied to the window with the same checks the decoding loop makes.
    fn apply(&mut self, toks: &[Tok], lits: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let flush_at = self.window_size() / 2;
        let size_end = self.size.map_or(u64::MAX, |s| self.file_base.saturating_add(s));
        let mut li = 0usize;
        for &tok in toks {
            if self.sp - self.file_base - self.emitted > flush_at {
                self.flush(sink)?;
            }
            match tok {
                Tok::Lits(n) => {
                    let mut n = n as usize;
                    while n > 0 {
                        if self.sp - self.file_base - self.emitted > flush_at {
                            self.flush(sink)?;
                        }
                        if self.sp >= size_end {
                            return Err(corrupt("more data than the header says"));
                        }
                        let stop = self.file_base + self.emitted + flush_at + 1;
                        let room = stop.min(size_end).saturating_sub(self.sp);
                        let take = n.min(usize::try_from(room).unwrap_or(usize::MAX));
                        if take == 0 {
                            return Err(corrupt("the window can't hold the pending output"));
                        }
                        self.put(&lits[li..li + take]);
                        li += take;
                        n -= take;
                    }
                }
                Tok::Filter { offset, len, kind } => {
                    let op = self.op();
                    let window = self.window_size();
                    add_filter(&mut self.filters, op, offset, len, kind, window)?;
                }
                _ => {
                    if let Some((len, d)) = resolve(tok, &mut self.history, &mut self.last_len) {
                        copy(&mut self.window, self.mask, self.sp, len, d, size_end)?;
                        self.sp += u64::from(len);
                    }
                }
            }
        }
        Ok(())
    }

    /// Literal bytes into the window at the stream position.
    fn put(&mut self, bytes: &[u8]) {
        let at = (self.sp & self.mask) as usize;
        let first = bytes.len().min(self.window.len() - at);
        self.window[at..at + first].copy_from_slice(&bytes[..first]);
        self.window[..bytes.len() - first].copy_from_slice(&bytes[first..]);
        self.sp += bytes.len() as u64;
    }

    /// More of the file's packed bytes. Every block that is now complete is decoded and its output emitted. Blocks
    /// that arrive whole are decoded where they lie; only a block split across calls is gathered first.
    pub fn feed(&mut self, mut data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        // finish the block an earlier call left incomplete
        while !self.input.is_empty() {
            let flags = self.input[0];
            let header_len = 2 + usize::from((flags >> 3) & 7) + 1;
            let header = block_header(&self.input);
            let need = match self.ordered(header, sink)? {
                Some((header_len, payload, _)) => header_len + payload,
                None => header_len,
            };
            let take = need.saturating_sub(self.input.len()).min(data.len());
            self.input.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.input.len() < need {
                return Ok(());
            }
            let header = block_header(&self.input);
            if let Some((header_len, payload, flags)) = self.ordered(header, sink)?
                && self.input.len() == header_len + payload
            {
                let mut block = std::mem::take(&mut self.input);
                block.resize(header_len + payload + PAD, 0);
                let result = self.block(&block[header_len..], payload, flags, sink);
                block.clear();
                self.input = block;
                result?;
            }
        }
        let mut at = 0;
        loop {
            let rest = &data[at..];
            let header = block_header(rest);
            let Some((header_len, payload, flags)) = self.ordered(header, sink)? else { break };
            if rest.len() < header_len + payload {
                break;
            }
            let start = at + header_len;
            let end = start + payload;
            if data.len() >= end + PAD {
                // the bytes after the block serve as its padding
                self.block(&data[start..end + PAD], payload, flags, sink)?;
            } else {
                let mut padded = std::mem::take(&mut self.padded);
                padded.clear();
                padded.extend_from_slice(&data[start..end]);
                padded.resize(payload + PAD, 0);
                let result = self.block(&padded, payload, flags, sink);
                self.padded = padded;
                result?;
            }
            at = end;
        }
        self.input.extend_from_slice(&data[at..]);
        Ok(())
    }

    /// The file's packed bytes are all in. Emits what is left and checks the stream ended where it should.
    pub fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.settle(0, sink)?;
        if !self.input.is_empty() {
            return Err(Error::Truncated);
        }
        self.flush(sink)?;
        if !self.filters.is_empty() {
            return Err(corrupt("a filter runs past the end of the file"));
        }
        if let Some(size) = self.size
            && self.emitted != size
        {
            return Err(corrupt("decoded size differs from the header"));
        }
        Ok(())
    }

    fn block(
        &mut self,
        buf: &[u8],
        payload: usize,
        flags: u8,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.parallel {
            return self.submit(buf, payload, flags, sink);
        }
        let valid_bits = usize::from(flags & 7) + 1;
        let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
        let mut bits = Bits::new(buf);
        if flags & 0x80 != 0 {
            self.read_tables(&mut bits, end_bits)?;
        } else if !self.tables_ready && payload > 0 {
            return Err(corrupt("block without tables at the start of a stream"));
        }
        let tables = Arc::clone(&self.tables);
        self.decode_rest(&mut bits, end_bits, &tables, sink)
    }

    /// Decodes a block's symbols from where `bits` stands to its end on this thread.
    fn decode_rest(
        &mut self,
        bits: &mut Bits<'_>,
        end_bits: usize,
        tables: &Tables,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        let flush_at = self.window_size() / 2;
        while bits.pos() < end_bits {
            if self.sp - self.file_base - self.emitted > flush_at {
                self.flush(sink)?;
            }
            // decode until the block ends or the window holds as much unflushed output as it may
            let stop = self.file_base + self.emitted + flush_at + 1;
            self.run(bits, end_bits, stop, tables)?;
        }
        if bits.pos() > end_bits {
            return Err(corrupt("a symbol runs past the end of its block"));
        }
        Ok(())
    }

    fn read_tables(&mut self, bits: &mut Bits<'_>, end: usize) -> Result<()> {
        let mut bl = [0u8; BC];
        let mut i = 0;
        while i < BC {
            bits.refill();
            if bits.pos() + 4 > end {
                return Err(corrupt("table runs past its block"));
            }
            let n = bits.get(4) as u8;
            if n == 15 {
                if bits.pos() + 4 > end {
                    return Err(corrupt("table runs past its block"));
                }
                let z = bits.get(4) as usize;
                if z == 0 {
                    bl[i] = 15;
                    i += 1;
                } else {
                    let run = (z + 2).min(BC - i);
                    i += run;
                }
            } else {
                bl[i] = n;
                i += 1;
            }
        }
        let mut pre = Huff::new();
        pre.build(&bl)?;
        let mut lens = [0u8; TABLES];
        let mut i = 0;
        while i < TABLES {
            bits.refill();
            if bits.pos() >= end {
                return Err(corrupt("table runs past its block"));
            }
            let sym = pre.decode(bits)?;
            match sym {
                0..=15 => {
                    lens[i] = sym as u8;
                    i += 1;
                }
                16 | 17 => {
                    if i == 0 {
                        return Err(corrupt("table repeats a length before the first"));
                    }
                    let n = if sym == 16 { 3 + bits.get(3) } else { 11 + bits.get(7) } as usize;
                    let prev = lens[i - 1];
                    let run = n.min(TABLES - i);
                    lens[i..i + run].fill(prev);
                    i += run;
                }
                _ => {
                    let n = if sym == 18 { 3 + bits.get(3) } else { 11 + bits.get(7) } as usize;
                    let run = n.min(TABLES - i);
                    lens[i..i + run].fill(0);
                    i += run;
                }
            }
        }
        if bits.pos() > end {
            return Err(corrupt("table runs past its block"));
        }
        // blocks still with the workers keep the tables they were sent with
        let t = Arc::make_mut(&mut self.tables);
        t.main.build(&lens[..NC])?;
        t.dist.build(&lens[NC..NC + DC])?;
        t.low.build(&lens[NC + DC..NC + DC + LDC])?;
        t.rep.build(&lens[NC + DC + LDC..])?;
        self.tables_ready = true;
        Ok(())
    }

    /// The decoding loop: symbols until the block's bits run out or the stream position reaches `stop`. The state
    /// it touches on every symbol lives in locals, so the window writes can't make the compiler reload it.
    fn run(&mut self, bits: &mut Bits<'_>, end_bits: usize, stop: u64, t: &Tables) -> Result<()> {
        let Unpacker { window, mask, sp: sp_ref, file_base, size, history, last_len, filters, .. } = self;
        let mask = *mask;
        let file_base = *file_base;
        let size_end = size.map_or(u64::MAX, |s| file_base.saturating_add(s));
        let limit = stop.min(size_end);
        let mut sp = *sp_ref;
        let mut hist = *history;
        let mut last = *last_len;
        let window = &mut window[..=mask as usize];
        let main = &t.main;
        macro_rules! decode {
            ($table:expr) => {
                match $table.decode(bits) {
                    Ok(sym) => sym,
                    Err(e) => break Err(e),
                }
            };
        }
        macro_rules! put {
            ($sym:expr) => {
                window[(sp & mask) as usize] = $sym as u8;
                sp += 1;
            };
        }
        // a run of quick literals is gathered here, where whole groups can be written past the ones kept, and then
        // copied to the window in one go
        let mut stage = [0u8; STAGE + 6];
        let result = loop {
            let sym;
            if bits.pos() + 128 <= end_bits && sp + 6 <= limit {
                bits.refill();
                let (lits, n) = main.quick(bits);
                if n > 0 {
                    stage[..6].copy_from_slice(&lits);
                    let mut k = n;
                    while k <= STAGE && bits.pos() + 128 <= end_bits && sp + k as u64 + 6 <= limit {
                        bits.refill();
                        let (lits, n) = main.quick(bits);
                        if n == 0 {
                            break;
                        }
                        stage[k..k + 6].copy_from_slice(&lits);
                        k += n;
                    }
                    let at = (sp & mask) as usize;
                    let first = k.min(window.len() - at);
                    window[at..at + first].copy_from_slice(&stage[..first]);
                    window[..k - first].copy_from_slice(&stage[first..k]);
                    sp += k as u64;
                    continue;
                }
                // well inside the block and the output limits: a refill holds at least 56 bits and a code is at
                // most 15, so up to three literals go without another refill or any limit check
                let s1 = decode!(main);
                if s1 >= 256 {
                    sym = s1;
                } else {
                    put!(s1);
                    let s2 = decode!(main);
                    if s2 >= 256 {
                        sym = s2;
                    } else {
                        put!(s2);
                        let s3 = decode!(main);
                        if s3 >= 256 {
                            sym = s3;
                        } else {
                            put!(s3);
                            continue;
                        }
                    }
                }
            } else {
                if bits.pos() >= end_bits || sp >= stop {
                    break Ok(());
                }
                bits.refill();
                let s = decode!(main);
                if s < 256 {
                    if sp >= size_end {
                        break Err(corrupt("more data than the header says"));
                    }
                    put!(s);
                    continue;
                }
                sym = s;
            }
            bits.refill();
            let tok = match read_op(sym, bits, t) {
                Ok(tok) => tok,
                Err(e) => break Err(e),
            };
            if let Tok::Filter { offset, len, kind } = tok {
                if let Err(e) = add_filter(filters, sp - file_base, offset, len, kind, mask + 1) {
                    break Err(e);
                }
                continue;
            }
            let Some((len, d)) = resolve(tok, &mut hist, &mut last) else { continue };
            if let Err(e) = copy(window, mask, sp, len, d, size_end) {
                break Err(e);
            }
            sp += u64::from(len);
        };
        *sp_ref = sp;
        *history = hist;
        *last_len = last;
        result
    }

    /// Emits everything decoded so far that no pending filter still needs, running filters whose input is complete.
    fn flush(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut done = 0;
        loop {
            let op = self.op();
            let Some(f) = self.filters.get(done).copied() else {
                self.emit(op, sink)?;
                break;
            };
            if self.emitted < f.start {
                self.emit(f.start.min(op), sink)?;
            }
            if self.emitted != f.start || op < f.start + f.len {
                break;
            }
            self.run_filter(f, sink)?;
            done += 1;
        }
        self.filters.drain(..done);
        Ok(())
    }

    /// Unfiltered window bytes from `emitted` up to file position `to`.
    fn emit(&mut self, to: u64, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        while self.emitted < to {
            let at = ((self.file_base + self.emitted) & self.mask) as usize;
            let n = ((to - self.emitted) as usize).min(self.window.len() - at);
            sink(&self.window[at..at + n])?;
            self.emitted += n as u64;
        }
        Ok(())
    }

    fn run_filter(&mut self, f: Filter, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let n = f.len as usize;
        let mut src = std::mem::take(&mut self.scratch);
        src.clear();
        let mut at = ((self.file_base + f.start) & self.mask) as usize;
        while src.len() < n {
            let take = (n - src.len()).min(self.window.len() - at);
            src.extend_from_slice(&self.window[at..at + take]);
            at = 0;
        }
        let out = apply_filter(f, &src);
        sink(&out)?;
        self.emitted += f.len;
        self.scratch = src;
        Ok(())
    }
}

/// A block header at the start of `b`: its length, its payload's length and its flags. None until all of the
/// header is there.
fn block_header(b: &[u8]) -> Result<Option<(usize, usize, u8)>> {
    let Some(&flags) = b.first() else { return Ok(None) };
    let size_len = usize::from((flags >> 3) & 7) + 1;
    if size_len > 3 {
        return Err(corrupt("block size field"));
    }
    if b.len() < 2 + size_len {
        return Ok(None);
    }
    let mut size = 0usize;
    for i in 0..size_len {
        size |= usize::from(b[2 + i]) << (8 * i);
    }
    let check = 0x5a ^ flags ^ (size as u8) ^ ((size >> 8) as u8) ^ ((size >> 16) as u8);
    if check != b[1] {
        return Err(corrupt("block header checksum"));
    }
    Ok(Some((2 + size_len, size, flags)))
}

/// Copies a match inside the window. `sp` is the stream position the copy starts at; nothing may land at or past
/// `size_end`.
#[inline(always)]
fn copy(window: &mut [u8], mask: u64, sp: u64, len: u32, dist: u64, size_end: u64) -> Result<()> {
    if dist == 0 || dist > sp || dist > mask + 1 {
        return Err(corrupt("match reaches before the start of the data"));
    }
    if u64::from(len) > size_end - sp {
        return Err(corrupt("more data than the header says"));
    }
    let n = len as usize;
    let dst = (sp & mask) as usize;
    let src = ((sp - dist) & mask) as usize;
    let w = window.len();
    if n <= 32 && dist >= n as u64 && dst + 32 <= w && src + 32 <= w {
        // a short copy that doesn't overlap: whole 16-byte words, keeping the destination's bytes past the match
        let mut i = 0;
        while i < n {
            let k = (n - i).min(16);
            let s = u128::from_le_bytes(window[src + i..src + i + 16].try_into().unwrap());
            let d = u128::from_le_bytes(window[dst + i..dst + i + 16].try_into().unwrap());
            let keep = if k == 16 { 0 } else { !0u128 << (8 * k) };
            window[dst + i..dst + i + 16].copy_from_slice(&((s & !keep) | (d & keep)).to_le_bytes());
            i += 16;
        }
        return Ok(());
    }
    if dst + n <= w && src + n <= w {
        if dist >= 8 {
            if dist >= n as u64 {
                window.copy_within(src..src + n, dst);
                return Ok(());
            }
            // eight bytes at a time: with the source at least eight behind, each chunk reads only finished bytes
            let mut i = 0;
            while i + 8 <= n {
                let v: [u8; 8] = window[src + i..src + i + 8].try_into().unwrap();
                window[dst + i..dst + i + 8].copy_from_slice(&v);
                i += 8;
            }
            while i < n {
                window[dst + i] = window[src + i];
                i += 1;
            }
        } else if dist == 1 {
            let b = window[src];
            window[dst..dst + n].fill(b);
        } else {
            for i in 0..n {
                window[dst + i] = window[src + i];
            }
        }
    } else {
        let m = mask as usize;
        for i in 0..n {
            window[(dst + i) & m] = window[(src + i) & m];
        }
    }
    Ok(())
}

/// What follows a main-table symbol of 256 or more, read right after a refill.
#[inline(always)]
fn read_op(sym: u16, bits: &mut Bits<'_>, t: &Tables) -> Result<Tok> {
    Ok(match sym {
        256 => read_filter(bits)?,
        257 => Tok::Last,
        258..=261 => {
            let slot = t.rep.decode(bits)?;
            Tok::Rep { k: (sym - 258) as u8, len: length(u32::from(slot), bits) }
        }
        _ => {
            let len = length(u32::from(sym - 262), bits);
            let slot = u32::from(t.dist.decode(bits)?);
            let dist = if slot < 4 {
                1 + u64::from(slot)
            } else {
                let n = slot / 2 - 1;
                let base = 1 + ((2 + u64::from(slot & 1)) << n);
                if n < 4 {
                    base + u64::from(bits.get(n))
                } else {
                    bits.refill();
                    let high = if n > 4 { u64::from(bits.get(n - 4)) << 4 } else { 0 };
                    base + high + u64::from(t.low.decode(bits)?)
                }
            };
            let len = len + u32::from(dist > 0x100) + u32::from(dist > 0x2000) + u32::from(dist > 0x40000);
            Tok::Match { len, dist }
        }
    })
}

/// Applies a token to the distance history and last length; the copy it asks for, if any.
#[inline(always)]
fn resolve(tok: Tok, hist: &mut [u64; 4], last: &mut u32) -> Option<(u32, u64)> {
    match tok {
        Tok::Last => (*last != 0).then(|| (*last, hist[0])),
        Tok::Rep { k, len } => {
            let k = usize::from(k);
            let d = hist[k];
            hist.copy_within(0..k, 1);
            hist[0] = d;
            *last = len;
            Some((len, d))
        }
        Tok::Match { len, dist } => {
            hist.copy_within(0..3, 1);
            hist[0] = dist;
            *last = len;
            Some((len, dist))
        }
        Tok::Lits(_) | Tok::Filter { .. } => None,
    }
}

/// A filter record's fields.
fn read_filter(bits: &mut Bits<'_>) -> Result<Tok> {
    let number = |bits: &mut Bits<'_>| -> u64 {
        bits.refill();
        let n = bits.get(2) + 1;
        let mut v = 0u64;
        for i in 0..n {
            v |= u64::from(bits.get(8)) << (8 * i);
        }
        v
    };
    let offset = number(bits);
    let len = number(bits);
    bits.refill();
    let kind = match bits.get(3) {
        0 => FilterKind::Delta(bits.get(5) as u8 + 1),
        1 => FilterKind::E8,
        2 => FilterKind::E8E9,
        3 => FilterKind::Arm,
        _ => return Err(corrupt("unknown filter type")),
    };
    Ok(Tok::Filter { offset, len, kind })
}

/// Queues a filter read at file position `op`.
fn add_filter(filters: &mut Vec<Filter>, op: u64, offset: u64, len: u64, kind: FilterKind, window: u64) -> Result<()> {
    let start = op + offset;
    if !(4..=MAX_FILTER_LEN).contains(&len) || len > window / 2 {
        return Err(corrupt("filter length"));
    }
    if let Some(prev) = filters.last()
        && start < prev.start + prev.len
    {
        return Err(corrupt("filters overlap"));
    }
    if filters.len() >= MAX_FILTERS {
        return Err(corrupt("too many filters"));
    }
    filters.push(Filter { start, len, kind });
    Ok(())
}

/// Workers to decode big files on: one fewer than the cores, so the calling thread keeps one for the window and
/// the output.
fn default_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).saturating_sub(1).min(16)
}

/// A length from its slot and extra bits: 2 to 4097.
#[inline(always)]
fn length(slot: u32, bits: &mut Bits<'_>) -> u32 {
    if slot < 8 {
        2 + slot
    } else {
        let e = slot / 4 - 1;
        2 + ((4 + (slot & 3)) << e) + bits.get(e)
    }
}

fn apply_filter(f: Filter, src: &[u8]) -> Vec<u8> {
    let n = src.len();
    match f.kind {
        FilterKind::Delta(channels) => {
            let mut out = vec![0u8; n];
            let mut s = 0;
            for c in 0..usize::from(channels) {
                let mut acc = 0u8;
                let mut j = c;
                while j < n {
                    acc = acc.wrapping_sub(src[s]);
                    out[j] = acc;
                    s += 1;
                    j += usize::from(channels);
                }
            }
            out
        }
        FilterKind::E8 | FilterKind::E8E9 => {
            let mut out = src.to_vec();
            let e9 = f.kind == FilterKind::E8E9;
            let mut j = 0;
            while j + 4 < n {
                let b = src[j];
                if b == 0xe8 || (e9 && b == 0xe9) {
                    let p = j + 1;
                    let pos = ((f.start + p as u64) % 0x100_0000) as u32;
                    let a = u32::from_le_bytes(src[p..p + 4].try_into().unwrap());
                    let new = if a & 0x8000_0000 != 0 {
                        if a.wrapping_add(pos) & 0x8000_0000 == 0 { Some(a.wrapping_add(0x100_0000)) } else { None }
                    } else if a < 0x100_0000 {
                        Some(a.wrapping_sub(pos))
                    } else {
                        None
                    };
                    if let Some(v) = new {
                        out[p..p + 4].copy_from_slice(&v.to_le_bytes());
                    }
                    j = p + 4;
                } else {
                    j += 1;
                }
            }
            out
        }
        FilterKind::Arm => {
            let mut out = src.to_vec();
            let mut j = 0;
            while j + 3 < n {
                if src[j + 3] == 0xeb {
                    let v = u32::from_le_bytes(src[j..j + 4].try_into().unwrap()) & 0x00ff_ffff;
                    let q = ((f.start + j as u64) / 4) as u32;
                    let v = (v.wrapping_sub(q) & 0x00ff_ffff) | 0xeb00_0000;
                    out[j..j + 4].copy_from_slice(&v.to_le_bytes());
                }
                j += 4;
            }
            out
        }
    }
}

#[cfg(test)]
mod tests;
