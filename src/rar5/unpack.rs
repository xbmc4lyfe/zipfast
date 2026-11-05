//! RAR 5.0 decompression (algorithm version 0), written from a behavioural specification of the format.
//!
//! The decoder is fed a file's packed bytes in whatever pieces they arrive in (one volume's part at a time) and
//! decodes every compressed block as soon as all of it is in. Decoded bytes go to a sink in file order, after any
//! filters over them have run.

use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ptr;
use std::sync::Arc;

mod crc;
mod parallel;
use parallel::{Boundary, Done, Job, Packed, Part, Pool, Slot};

/// Where decoded output goes.
pub trait Sink {
    /// The next bytes of the current file. An empty slice ends a queued file (see [`Unpacker::queue_file`]).
    fn put(&mut self, bytes: &[u8]) -> Result<()>;

    /// Whether the decoder is to work out the CRC32 of the current file's bytes and hand it to [`Sink::crc`], so
    /// that `put` needn't. The answer must not change while a file's bytes are being put.
    fn wants_crc(&self) -> bool {
        false
    }

    /// The CRC32 of all the current file's bytes, when [`Sink::wants_crc`] says so: after the last of them are put,
    /// before the empty slice that ends a queued file, and before [`Unpacker::finish`] returns.
    fn crc(&mut self, _crc: u32) {}
}

impl<F: FnMut(&[u8]) -> Result<()>> Sink for F {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self(bytes)
    }
}

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

/// Output is emitted at least this often (see [`Unpacker::flush_at`]). It must not be less than [`MAX_FILTER_LEN`].
const FLUSH_EVERY: u64 = MAX_FILTER_LEN;
/// How far past [`Unpacker::flush_at`] unemitted bytes the window may be written before output is emitted again:
/// the longest match, with the 32 bytes a short copy rewrites, and room to spare.
const WRITE_SLACK: u64 = 64 << 10;
/// Output is hashed on a helper thread straight from windows of this size up, where a stretch emitted stays in
/// place for a while: other windows are reused too soon after.
const HAND_OVER_WINDOW: usize = 4 * FLUSH_EVERY as usize;
/// The shortest stretch of a file's output that starts handing its hashing to the helper.
const HAND_OVER_MIN: usize = 64 << 10;
/// Quick literals gathered before they go to the window.
const STAGE: usize = 1024;
/// Bits of a code looked up in one step; longer codes take the slow path.
const LUT_BITS: u32 = 11;

fn corrupt(what: &'static str) -> Error {
    Error::Corrupt(what)
}

/// MSB-first bits over one block's payload, followed by [`PAD`] zero bytes. Bits are taken from a 64-bit
/// accumulator that [`Bits::refill`] tops up to at least 56 bits; every read must fit in what a refill guarantees.
///
/// The decoding loops keep one in a local that nothing takes the address of, so that it lives in registers: what isn't
/// inlined takes and gives back a copy (see [`read_filter`], [`Huff::decode_slow`]).
#[derive(Clone, Copy)]
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
    /// entries of `lut` past this are zero already
    dirty: usize,
    /// when the common length is 8: the literals of length 8 in code order, from code `first8` on. Canonical codes
    /// of one length go in symbol order, so they are the first `nlit8` codes of that length.
    lit8: Box<[u8; 256]>,
    first8: u8,
    nlit8: u16,
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
            dirty: 1 << LUT_BITS,
            lit8: Box::new([0; 256]),
            first8: 0,
            nlit8: 0,
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn build(&mut self, lengths: &[u8]) -> Result<()> {
        // (a length is at most 15) the literals are counted apart too, for the guess at their common length below
        let lits = if lengths.len() >= 256 { &lengths[..256] } else { &[][..] };
        let mut by_len = [0u32; 16];
        for &l in lits {
            by_len[usize::from(l & 15)] += 1;
        }
        let mut count = by_len;
        for &l in &lengths[lits.len()..] {
            count[usize::from(l & 15)] += 1;
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
        by_len[0] = 0;
        let (len, n) = by_len.iter().enumerate().max_by_key(|&(l, &n)| (n, std::cmp::Reverse(l))).unwrap();
        self.common = if !lits.is_empty() && *n >= 160 && len <= LUT_BITS as usize { len as u32 } else { 0 };
        // canonical codes up to the table's width fill it from the start, in order; the rest belongs to longer codes
        // or to none, and is marked for the slow path
        let mut covered = 0;
        for l in 1..=LUT_BITS as usize {
            let n = count[l] as usize;
            if n == 0 {
                continue;
            }
            let from = self.start[l] as usize;
            let syms = &self.sorted[from..from + n];
            let shift = LUT_BITS as usize - l;
            let lut = &mut self.lut[covered..covered + (n << shift)];
            let tag = l as u16;
            // a code of length l covers 2^shift entries; the common spans get loops of their own
            match shift {
                0 => fill::<1>(lut, syms, tag),
                1 => fill::<2>(lut, syms, tag),
                2 => fill::<4>(lut, syms, tag),
                3 => fill::<8>(lut, syms, tag),
                4 => fill::<16>(lut, syms, tag),
                5 => fill::<32>(lut, syms, tag),
                _ => {
                    for (d, &sym) in lut.chunks_exact_mut(1 << shift).zip(syms) {
                        d.fill((sym << 4) | tag);
                    }
                }
            }
            covered += n << shift;
        }
        if covered < self.dirty {
            self.lut[covered..self.dirty].fill(0);
        }
        self.dirty = covered;
        // the literals of length 8, by their codes
        if self.common == 8 {
            let from = self.start[8] as usize;
            let n = by_len[8] as usize;
            for (slot, &sym) in self.lit8.iter_mut().zip(&self.sorted[from..from + n]) {
                *slot = sym as u8;
            }
            self.first8 = (self.first[8] >> 8) as u8;
            self.nlit8 = n as u16;
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
        let (sym, len) = self.decode_slow(peek)?;
        bits.skip(len);
        Ok(sym)
    }

    /// Up to six literals of the common length from one refill (seven when it is 8). All the lookups are made at once, as if every
    /// code had that length, and kept for as long as that holds. Returns them with how many there are (none when
    /// the first code isn't such a literal). Needs 56 bits in the accumulator.
    #[inline(always)]
    fn quick(&self, bits: &mut Bits<'_>) -> ([u8; 8], usize) {
        let g = self.common;
        if g == 8 {
            return self.quick8(bits);
        }
        let a = bits.acc;
        let sh = 64 - LUT_BITS;
        let at = |k: u32| self.lut[((a << (k * g)) >> sh) as usize];
        // a literal (symbol below 256, so the top four bits clear) of length g
        let hit = |e: u16| u32::from(e & 0xF00F) == g;
        let e = [at(0), at(1), at(2), at(3), at(4), at(5), 0, 0];
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

    /// [`Huff::quick`] when the common length is 8, as it is for incompressible data: the next codes are the
    /// accumulator's top bytes, and a byte is the code of a literal of length 8 when it falls in their range. Up to
    /// seven.
    #[inline(always)]
    fn quick8(&self, bits: &mut Bits<'_>) -> ([u8; 8], usize) {
        let c = bits.acc.to_be_bytes();
        let mut lits = [0u8; 8];
        let mut n = 0;
        while n < 7 {
            let i = c[n].wrapping_sub(self.first8);
            if u16::from(i) >= self.nlit8 {
                break;
            }
            lits[n] = self.lit8[usize::from(i)];
            n += 1;
        }
        bits.skip(n as u32 * 8);
        (lits, n)
    }

    /// Literals of length 8, sixteen at a time. Within a run of such codes the bit offset in each byte stays the
    /// same, so the next sixteen codes are the payload's bytes shifted by it; each is checked against the range of
    /// literal codes and looked up in [`Huff::lit8`] in one go. Stops before the first code that isn't one, or when
    /// the bits come within 136 of `end_bits` or fewer than sixteen of `room` are left. Returns how many.
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    fn run8(&self, bits: &mut Bits<'_>, end_bits: usize, out: &mut [u8], room: usize) -> usize {
        use std::arch::aarch64::*;
        let room = room.min(out.len());
        let start = bits.pos();
        let mut pos = start;
        let mut k = 0;
        if self.common != 8 || pos + 136 > end_bits || room < 16 {
            return 0;
        }
        // SAFETY: round r reads 17 bytes from byte `pos / 8 + 16 r`, all before byte `end_bits / 8`, which the
        // buffer holds, and writes 16 bytes at `16 r`, inside `room`, which `out` holds
        unsafe {
            let t = self.lit8.as_ptr();
            let tables = [vld1q_u8_x4(t), vld1q_u8_x4(t.add(64)), vld1q_u8_x4(t.add(128)), vld1q_u8_x4(t.add(192))];
            let first = vdupq_n_u8(self.first8);
            let last = vdupq_n_u8((self.nlit8 - 1) as u8);
            let shift = (pos & 7) as i8;
            let (left, right) = (vdupq_n_s8(shift), vdupq_n_s8(shift - 8));
            let quarter = vdupq_n_u8(64);
            let from = bits.buf.as_ptr().add(pos / 8);
            // rounds go at fixed places, as if every code so far was a literal: nothing a round needs waits on the
            // round before, and the first that finds another code ends the run
            let rounds = ((end_bits - pos - 136) / 128 + 1).min(room / 16);
            for r in 0..rounds {
                let at = from.add(16 * r);
                let codes = vorrq_u8(vshlq_u8(vld1q_u8(at), left), vshlq_u8(vld1q_u8(at.add(1)), right));
                let i = vsubq_u8(codes, first);
                // a table of 64 entries leaves an index past it alone, so each quarter fills in only its own
                let mut lits = vqtbl4q_u8(tables[0], i);
                let i1 = vsubq_u8(i, quarter);
                lits = vqtbx4q_u8(lits, tables[1], i1);
                let i2 = vsubq_u8(i1, quarter);
                lits = vqtbx4q_u8(lits, tables[2], i2);
                lits = vqtbx4q_u8(lits, tables[3], vsubq_u8(i2, quarter));
                vst1q_u8(out.as_mut_ptr().add(16 * r), lits);
                // four bits per code, set while it is a literal's
                let ok = vcleq_u8(i, last);
                let mask = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(ok), 4)), 0);
                if mask != u64::MAX {
                    k = 16 * r + ((!mask).trailing_zeros() / 4) as usize;
                    break;
                }
                k = 16 * (r + 1);
            }
            pos += 8 * k;
        }
        if pos != start {
            *bits = Bits::at(bits.buf, pos);
        }
        k
    }

    /// Quick literals for as long as they keep coming, into `stage`, while the bits stay at least 128 short of
    /// `end_bits` and fewer than `room` are out. Returns how many.
    #[inline(always)]
    fn quick_run(&self, bits: &mut Bits<'_>, end_bits: usize, stage: &mut [u8; STAGE + 8], room: usize) -> usize {
        let room = room.min(STAGE);
        let mut k = 0;
        if self.common == 0 {
            return 0;
        }
        while k < room && bits.pos() + 128 <= end_bits {
            #[cfg(target_arch = "aarch64")]
            {
                k += self.run8(bits, end_bits, &mut stage[k..], room - k);
                if k >= room || bits.pos() + 128 > end_bits {
                    break;
                }
            }
            bits.refill();
            let (lits, n) = self.quick(bits);
            stage[k..k + 8].copy_from_slice(&lits);
            k += n;
            if n < 5 {
                // a code of some other kind stopped them, with at least the table's width of bits still in the
                // accumulator: a literal of another length joins them, anything else ends the run
                let entry = self.lut[(bits.acc >> (64 - LUT_BITS)) as usize];
                if entry == 0 || entry >> 4 >= 256 {
                    break;
                }
                stage[k] = (entry >> 4) as u8;
                k += 1;
                bits.skip(u32::from(entry & 15));
            }
        }
        k
    }

    /// A code longer than the table, from the next 16 bits: its symbol and length.
    #[cold]
    fn decode_slow(&self, peek: u32) -> Result<(u16, u32)> {
        for l in LUT_BITS as usize + 1..16 {
            if peek < self.limit[l] && peek >= self.first[l] {
                let idx = self.start[l] as u32 + ((peek - self.first[l]) >> (16 - l));
                let sym = self.sorted.get(idx as usize).copied().ok_or(corrupt("prefix code"))?;
                return Ok((sym, l as u32));
            }
        }
        Err(corrupt(if self.empty { "symbol from an empty prefix code" } else { "bit pattern matches no code" }))
    }
}

/// Each symbol's entry, `SPAN` times over, in order.
#[inline(always)]
fn fill<const SPAN: usize>(lut: &mut [u16], syms: &[u16], tag: u16) {
    for (d, &sym) in lut.as_chunks_mut::<SPAN>().0.iter_mut().zip(syms) {
        *d = [(sym << 4) | tag; SPAN];
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

/// Every code length a block's tables give, main table first.
type Lengths = [u8; TABLES];

impl Tables {
    fn empty() -> Tables {
        Tables { main: Huff::new(), dist: Huff::new(), low: Huff::new(), rep: Huff::new() }
    }

    fn build(&mut self, lens: &Lengths) -> Result<()> {
        self.main.build(&lens[..NC])?;
        self.dist.build(&lens[NC..NC + DC])?;
        self.low.build(&lens[NC + DC..NC + DC + LDC])?;
        self.rep.build(&lens[NC + DC + LDC..])
    }
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

/// Blocks are handed to workers in runs of about this many packed bytes.
const JOB_BYTES: usize = 256 << 10;

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
    /// the code lengths the next block without tables is read with, which a worker may still be reading, and the
    /// lengths `tables` was last built from
    slot: Arc<Slot>,
    built: Option<Arc<Slot>>,
    /// the code the lengths themselves are read with, kept so each block needn't allocate one
    pre: Huff,
    tables: Arc<Tables>,
    history: [u64; 4],
    last_len: u32,
    filters: Vec<Filter>,
    /// filtered output for one filter at a time, and the delta filter's second buffer
    scratch: Vec<u8>,
    scratch_delta: Vec<u8>,
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
    /// blocks gathered for the next job
    batch: Job,
    /// jobs handed to workers, and jobs applied to the window, both counted over the decoder's life
    submitted: u64,
    applied: u64,
    /// packed bytes of the jobs not yet applied
    queued: usize,
    /// blocks a worker stopped early on, at its memory budget, and this thread finished
    resumed: u64,
    /// finished jobs waiting for the ones before them
    ready: BTreeMap<u64, Done>,
    /// finished jobs, for their buffers
    spare: Vec<Job>,
    /// files queued behind the one before, and how many of those have begun in the window, both over the decoder's
    /// life
    files_queued: u64,
    files_begun: u64,
    /// [`Self::settle`] waits for the workers until this many queued files have begun
    files_goal: u64,
    /// the current file's CRC32, when the sink wants it
    crc: crc::FileCrc,
    /// the smallest window, and the shortest stretch, whose hashing goes to the helper ([`HAND_OVER_WINDOW`],
    /// [`HAND_OVER_MIN`])
    hand_over_window: usize,
    hand_over_min: usize,
}

impl Drop for Unpacker {
    fn drop(&mut self) {
        // the helper is done with the window before it goes
        self.crc.reset();
    }
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
        // asked first so an absurd size is an error, not an abort; the window itself comes zeroed from the system,
        // so its pages cost nothing until they are written
        Vec::<u8>::new()
            .try_reserve_exact(size)
            .map_err(|_| Error::Unsupported(format!("can't allocate a {window} byte window")))?;
        Ok(Unpacker {
            window: vec![0; size],
            mask: window - 1,
            sp: 0,
            file_base: 0,
            emitted: 0,
            size: None,
            tables_ready: false,
            slot: Slot::filled(None),
            built: None,
            pre: Huff::new(),
            tables: Arc::new(Tables::empty()),
            history: [0; 4],
            last_len: 0,
            filters: Vec::new(),
            scratch: Vec::new(),
            scratch_delta: Vec::new(),
            input: Vec::new(),
            padded: Vec::new(),
            threads: default_threads(),
            parallel_min: PARALLEL_MIN,
            parallel: false,
            pool: None,
            batch: Job::default(),
            submitted: 0,
            applied: 0,
            queued: 0,
            resumed: 0,
            ready: BTreeMap::new(),
            spare: Vec::new(),
            files_queued: 0,
            files_begun: 0,
            files_goal: 0,
            crc: crc::FileCrc::with_helper(default_threads() > 0),
            hand_over_window: HAND_OVER_WINDOW,
            hand_over_min: HAND_OVER_MIN,
        })
    }

    /// How many worker threads big files are decoded on (0 for none), and from what file size.
    pub fn set_threads(&mut self, threads: usize, min_size: u64) {
        self.discard_in_flight();
        // the CRC helper is one more thread at work beside the decoder's, so it goes with them
        self.crc.reset();
        self.crc.helper = if threads > 0 { crc::Helper::Thread } else { crc::Helper::Off };
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

    /// Whether this decoder can take a stream that needs a `window` byte window: its own is big enough, and not so
    /// much bigger that keeping it wastes memory. Reusing one saves allocating a window for every file.
    pub fn fits(&self, window: u64) -> bool {
        let have = self.window_size();
        have >= window && have <= window.saturating_mul(4).max(4 << 20)
    }

    /// Decodes the current file's blocks on the workers whatever its size, when there are any: for a file that
    /// [`Self::queue_file`] will follow.
    pub fn force_parallel(&mut self) {
        self.parallel = self.threads > 0;
    }

    /// Starts the next file of a solid stream without waiting for the one before: its blocks may still be with the
    /// workers. Where the files meet, the earlier one is checked as [`Self::finish`] would, then the sink is called
    /// with an empty slice; the sink is never called with one otherwise. The earlier file's errors come out of later
    /// calls, in stream order, and a caller tells whose they are by the empty slices it has seen. The blocks before
    /// must have gone to the workers ([`Self::force_parallel`]), and so do this file's.
    pub fn queue_file(&mut self, size: Option<u64>) {
        debug_assert!(self.parallel, "queued files are decoded on the workers");
        let boundary = Boundary { size, truncated: !self.input.is_empty() };
        self.input.clear();
        let at = self.batch.buf.len();
        self.batch.parts.push(Part {
            at,
            end_bits: 0,
            read_tables: false,
            slot: Arc::clone(&self.slot),
            boundary: Some(boundary),
        });
        self.files_queued += 1;
        self.parallel = self.threads > 0;
    }

    /// Decodes until no more than `behind` queued files are still waiting for the ones before them to end.
    pub fn catch_up(&mut self, behind: u64, sink: &mut dyn Sink) -> Result<()> {
        self.files_goal = self.files_queued.saturating_sub(behind);
        if self.files_begun < self.files_goal {
            self.send_batch();
        }
        let r = self.settle(u64::MAX, sink);
        self.files_goal = 0;
        r
    }

    /// Starts the next file of a solid stream: the window, tables and history carry on.
    pub fn next_file(&mut self, size: Option<u64>) {
        self.discard_in_flight();
        self.crc.reset();
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

    /// How much unemitted output the window may hold before it is emitted. No more than half the window, so a
    /// match never overwrites output not yet emitted, and no more than [`FLUSH_EVERY`], so the output is still in
    /// cache when the sink reads it. Never less than a filter's longest range, which is emitted only once it is
    /// whole, so decoding can always reach the end of one.
    fn flush_at(&self) -> u64 {
        (self.window_size() / 2).min(FLUSH_EVERY)
    }

    fn op(&self) -> u64 {
        self.sp - self.file_base
    }

    /// Hands a block to the workers. A worker reads its code lengths, builds the tables and reads its symbols; the
    /// tokens are applied to the window in order by [`Self::settle`]. Later blocks without tables of their own wait
    /// for the lengths, on the worker that has them.
    fn submit(&mut self, buf: &[u8], payload: usize, flags: u8, sink: &mut dyn Sink) -> Result<()> {
        let valid_bits = usize::from(flags & 7) + 1;
        let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
        let read_tables = flags & 0x80 != 0;
        if !read_tables {
            if payload == 0 {
                return Ok(());
            }
            if !self.tables_ready {
                // an earlier block's error comes first
                self.settle(0, sink)?;
                return Err(corrupt("block without tables at the start of a stream"));
            }
        }
        if read_tables {
            self.slot = Slot::pending();
            self.tables_ready = true;
        }
        let at = self.batch.buf.len();
        self.batch.buf.extend_from_slice(&buf[..payload + PAD]);
        self.batch.parts.push(Part { at, end_bits, read_tables, slot: Arc::clone(&self.slot), boundary: None });
        if self.batch.buf.len() >= JOB_BYTES {
            self.send_batch();
            self.settle(4 * self.threads as u64, sink)?;
        }
        Ok(())
    }

    /// Hands the blocks gathered so far to a worker.
    fn send_batch(&mut self) {
        if self.batch.parts.is_empty() {
            return;
        }
        let pool = self.pool.get_or_insert_with(|| Pool::new(self.threads));
        let mut job = std::mem::replace(&mut self.batch, self.spare.pop().unwrap_or_default());
        self.batch.buf.clear();
        self.batch.parts.clear();
        job.seq = self.submitted;
        self.queued += job.buf.len();
        pool.submit(job);
        self.submitted += 1;
    }

    /// Applies finished jobs in order until no more than `max` are still with the workers; with `max` 0 the blocks
    /// still being gathered go first. The first error in stream order is returned; after one, the rest are collected
    /// and dropped.
    fn settle(&mut self, max: u64, sink: &mut dyn Sink) -> Result<()> {
        if max == 0 {
            self.send_batch();
        }
        let mut max = max;
        let mut failed = None;
        loop {
            while let Some(done) = self.ready.remove(&self.applied) {
                self.applied += 1;
                let Done { job, result, tables } = done;
                self.queued -= job.buf.len();
                if failed.is_none() {
                    let mut applied = self.apply_job(&job, sink).and(result);
                    // the worker stopped at its memory budget: the rest of the job is decoded here
                    if let Ok(Some((part, bit))) = applied {
                        self.resumed += 1;
                        applied = self.resume(&job, part, bit, tables, sink).map(|()| None);
                    }
                    if let Err(e) = applied {
                        failed = Some(e);
                        max = 0;
                    }
                }
                self.spare.push(job);
            }
            let in_flight = self.submitted - self.applied;
            if in_flight == 0 {
                break;
            }
            let Some(pool) = self.pool.as_ref() else { break };
            let done = if in_flight <= max && self.queued <= MAX_QUEUED && self.files_begun >= self.files_goal {
                // take what's finished, but don't wait
                match pool.try_next() {
                    Some(done) => done,
                    None => break,
                }
            } else {
                pool.next()
            };
            self.ready.insert(done.job.seq, done);
        }
        failed.map_or(Ok(()), Err)
    }

    /// Decodes the rest of a job a worker stopped at its budget: block `part` from `bit` on, with `tables`, then the
    /// blocks after it.
    fn resume(
        &mut self,
        job: &Job,
        part: usize,
        bit: usize,
        mut tables: Arc<Tables>,
        sink: &mut dyn Sink,
    ) -> Result<()> {
        for (i, p) in job.parts.iter().enumerate().skip(part) {
            if let Some(b) = p.boundary {
                self.end_file(b, sink)?;
                continue;
            }
            let buf = &job.buf[p.at..];
            let mut bits = if i == part { Bits::at(buf, bit) } else { Bits::new(buf) };
            if i > part && p.read_tables {
                let lens = read_lengths(&mut self.pre, &mut bits, p.end_bits)?;
                let mut t = Tables::empty();
                t.build(&lens)?;
                tables = Arc::new(t);
            }
            self.decode_rest(&mut bits, p.end_bits, &tables, sink)?;
        }
        Ok(())
    }

    /// An error found reading ahead of the workers waits for theirs: an earlier block's error comes first.
    fn ordered<T>(&mut self, r: Result<T>, sink: &mut dyn Sink) -> Result<T> {
        if r.is_err() && (self.submitted > self.applied || !self.batch.parts.is_empty()) {
            self.settle(0, sink)?;
        }
        r
    }

    /// Waits out blocks still with the workers and drops them: the file they belong to was abandoned. The blocks
    /// being gathered go to the workers too, since later blocks may wait on the lengths they carry.
    fn discard_in_flight(&mut self) {
        self.send_batch();
        while self.applied < self.submitted {
            if !self.ready.contains_key(&self.applied) {
                let Some(pool) = self.pool.as_ref() else { break };
                let done = pool.next();
                self.ready.insert(done.job.seq, done);
                continue;
            }
            if let Some(Done { job, .. }) = self.ready.remove(&self.applied) {
                self.queued -= job.buf.len();
                self.spare.push(job);
            }
            self.applied += 1;
        }
        self.applied = self.submitted;
        self.ready.clear();
        self.queued = 0;
    }

    /// A job's tokens, part by part, with the file boundaries between them, as far as the worker got.
    fn apply_job(&mut self, job: &Job, sink: &mut dyn Sink) -> Result<()> {
        let mut from = (0, 0);
        for (p, &to) in job.parts.iter().zip(&job.ends) {
            if let Some(b) = p.boundary {
                self.end_file(b, sink)?;
            }
            self.apply(&job.toks[from.0..to.0], &job.filters, &job.lits[from.1..to.1], sink)?;
            from = to;
        }
        Ok(())
    }

    /// Where one queued file ends and the next begins: the first is checked and done with.
    fn end_file(&mut self, b: Boundary, sink: &mut dyn Sink) -> Result<()> {
        if b.truncated {
            return Err(Error::Truncated);
        }
        self.check_end(sink)?;
        sink.put(&[])?;
        self.crc.reset();
        self.files_begun += 1;
        self.file_base = self.sp;
        self.emitted = 0;
        self.size = b.size;
        Ok(())
    }

    /// Emits the rest of the current file and checks it ended where it should, then hands the sink the file's
    /// CRC32 if it wants it.
    fn check_end(&mut self, sink: &mut dyn Sink) -> Result<()> {
        // what is left is hashed here, since the CRC is needed now
        let ended = self.flush_to(false, sink).and_then(|()| {
            if !self.filters.is_empty() {
                return Err(corrupt("a filter runs past the end of the file"));
            }
            match self.size {
                Some(size) if self.emitted != size => Err(corrupt("decoded size differs from the header")),
                _ => Ok(()),
            }
        });
        if ended.is_ok() && sink.wants_crc() {
            sink.crc(self.crc.finish());
        } else {
            // nothing of this file's is hashed into the next's, even if decoding goes on after a failure
            self.crc.reset();
        }
        ended
    }

    /// Some of a block's tokens, applied to the window with the same checks the decoding loop makes.
    fn apply(
        &mut self,
        toks: &[Packed],
        filters: &[parallel::FilterFields],
        lits: &[u8],
        sink: &mut dyn Sink,
    ) -> Result<()> {
        let flush_at = self.flush_at();
        let size_end = self.size.map_or(u64::MAX, |s| self.file_base.saturating_add(s));
        let mut li = 0usize;
        for &packed in toks {
            let tok = packed.get(filters);
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
                        copy(Win::of(&mut self.window), self.sp, len, d, size_end)?;
                        self.sp += u64::from(len);
                    }
                }
            }
        }
        Ok(())
    }

    /// Literal bytes into the window at the stream position.
    fn put(&mut self, bytes: &[u8]) {
        Win::of(&mut self.window).write(self.sp, bytes);
        self.sp += bytes.len() as u64;
    }

    /// More of the file's packed bytes. Every block that is now complete is decoded and its output emitted. Blocks
    /// that arrive whole are decoded where they lie; only a block split across calls is gathered first.
    pub fn feed(&mut self, mut data: &[u8], sink: &mut dyn Sink) -> Result<()> {
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

    /// Applies everything handed to the workers so far, leaving a block still coming in as it is.
    pub fn wait(&mut self, sink: &mut dyn Sink) -> Result<()> {
        self.settle(0, sink)
    }

    /// The file's packed bytes are all in. Emits what is left and checks the stream ended where it should.
    pub fn finish(&mut self, sink: &mut dyn Sink) -> Result<()> {
        self.settle(0, sink)?;
        if !self.input.is_empty() {
            return Err(Error::Truncated);
        }
        self.check_end(sink)
    }

    fn block(&mut self, buf: &[u8], payload: usize, flags: u8, sink: &mut dyn Sink) -> Result<()> {
        if self.parallel {
            return self.submit(buf, payload, flags, sink);
        }
        let valid_bits = usize::from(flags & 7) + 1;
        let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
        let mut bits = Bits::new(buf);
        if flags & 0x80 != 0 {
            let lens = read_lengths(&mut self.pre, &mut bits, end_bits)?;
            self.slot = Slot::filled(Some(lens));
            self.tables_ready = true;
        } else if !self.tables_ready && payload > 0 {
            return Err(corrupt("block without tables at the start of a stream"));
        }
        // after blocks on workers, the tables here may lag behind the lengths last read
        if self.tables_ready && !self.built.as_ref().is_some_and(|b| Arc::ptr_eq(b, &self.slot)) {
            let lens = self.slot.wait().ok_or_else(|| corrupt("the tables before this block were damaged"))?;
            // blocks still decoding on the main thread's behalf keep the tables they were handed
            Arc::make_mut(&mut self.tables).build(&lens)?;
            self.built = Some(Arc::clone(&self.slot));
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
        sink: &mut dyn Sink,
    ) -> Result<()> {
        let flush_at = self.flush_at();
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

    /// The decoding loop: symbols until the block's bits run out or the stream position reaches `stop`. The state
    /// it touches on every symbol lives in locals, so the window writes can't make the compiler reload it.
    fn run(&mut self, bits_at: &mut Bits<'_>, end_bits: usize, stop: u64, t: &Tables) -> Result<()> {
        // a copy, so that it can live in registers
        let mut local = *bits_at;
        let bits = &mut local;
        let Unpacker { window, mask, sp: sp_ref, file_base, size, history, last_len, filters, .. } = self;
        let mask = *mask;
        let file_base = *file_base;
        let size_end = size.map_or(u64::MAX, |s| file_base.saturating_add(s));
        let limit = stop.min(size_end);
        let mut sp = *sp_ref;
        let mut hist = *history;
        let mut last = *last_len;
        let window = Win::of(window);
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
                window.set(sp, $sym as u8);
                sp += 1;
            };
        }
        // a run of quick literals is gathered here, where whole groups can be written past the ones kept, and then
        // copied to the window in one go
        let mut stage = [0u8; STAGE + 8];
        let result = loop {
            let sym;
            if bits.pos() + 128 <= end_bits && sp + 7 <= limit {
                // room for every literal the stage can take, each run of quick ones ending at most seven past it
                let room = usize::try_from(limit - sp - 6).unwrap_or(usize::MAX);
                // a table with no common literal length (text, mostly) has no quick literals to try for
                let k = if main.common == 0 { 0 } else { main.quick_run(bits, end_bits, &mut stage, room) };
                if k > 0 {
                    window.write(sp, &stage[..k]);
                    sp += k as u64;
                    continue;
                }
                bits.refill();
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
            if let Err(e) = copy(window, sp, len, d, size_end) {
                break Err(e);
            }
            sp += u64::from(len);
        };
        *sp_ref = sp;
        *history = hist;
        *last_len = last;
        *bits_at = local;
        result
    }

    /// Emits everything decoded so far that no pending filter still needs, running filters whose input is complete.
    fn flush(&mut self, sink: &mut dyn Sink) -> Result<()> {
        self.flush_to(true, sink)
    }

    /// [`Self::flush`], handing the hashing of long stretches to the helper if `hand_over`.
    fn flush_to(&mut self, hand_over: bool, sink: &mut dyn Sink) -> Result<()> {
        let mut done = 0;
        loop {
            let op = self.op();
            let Some(f) = self.filters.get(done).copied() else {
                self.emit(op, hand_over, sink)?;
                break;
            };
            if self.emitted < f.start {
                self.emit(f.start.min(op), hand_over, sink)?;
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

    /// Unfiltered window bytes from `emitted` up to file position `to`. With `hand_over`, long stretches of them
    /// are hashed on the helper, if the sink wants them hashed.
    fn emit(&mut self, to: u64, hand_over: bool, sink: &mut dyn Sink) -> Result<()> {
        if self.emitted >= to {
            return Ok(());
        }
        let hashing = sink.wants_crc();
        let hand_over = hand_over && self.window.len() >= self.hand_over_window;
        while self.emitted < to {
            let at = ((self.file_base + self.emitted) & self.mask) as usize;
            let n = ((to - self.emitted) as usize).min(self.window.len() - at);
            let bytes = &self.window[at..at + n];
            sink.put(bytes)?;
            if hashing {
                // SAFETY: what goes to the helper stays in place until it is hashed: `keep_clear` waits for a
                // stretch before decoding can reach it again, and `crc.reset` before the window is reused from its
                // start or let go
                unsafe { self.crc.window(self.file_base + self.emitted, bytes, hand_over && n >= self.hand_over_min) };
            }
            self.emitted += n as u64;
        }
        self.keep_clear();
        Ok(())
    }

    /// Waits for the hashing of output that decoding up to the next emit could write over. Up to then, nothing is
    /// written as far as [`Self::flush_at`] plus [`WRITE_SLACK`] past what is emitted.
    fn keep_clear(&mut self) {
        if self.crc.out() {
            let window = self.window_size();
            let reach = self.file_base + self.emitted + self.flush_at() + WRITE_SLACK;
            // a short copy may have rewritten 32 bytes past the stream position
            self.crc.clear_before(reach.saturating_sub(window), (self.sp + 32).saturating_sub(window));
        }
    }

    fn run_filter(&mut self, f: Filter, sink: &mut dyn Sink) -> Result<()> {
        let n = f.len as usize;
        let mut data = std::mem::take(&mut self.scratch);
        data.clear();
        let mut at = ((self.file_base + f.start) & self.mask) as usize;
        while data.len() < n {
            let take = (n - data.len()).min(self.window.len() - at);
            data.extend_from_slice(&self.window[at..at + take]);
            at = 0;
        }
        apply_filter(f, &mut data, &mut self.scratch_delta);
        let sent = sink.put(&data);
        if sent.is_ok() && sink.wants_crc() {
            data = self.crc.owned(self.file_base + f.start, data);
        }
        self.scratch = data;
        sent?;
        self.emitted += f.len;
        self.keep_clear();
        Ok(())
    }
}

/// A block's code lengths, read with the precode, which `pre` is rebuilt as.
fn read_lengths(pre: &mut Huff, bits: &mut Bits<'_>, end: usize) -> Result<Lengths> {
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
    Ok(lens)
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

/// The window as the decoder writes it: through a pointer that makes no reference to its bytes, never through a
/// `&mut` to all of them, since the CRC helper may be reading stretches of output from it meanwhile (see [`crc`]).
/// Positions are stream positions, taken modulo the window's size, so every access is inside it.
#[derive(Clone, Copy)]
struct Win<'a> {
    ptr: *mut u8,
    mask: usize,
    _window: PhantomData<&'a mut Vec<u8>>,
}

impl<'a> Win<'a> {
    /// `window`'s length must be a power of two.
    #[inline(always)]
    fn of(window: &'a mut Vec<u8>) -> Self {
        debug_assert!(window.len().is_power_of_two());
        Win { ptr: window.as_mut_ptr(), mask: window.len() - 1, _window: PhantomData }
    }

    #[inline(always)]
    fn len(self) -> usize {
        self.mask + 1
    }

    /// The byte at stream position `pos`.
    #[inline(always)]
    fn set(self, pos: u64, b: u8) {
        // SAFETY: masked to the window
        unsafe { *self.ptr.add(pos as usize & self.mask) = b };
    }

    /// `bytes`, no more than the window holds, from stream position `pos` on.
    #[inline(always)]
    fn write(self, pos: u64, bytes: &[u8]) {
        assert!(bytes.len() <= self.len());
        let at = pos as usize & self.mask;
        let first = bytes.len().min(self.len() - at);
        // SAFETY: `first` bytes from `at` and the rest from the start are inside the window, which `bytes` (a
        // shared slice) can't overlap while this holds it mutably
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr.add(at), first);
            ptr::copy_nonoverlapping(bytes.as_ptr().add(first), self.ptr, bytes.len() - first);
        }
    }
}

/// Copies a match inside the window. `sp` is the stream position the copy starts at; nothing may land at or past
/// `size_end`.
#[inline(always)]
fn copy(window: Win<'_>, sp: u64, len: u32, dist: u64, size_end: u64) -> Result<()> {
    let mask = window.mask as u64;
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
    let p = window.ptr;
    if n <= 32 && dist >= n as u64 && dst + 32 <= w && src + 32 <= w {
        // a short copy whose source ends before it: whole 16-byte words, keeping the destination's bytes past the
        // match, which a match from nearly a window back may still read
        // SAFETY: the 32 bytes at `src` and at `dst` are inside the window, and 1 <= n <= 32
        unsafe {
            blend16(p, src, dst, n.min(16));
            if n > 16 {
                blend16(p, src + 16, dst + 16, n - 16);
            }
        }
        return Ok(());
    }
    if dst + n <= w && src + n <= w {
        // SAFETY (all of this branch): the `n` bytes at `src` and at `dst` are inside the window
        if dist >= 8 {
            if dist >= n as u64 {
                unsafe { ptr::copy(p.add(src), p.add(dst), n) };
                return Ok(());
            }
            // eight bytes at a time: with the source at least eight behind, each chunk reads only finished bytes
            let mut i = 0;
            while i + 8 <= n {
                unsafe { p.add(dst + i).cast::<u64>().write_unaligned(p.add(src + i).cast::<u64>().read_unaligned()) };
                i += 8;
            }
            while i < n {
                unsafe { *p.add(dst + i) = *p.add(src + i) };
                i += 1;
            }
        } else if dist == 1 {
            unsafe { ptr::write_bytes(p.add(dst), *p.add(src), n) };
        } else {
            for i in 0..n {
                unsafe { *p.add(dst + i) = *p.add(src + i) };
            }
        }
    } else {
        let m = window.mask;
        for i in 0..n {
            // SAFETY: masked to the window
            unsafe { *p.add((dst + i) & m) = *p.add((src + i) & m) };
        }
    }
    Ok(())
}

/// 16 bytes of 0xFF then 16 of zero: the 16 bytes from `16 - k` on select the first `k` of a word.
static FIRST: [u8; 32] = {
    let mut m = [0u8; 32];
    let mut i = 0;
    while i < 16 {
        m[i] = 0xff;
        i += 1;
    }
    m
};

/// The first `k` of the 16 bytes at `w + src` written over those at `w + dst`, the rest of `dst` kept.
///
/// # Safety
///
/// The 16 bytes at `w + src` and at `w + dst` must be valid to read and write, and `k` must be 1 to 16.
#[inline(always)]
unsafe fn blend16(w: *mut u8, src: usize, dst: usize, k: usize) {
    debug_assert!((1..=16).contains(&k));
    #[cfg(target_arch = "aarch64")]
    // SAFETY: as the caller promises; the 16 bytes at `16 - k` are inside `FIRST`
    unsafe {
        use std::arch::aarch64::*;
        let pick = vld1q_u8(FIRST.as_ptr().add(16 - k));
        vst1q_u8(w.add(dst), vbslq_u8(pick, vld1q_u8(w.add(src)), vld1q_u8(w.add(dst))));
    }
    #[cfg(not(target_arch = "aarch64"))]
    // SAFETY: as the caller promises
    unsafe {
        blend16_words(w, src, dst, k)
    }
}

/// [`blend16`] with plain 128-bit words, where there is no NEON.
///
/// # Safety
///
/// As for [`blend16`].
#[cfg(any(test, not(target_arch = "aarch64")))]
#[inline(always)]
unsafe fn blend16_words(w: *mut u8, src: usize, dst: usize, k: usize) {
    // SAFETY: as the caller promises
    unsafe {
        let s = w.add(src).cast::<u128>().read_unaligned();
        let d = w.add(dst).cast::<u128>().read_unaligned();
        // in the reads' own byte order, so each mask byte lines up with the window byte it picks
        let pick = u128::from_ne_bytes(FIRST[16 - k..32 - k].try_into().unwrap());
        w.add(dst).cast::<u128>().write_unaligned((s & pick) | (d & !pick));
    }
}

/// What follows a main-table symbol of 256 or more, read right after a refill.
#[inline(always)]
fn read_op(sym: u16, bits: &mut Bits<'_>, t: &Tables) -> Result<Tok> {
    Ok(match sym {
        256 => {
            let (after, tok) = read_filter(*bits);
            *bits = after;
            tok?
        }
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
            // the distance used moves to the front and the ones before it back one; spelled out, since shifting a
            // run of variable length calls memmove
            let k = usize::from(k) & 3;
            let d = hist[k];
            if k >= 3 {
                hist[3] = hist[2];
            }
            if k >= 2 {
                hist[2] = hist[1];
            }
            if k >= 1 {
                hist[1] = hist[0];
            }
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

/// A filter record's fields, with the bits after it.
fn read_filter(mut bits: Bits<'_>) -> (Bits<'_>, Result<Tok>) {
    let tok = read_filter_fields(&mut bits);
    (bits, tok)
}

fn read_filter_fields(bits: &mut Bits<'_>) -> Result<Tok> {
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

/// Runs a filter over `data`. The address filters work in place; delta reads its input out of order, so it writes
/// to `spare`, and the two are swapped after. The result is in `data`.
fn apply_filter(f: Filter, data: &mut Vec<u8>, spare: &mut Vec<u8>) {
    let n = data.len();
    match f.kind {
        FilterKind::Delta(channels) => {
            spare.clear();
            spare.resize(n, 0);
            let mut s = 0;
            for c in 0..usize::from(channels) {
                let mut acc = 0u8;
                for out in spare.iter_mut().skip(c).step_by(usize::from(channels)) {
                    acc = acc.wrapping_sub(data[s]);
                    *out = acc;
                    s += 1;
                }
            }
            std::mem::swap(data, spare);
        }
        FilterKind::E8 | FilterKind::E8E9 => {
            let e9 = f.kind == FilterKind::E8E9;
            // the four address bytes after an opcode are never scanned for one, so they can be rewritten in place
            let mut j = 0;
            while j + 4 < n {
                j = find_call(data, j, n - 4, e9);
                if j + 4 >= n {
                    break;
                }
                let p = j + 1;
                let pos = ((f.start + p as u64) % 0x100_0000) as u32;
                let a = u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
                let new = if a & 0x8000_0000 != 0 {
                    if a.wrapping_add(pos) & 0x8000_0000 == 0 { Some(a.wrapping_add(0x100_0000)) } else { None }
                } else if a < 0x100_0000 {
                    Some(a.wrapping_sub(pos))
                } else {
                    None
                };
                if let Some(v) = new {
                    data[p..p + 4].copy_from_slice(&v.to_le_bytes());
                }
                j = p + 4;
            }
        }
        FilterKind::Arm => {
            let mut j = 0;
            while j + 3 < n {
                if data[j + 3] == 0xeb {
                    let v = u32::from_le_bytes(data[j..j + 4].try_into().unwrap()) & 0x00ff_ffff;
                    let q = ((f.start + j as u64) / 4) as u32;
                    let v = (v.wrapping_sub(q) & 0x00ff_ffff) | 0xeb00_0000;
                    data[j..j + 4].copy_from_slice(&v.to_le_bytes());
                }
                j += 4;
            }
        }
    }
}

/// The first place from `j` on, before `end`, that holds 0xE8 (or 0xE9, when `e9`); `end` when there is none. Eight
/// bytes are checked at a time: with the low bit set in each, both opcodes read 0xE9, and a byte that matches comes
/// out zero, which the borrow trick finds (any byte it flags above the first true zero is ignored).
fn find_call(data: &[u8], mut j: usize, end: usize, e9: bool) -> usize {
    const ONES: u64 = 0x0101_0101_0101_0101;
    let (fold, want) = if e9 { (ONES, 0xe9 * ONES) } else { (0, 0xe8 * ONES) };
    while j + 8 <= end {
        let t = (u64::from_le_bytes(data[j..j + 8].try_into().unwrap()) | fold) ^ want;
        let zero = t.wrapping_sub(ONES) & !t & (ONES << 7);
        if zero != 0 {
            return j + (zero.trailing_zeros() / 8) as usize;
        }
        j += 8;
    }
    while j < end && data[j] | fold as u8 != want as u8 {
        j += 1;
    }
    j
}

#[cfg(test)]
mod tests;
