//! RAR 5.0 decompression (algorithm version 0), written from a behavioural specification of the format.
//!
//! The decoder is fed a file's packed bytes in whatever pieces they arrive in (one volume's part at a time) and
//! decodes every compressed block as soon as all of it is in. Decoded bytes go to a sink in file order, after any
//! filters over them have run.

use crate::error::{Error, Result};

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
/// Bits of a code looked up in one step; longer codes take the slow path.
const LUT_BITS: u32 = 10;

fn corrupt(what: &'static str) -> Error {
    Error::Corrupt(what)
}

/// MSB-first bits over one block's payload, followed by [`PAD`] zero bytes.
struct Bits<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    #[inline(always)]
    fn word(&self) -> u64 {
        let at = self.pos >> 3;
        // the padding keeps `at + 8` inside the buffer for any read that starts inside the payload
        let bytes: [u8; 8] = self.buf[at..at + 8].try_into().unwrap();
        u64::from_be_bytes(bytes) << (self.pos & 7)
    }

    #[inline(always)]
    fn peek16(&self) -> u32 {
        (self.word() >> 48) as u32
    }

    #[inline(always)]
    fn skip(&mut self, n: u32) {
        self.pos += n as usize;
    }

    /// Up to 32 bits.
    #[inline(always)]
    fn get(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let v = (self.word() >> (64 - n)) as u32;
        self.pos += n as usize;
        v
    }
}

/// A canonical prefix code with a lookup table for short codes.
#[derive(Clone)]
struct Huff {
    /// symbol << 4 | length, or 0 when the code is longer than the table
    lut: Vec<u16>,
    /// for each length, the first 16-bit left-aligned value past every code of that length or shorter
    limit: [u32; 16],
    /// for each length, the left-aligned first code of that length
    first: [u32; 16],
    /// for each length, where its symbols start in `sorted`
    start: [u16; 16],
    sorted: Vec<u16>,
    /// no codes at all
    empty: bool,
}

impl Huff {
    fn new() -> Self {
        Huff {
            lut: vec![0; 1 << LUT_BITS],
            limit: [0; 16],
            first: [0; 16],
            start: [0; 16],
            sorted: Vec::new(),
            empty: true,
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

    #[cold]
    fn decode_slow(&self, peek: u32, bits: &mut Bits<'_>) -> Result<u16> {
        for l in 1..16usize {
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
    main: Huff,
    dist: Huff,
    low: Huff,
    rep: Huff,
    history: [u64; 4],
    last_len: u32,
    filters: Vec<Filter>,
    /// filtered output for one filter at a time
    scratch: Vec<u8>,
    /// packed bytes not yet decoded: always the start of a block
    input: Vec<u8>,
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
            main: Huff::new(),
            dist: Huff::new(),
            low: Huff::new(),
            rep: Huff::new(),
            history: [0; 4],
            last_len: 0,
            filters: Vec::new(),
            scratch: Vec::new(),
            input: Vec::new(),
        })
    }

    pub fn window_size(&self) -> u64 {
        self.mask + 1
    }

    /// Starts the next file of a solid stream: the window, tables and history carry on.
    pub fn next_file(&mut self, size: Option<u64>) {
        self.file_base = self.sp;
        self.emitted = 0;
        self.size = size;
        self.filters.clear();
        self.input.clear();
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

    /// More of the file's packed bytes. Every block that is now complete is decoded and its output emitted.
    pub fn feed(&mut self, data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.input.extend_from_slice(data);
        let mut at = 0;
        loop {
            let rest = &self.input[at..];
            let Some((header_len, payload, flags)) = block_header(rest)? else { break };
            if rest.len() < header_len + payload {
                break;
            }
            let mut block = std::mem::take(&mut self.input);
            let start = at + header_len;
            // padding goes past the payload, into what follows it or past the end of the buffer
            let end = start + payload;
            let mut padded;
            let buf: &[u8] = if block.len() >= end + PAD {
                &block[..end + PAD]
            } else {
                padded = block[..end].to_vec();
                padded.resize(end + PAD, 0);
                &padded
            };
            let result = self.block(&buf[start..], payload, flags, sink);
            at = end;
            self.input = std::mem::take(&mut block);
            result?;
        }
        self.input.drain(..at);
        Ok(())
    }

    /// The file's packed bytes are all in. Emits what is left and checks the stream ended where it should.
    pub fn finish(&mut self, sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
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
        let valid_bits = usize::from(flags & 7) + 1;
        let end_bits = if payload == 0 { 0 } else { (payload - 1) * 8 + valid_bits };
        let mut bits = Bits { buf, pos: 0 };
        if flags & 0x80 != 0 {
            self.read_tables(&mut bits, end_bits)?;
        } else if !self.tables_ready && payload > 0 {
            return Err(corrupt("block without tables at the start of a stream"));
        }
        let flush_at = self.window_size() / 2;
        while bits.pos < end_bits {
            if self.sp - self.file_base - self.emitted > flush_at {
                self.flush(sink)?;
            }
            self.symbol(&mut bits)?;
        }
        if bits.pos > end_bits {
            return Err(corrupt("a symbol runs past the end of its block"));
        }
        Ok(())
    }

    fn read_tables(&mut self, bits: &mut Bits<'_>, end: usize) -> Result<()> {
        let mut bl = [0u8; BC];
        let mut i = 0;
        while i < BC {
            if bits.pos + 4 > end {
                return Err(corrupt("table runs past its block"));
            }
            let n = bits.get(4) as u8;
            if n == 15 {
                if bits.pos + 4 > end {
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
            if bits.pos >= end {
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
        if bits.pos > end {
            return Err(corrupt("table runs past its block"));
        }
        self.main.build(&lens[..NC])?;
        self.dist.build(&lens[NC..NC + DC])?;
        self.low.build(&lens[NC + DC..NC + DC + LDC])?;
        self.rep.build(&lens[NC + DC + LDC..])?;
        self.tables_ready = true;
        Ok(())
    }

    #[inline(always)]
    fn symbol(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        let sym = self.main.decode(bits)?;
        if sym < 256 {
            if self.size.is_some_and(|s| self.op() >= s) {
                return Err(corrupt("more data than the header says"));
            }
            let at = (self.sp & self.mask) as usize;
            self.window[at] = sym as u8;
            self.sp += 1;
            return Ok(());
        }
        match sym {
            256 => self.read_filter(bits),
            257 => {
                if self.last_len != 0 {
                    self.copy(self.last_len, self.history[0])?;
                }
                Ok(())
            }
            258..=261 => {
                let k = (sym - 258) as usize;
                let dist = self.history[k];
                self.history.copy_within(0..k, 1);
                self.history[0] = dist;
                let slot = self.rep.decode(bits)?;
                let len = length(slot as u32, bits);
                self.last_len = len;
                self.copy(len, dist)
            }
            _ => {
                let mut len = length(u32::from(sym - 262), bits);
                let slot = u32::from(self.dist.decode(bits)?);
                let dist = if slot < 4 {
                    1 + u64::from(slot)
                } else {
                    let d = slot / 2 - 1;
                    let base = 1 + ((2 + u64::from(slot & 1)) << d);
                    if d < 4 {
                        base + u64::from(bits.get(d))
                    } else {
                        let high = if d > 4 { u64::from(bits.get(d - 4)) << 4 } else { 0 };
                        base + high + u64::from(self.low.decode(bits)?)
                    }
                };
                len += u32::from(dist > 0x100) + u32::from(dist > 0x2000) + u32::from(dist > 0x40000);
                self.history.copy_within(0..3, 1);
                self.history[0] = dist;
                self.last_len = len;
                self.copy(len, dist)
            }
        }
    }

    #[inline(always)]
    fn copy(&mut self, len: u32, dist: u64) -> Result<()> {
        if dist == 0 || dist > self.sp || dist > self.mask + 1 {
            return Err(corrupt("match reaches before the start of the data"));
        }
        let len64 = u64::from(len);
        if let Some(size) = self.size
            && len64 > size.saturating_sub(self.op())
        {
            return Err(corrupt("more data than the header says"));
        }
        let size = self.mask + 1;
        let dst = (self.sp & self.mask) as usize;
        let src = ((self.sp - dist) & self.mask) as usize;
        let n = len as usize;
        if dst + n <= size as usize && src + n <= size as usize && (dist >= len64) {
            self.window.copy_within(src..src + n, dst);
        } else if dist == 1 && dst + n <= size as usize {
            let b = self.window[src];
            self.window[dst..dst + n].fill(b);
        } else {
            let mask = self.mask as usize;
            for i in 0..n {
                self.window[(dst + i) & mask] = self.window[(src + i) & mask];
            }
        }
        self.sp += len64;
        Ok(())
    }

    fn read_filter(&mut self, bits: &mut Bits<'_>) -> Result<()> {
        let number = |bits: &mut Bits<'_>| -> u64 {
            let n = bits.get(2) + 1;
            let mut v = 0u64;
            for i in 0..n {
                v |= u64::from(bits.get(8)) << (8 * i);
            }
            v
        };
        let start = self.op() + number(bits);
        let len = number(bits);
        let kind = match bits.get(3) {
            0 => FilterKind::Delta(bits.get(5) as u8 + 1),
            1 => FilterKind::E8,
            2 => FilterKind::E8E9,
            3 => FilterKind::Arm,
            _ => return Err(corrupt("unknown filter type")),
        };
        if !(4..=MAX_FILTER_LEN).contains(&len) || len > self.window_size() / 2 {
            return Err(corrupt("filter length"));
        }
        if let Some(prev) = self.filters.last()
            && start < prev.start + prev.len
        {
            return Err(corrupt("filters overlap"));
        }
        if self.filters.len() >= MAX_FILTERS {
            return Err(corrupt("too many filters"));
        }
        self.filters.push(Filter { start, len, kind });
        Ok(())
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
