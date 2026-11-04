//! A small RAR 5.0 block encoder for tests: fixed code lengths, the ops it is given, nothing clever. It exists so
//! the decoder and the extractor can be tested without archives made by other tools.
#![allow(missing_docs)]

use super::unpack::{BC, DC, LDC, NC, RC};

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BitWriter {
    out: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    pub fn new() -> Self {
        BitWriter { out: Vec::new(), bits: 0 }
    }

    pub fn put(&mut self, value: u64, n: u32) {
        for i in (0..n).rev() {
            if self.bits.is_multiple_of(8) {
                self.out.push(0);
            }
            if (value >> i) & 1 == 1 {
                let last = self.out.len() - 1;
                self.out[last] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
    }
}

/// Uniform code lengths: with every symbol the same length, a symbol's code is its own number.
pub const MAIN_LEN: u32 = 9;
const DIST_LEN: u32 = 6;
const LOW_LEN: u32 = 4;
const REP_LEN: u32 = 6;

#[derive(Clone, Debug)]
pub enum Op {
    Lit(u8),
    Match(u32, u64),
    Rep(usize, u32),
    Last,
    Filter { start: u64, len: u64, kind: u8, channels: u8 },
}

fn len_slot(len: u32) -> (u32, u32, u32) {
    for slot in 0..44u32 {
        let (base, extra) = if slot < 8 {
            (2 + slot, 0)
        } else {
            let e = slot / 4 - 1;
            (2 + ((4 + (slot & 3)) << e), e)
        };
        if len >= base && len < base + (1 << extra) {
            return (slot, extra, len - base);
        }
    }
    panic!("length {len}");
}

/// Canonical codes for one table: (code, length) per symbol, assigned in (length, symbol) order like the decoder.
#[derive(Clone)]
struct Table {
    codes: Vec<(u32, u32)>,
}

impl Table {
    fn uniform(n: usize, len: u32) -> Self {
        Table::from_lengths(&vec![len; n])
    }

    fn from_lengths(lengths: &[u32]) -> Self {
        let mut codes = vec![(0, 0); lengths.len()];
        let mut code = 0u32;
        for l in 1..16u32 {
            for (sym, &sl) in lengths.iter().enumerate() {
                if sl == l {
                    codes[sym] = (code, l);
                    code += 1;
                }
            }
            code <<= 1;
        }
        Table { codes }
    }

    fn lengths(&self) -> Vec<u32> {
        self.codes.iter().map(|c| c.1).collect()
    }

    fn put(&self, w: &mut BitWriter, sym: u32) {
        let (code, len) = self.codes[sym as usize];
        assert!(len > 0, "symbol {sym} has no code");
        w.put(u64::from(code), len);
    }
}

/// Huffman code lengths of at most 15 bits for these counts; unused symbols get none.
fn lengths_for(counts: &[u64]) -> Vec<u32> {
    let mut counts = counts.to_vec();
    loop {
        let used: Vec<usize> = (0..counts.len()).filter(|&i| counts[i] > 0).collect();
        let mut out = vec![0u32; counts.len()];
        if used.len() == 1 {
            out[used[0]] = 1;
            return out;
        }
        if used.is_empty() {
            return out;
        }
        // nodes: (weight, members)
        let mut nodes: Vec<(u64, Vec<usize>)> = used.iter().map(|&i| (counts[i], vec![i])).collect();
        while nodes.len() > 1 {
            nodes.sort_by_key(|n| std::cmp::Reverse(n.0));
            let a = nodes.pop().unwrap();
            let b = nodes.pop().unwrap();
            for &m in a.1.iter().chain(b.1.iter()) {
                out[m] += 1;
            }
            let mut members = a.1;
            members.extend(b.1);
            nodes.push((a.0 + b.0, members));
        }
        if out.iter().all(|&l| l <= 15) {
            return out;
        }
        for c in counts.iter_mut().filter(|c| **c > 0) {
            *c = (*c >> 1) | 1;
        }
    }
}

/// The four tables a block's symbols are written with.
#[derive(Clone)]
struct Codes {
    main: Table,
    dist: Table,
    low: Table,
    rep: Table,
}

impl Codes {
    fn fixed() -> Self {
        Codes {
            main: Table::uniform(NC, MAIN_LEN),
            dist: Table::uniform(DC, DIST_LEN),
            low: Table::uniform(LDC, LOW_LEN),
            rep: Table::uniform(RC, REP_LEN),
        }
    }

    /// Codes fitted to how often `ops` use each symbol.
    fn tuned(ops: &[Op]) -> Self {
        let mut c = Counts::default();
        for op in ops {
            visit(op, &mut |t, sym| c.0[t][sym as usize] += 1);
        }
        Codes {
            main: Table::from_lengths(&lengths_for(&c.0[0][..NC])),
            dist: Table::from_lengths(&lengths_for(&c.0[1][..DC])),
            low: Table::from_lengths(&lengths_for(&c.0[2][..LDC])),
            rep: Table::from_lengths(&lengths_for(&c.0[3][..RC])),
        }
    }

    fn table(&self, t: usize) -> &Table {
        [&self.main, &self.dist, &self.low, &self.rep][t]
    }
}

struct Counts([[u64; NC]; 4]);

impl Default for Counts {
    fn default() -> Self {
        Counts([[0; NC]; 4])
    }
}

const T_MAIN: usize = 0;
const T_DIST: usize = 1;
const T_LOW: usize = 2;
const T_REP: usize = 3;

fn len_parts(len: u32) -> (u32, u32, u32) {
    let (slot, extra, rest) = len_slot(len);
    (slot, rest, extra)
}

fn dist_parts(dist: u64) -> (u32, u32, u64) {
    (0..64u32)
        .map(|slot| {
            if slot < 4 {
                (slot, 0, 1 + u64::from(slot))
            } else {
                let d = slot / 2 - 1;
                (slot, d, 1 + ((2 + u64::from(slot & 1)) << d))
            }
        })
        .find(|&(_, d, base)| dist >= base && dist < base + (1u64 << d))
        .map(|(slot, d, base)| (slot, d, dist - base))
        .unwrap()
}

fn match_bonus(dist: u64) -> u32 {
    u32::from(dist > 0x100) + u32::from(dist > 0x2000) + u32::from(dist > 0x40000)
}

/// Calls `f(table, symbol)` for each coded symbol an op writes.
fn visit(op: &Op, f: &mut dyn FnMut(usize, u32)) {
    match *op {
        Op::Lit(b) => f(T_MAIN, u32::from(b)),
        Op::Last => f(T_MAIN, 257),
        Op::Rep(k, len) => {
            f(T_MAIN, 258 + k as u32);
            f(T_REP, len_parts(len).0);
        }
        Op::Match(len, dist) => {
            f(T_MAIN, 262 + len_parts(len - match_bonus(dist)).0);
            let (slot, d, _) = dist_parts(dist);
            f(T_DIST, slot);
            if d >= 4 {
                f(T_LOW, (dist_parts(dist).2 & 15) as u32);
            }
        }
        Op::Filter { .. } => f(T_MAIN, 256),
    }
}

fn put_number(w: &mut BitWriter, v: u64) {
    let bytes = if v < 1 << 8 {
        1
    } else if v < 1 << 16 {
        2
    } else if v < 1 << 24 {
        3
    } else {
        4
    };
    w.put(bytes - 1, 2);
    for i in 0..bytes {
        w.put((v >> (8 * i)) & 0xff, 8);
    }
}

fn put_tables(w: &mut BitWriter, codes: &Codes) {
    let mut all = Vec::new();
    for t in 0..4 {
        all.extend(codes.table(t).lengths());
    }
    // the lengths as pre-code symbols: 0-15 literally, 18/19 for runs of zeros
    let mut syms: Vec<(u32, u32, u32)> = Vec::new(); // (symbol, extra value, extra bits)
    let mut i = 0;
    while i < all.len() {
        if all[i] == 0 {
            let mut run = 1;
            while i + run < all.len() && all[i + run] == 0 && run < 138 {
                run += 1;
            }
            if run >= 11 {
                syms.push((19, (run - 11) as u32, 7));
                i += run;
                continue;
            }
            if run >= 3 {
                syms.push((18, (run - 3) as u32, 3));
                i += run;
                continue;
            }
        }
        syms.push((all[i], 0, 0));
        i += 1;
    }
    let mut counts = [0u64; BC];
    for s in &syms {
        counts[s.0 as usize] += 1;
    }
    let mut pre_len = lengths_for(&counts);
    // a pre-code with one symbol still needs two codes' room to be read back; give it a partner
    if pre_len.iter().filter(|&&l| l > 0).count() == 1 {
        let other = if pre_len[0] == 0 { 0 } else { 1 };
        pre_len[other] = 1;
    }
    for &l in &pre_len {
        w.put(u64::from(l), 4);
        if l == 15 {
            w.put(0, 4);
        }
    }
    let pre = Table::from_lengths(&pre_len);
    for (sym, extra, bits) in syms {
        pre.put(w, sym);
        w.put(u64::from(extra), bits);
    }
}

fn put_op(w: &mut BitWriter, codes: &Codes, op: &Op) {
    match *op {
        Op::Lit(b) => codes.main.put(w, u32::from(b)),
        Op::Last => codes.main.put(w, 257),
        Op::Rep(k, len) => {
            codes.main.put(w, 258 + k as u32);
            let (slot, rest, extra) = len_parts(len);
            codes.rep.put(w, slot);
            w.put(u64::from(rest), extra);
        }
        Op::Match(len, dist) => {
            let (slot, rest, extra) = len_parts(len - match_bonus(dist));
            codes.main.put(w, 262 + slot);
            w.put(u64::from(rest), extra);
            let (slot, d, rest) = dist_parts(dist);
            codes.dist.put(w, slot);
            if d < 4 {
                w.put(rest, d);
            } else {
                if d > 4 {
                    w.put(rest >> 4, d - 4);
                }
                codes.low.put(w, (rest & 15) as u32);
            }
        }
        Op::Filter { start, len, kind, channels } => {
            codes.main.put(w, 256);
            put_number(w, start);
            put_number(w, len);
            w.put(u64::from(kind), 3);
            if kind == 0 {
                w.put(u64::from(channels - 1), 5);
            }
        }
    }
}

/// One block: header and payload.
pub fn block(ops: &[Op], tables: bool, last: bool) -> Vec<u8> {
    write_block(ops, &Codes::fixed(), tables, last)
}

/// One block with code lengths fitted to its ops, as a real encoder would write it.
pub fn tuned_block(ops: &[Op], last: bool) -> Vec<u8> {
    write_block(ops, &Codes::tuned(ops), true, last)
}

fn write_block(ops: &[Op], codes: &Codes, tables: bool, last: bool) -> Vec<u8> {
    let mut w = BitWriter::new();
    if tables {
        put_tables(&mut w, codes);
    }
    for op in ops {
        put_op(&mut w, codes, op);
    }
    let size = w.out.len();
    let valid = if w.bits.is_multiple_of(8) { 8 } else { w.bits % 8 };
    let size_len = if size < 1 << 8 {
        1
    } else if size < 1 << 16 {
        2
    } else {
        3
    };
    let mut flags = (valid - 1) as u8 | (((size_len - 1) as u8) << 3);
    if tables {
        flags |= 0x80;
    }
    if last {
        flags |= 0x40;
    }
    let mut out = vec![flags, 0];
    for i in 0..size_len {
        out.push((size >> (8 * i)) as u8);
    }
    out[1] = 0x5a ^ flags ^ (size as u8) ^ ((size >> 8) as u8) ^ ((size >> 16) as u8);
    out.extend(w.out);
    out
}

/// What the ops decode to, by the format's rules (before filters).
pub fn model(ops: &[Op]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut hist = [0u64; 4];
    let mut last = 0u32;
    let copy = |out: &mut Vec<u8>, len: u32, dist: u64| {
        for _ in 0..len {
            let b = out[out.len() - dist as usize];
            out.push(b);
        }
    };
    for op in ops {
        match *op {
            Op::Lit(b) => out.push(b),
            Op::Match(len, dist) => {
                hist.copy_within(0..3, 1);
                hist[0] = dist;
                last = len;
                copy(&mut out, len, dist);
            }
            Op::Rep(k, len) => {
                let d = hist[k];
                hist.copy_within(0..k, 1);
                hist[0] = d;
                last = len;
                copy(&mut out, len, d);
            }
            Op::Last => copy(&mut out, last, hist[0]),
            Op::Filter { .. } => {}
        }
    }
    out
}

/// Greedy LZ77 over `data` with matches no farther back than `window`: good enough to give the decoder a realistic
/// mix of literals, matches and repeats to chew on. Slow, and not meant to be anything else.
pub fn lz(data: &[u8], window: usize, depth: usize) -> Vec<Op> {
    const HASH: usize = 1 << 16;
    let mut head = vec![usize::MAX; HASH];
    let mut prev = vec![usize::MAX; data.len()];
    let hash = |i: usize| -> usize {
        let v = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        (v.wrapping_mul(0x9e37_79b1) >> 16) as usize
    };
    let common = |a: usize, b: usize, cap: usize| -> usize {
        let mut n = 0;
        while n < cap && data[a + n] == data[b + n] {
            n += 1;
        }
        n
    };
    let mut ops = Vec::new();
    let mut hist = [0u64; 4];
    let mut i = 0;
    let insert = |head: &mut Vec<usize>, prev: &mut Vec<usize>, j: usize| {
        if j + 4 <= data.len() {
            let h = hash(j);
            prev[j] = head[h];
            head[h] = j;
        }
    };
    while i < data.len() {
        let cap = (data.len() - i).min(4097);
        let mut best = (0usize, 0u64, None::<usize>);
        for (k, &d) in hist.iter().enumerate() {
            let d = d as usize;
            if d != 0 && d <= i {
                let n = common(i - d, i, cap);
                if n >= 2 && n > best.0 {
                    best = (n, d as u64, Some(k));
                }
            }
        }
        if i + 4 <= data.len() {
            let mut cand = head[hash(i)];
            let mut tries = depth;
            while cand != usize::MAX && tries > 0 && i - cand <= window {
                let d = (i - cand) as u64;
                let n = common(cand, i, cap);
                let need = 2 + match_bonus(d) as usize + 2;
                if n >= need && n > best.0 + 1 {
                    best = (n, d, None);
                }
                cand = prev[cand];
                tries -= 1;
            }
        }
        let (n, d, rep) = best;
        if n == 0 {
            ops.push(Op::Lit(data[i]));
            insert(&mut head, &mut prev, i);
            i += 1;
            continue;
        }
        match rep {
            Some(k) => {
                let n = n.min(4097);
                ops.push(Op::Rep(k, n as u32));
                let v = hist[k];
                hist.copy_within(0..k, 1);
                hist[0] = v;
                for j in i..i + n {
                    insert(&mut head, &mut prev, j);
                }
                i += n;
            }
            None => {
                let n = n.min(4097);
                ops.push(Op::Match(n as u32, d));
                hist.copy_within(0..3, 1);
                hist[0] = d;
                for j in i..i + n {
                    insert(&mut head, &mut prev, j);
                }
                i += n;
            }
        }
    }
    ops
}

/// `ops` as a stream of blocks of at most `per_block` ops each, every block with its own fitted tables.
pub fn tuned_stream(ops: &[Op], per_block: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let chunks: Vec<&[Op]> = ops.chunks(per_block.max(1)).collect();
    for (i, c) in chunks.iter().enumerate() {
        out.extend(tuned_block(c, i + 1 == chunks.len()));
    }
    out
}
