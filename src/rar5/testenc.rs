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
const PRE_LEN: u32 = 5;

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

fn put_len(w: &mut BitWriter, len: u32, code_len: u32, sym_base: u32) {
    let (slot, extra, rest) = len_slot(len);
    w.put(u64::from(sym_base + slot), code_len);
    w.put(u64::from(rest), extra);
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

fn put_tables(w: &mut BitWriter) {
    for _ in 0..BC {
        w.put(u64::from(PRE_LEN), 4);
    }
    let lens = [(NC, MAIN_LEN), (DC, DIST_LEN), (LDC, LOW_LEN), (RC, REP_LEN)];
    for (n, l) in lens {
        for _ in 0..n {
            w.put(u64::from(l), PRE_LEN);
        }
    }
}

fn put_op(w: &mut BitWriter, op: &Op) {
    match *op {
        Op::Lit(b) => w.put(u64::from(b), MAIN_LEN),
        Op::Last => w.put(257, MAIN_LEN),
        Op::Rep(k, len) => {
            w.put(258 + k as u64, MAIN_LEN);
            put_len(w, len, REP_LEN, 0);
        }
        Op::Match(len, dist) => {
            let bonus = u32::from(dist > 0x100) + u32::from(dist > 0x2000) + u32::from(dist > 0x40000);
            put_len(w, len - bonus, MAIN_LEN, 262);
            let (slot, d, base) = (0..64u32)
                .map(|slot| {
                    if slot < 4 {
                        (slot, 0, 1 + u64::from(slot))
                    } else {
                        let d = slot / 2 - 1;
                        (slot, d, 1 + ((2 + u64::from(slot & 1)) << d))
                    }
                })
                .find(|&(_, d, base)| dist >= base && dist < base + (1u64 << d))
                .unwrap();
            w.put(u64::from(slot), DIST_LEN);
            let rest = dist - base;
            if d < 4 {
                w.put(rest, d);
            } else {
                if d > 4 {
                    w.put(rest >> 4, d - 4);
                }
                w.put(rest & 15, LOW_LEN);
            }
        }
        Op::Filter { start, len, kind, channels } => {
            w.put(256, MAIN_LEN);
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
    let mut w = BitWriter::new();
    if tables {
        put_tables(&mut w);
    }
    for op in ops {
        put_op(&mut w, op);
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
