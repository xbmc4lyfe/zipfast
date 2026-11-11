// Copyright (C) 2026 xbmc4lyfe
// SPDX-License-Identifier: RPL-1.5
//
// Unless explicitly acquired and licensed from Licensor under another license,
// the contents of this file are subject to the Reciprocal Public License
// ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
// may not copy or use this file in either source code or executable form,
// except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS"
// basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
// HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
// ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
// rights and limitations under the RPL.

//! BLAKE2sp, the 8-way parallel form of BLAKE2s, as RAR 5.0 uses for its optional file hash. Written from RFC 7693
//! (BLAKE2s) and the BLAKE2 paper's description of the parallel modes: eight leaves take the input's 64-byte blocks
//! in turn, and a root hashes the leaves' digests.

const IV: [u32; 8] = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const BLOCK: usize = 64;
const LANES: usize = 8;

/// One BLAKE2s instance. The last block seen is held back until `finish`, since only then is it known to be last.
#[derive(Clone)]
struct Blake2s {
    h: [u32; 8],
    t: u64,
    buf: [u8; BLOCK],
    buf_len: usize,
    last_node: bool,
}

impl Blake2s {
    /// A tree node: 32-byte digest, no key, fanout 8, depth 2, inner length 32.
    fn node(offset: u32, depth: u8, last_node: bool) -> Self {
        let mut h = IV;
        // parameter block words: digest length, key length, fanout, depth / leaf length / node offset /
        // node offset high, node depth, inner length / salt and personalisation (zero)
        h[0] ^= 32 | (u32::from(LANES as u8) << 16) | (2 << 24);
        h[2] ^= offset;
        h[3] ^= (u32::from(depth) << 16) | (32 << 24);
        Blake2s { h, t: 0, buf: [0; BLOCK], buf_len: 0, last_node }
    }

    fn compress(&mut self, block: &[u8; BLOCK], last: bool) {
        let mut m = [0u32; 16];
        for (i, w) in m.iter_mut().enumerate() {
            *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t as u32;
        v[13] ^= (self.t >> 32) as u32;
        if last {
            v[14] = !v[14];
            if self.last_node {
                v[15] = !v[15];
            }
        }
        #[inline(always)]
        fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(12);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(8);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(7);
        }
        for s in &SIGMA {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.buf_len == BLOCK {
                self.t += BLOCK as u64;
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
            }
            let n = (BLOCK - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
            self.buf_len += n;
            data = &data[n..];
        }
    }

    fn finish(mut self) -> [u8; 32] {
        self.t += self.buf_len as u64;
        self.buf[self.buf_len..].fill(0);
        let block = self.buf;
        self.compress(&block, true);
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }
}

/// Streaming BLAKE2sp. Input is gathered into rounds of eight blocks; a full round is dealt out only once more input
/// follows it, so the final round can be split the way the parallel mode splits a message's tail.
#[derive(Clone)]
pub struct Blake2sp {
    leaves: Vec<Blake2s>,
    round: Vec<u8>,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    pub fn new() -> Self {
        let leaves = (0..LANES).map(|i| Blake2s::node(i as u32, 0, i == LANES - 1)).collect();
        Blake2sp { leaves, round: Vec::with_capacity(LANES * BLOCK) }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.round.len() == LANES * BLOCK {
                for (leaf, block) in self.leaves.iter_mut().zip(self.round.as_chunks::<BLOCK>().0) {
                    leaf.update(block);
                }
                self.round.clear();
            }
            let n = (LANES * BLOCK - self.round.len()).min(data.len());
            self.round.extend_from_slice(&data[..n]);
            data = &data[n..];
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        for (i, leaf) in self.leaves.iter_mut().enumerate() {
            let from = i * BLOCK;
            if self.round.len() > from {
                leaf.update(&self.round[from..self.round.len().min(from + BLOCK)]);
            }
        }
        let mut root = Blake2s::node(0, 1, true);
        for leaf in self.leaves {
            root.update(&leaf.finish());
        }
        root.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn blake2s_matches_rfc_7693() {
        // the RFC's own example, with plain sequential parameters
        let mut s = Blake2s::node(0, 0, false);
        s.h = IV;
        s.h[0] ^= 0x0101_0020;
        s.update(b"abc");
        assert_eq!(hex(&s.finish()), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    }

    #[test]
    fn blake2sp_known_answers() {
        // computed with an independent construction from Python's hashlib tree parameters
        let cases = [
            (0, "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"),
            (1, "a6b9eecc25227ad788c99d3f236debc8da408849e9a5178978727a81457f7239"),
            (64, "cc7a4d29e03634d99a2faa6812670672259183d47fc824eed98990045df1d4df"),
            (511, "eaf475c4cf2ef7466da52a56e0a7e2f8ae80047edf5ddbafacf995fd7821e88b"),
            (512, "36d2635a4853aa0ec5a6f246986a28f490129beac52c5ea047478a488c050f0a"),
            (513, "560d0aa2ffaeb39746112bd4f5b7d0bccef3efdf21be47e14dd9e33b782db88c"),
            (1024, "4fa7de206fb54150dd7a79b6d59c5c5739e9433c5437a9e6baef8ac1dc983e8f"),
            (5000, "9b79f268588cfaece26cfe812a4ca3c72c796bd82dcb81547469f8cf72e8b7ba"),
        ];
        for (n, want) in cases {
            let data: Vec<u8> = (0..n as u32).map(|i| (i * 31 % 251) as u8).collect();
            let mut h = Blake2sp::new();
            h.update(&data);
            assert_eq!(hex(&h.finish()), want, "length {n}");
        }
    }

    #[test]
    fn chunking_does_not_change_the_hash() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 % 251) as u8).collect();
        let mut whole = Blake2sp::new();
        whole.update(&data);
        let mut pieces = Blake2sp::new();
        for c in data.chunks(77) {
            pieces.update(c);
        }
        assert_eq!(whole.finish(), pieces.finish());
    }
}
