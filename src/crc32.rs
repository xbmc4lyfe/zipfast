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

//! CRC-32 (IEEE 802.3, reflected), as RAR, ZIP and gzip store it.
//!
//! On 64-bit ARM, input of a few hundred bytes or more is folded with carry-less multiplies (PMULL): eight 16-byte
//! lanes take in 128 bytes a round, each lane's value carried 1024 bits on by multiplying its halves by constants,
//! and the lanes are then folded into one, whose 16 bytes the CRC instructions finish. That runs at more than twice
//! the speed of chained CRC instructions, which wait on each other. Elsewhere, and for short input, `crc32fast`
//! does the work.

/// The CRC-32 of bytes given in pieces.
#[derive(Clone, Default)]
pub struct Hasher {
    /// the CRC of the bytes so far (final form: not inverted)
    crc: u32,
    /// how many there were, for [`Hasher::combine`]
    len: u64,
}

impl Hasher {
    pub fn new() -> Self {
        Hasher::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.crc = update(self.crc, bytes);
        self.len += bytes.len() as u64;
    }

    pub fn finalize(self) -> u32 {
        self.crc
    }

    /// Takes in the bytes `other` was given, as if they had been given to this one after its own.
    pub fn combine(&mut self, other: &Hasher) {
        let mut a = crc32fast::Hasher::new_with_initial_len(self.crc, self.len);
        a.combine(&crc32fast::Hasher::new_with_initial_len(other.crc, other.len));
        self.crc = a.finalize();
        self.len += other.len;
    }
}

/// The CRC-32 of `bytes`.
pub fn hash(bytes: &[u8]) -> u32 {
    update(0, bytes)
}

/// The CRC of what `crc` is the CRC of, with `bytes` after it.
fn update(crc: u32, bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "aarch64")]
    if bytes.len() >= FOLD_MIN && fold::usable() {
        // SAFETY: `usable` found the instructions `fold::run` needs
        return !unsafe { fold::run(!crc, bytes) };
    }
    let mut h = crc32fast::Hasher::new_with_initial(crc);
    h.update(bytes);
    h.finalize()
}

/// The shortest input folded: below it, setting up the lanes costs more than chaining CRC instructions.
#[cfg(target_arch = "aarch64")]
const FOLD_MIN: usize = 256;

#[cfg(target_arch = "aarch64")]
mod fold {
    use std::arch::aarch64::*;

    /// The polynomial, with its x^32 term, in normal order (bit i is the coefficient of x^i).
    const POLY: u64 = 0x1_04c1_1db7;

    /// x^n mod the polynomial, in normal order.
    const fn x_pow_mod(n: u32) -> u64 {
        let mut r: u64 = 1;
        let mut i = 0;
        while i < n {
            r <<= 1;
            if r & 1 << 32 != 0 {
                r ^= POLY;
            }
            i += 1;
        }
        r
    }

    /// What carries a 64-bit half `n` bits on: x^(n-1) mod the polynomial, bit-reflected like the data. A
    /// carry-less product of two reflected values comes out one place short, which the missing factor of x makes
    /// up.
    const fn k(n: u32) -> u64 {
        x_pow_mod(n - 1).reverse_bits()
    }

    /// For a lane carried 1024 bits on (eight lanes) and 128 bits on (the next lane): the constants for its first
    /// half, which stands 64 bits further from the end, and its second.
    const K1024: (u64, u64) = (k(1024 + 64), k(1024));
    const K128: (u64, u64) = (k(128 + 64), k(128));

    pub(super) fn usable() -> bool {
        std::arch::is_aarch64_feature_detected!("pmull") && std::arch::is_aarch64_feature_detected!("crc")
    }

    /// `acc` carried on by `k`'s distance, with `next` added.
    ///
    /// # Safety
    ///
    /// The processor must have PMULL.
    #[target_feature(enable = "aes")]
    #[inline]
    unsafe fn carry(acc: uint8x16_t, k: (u64, u64), next: uint8x16_t) -> uint8x16_t {
        let halves = vreinterpretq_u64_u8(acc);
        let a = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(halves, 0), k.0));
        let b = vreinterpretq_u8_p128(vmull_p64(vgetq_lane_u64(halves, 1), k.1));
        #[cfg(target_feature = "sha3")]
        // SAFETY: This build requires SHA3 support.
        let sum = unsafe { veor3q_u8(a, b, next) };
        #[cfg(not(target_feature = "sha3"))]
        let sum = veorq_u8(veorq_u8(a, b), next);
        sum
    }

    /// Chained CRC instructions over `bytes`, from the raw (inverted) register `c`.
    #[target_feature(enable = "crc")]
    unsafe fn chained(mut c: u32, bytes: &[u8]) -> u32 {
        let (words, rest) = bytes.as_chunks::<8>();
        for &w in words {
            c = __crc32d(c, u64::from_le_bytes(w));
        }
        for &b in rest {
            c = __crc32b(c, b);
        }
        c
    }

    /// The raw (inverted) CRC register after `bytes`, from `c`.
    ///
    /// # Safety
    ///
    /// The processor must have PMULL and the CRC instructions, and `bytes` must hold at least 128 bytes.
    #[target_feature(enable = "aes,crc")]
    pub(super) unsafe fn run(c: u32, bytes: &[u8]) -> u32 {
        debug_assert!(bytes.len() >= 128);
        // SAFETY: as the caller promises; every load is of 16 bytes inside `bytes`
        unsafe {
            let p = bytes.as_ptr();
            let mut lanes = [vdupq_n_u8(0); 8];
            for (i, lane) in lanes.iter_mut().enumerate() {
                *lane = vld1q_u8(p.add(16 * i));
            }
            // the register's starting value goes into the first four bytes
            lanes[0] = veorq_u8(lanes[0], vreinterpretq_u8_u32(vsetq_lane_u32(c, vdupq_n_u32(0), 0)));
            let mut at = 128;
            while at + 128 <= bytes.len() {
                for (i, lane) in lanes.iter_mut().enumerate() {
                    *lane = carry(*lane, K1024, vld1q_u8(p.add(at + 16 * i)));
                }
                at += 128;
            }
            let mut v = lanes[0];
            for &lane in &lanes[1..] {
                v = carry(v, K128, lane);
            }
            while at + 16 <= bytes.len() {
                v = carry(v, K128, vld1q_u8(p.add(at)));
                at += 16;
            }
            // what is left is congruent to the CRC of its own 16 bytes from a zero register
            let halves = vreinterpretq_u64_u8(v);
            let c = __crc32d(__crc32d(0, vgetq_lane_u64(halves, 0)), vgetq_lane_u64(halves, 1));
            chained(c, &bytes[at..])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(n: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 32) as u8
            })
            .collect()
    }

    #[test]
    fn matches_crc32fast_at_every_length_offset_and_split() {
        let data = bytes(70_000);
        for len in (0..1200).chain([2047, 2048, 2049, 4096, 65_537]) {
            for off in [0, 1, 7, 13] {
                let d = &data[off..off + len];
                let want = crc32fast::hash(d);
                assert_eq!(hash(d), want, "len {len} off {off}");
                for cut in [0, 1.min(len), len / 3, len.saturating_sub(5), len] {
                    let mut h = Hasher::new();
                    h.update(&d[..cut]);
                    h.update(&d[cut..]);
                    assert_eq!(h.clone().finalize(), want, "len {len} off {off} cut {cut}");
                    let mut first = Hasher::new();
                    first.update(&d[..cut]);
                    let mut second = Hasher::new();
                    second.update(&d[cut..]);
                    first.combine(&second);
                    assert_eq!(first.finalize(), want, "combined: len {len} off {off} cut {cut}");
                }
            }
        }
    }
}
