//! Pure-Rust cryptographic primitives for archive password verification and decryption:
//! - FIPS 197 AES-128, AES-192, and AES-256 (CBC and WinZip CTR modes)
//! - RAR 5.0 PBKDF2-HMAC-SHA256 key derivation, `PasswordCheck` verification, tweaked CRC32, and `-hp` header decryption
//! - RAR 4.x (`SetKey30`) SHA-1 key/IV derivation and `-hp` header decryption
//! - ZIP traditional PKWARE stream cipher (ZipCrypto) and WinZip AES (`0x9901`) PBKDF2-HMAC-SHA1 decryption

/// AES-128 (10 rounds), AES-192 (12 rounds), or AES-256 (14 rounds) expanded round keys.
#[derive(Clone, Copy)]
pub struct AesKey {
    enc_rk: [[u8; 16]; 15],
    rounds: usize,
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39,
    0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2,
    0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76,
    0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc,
    0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d,
    0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c,
    0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f,
    0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62,
    0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd,
    0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
    0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6,
    0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

const RCON: [u32; 10] = [
    0x0100_0000,
    0x0200_0000,
    0x0400_0000,
    0x0800_0000,
    0x1000_0000,
    0x2000_0000,
    0x4000_0000,
    0x8000_0000,
    0x1b00_0000,
    0x3600_0000,
];

fn sub_word(w: u32) -> u32 {
    let [b0, b1, b2, b3] = w.to_be_bytes();
    u32::from_be_bytes([SBOX[usize::from(b0)], SBOX[usize::from(b1)], SBOX[usize::from(b2)], SBOX[usize::from(b3)]])
}

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

#[inline]
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for col in s.as_chunks_mut::<4>().0 {
        let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
        col[0] = gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
        col[1] = gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
        col[2] = gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
        col[3] = gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
    }
}

impl AesKey {
    pub fn new(key: &[u8]) -> Option<Self> {
        let (nk, nr) = match key.len() {
            16 => (4usize, 10usize),
            24 => (6usize, 12usize),
            32 => (8usize, 14usize),
            _ => return None,
        };
        let total_words = 4 * (nr + 1);
        let mut w = [0u32; 60];
        for (i, chunk) in key.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in nk..total_words {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = sub_word(temp.rotate_left(8)) ^ RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
        let mut enc_rk = [[0u8; 16]; 15];
        for r in 0..=nr {
            for c in 0..4 {
                enc_rk[r][c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c].to_be_bytes());
            }
        }
        Some(Self { enc_rk, rounds: nr })
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[0]) {
            *b ^= k;
        }
        for round_key in self.enc_rk.iter().take(self.rounds).skip(1) {
            for b in &mut s {
                *b = SBOX[usize::from(*b)];
            }
            s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]];
            for col in s.as_chunks_mut::<4>().0 {
                let (s0, s1, s2, s3) = (col[0], col[1], col[2], col[3]);
                let t = s0 ^ s1 ^ s2 ^ s3;
                col[0] ^= t ^ xtime(s0 ^ s1);
                col[1] ^= t ^ xtime(s1 ^ s2);
                col[2] ^= t ^ xtime(s2 ^ s3);
                col[3] ^= t ^ xtime(s3 ^ s0);
            }
            for (b, &k) in s.iter_mut().zip(round_key) {
                *b ^= k;
            }
        }
        for b in &mut s {
            *b = SBOX[usize::from(*b)];
        }
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]];
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[self.rounds]) {
            *b ^= k;
        }
        s
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[self.rounds]) {
            *b ^= k;
        }
        for round in (1..self.rounds).rev() {
            s = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]];
            for b in &mut s {
                *b = INV_SBOX[usize::from(*b)];
            }
            for (b, &k) in s.iter_mut().zip(&self.enc_rk[round]) {
                *b ^= k;
            }
            inv_mix_columns(&mut s);
        }
        s = [s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3]];
        for b in &mut s {
            *b = INV_SBOX[usize::from(*b)];
        }
        for (b, &k) in s.iter_mut().zip(&self.enc_rk[0]) {
            *b ^= k;
        }
        s
    }

    /// Decrypts 16-byte aligned blocks in place using AES-CBC and updates `iv` to the last ciphertext block.
    pub fn decrypt_cbc_in_place(&self, iv: &mut [u8; 16], data: &mut [u8]) {
        for chunk in data.as_chunks_mut::<16>().0 {
            let ct = *chunk;
            let mut plain = self.decrypt_block(&ct);
            for (p, &iv_b) in plain.iter_mut().zip(&*iv) {
                *p ^= iv_b;
            }
            *chunk = plain;
            *iv = ct;
        }
    }
}

/// Decrypts AES-CBC ciphertext (`key` is 16, 24, or 32 bytes; `iv` is 16 bytes).
/// Trailing bytes that do not form a complete 16-byte block are ignored.
pub fn decrypt_cbc(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = AesKey::new(key)?;
    let n = (data.len() / 16) * 16;
    if n == 0 {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(n);
    let mut prev = *iv;
    for chunk in data.get(..n)?.as_chunks::<16>().0 {
        let mut plain = cipher.decrypt_block(chunk);
        for (p, &iv_b) in plain.iter_mut().zip(&prev) {
            *p ^= iv_b;
        }
        out.extend_from_slice(&plain);
        prev = *chunk;
    }
    Some(out)
}

/// Encrypts AES-CBC plaintext (`data` must be a multiple of 16 bytes).
pub fn encrypt_cbc(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    let cipher = AesKey::new(key)?;
    if !data.len().is_multiple_of(16) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = *iv;
    for chunk in data.as_chunks::<16>().0 {
        let mut x = *chunk;
        for (b, &p) in x.iter_mut().zip(&prev) {
            *b ^= p;
        }
        let enc = cipher.encrypt_block(&x);
        out.extend_from_slice(&enc);
        prev = enc;
    }
    Some(out)
}

/// Decrypts WinZip AES CTR-mode ciphertext (little-endian counter starting at 1).
pub fn decrypt_winzip_ctr(key: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = AesKey::new(key)?;
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut counter = [0u8; 16];
    for chunk in ciphertext.chunks(16) {
        for b in &mut counter {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let ks = cipher.encrypt_block(&counter);
        for (&c, &k) in chunk.iter().zip(&ks) {
            out.push(c ^ k);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Pure-Rust SHA-256 + HMAC-SHA256 + RAR 5.0 key derivation & header decryption
// ---------------------------------------------------------------------------

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const SHA256_IV: [u32; 8] =
    [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];

#[inline]
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Computes SHA-256 over `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = SHA256_IV;
    let (blocks, rem) = data.as_chunks::<64>();
    for b in blocks {
        sha256_compress(&mut state, b);
    }
    let bit_len = (data.len() as u64) * 8;
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    if rem.len() < 56 {
        tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut state, tail[..64].try_into().unwrap());
    } else {
        tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
        sha256_compress(&mut state, tail[..64].try_into().unwrap());
        sha256_compress(&mut state, tail[64..128].try_into().unwrap());
    }
    let mut out = [0u8; 32];
    for (i, &word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Precomputed inner/outer SHA-256 states after absorbing the 64-byte HMAC ipad and opad blocks.
#[derive(Clone, Copy)]
struct HmacSha256Key {
    inner: [u32; 8],
    outer: [u32; 8],
}

impl HmacSha256Key {
    fn new(key: &[u8]) -> Self {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&sha256(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = SHA256_IV;
        let mut outer = SHA256_IV;
        sha256_compress(&mut inner, &ipad);
        sha256_compress(&mut outer, &opad);
        Self { inner, outer }
    }

    /// Computes HMAC-SHA256 over a 32-byte digest (`u`), avoiding heap allocation inside PBKDF2 loops.
    #[inline]
    fn mac_32(&self, u: &[u8; 32]) -> [u8; 32] {
        let mut in_state = self.inner;
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(u);
        block[32] = 0x80;
        // Total length = 64 (ipad) + 32 (u) = 96 bytes = 768 bits
        block[56..64].copy_from_slice(&768u64.to_be_bytes());
        sha256_compress(&mut in_state, &block);

        let mut out_block = [0u8; 64];
        for (i, &word) in in_state.iter().enumerate() {
            out_block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out_block[32] = 0x80;
        out_block[56..64].copy_from_slice(&768u64.to_be_bytes());
        let mut out_state = self.outer;
        sha256_compress(&mut out_state, &out_block);

        let mut out = [0u8; 32];
        for (i, &word) in out_state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn mac_slice(&self, data: &[u8]) -> [u8; 32] {
        let mut in_state = self.inner;
        let (blocks, rem) = data.as_chunks::<64>();
        for b in blocks {
            sha256_compress(&mut in_state, b);
        }
        let bit_len = ((64 + data.len()) as u64) * 8;
        let mut tail = [0u8; 128];
        tail[..rem.len()].copy_from_slice(rem);
        tail[rem.len()] = 0x80;
        if rem.len() < 56 {
            tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
            sha256_compress(&mut in_state, tail[..64].try_into().unwrap());
        } else {
            tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
            sha256_compress(&mut in_state, tail[..64].try_into().unwrap());
            sha256_compress(&mut in_state, tail[64..128].try_into().unwrap());
        }
        let mut out_block = [0u8; 64];
        for (i, &word) in in_state.iter().enumerate() {
            out_block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out_block[32] = 0x80;
        out_block[56..64].copy_from_slice(&768u64.to_be_bytes());
        let mut out_state = self.outer;
        sha256_compress(&mut out_state, &out_block);
        let mut out = [0u8; 32];
        for (i, &word) in out_state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// RAR5 encryption parameters from a file's encryption extra record (`0x01`) or archive encryption header (`HEAD_CRYPT`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar5CryptParams {
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    pub check: Option<([u8; 8], [u8; 4])>,
    pub tweaked_crc: bool,
}

/// What a RAR5 header or extra record keeps to test a password: PBKDF2 count, salt, and 8-byte check value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar5PasswordCheck {
    pub kdf_count: u8,
    pub salt: [u8; 16],
    pub check: [u8; 8],
}

impl Rar5PasswordCheck {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(25);
        out.push(self.kdf_count);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.check);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(Self {
            kdf_count: *b.first()?,
            salt: b.get(1..17)?.try_into().ok()?,
            check: b.get(17..25)?.try_into().ok()?,
        })
    }

    pub fn accepts(&self, password: &str) -> bool {
        if self.kdf_count > 24 {
            return false;
        }
        let keyed = HmacSha256Key::new(password.as_bytes());
        let mut salt_block = [0u8; 20];
        salt_block[..16].copy_from_slice(&self.salt);
        salt_block[16..20].copy_from_slice(&1u32.to_be_bytes());
        let mut u = keyed.mac_slice(&salt_block);
        let mut fn_acc = u;
        let iterations = 1u32 << self.kdf_count;
        for _ in 1..iterations.saturating_add(32) {
            u = keyed.mac_32(&u);
            for (slot, b) in fn_acc.iter_mut().zip(u) {
                *slot ^= b;
            }
        }
        let mut folded = [0u8; 8];
        for (i, b) in fn_acc.iter().enumerate() {
            folded[i % 8] ^= *b;
        }
        folded == self.check
    }
}

fn vint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut val = 0u64;
    for i in 0..10usize {
        let b = *data.get(pos + i)?;
        val |= u64::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 {
            return Some((val, pos + i + 1));
        }
    }
    None
}

/// Parses a RAR5 encryption record body (`HEAD_CRYPT` fields or `FHEXTRA_CRYPT` after its record-type vint).
pub fn rar5_record_params(record: &[u8]) -> Option<Rar5CryptParams> {
    let (version, p) = vint(record, 0)?;
    if version != 0 {
        return None;
    }
    let (flags, p) = vint(record, p)?;
    let kdf_count = *record.get(p)?;
    if kdf_count > 24 {
        return None;
    }
    let salt: [u8; 16] = record.get(p + 1..p + 17)?.try_into().ok()?;
    let mut at = p + 17;
    let mut iv = [0u8; 16];
    if record.len() >= at + 16 {
        iv.copy_from_slice(record.get(at..at + 16)?);
        at += 16;
    }
    let check = if flags & 0x0001 != 0 && record.len() >= at + 12 {
        let chk: [u8; 8] = record.get(at..at + 8)?.try_into().ok()?;
        let csum: [u8; 4] = record.get(at + 8..at + 12)?.try_into().ok()?;
        Some((chk, csum))
    } else {
        None
    };
    Some(Rar5CryptParams { kdf_count, salt, iv, check, tweaked_crc: flags & 0x0002 != 0 })
}

/// Derives the RAR5 32-byte AES-256 key and 32-byte `HashKey` (for tweaked CRC32) from `password`, `kdf_count`, and `salt`.
/// If `check` is `Some((chk, csum))` and `sha256(&chk)[..4] == csum`, verifies the password against `chk`.
pub fn derive_rar5_key_and_hash_key(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> Option<([u8; 32], [u8; 32])> {
    if kdf_count > 24 {
        return None;
    }
    let keyed = HmacSha256Key::new(password.as_bytes());
    let mut salt_block = [0u8; 20];
    salt_block[..16].copy_from_slice(salt);
    salt_block[16..20].copy_from_slice(&1u32.to_be_bytes());
    let mut u = keyed.mac_slice(&salt_block);
    let mut fn_acc = u;
    let iterations = 1u32 << kdf_count;
    for _ in 1..iterations {
        u = keyed.mac_32(&u);
        for (slot, b) in fn_acc.iter_mut().zip(u) {
            *slot ^= b;
        }
    }
    let key = fn_acc;
    for _ in 0..16 {
        u = keyed.mac_32(&u);
        for (slot, b) in fn_acc.iter_mut().zip(u) {
            *slot ^= b;
        }
    }
    let hash_key = fn_acc;
    if let Some((chk, csum)) = check {
        let digest = sha256(&chk);
        if digest.get(..4) == Some(csum.as_slice()) {
            for _ in 0..16 {
                u = keyed.mac_32(&u);
                for (slot, b) in fn_acc.iter_mut().zip(u) {
                    *slot ^= b;
                }
            }
            let mut folded = [0u8; 8];
            for (i, b) in fn_acc.iter().enumerate() {
                folded[i % 8] ^= *b;
            }
            if folded != chk {
                return None;
            }
        }
    }
    Some((key, hash_key))
}

/// Derives the RAR5 32-byte AES-256 key from `password`, `kdf_count`, and `salt`.
pub fn derive_rar5_key(
    password: &str,
    kdf_count: u8,
    salt: &[u8; 16],
    check: Option<([u8; 8], [u8; 4])>,
) -> Option<[u8; 32]> {
    derive_rar5_key_and_hash_key(password, kdf_count, salt, check).map(|(k, _)| k)
}

/// Computes the RAR5 tweaked CRC32 (`MAC` over the little-endian CRC32 using `hash_key`).
pub fn rar5_tweak_crc32(crc: u32, hash_key: &[u8; 32]) -> u32 {
    let keyed = HmacSha256Key::new(hash_key);
    let digest = keyed.mac_slice(&crc.to_le_bytes());
    let mut out = 0u32;
    for (i, &b) in digest.iter().enumerate() {
        out ^= u32::from(b) << ((i & 3) * 8);
    }
    out
}

/// Decrypts an encrypted RAR5 block header at `pos` (starts with 16-byte IV followed by AES-256-CBC blocks).
/// Returns `(decrypted_header_starting_at_crc, raw_encrypted_end_pos)` if the header CRC32 matches.
pub fn decrypt_rar5_header(data: &[u8], pos: usize, key: &[u8; 32]) -> Option<(Vec<u8>, usize)> {
    let iv: [u8; 16] = data.get(pos..pos.checked_add(16)?)?.try_into().ok()?;
    let ct_start = pos + 16;
    let first_block = data.get(ct_start..ct_start.checked_add(16)?)?;
    let first_dec = decrypt_cbc(key, &iv, first_block)?;
    let (hdr_size, size_after) = vint(&first_dec, 4)?;
    let hdr_size = usize::try_from(hdr_size).ok()?;
    if hdr_size == 0 || hdr_size > 2 * 1024 * 1024 {
        return None;
    }
    let plain_need = size_after.checked_add(hdr_size)?;
    let padded_len = plain_need.checked_next_multiple_of(16)?;
    let ct_end = ct_start.checked_add(padded_len)?;
    let ct = data.get(ct_start..ct_end)?;
    let dec = decrypt_cbc(key, &iv, ct)?;
    let stored_crc = u32::from_le_bytes(dec.get(..4)?.try_into().ok()?);
    let crc_slice = dec.get(4..plain_need)?;
    if crc32fast::hash(crc_slice) != stored_crc {
        return None;
    }
    Some((dec, ct_end))
}

// ---------------------------------------------------------------------------
// Pure-Rust SHA-1 + RAR 4.x (`SetKey30`) key/IV derivation & header decryption
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Sha1 {
    state: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476, 0xc3d2_e1f0],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u32; 5], chunk: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdcu32),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for b in blocks {
            Self::compress(&mut self.state, b);
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    fn finalize_words(&self) -> [u32; 5] {
        let mut state = self.state;
        let bit_len = self.total_len * 8;
        let mut tail = [0u8; 128];
        tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        tail[self.buf_len] = 0x80;
        if self.buf_len < 56 {
            tail[56..64].copy_from_slice(&bit_len.to_be_bytes());
            Self::compress(&mut state, tail[..64].try_into().unwrap());
        } else {
            tail[120..128].copy_from_slice(&bit_len.to_be_bytes());
            Self::compress(&mut state, tail[..64].try_into().unwrap());
            Self::compress(&mut state, tail[64..128].try_into().unwrap());
        }
        state
    }

    fn finalize_bytes(&self) -> [u8; 20] {
        let words = self.finalize_words();
        let mut out = [0u8; 20];
        for (i, &w) in words.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// Derives the RAR4 (`SetKey30`) 16-byte AES-128 key and 16-byte IV from `password` and `salt`.
pub fn derive_rar4_key_iv(password: &str, salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    let mut raw = Vec::with_capacity(password.len() * 2 + 8);
    for ch in password.encode_utf16() {
        raw.extend_from_slice(&ch.to_le_bytes());
    }
    raw.extend_from_slice(salt);

    const ROUNDS: u32 = 0x40000;
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..ROUNDS {
        sha.update(&raw);
        let idx = [i as u8, (i >> 8) as u8, (i >> 16) as u8];
        sha.update(&idx);
        if i % (ROUNDS / 16) == 0 {
            let words = sha.finalize_words();
            let pos = (i / (ROUNDS / 16)) as usize;
            if let Some(slot) = iv.get_mut(pos) {
                *slot = (words[4] & 0xff) as u8;
            }
        }
    }
    let words = sha.finalize_words();
    let mut key = [0u8; 16];
    for (i, &w) in words.iter().take(4).enumerate() {
        key[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    (key, iv)
}

/// Decrypts an encrypted RAR4 block header at `pos` (starts with 8-byte salt followed by AES-128-CBC blocks).
pub fn decrypt_rar4_header(data: &[u8], pos: usize, key: &[u8; 16], iv: &[u8; 16]) -> Option<(Vec<u8>, usize)> {
    let first_block = data.get(pos..pos.checked_add(16)?)?;
    let first_dec = decrypt_cbc(key, iv, first_block)?;
    let head_type = *first_dec.get(2)?;
    if !(0x72..=0x7b).contains(&head_type) {
        return None;
    }
    let head_size = usize::from(u16::from_le_bytes(first_dec.get(5..7)?.try_into().ok()?));
    if !(7..=65536).contains(&head_size) {
        return None;
    }
    let padded = head_size.checked_next_multiple_of(16)?;
    let ct_end = pos.checked_add(padded)?;
    let ct = data.get(pos..ct_end)?;
    let dec = decrypt_cbc(key, iv, ct)?;
    let stored_crc = u16::from_le_bytes(dec.get(0..2)?.try_into().ok()?);
    let calc_crc = (crc32fast::hash(dec.get(2..head_size)?) & 0xffff) as u16;
    if stored_crc != calc_crc {
        return None;
    }
    Some((dec, ct_end))
}

/// What a header-encrypted RAR4 (`-hp`) keeps at the start of its first encrypted block to test a password:
/// the 8-byte salt and the first 16-byte AES-128-CBC block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rar4HeaderCheck {
    pub salt: [u8; 8],
    pub block: [u8; 16],
}

impl Rar4HeaderCheck {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.block);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        Some(Self { salt: b.get(0..8)?.try_into().ok()?, block: b.get(8..24)?.try_into().ok()? })
    }

    pub fn accepts(&self, password: &str) -> bool {
        let (key, iv) = derive_rar4_key_iv(password, &self.salt);
        let Some(dec) = decrypt_cbc(&key, &iv, &self.block) else { return false };
        let Some(&head_type) = dec.get(2) else { return false };
        let Some(size_bytes) = dec.get(5..7) else { return false };
        let head_size = usize::from(u16::from_le_bytes([size_bytes[0], size_bytes[1]]));
        if !(0x74..=0x7b).contains(&head_type) || !(7..=16384).contains(&head_size) {
            return false;
        }
        if head_size <= 16 {
            let stored_crc = u16::from_le_bytes([dec[0], dec[1]]);
            let calc_crc = (crc32fast::hash(&dec[2..head_size]) & 0xffff) as u16;
            return stored_crc == calc_crc;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// ZIP Traditional Stream Cipher (ZipCrypto) & WinZip AES (`0x9901`)
// ---------------------------------------------------------------------------

fn crypto_keys(password: &[u8]) -> [u32; 3] {
    let mut keys = [0x1234_5678u32, 0x2345_6789, 0x3456_7890];
    for b in password {
        crypto_update(&mut keys, *b);
    }
    keys
}

fn crypto_update(keys: &mut [u32; 3], b: u8) {
    fn crc_byte(crc: u32, b: u8) -> u32 {
        let mut c = (crc ^ u32::from(b)) & 0xff;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 };
        }
        (crc >> 8) ^ c
    }
    keys[0] = crc_byte(keys[0], b);
    keys[1] = keys[1].wrapping_add(keys[0] & 0xff).wrapping_mul(134_775_813).wrapping_add(1);
    keys[2] = crc_byte(keys[2], (keys[1] >> 24) as u8);
}

fn crypto_step(keys: &mut [u32; 3], cipher: u8) -> u8 {
    let t = keys[2] | 2;
    let plain = cipher ^ (t.wrapping_mul(t ^ 1) >> 8) as u8;
    crypto_update(keys, plain);
    plain
}

/// Decrypts a ZipCrypto entry starting at `data` (12-byte encryption header + payload) if `check` matches.
pub fn decrypt_zipcrypto(password: &str, check: u8, data: &[u8]) -> Option<Vec<u8>> {
    let header = data.get(..12)?;
    let payload = data.get(12..)?;
    let mut keys = crypto_keys(password.as_bytes());
    let mut last = 0u8;
    for b in header {
        last = crypto_step(&mut keys, *b);
    }
    if last != check {
        return None;
    }
    let mut out = Vec::with_capacity(payload.len());
    for b in payload {
        out.push(crypto_step(&mut keys, *b));
    }
    Some(out)
}

fn hmac_sha1(ipad: &[u8; 64], opad: &[u8; 64], data: &[u8]) -> [u8; 20] {
    let mut inner = Sha1::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize_bytes();
    let mut outer = Sha1::new();
    outer.update(opad);
    outer.update(&inner_digest);
    outer.finalize_bytes()
}

/// PBKDF2-HMAC-SHA1 (1000 rounds) for WinZip AES: derives `2 * key_len + 2` bytes.
pub fn aes_derive(password: &[u8], salt: &[u8], key_len: usize) -> Option<Vec<u8>> {
    let mut k = [0u8; 64];
    if password.len() > 64 {
        let mut s = Sha1::new();
        s.update(password);
        k[..20].copy_from_slice(&s.finalize_bytes());
    } else {
        k[..password.len()].copy_from_slice(password);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let wanted = key_len * 2 + 2;
    let mut derived = Vec::with_capacity(wanted + 20);
    let mut block = 1u32;
    let mut salt_block = Vec::with_capacity(salt.len() + 4);
    while derived.len() < wanted {
        salt_block.clear();
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha1(&ipad, &opad, &salt_block);
        let mut out = u;
        for _ in 1..1000 {
            u = hmac_sha1(&ipad, &opad, &u);
            for (slot, b) in out.iter_mut().zip(u) {
                *slot ^= b;
            }
        }
        derived.extend_from_slice(&out);
        block += 1;
    }
    derived.truncate(wanted);
    Some(derived)
}

/// Decrypts a WinZip AES (method 99) entry starting at `data` (`salt + verifier + ciphertext [+ 10-byte auth]`).
pub fn decrypt_winzip_aes(password: &str, strength: u8, data: &[u8], full_packed: Option<u64>) -> Option<Vec<u8>> {
    if !(1..=3).contains(&strength) {
        return None;
    }
    let salt_len = usize::from(strength) * 4 + 4;
    let key_len = (usize::from(strength) + 1) * 8;
    let salt = data.get(..salt_len)?;
    let verifier = data.get(salt_len..salt_len + 2)?;
    let derived = aes_derive(password.as_bytes(), salt, key_len)?;
    if derived.get(key_len * 2..key_len * 2 + 2) != Some(verifier) {
        return None;
    }
    let key = derived.get(..key_len)?;
    let ct_end = match full_packed.and_then(|p| usize::try_from(p).ok()) {
        Some(p) if p >= salt_len + 12 => data.len().min(p - 10),
        _ => data.len(),
    };
    let ct = data.get(salt_len + 2..ct_end)?;
    decrypt_winzip_ctr(key, ct)
}

/// Parses WinZip AES extra field `0x9901`: `(strength, actual_method)`.
pub fn aes_extra(extra: &[u8]) -> Option<(u8, u16)> {
    let (strength, _, method) = aes_extra_info(extra)?;
    Some((strength, method))
}

/// Parses WinZip AES extra field `0x9901`: `(strength, vendor_version, actual_method)`.
pub fn aes_extra_info(extra: &[u8]) -> Option<(u8, u16, u16)> {
    let mut p = 0usize;
    while p + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[p], extra[p + 1]]);
        let size = u16::from_le_bytes([extra[p + 2], extra[p + 3]]) as usize;
        if id == 0x9901 && size >= 7 {
            let vendor = u16::from_le_bytes(extra.get(p + 4..p + 6)?.try_into().ok()?);
            let strength = extra.get(p + 8).copied().filter(|s| (1..=3).contains(s))?;
            let method = u16::from_le_bytes(extra.get(p + 9..p + 11)?.try_into().ok()?);
            return Some((strength, vendor, method));
        }
        p = p.checked_add(4 + size)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_197_and_cbc_round_trip() {
        let pt: [u8; 16] =
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let k256: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
            0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let c256: [u8; 16] =
            [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
        let aes = AesKey::new(&k256).unwrap();
        let enc = aes.encrypt_block(&pt);
        assert_eq!(enc, c256);
        assert_eq!(aes.decrypt_block(&enc), pt);

        let iv = [0x42u8; 16];
        let msg = b"0123456789abcdeffedcba9876543210";
        let ct = encrypt_cbc(&k256, &iv, msg).unwrap();
        assert_eq!(decrypt_cbc(&k256, &iv, &ct).unwrap(), msg);
    }
}
