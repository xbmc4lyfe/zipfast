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

//! Compressed streams: gzip, xz, zstd and bzip2, found by their magic bytes. Each wraps a tar archive or a single
//! file; the tar reader decides which.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use flate2::bufread::MultiGzDecoder;

pub(crate) const LZMA_MEMORY_LIMIT: u64 = 256 << 20;
const ZSTD_WINDOW_LOG_LIMIT: u32 = 27;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Gzip,
    Xz,
    Zstd,
    Bzip2,
}

impl Codec {
    /// The codec a file starts with, if any.
    pub fn sniff(head: &[u8]) -> Option<Codec> {
        if head.starts_with(&[0x1f, 0x8b, 8]) {
            Some(Codec::Gzip)
        } else if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
            Some(Codec::Xz)
        } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])
            // a skippable frame (magic 0x184D2A50 to 0x184D2A5F) may come before the first compressed one
            || (head.len() >= 4 && head[0] & 0xf0 == 0x50 && head[1..4] == [0x2a, 0x4d, 0x18])
        {
            Some(Codec::Zstd)
        } else if head.len() >= 4 && head.starts_with(b"BZh") && (b'1'..=b'9').contains(&head[3]) {
            Some(Codec::Bzip2)
        } else {
            None
        }
    }

    /// File name endings for this codec, longest first, and what each leaves behind: `.tgz` stands for `.tar.gz`.
    pub fn endings(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Codec::Gzip => &[(".tgz", ".tar"), (".taz", ".tar"), (".gzip", ""), (".gz", ""), (".z", "")],
            Codec::Xz => &[(".txz", ".tar"), (".xz", "")],
            Codec::Zstd => &[(".tzst", ".tar"), (".zstd", ""), (".zst", "")],
            Codec::Bzip2 => &[(".tbz2", ".tar"), (".tbz", ".tar"), (".bzip2", ""), (".bz2", ""), (".bz", "")],
        }
    }

    /// A reader of the decompressed data. Concatenated streams or members read as one. `threads` is how many
    /// threads xz may decode with, for files that were compressed in independent blocks.
    pub fn open(self, r: BufReader<File>, threads: usize) -> io::Result<Box<dyn Read>> {
        self.open_reader(r, threads)
    }

    pub(crate) fn open_reader(self, r: impl BufRead + 'static, threads: usize) -> io::Result<Box<dyn Read>> {
        Ok(match self {
            Codec::Gzip => Box::new(MultiGzDecoder::new(r)),
            Codec::Xz => Box::new(XzStreams { inner: Some(xz_decoder(r, threads)?), threads }),
            Codec::Zstd => Box::new(zstd_decoder(r)?),
            Codec::Bzip2 => Box::new(bzip2::bufread::MultiBzDecoder::new(r)),
        })
    }
}

pub(crate) fn zstd_decoder<R: BufRead>(reader: R) -> io::Result<zstd::stream::read::Decoder<'static, R>> {
    let mut decoder = zstd::stream::read::Decoder::with_buffer(reader)?;
    decoder.window_log_max(ZSTD_WINDOW_LOG_LIMIT)?;
    Ok(decoder)
}

fn xz_decoder<R: BufRead>(r: R, threads: usize) -> io::Result<liblzma::bufread::XzDecoder<R>> {
    let stream = liblzma::stream::MtStreamBuilder::new()
        .threads(threads.clamp(1, 64) as u32)
        // past this much memory liblzma falls back to one thread rather than failing
        .memlimit_threading(LZMA_MEMORY_LIMIT)
        .memlimit_stop(LZMA_MEMORY_LIMIT)
        .decoder()
        .map_err(io::Error::other)?;
    Ok(liblzma::bufread::XzDecoder::new_stream(r, stream))
}

/// xz streams back to back, as `xz` itself reads them: the decoder stops at the end of each stream, so a new one
/// takes over after any stream padding, which is zero bytes in fours.
struct XzStreams<R: BufRead> {
    inner: Option<liblzma::bufread::XzDecoder<R>>,
    threads: usize,
}

impl<R: BufRead> Read for XzStreams<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(dec) = self.inner.as_mut() else { return Ok(0) };
            let n = dec.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            let mut r = self.inner.take().map(|d| d.into_inner()).expect("decoder is there");
            let mut zeros = 0usize;
            loop {
                let avail = r.fill_buf()?;
                if avail.is_empty() {
                    break;
                }
                let run = avail.iter().take_while(|&&b| b == 0).count();
                zeros += run;
                let all = run == avail.len();
                r.consume(run);
                if !all {
                    break;
                }
            }
            if !zeros.is_multiple_of(4) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "xz stream padding is malformed"));
            }
            if r.fill_buf()?.is_empty() {
                return Ok(0);
            }
            self.inner = Some(xz_decoder(r, self.threads)?);
        }
    }
}

/// The file name stored in a gzip header (RFC 1952's FNAME field), if there is one. The header is read field by
/// field, so an extra field of any size before the name is passed over.
pub fn gzip_name(path: &Path) -> Option<String> {
    let mut r = BufReader::new(File::open(path).ok()?);
    let mut fixed = [0u8; 10];
    r.read_exact(&mut fixed).ok()?;
    let flags = fixed[3];
    if flags & 0x04 != 0 {
        let mut len = [0u8; 2];
        r.read_exact(&mut len).ok()?;
        let len = u16::from_le_bytes(len) as u64;
        if io::copy(&mut r.by_ref().take(len), &mut io::sink()).ok()? != len {
            return None;
        }
    }
    if flags & 0x08 == 0 {
        return None;
    }
    let mut name = Vec::new();
    // a name runs to a NUL; one longer than any real file name is not taken
    r.take(64 << 10).read_until(0, &mut name).ok()?;
    if name.pop() != Some(0) {
        return None;
    }
    // ISO 8859-1 by the RFC; UTF-8 in practice
    Some(match std::str::from_utf8(&name) {
        Ok(s) => s.to_string(),
        Err(_) => name.iter().map(|&b| b as char).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic() {
        assert_eq!(Codec::sniff(&[0x1f, 0x8b, 8, 0]), Some(Codec::Gzip));
        assert_eq!(Codec::sniff(b"\xfd7zXZ\0\0"), Some(Codec::Xz));
        assert_eq!(Codec::sniff(&[0x28, 0xb5, 0x2f, 0xfd, 0]), Some(Codec::Zstd));
        assert_eq!(Codec::sniff(&[0x5a, 0x2a, 0x4d, 0x18, 0]), Some(Codec::Zstd));
        assert_eq!(Codec::sniff(&[0x60, 0x2a, 0x4d, 0x18, 0]), None);
        assert_eq!(Codec::sniff(b"BZh91AY"), Some(Codec::Bzip2));
        assert_eq!(Codec::sniff(b"BZh0"), None);
        assert_eq!(Codec::sniff(b"Rar!\x1a\x07"), None);
    }
}
