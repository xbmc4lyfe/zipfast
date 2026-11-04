//! Compressed streams: gzip, xz, zstd and bzip2, found by their magic bytes. Each wraps a tar archive or a single
//! file; the tar reader decides which.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use flate2::bufread::MultiGzDecoder;

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
        } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
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
        Ok(match self {
            Codec::Gzip => Box::new(MultiGzDecoder::new(r)),
            Codec::Xz => Box::new(XzStreams { inner: Some(xz_decoder(r, threads)?), threads }),
            Codec::Zstd => Box::new(zstd::stream::read::Decoder::with_buffer(r)?),
            Codec::Bzip2 => Box::new(bzip2::bufread::MultiBzDecoder::new(r)),
        })
    }
}

fn xz_decoder(r: BufReader<File>, threads: usize) -> io::Result<liblzma::bufread::XzDecoder<BufReader<File>>> {
    let stream = liblzma::stream::MtStreamBuilder::new()
        .threads(threads.clamp(1, 64) as u32)
        // past this much memory liblzma falls back to one thread rather than failing
        .memlimit_threading(1 << 30)
        .memlimit_stop(u64::MAX)
        .decoder()
        .map_err(io::Error::other)?;
    Ok(liblzma::bufread::XzDecoder::new_stream(r, stream))
}

/// xz streams back to back, as `xz` itself reads them: the decoder stops at the end of each stream, so a new one
/// takes over after any stream padding, which is zero bytes in fours.
struct XzStreams {
    inner: Option<liblzma::bufread::XzDecoder<BufReader<File>>>,
    threads: usize,
}

impl Read for XzStreams {
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

/// The file name stored in a gzip header (RFC 1952's FNAME field), if there is one.
pub fn gzip_name(path: &Path) -> Option<String> {
    let mut head = vec![0u8; 64 << 10];
    let n = File::open(path).ok()?.read(&mut head).ok()?;
    let h = &head[..n];
    let flags = *h.get(3)?;
    let mut at = 10;
    if flags & 0x04 != 0 {
        let len = u16::from_le_bytes([*h.get(at)?, *h.get(at + 1)?]) as usize;
        at += 2 + len;
    }
    if flags & 0x08 == 0 {
        return None;
    }
    let rest = h.get(at..)?;
    let end = rest.iter().position(|&b| b == 0)?;
    // ISO 8859-1 by the RFC; UTF-8 in practice
    Some(match std::str::from_utf8(&rest[..end]) {
        Ok(s) => s.to_string(),
        Err(_) => rest[..end].iter().map(|&b| b as char).collect(),
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
        assert_eq!(Codec::sniff(b"BZh91AY"), Some(Codec::Bzip2));
        assert_eq!(Codec::sniff(b"BZh0"), None);
        assert_eq!(Codec::sniff(b"Rar!\x1a\x07"), None);
    }
}
