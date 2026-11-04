//! Walks one RAR 5.0 volume block by block.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::*;
use crate::error::{Error, Result};

pub enum Block {
    Main(MainHeader),
    File(FileHeader),
    Service(FileHeader),
    End {
        more_volumes: bool,
    },
    /// Headers from here on are encrypted.
    Crypt,
    Unknown,
}

pub struct Volume {
    pub path: PathBuf,
    file: BufReader<File>,
    /// where the next block starts
    next: u64,
    len: u64,
    pub main: MainHeader,
}

/// Finds the signature within the first [`MAX_SFX`] bytes. Returns the offset just past it.
fn find_signature(file: &mut BufReader<File>) -> Result<u64> {
    let mut head = Vec::with_capacity(4096);
    file.by_ref().take(MAX_SFX + SIGNATURE.len() as u64).read_to_end(&mut head)?;
    if head.starts_with(SIGNATURE) {
        return Ok(SIGNATURE.len() as u64);
    }
    if head.starts_with(SIGNATURE_V4) {
        return Err(Error::Unsupported("RAR 4.x archive".into()));
    }
    head.windows(SIGNATURE.len())
        .position(|w| w == SIGNATURE)
        .map(|at| (at + SIGNATURE.len()) as u64)
        .ok_or(Error::NotAnArchive)
}

impl Volume {
    pub fn open(path: &Path) -> Result<Volume> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut file = BufReader::with_capacity(64 * 1024, file);
        let next = find_signature(&mut file)?;
        let mut vol = Volume { path: path.to_path_buf(), file, next, len, main: MainHeader::default() };
        match vol.next_block()? {
            Some(Block::Main(m)) => vol.main = m,
            Some(Block::Crypt) => return Err(Error::Encrypted),
            _ => return Err(Error::Corrupt("main archive header missing")),
        }
        Ok(vol)
    }

    /// The next block, or None at the physical end of the volume.
    pub fn next_block(&mut self) -> Result<Option<Block>> {
        if self.next >= self.len {
            return Ok(None);
        }
        self.file.seek(SeekFrom::Start(self.next))?;
        let start = self.next;
        let mut crc_bytes = [0u8; 4];
        self.file.read_exact(&mut crc_bytes)?;
        let stored_crc = u32::from_le_bytes(crc_bytes);
        // the size field is a vint of at most 3 bytes
        let mut size_field = Vec::with_capacity(3);
        let mut size = 0u64;
        for i in 0..3 {
            let mut b = [0u8; 1];
            self.file.read_exact(&mut b)?;
            size_field.push(b[0]);
            size |= u64::from(b[0] & 0x7f) << (7 * i);
            if b[0] & 0x80 == 0 {
                break;
            }
            if i == 2 {
                return Err(Error::Corrupt("header size field too long"));
            }
        }
        if size == 0 || size > MAX_HEADER {
            return Err(Error::Corrupt("header size"));
        }
        let header_end = start + 4 + size_field.len() as u64 + size;
        if header_end > self.len {
            return Err(Error::Truncated);
        }
        let mut body = vec![0u8; size as usize];
        self.file.read_exact(&mut body)?;
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&size_field);
        hasher.update(&body);
        if hasher.finalize() != stored_crc {
            return Err(Error::Corrupt("header checksum mismatch"));
        }

        let mut c = Cursor::new(&body);
        let kind = c.vint()?;
        let flags = c.vint()?;
        let extra_size = if flags & HFL_EXTRA != 0 { c.vsize()? } else { 0 };
        let data_size = if flags & HFL_DATA != 0 { c.vint()? } else { 0 };
        let fields_end = body.len().checked_sub(extra_size).filter(|&e| e >= c.pos());
        let Some(fields_end) = fields_end else { return Err(Error::Corrupt("extra area size")) };
        let fields = &body[c.pos()..fields_end];
        let extra = &body[fields_end..];
        let data_end = header_end.checked_add(data_size).ok_or(Error::Corrupt("data size"))?;
        self.next = data_end;
        let head = BlockHead { kind, flags, data_size, data_at: header_end };

        Ok(Some(match kind {
            HEAD_MAIN => {
                let mut f = Cursor::new(fields);
                let flags = f.vint()?;
                let volume_number = if flags & MHFL_VOLNUMBER != 0 { f.vint()? } else { 0 };
                Block::Main(MainHeader { flags, volume_number })
            }
            HEAD_FILE => Block::File(parse_file(&head, fields, extra)?),
            HEAD_SERVICE => Block::Service(parse_file(&head, fields, extra)?),
            HEAD_CRYPT => Block::Crypt,
            HEAD_END => {
                let mut f = Cursor::new(fields);
                let flags = f.vint().unwrap_or(0);
                self.next = self.len;
                Block::End { more_volumes: flags & EOAFL_MORE_VOLUMES != 0 }
            }
            _ => Block::Unknown,
        }))
    }

    /// Reads `len` bytes of a data area starting at `at` into `out`, in pieces, calling `sink` on each.
    pub fn read_data(
        &mut self,
        at: u64,
        len: u64,
        buf: &mut [u8],
        mut sink: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        if at.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(Error::Truncated);
        }
        self.file.seek(SeekFrom::Start(at))?;
        let mut left = len;
        while left > 0 {
            let n = (buf.len() as u64).min(left) as usize;
            self.file.read_exact(&mut buf[..n])?;
            sink(&buf[..n])?;
            left -= n as u64;
        }
        Ok(())
    }
}
