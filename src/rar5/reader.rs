//! Walks one RAR 5.0 volume block by block.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};

use crate::batch::read_at;

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

/// Bytes read from a volume at a time. Headers and the data of small files after them come in together, so a
/// run of small files takes one read for several of them.
const READ: usize = 1 << 20;

/// Pieces read ahead of the one in use, once the volume is read straight through.
const AHEAD: usize = 2;

/// A move forward by up to this much past what is read reads on through; a longer one starts again at the place.
const SKIP_MAX: u64 = 2 * READ as u64;

/// A volume read in pieces of [`READ`] bytes. Read straight through, the pieces come from a thread of its own
/// that keeps [`AHEAD`] of them ready, so the reading is off the caller's thread. All reads are by position, so
/// nothing depends on where the file stands.
struct Source {
    file: File,
    len: u64,
    /// the piece in use, which starts at `at` in the file; `off` of it is used up
    piece: Vec<u8>,
    at: u64,
    off: usize,
    /// set while pieces are read in order, so the next one can come from the thread
    sequential: bool,
    ahead: Option<Ahead>,
}

/// The thread reading ahead, and where the next piece it sends starts.
struct Ahead {
    pieces: Receiver<Result<Vec<u8>>>,
    spare: Sender<Vec<u8>>,
    next: u64,
}

impl Ahead {
    fn start(file: &File, from: u64, len: u64) -> Result<Ahead> {
        let file = file.try_clone()?;
        let (send, pieces) = sync_channel::<Result<Vec<u8>>>(AHEAD);
        let (spare, spares) = channel::<Vec<u8>>();
        std::thread::Builder::new()
            .name("rar5-read".into())
            .spawn(move || read_ahead(&file, from, len, &send, &spares))?;
        Ok(Ahead { pieces, spare, next: from })
    }
}

/// Reads pieces from `at` to `len` in order and sends them, until the receiver goes away.
fn read_ahead(file: &File, mut at: u64, len: u64, send: &SyncSender<Result<Vec<u8>>>, spares: &Receiver<Vec<u8>>) {
    while at < len {
        let n = (len - at).min(READ as u64) as usize;
        let mut buf = spares.try_recv().unwrap_or_default();
        buf.resize(n, 0);
        let read = read_at(file, &mut buf, at).map(|()| buf);
        let failed = read.is_err();
        if send.send(read).is_err() || failed {
            return;
        }
        at += n as u64;
    }
}

impl Source {
    fn new(file: File, len: u64) -> Source {
        Source { file, len, piece: Vec::new(), at: 0, off: 0, sequential: false, ahead: None }
    }

    /// What is left of the piece in use.
    fn held(&self) -> &[u8] {
        &self.piece[self.off..]
    }

    fn consume(&mut self, n: usize) {
        self.off += n;
    }

    /// Moves to `at`.
    fn seek(&mut self, at: u64) {
        let end = self.at + self.piece.len() as u64;
        if (self.at..=end).contains(&at) {
            self.off = (at - self.at) as usize;
        } else if at > end && at - end <= SKIP_MAX {
            // close ahead: read on to it, so a run of small blocks keeps its pieces coming
            self.at = end;
            self.piece.clear();
            self.off = (at - end) as usize;
        } else {
            self.ahead = None;
            self.sequential = false;
            self.at = at;
            self.piece.clear();
            self.off = 0;
        }
    }

    /// Makes sure the piece in use has bytes left, unless the file ends. False at the end of the file.
    fn fill(&mut self) -> Result<bool> {
        while self.off >= self.piece.len() {
            let skip = self.off - self.piece.len();
            let from = self.at + self.piece.len() as u64;
            if from >= self.len {
                return Ok(false);
            }
            let used = std::mem::take(&mut self.piece);
            if self.ahead.as_ref().is_some_and(|a| a.next != from) {
                self.ahead = None;
            }
            if self.ahead.is_none() && self.sequential {
                self.ahead = Some(Ahead::start(&self.file, from, self.len)?);
            }
            self.piece = match self.ahead.as_mut() {
                Some(a) => {
                    if used.capacity() > 0 {
                        // the thread fills it again rather than making a new one
                        let _ = a.spare.send(used);
                    }
                    let piece = a.pieces.recv().map_err(|_| Error::Truncated)??;
                    a.next += piece.len() as u64;
                    piece
                }
                None => {
                    // the first piece after a move is read here; read on past it, and the thread takes over
                    let mut buf = used;
                    buf.resize((self.len - from).min(READ as u64) as usize, 0);
                    read_at(&self.file, &mut buf, from)?;
                    self.sequential = true;
                    buf
                }
            };
            self.at = from;
            self.off = skip;
        }
        Ok(true)
    }
}

pub struct Volume {
    pub path: PathBuf,
    src: Source,
    /// where the next block starts
    next: u64,
    len: u64,
    pub main: MainHeader,
}

/// Finds the signature within the first [`MAX_SFX`] bytes. Returns the offset just past it.
fn find_signature(file: &File, len: u64) -> Result<u64> {
    let mut head = vec![0u8; len.min(MAX_SFX + SIGNATURE.len() as u64) as usize];
    read_at(file, &mut head, 0)?;
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
        let next = find_signature(&file, len)?;
        let mut vol =
            Volume { path: path.to_path_buf(), src: Source::new(file, len), next, len, main: MainHeader::default() };
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
        self.seek(self.next)?;
        let start = self.next;
        let mut crc_bytes = [0u8; 4];
        self.read_exact(&mut crc_bytes)?;
        let stored_crc = u32::from_le_bytes(crc_bytes);
        // the size field is a vint of at most 3 bytes
        let mut size_field = Vec::with_capacity(3);
        let mut size = 0u64;
        for i in 0..3 {
            let mut b = [0u8; 1];
            self.read_exact(&mut b)?;
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
        self.read_exact(&mut body)?;
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
        // checked here, not only when the data is read, since skipped blocks are never read
        if data_end > self.len {
            return Err(Error::Truncated);
        }
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

    /// The open volume, for reads by position.
    pub fn file(&mut self) -> &File {
        &self.src.file
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.len
    }

    fn seek(&mut self, at: u64) -> Result<()> {
        self.src.seek(at);
        Ok(())
    }

    fn read_exact(&mut self, mut out: &mut [u8]) -> Result<()> {
        while !out.is_empty() {
            if !self.src.fill()? {
                return Err(Error::Truncated);
            }
            let held = self.src.held();
            let n = held.len().min(out.len());
            out[..n].copy_from_slice(&held[..n]);
            self.src.consume(n);
            out = &mut out[n..];
        }
        Ok(())
    }

    /// `len` bytes at `at`, appended to `out`.
    pub fn read_data_into(&mut self, at: u64, len: u64, out: &mut Vec<u8>) -> Result<()> {
        if at.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(Error::Truncated);
        }
        out.reserve(len as usize);
        self.read_data(at, len, |piece| {
            out.extend_from_slice(piece);
            Ok(())
        })
    }

    /// Reads `len` bytes of a data area starting at `at`, in pieces, calling `sink` on each.
    pub fn read_data(&mut self, at: u64, len: u64, mut sink: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if at.checked_add(len).is_none_or(|end| end > self.len) {
            return Err(Error::Truncated);
        }
        self.seek(at)?;
        let mut left = len;
        while left > 0 {
            if !self.src.fill()? {
                return Err(Error::Truncated);
            }
            let held = self.src.held();
            let n = (held.len() as u64).min(left) as usize;
            let result = sink(&held[..n]);
            self.src.consume(n);
            result?;
            left -= n as u64;
        }
        Ok(())
    }
}
