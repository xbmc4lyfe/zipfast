//! RAR 5.0 archive blocks, read from the published archive layout: the signature, the main header, file and service
//! headers with their extra records, and the end of archive header.

pub mod reader;

use crate::error::{Error, Result};

pub const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
/// The older format's signature, recognised only to say it isn't this one.
pub const SIGNATURE_V4: &[u8; 7] = b"Rar!\x1a\x07\x00";
/// How far into a file a self-extracting module may push the signature.
pub const MAX_SFX: u64 = 1 << 20;
/// A header size field is at most 3 bytes long, so a header is under 2 MiB.
pub const MAX_HEADER: u64 = 1 << 21;

pub const HEAD_MAIN: u64 = 1;
pub const HEAD_FILE: u64 = 2;
pub const HEAD_SERVICE: u64 = 3;
pub const HEAD_CRYPT: u64 = 4;
pub const HEAD_END: u64 = 5;

pub const HFL_EXTRA: u64 = 0x0001;
pub const HFL_DATA: u64 = 0x0002;
pub const HFL_SPLIT_BEFORE: u64 = 0x0008;
pub const HFL_SPLIT_AFTER: u64 = 0x0010;

pub const MHFL_VOLUME: u64 = 0x0001;
pub const MHFL_VOLNUMBER: u64 = 0x0002;
pub const MHFL_SOLID: u64 = 0x0004;

pub const FHFL_DIRECTORY: u64 = 0x0001;
pub const FHFL_UTIME: u64 = 0x0002;
pub const FHFL_CRC32: u64 = 0x0004;
pub const FHFL_UNPUNKNOWN: u64 = 0x0008;

pub const EOAFL_MORE_VOLUMES: u64 = 0x0001;

pub const FHEXTRA_CRYPT: u64 = 0x01;
pub const FHEXTRA_HASH: u64 = 0x02;
pub const FHEXTRA_HTIME: u64 = 0x03;
pub const FHEXTRA_VERSION: u64 = 0x04;
pub const FHEXTRA_REDIR: u64 = 0x05;

/// A cursor over one header's bytes. Every read is checked; running off the end is corruption, since the header's
/// own size said the bytes were there.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or(Error::Corrupt("header field"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }

    /// Seven bits per byte, low bits first, high bit set while more follow. Ten bytes at most.
    pub fn vint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for i in 0..10 {
            let b = self.u8()?;
            let bits = u64::from(b & 0x7f);
            if i == 9 && b > 1 {
                return Err(Error::Corrupt("variable length integer overflows 64 bits"));
            }
            value |= bits << (7 * i);
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Error::Corrupt("variable length integer too long"))
    }

    pub fn vsize(&mut self) -> Result<usize> {
        usize::try_from(self.vint()?).map_err(|_| Error::Corrupt("size too large"))
    }
}

/// The fields shared by every block, and where the block's data area sits in its volume.
#[derive(Clone, Debug)]
pub struct BlockHead {
    pub kind: u64,
    pub flags: u64,
    pub data_size: u64,
    /// absolute offset of the data area in the volume
    pub data_at: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MainHeader {
    pub flags: u64,
    pub volume_number: u64,
}

impl MainHeader {
    pub fn is_volume(&self) -> bool {
        self.flags & MHFL_VOLUME != 0
    }

    pub fn is_solid(&self) -> bool {
        self.flags & MHFL_SOLID != 0
    }
}

/// How a file system object is to be recreated other than as a regular file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redirection {
    UnixSymlink(String),
    WindowsSymlink(String),
    Junction(String),
    HardLink(String),
    FileCopy(String),
    Unknown(u64),
}

/// A file or service header.
#[derive(Clone, Debug, Default)]
pub struct FileHeader {
    pub service: bool,
    pub block_flags: u64,
    pub file_flags: u64,
    pub packed_size: u64,
    pub data_at: u64,
    pub unpacked_size: u64,
    pub attributes: u64,
    /// seconds since 1970, from the header or the high precision time record
    pub mtime: Option<i64>,
    pub mtime_nanos: u32,
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    /// 0 for RAR 5.0's algorithm, 1 for RAR 7.0's
    pub algorithm: u8,
    pub solid: bool,
    /// 0 is stored, 1 to 5 are compression levels
    pub method: u8,
    /// bytes of history the decoder must keep
    pub dictionary: u64,
    pub host_os: u64,
    pub name: String,
    pub encrypted: bool,
    pub redirection: Option<Redirection>,
    /// set on an older revision of a file kept alongside the current one
    pub version: Option<u64>,
}

impl FileHeader {
    pub fn is_dir(&self) -> bool {
        self.file_flags & FHFL_DIRECTORY != 0
    }

    pub fn split_before(&self) -> bool {
        self.block_flags & HFL_SPLIT_BEFORE != 0
    }

    pub fn split_after(&self) -> bool {
        self.block_flags & HFL_SPLIT_AFTER != 0
    }

    pub fn size_unknown(&self) -> bool {
        self.file_flags & FHFL_UNPUNKNOWN != 0
    }

    pub fn is_unix(&self) -> bool {
        self.host_os == 1
    }
}

/// The body of a file or service header, from the file flags on. `extra` is the extra area, if any.
pub fn parse_file(head: &BlockHead, body: &[u8], extra: &[u8]) -> Result<FileHeader> {
    let mut c = Cursor::new(body);
    let mut f = FileHeader {
        service: head.kind == HEAD_SERVICE,
        block_flags: head.flags,
        packed_size: head.data_size,
        data_at: head.data_at,
        ..FileHeader::default()
    };
    f.file_flags = c.vint()?;
    f.unpacked_size = c.vint()?;
    f.attributes = c.vint()?;
    if f.file_flags & FHFL_UTIME != 0 {
        f.mtime = Some(i64::from(c.u32()?));
    }
    if f.file_flags & FHFL_CRC32 != 0 {
        f.crc32 = Some(c.u32()?);
    }
    let info = c.vint()?;
    f.algorithm = (info & 0x3f) as u8;
    f.solid = info & 0x40 != 0;
    f.method = ((info >> 7) & 7) as u8;
    let power = (info >> 10) & 0x1f;
    let mut dictionary = (128u64 * 1024).checked_shl(power as u32).unwrap_or(u64::MAX);
    if f.algorithm == 1 {
        let fraction = (info >> 15) & 0x1f;
        dictionary = dictionary.saturating_add(dictionary / 32 * fraction);
        if info & 0x10_0000 != 0 {
            // dictionary sized for the newer algorithm, data packed with the older one
            f.algorithm = 0;
        }
    }
    f.dictionary = dictionary;
    f.host_os = c.vint()?;
    let name_len = c.vsize()?;
    f.name = String::from_utf8_lossy(c.bytes(name_len)?).into_owned();
    parse_file_extra(&mut f, extra)?;
    Ok(f)
}

fn parse_file_extra(f: &mut FileHeader, extra: &[u8]) -> Result<()> {
    let mut c = Cursor::new(extra);
    while c.remaining() > 0 {
        let size = c.vsize()?;
        let record = c.bytes(size)?;
        let mut r = Cursor::new(record);
        let kind = r.vint()?;
        match kind {
            FHEXTRA_CRYPT => f.encrypted = true,
            FHEXTRA_HASH => {
                if r.vint()? == 0 {
                    f.blake2sp = Some(r.bytes(32)?.try_into().unwrap());
                }
            }
            FHEXTRA_HTIME => parse_htime(f, &mut r)?,
            FHEXTRA_VERSION => {
                let _flags = r.vint()?;
                f.version = Some(r.vint()?);
            }
            FHEXTRA_REDIR => {
                let kind = r.vint()?;
                let _flags = r.vint()?;
                let len = r.vsize()?;
                let target = String::from_utf8_lossy(r.bytes(len)?).into_owned();
                f.redirection = Some(match kind {
                    1 => Redirection::UnixSymlink(target),
                    2 => Redirection::WindowsSymlink(target),
                    3 => Redirection::Junction(target),
                    4 => Redirection::HardLink(target),
                    5 => Redirection::FileCopy(target),
                    other => Redirection::Unknown(other),
                });
            }
            // version, owner, service data and anything newer are skipped
            _ => {}
        }
    }
    Ok(())
}

/// Windows FILETIME is 100 ns ticks since 1601.
const FILETIME_TO_UNIX: i64 = 11_644_473_600;

fn parse_htime(f: &mut FileHeader, r: &mut Cursor<'_>) -> Result<()> {
    let flags = r.vint()?;
    let unix = flags & 1 != 0;
    let read = |r: &mut Cursor<'_>| -> Result<(i64, u32)> {
        if unix {
            Ok((i64::from(r.u32()?), 0))
        } else {
            let ticks = r.u64()?;
            let secs = (ticks / 10_000_000) as i64 - FILETIME_TO_UNIX;
            Ok((secs, ((ticks % 10_000_000) * 100) as u32))
        }
    };
    let mtime = if flags & 2 != 0 { Some(read(r)?) } else { None };
    if flags & 4 != 0 {
        read(r)?;
    }
    if flags & 8 != 0 {
        read(r)?;
    }
    if let Some((secs, nanos)) = mtime {
        f.mtime = Some(secs);
        f.mtime_nanos = nanos;
        if unix && flags & 0x10 != 0 {
            f.mtime_nanos = r.u32()?.min(999_999_999);
        }
    }
    Ok(())
}
