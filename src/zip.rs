//! ZIP archives, read from PKWARE's published APPNOTE: the end of central directory record (and its ZIP64 form),
//! the central directory, and each entry's local header. Entries are stored or deflated.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{Error, Result};
use crate::extract::{Entry, Meta, Mode, Options, Summary, Target, finish_dirs, finish_file, make_dirs, open_target};
use crate::output::Output;
use crate::path::sanitize;
use crate::rar5::Redirection;

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_END: u32 = 0x0605_4b50;
const SIG_END64: u32 = 0x0606_4b50;
const SIG_END64_LOCATOR: u32 = 0x0706_4b50;

const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_UTF8: u16 = 0x0800;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

const HOST_UNIX: u8 = 3;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

const BUF: usize = 1 << 20;

/// Whether the file starts the way a ZIP archive does.
pub fn sniff(head: &[u8]) -> bool {
    head.len() >= 4 && head[..2] == *b"PK" && matches!(head[2..4], [3, 4] | [5, 6] | [7, 8])
}

/// One central directory entry.
#[derive(Clone, Debug, Default)]
pub struct ZipEntry {
    pub name: String,
    pub flags: u16,
    pub method: u16,
    pub host: u8,
    pub crc32: u32,
    pub packed: u64,
    pub size: u64,
    pub local_at: u64,
    pub external: u32,
    pub mtime: Option<i64>,
    pub nanos: u32,
}

impl ZipEntry {
    pub fn unix_mode(&self) -> Option<u32> {
        (self.host == HOST_UNIX && self.external >> 16 != 0).then_some(self.external >> 16)
    }

    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
            || self.unix_mode().is_some_and(|m| m & S_IFMT == S_IFDIR)
            || (self.host != HOST_UNIX && self.external & 0x10 != 0)
    }

    pub fn is_link(&self) -> bool {
        self.unix_mode().is_some_and(|m| m & S_IFMT == S_IFLNK)
    }

    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0 || self.method == 99
    }

    fn meta(&self) -> Meta {
        Meta { mtime: self.mtime, nanos: self.nanos, mode: self.unix_mode() }
    }
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn read_at(file: &mut File, at: u64, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(at))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// An open archive: the file and its central directory.
pub struct Archive {
    file: File,
    len: u64,
    pub entries: Vec<ZipEntry>,
}

impl Archive {
    pub fn open(path: &Path) -> Result<Archive> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        // the end record is 22 bytes plus a comment of at most 65535
        let tail_len = len.min(22 + 65535);
        let tail = read_at(&mut file, len - tail_len, tail_len as usize)?;
        // the real end record's comment runs exactly to the end of the file; one whose comment would stop short
        // is more likely a signature inside a comment, so it is only a fallback, for files with bytes appended
        let candidates = || (0..tail.len().saturating_sub(21)).rev().filter(|&i| le32(&tail, i) == SIG_END);
        let end = candidates()
            .find(|&i| i + 22 + le16(&tail, i + 20) as usize == tail.len())
            .or_else(|| candidates().find(|&i| i + 22 + le16(&tail, i + 20) as usize <= tail.len()))
            .ok_or(Error::NotAnArchive)?;
        let end_at = len - tail_len + end as u64;
        let e = &tail[end..end + 22];
        let (disk, cd_disk) = (le16(e, 4), le16(e, 6));
        let mut count = u64::from(le16(e, 10));
        let mut cd_size = u64::from(le32(e, 12));
        let mut cd_at = u64::from(le32(e, 16));
        let mut cd_end = end_at;
        let mut multi_disk = disk != 0 || cd_disk != 0;
        if end_at >= 20 {
            let loc = read_at(&mut file, end_at - 20, 20)?;
            if le32(&loc, 0) == SIG_END64_LOCATOR {
                let stored_at = le64(&loc, 8);
                multi_disk |= le32(&loc, 16) > 1;
                // the stored offset, or, behind a self-extracting stub, where a plain 56-byte record would sit
                let mut rec = None;
                for at in [Some(stored_at), (end_at - 20).checked_sub(56)].into_iter().flatten() {
                    if at.checked_add(56).is_some_and(|e| e <= end_at - 20) {
                        let r = read_at(&mut file, at, 56)?;
                        if le32(&r, 0) == SIG_END64 {
                            rec = Some((at, r));
                            break;
                        }
                    }
                }
                let Some((rec_at, rec)) = rec else { return Err(Error::Corrupt("ZIP64 end record")) };
                multi_disk |= le32(&rec, 16) != 0 || le32(&rec, 20) != 0;
                count = le64(&rec, 32);
                cd_size = le64(&rec, 40);
                cd_at = le64(&rec, 48);
                cd_end = end_at - 20;
                // the ZIP64 record itself sits between the directory and its locator
                cd_end = cd_end.min(rec_at);
            }
        }
        if multi_disk {
            return Err(Error::Unsupported("split ZIP archives (.z01 and on)".into()));
        }
        // bytes in front of the archive (a self-extracting stub) shift every stored offset by the same amount
        let shift = cd_end
            .checked_sub(cd_size)
            .and_then(|real| real.checked_sub(cd_at))
            .ok_or(Error::Corrupt("central directory size or offset"))?;
        let cd_start = cd_at + shift;
        if cd_start.checked_add(cd_size).is_none_or(|e| e > len) {
            return Err(Error::Corrupt("central directory size or offset"));
        }
        let cd_len = usize::try_from(cd_size).map_err(|_| Error::Corrupt("central directory size"))?;
        let cd = read_at(&mut file, cd_start, cd_len)?;
        let mut entries = Vec::with_capacity(count.min(1 << 20) as usize);
        let mut at = 0usize;
        while at + 46 <= cd.len() && le32(&cd, at) == SIG_CENTRAL {
            let (entry, next) = parse_central(&cd, at)?;
            let local_at = entry.local_at.checked_add(shift).filter(|&a| a < len);
            let local_at = local_at.ok_or(Error::Corrupt("local header offset"))?;
            entries.push(ZipEntry { local_at, ..entry });
            at = next;
        }
        if entries.len() as u64 != count {
            return Err(Error::Corrupt("central directory entry count"));
        }
        Ok(Archive { file, len, entries })
    }

    /// Where an entry's data starts, from its local header.
    fn data_at(&mut self, e: &ZipEntry) -> Result<u64> {
        if e.local_at.checked_add(30).is_none_or(|end| end > self.len) {
            return Err(Error::Truncated);
        }
        let head = read_at(&mut self.file, e.local_at, 30)?;
        if le32(&head, 0) != SIG_LOCAL {
            return Err(Error::Corrupt("local header signature"));
        }
        let at = e.local_at + 30 + u64::from(le16(&head, 26)) + u64::from(le16(&head, 28));
        if at.checked_add(e.packed).is_none_or(|end| end > self.len) {
            return Err(Error::Truncated);
        }
        Ok(at)
    }

    /// Reads an entry's data, decompressed, into `sink`, and checks its size and CRC.
    fn read_entry(&mut self, e: &ZipEntry, buf: &mut [u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let at = self.data_at(e)?;
        self.file.seek(SeekFrom::Start(at))?;
        let mut crc = crc32fast::Hasher::new();
        let mut size = 0u64;
        let mut emit = |chunk: &[u8]| -> Result<()> {
            size += chunk.len() as u64;
            if size > e.size {
                return Err(Error::Corrupt("more data than the directory says"));
            }
            crc.update(chunk);
            sink(chunk)
        };
        let mut left = e.packed;
        match e.method {
            METHOD_STORED => {
                if e.packed != e.size {
                    return Err(Error::Corrupt("stored entry's sizes differ"));
                }
                while left > 0 {
                    let n = (left.min(buf.len() as u64)) as usize;
                    self.file.read_exact(&mut buf[..n])?;
                    emit(&buf[..n])?;
                    left -= n as u64;
                }
            }
            METHOD_DEFLATE => {
                let mut z = Decompress::new(false);
                let mut out = vec![0u8; BUF];
                let mut done = false;
                while !done {
                    let n = (left.min(buf.len() as u64)) as usize;
                    self.file.read_exact(&mut buf[..n])?;
                    left -= n as u64;
                    let mut input = &buf[..n];
                    loop {
                        let (before_in, before_out) = (z.total_in(), z.total_out());
                        let status = z
                            .decompress(input, &mut out, FlushDecompress::None)
                            .map_err(|_| Error::Corrupt("deflate data"))?;
                        let used = (z.total_in() - before_in) as usize;
                        let made = (z.total_out() - before_out) as usize;
                        input = &input[used..];
                        emit(&out[..made])?;
                        if status == Status::StreamEnd {
                            done = true;
                            break;
                        }
                        // a full output buffer means there may be more to come from the same input
                        if made == out.len() {
                            continue;
                        }
                        if input.is_empty() {
                            if left == 0 {
                                return Err(Error::Corrupt("deflate data ends early"));
                            }
                            break;
                        }
                        if used == 0 && made == 0 {
                            return Err(Error::Corrupt("deflate data"));
                        }
                    }
                }
            }
            m => return Err(Error::Unsupported(format!("compression method {m}"))),
        }
        if size != e.size {
            return Err(Error::Corrupt("less data than the directory says"));
        }
        if crc.finalize() != e.crc32 {
            return Err(Error::BadChecksum(e.name.clone()));
        }
        Ok(())
    }
}

/// One central directory record at `at`: the entry and where the next record starts.
fn parse_central(cd: &[u8], at: usize) -> Result<(ZipEntry, usize)> {
    let h = &cd[at..at + 46];
    let name_len = le16(h, 28) as usize;
    let extra_len = le16(h, 30) as usize;
    let comment_len = le16(h, 32) as usize;
    let name_end = at + 46 + name_len;
    let extra_end = name_end + extra_len;
    let next = extra_end + comment_len;
    if next > cd.len() {
        return Err(Error::Corrupt("central directory record"));
    }
    let raw_name = &cd[at + 46..name_end];
    let extra = &cd[name_end..extra_end];
    let flags = le16(h, 8);
    let mut e = ZipEntry {
        name: String::new(),
        flags,
        method: le16(h, 10),
        host: h[5],
        crc32: le32(h, 16),
        packed: u64::from(le32(h, 20)),
        size: u64::from(le32(h, 24)),
        local_at: u64::from(le32(h, 42)),
        external: le32(h, 38),
        mtime: dos_time(le16(h, 12), le16(h, 14)),
        nanos: 0,
    };
    let disk_start = le16(h, 34);
    e.name = decode_name(raw_name, flags & FLAG_UTF8 != 0);
    let mut x = 0;
    while x + 4 <= extra.len() {
        let id = le16(extra, x);
        let len = le16(extra, x + 2) as usize;
        let Some(body) = extra.get(x + 4..x + 4 + len) else { break };
        match id {
            // ZIP64: only the fields whose 32-bit versions are saturated are present, in this order
            0x0001 => {
                let mut f = 0;
                let mut take = |want: bool| -> Result<Option<u64>> {
                    if !want {
                        return Ok(None);
                    }
                    let v = body.get(f..f + 8).ok_or(Error::Corrupt("ZIP64 extra field"))?;
                    f += 8;
                    Ok(Some(u64::from_le_bytes(v.try_into().unwrap())))
                };
                if let Some(v) = take(e.size == 0xFFFF_FFFF)? {
                    e.size = v;
                }
                if let Some(v) = take(e.packed == 0xFFFF_FFFF)? {
                    e.packed = v;
                }
                if let Some(v) = take(e.local_at == 0xFFFF_FFFF)? {
                    e.local_at = v;
                }
            }
            // NTFS times: tag 1 holds modification, access and creation FILETIMEs
            0x000a if body.len() >= 32 && le16(body, 4) == 1 && le16(body, 6) >= 24 => {
                let ticks = le64(body, 8);
                if ticks > 0 {
                    e.mtime = Some((ticks / 10_000_000) as i64 - 11_644_473_600);
                    e.nanos = ((ticks % 10_000_000) * 100) as u32;
                }
            }
            // extended timestamp: a flags byte, then the modification time when bit 0 is set
            0x5455 if body.len() >= 5 && body[0] & 1 != 0 => {
                e.mtime = Some(i64::from(le32(body, 1) as i32));
                e.nanos = 0;
            }
            // Info-ZIP Unicode path: used when it was made from the very name stored here
            0x7075 if body.len() >= 5 && body[0] == 1 && le32(body, 1) == crc32fast::hash(raw_name) => {
                e.name = String::from_utf8_lossy(&body[5..]).into_owned();
            }
            _ => {}
        }
        x += 4 + len;
    }
    if disk_start != 0 && disk_start != 0xFFFF {
        return Err(Error::Unsupported("split ZIP archives (.z01 and on)".into()));
    }
    Ok((e, next))
}

/// MS-DOS date and time, which carry no time zone: read as UTC.
fn dos_time(time: u16, date: u16) -> Option<i64> {
    let (year, month, day) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 15), i64::from(date & 31));
    let (hour, min, sec) = (i64::from(time >> 11), i64::from((time >> 5) & 63), i64::from(time & 31) * 2);
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || min > 59 || sec > 59 {
        return None;
    }
    // days since 1970 for a civil date (proleptic Gregorian)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

/// The high half of code page 437, the encoding of names without the UTF-8 flag.
const CP437_HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";

fn decode_name(raw: &[u8], utf8: bool) -> String {
    if utf8 {
        return String::from_utf8_lossy(raw).into_owned();
    }
    // many tools write UTF-8 without setting the flag; anything else is taken as code page 437
    if let Ok(s) = std::str::from_utf8(raw) {
        return s.to_string();
    }
    let high: Vec<char> = CP437_HIGH.chars().collect();
    raw.iter().map(|&b| if b < 0x80 { b as char } else { high[(b - 0x80) as usize] }).collect()
}

pub fn list(path: &Path) -> Result<Vec<Entry>> {
    let archive = Archive::open(path)?;
    Ok(archive
        .entries
        .iter()
        .map(|e| Entry {
            name: e.name.clone(),
            size: e.size,
            packed: e.packed,
            mtime: e.mtime,
            crc32: (!e.is_dir()).then_some(e.crc32),
            method: e.method.min(255) as u8,
            dir: e.is_dir(),
            encrypted: e.encrypted(),
            solid: false,
            link: e.is_link().then(|| Redirection::UnixSymlink(String::new())),
        })
        .collect())
}

pub fn run(path: &Path, opts: &Options, mut report: impl FnMut(&str)) -> Result<Summary> {
    let mut archive = Archive::open(path)?;
    let mut summary = Summary { volumes: 1, ..Summary::default() };
    let mut buf = vec![0u8; BUF];
    let entries = std::mem::take(&mut archive.entries);
    fn fail(summary: &mut Summary, report: &mut impl FnMut(&str), name: &str, why: &str) {
        let line = format!("{name}: {why}");
        report(&line);
        summary.errors.push(line);
    }
    for e in &entries {
        let rel = match sanitize(&e.name, e.host != HOST_UNIX) {
            Ok(rel) => rel,
            Err(err) => {
                fail(&mut summary, &mut report, &e.name, &err.to_string());
                continue;
            }
        };
        let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        if e.is_dir() {
            if opts.mode == Mode::Extract && !opts.flatten {
                make_dirs(&opts.dest, &rel)?;
                summary.dir_meta.push((opts.dest.join(&rel), e.meta()));
            }
            summary.dirs += 1;
            continue;
        }
        let refuse = if e.encrypted() {
            Some("encrypted (passwords are not supported yet)".to_string())
        } else if e.method != METHOD_STORED && e.method != METHOD_DEFLATE {
            Some(format!("compression method {} is not supported yet", e.method))
        } else if e.is_link() {
            Some("links are not supported yet".to_string())
        } else {
            None
        };
        if let Some(why) = refuse {
            fail(&mut summary, &mut report, &e.name, &why);
            continue;
        }
        let mut target = None;
        if opts.mode == Mode::Extract {
            match open_target(opts, &rel, Some(e.size))? {
                Target::Write(file, path) => target = Some((Output::new(file, Some(e.size)), path)),
                Target::Exists => {
                    report(&format!("{}: exists, skipped", e.name));
                    summary.skipped += 1;
                    continue;
                }
                Target::Blocked(why) => {
                    fail(&mut summary, &mut report, &e.name, why);
                    continue;
                }
            }
        }
        let read = match target.as_mut() {
            Some((out, _)) => archive.read_entry(e, &mut buf, &mut |chunk| Ok(out.write(chunk)?)),
            None => archive.read_entry(e, &mut buf, &mut |_| Ok(())),
        };
        match read {
            Ok(()) => {
                if let Some((out, path)) = target.take() {
                    // the last of a big entry may still be on its way to the disk
                    match out.finish() {
                        Ok(file) => finish_file(&file, &e.meta()),
                        Err(io) => {
                            let _ = std::fs::remove_file(path);
                            finish_dirs(&mut summary);
                            return Err(Error::Io(io));
                        }
                    }
                }
                summary.files += 1;
                summary.bytes += e.size;
            }
            Err(err) => {
                if let Some((out, path)) = target.take() {
                    // waits for anything still being written, so the removal is the last word
                    drop(out);
                    let _ = std::fs::remove_file(path);
                }
                match err {
                    // a failure writing out stops the run; anything about this entry's data fails only the entry
                    Error::Io(io) if io.kind() != std::io::ErrorKind::UnexpectedEof => {
                        finish_dirs(&mut summary);
                        return Err(Error::Io(io));
                    }
                    Error::Io(_) => fail(&mut summary, &mut report, &e.name, &Error::Truncated.to_string()),
                    other => fail(&mut summary, &mut report, &e.name, &other.to_string()),
                }
            }
        }
    }
    finish_dirs(&mut summary);
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_times() {
        // 2024-02-29 13:37:58
        let date = ((2024 - 1980) << 9) | (2 << 5) | 29;
        let time = (13 << 11) | (37 << 5) | 29;
        assert_eq!(dos_time(time, date), Some(1_709_213_878));
        assert_eq!(dos_time(0, 0), None);
    }

    #[test]
    fn names() {
        assert_eq!(decode_name(b"caf\x82", false), "café");
        assert_eq!(decode_name("café".as_bytes(), false), "café");
        assert_eq!(decode_name(b"a\xffb", true), "a\u{fffd}b");
        assert_eq!(CP437_HIGH.chars().count(), 128);
    }
}
