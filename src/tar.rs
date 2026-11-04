//! tar archives, read from the POSIX ustar and pax layouts plus GNU's long-name records, either plain or inside
//! gzip. A gzip file that holds no tar archive is one compressed file, and comes out as that file.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek};
use std::path::{Path, PathBuf};

use flate2::bufread::MultiGzDecoder;

use crate::error::{Error, Result};
use crate::extract::{Entry, Meta, Mode, Options, Summary, Target, finish_dirs, finish_file, make_dirs, open_target};
use crate::output::Output;
use crate::path::sanitize;
use crate::rar5::Redirection;

const BLOCK: usize = 512;
/// Bytes moved per read.
const BUF: usize = 4 << 20;
/// The longest name, link target or pax record set taken from an extension record.
const MAX_EXT: u64 = 1 << 20;
/// The most zero bytes an empty archive is taken to be: GNU tar pads one to 10 KiB, other writers to whole
/// records of up to this much.
const EMPTY_MAX: usize = 1 << 20;

/// Whether the file starts with a gzip member.
pub fn sniff_gzip(head: &[u8]) -> bool {
    head.len() >= 3 && head[..3] == [0x1f, 0x8b, 8]
}

/// Whether the file starts with a tar header: a block whose checksum adds up, or the two zero blocks that make an
/// empty archive.
pub fn sniff_tar(head: &[u8]) -> bool {
    (head.len() >= BLOCK && checksum_ok(&head[..BLOCK])) || (head.len() >= 2 * BLOCK && zero(&head[..2 * BLOCK]))
}

fn zero(b: &[u8]) -> bool {
    b.iter().all(|&b| b == 0)
}

/// The header checksum: every byte of the block added up, with the checksum field counted as spaces. Old writers
/// summed signed bytes, so either sum is taken.
fn checksum_ok(h: &[u8]) -> bool {
    if h.iter().all(|&b| b == 0) {
        return false;
    }
    let Some(stored) = octal(&h[148..156]) else { return false };
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in h[..BLOCK].iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += b as u64;
        signed += b as i8 as i64;
    }
    stored == unsigned || stored as i64 == signed
}

/// An octal field: optional leading spaces, digits, then a space or NUL. An empty field is no number.
fn octal(field: &[u8]) -> Option<u64> {
    let mut digits = field.iter().skip_while(|&&b| b == b' ').take_while(|&&b| b != 0 && b != b' ').peekable();
    digits.peek()?;
    let mut v: u64 = 0;
    for &d in digits {
        if !(b'0'..=b'7').contains(&d) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add((d - b'0') as u64)?;
    }
    Some(v)
}

/// A numeric field: octal, or GNU's base-256 form when the top bit of the first byte is set. Negative base-256
/// values (a first byte of 0xff) are returned as negative.
fn number(field: &[u8]) -> Option<i64> {
    match field.first() {
        Some(&b) if b & 0x80 != 0 => {
            // the bits after the marker are a big-endian two's complement number
            let mut v = (b & 0x7f) as i64;
            if b & 0x40 != 0 {
                v -= 0x80;
            }
            for &b in &field[1..] {
                v = v.checked_mul(256)?.checked_add(b as i64)?;
            }
            Some(v)
        }
        _ => octal(field).and_then(|v| i64::try_from(v).ok()),
    }
}

/// Text from a NUL-padded field.
fn text(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..end]
}

fn name_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Where the archive's bytes come from: the file itself, which can be skipped through, or a gzip stream, which
/// has to be read.
enum Source {
    Plain { r: BufReader<File>, len: u64, pos: u64 },
    Gzip(Box<MultiGzDecoder<BufReader<File>>>),
}

impl Source {
    fn open(path: &Path) -> Result<(Source, bool)> {
        let mut file = File::open(path)?;
        let mut head = [0u8; 3];
        let n = read_full(&mut file, &mut head)?;
        file.rewind()?;
        let len = file.metadata()?.len();
        let r = BufReader::with_capacity(1 << 20, file);
        if sniff_gzip(&head[..n]) {
            Ok((Source::Gzip(Box::new(MultiGzDecoder::new(r))), true))
        } else {
            Ok((Source::Plain { r, len, pos: 0 }, false))
        }
    }

    /// Fills `buf` unless the stream ends first; returns how much was read.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = match self {
            Source::Plain { r, pos, .. } => {
                let n = read_full(r, buf).map_err(read_error)?;
                *pos += n as u64;
                n
            }
            Source::Gzip(g) => read_full(g, buf).map_err(read_error)?,
        };
        Ok(n)
    }

    /// Passes over `n` bytes, which must all be there.
    fn skip(&mut self, n: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            Source::Plain { r, len, pos } => {
                if *len - *pos < n {
                    return Err(Error::Truncated);
                }
                r.seek_relative(n as i64)?;
                *pos += n;
                Ok(())
            }
            Source::Gzip(_) => {
                let mut left = n;
                while left > 0 {
                    let want = left.min(buf.len() as u64) as usize;
                    let got = self.read(&mut buf[..want])?;
                    if got < want {
                        return Err(Error::Truncated);
                    }
                    left -= got as u64;
                }
                Ok(())
            }
        }
    }

    /// The name stored in the gzip header, once the header has been read.
    fn gzip_name(&self) -> Option<String> {
        match self {
            Source::Gzip(g) => g.header().and_then(|h| h.filename()).map(name_of),
            Source::Plain { .. } => None,
        }
    }
}

pub(crate) fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// A failed read of the archive. Damaged compressed data is the archive's fault; anything else is the disk's.
fn read_error(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::UnexpectedEof => Error::Truncated,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => Error::Corrupt("compressed data is damaged"),
        _ => Error::Io(e),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    HardLink,
    /// a device, a pipe, or a GNU record this reader doesn't restore
    Other(u8),
}

/// One member, with any long-name and pax records before it already applied.
#[derive(Clone, Debug)]
struct Member {
    name: String,
    link: String,
    size: u64,
    kind: Kind,
    mtime: Option<i64>,
    nanos: u32,
    mode: u32,
}

impl Member {
    fn meta(&self) -> Meta {
        Meta { mtime: self.mtime, nanos: self.nanos, mode: Some(self.mode) }
    }

    fn entry(&self) -> Entry {
        let link = match self.kind {
            Kind::Symlink => Some(Redirection::UnixSymlink(self.link.clone())),
            Kind::HardLink => Some(Redirection::HardLink(self.link.clone())),
            _ => None,
        };
        let data = self.kind == Kind::File;
        Entry {
            name: self.name.clone(),
            size: if data { self.size } else { 0 },
            packed: if data { self.size } else { 0 },
            mtime: self.mtime,
            crc32: None,
            method: 0,
            dir: self.kind == Kind::Dir,
            encrypted: false,
            solid: false,
            link,
        }
    }
}

/// Values from pax records, for the next member or (from a global record) for every member after.
#[derive(Clone, Debug, Default)]
struct Pax {
    path: Option<String>,
    linkpath: Option<String>,
    size: Option<u64>,
    mtime: Option<(i64, u32)>,
    sparse: bool,
}

impl Pax {
    /// Records of the form "<length> <key>=<value>\n", where the length counts the whole record.
    fn parse(&mut self, data: &[u8]) -> Result<()> {
        let bad = || Error::Corrupt("a pax record is malformed");
        let mut rest = data;
        while !rest.is_empty() {
            if rest.iter().all(|&b| b == 0) {
                break;
            }
            let space = rest.iter().position(|&b| b == b' ').ok_or_else(bad)?;
            let len: usize = std::str::from_utf8(&rest[..space]).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
            if len <= space + 1 || len > rest.len() || rest[len - 1] != b'\n' {
                return Err(bad());
            }
            let record = &rest[space + 1..len - 1];
            rest = &rest[len..];
            let eq = record.iter().position(|&b| b == b'=').ok_or_else(bad)?;
            let (key, value) = (&record[..eq], &record[eq + 1..]);
            match key {
                b"path" => self.path = Some(name_of(value)),
                b"linkpath" => self.linkpath = Some(name_of(value)),
                b"size" => {
                    self.size = Some(std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()).ok_or_else(bad)?)
                }
                b"mtime" => self.mtime = parse_time(value),
                k if k.starts_with(b"GNU.sparse.") => self.sparse = true,
                _ => {}
            }
        }
        Ok(())
    }

    /// `self` over `under`, key by key.
    fn over(&self, under: &Pax) -> Pax {
        Pax {
            path: self.path.clone().or_else(|| under.path.clone()),
            linkpath: self.linkpath.clone().or_else(|| under.linkpath.clone()),
            size: self.size.or(under.size),
            mtime: self.mtime.or(under.mtime),
            sparse: self.sparse || under.sparse,
        }
    }
}

/// A pax time: decimal seconds, maybe negative, maybe with a fraction.
fn parse_time(v: &[u8]) -> Option<(i64, u32)> {
    let s = std::str::from_utf8(v).ok()?;
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let secs: i64 = whole.parse().ok()?;
    if !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut digits: String = frac.chars().take(9).collect();
    while digits.len() < 9 {
        digits.push('0');
    }
    let mut nanos: u32 = digits.parse().ok()?;
    let mut secs = secs;
    // "-1.5" is half a second before -1, so a negative time with a fraction borrows a second
    if whole.starts_with('-') && nanos > 0 {
        secs = secs.checked_sub(1)?;
        nanos = 1_000_000_000 - nanos;
    }
    Some((secs, nanos))
}

/// What the archive turned out to hold.
enum Content {
    Tar,
    /// one gzip-compressed file; the start of its data is in the reader's buffer
    Single,
}

struct Reader {
    src: Source,
    content: Content,
    /// the start of the data, read to tell tar from a lone compressed file: one header block for tar
    first: Option<Vec<u8>>,
    /// data and padding of the current member not read yet
    unread: u64,
    global: Pax,
    scratch: Vec<u8>,
}

impl Reader {
    fn open(path: &Path) -> Result<Reader> {
        let (mut src, gzip) = Source::open(path)?;
        let mut first = vec![0u8; BLOCK];
        let n = src.read(&mut first)?;
        first.truncate(n);
        let mut content = if n == BLOCK && checksum_ok(&first) {
            Some(Content::Tar)
        } else if gzip {
            Some(Content::Single)
        } else {
            None
        };
        if n == BLOCK && zero(&first) {
            // an empty archive is zero blocks and nothing else; a compressed file that only starts with zeros is
            // a file
            first.resize(EMPTY_MAX + 1, 0);
            let more = src.read(&mut first[BLOCK..])?;
            first.truncate(BLOCK + more);
            let len = first.len();
            if (2 * BLOCK..=EMPTY_MAX).contains(&len) && len.is_multiple_of(BLOCK) && zero(&first) {
                content = Some(Content::Tar);
                // nothing is left for the first header: the archive ends at once
                first.clear();
            }
        }
        let Some(content) = content else { return Err(Error::NotAnArchive) };
        Ok(Reader { src, content, first: Some(first), unread: 0, global: Pax::default(), scratch: vec![0; 64 << 10] })
    }

    /// The next header block, or None at the end of the archive: a zero block, or the end of the data exactly at
    /// a block boundary (some writers leave out the end marker).
    fn header_block(&mut self) -> Result<Option<[u8; BLOCK]>> {
        if let Some(first) = self.first.take() {
            // an empty archive leaves nothing here
            return Ok(first.as_slice().try_into().ok());
        }
        let mut block = [0u8; BLOCK];
        match self.src.read(&mut block)? {
            0 => Ok(None),
            BLOCK if block.iter().all(|&b| b == 0) => Ok(None),
            BLOCK if checksum_ok(&block) => Ok(Some(block)),
            BLOCK => Err(Error::Corrupt("a tar header fails its checksum")),
            _ => Err(Error::Truncated),
        }
    }

    /// The data of an extension record, `size` bytes followed by padding.
    fn ext_data(&mut self, size: u64) -> Result<Vec<u8>> {
        if size > MAX_EXT {
            return Err(Error::Corrupt("an extension record is too long"));
        }
        let mut data = vec![0u8; size as usize];
        if self.src.read(&mut data)? < data.len() {
            return Err(Error::Truncated);
        }
        self.src.skip(padding(size), &mut self.scratch)?;
        Ok(data)
    }

    /// The next member, after passing over whatever is left of the one before.
    fn next(&mut self) -> Result<Option<Member>> {
        if self.unread > 0 {
            let n = std::mem::take(&mut self.unread);
            self.src.skip(n, &mut self.scratch)?;
        }
        let mut long_name: Option<String> = None;
        let mut long_link: Option<String> = None;
        let mut pax = Pax::default();
        loop {
            let Some(h) = self.header_block()? else { return Ok(None) };
            let kind = h[156];
            let size = number(&h[124..136]).and_then(|v| u64::try_from(v).ok());
            let Some(size) = size else { return Err(Error::Corrupt("a tar header's size is unreadable")) };
            match kind {
                b'L' => {
                    long_name = Some(name_of(text(&self.ext_data(size)?)));
                    continue;
                }
                b'K' => {
                    long_link = Some(name_of(text(&self.ext_data(size)?)));
                    continue;
                }
                b'x' | b'X' => {
                    let data = self.ext_data(size)?;
                    pax.parse(&data)?;
                    continue;
                }
                b'g' => {
                    let data = self.ext_data(size)?;
                    self.global.parse(&data)?;
                    // a name or size shared by every member after would make no sense: only times carry over
                    self.global.path = None;
                    self.global.linkpath = None;
                    self.global.size = None;
                    continue;
                }
                _ => {}
            }
            let p = pax.over(&self.global);
            let ustar = &h[257..263] == b"ustar\0";
            let mut name = text(&h[0..100]).to_vec();
            if ustar {
                let prefix = text(&h[345..500]);
                if !prefix.is_empty() {
                    name = [prefix, b"/", &name].concat();
                }
            }
            let name = p.path.clone().or(long_name).unwrap_or_else(|| name_of(&name));
            let link = p.linkpath.clone().or(long_link).unwrap_or_else(|| name_of(text(&h[157..257])));
            let size = p.size.unwrap_or(size);
            // the size with its padding has to be a number too
            if size > u64::MAX - BLOCK as u64 {
                return Err(Error::Corrupt("a tar member's size is impossible"));
            }
            let (mtime, nanos) = match p.mtime {
                Some((s, n)) => (Some(s), n),
                None => (number(&h[136..148]), 0),
            };
            let mode = number(&h[100..108]).unwrap_or(0o644) as u32 & 0o7777;
            let kind = match kind {
                b'0' | 0 | b'7' if name.ends_with('/') => Kind::Dir,
                b'5' | b'D' => Kind::Dir,
                b'1' => Kind::HardLink,
                b'2' => Kind::Symlink,
                b'3' | b'4' | b'6' | b'S' | b'M' | b'V' => Kind::Other(kind),
                _ if p.sparse => Kind::Other(b'S'),
                // POSIX: a type this reader doesn't know is read as a regular file
                _ => Kind::File,
            };
            // an old GNU sparse member's map can go on in extension blocks between the header and the data;
            // they are passed over so the member after it is still found
            if h[156] == b'S' && &h[257..263] != b"ustar\0" && h[482] != 0 {
                loop {
                    let mut ext = [0u8; BLOCK];
                    if self.src.read(&mut ext)? < BLOCK {
                        return Err(Error::Truncated);
                    }
                    if ext[504] == 0 {
                        break;
                    }
                }
            }
            // links and folders carry no data, whatever the size field says, except GNU's dump folders
            let has_data = !matches!(kind, Kind::HardLink | Kind::Symlink) && !(kind == Kind::Dir && h[156] == b'5');
            self.unread = if has_data { size + padding(size) } else { 0 };
            return Ok(Some(Member { name, link, size: if has_data { size } else { 0 }, kind, mtime, nanos, mode }));
        }
    }

    /// The current member's data, in pieces, to `sink`. Reads exactly its size and leaves the padding for later.
    fn read_data(&mut self, size: u64, buf: &mut [u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        let mut left = size;
        while left > 0 {
            let want = left.min(buf.len() as u64) as usize;
            let got = self.src.read(&mut buf[..want])?;
            self.unread -= got as u64;
            if got > 0 {
                sink(&buf[..got])?;
            }
            if got < want {
                return Err(Error::Truncated);
            }
            left -= got as u64;
        }
        Ok(())
    }

    /// Reads to the end of the stream, so that every gzip member's checksum is checked.
    fn drain(&mut self, buf: &mut [u8]) -> Result<()> {
        while self.src.read(buf)? > 0 {}
        Ok(())
    }

    /// The whole data of a lone compressed file, starting with the block read when the archive was opened.
    fn read_single(&mut self, buf: &mut [u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<u64> {
        let mut total = 0u64;
        if let Some(first) = self.first.take() {
            if !first.is_empty() {
                sink(&first)?;
            }
            total += first.len() as u64;
        }
        loop {
            let got = self.src.read(buf)?;
            if got == 0 {
                return Ok(total);
            }
            sink(&buf[..got])?;
            total += got as u64;
        }
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// The name a lone compressed file comes out as: the one in its gzip header, or the archive's own name without
/// its gzip ending. Either is cleaned the way a member's name is, and only its last part is kept: a stored name is
/// a file name, never a place to write to.
fn single_name(reader: &Reader, path: &Path) -> String {
    let clean = |name: &str| {
        let last = name.rsplit(['/', '\\']).find(|s| !s.is_empty() && *s != "." && *s != "..")?;
        // as a Windows name, so a drive prefix such as "C:" can't take the path out of the destination
        let rel = sanitize(last, true).ok()?;
        Some(rel.file_name()?.to_string_lossy().into_owned())
    };
    if let Some(name) = reader.src.gzip_name().as_deref().and_then(clean) {
        return name;
    }
    single_fallback(path, &clean)
}

fn single_fallback(path: &Path, clean: &dyn Fn(&str) -> Option<String>) -> String {
    let file = path.file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    let lower = file.to_ascii_lowercase();
    if lower.ends_with(".tgz") {
        return clean(&format!("{}.tar", &file[..file.len() - 4])).unwrap_or_else(|| "file".to_string());
    }
    for ending in [".gz", ".gzip", ".z"] {
        if lower.ends_with(ending) && lower.len() > ending.len() {
            return clean(&file[..file.len() - ending.len()]).unwrap_or_else(|| "file".to_string());
        }
    }
    clean(&format!("{file}.out")).unwrap_or_else(|| "file".to_string())
}

/// The archive's members. A lone compressed file is decoded to find its size: the gzip trailer holds only the
/// last member's size, and only below 4 GiB.
pub fn list(path: &Path) -> Result<Vec<Entry>> {
    let mut reader = Reader::open(path)?;
    if let Content::Single = reader.content {
        let packed = std::fs::metadata(path)?.len();
        let name = single_name(&reader, path);
        let mut buf = vec![0u8; BUF];
        let size = reader.read_single(&mut buf, &mut |_| Ok(()))?;
        return Ok(vec![Entry {
            name,
            size,
            packed,
            mtime: None,
            crc32: None,
            method: 8,
            dir: false,
            encrypted: false,
            solid: false,
            link: None,
        }]);
    }
    let mut out = Vec::new();
    while let Some(m) = reader.next()? {
        if m.kind != Kind::Other(b'V') {
            out.push(m.entry());
        }
    }
    Ok(out)
}

pub fn run(path: &Path, opts: &Options, mut report: impl FnMut(&str)) -> Result<Summary> {
    let mut reader = Reader::open(path)?;
    if opts.mode == Mode::Extract {
        std::fs::create_dir_all(&opts.dest)?;
    }
    let mut summary = Summary { volumes: 1, ..Summary::default() };
    let mut buf = vec![0u8; BUF];
    let result = match reader.content {
        Content::Single => run_single(&mut reader, path, opts, &mut summary, &mut buf, &mut report),
        Content::Tar => run_tar(&mut reader, opts, &mut summary, &mut buf, &mut report),
    };
    finish_dirs(&mut summary);
    result.map(|()| summary)
}

fn fail(summary: &mut Summary, report: &mut impl FnMut(&str), name: &str, why: &str) {
    let line = format!("{name}: {why}");
    report(&line);
    summary.errors.push(line);
}

/// Opens where `rel` is to be written, or says why not. `Ok(None)` means skip it, already reported.
fn target(
    opts: &Options,
    rel: &Path,
    name: &str,
    size: Option<u64>,
    summary: &mut Summary,
    report: &mut impl FnMut(&str),
) -> Result<Option<(Output, PathBuf)>> {
    match open_target(opts, rel, size)? {
        Target::Write(file, path) => Ok(Some((Output::new(file, size), path))),
        Target::Exists => {
            report(&format!("{name}: exists, skipped"));
            summary.skipped += 1;
            Ok(None)
        }
        Target::Blocked(why) => {
            fail(summary, report, name, why);
            Ok(None)
        }
    }
}

/// How a member's data went: written whole, or the error that stopped it.
enum Outcome {
    Done,
    /// the archive itself is damaged or cut short: the member fails and nothing after it can be found
    Archive(Error),
}

/// Reads one member's data into its output (or nowhere, when testing), finishing or removing the output file.
/// A failure to write stops the run; a failure in the archive's data fails the member.
fn copy_out(
    target: Option<(Output, PathBuf)>,
    meta: &Meta,
    read: impl FnOnce(&mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()>,
) -> Result<Outcome> {
    let mut target = target;
    // write errors are kept apart from read errors so the two can be told apart afterwards
    let mut write_error: Option<io::Error> = None;
    let read = {
        let mut sink = |chunk: &[u8]| -> Result<()> {
            if let Some((out, _)) = target.as_mut()
                && let Err(e) = out.write(chunk)
            {
                write_error = Some(e);
                return Err(Error::Corrupt("write failed"));
            }
            Ok(())
        };
        read(&mut sink)
    };
    if let Some(e) = write_error {
        if let Some((out, path)) = target.take() {
            drop(out);
            let _ = std::fs::remove_file(path);
        }
        return Err(Error::Io(e));
    }
    match read {
        Ok(()) => {
            if let Some((out, path)) = target.take() {
                match out.finish() {
                    Ok(file) => finish_file(&file, meta),
                    Err(e) => {
                        let _ = std::fs::remove_file(path);
                        return Err(Error::Io(e));
                    }
                }
            }
            Ok(Outcome::Done)
        }
        Err(e) => {
            if let Some((out, path)) = target.take() {
                // waits for anything still being written, so the removal is the last word
                drop(out);
                let _ = std::fs::remove_file(path);
            }
            match e {
                // the disk under the archive failed: stop
                Error::Io(io) => Err(Error::Io(io)),
                other => Ok(Outcome::Archive(other)),
            }
        }
    }
}

fn run_single(
    reader: &mut Reader,
    path: &Path,
    opts: &Options,
    summary: &mut Summary,
    buf: &mut [u8],
    report: &mut impl FnMut(&str),
) -> Result<()> {
    let name = single_name(reader, path);
    let mut out = None;
    if opts.mode == Mode::Extract {
        let rel = PathBuf::from(&name);
        match target(opts, &rel, &name, None, summary, report)? {
            Some(t) => out = Some(t),
            None => return Ok(()),
        }
    }
    let mut total = 0u64;
    let outcome = copy_out(out, &Meta::default(), |sink| {
        total = reader.read_single(buf, sink)?;
        Ok(())
    })?;
    match outcome {
        Outcome::Done => {
            summary.files += 1;
            summary.bytes += total;
        }
        Outcome::Archive(e) => fail(summary, report, &name, &e.to_string()),
    }
    Ok(())
}

fn run_tar(
    reader: &mut Reader,
    opts: &Options,
    summary: &mut Summary,
    buf: &mut [u8],
    report: &mut impl FnMut(&str),
) -> Result<()> {
    loop {
        let m = match reader.next() {
            Ok(Some(m)) => m,
            Ok(None) => {
                // gzip checks its data only at the end of each member, which may lie past the end marker
                if let Source::Gzip(_) = reader.src {
                    match reader.drain(buf) {
                        Ok(()) => {}
                        Err(Error::Io(e)) => return Err(Error::Io(e)),
                        Err(e) => fail(summary, report, "archive", &e.to_string()),
                    }
                }
                return Ok(());
            }
            Err(Error::Io(e)) => return Err(Error::Io(e)),
            Err(e) => {
                // nothing after a damaged header or a cut-short archive can be found
                fail(summary, report, "archive", &e.to_string());
                return Ok(());
            }
        };
        // "./" stands for the destination itself
        if m.kind == Kind::Dir && m.name.split('/').all(|p| p.is_empty() || p == ".") {
            continue;
        }
        let rel = match sanitize(&m.name, false) {
            Ok(rel) => rel,
            Err(e) => {
                fail(summary, report, &m.name, &e.to_string());
                continue;
            }
        };
        let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        let why = match m.kind {
            Kind::Dir => {
                if opts.mode == Mode::Extract && !opts.flatten {
                    make_dirs(&opts.dest, &rel)?;
                    summary.dir_meta.push((opts.dest.join(&rel), m.meta()));
                }
                summary.dirs += 1;
                continue;
            }
            Kind::File => None,
            Kind::Symlink | Kind::HardLink => Some("links are not supported yet"),
            Kind::Other(b'V') => continue,
            Kind::Other(b'S') => Some("sparse files are not supported yet"),
            Kind::Other(b'M') => Some("multi-volume tar archives are not supported yet"),
            Kind::Other(_) => Some("devices and pipes are not extracted"),
        };
        if let Some(why) = why {
            fail(summary, report, &m.name, why);
            continue;
        }
        let mut out = None;
        if opts.mode == Mode::Extract {
            match target(opts, &rel, &m.name, Some(m.size), summary, report)? {
                Some(t) => out = Some(t),
                None => continue,
            }
        } else if let Source::Plain { .. } = reader.src {
            // tar keeps no checksum of the data, so a test only has to find that all of it is there
            let size = m.size + padding(m.size);
            match reader.src.skip(size, &mut reader.scratch) {
                Ok(()) => {
                    reader.unread = 0;
                    summary.files += 1;
                    summary.bytes += m.size;
                    continue;
                }
                Err(Error::Io(e)) => return Err(Error::Io(e)),
                Err(e) => {
                    fail(summary, report, &m.name, &e.to_string());
                    return Ok(());
                }
            }
        }
        let size = m.size;
        match copy_out(out, &m.meta(), |sink| reader.read_data(size, buf, sink))? {
            Outcome::Done => {
                summary.files += 1;
                summary.bytes += m.size;
            }
            Outcome::Archive(e) => {
                fail(summary, report, &m.name, &e.to_string());
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers() {
        assert_eq!(octal(b"0000644\0"), Some(0o644));
        assert_eq!(octal(b"   755 \0"), Some(0o755));
        assert_eq!(octal(b"\0\0\0\0"), None);
        assert_eq!(octal(b"0009\0"), None);
        let mut big = [0u8; 12];
        big[0] = 0x80;
        big[4..].copy_from_slice(&(10u64 << 32).to_be_bytes());
        assert_eq!(number(&big), Some(10 << 32));
        let neg = [0xffu8; 12];
        assert_eq!(number(&neg), Some(-1));
    }

    #[test]
    fn pax_records() {
        let mut p = Pax::default();
        let rec = |k: &str, v: &str| {
            let body = format!(" {k}={v}\n");
            let mut n = body.len() + 1;
            while format!("{n}{body}").len() != n {
                n += 1;
            }
            format!("{n}{body}")
        };
        let data =
            format!("{}{}{}", rec("path", "a/é/long name.mkv"), rec("size", "12345678901"), rec("mtime", "-1.25"));
        p.parse(data.as_bytes()).unwrap();
        assert_eq!(p.path.as_deref(), Some("a/é/long name.mkv"));
        assert_eq!(p.size, Some(12_345_678_901));
        assert_eq!(p.mtime, Some((-2, 750_000_000)));
        assert!(Pax::default().parse(b"99 path=x\n").is_err());
        // a time whose borrowed second doesn't fit is dropped, not wrapped
        assert_eq!(parse_time(b"-9223372036854775808.1"), None);
        assert_eq!(parse_time(b"-9223372036854775808"), Some((i64::MIN, 0)));
    }

    #[test]
    fn padding_rounds_to_blocks() {
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 511);
        assert_eq!(padding(512), 0);
        assert_eq!(padding(513), 511);
    }
}
