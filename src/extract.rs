//! Lists, tests and extracts a RAR 5.0 archive, following its volumes in order and decoding compressed files.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::path::sanitize;
use crate::rar5::reader::{Block, Volume};
use crate::rar5::unpack::{Unpacker, window_for};
use crate::rar5::{FileHeader, Redirection};
use crate::volume::next_volume;

/// Bytes moved per read. Large enough that a stored file is copied at disk speed.
const BUF: usize = 4 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// read every file and check it, write nothing
    Test,
    /// write every file under the destination
    Extract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Overwrite {
    /// leave a file that is already there alone
    #[default]
    Skip,
    Always,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: Mode,
    pub dest: PathBuf,
    pub overwrite: Overwrite,
    /// drop the stored folders and write every file straight into the destination
    pub flatten: bool,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped: u64,
    /// one line per file that failed
    pub errors: Vec<String>,
    pub volumes: u64,
    /// folders whose times and permissions are set once everything inside them is written
    pub(crate) dir_meta: Vec<(PathBuf, Meta)>,
}

/// What is restored on an extracted file or folder besides its data.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Meta {
    /// seconds since 1970
    pub mtime: Option<i64>,
    pub nanos: u32,
    /// Unix permission bits, when the archive was made on a Unix system
    pub mode: Option<u32>,
}

impl From<&FileHeader> for Meta {
    fn from(h: &FileHeader) -> Self {
        Meta { mtime: h.mtime, nanos: h.mtime_nanos, mode: h.is_unix().then_some(h.attributes as u32) }
    }
}

/// Where a file's data is to go, once the destination has been checked.
pub(crate) enum Target {
    Write(File, PathBuf),
    /// already there and not to be overwritten
    Exists,
    /// something else stands in the way
    Blocked(&'static str),
}

/// Prepares the output file for `rel`: makes its folders, honours the overwrite choice, and never writes through a
/// link left at the target. `size` is preallocated when known.
pub(crate) fn open_target(opts: &Options, rel: &Path, size: Option<u64>) -> Result<Target> {
    let target = opts.dest.join(rel);
    if let Some(parent) = rel.parent() {
        make_dirs(&opts.dest, parent)?;
    }
    match fs::symlink_metadata(&target) {
        Ok(_) if opts.overwrite == Overwrite::Skip => return Ok(Target::Exists),
        Ok(meta) if meta.is_dir() => return Ok(Target::Blocked("a folder is in the way")),
        // removing first means a link left at the target is replaced, never written through
        Ok(_) => fs::remove_file(&target)?,
        Err(_) => {}
    }
    let file = OpenOptions::new().write(true).create_new(true).open(&target)?;
    if let Some(size) = size.filter(|&s| s > 0) {
        // one allocation up front keeps a big file in few extents; failure here is harmless
        let _ = file.set_len(size);
    }
    Ok(Target::Write(file, target))
}

/// One entry for a listing.
#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub size: u64,
    pub packed: u64,
    pub mtime: Option<i64>,
    pub crc32: Option<u32>,
    pub method: u8,
    pub dir: bool,
    pub encrypted: bool,
    pub solid: bool,
    pub link: Option<Redirection>,
}

/// Every volume of the set in turn, starting from `first`, calling `on_block` for each block.
fn walk(first: &Path, mut on_block: impl FnMut(&mut Volume, Block) -> Result<()>) -> Result<u64> {
    let mut path = first.to_path_buf();
    let mut volumes = 0;
    loop {
        let mut vol = Volume::open(&path)?;
        volumes += 1;
        let mut more = vol.main.is_volume();
        let mut saw_end = false;
        while let Some(block) = vol.next_block()? {
            match block {
                Block::End { more_volumes } => {
                    more = more_volumes;
                    saw_end = true;
                    break;
                }
                Block::Crypt => return Err(Error::Encrypted),
                b => on_block(&mut vol, b)?,
            }
        }
        if !saw_end && !vol.main.is_volume() {
            more = false;
        }
        if !more {
            return Ok(volumes);
        }
        let Some(next) = next_volume(&path) else {
            // the set says it goes on, but this name has no volume number to step
            if saw_end {
                return Err(Error::UnnamedVolume(path));
            }
            return Ok(volumes);
        };
        if !next.exists() {
            // without an end header a volume flag alone doesn't prove another volume was made
            if saw_end {
                return Err(Error::MissingVolume(next));
            }
            return Ok(volumes);
        }
        path = next;
    }
}

/// Which reader a file needs, from its first bytes. RAR is tried for anything else, since a self-extracting RAR
/// starts with a program; a file that turns out not to be RAR gets one more try as a ZIP, which is found from
/// its end.
fn is_zip(path: &Path) -> Result<bool> {
    let mut head = [0u8; 4];
    let n = std::io::Read::read(&mut File::open(path)?, &mut head)?;
    Ok(crate::zip::sniff(&head[..n]))
}

/// The entries of an archive, whatever its format.
pub fn list(first: &Path) -> Result<Vec<Entry>> {
    if is_zip(first)? {
        return crate::zip::list(first);
    }
    match rar_list(first) {
        Err(Error::NotAnArchive) => crate::zip::list(first),
        other => other,
    }
}

/// Tests or extracts an archive, whatever its format.
pub fn run(first: &Path, opts: &Options, mut report: impl FnMut(&str)) -> Result<Summary> {
    if is_zip(first)? {
        return zip_run(first, opts, &mut report);
    }
    match rar_run(first, opts, &mut report) {
        Err(Error::NotAnArchive) => zip_run(first, opts, &mut report),
        other => other,
    }
}

fn zip_run(path: &Path, opts: &Options, report: &mut impl FnMut(&str)) -> Result<Summary> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)?;
    }
    crate::zip::run(path, opts, report)
}

fn rar_list(first: &Path) -> Result<Vec<Entry>> {
    let mut out: Vec<Entry> = Vec::new();
    walk(first, |_, block| {
        let Block::File(h) = block else { return Ok(()) };
        if h.split_before() {
            if let Some(last) = out.last_mut().filter(|e| e.name == h.name) {
                last.packed += h.packed_size;
                if !h.split_after() {
                    last.crc32 = h.crc32;
                }
            }
            return Ok(());
        }
        out.push(Entry {
            name: h.name.clone(),
            size: h.unpacked_size,
            packed: h.packed_size,
            mtime: h.mtime,
            crc32: if h.split_after() { None } else { h.crc32 },
            method: h.method,
            dir: h.is_dir(),
            encrypted: h.encrypted,
            solid: h.solid,
            link: h.redirection.clone(),
        });
        Ok(())
    })?;
    Ok(out)
}

/// A file being read, whose data may run on into later volumes.
struct Pending {
    name: String,
    out: Option<File>,
    path: Option<PathBuf>,
    hasher: crc32fast::Hasher,
    /// kept only when the archive stores a BLAKE2sp hash for this file
    blake: Option<Blake2sp>,
    /// unpacked bytes so far
    bytes: u64,
    /// something already went wrong: read past the rest of it
    failed: bool,
    /// decoded only to keep a solid stream going: not counted, not written
    passive: bool,
    compressed: bool,
}

impl Pending {
    fn new(h: &FileHeader, out: Option<File>, path: Option<PathBuf>) -> Self {
        Pending {
            name: h.name.clone(),
            out,
            path,
            hasher: crc32fast::Hasher::new(),
            blake: h.blake2sp.map(|_| Blake2sp::new()),
            bytes: 0,
            failed: false,
            passive: false,
            compressed: h.method != 0,
        }
    }

    /// Gives up on this file: what was written of it is removed, so a later run doesn't take it for finished.
    fn discard(&mut self) {
        self.failed = true;
        drop(self.out.take());
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }

    /// Where decoded bytes go: the checksums and the output file.
    fn sink(&mut self) -> impl FnMut(&[u8]) -> Result<()> + '_ {
        move |chunk: &[u8]| {
            self.hasher.update(chunk);
            if let Some(b) = self.blake.as_mut() {
                b.update(chunk);
            }
            if let Some(out) = self.out.as_mut() {
                out.write_all(chunk)?;
            }
            self.bytes += chunk.len() as u64;
            Ok(())
        }
    }
}

struct Run<'a, R: FnMut(&str)> {
    opts: &'a Options,
    summary: Summary,
    pending: Option<Pending>,
    /// the decoder, kept between files of a solid stream
    stream: Option<Unpacker>,
    buf: Vec<u8>,
    report: R,
}

fn rar_run(first: &Path, opts: &Options, report: impl FnMut(&str)) -> Result<Summary> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)?;
    }
    let mut r = Run { opts, summary: Summary::default(), pending: None, stream: None, buf: vec![0u8; BUF], report };
    let walked = walk(first, |vol, block| {
        let Block::File(h) = block else { return Ok(()) };
        r.file_block(vol, &h)
    });
    // whatever stopped the walk, a file left half-written is removed
    let volumes = match walked {
        Ok(v) => v,
        Err(e) => {
            if let Some(mut p) = r.pending.take() {
                p.discard();
            }
            finish_dirs(&mut r.summary);
            return Err(e);
        }
    };
    r.summary.volumes = volumes;
    if let Some(mut p) = r.pending.take() {
        r.fail(&p.name, "archive ends before this file does");
        p.discard();
    }
    finish_dirs(&mut r.summary);
    Ok(r.summary)
}

impl<R: FnMut(&str)> Run<'_, R> {
    fn fail(&mut self, name: &str, why: &str) {
        let line = format!("{name}: {why}");
        (self.report)(&line);
        self.summary.errors.push(line);
    }

    fn file_block(&mut self, vol: &mut Volume, h: &FileHeader) -> Result<()> {
        if h.split_before() {
            match self.pending.take() {
                Some(p) if p.name == h.name => return self.continue_file(vol, h, p),
                Some(mut p) => {
                    self.fail(&p.name, "next part is missing");
                    p.discard();
                    self.stream = None;
                }
                // the set was opened past the start of this file
                None => {
                    self.summary.skipped += 1;
                    return Ok(());
                }
            }
        } else if let Some(mut p) = self.pending.take() {
            self.fail(&p.name, "next part is missing");
            p.discard();
            self.stream = None;
        }
        self.start_file(vol, h)
    }

    /// Reads past a file this run won't write. In a solid archive its data is still decoded, since the files
    /// after it build on it.
    fn pass_over(&mut self, vol: &mut Volume, h: &FileHeader) -> Result<()> {
        if vol.main.is_solid() && h.method != 0 && !h.encrypted {
            let mut p = Pending::new(h, None, None);
            p.passive = true;
            return self.begin_decoding(vol, h, p);
        }
        if h.split_after() {
            let mut p = Pending::new(h, None, None);
            p.failed = true;
            self.pending = Some(p);
        }
        Ok(())
    }

    fn start_file(&mut self, vol: &mut Volume, h: &FileHeader) -> Result<()> {
        // an older revision shares the current file's name: only the current one is written, but a test checks all
        if let Some(v) = h.version
            && self.opts.mode == Mode::Extract
        {
            (self.report)(&format!("{}: older version {v}, skipped", h.name));
            self.summary.skipped += 1;
            return self.pass_over(vol, h);
        }
        let rel = match sanitize(&h.name, !h.is_unix()) {
            Ok(rel) => rel,
            Err(e) => {
                self.fail(&h.name, &e.to_string());
                return self.pass_over(vol, h);
            }
        };
        // U+FFFE marks a Unix name holding bytes that aren't UTF-8, mapped into private-use characters
        if self.opts.mode == Mode::Extract && h.name.contains('\u{FFFE}') {
            self.fail(&h.name, "the name holds bytes that aren't UTF-8, which isn't supported yet");
            return self.pass_over(vol, h);
        }
        let rel = if self.opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        if h.is_dir() {
            if self.opts.mode == Mode::Extract && !self.opts.flatten {
                make_dirs(&self.opts.dest, &rel)?;
                self.summary.dir_meta.push((self.opts.dest.join(&rel), Meta::from(h)));
            }
            self.summary.dirs += 1;
            return Ok(());
        }
        let refuse = if h.encrypted {
            Some("encrypted (passwords are not supported yet)".to_string())
        } else if h.method != 0 && h.algorithm != 0 {
            Some("RAR 7 compression is not supported yet".to_string())
        } else {
            h.redirection.as_ref().map(|link| format!("links are not supported yet ({link:?})"))
        };
        if let Some(why) = refuse {
            self.fail(&h.name, &why);
            return self.pass_over(vol, h);
        }

        let (out, path) = if self.opts.mode == Mode::Extract {
            match open_target(self.opts, &rel, (!h.size_unknown()).then_some(h.unpacked_size))? {
                Target::Write(file, target) => (Some(file), Some(target)),
                Target::Exists => {
                    (self.report)(&format!("{}: exists, skipped", h.name));
                    self.summary.skipped += 1;
                    return self.pass_over(vol, h);
                }
                Target::Blocked(why) => {
                    self.fail(&h.name, why);
                    return self.pass_over(vol, h);
                }
            }
        } else {
            (None, None)
        };
        let p = Pending::new(h, out, path);
        self.begin_decoding(vol, h, p)
    }

    /// Sets the decoder up for a compressed file, then reads its first part.
    fn begin_decoding(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> Result<()> {
        if h.method != 0 {
            let size = (!h.size_unknown()).then_some(h.unpacked_size);
            let solid_archive = vol.main.is_solid();
            let ready = if h.solid {
                match self.stream.as_mut() {
                    Some(u) if h.dictionary <= u.window_size() => {
                        u.next_file(size);
                        Ok(())
                    }
                    _ => Err("needs the files before it in this solid archive, which weren't decoded".to_string()),
                }
            } else {
                match window_for(h.dictionary, size, solid_archive) {
                    Ok(window) => match self.stream.as_mut().filter(|u| u.window_size() == window) {
                        Some(u) => {
                            u.reset(size);
                            Ok(())
                        }
                        None => Unpacker::new(window).map(|mut u| {
                            u.reset(size);
                            self.stream = Some(u);
                        }),
                    }
                    .map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                }
            };
            if let Err(why) = ready {
                if !p.passive {
                    self.fail(&h.name, &why);
                }
                p.discard();
                self.stream = None;
            }
        }
        self.continue_file(vol, h, p)
    }

    /// Reads this volume's part of a file and, at its last part, checks and finishes it.
    fn continue_file(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> Result<()> {
        let split_after = h.split_after();
        if p.failed {
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        if (h.method != 0) != p.compressed || h.encrypted {
            if !p.passive {
                self.fail(&p.name, "a later part is packed differently");
            }
            p.discard();
            self.stream = None;
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        // a part's checksums cover only its own packed bytes
        let mut part = crc32fast::Hasher::new();
        let mut part_blake = h.blake2sp.filter(|_| split_after).map(|_| Blake2sp::new());
        let mut buf = std::mem::take(&mut self.buf);
        let mut stream = if p.compressed { self.stream.take() } else { None };
        let read = vol.read_data(h.data_at, h.packed_size, &mut buf, |chunk| {
            if split_after {
                part.update(chunk);
                if let Some(b) = part_blake.as_mut() {
                    b.update(chunk);
                }
            }
            match stream.as_mut() {
                Some(u) => u.feed(chunk, &mut p.sink()),
                None => p.sink()(chunk),
            }
        });
        self.buf = buf;
        // a decoder error is this file's problem; an archive read error ends the run
        let decoded = match read {
            Ok(()) if !split_after => match stream.as_mut() {
                Some(u) => u.finish(&mut p.sink()),
                None => Ok(()),
            },
            Ok(()) => Ok(()),
            Err(e @ (Error::Corrupt(_) | Error::Unsupported(_))) if p.compressed => Err(e),
            Err(e) => {
                p.discard();
                return Err(e);
            }
        };
        if let Err(e) = decoded {
            if !p.passive {
                self.fail(&p.name, &e.to_string());
            }
            p.discard();
            // the stream's state is lost with it
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        self.stream = stream.or(self.stream.take());
        if split_after {
            let crc_bad = h.crc32.is_some_and(|want| part.finalize() != want);
            let blake_bad = h.blake2sp.zip(part_blake).is_some_and(|(want, got)| got.finish() != want);
            if crc_bad || blake_bad {
                if !p.passive {
                    self.fail(&p.name, "checksum error in a volume's part");
                }
                p.discard();
                if p.compressed {
                    self.stream = None;
                }
            }
            self.pending = Some(p);
            return Ok(());
        }
        let crc_bad = h.crc32.is_some_and(|want| p.hasher.clone().finalize() != want);
        let blake_bad = match (h.blake2sp, p.blake.take()) {
            (Some(want), Some(got)) => got.finish() != want,
            // a hash that only the last part states can't be checked from here: say so rather than pass it
            (Some(_), None) if h.crc32.is_none() => {
                if !p.passive {
                    self.fail(&p.name, "its BLAKE2sp hash starts only in a later part, so it can't be checked");
                }
                p.discard();
                return Ok(());
            }
            _ => false,
        };
        if p.passive {
            return Ok(());
        }
        if crc_bad || blake_bad {
            self.fail(&p.name, "checksum error");
            p.discard();
            return Ok(());
        }
        // a matching checksum doesn't vouch for the size the header states
        if !h.size_unknown() && p.bytes != h.unpacked_size {
            self.fail(&p.name, &format!("{} bytes where the header says {}", p.bytes, h.unpacked_size));
            p.discard();
            return Ok(());
        }
        if let Some(out) = p.out.take() {
            finish_file(&out, &Meta::from(h));
        }
        self.summary.files += 1;
        self.summary.bytes += p.bytes;
        Ok(())
    }
}

/// Restores folders' permissions and times, deepest first, after their contents are written: a read-only folder
/// set first would stop its own files from being created.
pub(crate) fn finish_dirs(summary: &mut Summary) {
    let mut dirs = std::mem::take(&mut summary.dir_meta);
    dirs.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    #[cfg(unix)]
    for (path, h) in &dirs {
        use std::os::unix::fs::PermissionsExt;
        // only a real folder: never follow something that replaced it since
        if !fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        if let Ok(dir) = File::open(path) {
            set_time(&dir, h);
        }
        if let Some(mode) = h.mode {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777));
        }
    }
    #[cfg(not(unix))]
    let _ = dirs;
}

/// Times and permissions, best effort: a file system that can't keep them still gets the data.
pub(crate) fn finish_file(out: &File, h: &Meta) {
    set_time(out, h);
    #[cfg(unix)]
    if let Some(mode) = h.mode {
        use std::os::unix::fs::PermissionsExt;
        // set-id and sticky bits are never restored from an archive; zero is a real mode, not a missing one
        let _ = out.set_permissions(fs::Permissions::from_mode(mode & 0o777));
    }
}

fn set_time(out: &File, h: &Meta) {
    if let Some(secs) = h.mtime {
        let at = if secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(secs as u64, h.nanos))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
        };
        if let Some(at) = at.filter(|t| *t != SystemTime::UNIX_EPOCH || secs == 0) {
            let _ = out.set_modified(at);
        }
    }
}

/// Creates `rel` under `root` one folder at a time, refusing to pass through a link.
pub(crate) fn make_dirs(root: &Path, rel: &Path) -> Result<()> {
    let mut at = root.to_path_buf();
    for part in rel.components() {
        at.push(part);
        match fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(Error::UnsafePath(rel.display().to_string()));
            }
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(Error::UnsafePath(format!("{}: a file is in the way", rel.display()))),
            Err(_) => match fs::create_dir(&at) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            },
        }
    }
    Ok(())
}
