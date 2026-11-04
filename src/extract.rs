//! Lists, tests and extracts a RAR 5.0 archive, following its volumes in order.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::path::sanitize;
use crate::rar5::reader::{Block, Volume};
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
    dir_meta: Vec<(PathBuf, FileHeader)>,
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

pub fn list(first: &Path) -> Result<Vec<Entry>> {
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

/// A file whose data runs on into later volumes.
struct Pending {
    name: String,
    out: Option<File>,
    path: Option<PathBuf>,
    hasher: crc32fast::Hasher,
    /// kept only when the archive stores a BLAKE2sp hash for this file
    blake: Option<Blake2sp>,
    bytes: u64,
    /// something already went wrong: read past the rest of it
    failed: bool,
}

impl Pending {
    fn skipping(name: &str) -> Self {
        Pending {
            name: name.to_string(),
            out: None,
            path: None,
            hasher: Default::default(),
            blake: None,
            bytes: 0,
            failed: true,
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
}

pub fn run(first: &Path, opts: &Options, mut report: impl FnMut(&str)) -> Result<Summary> {
    let mut summary = Summary::default();
    let mut pending: Option<Pending> = None;
    let mut buf = vec![0u8; BUF];
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)?;
    }
    let walked = walk(first, |vol, block| {
        let Block::File(h) = block else { return Ok(()) };
        if h.split_before() {
            match pending.take() {
                Some(p) if p.name == h.name => {
                    return continue_file(vol, &h, p, &mut pending, &mut buf, opts, &mut summary, &mut report);
                }
                Some(mut p) => {
                    fail(&mut summary, &mut report, &p.name, "next part is missing");
                    p.discard();
                }
                // the set was opened past the start of this file
                None => {
                    summary.skipped += 1;
                    return Ok(());
                }
            }
        } else if let Some(mut p) = pending.take() {
            fail(&mut summary, &mut report, &p.name, "next part is missing");
            p.discard();
        }
        start_file(vol, &h, &mut pending, &mut buf, opts, &mut summary, &mut report)
    });
    // whatever stopped the walk, a file left half-written is removed
    let volumes = match walked {
        Ok(v) => v,
        Err(e) => {
            if let Some(mut p) = pending.take() {
                p.discard();
            }
            finish_dirs(&mut summary);
            return Err(e);
        }
    };
    summary.volumes = volumes;
    if let Some(mut p) = pending.take() {
        fail(&mut summary, &mut report, &p.name, "archive ends before this file does");
        p.discard();
    }
    finish_dirs(&mut summary);
    Ok(summary)
}

/// Restores folders' permissions and times, deepest first, after their contents are written: a read-only folder
/// set first would stop its own files from being created.
fn finish_dirs(summary: &mut Summary) {
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
        if h.is_unix() {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode((h.attributes as u32) & 0o777));
        }
    }
    #[cfg(not(unix))]
    let _ = dirs;
}

fn fail(summary: &mut Summary, report: &mut impl FnMut(&str), name: &str, why: &str) {
    let line = format!("{name}: {why}");
    report(&line);
    summary.errors.push(line);
}

#[allow(clippy::too_many_arguments)]
fn start_file(
    vol: &mut Volume,
    h: &FileHeader,
    pending: &mut Option<Pending>,
    buf: &mut [u8],
    opts: &Options,
    summary: &mut Summary,
    report: &mut impl FnMut(&str),
) -> Result<()> {
    let skip_rest = |pending: &mut Option<Pending>| {
        if h.split_after() {
            *pending = Some(Pending::skipping(&h.name));
        }
    };
    let rel = match sanitize(&h.name, !h.is_unix()) {
        Ok(rel) => rel,
        Err(e) => {
            fail(summary, report, &h.name, &e.to_string());
            skip_rest(pending);
            return Ok(());
        }
    };
    let rel = if opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
    if h.is_dir() {
        if opts.mode == Mode::Extract && !opts.flatten {
            make_dirs(&opts.dest, &rel)?;
            summary.dir_meta.push((opts.dest.join(&rel), h.clone()));
        }
        summary.dirs += 1;
        return Ok(());
    }
    let refuse = if h.encrypted {
        Some("encrypted (passwords are not supported yet)".to_string())
    } else if h.method != 0 {
        Some(format!("compression method {} is not supported yet", h.method))
    } else {
        h.redirection.as_ref().map(|link| format!("links are not supported yet ({link:?})"))
    };
    if let Some(why) = refuse {
        fail(summary, report, &h.name, &why);
        skip_rest(pending);
        return Ok(());
    }

    let (out, path) = if opts.mode == Mode::Extract {
        let target = opts.dest.join(&rel);
        if let Some(parent) = rel.parent() {
            make_dirs(&opts.dest, parent)?;
        }
        match fs::symlink_metadata(&target) {
            Ok(_) if opts.overwrite == Overwrite::Skip => {
                report(&format!("{}: exists, skipped", h.name));
                summary.skipped += 1;
                skip_rest(pending);
                return Ok(());
            }
            // removing first means a link left at the target is replaced, never written through
            Ok(meta) if meta.is_dir() => {
                fail(summary, report, &h.name, "a folder is in the way");
                skip_rest(pending);
                return Ok(());
            }
            Ok(_) => fs::remove_file(&target)?,
            Err(_) => {}
        }
        let file = OpenOptions::new().write(true).create_new(true).open(&target)?;
        if h.unpacked_size > 0 && !h.size_unknown() {
            // one allocation up front keeps a big file in few extents; failure here is harmless
            let _ = file.set_len(h.unpacked_size);
        }
        (Some(file), Some(target))
    } else {
        (None, None)
    };
    let p = Pending {
        name: h.name.clone(),
        out,
        path,
        hasher: crc32fast::Hasher::new(),
        blake: h.blake2sp.map(|_| Blake2sp::new()),
        bytes: 0,
        failed: false,
    };
    continue_file(vol, h, p, pending, buf, opts, summary, report)
}

/// Copies this volume's part of a stored file and, at its last part, checks and finishes it.
#[allow(clippy::too_many_arguments)]
fn continue_file(
    vol: &mut Volume,
    h: &FileHeader,
    mut p: Pending,
    pending: &mut Option<Pending>,
    buf: &mut [u8],
    _opts: &Options,
    summary: &mut Summary,
    report: &mut impl FnMut(&str),
) -> Result<()> {
    if p.failed {
        if h.split_after() {
            *pending = Some(p);
        }
        return Ok(());
    }
    if h.method != 0 || h.encrypted {
        fail(summary, report, &p.name, "a later part is packed differently");
        p.discard();
        if h.split_after() {
            *pending = Some(p);
        }
        return Ok(());
    }
    let split_after = h.split_after();
    let mut part = crc32fast::Hasher::new();
    let mut part_blake = h.blake2sp.filter(|_| split_after).map(|_| Blake2sp::new());
    let read = vol.read_data(h.data_at, h.packed_size, buf, |chunk| {
        p.hasher.update(chunk);
        if let Some(b) = p.blake.as_mut() {
            b.update(chunk);
        }
        if split_after {
            part.update(chunk);
            if let Some(b) = part_blake.as_mut() {
                b.update(chunk);
            }
        }
        if let Some(out) = p.out.as_mut() {
            out.write_all(chunk)?;
        }
        Ok(())
    });
    if let Err(e) = read {
        p.discard();
        return Err(e);
    }
    p.bytes += h.packed_size;
    if split_after {
        // a part's checksums cover only its own packed bytes
        let crc_bad = h.crc32.is_some_and(|want| part.finalize() != want);
        let blake_bad = h.blake2sp.zip(part_blake).is_some_and(|(want, got)| got.finish() != want);
        if crc_bad || blake_bad {
            fail(summary, report, &p.name, "checksum error in a volume's part");
            p.discard();
        }
        *pending = Some(p);
        return Ok(());
    }
    let crc_bad = h.crc32.is_some_and(|want| p.hasher.clone().finalize() != want);
    let blake_bad = match (h.blake2sp, p.blake.take()) {
        (Some(want), Some(got)) => got.finish() != want,
        // a hash that only the last part states can't be checked from here: say so rather than pass it
        (Some(_), None) if h.crc32.is_none() => {
            fail(summary, report, &p.name, "its BLAKE2sp hash starts only in a later part, so it can't be checked");
            p.discard();
            return Ok(());
        }
        _ => false,
    };
    if crc_bad || blake_bad {
        fail(summary, report, &p.name, "checksum error");
        p.discard();
        return Ok(());
    }
    if let Some(out) = p.out.take() {
        if !h.size_unknown() && p.bytes != h.unpacked_size {
            out.set_len(p.bytes)?;
        }
        finish_file(&out, h);
    }
    summary.files += 1;
    summary.bytes += p.bytes;
    Ok(())
}

/// Times and permissions, best effort: a file system that can't keep them still gets the data.
fn finish_file(out: &File, h: &FileHeader) {
    set_time(out, h);
    #[cfg(unix)]
    if h.is_unix() {
        use std::os::unix::fs::PermissionsExt;
        // set-id and sticky bits are never restored from an archive; zero is a real mode, not a missing one
        let mode = (h.attributes as u32) & 0o777;
        let _ = out.set_permissions(fs::Permissions::from_mode(mode));
    }
}

fn set_time(out: &File, h: &FileHeader) {
    if let Some(secs) = h.mtime {
        let at = if secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(secs as u64, h.mtime_nanos))
        } else {
            UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
        };
        if let Some(at) = at.filter(|t| *t != SystemTime::UNIX_EPOCH || secs == 0) {
            let _ = out.set_modified(at);
        }
    }
}

/// Creates `rel` under `root` one folder at a time, refusing to pass through a link.
fn make_dirs(root: &Path, rel: &Path) -> Result<()> {
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
