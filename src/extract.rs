//! Lists, tests and extracts an archive. RAR 5.0 lives here: its volumes are followed in order and compressed files
//! decoded. Other formats have modules of their own.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::batch::{self, Batch, Done, Job, Outcome};
use crate::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::output::Output;
use crate::path::sanitize;
use crate::rar5::reader::{Block, Volume};
use crate::rar5::unpack::{Unpacker, window_for};
use crate::rar5::{FileHeader, Redirection};
use crate::volume::next_volume;

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
    /// threads to decode with, counting the one that writes the output; None for one per core
    pub threads: Option<usize>,
    /// the smallest file decoded on several threads; None for the decoder's default
    #[doc(hidden)]
    pub parallel_min: Option<u64>,
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

/// A checked place for a file not created yet: `replace` when something there is to be removed first.
pub(crate) struct Place {
    pub path: PathBuf,
    pub replace: bool,
}

/// What [`check_target`] found.
pub(crate) enum Checked {
    Write(Place),
    Exists,
    Blocked(&'static str),
}

/// Prepares the output file for `rel`: makes its folders, honours the overwrite choice, and never writes through a
/// link left at the target. `size` is preallocated when known.
pub(crate) fn open_target(opts: &Options, rel: &Path, size: Option<u64>) -> Result<Target> {
    Ok(match check_target(opts, rel, None)? {
        Checked::Write(place) => {
            let file = create_target(&place, size)?;
            Target::Write(file, place.path)
        }
        Checked::Exists => Target::Exists,
        Checked::Blocked(why) => Target::Blocked(why),
    })
}

/// The folders one run has made or checked, so each is looked at once.
#[derive(Default)]
pub(crate) struct Dirs {
    /// each folder, and whether this run made it
    known: HashMap<PathBuf, bool>,
    /// every path this run has written or made, in lower case
    taken: HashSet<String>,
    /// a name was seen that a file system may take as another spelling of a different one, so from then on every
    /// target is looked for
    unsure: bool,
}

/// The first half of [`open_target`]: makes the folders and checks the target, without creating it. With `dirs`,
/// folders are made only once, and a file in a folder this run made is not looked for, since nothing can be there
/// that the run did not put there.
pub(crate) fn check_target(opts: &Options, rel: &Path, dirs: Option<&mut Dirs>) -> Result<Checked> {
    let target = opts.dest.join(rel);
    if let Some(parent) = rel.parent() {
        match dirs {
            Some(dirs) => {
                make_dirs_known(&opts.dest, parent, dirs)?;
                let first = dirs.note(rel);
                if first && dirs.known.get(parent) == Some(&true) {
                    return Ok(Checked::Write(Place { path: target, replace: false }));
                }
            }
            None => make_dirs(&opts.dest, parent)?,
        }
    }
    Ok(match fs::symlink_metadata(&target) {
        Ok(_) if opts.overwrite == Overwrite::Skip => Checked::Exists,
        Ok(meta) if meta.is_dir() => Checked::Blocked("a folder is in the way"),
        Ok(_) => Checked::Write(Place { path: target, replace: true }),
        Err(_) => Checked::Write(Place { path: target, replace: false }),
    })
}

/// Files from this size up are given their full length when created. A small file gains nothing from it, and the
/// call costs as much as closing the file.
const PREALLOCATE_MIN: u64 = 1 << 20;

/// The second half of [`open_target`].
pub(crate) fn create_target(place: &Place, size: Option<u64>) -> Result<File> {
    if place.replace {
        // removing first means a link left at the target is replaced, never written through
        match fs::remove_file(&place.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    let file = OpenOptions::new().write(true).create_new(true).open(&place.path)?;
    if let Some(size) = size.filter(|&s| s >= PREALLOCATE_MIN) {
        // one allocation up front keeps a big file in few extents; failure here is harmless
        let _ = file.set_len(size);
    }
    Ok(file)
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
fn walk(
    first: &Path,
    password: Option<&str>,
    mut on_block: impl FnMut(&mut Volume, Block) -> Result<()>,
) -> Result<u64> {
    let mut path = first.to_path_buf();
    let mut volumes = 0;
    loop {
        let mut vol = Volume::open_with_password(&path, password)?;
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

/// The formats found by their first bytes. Anything else is tried as RAR, since a self-extracting RAR starts with
/// a program; a file that turns out not to be RAR gets one more try as a ZIP, which is found from its end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    Zip,
    /// tar, plain or compressed, or a lone compressed file
    Tar,
    Other,
}

fn sniff(path: &Path) -> Result<Format> {
    let mut head = [0u8; 1024];
    let n = crate::tar::read_full(&mut File::open(path)?, &mut head)?;
    let head = &head[..n];
    Ok(if crate::zip::sniff(head) {
        Format::Zip
    } else if crate::stream::Codec::sniff(head).is_some() || crate::tar::sniff_tar(head) {
        Format::Tar
    } else {
        Format::Other
    })
}

/// The entries of an archive, whatever its format.
pub fn list(first: &Path) -> Result<Vec<Entry>> {
    list_with_password(first, None)
}

/// The entries of an archive, decrypting encrypted headers when `password` is given.
pub fn list_with_password(first: &Path, password: Option<&str>) -> Result<Vec<Entry>> {
    match sniff(first)? {
        Format::Zip => return crate::zip::list(first),
        Format::Tar => return crate::tar::list(first),
        Format::Other => {}
    }
    match rar_list(first, password) {
        Err(Error::NotAnArchive) => crate::zip::list(first),
        other => other,
    }
}

/// Tests or extracts an archive, whatever its format.
pub fn run(first: &Path, opts: &Options, report: impl FnMut(&str)) -> Result<Summary> {
    run_with_password(first, opts, None, report)
}

/// Tests or extracts an archive, decrypting with `password` when encrypted.
pub fn run_with_password(
    first: &Path,
    opts: &Options,
    password: Option<&str>,
    mut report: impl FnMut(&str),
) -> Result<Summary> {
    match sniff(first)? {
        Format::Zip => return zip_run(first, opts, password, &mut report),
        Format::Tar => return crate::tar::run(first, opts, &mut report),
        Format::Other => {}
    }
    match rar_run(first, opts, password, &mut report) {
        Err(Error::NotAnArchive) => zip_run(first, opts, password, &mut report),
        other => other,
    }
}

fn zip_run(path: &Path, opts: &Options, password: Option<&str>, report: &mut impl FnMut(&str)) -> Result<Summary> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)?;
    }
    crate::zip::run_with_password(path, opts, password, report)
}

fn rar_list(first: &Path, password: Option<&str>) -> Result<Vec<Entry>> {
    let mut out: Vec<Entry> = Vec::new();
    walk(first, password, |_, block| {
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

struct PendingCipher {
    aes: crate::crypto::AesKey,
    iv: [u8; 16],
    rem: Vec<u8>,
    hash_key: Option<[u8; 32]>,
    cap: Option<u64>,
}

/// A file being read, whose data may run on into later volumes.
struct Pending {
    name: String,
    out: Option<Output>,
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
    encrypted: bool,
    /// AES-256-CBC state for an encrypted RAR5 file
    cipher: Option<PendingCipher>,
    /// where it is written, folded as `batch_paths` is
    key: Option<String>,
    /// where it is to be written, until the file is created there
    place: Option<Place>,
    /// its bytes, gathered to be checked and written whole on a worker
    mem: Option<Vec<u8>>,
}

impl Pending {
    fn new(h: &FileHeader, out: Option<File>, path: Option<PathBuf>) -> Self {
        let size = (!h.size_unknown()).then_some(h.unpacked_size);
        Pending {
            name: h.name.clone(),
            out: out.map(|f| Output::new(f, size)),
            path,
            hasher: crc32fast::Hasher::new(),
            blake: h.blake2sp.map(|_| Blake2sp::new()),
            bytes: 0,
            failed: false,
            passive: false,
            compressed: h.method != 0,
            encrypted: h.encrypted,
            cipher: None,
            key: None,
            place: None,
            mem: None,
        }
    }

    /// Creates the file at its place, if it has one and isn't created yet.
    fn open(&mut self, size: Option<u64>) -> Result<()> {
        if let Some(place) = self.place.take() {
            let file = create_target(&place, size)?;
            self.out = Some(Output::new(file, size));
            self.path = Some(place.path);
        }
        Ok(())
    }

    /// Gives up on this file: what was written of it is removed, so a later run doesn't take it for finished.
    fn discard(&mut self) {
        self.failed = true;
        self.place = None;
        self.mem = None;
        drop(self.out.take());
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }

    /// Where decoded bytes go: the checksums and the output file.
    fn sink(&mut self) -> impl FnMut(&[u8]) -> Result<()> + '_ {
        move |chunk: &[u8]| self.take(chunk)
    }

    fn take(&mut self, mut chunk: &[u8]) -> Result<()> {
        if let Some(cap) = self.cipher.as_ref().and_then(|c| c.cap) {
            let rem = cap.saturating_sub(self.bytes) as usize;
            if chunk.len() > rem {
                chunk = &chunk[..rem];
            }
            if chunk.is_empty() {
                return Ok(());
            }
        }
        if let Some(mem) = self.mem.as_mut() {
            mem.extend_from_slice(chunk);
            self.bytes += chunk.len() as u64;
            return Ok(());
        }
        self.hasher.update(chunk);
        if let Some(b) = self.blake.as_mut() {
            b.update(chunk);
        }
        if let Some(out) = self.out.as_mut() {
            out.write(chunk)?;
        }
        self.bytes += chunk.len() as u64;
        Ok(())
    }
}

/// What a file is checked against once all of it is in.
struct Checks {
    crc32: Option<u32>,
    blake2sp: Option<[u8; 32]>,
    size: Option<u64>,
    meta: Meta,
}

impl From<&FileHeader> for Checks {
    fn from(h: &FileHeader) -> Self {
        Checks {
            crc32: h.crc32,
            blake2sp: h.blake2sp,
            size: (!h.size_unknown()).then_some(h.unpacked_size),
            meta: Meta::from(h),
        }
    }
}

/// A file of a solid stream whose blocks went to the decoder behind the ones before it.
type Queued = (Pending, Checks);

/// Queued files of a solid stream held open at most, when extracting and when testing: past this, the decoder
/// catches up to half as many.
const MAX_OPEN_QUEUED: usize = 64;
const MAX_TESTED_QUEUED: usize = 1024;

/// Queued files up to this size are gathered in memory and created, written and finished on a worker.
const GATHER_MAX: u64 = 1 << 20;

const NEEDS_EARLIER: &str = "needs the files before it in this solid archive, which weren't decoded";

fn fail_to(summary: &mut Summary, report: &mut impl FnMut(&str), name: &str, why: &str) {
    let line = format!("{name}: {why}");
    report(&line);
    summary.errors.push(line);
}

/// Where finished files are counted and reported, and the workers files are written on. A report waits for the
/// files the workers hold, so reports keep archive order.
struct Books<'a, R: FnMut(&str)> {
    summary: &'a mut Summary,
    report: &'a mut R,
    batch: &'a mut Option<Batch>,
}

impl<R: FnMut(&str)> Books<'_, R> {
    /// Takes in every file the workers hold.
    fn catch_up(&mut self) -> Result<()> {
        let Some(batch) = self.batch.as_mut() else { return Ok(()) };
        let (summary, report) = (&mut *self.summary, &mut *self.report);
        batch.drain(&mut |done| apply_done(summary, report, done))
    }

    fn fail(&mut self, name: &str, why: &str) -> Result<()> {
        self.catch_up()?;
        fail_to(self.summary, self.report, name, why);
        Ok(())
    }
}

/// A file's last part is in: checks it whole and finishes it, or hands it to a worker for that when its bytes were
/// gathered.
fn check_and_finish<R: FnMut(&str)>(books: &mut Books<'_, R>, c: &Checks, mut p: Pending) -> Result<()> {
    if let Some(packed) = p.mem.take() {
        let job = Job {
            name: std::mem::take(&mut p.name),
            packed,
            method: 0,
            dictionary: 0,
            size: c.size.unwrap_or(p.bytes),
            crc32: c.crc32,
            blake2sp: c.blake2sp,
            out: p.place.take(),
            meta: c.meta,
        };
        let Some(batch) = books.batch.as_mut() else { return Err(Error::Io(std::io::Error::other("no file workers"))) };
        let (summary, report) = (&mut *books.summary, &mut *books.report);
        return batch.submit(job, &mut |done| apply_done(summary, report, done));
    }
    let got_crc = match p.cipher.as_ref().and_then(|c| c.hash_key.as_ref()) {
        Some(hk) => crate::crypto::rar5_tweak_crc32(p.hasher.clone().finalize(), hk),
        None => p.hasher.clone().finalize(),
    };
    let crc_bad = c.crc32.is_some_and(|want| got_crc != want);
    let blake_bad = if p.encrypted && p.cipher.as_ref().is_some_and(|c| c.hash_key.is_some()) {
        false
    } else {
        match (c.blake2sp, p.blake.take()) {
            (Some(want), Some(got)) => got.finish() != want,
            // a hash that only the last part states can't be checked from here: say so rather than pass it
            (Some(_), None) if c.crc32.is_none() => {
                if !p.passive {
                    books.fail(&p.name, "its BLAKE2sp hash starts only in a later part, so it can't be checked")?;
                }
                p.discard();
                return Ok(());
            }
            _ => false,
        }
    };
    if p.passive {
        return Ok(());
    }
    if crc_bad || blake_bad {
        p.discard();
        return books.fail(&p.name, "checksum error");
    }
    // a matching checksum doesn't vouch for the size the header states
    if let Some(size) = c.size
        && p.bytes != size
    {
        p.discard();
        return books.fail(&p.name, &format!("{} bytes where the header says {size}", p.bytes));
    }
    if let Some(out) = p.out.take() {
        // the last of a big file may still be on its way to the disk
        match out.finish() {
            Ok(file) => finish_file(&file, &c.meta),
            Err(e) => {
                p.discard();
                return Err(e.into());
            }
        }
    }
    books.summary.files += 1;
    books.summary.bytes += p.bytes;
    Ok(())
}

/// Where a solid stream's queued files' bytes go: to the oldest file not yet finished, which an empty slice from the
/// decoder finishes.
fn route<'a, 'b: 'a, R: FnMut(&str)>(
    queued: &'a mut VecDeque<Queued>,
    books: &'a mut Books<'b, R>,
) -> impl FnMut(&[u8]) -> Result<()> + 'a {
    move |chunk: &[u8]| {
        if chunk.is_empty() {
            let Some((p, c)) = queued.pop_front() else { return Err(Error::Corrupt("more files than were queued")) };
            return check_and_finish(books, &c, p);
        }
        match queued.front_mut() {
            Some((p, _)) => p.take(chunk),
            None => Err(Error::Corrupt("more files than were queued")),
        }
    }
}

/// Whether a decoder's error is the file's own trouble rather than the run's.
fn decoding_error(e: &Error) -> bool {
    matches!(e, Error::Corrupt(_) | Error::Unsupported(_) | Error::Truncated)
}

struct Run<'a, R: FnMut(&str)> {
    opts: &'a Options,
    password: Option<&'a str>,
    summary: Summary,
    pending: Option<Pending>,
    /// the decoder, kept between files of a solid stream
    stream: Option<Unpacker>,
    report: R,
    /// threads for work spread over files; 1 for none
    threads: usize,
    /// small files being decoded and written on other threads
    batch: Option<Batch>,
    /// where the files handed to the workers since they last finished everything are written, folded to lower case
    /// as a case-insensitive file system would; a later file going to one of these waits for them first
    batch_paths: HashSet<String>,
    /// files of a solid stream fed to the decoder and not yet finished, oldest first: their blocks may still be with
    /// its workers
    queued: VecDeque<Queued>,
    /// where the queued files are written, as `batch_paths`
    queued_paths: HashSet<String>,
    /// folders under the destination made (or found) so far
    dirs: Dirs,
}

/// A file finished on another thread, counted and reported as if done here.
fn apply_done(summary: &mut Summary, report: &mut impl FnMut(&str), done: Done) -> Result<()> {
    match done.outcome {
        Outcome::Done(bytes) => {
            summary.files += 1;
            summary.bytes += bytes;
            Ok(())
        }
        Outcome::Failed(why) => {
            let line = format!("{}: {why}", done.name);
            report(&line);
            summary.errors.push(line);
            Ok(())
        }
        Outcome::Fatal(e) => Err(e),
    }
}

fn rar_run(first: &Path, opts: &Options, password: Option<&str>, report: impl FnMut(&str)) -> Result<Summary> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)?;
    }
    let threads = opts.threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    // the hidden size knob is there to test decoding blocks on workers, which batching would bypass
    let threads = if opts.parallel_min.is_some() { 1 } else { threads };
    let mut r = Run {
        opts,
        password: password.filter(|s| !s.is_empty()),
        summary: Summary::default(),
        pending: None,
        stream: None,
        report,
        threads,
        batch: None,
        batch_paths: HashSet::new(),
        queued: VecDeque::new(),
        queued_paths: HashSet::new(),
        dirs: Dirs::default(),
    };
    let walked = walk(first, r.password, |vol, block| {
        let Block::File(h) = block else { return Ok(()) };
        r.file_block(vol, &h)
    });
    // files still with the workers come in before anything is summed up or folders are finished
    let walked = walked.and_then(|v| r.drain().map(|()| v));
    if walked.is_err() {
        // whatever went wrong, the workers finish (or remove) what they hold
        let _ = r.drain();
    }
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
    /// Finishes everything still on other threads.
    fn drain(&mut self) -> Result<()> {
        self.drain_solid()?;
        self.drain_batch()
    }

    fn drain_batch(&mut self) -> Result<()> {
        let Some(mut batch) = self.batch.take() else { return Ok(()) };
        let (summary, report) = (&mut self.summary, &mut self.report);
        let result = batch.drain(&mut |done| apply_done(summary, report, done));
        self.batch = Some(batch);
        self.batch_paths.clear();
        result
    }

    /// Whether `h` goes to the workers: it can, and at least one of them started.
    fn goes_to_batch(&mut self, vol: &Volume, h: &FileHeader) -> bool {
        self.batchable(vol, h) && self.batch.get_or_insert_with(|| Batch::new(self.threads)).usable()
    }

    /// Reports a failure after every file before it, so reports keep archive order.
    fn fail_in_order(&mut self, name: &str, why: &str) -> Result<()> {
        self.drain()?;
        self.fail(name, why);
        Ok(())
    }

    /// Whether `h` can go to the workers whole: a small file standing alone in one volume.
    fn batchable(&self, vol: &Volume, h: &FileHeader) -> bool {
        self.threads > 1
            && !vol.main.is_solid()
            && !h.solid
            && !h.encrypted
            && !h.split_before()
            && !h.split_after()
            && !h.size_unknown()
            && h.unpacked_size <= batch::JOB_MAX
            && h.packed_size <= batch::JOB_MAX
            && (h.method == 0 || h.packed_size > 0)
    }

    /// Reads `h`'s data and hands it to the workers.
    fn send_to_batch(&mut self, vol: &mut Volume, h: &FileHeader, out: Option<Place>) -> Result<()> {
        let mut packed = Vec::with_capacity(h.packed_size as usize);
        vol.read_data_into(h.data_at, h.packed_size, &mut packed)?;
        let job = Job {
            name: h.name.clone(),
            packed,
            method: h.method,
            dictionary: h.dictionary,
            size: h.unpacked_size,
            crc32: h.crc32,
            blake2sp: h.blake2sp,
            out,
            meta: Meta::from(h),
        };
        let batch = self.batch.get_or_insert_with(|| Batch::new(self.threads));
        let (summary, report) = (&mut self.summary, &mut self.report);
        batch.submit(job, &mut |done| apply_done(summary, report, done))
    }

    fn fail(&mut self, name: &str, why: &str) {
        fail_to(&mut self.summary, &mut self.report, name, why);
    }

    fn file_block(&mut self, vol: &mut Volume, h: &FileHeader) -> Result<()> {
        // a file done here reports as it goes, so the ones before it with the workers come in first (a solid
        // stream's queued files, and the ones the workers write for it, wait for the next file that can't join
        // them)
        if !self.goes_to_batch(vol, h) && !self.queueable(vol, h) {
            self.drain_batch()?;
        }
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
            self.drain()?;
            (self.report)(&format!("{}: older version {v}, skipped", h.name));
            self.summary.skipped += 1;
            return self.pass_over(vol, h);
        }
        let rel = match sanitize(&h.name, !h.is_unix()) {
            Ok(rel) => rel,
            Err(e) => {
                self.fail_in_order(&h.name, &e.to_string())?;
                return self.pass_over(vol, h);
            }
        };
        // U+FFFE marks a Unix name holding bytes that aren't UTF-8, mapped into private-use characters
        if self.opts.mode == Mode::Extract && h.name.contains('\u{FFFE}') {
            self.fail_in_order(&h.name, "the name holds bytes that aren't UTF-8, which isn't supported yet")?;
            return self.pass_over(vol, h);
        }
        let rel = if self.opts.flatten { PathBuf::from(rel.file_name().unwrap_or_default()) } else { rel };
        // a file the workers still hold may be written, or removed, at the same place
        // (a folder on its way to it may still be such a file, too)
        let key = rel.to_string_lossy().to_lowercase();
        if self.opts.mode == Mode::Extract
            && rel.ancestors().any(|a| {
                let a = a.to_string_lossy().to_lowercase();
                self.batch_paths.contains(&a) || self.queued_paths.contains(&a)
            })
        {
            self.drain()?;
        }
        if h.is_dir() {
            if self.opts.mode == Mode::Extract && !self.opts.flatten {
                // a folder made earlier for a file inside it still gets its own times and permissions
                make_dirs_known(&self.opts.dest, &rel, &mut self.dirs)?;
                self.summary.dir_meta.push((self.opts.dest.join(&rel), Meta::from(h)));
            }
            self.summary.dirs += 1;
            return Ok(());
        }
        let refuse = if h.encrypted && (self.password.is_none() || h.crypt.is_none()) {
            Some("encrypted (password required)".to_string())
        } else if h.method != 0 && h.algorithm != 0 {
            Some("RAR 7 compression is not supported yet".to_string())
        } else {
            h.redirection.as_ref().map(|link| format!("links are not supported yet ({link:?})"))
        };
        if let Some(why) = refuse {
            self.fail_in_order(&h.name, &why)?;
            return self.pass_over(vol, h);
        }
        let cipher = if h.encrypted {
            let pw = self.password.unwrap_or_default();
            let cp = h.crypt.as_ref().unwrap();
            let Some((key, hk)) = crate::crypto::derive_rar5_key_and_hash_key(pw, cp.kdf_count, &cp.salt, cp.check)
            else {
                self.fail_in_order(&h.name, "wrong password")?;
                return self.pass_over(vol, h);
            };
            let Some(aes) = crate::crypto::AesKey::new(&key) else {
                self.fail_in_order(&h.name, "invalid encryption key")?;
                return self.pass_over(vol, h);
            };
            let cap = (!h.size_unknown()).then_some(h.unpacked_size);
            Some(PendingCipher { aes, iv: cp.iv, rem: Vec::new(), hash_key: cp.tweaked_crc.then_some(hk), cap })
        } else {
            None
        };

        let place = if self.opts.mode == Mode::Extract {
            match check_target(self.opts, &rel, Some(&mut self.dirs))? {
                Checked::Write(place) => Some(place),
                Checked::Exists => {
                    self.drain()?;
                    (self.report)(&format!("{}: exists, skipped", h.name));
                    self.summary.skipped += 1;
                    return self.pass_over(vol, h);
                }
                Checked::Blocked(why) => {
                    self.fail_in_order(&h.name, why)?;
                    return self.pass_over(vol, h);
                }
            }
        } else {
            None
        };
        if self.goes_to_batch(vol, h) {
            if self.opts.mode == Mode::Extract {
                self.batch_paths.insert(key);
            }
            return self.send_to_batch(vol, h, place);
        }
        let mut p = Pending::new(h, None, None);
        p.cipher = cipher;
        p.key = (self.opts.mode == Mode::Extract).then_some(key);
        p.place = place;
        self.begin_decoding(vol, h, p)
    }

    /// Sets the decoder up for a compressed file, then reads its first part.
    fn begin_decoding(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> Result<()> {
        let size = (!h.size_unknown()).then_some(h.unpacked_size);
        let queues = self.queueable(vol, h);
        if queues
            && h.solid
            && !self.queued.is_empty()
            && let Some(u) = self.stream.as_mut()
            && h.dictionary <= u.window_size()
        {
            // every queued file holds its output open
            let most = if self.opts.mode == Mode::Extract { MAX_OPEN_QUEUED } else { MAX_TESTED_QUEUED };
            if self.queued.len() >= most {
                let mut books = Books { summary: &mut self.summary, report: &mut self.report, batch: &mut self.batch };
                let caught_up = u.catch_up(most as u64 / 2, &mut route(&mut self.queued, &mut books));
                if let Err(e) = caught_up {
                    if !decoding_error(&e) {
                        p.discard();
                        self.discard_queued();
                        return Err(e);
                    }
                    // the stream is gone with the file that failed, so this one fails after it
                    if let Err(e) = self.fail_queued(&e.to_string()) {
                        p.discard();
                        return Err(e);
                    }
                    return self.begin_decoding(vol, h, p);
                }
            }
            u.queue_file(size);
            return self.decode_queued(vol, h, p);
        }
        // anything else is done in order, after the queued files and what the workers hold
        if let Err(e) = self.drain() {
            p.discard();
            return Err(e);
        }
        if h.method != 0 {
            let solid_archive = vol.main.is_solid();
            let ready = if h.solid {
                match self.stream.as_mut() {
                    Some(u) if h.dictionary <= u.window_size() => {
                        u.next_file(size);
                        Ok(())
                    }
                    _ => Err(NEEDS_EARLIER.to_string()),
                }
            } else {
                match window_for(h.dictionary, size, solid_archive) {
                    Ok(window) => match self.stream.as_mut().filter(|u| u.fits(window)) {
                        Some(u) => {
                            u.reset(size);
                            Ok(())
                        }
                        None => Unpacker::new(window).map(|mut u| {
                            if self.opts.threads.is_some() || self.opts.parallel_min.is_some() {
                                let workers = self.opts.threads.map_or_else(|| u.threads(), |n| n.saturating_sub(1));
                                u.set_threads(workers, self.opts.parallel_min.unwrap_or(u.parallel_min()));
                            }
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
            } else if queues
                && let Some(u) = self.stream.as_mut()
                && u.threads() > 0
            {
                u.force_parallel();
                return self.decode_queued(vol, h, p);
            }
        }
        if let Err(e) = p.open(size) {
            p.discard();
            return Err(e);
        }
        self.continue_file(vol, h, p)
    }

    /// Whether `h` can be decoded behind the files before it in a solid stream: compressed, whole in this volume, of
    /// known size, with threads to spare.
    fn queueable(&self, vol: &Volume, h: &FileHeader) -> bool {
        self.threads > 1
            && vol.main.is_solid()
            && h.method != 0
            && h.algorithm == 0
            && !h.encrypted
            && !h.split_before()
            && !h.split_after()
            && !h.size_unknown()
    }

    /// Feeds a whole file to the decoder behind the queued ones. Its bytes go to it once the ones before are done.
    fn decode_queued(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> Result<()> {
        // a small file is gathered and written whole on a worker; a bigger one is written as it comes
        let size = h.unpacked_size;
        if p.place.is_some()
            && size <= GATHER_MAX
            && self.batch.get_or_insert_with(|| Batch::new(self.threads)).usable()
        {
            p.mem = Some(Vec::with_capacity(size as usize));
        } else if let Err(e) = p.open(Some(size)) {
            p.discard();
            return Err(e);
        }
        // registered only now, after any stream before was drained, so a later file at the same place waits for it
        if let Some(key) = p.key.clone() {
            self.queued_paths.insert(key);
        }
        self.queued.push_back((p, Checks::from(h)));
        let mut stream = self.stream.take();
        let mut fed = false;
        let mut books = Books { summary: &mut self.summary, report: &mut self.report, batch: &mut self.batch };
        let queued = &mut self.queued;
        let read = vol.read_data(h.data_at, h.packed_size, |chunk| {
            let Some(u) = stream.as_mut() else { return Err(Error::Corrupt("no decoder for a queued file")) };
            let r = u.feed(chunk, &mut route(queued, &mut books));
            fed = r.is_err();
            r
        });
        match read {
            Ok(()) => {
                self.stream = stream;
                Ok(())
            }
            // the oldest file still queued is the one the decoder was on
            Err(e) if fed && decoding_error(&e) => self.fail_queued(&e.to_string()),
            Err(e) if fed => {
                self.discard_queued();
                Err(e)
            }
            // the archive can't be read on: the files before this one are whole, so they are finished first
            Err(e) => {
                if let Some(u) = stream.as_mut() {
                    let mut books =
                        Books { summary: &mut self.summary, report: &mut self.report, batch: &mut self.batch };
                    let waited = u.wait(&mut route(&mut self.queued, &mut books));
                    if let Err(d) = waited
                        && decoding_error(&d)
                    {
                        let _ = self.fail_queued(&d.to_string());
                    }
                }
                self.discard_queued();
                Err(e)
            }
        }
    }

    /// Decodes the queued files to their end and finishes them.
    fn drain_solid(&mut self) -> Result<()> {
        if self.queued.is_empty() {
            return Ok(());
        }
        let Some(mut u) = self.stream.take() else { return self.fail_queued(NEEDS_EARLIER) };
        let mut books = Books { summary: &mut self.summary, report: &mut self.report, batch: &mut self.batch };
        let finished = u.finish(&mut route(&mut self.queued, &mut books));
        match finished {
            Ok(()) => {
                self.stream = Some(u);
                // files still being written on the workers keep their places guarded
                self.batch_paths.extend(self.queued_paths.drain());
                // every file but the last was finished where the next began
                let Some((p, c)) = self.queued.pop_front() else { return Ok(()) };
                debug_assert!(self.queued.is_empty());
                check_and_finish(
                    &mut Books { summary: &mut self.summary, report: &mut self.report, batch: &mut self.batch },
                    &c,
                    p,
                )
            }
            Err(e) if decoding_error(&e) => self.fail_queued(&e.to_string()),
            Err(e) => {
                self.discard_queued();
                Err(e)
            }
        }
    }

    /// The decoder failed on the oldest queued file: the ones after it can't be decoded either.
    fn fail_queued(&mut self, why: &str) -> Result<()> {
        // the files before them that the workers hold come in first
        if let Err(e) = self.drain_batch() {
            self.discard_queued();
            return Err(e);
        }
        let mut why = why;
        while let Some((mut p, _)) = self.queued.pop_front() {
            if !p.passive {
                self.fail(&p.name, why);
            }
            p.discard();
            why = NEEDS_EARLIER;
        }
        self.stream = None;
        self.queued_paths.clear();
        Ok(())
    }

    /// Drops the queued files and what was written of them, unreported: the run itself is failing.
    fn discard_queued(&mut self) {
        for (mut p, _) in self.queued.drain(..) {
            p.discard();
        }
        self.stream = None;
        self.queued_paths.clear();
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
        if (h.method != 0) != p.compressed || h.encrypted != p.encrypted {
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
        if !p.compressed
            && !p.encrypted
            && self.threads > 1
            && h.packed_size >= batch::STORED_PARALLEL_MIN
            && p.blake.is_none()
            && part_blake.is_none()
        {
            return self.stored_parallel(vol, h, p);
        }
        let mut stream = if p.compressed { self.stream.take() } else { None };
        let read = vol.read_data(h.data_at, h.packed_size, |chunk| {
            if split_after {
                part.update(chunk);
                if let Some(b) = part_blake.as_mut() {
                    b.update(chunk);
                }
            }
            if let Some(PendingCipher { aes, iv, rem, .. }) = p.cipher.as_mut() {
                let mut dec_buf;
                let to_feed: &[u8] = if !rem.is_empty() || !chunk.len().is_multiple_of(16) {
                    rem.extend_from_slice(chunk);
                    let aligned = rem.len() & !15;
                    if aligned == 0 {
                        return Ok(());
                    }
                    dec_buf = rem.drain(..aligned).collect::<Vec<u8>>();
                    aes.decrypt_cbc_in_place(iv, &mut dec_buf);
                    &dec_buf
                } else {
                    dec_buf = chunk.to_vec();
                    aes.decrypt_cbc_in_place(iv, &mut dec_buf);
                    &dec_buf
                };
                match stream.as_mut() {
                    Some(u) => u.feed(to_feed, &mut p.sink()),
                    None => p.sink()(to_feed),
                }
            } else {
                match stream.as_mut() {
                    Some(u) => u.feed(chunk, &mut p.sink()),
                    None => p.sink()(chunk),
                }
            }
        });
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
        self.finish_file_checks(h, p)
    }

    /// A file's last part is in: checks it whole and finishes it.
    fn finish_file_checks(&mut self, h: &FileHeader, p: Pending) -> Result<()> {
        check_and_finish(
            &mut Books { summary: &mut self.summary, report: &mut self.report, batch: &mut self.batch },
            &Checks::from(h),
            p,
        )
    }
}

impl<R: FnMut(&str)> Run<'_, R> {
    /// A big part of a stored file, checked (and copied) on several threads. Ends as [`Self::continue_file`] does.
    fn stored_parallel(&mut self, vol: &mut Volume, h: &FileHeader, mut p: Pending) -> Result<()> {
        let split_after = h.split_after();
        if h.data_at.checked_add(h.packed_size).is_none_or(|end| end > vol.len()) {
            p.discard();
            return Err(Error::Truncated);
        }
        // the pieces are written by position, so the writer thread hands the file over first
        let file = match p.out.take().map(Output::finish).transpose() {
            Ok(f) => f,
            Err(e) => {
                p.discard();
                return Err(e.into());
            }
        };
        let part = batch::stored(vol.file(), h.data_at, h.packed_size, file.as_ref(), p.bytes, self.threads);
        let part = match part {
            Ok(part) => part,
            Err(e) => {
                drop(file);
                p.discard();
                return Err(e);
            }
        };
        p.hasher.combine(&part);
        p.bytes += h.packed_size;
        if let Some(mut file) = file {
            use std::io::{Seek, SeekFrom};
            if let Err(e) = file.seek(SeekFrom::Start(p.bytes)) {
                drop(file);
                p.discard();
                return Err(e.into());
            }
            let left = (!h.size_unknown()).then(|| h.unpacked_size.saturating_sub(p.bytes));
            p.out = Some(Output::new(file, left));
        }
        if split_after {
            if h.crc32.is_some_and(|want| part.finalize() != want) {
                if !p.passive {
                    self.fail(&p.name, "checksum error in a volume's part");
                }
                p.discard();
            }
            self.pending = Some(p);
            return Ok(());
        }
        self.finish_file_checks(h, p)
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

impl Dirs {
    /// Records the path `rel` as used by this run. True when nothing this run wrote can be at `rel` under any
    /// spelling: every part of it is a plain name, it was not used before in any letter case, and no name seen so
    /// far could be another spelling of it. A plain name has only ASCII letters, digits and common punctuation, and
    /// doesn't end in a dot or space. Anything else may be folded by some file system into a different name
    /// (Unicode normalization, `~` short names, `\` or `:` on Windows, trailing dots and spaces), so it makes every
    /// later answer false. (Opening the file still refuses to replace anything, should a name slip by.)
    fn note(&mut self, rel: &Path) -> bool {
        let mut key = String::new();
        for part in rel.components() {
            let plain = match part {
                Component::Normal(name) => name.to_str().filter(|n| plain_name(n)),
                _ => None,
            };
            let Some(name) = plain else {
                self.unsure = true;
                return false;
            };
            if !key.is_empty() {
                key.push('/');
            }
            key.extend(name.chars().map(|c| c.to_ascii_lowercase()));
        }
        self.taken.insert(key) && !self.unsure
    }
}

/// A name every file system keeps as it is, apart from letter case.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with(['.', ' '])
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b" -_.,+=()[]{}@#&!'$%^;".contains(&b))
}

/// [`make_dirs`] for a run that remembers the folders it has made or checked, in `dirs`. It starts below the
/// deepest one already known, and tries to make each folder before looking at what is there, so a new folder costs
/// one call.
pub(crate) fn make_dirs_known(root: &Path, rel: &Path, dirs: &mut Dirs) -> Result<()> {
    let known =
        rel.ancestors().find(|a| a.as_os_str().is_empty() || dirs.known.contains_key(*a)).unwrap_or(Path::new(""));
    let Ok(rest) = rel.strip_prefix(known) else { return make_dirs(root, rel) };
    let mut at = root.join(known);
    let mut sub = known.to_path_buf();
    for part in rest.components() {
        at.push(part);
        sub.push(part);
        let made = match fs::create_dir(&at) {
            Ok(()) => true,
            // something is there already: only a real folder will do, never a link to one
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match fs::symlink_metadata(&at) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(Error::UnsafePath(rel.display().to_string()));
                }
                Ok(meta) if meta.is_dir() => false,
                Ok(_) => return Err(Error::UnsafePath(format!("{}: a file is in the way", rel.display()))),
                Err(e) => return Err(e.into()),
            },
            Err(e) => return Err(e.into()),
        };
        // a folder takes its name, so no file is later created over it
        dirs.note(&sub);
        dirs.known.insert(sub.clone(), made);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_used_under_other_letter_case_is_not_new() {
        let mut dirs = Dirs::default();
        assert!(dirs.note(Path::new("d")));
        assert!(dirs.note(Path::new("d/one")));
        // `D` may be `d` itself, and what goes in it lands in `d`
        assert!(!dirs.note(Path::new("D")));
        assert!(dirs.note(Path::new("D/two")));
        assert!(!dirs.note(Path::new("d/two")));
        assert!(!dirs.note(Path::new("d/ONE")));
        assert!(dirs.note(Path::new("d/three")));
    }

    #[test]
    fn after_a_name_that_may_fold_into_another_nothing_is_new() {
        for odd in ["d/\u{212A}", "d/e\u{301}", "d/LONGNA~1.TXT", "d/f.", "d/f ", "d./f", "d\\\\f", "d/f:s", "d/f*"] {
            let mut dirs = Dirs::default();
            assert!(dirs.note(Path::new("d/a")));
            assert!(!dirs.note(Path::new(odd)), "{odd:?}");
            // the Kelvin sign is `K` to a file system that normalizes names
            assert!(!dirs.note(Path::new("d/K")), "after {odd:?}");
            assert!(!dirs.note(Path::new("x/y")), "after {odd:?}");
        }
    }
}
