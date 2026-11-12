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

//! Lists, tests and extracts an archive. RAR 5.0 lives here: its volumes are followed in order and compressed files
//! decoded. Other formats have modules of their own.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::batch::{self, Batch, Done, Job, Outcome};
use crate::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::output::{Output, temporary};
use crate::path::sanitize;
use crate::rar5::reader::{Block, SIGNATURE_PROBE_BYTES, Volume, signature_end};
use crate::rar5::unpack::{Sink, Unpacker, window_for};
use crate::rar5::{FileHeader, Redirection};
use crate::volume::next_volume;
use crate::zip::{InspectionSource, ReadSession, SessionResult};

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
    /// Additional existing paths to preserve. Extraction also protects its archive and RAR volumes.
    pub protected_paths: HashSet<PathBuf>,
    /// the smallest file decoded on several threads; None for the decoder's default
    #[doc(hidden)]
    pub parallel_min: Option<u64>,
}

impl Options {
    pub(crate) fn protecting(&self, input: &Path) -> Result<Cow<'_, Self>> {
        if self.mode != Mode::Extract {
            return Ok(Cow::Borrowed(self));
        }
        let mut opts = self.clone();
        for path in &self.protected_paths {
            if let Ok(canonical) = path.canonicalize() {
                opts.protected_paths.insert(canonical);
            }
        }
        opts.protected_paths.insert(input.canonicalize()?);
        Ok(Cow::Owned(opts))
    }
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
    Write(Output),
    /// already there and not to be overwritten
    Exists,
    /// something else stands in the way
    Blocked(&'static str),
}

/// A checked output path. A replacement is staged until verification.
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
        Checked::Write(place) => Target::Write(create_target(place, size)?),
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
        Ok(meta) if meta.file_type().is_symlink() => Checked::Blocked("a symlink is in the way"),
        Ok(_) if opts.overwrite == Overwrite::Skip => Checked::Exists,
        Ok(meta) if meta.is_dir() => Checked::Blocked("a folder is in the way"),
        Ok(_) if !opts.protected_paths.is_empty() && opts.protected_paths.contains(&target.canonicalize()?) => {
            Checked::Blocked("the output path would replace a protected input")
        }
        Ok(_) => Checked::Write(Place { path: target, replace: true }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Checked::Write(Place { path: target, replace: false }),
        Err(e) => return Err(e.into()),
    })
}

/// Files from this size up are given their full length when created. A small file gains nothing from it, and the
/// call costs as much as closing the file.
const PREALLOCATE_MIN: u64 = 1 << 20;

/// The second half of [`open_target`].
pub(crate) fn create_target(place: Place, size: Option<u64>) -> Result<Output> {
    create_target_detailed(place, size).map_err(crate::error::RarFault::into_legacy)
}

pub(crate) fn create_target_detailed(place: Place, size: Option<u64>) -> crate::error::RarResult<Output> {
    use crate::error::{IoOperation, RarFailure, RarFault, RarPolicyReason};
    let create_fault = |e| RarFault::output(IoOperation::CreateFile, Some(place.path.clone()), None, e, false);
    let (file, staged) = if place.replace {
        let parent = place.path.parent().ok_or_else(|| {
            RarFault::new(
                RarFailure::Policy { reason: RarPolicyReason::UnsafePath, path: place.path.clone() },
                Error::UnsafePath(place.path.display().to_string()),
            )
        })?;
        let (file, path) = temporary(parent).map_err(create_fault)?.into_parts();
        (file, Some(path))
    } else {
        let file = OpenOptions::new().write(true).create_new(true).open(&place.path).map_err(create_fault)?;
        (file, None)
    };
    if let Some(size) = size.filter(|&s| s >= PREALLOCATE_MIN) {
        // one allocation up front keeps a big file in few extents; failure here is harmless
        let _ = file.set_len(size);
    }
    Ok(match staged {
        Some(path) => Output::staged(file, size, path, place.path),
        None => Output::created(file, size, place.path),
    })
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

#[derive(Default)]
pub(crate) struct ListingBudget {
    entries: usize,
    name_bytes: usize,
}

impl ListingBudget {
    pub(crate) fn record(&mut self, name: &str) -> Result<()> {
        self.entries += 1;
        self.name_bytes += name.len();
        if self.entries > 1_000_000 || self.name_bytes > 64 << 20 {
            return Err(Error::Unsupported("archive listing exceeds the entry or name byte limit".into()));
        }
        Ok(())
    }
}

/// Every volume of the set in turn, starting from `first`, calling `on_block` for each block.
fn walk(
    vol: Volume,
    password: Option<&str>,
    mut on_block: impl FnMut(&mut Volume, Block) -> Result<()>,
) -> Result<u64> {
    walk_until(vol, password, None, |vol, block| {
        on_block(vol, block)?;
        Ok(false)
    })
}

fn walk_until(
    mut vol: Volume,
    password: Option<&str>,
    cancel: Option<&Cancellation>,
    mut on_block: impl FnMut(&mut Volume, Block) -> Result<bool>,
) -> Result<u64> {
    let mut volumes = 0;
    loop {
        volumes += 1;
        let mut more = vol.main.is_volume();
        let mut saw_end = false;
        loop {
            if let Some(cancel) = cancel {
                cancel.check_io()?;
            }
            let Some(block) = vol.next_block()? else { break };
            match block {
                Block::End { more_volumes } => {
                    more = more_volumes;
                    saw_end = true;
                    break;
                }
                Block::Crypt => return Err(Error::Encrypted),
                b => {
                    if on_block(&mut vol, b)? {
                        return Ok(volumes);
                    }
                }
            }
        }
        if !saw_end && !vol.main.is_volume() {
            more = false;
        }
        if !more {
            return Ok(volumes);
        }
        let Some(next) = next_volume(&vol.path) else {
            // the set says it goes on, but this name has no volume number to step
            if saw_end {
                return Err(Error::UnnamedVolume(vol.path));
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
        vol = Volume::open_with_password(&next, password)?;
    }
}

fn walk_rar(
    mut vol: Volume,
    password: Option<&str>,
    mut on_block: impl FnMut(&mut Volume, Block, crate::rar5::MemberCrypt) -> Result<()>,
) -> Result<u64> {
    use crate::error::RarFault;
    let mut volumes = 0;
    loop {
        volumes += 1;
        let mut more = vol.main.is_volume();
        let mut saw_end = false;
        while let Some((block, crypt)) = vol.next_block_detailed().map_err(RarFault::into_legacy)? {
            match block {
                Block::End { more_volumes } => {
                    more = more_volumes;
                    saw_end = true;
                    break;
                }
                b => on_block(&mut vol, b, crypt)?,
            }
        }
        if !more {
            return Ok(volumes);
        }
        let Some(next) = next_volume(&vol.path) else {
            return if saw_end { Err(Error::UnnamedVolume(vol.path)) } else { Ok(volumes) };
        };
        if !next.exists() {
            return if saw_end { Err(Error::MissingVolume(next)) } else { Ok(volumes) };
        }
        vol = Volume::open_detailed(&next, password).map_err(RarFault::into_legacy)?;
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

const HEAD_PROBE_BYTES: usize = 1024;

fn sniff(path: &Path) -> Result<Format> {
    let mut head = [0u8; HEAD_PROBE_BYTES];
    let n = crate::tar::read_full(&mut File::open(path)?, &mut head)?;
    Ok(classify_head(&head[..n]))
}

fn classify_head(head: &[u8]) -> Format {
    if crate::zip::sniff(head) {
        Format::Zip
    } else if crate::stream::Codec::sniff(head).is_some() || crate::tar::sniff_tar(head) {
        Format::Tar
    } else {
        Format::Other
    }
}

enum SelectedSource {
    Zip(crate::zip::Archive),
    Tar(Box<crate::tar::Selected>),
    Rar { path: PathBuf, chain_start: usize },
}

const RAR_SELECTED_WINDOW_LIMIT: u64 = 256 << 20;

/// A shared cancellation signal for selected reads.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    /// Requests that the decoder stop at its next cancellation check.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Reports whether the caller requested cancellation.
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn check_io(&self) -> std::io::Result<()> {
        if self.is_canceled() {
            return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "operation canceled"));
        }
        Ok(())
    }
}

/// A regular file selected by its index in the archive listing.
pub struct SelectedEntry {
    source: SelectedSource,
    index: usize,
    limit: u64,
    name: String,
    windows_names: bool,
    meta: Meta,
    cancel: Cancellation,
}

impl SelectedEntry {
    /// Opens a zero-based listing entry. The limit applies independently to
    /// packed and decoded bytes. It includes the entire compressed TAR stream
    /// or any solid RAR members required to decode the selection.
    pub fn open(path: &Path, index: usize, password: Option<&str>, limit: u64) -> Result<Self> {
        Self::open_cancelable(path, index, password, limit, Cancellation::default())
    }

    /// Opens an entry and checks the signal while scanning and decoding it.
    pub fn open_cancelable(
        path: &Path,
        index: usize,
        password: Option<&str>,
        limit: u64,
        cancel: Cancellation,
    ) -> Result<Self> {
        cancel.check_io()?;
        match sniff(path)? {
            Format::Tar => {
                let selected = crate::tar::Selected::open(path, index, limit, cancel.clone())?;
                return Ok(Self {
                    name: selected.name.clone(),
                    meta: selected.meta,
                    windows_names: false,
                    index,
                    limit,
                    source: SelectedSource::Tar(Box::new(selected)),
                    cancel,
                });
            }
            Format::Other => match rar_selected_header(path, index, password, &cancel) {
                Ok((header, chain_start)) => {
                    if header.is_dir() || header.redirection.is_some() {
                        return Err(Error::Unsupported("the selected RAR5 entry is not a regular file".into()));
                    }
                    if header.packed_size > limit || (!header.size_unknown() && header.unpacked_size > limit) {
                        return Err(Error::Unsupported("the selected RAR5 entry exceeds the byte limit".into()));
                    }
                    return Ok(Self {
                        meta: Meta::from(&header),
                        windows_names: !header.is_unix(),
                        name: header.name,
                        index,
                        limit,
                        source: SelectedSource::Rar { path: path.to_path_buf(), chain_start },
                        cancel,
                    });
                }
                Err(Error::NotAnArchive) => {}
                Err(error) => return Err(error),
            },
            Format::Zip => {}
        }
        let archive = crate::zip::Archive::open_cancelable(path, Some(&cancel))?;
        let entry = archive.selected_entry(index, limit)?;
        Ok(Self {
            name: entry.name.clone(),
            windows_names: entry.host != 3,
            meta: Meta { mtime: entry.mtime, nanos: entry.nanos, mode: entry.unix_mode() },
            index,
            limit,
            source: SelectedSource::Zip(archive),
            cancel,
        })
    }

    /// Returns the name stored in the archive.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a path checked for traversal and absolute components.
    pub fn relative_path(&self) -> Result<PathBuf> {
        if matches!(self.source, SelectedSource::Rar { .. }) && self.name.contains('\u{FFFE}') {
            return Err(Error::Unsupported("the selected name contains bytes that are not UTF-8".into()));
        }
        sanitize(&self.name, self.windows_names)
    }

    /// Returns Unix permission bits if the archive stores them.
    pub fn unix_mode(&self) -> Option<u32> {
        self.meta.mode
    }

    /// Returns the modification time as Unix seconds and nanoseconds.
    pub fn modified(&self) -> Option<(i64, u32)> {
        self.meta.mtime.map(|seconds| (seconds, self.meta.nanos))
    }

    /// Decodes the selected file into the sink. Data is provisional until
    /// all available integrity checks pass and this function returns success.
    pub fn read(self, password: Option<&str>, mut sink: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
        self.cancel.check_io()?;
        let mut checked_sink = |chunk: &[u8]| {
            self.cancel.check_io()?;
            sink(chunk)
        };
        match self.source {
            SelectedSource::Zip(mut archive) => {
                archive.read_at_cancelable(self.index, password, self.limit, Some(&self.cancel), &mut checked_sink)
            }
            SelectedSource::Tar(selected) => selected.read(&mut checked_sink),
            SelectedSource::Rar { path, chain_start } => {
                let selection = RarSelection {
                    sink: &mut checked_sink,
                    emit: false,
                    packed_left: self.limit,
                    decoded_left: self.limit,
                    cancel: &self.cancel,
                };
                rar_read_at(&path, chain_start, self.index, &self.name, password, selection)
            }
        }?;
        self.cancel.check_io()?;
        Ok(())
    }
}

fn rar_selected_header(
    path: &Path,
    index: usize,
    password: Option<&str>,
    cancel: &Cancellation,
) -> Result<(FileHeader, usize)> {
    let mut current = 0;
    let mut chain_start = None;
    let mut header = None;
    let volume = Volume::open_with_password(path, password)?;
    walk_until(volume, password, Some(cancel), |_, block| {
        if let Block::File(file) = block
            && !file.split_before()
        {
            if file.method != 0 && !file.solid && !file.is_dir() && file.redirection.is_none() {
                chain_start = Some(current);
            }
            if current == index {
                let first = if file.solid && file.method != 0 { chain_start.unwrap_or(current) } else { current };
                header = Some((file, first));
                return Ok(true);
            }
            current += 1;
        }
        Ok(false)
    })?;
    header.ok_or_else(|| Error::Unsupported("entry index is out of range".into()))
}

/// Format-specific metadata returned by archive inspection.
pub enum Inspection {
    /// Immutable ZIP directory and the retained source for selected reads.
    Zip(ReadSession),
    /// The existing listing for TAR, compressed streams, or RAR.
    Other(Vec<Entry>),
}

/// Inspects an archive and retains the ZIP source for selected reads.
pub fn inspect(first: &Path) -> SessionResult<Inspection> {
    inspect_with_password(first, None)
}

/// Inspects an archive, using `password` for encrypted RAR headers.
pub fn inspect_with_password(first: &Path, password: Option<&str>) -> SessionResult<Inspection> {
    inspect_cancelable(first, password, &Cancellation::default())
}

/// Inspects an archive with cooperative cancellation.
///
/// ZIP and TAR/codec head signatures take precedence. With an unknown head,
/// inspection searches the bounded RAR signature window before trying ZIP.
/// After recognition, errors from that format are terminal, including RAR
/// errors from later volumes. ZIP sessions require supported Unix identity.
///
/// The ZIP fetch budget includes both format probes and directory parsing.
/// The existing non-ZIP listing calls observe cancellation on successful
/// return. For ZIP payloads, supply a password to the selected read.
pub fn inspect_cancelable(first: &Path, password: Option<&str>, cancel: &Cancellation) -> SessionResult<Inspection> {
    let mut source = InspectionSource::open(first, cancel)?;
    let mut head = [0; HEAD_PROBE_BYTES];
    let n = source.read_probe(&mut head, cancel)?;
    let format = classify_head(&head[..n]);
    cancel.check_io().map_err(Error::from)?;
    let entries = match format {
        Format::Zip => return source.into_zip(cancel).map(Inspection::Zip),
        Format::Tar => {
            drop(source);
            crate::tar::list(first)?
        }
        Format::Other => {
            let signature = signature_end(&source.probe_prefix(SIGNATURE_PROBE_BYTES, cancel)?);
            cancel.check_io().map_err(Error::from)?;
            match signature {
                Ok(_) => {
                    drop(source);
                    rar_list(first, password)?
                }
                Err(Error::NotAnArchive) => return source.into_zip(cancel).map(Inspection::Zip),
                Err(error) => return Err(error.into()),
            }
        }
    };
    cancel.check_io().map_err(Error::from)?;
    Ok(Inspection::Other(entries))
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
    let mut budget = ListingBudget::default();
    walk(Volume::open_with_password(first, password)?, password, |_, block| {
        let Block::File(h) = block else { return Ok(()) };
        if h.split_before() {
            if let Some(last) = out.last_mut().filter(|e| e.name == h.name) {
                last.packed = last.packed.checked_add(h.packed_size).ok_or(Error::Corrupt("split packed size"))?;
                if !h.split_after() {
                    last.crc32 = h.crc32;
                }
            }
            return Ok(());
        }
        budget.record(&h.name)?;
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
    hash_key: [u8; 32],
    stored_padding: Option<StoredCipherPadding>,
    blocks: Option<CipherBlocks>,
}

struct StoredCipherPadding {
    size: u64,
    skipped: usize,
}

#[derive(Default)]
struct CipherBlocks {
    header: Vec<u8>,
    left: usize,
    last: bool,
    ended: bool,
    padding: usize,
}

impl CipherBlocks {
    fn feed(&mut self, mut data: &[u8], decoder: &mut Unpacker, sink: &mut dyn Sink) -> Result<()> {
        while !data.is_empty() {
            if self.ended {
                if data.len() > 15 - self.padding {
                    return Err(Error::Corrupt("excess encrypted RAR5 padding"));
                }
                self.padding += data.len();
                return Ok(());
            }
            if self.left > 0 {
                let count = self.left.min(data.len());
                decoder.feed(&data[..count], sink)?;
                data = &data[count..];
                self.left -= count;
                self.ended = self.last && self.left == 0;
                continue;
            }
            self.header.push(data[0]);
            data = &data[1..];
            if let Some((_, payload, flags)) = crate::rar5::unpack::block_header(&self.header)? {
                decoder.feed(&self.header, sink)?;
                self.header.clear();
                self.left = payload;
                self.last = flags & 0x40 != 0;
                self.ended = self.last && self.left == 0;
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<()> {
        if !self.ended || self.left != 0 || !self.header.is_empty() {
            return Err(Error::Truncated);
        }
        Ok(())
    }
}

/// A file being read, whose data may run on into later volumes.
struct Pending {
    name: String,
    out: Option<Output>,
    hasher: crate::crc32::Hasher,
    /// the decoder works out the CRC32 instead, and hands it over as `crc`: it does so for every compressed file
    /// whose bytes aren't gathered for a worker
    decoder_crc: bool,
    crc: Option<u32>,
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
    fn new(h: &FileHeader) -> Self {
        Pending {
            name: h.name.clone(),
            out: None,
            hasher: crate::crc32::Hasher::new(),
            decoder_crc: h.method != 0 && !h.encrypted,
            crc: None,
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
            self.out = Some(create_target(place, size)?);
        }
        Ok(())
    }

    /// Gives up on this file: what was written of it is removed, so a later run doesn't take it for finished.
    fn discard(&mut self) {
        self.failed = true;
        self.place = None;
        self.mem = None;
        drop(self.out.take());
    }

    fn hash_key(&self, keyed: bool) -> Option<&[u8; 32]> {
        self.cipher.as_ref().filter(|_| keyed).map(|cipher| &cipher.hash_key)
    }

    /// Decoded bytes, to the checksums and the output file.
    fn take(&mut self, mut chunk: &[u8]) -> Result<()> {
        if let Some(padding) = self.cipher.as_mut().and_then(|c| c.stored_padding.as_mut()) {
            let count = padding.size.saturating_sub(self.bytes).min(chunk.len() as u64) as usize;
            let skipped = chunk.len() - count;
            if skipped > 15 - padding.skipped {
                return Err(Error::Corrupt("excess encrypted RAR5 padding"));
            }
            padding.skipped += skipped;
            chunk = &chunk[..count];
            if chunk.is_empty() {
                return Ok(());
            }
        }
        if let Some(mem) = self.mem.as_mut() {
            mem.extend_from_slice(chunk);
            self.bytes += chunk.len() as u64;
            return Ok(());
        }
        if !self.decoder_crc {
            self.hasher.update(chunk);
        }
        if let Some(b) = self.blake.as_mut() {
            b.update(chunk);
        }
        if let Some(out) = self.out.as_mut() {
            out.write_detailed(chunk).map_err(|e| e.detailed(false).into_legacy())?;
        }
        self.bytes += chunk.len() as u64;
        Ok(())
    }
}

impl Sink for Pending {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        self.take(bytes)
    }

    fn wants_crc(&self) -> bool {
        self.decoder_crc
    }

    fn crc(&mut self, crc: u32) {
        self.crc = Some(crc);
    }
}

struct RarSelection<'a> {
    sink: &'a mut dyn FnMut(&[u8]) -> Result<()>,
    emit: bool,
    packed_left: u64,
    decoded_left: u64,
    cancel: &'a Cancellation,
}

struct SelectedSink<'p, 's> {
    pending: &'p mut Pending,
    selection: &'p mut RarSelection<'s>,
}

impl Sink for SelectedSink<'_, '_> {
    fn put(&mut self, chunk: &[u8]) -> Result<()> {
        self.selection.cancel.check_io()?;
        let before = self.pending.bytes;
        self.pending.take(chunk)?;
        let count = self.pending.bytes - before;
        self.selection.decoded_left = self
            .selection
            .decoded_left
            .checked_sub(count)
            .ok_or_else(|| Error::Unsupported("RAR5 decoding exceeds the decoded byte limit".into()))?;
        if self.selection.emit && count > 0 {
            (self.selection.sink)(&chunk[..count as usize])?;
        }
        Ok(())
    }

    fn wants_crc(&self) -> bool {
        self.pending.wants_crc()
    }

    fn crc(&mut self, crc: u32) {
        self.pending.crc(crc);
    }
}

/// What a file is checked against once all of it is in.
struct Checks {
    crc32: Option<u32>,
    blake2sp: Option<[u8; 32]>,
    keyed: bool,
    size: Option<u64>,
    meta: Meta,
}

impl From<&FileHeader> for Checks {
    fn from(h: &FileHeader) -> Self {
        Checks {
            crc32: h.crc32,
            blake2sp: h.blake2sp,
            keyed: h.crypt.as_ref().is_some_and(|crypt| crypt.tweaked_crc),
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
    // a CRC the decoder never handed over can't match
    let raw_crc = if p.decoder_crc { p.crc } else { Some(p.hasher.clone().finalize()) };
    let blake = p.blake.take();
    let hash_key = p.hash_key(c.keyed);
    let got_crc = match hash_key {
        Some(key) => raw_crc.map(|crc| crate::crypto::rar5_tweak_crc32(crc, key)),
        None => raw_crc,
    };
    let crc_bad = c.crc32.is_some_and(|want| got_crc != Some(want));
    let blake_bad = match (c.blake2sp, blake) {
        (Some(want), Some(got)) => {
            let digest = got.finish();
            hash_key.map_or(digest, |key| crate::crypto::rar5_tweak_blake2sp(&digest, key)) != want
        }
        (Some(_), None) => {
            p.discard();
            if !p.passive {
                books.fail(&p.name, "its BLAKE2sp hash starts only in a later part, so it can't be checked")?;
            }
            return Ok(());
        }
        _ => false,
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
        out.finish(|file| finish_file(file, &c.meta))?;
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
) -> Route<'a, 'b, R> {
    Route { queued, books }
}

struct Route<'a, 'b, R: FnMut(&str)> {
    queued: &'a mut VecDeque<Queued>,
    books: &'a mut Books<'b, R>,
}

impl<R: FnMut(&str)> Sink for Route<'_, '_, R> {
    fn put(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.is_empty() {
            let Some((p, c)) = self.queued.pop_front() else {
                return Err(Error::Corrupt("more files than were queued"));
            };
            return check_and_finish(self.books, &c, p);
        }
        match self.queued.front_mut() {
            Some((p, _)) => p.take(chunk),
            None => Err(Error::Corrupt("more files than were queued")),
        }
    }

    fn wants_crc(&self) -> bool {
        self.queued.front().is_some_and(|(p, _)| p.wants_crc())
    }

    fn crc(&mut self, crc: u32) {
        if let Some((p, _)) = self.queued.front_mut() {
            p.crc = Some(crc);
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
    selection: Option<RarSelection<'a>>,
}

/// A file finished on another thread, counted and reported as if done here.
fn apply_done(summary: &mut Summary, report: &mut impl FnMut(&str), done: Done) -> Result<()> {
    match done.outcome {
        Outcome::Done(bytes) => {
            summary.files += 1;
            summary.bytes += bytes;
            Ok(())
        }
        Outcome::Failed { reason, legacy: why } => {
            drop(reason);
            let line = format!("{}: {why}", done.name);
            report(&line);
            summary.errors.push(line);
            Ok(())
        }
        Outcome::Fatal(e) => Err(e.into_legacy()),
    }
}

fn rar_run(first: &Path, opts: &Options, password: Option<&str>, report: impl FnMut(&str)) -> Result<Summary> {
    if opts.mode == Mode::Extract {
        fs::create_dir_all(&opts.dest)?;
    }
    let first_volume = Volume::open_detailed(first, password).map_err(crate::error::RarFault::into_legacy)?;
    let mut opts = opts.protecting(first)?;
    if let Cow::Owned(opts) = &mut opts {
        // An end header can request the next volume even if the main header omits the volume flag.
        // Reserve existing consecutive names before any member can replace one.
        let mut next = next_volume(first);
        while let Some(path) = next {
            match path.canonicalize() {
                Ok(canonical) => {
                    opts.protected_paths.insert(canonical);
                    next = next_volume(&path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(e.into()),
            }
        }
    }
    let threads = opts.threads.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    // the hidden size knob is there to test decoding blocks on workers, which batching would bypass
    let threads = if opts.parallel_min.is_some() { 1 } else { threads };
    let mut r = Run::new(&opts, password, report, threads);
    let walked = walk_rar(first_volume, r.password, |vol, block, _| {
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

fn rar_read_at(
    first: &Path,
    chain_start: usize,
    index: usize,
    name: &str,
    password: Option<&str>,
    selection: RarSelection<'_>,
) -> Result<()> {
    let opts = Options {
        mode: Mode::Test,
        dest: PathBuf::new(),
        overwrite: Overwrite::Skip,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    };
    let cancel = selection.cancel;
    let mut run = Run::new(&opts, password, |_: &str| {}, 1);
    run.selection = Some(RarSelection { sink: &mut *selection.sink, ..selection });
    let mut next = 0;
    let mut selected = false;
    let mut prerequisite = false;
    let mut complete = false;
    let volume = Volume::open_with_password(first, run.password)?;
    walk_until(volume, run.password, Some(cancel), |volume, block| {
        let Block::File(header) = block else { return Ok(false) };
        if !header.split_before() {
            if run.pending.is_some() {
                return Err(Error::Truncated);
            }
            selected = next == index;
            prerequisite = (chain_start..index).contains(&next)
                && header.method != 0
                && !header.is_dir()
                && header.redirection.is_none();
            next += 1;
            if selected && (header.name != name || header.is_dir() || header.redirection.is_some()) {
                return Err(Error::Corrupt("RAR5 entry changed since it was selected"));
            }
        }
        if !selected && !prerequisite {
            return Ok(false);
        }
        if header.split_before() && run.pending.is_none() {
            return Err(Error::Truncated);
        }
        if let Some(selection) = &mut run.selection {
            selection.emit = selected;
        }
        let before = run.summary.files;
        run.file_block(volume, &header)?;
        if let Some(error) = run.summary.errors.first() {
            return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error.clone())));
        }
        complete = selected && !header.split_after() && run.summary.files > before && run.pending.is_none();
        Ok(complete)
    })?;
    if !complete {
        return Err(Error::Truncated);
    }
    Ok(())
}

impl<'a, R: FnMut(&str)> Run<'a, R> {
    fn new(opts: &'a Options, password: Option<&'a str>, report: R, threads: usize) -> Self {
        Self {
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
            selection: None,
        }
    }
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
        // stored data is only checked (and written) by the worker; compressed data keeps it busy decoding
        vol.read_fast(h.method == 0);
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
        if !self.goes_to_batch(vol, h) && !self.queueable(vol, h) && !self.beside_batch(vol, h) {
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
        self.pass_over_with_cipher(vol, h, None)
    }

    fn pass_over_with_cipher(&mut self, vol: &mut Volume, h: &FileHeader, cipher: Option<PendingCipher>) -> Result<()> {
        if vol.main.is_solid() && h.method != 0 && (!h.encrypted || cipher.is_some()) {
            let mut p = Pending::new(h);
            p.passive = true;
            p.cipher = cipher;
            return self.begin_decoding(vol, h, p);
        }
        if h.split_after() {
            let mut p = Pending::new(h);
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
        let rel = if self.selection.is_some() {
            PathBuf::new()
        } else {
            match sanitize(&h.name, !h.is_unix()) {
                Ok(rel) => rel,
                Err(e) => {
                    self.fail_in_order(&h.name, &e.to_string())?;
                    return self.pass_over(vol, h);
                }
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
            // An unknown-size stored member has no boundary to distinguish data from alignment padding.
            let stored_padding = (h.method == 0 && !h.size_unknown())
                .then_some(StoredCipherPadding { size: h.unpacked_size, skipped: 0 });
            Some(PendingCipher {
                aes,
                iv: cp.iv,
                rem: Vec::new(),
                hash_key: hk,
                stored_padding,
                blocks: (h.method != 0).then(CipherBlocks::default),
            })
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
                    return self.pass_over_with_cipher(vol, h, cipher);
                }
                Checked::Blocked(why) => {
                    self.fail_in_order(&h.name, why)?;
                    return self.pass_over_with_cipher(vol, h, cipher);
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
        let mut p = Pending::new(h);
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
            && h.dictionary <= u.reach()
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
        // anything else is done in order, after the queued files and what the workers hold; a whole file too big
        // for the workers is decoded here while they finish the ones before it, and reports in order when it fails
        let drained = if self.beside_batch(vol, h) { self.drain_solid() } else { self.drain() };
        if let Err(e) = drained {
            p.discard();
            return Err(e);
        }
        if h.method != 0 {
            let solid_archive = vol.main.is_solid();
            let ready = if h.solid {
                match self.stream.as_mut() {
                    Some(u) if h.dictionary <= u.reach() => {
                        u.next_file(size);
                        Ok(())
                    }
                    _ => Err(NEEDS_EARLIER.to_string()),
                }
            } else {
                match window_for(h.dictionary, size, solid_archive) {
                    Ok(window) if self.selection.is_some() && window.size > RAR_SELECTED_WINDOW_LIMIT => {
                        return Err(Error::Unsupported("RAR5 window exceeds the 256 MiB limit".into()));
                    }
                    Ok(window) => match self.stream.as_mut().filter(|u| u.fits(window)) {
                        Some(u) => {
                            u.restart(window, size);
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
                p.discard();
                self.stream = None;
                if !p.passive {
                    self.fail_in_order(&h.name, &why)?;
                }
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

    /// Whether `h` is a whole compressed file, standing alone, that is decoded on this thread while the workers
    /// finish the files handed to them before it: one too big to hand them. Its reports wait for theirs.
    fn beside_batch(&self, vol: &Volume, h: &FileHeader) -> bool {
        self.threads > 1
            && !vol.main.is_solid()
            && !h.solid
            && h.method != 0
            && h.algorithm == 0
            && !h.encrypted
            && !h.split_before()
            && !h.split_after()
            && h.version.is_none()
            && h.redirection.is_none()
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
            // checked on the worker
            p.decoder_crc = false;
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
        vol.read_fast(false);
        let read = vol.read_data_shared(h.data_at, h.packed_size, |piece, range| {
            let Some(u) = stream.as_mut() else { return Err(Error::Corrupt("no decoder for a queued file")) };
            let r = u.feed_shared(piece, range, &mut route(queued, &mut books));
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
        if let Some(selection) = &mut self.selection {
            selection.cancel.check_io()?;
            selection.packed_left = selection
                .packed_left
                .checked_sub(h.packed_size)
                .ok_or_else(|| Error::Unsupported("RAR5 decoding exceeds the packed byte limit".into()))?;
        }
        // a part's checksums cover only its own packed bytes
        let mut part = crate::crc32::Hasher::new();
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
        // stored data is only checked (and copied) as it comes; compressed data goes to the decoder
        vol.read_fast(self.threads > 1 && !p.compressed && p.cipher.is_none());
        // The decoder needs the pending member as a sink while the framing state is borrowed.
        let mut blocks = p.cipher.as_mut().and_then(|cipher| cipher.blocks.take());
        let read = vol.read_data_shared(h.data_at, h.packed_size, |piece, range| {
            if let Some(selection) = &self.selection {
                selection.cancel.check_io()?;
            }
            let chunk = &piece.bytes()[range.clone()];
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
                let mut selected_sink;
                let sink: &mut dyn Sink = match self.selection.as_mut() {
                    Some(selection) => {
                        selected_sink = SelectedSink { pending: &mut p, selection };
                        &mut selected_sink
                    }
                    None => &mut p,
                };
                match stream.as_mut() {
                    Some(decoder) => blocks
                        .as_mut()
                        .ok_or(Error::Corrupt("missing encrypted block state"))?
                        .feed(to_feed, decoder, sink),
                    None => sink.put(to_feed),
                }
            } else if let Some(selection) = &mut self.selection {
                let mut sink = SelectedSink { pending: &mut p, selection };
                match stream.as_mut() {
                    Some(u) => u.feed_shared(piece, range, &mut sink),
                    None => sink.put(chunk),
                }
            } else {
                match stream.as_mut() {
                    Some(u) => u.feed_shared(piece, range, &mut p),
                    None => p.take(chunk),
                }
            }
        });
        if let Some(cipher) = p.cipher.as_mut() {
            cipher.blocks = blocks;
        }
        // a decoder error is this file's problem; an archive read error ends the run
        let decoded = match read {
            Ok(()) if !split_after => {
                let padding = match p.cipher.as_ref() {
                    Some(cipher) if !cipher.rem.is_empty() => Err(Error::Truncated),
                    Some(cipher) => cipher.blocks.as_ref().map_or(Ok(()), CipherBlocks::finish),
                    None => Ok(()),
                };
                padding.and_then(|()| match stream.as_mut() {
                    Some(u) => match self.selection.as_mut() {
                        Some(selection) => u.finish(&mut SelectedSink { pending: &mut p, selection }),
                        None => u.finish(&mut p),
                    },
                    None => Ok(()),
                })
            }
            Ok(()) => Ok(()),
            Err(e @ (Error::Corrupt(_) | Error::Unsupported(_)))
                if self.selection.is_none() && (p.compressed || p.encrypted) =>
            {
                Err(e)
            }
            Err(e) => {
                p.discard();
                return Err(e);
            }
        };
        if let Err(e) = decoded {
            p.discard();
            if self.selection.is_some() {
                return Err(e);
            }
            if !p.passive {
                self.fail_in_order(&p.name, &e.to_string())?;
            }
            // the stream's state is lost with it
            if split_after {
                self.pending = Some(p);
            }
            return Ok(());
        }
        self.stream = stream.or(self.stream.take());
        if split_after {
            // The hash mode belongs to this part, even though CBC and its derived key span the member.
            let hash_key = p.hash_key(h.crypt.as_ref().is_some_and(|crypt| crypt.tweaked_crc));
            let crc_bad = h.crc32.is_some_and(|want| {
                let crc = part.finalize();
                hash_key.map_or(crc, |key| crate::crypto::rar5_tweak_crc32(crc, key)) != want
            });
            let blake_bad = h.blake2sp.zip(part_blake).is_some_and(|(want, got)| {
                let digest = got.finish();
                hash_key.map_or(digest, |key| crate::crypto::rar5_tweak_blake2sp(&digest, key)) != want
            });
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
        let file = match p.out.take().map(Output::handoff_detailed).transpose() {
            Ok(f) => f,
            Err(e) => {
                p.discard();
                return Err(e.detailed(false).into_legacy());
            }
        };
        let volume_path = vol.path.clone();
        let part = batch::stored_detailed(
            (vol.file(), Some(&volume_path)),
            h.data_at,
            h.packed_size,
            file.as_ref().map(|f| (&f.file, f.target())),
            p.bytes,
            self.threads,
        )
        .map_err(crate::error::RarFault::into_legacy);
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
            if let Err(e) = file.file.seek(SeekFrom::Start(p.bytes)) {
                drop(file);
                p.discard();
                return Err(e.into());
            }
            let left = (!h.size_unknown()).then(|| h.unpacked_size.saturating_sub(p.bytes));
            p.out = Some(Output::resume(file, left));
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
    if let Some(at) = h.mtime.and_then(|seconds| archive_time(seconds, h.nanos)) {
        let _ = out.set_modified(at);
    }
}

/// Converts an archive timestamp with a nonnegative fraction of a second.
pub fn archive_time(seconds: i64, nanos: u32) -> Option<SystemTime> {
    let elapsed = Duration::from_secs(seconds.unsigned_abs());
    let base = if seconds < 0 { UNIX_EPOCH.checked_sub(elapsed) } else { UNIX_EPOCH.checked_add(elapsed) }?;
    base.checked_add(Duration::from_nanos(u64::from(nanos)))
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
    fn encrypted_compressed_framing_bounds_padding_across_chunks() {
        use crate::rar5::testenc::{Op, block};

        let expected = b"cipher padding example";
        let ops: Vec<_> = expected.iter().copied().map(Op::Lit).collect();
        let packed = block(&ops, true, true);
        for piece in [1, 7, packed.len()] {
            let mut decoder = Unpacker::new(window_for(1 << 20, Some(expected.len() as u64), false).unwrap()).unwrap();
            decoder.set_threads(0, u64::MAX);
            decoder.reset(Some(expected.len() as u64));
            let mut sink = Pending::new(&FileHeader::default());
            sink.mem = Some(Vec::new());
            let mut blocks = CipherBlocks::default();

            blocks.feed(&packed[..2], &mut decoder, &mut sink).unwrap();
            assert!(matches!(blocks.finish(), Err(Error::Truncated)));
            for part in packed[2..packed.len() - 1].chunks(piece) {
                blocks.feed(part, &mut decoder, &mut sink).unwrap();
            }
            assert!(matches!(blocks.finish(), Err(Error::Truncated)));
            blocks.feed(&packed[packed.len() - 1..], &mut decoder, &mut sink).unwrap();
            blocks.feed(&[0; 7], &mut decoder, &mut sink).unwrap();
            blocks.feed(&[0; 8], &mut decoder, &mut sink).unwrap();
            blocks.finish().unwrap();
            decoder.finish(&mut sink).unwrap();
            assert_eq!(sink.mem.unwrap(), expected);

            let mut sink = Pending::new(&FileHeader::default());
            assert!(matches!(blocks.feed(&[0], &mut decoder, &mut sink), Err(Error::Corrupt(_))));
        }
    }

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

    #[test]
    fn listing_budget_accepts_exactly_one_million_names() {
        let mut budget = ListingBudget::default();
        for _ in 0..1_000_000 {
            budget.record("name").unwrap();
        }
        assert!(matches!(budget.record("name"), Err(Error::Unsupported(_))));
    }

    #[test]
    fn listing_budget_accepts_exactly_sixty_four_mib_of_names() {
        let mut budget = ListingBudget::default();
        let name = "a".repeat(1 << 20);
        for _ in 0..64 {
            budget.record(&name).unwrap();
        }
        assert!(matches!(budget.record("a"), Err(Error::Unsupported(_))));
    }
}
