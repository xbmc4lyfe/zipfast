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

//! Bounded metadata for a RAR5 volume set. A session owns the read-only
//! files used for its catalogue. Member metadata describes the headers,
//! including any known issue that would prevent reading a payload.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::mem::size_of;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::batch::read_at_detailed;
use crate::error::{
    Error, IoOperation, RarFailure, RarFault, RarIntegrityReason, RarPasswordEvidence, RarResource, RarResult,
    RarScope, RarUnsupported,
};
use crate::extract::{Cancellation, RarRunError, RarRunSummary};
use crate::volume::next_volume;

use super::reader::{Block, Volume, read_failure};
use super::{FileHeader, FileWire, MHFL_VOLNUMBER, MainHeader, MemberCrypt, Redirection};

const MAX_VOLUMES: u64 = 4_096;

/// Independent limits on catalogue work and storage.
#[derive(Clone, Copy, Debug)]
pub struct RarCatalogueLimits {
    /// Retained descriptors, with a maximum of 4,096.
    pub volumes: u64,
    pub entries: u64,
    pub name_bytes: u64,
    pub capacity: u64,
    pub parts: u64,
    pub header_blocks: u64,
    pub read_bytes: u64,
}

impl Default for RarCatalogueLimits {
    fn default() -> Self {
        Self {
            volumes: 64,
            entries: 1_000_000,
            name_bytes: 64 << 20,
            capacity: 128 << 20,
            parts: 1_000_000,
            header_blocks: 2_000_000,
            read_bytes: 512 << 20,
        }
    }
}

/// Options for opening a catalogue.
#[derive(Clone, Default)]
pub struct RarSessionOptions {
    pub limits: RarCatalogueLimits,
    pub cancel: Cancellation,
}

/// Work and retained capacity used when opening the catalogue.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RarCatalogueUsage {
    pub volumes: u64,
    pub entries: u64,
    pub name_bytes: u64,
    pub capacity: u64,
    pub parts: u64,
    pub header_blocks: u64,
    pub read_bytes: u64,
}

/// Summary of a RAR5 catalogue.
#[derive(Debug, Default)]
pub struct RarArchiveMetadata {
    volumes: usize,
    orphan_continuations: u64,
}

impl RarArchiveMetadata {
    pub fn volume_count(&self) -> usize {
        self.volumes
    }

    pub fn orphan_continuations(&self) -> u64 {
        self.orphan_continuations
    }
}

/// Header metadata for an observed volume.
#[derive(Debug)]
pub struct RarVolumeMetadata {
    main: MainHeader,
    encrypted_headers: bool,
}

impl RarVolumeMetadata {
    pub fn flags(&self) -> u64 {
        self.main.flags
    }

    pub fn declared_number(&self) -> Option<u64> {
        (self.main.flags & MHFL_VOLNUMBER != 0).then_some(self.main.volume_number)
    }

    pub fn encrypted_headers(&self) -> bool {
        self.encrypted_headers
    }
}

/// Checksum values declared by a part header. These describe packed bytes
/// for intermediate parts and decoded bytes for a final part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RarChecks {
    pub crc32: Option<u32>,
    pub blake2sp: Option<[u8; 32]>,
    pub keyed: bool,
}

/// Observed data range for one associated part.
#[derive(Clone, Copy)]
pub struct RarPart<'a>(&'a Part);

impl RarPart<'_> {
    /// Zero-based volume position in the session.
    pub fn volume(&self) -> usize {
        self.0.volume
    }

    pub fn data_offset(&self) -> u64 {
        self.0.data_offset
    }

    pub fn packed_size(&self) -> u64 {
        self.0.packed_size
    }

    pub fn checks(&self) -> RarChecks {
        self.0.checks
    }
}

struct Part {
    volume: usize,
    data_offset: u64,
    packed_size: u64,
    checks: RarChecks,
    _crypt: MemberCrypt,
}

/// Borrowed metadata for one logical member, in archive order.
#[derive(Clone, Copy)]
pub struct RarMember<'a> {
    ordinal: u64,
    member: &'a Member,
    parts: &'a [Part],
}

impl<'a> RarMember<'a> {
    pub fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Stored name decoded using the same rules as the RAR5 header parser.
    pub fn name(&self) -> &'a str {
        &self.member.header.name
    }

    pub fn unpacked_size(&self) -> Option<u64> {
        self.member.unpacked_size
    }

    pub fn packed_size(&self) -> u64 {
        self.member.packed_size
    }

    pub fn is_directory(&self) -> bool {
        self.member.header.is_dir()
    }

    pub fn redirection(&self) -> Option<&'a Redirection> {
        self.member.header.redirection.as_ref()
    }

    pub fn version(&self) -> Option<u64> {
        self.member.header.version
    }

    pub fn modified(&self) -> Option<(i64, u32)> {
        let header = &self.member.header;
        header.mtime.map(|seconds| (seconds, header.mtime_nanos))
    }

    pub fn attributes(&self) -> u64 {
        self.member.header.attributes
    }

    pub fn host_os(&self) -> u64 {
        self.member.header.host_os
    }

    pub fn method(&self) -> u8 {
        self.member.header.method
    }

    pub fn algorithm(&self) -> u8 {
        self.member.header.algorithm
    }

    pub fn compression_info(&self) -> u64 {
        self.member.wire.compression
    }

    pub fn dictionary(&self) -> u64 {
        self.member.header.dictionary
    }

    pub fn solid(&self) -> bool {
        self.member.header.solid
    }

    pub fn encrypted(&self) -> bool {
        self.member.header.encrypted
    }

    /// Whether the observed parts include a final header.
    pub fn is_complete(&self) -> bool {
        self.member.complete
    }

    /// First issue discovered in the member's headers that blocks decoding.
    pub fn payload_issue(&self) -> Option<&'a RarFailure> {
        self.member.issue.as_deref()
    }

    pub fn final_checks(&self) -> Option<RarChecks> {
        self.is_complete().then(|| self.parts.last().expect("each member has a part").checks)
    }

    pub fn parts(&self) -> impl ExactSizeIterator<Item = RarPart<'a>> {
        self.parts.iter().map(RarPart)
    }
}

struct Member {
    header: FileHeader,
    wire: FileWire,
    parts: Range<usize>,
    packed_size: u64,
    unpacked_size: Option<u64>,
    complete: bool,
    issue: Option<Box<RarFailure>>,
    _history_barrier: bool,
}

struct HeldVolume {
    metadata: RarVolumeMetadata,
    file: File,
    path: PathBuf,
    stamp: SourceStamp,
}

/// A read-only RAR5 catalogue with the original volume descriptors held open.
pub struct RarSession {
    archive: RarArchiveMetadata,
    volumes: Vec<HeldVolume>,
    members: Vec<Member>,
    parts: Vec<Part>,
    usage: RarCatalogueUsage,
}

impl RarSession {
    /// Read the volume headers and check their source binding. Member
    /// payloads are neither decoded nor checked by catalogue construction.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn open(first: &Path, password: Option<&str>, options: RarSessionOptions) -> Result<Self, RarRunError> {
        let mut catalogue = Catalogue {
            session: Self {
                archive: RarArchiveMetadata::default(),
                volumes: Vec::new(),
                members: Vec::new(),
                parts: Vec::new(),
                usage: RarCatalogueUsage::default(),
            },
            options,
            owned_capacity: 0,
            pending: false,
            history_barrier: false,
        };
        if let Err(fault) = catalogue.scan(first, password) {
            let partial = RarRunSummary {
                encountered: catalogue.session.usage.entries,
                volumes: catalogue.session.usage.volumes,
                ..RarRunSummary::default()
            };
            return Err(RarRunError { partial, entry: None, failure: Arc::from(fault.failure) });
        }
        Ok(catalogue.session)
    }

    pub fn archive(&self) -> &RarArchiveMetadata {
        &self.archive
    }

    pub fn volumes(&self) -> impl ExactSizeIterator<Item = &RarVolumeMetadata> {
        self.volumes.iter().map(|volume| &volume.metadata)
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = RarMember<'_>> {
        self.members.iter().enumerate().map(|(index, member)| RarMember {
            ordinal: index as u64,
            member,
            parts: &self.parts[member.parts.clone()],
        })
    }

    pub fn usage(&self) -> RarCatalogueUsage {
        self.usage
    }
}

struct Catalogue {
    session: RarSession,
    options: RarSessionOptions,
    owned_capacity: u64,
    pending: bool,
    history_barrier: bool,
}

impl Catalogue {
    fn scan(&mut self, first: &Path, password: Option<&str>) -> RarResult<()> {
        if !cfg!(unix) {
            return Err(RarFault::new(
                RarFailure::Unsupported(RarUnsupported::SourceIdentity),
                Error::Unsupported("RAR session source identity unavailable".into()),
            ));
        }
        let mut path = std::path::absolute(first)
            .map_err(|error| RarFault::input(IoOperation::Open, Some(first.to_path_buf()), None, error))?;
        let mut required = None;
        loop {
            check_cancel(&self.options.cancel)?;
            if required == Some(false) {
                match fs::metadata(&path) {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                    Err(error) => return Err(RarFault::input(IoOperation::Metadata, Some(path), None, error)),
                }
            }
            let volumes = add(self.session.usage.volumes, 1)?;
            limit(volumes, self.options.limits.volumes.min(MAX_VOLUMES), RarResource::CatalogueVolumes)?;
            let path_bytes = path.capacity() as u64;
            self.reserve_volume(path_bytes)?;
            let file = match open_read_only(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound && required == Some(true) => {
                    return Err(RarFault::new(
                        RarFailure::MissingVolume { path: path.clone() },
                        Error::MissingVolume(path),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound && required == Some(false) => break,
                Err(error) => return Err(RarFault::input(IoOperation::Open, Some(path), None, error)),
            };
            let stamp = SourceStamp::capture(&file, &path)?;
            if self.session.volumes.iter().any(|v| (v.stamp.device, v.stamp.inode) == (stamp.device, stamp.inode)) {
                return Err(volume_framing(&path, "RAR volume identity repeats"));
            }
            self.owned_capacity = add(self.owned_capacity, path_bytes)?;
            let mut volume = Volume::open_catalogue(&path, file, stamp.len, password, &mut self.scan_budget())?;
            self.session.usage.volumes = volumes;
            let encrypted_headers = volume.encrypted_headers();
            if self.session.volumes.first().is_some_and(|v| v.metadata.encrypted_headers != encrypted_headers) {
                return Err(volume_framing(&path, "RAR volume header encryption changed"));
            }
            let volume_index = self.session.volumes.len();
            let mut next = volume.main.is_volume().then_some(false);
            while let Some((block, crypt, wire)) = volume.next_catalogue(&mut self.scan_budget())? {
                match block {
                    Block::File(header) => {
                        let wire = wire.expect("catalogue file metadata includes the wire name");
                        self.add_part(volume_index, header, crypt, wire)?;
                    }
                    Block::End { more_volumes } => {
                        next = more_volumes.then_some(true);
                        break;
                    }
                    Block::Main(_) | Block::Crypt => return Err(volume_framing(&path, "unexpected RAR volume header")),
                    Block::Service(_) | Block::Unknown => {}
                }
            }
            let metadata = RarVolumeMetadata { main: volume.main.clone(), encrypted_headers };
            let file = volume.into_catalogue_file();
            stamp.check(&file, &path)?;
            let next_path = next.and_then(|_| next_volume(&path));
            self.session.volumes.push(HeldVolume { metadata, file, path, stamp });
            self.update_capacity()?;
            match (next, next_path) {
                (_, Some(next_path)) => {
                    path = next_path;
                    required = next;
                }
                (Some(true), None) => {
                    let path = self.session.volumes.last().unwrap().path.clone();
                    return Err(RarFault::new(
                        RarFailure::UnnamedVolume { path: path.clone() },
                        Error::UnnamedVolume(path),
                    ));
                }
                _ => break,
            }
        }
        self.end_incomplete()?;
        for volume in &self.session.volumes {
            check_cancel(&self.options.cancel)?;
            volume.stamp.check(&volume.file, &volume.path)?;
        }
        check_cancel(&self.options.cancel)?;
        self.session.archive.volumes = self.session.volumes.len();
        Ok(())
    }

    fn scan_budget(&mut self) -> ScanBudget<'_> {
        ScanBudget { cancel: &self.options.cancel, limits: self.options.limits, usage: &mut self.session.usage }
    }

    fn add_part(&mut self, volume: usize, header: FileHeader, crypt: MemberCrypt, wire: FileWire) -> RarResult<()> {
        let parts = add(self.session.usage.parts, 1)?;
        limit(parts, self.options.limits.parts, RarResource::CatalogueParts)?;
        self.session.usage.parts = parts;
        let associated = self.pending
            && header.split_before()
            && self.session.members.last().is_some_and(|member| member.wire.name == wire.name);
        if !associated {
            self.end_incomplete()?;
            if header.split_before() {
                self.session.archive.orphan_continuations = add(self.session.archive.orphan_continuations, 1)?;
                self.history_barrier |= header.method != 0;
                return Ok(());
            }
        }
        let final_part = !header.split_after();
        let part = Part {
            volume,
            data_offset: header.data_at,
            packed_size: header.packed_size,
            checks: RarChecks {
                crc32: header.crc32,
                blake2sp: header.blake2sp,
                keyed: header.crypt.as_ref().is_some_and(|params| params.tweaked_crc),
            },
            _crypt: crypt,
        };
        let ordinal = if associated { self.session.members.len() - 1 } else { self.session.members.len() } as u64;
        let size = (!header.size_unknown()).then_some(header.unpacked_size);
        let issue = if associated {
            let initial = self.session.members.last().unwrap();
            if initial.issue.is_some() {
                None
            } else if (header.method == 0) != (initial.header.method == 0)
                || header.algorithm != initial.header.algorithm
                || header.encrypted != initial.header.encrypted
                || header.is_dir() != initial.header.is_dir()
                || header.redirection != initial.header.redirection
            {
                Some(member_integrity(ordinal, RarIntegrityReason::ChangedContinuationEncoding))
            } else if let (Some(expected), Some(actual)) = (initial.unpacked_size, size)
                && expected != actual
            {
                Some(member_integrity(ordinal, RarIntegrityReason::SplitSizeMismatch { expected, actual }))
            } else {
                payload_issue(&header, crypt, ordinal).or_else(|| {
                    (final_part && header.blake2sp.is_some() && initial.header.blake2sp.is_none())
                        .then(|| member_integrity(ordinal, RarIntegrityReason::DeclaredHashUnavailable))
                })
            }
        } else {
            payload_issue(&header, crypt, ordinal)
        };
        let issue_bytes = issue.as_ref().map_or(0, |_| size_of::<RarFailure>() as u64);
        let part_index = self.session.parts.len();
        if associated {
            let base = add(self.capacity_without::<Part>(self.session.parts.capacity())?, issue_bytes)?;
            reserve_one(&mut self.session.parts, base, self.options.limits.capacity)?;
            self.owned_capacity = add(self.owned_capacity, issue_bytes)?;
            let member = self.session.members.last_mut().unwrap();
            member.parts.end += 1;
            member.packed_size = add(member.packed_size, header.packed_size)?;
            member.unpacked_size = member.unpacked_size.or(size);
            member.complete = final_part;
            if let Some(issue) = issue {
                member.issue = Some(Box::new(issue));
            }
        } else {
            let entries = add(self.session.usage.entries, 1)?;
            limit(entries, self.options.limits.entries, RarResource::CatalogueEntries)?;
            let target = target_name(&header);
            let name_bytes =
                add(add(header.name.len() as u64, wire.name.len() as u64)?, target.map_or(0, |t| t.len() as u64))?;
            let names = add(self.session.usage.name_bytes, name_bytes)?;
            limit(names, self.options.limits.name_bytes, RarResource::CatalogueNameBytes)?;
            let allocation = add(
                add(header.name.capacity() as u64, wire.name.capacity() as u64)?,
                add(target.map_or(0, |t| t.capacity() as u64), issue_bytes)?,
            )?;
            let part_minimum =
                u64::from(self.session.parts.len() == self.session.parts.capacity()) * size_of::<Part>() as u64;
            let base =
                add(add(self.capacity_without::<Member>(self.session.members.capacity())?, allocation)?, part_minimum)?;
            reserve_one(&mut self.session.members, base, self.options.limits.capacity)?;
            let base = add(self.capacity_without::<Part>(self.session.parts.capacity())?, allocation)?;
            reserve_one(&mut self.session.parts, base, self.options.limits.capacity)?;
            self.owned_capacity = add(self.owned_capacity, allocation)?;
            self.session.usage.entries = entries;
            self.session.usage.name_bytes = names;
            let history_barrier = header.method != 0
                && !header.is_dir()
                && header.redirection.is_none()
                && std::mem::take(&mut self.history_barrier);
            self.session.members.push(Member {
                header,
                wire,
                parts: part_index..part_index + 1,
                packed_size: part.packed_size,
                unpacked_size: size,
                complete: final_part,
                issue: issue.map(Box::new),
                _history_barrier: history_barrier,
            });
        }
        self.session.parts.push(part);
        self.pending = !final_part;
        self.update_capacity()
    }

    fn end_incomplete(&mut self) -> RarResult<()> {
        if std::mem::take(&mut self.pending) {
            let index = self.session.members.len() - 1;
            if self.session.members[index].issue.is_none() {
                let extra = size_of::<RarFailure>() as u64;
                limit(add(self.capacity()?, extra)?, self.options.limits.capacity, RarResource::CatalogueCapacity)?;
                self.owned_capacity = add(self.owned_capacity, extra)?;
                self.session.members[index].issue =
                    Some(Box::new(member_integrity(index as u64, RarIntegrityReason::MissingSplitContinuation)));
                self.update_capacity()?;
            }
        }
        Ok(())
    }

    fn reserve_volume(&mut self, path_bytes: u64) -> RarResult<()> {
        let base = add(self.capacity_without::<HeldVolume>(self.session.volumes.capacity())?, path_bytes)?;
        reserve_one(&mut self.session.volumes, base, self.options.limits.capacity)
    }

    fn capacity(&self) -> RarResult<u64> {
        add(
            add(self.owned_capacity, vector_bytes::<HeldVolume>(self.session.volumes.capacity())?)?,
            add(
                vector_bytes::<Member>(self.session.members.capacity())?,
                vector_bytes::<Part>(self.session.parts.capacity())?,
            )?,
        )
    }

    fn capacity_without<T>(&self, count: usize) -> RarResult<u64> {
        Ok(self.capacity()? - vector_bytes::<T>(count)?)
    }

    fn update_capacity(&mut self) -> RarResult<()> {
        let capacity = self.capacity()?;
        limit(capacity, self.options.limits.capacity, RarResource::CatalogueCapacity)?;
        self.session.usage.capacity = capacity;
        Ok(())
    }
}

fn target_name(header: &FileHeader) -> Option<&String> {
    match header.redirection.as_ref()? {
        Redirection::UnixSymlink(name)
        | Redirection::WindowsSymlink(name)
        | Redirection::Junction(name)
        | Redirection::HardLink(name)
        | Redirection::FileCopy(name) => Some(name),
        Redirection::Unknown(_) => None,
    }
}

fn payload_issue(header: &FileHeader, crypt: MemberCrypt, ordinal: u64) -> Option<RarFailure> {
    match crypt {
        Some(Err(error)) => Some(RarFailure::crypt(error, RarScope::Member { index: Some(ordinal) })),
        _ if header.method != 0 && header.algorithm != 0 => {
            Some(RarFailure::Unsupported(RarUnsupported::CompressionAlgorithm {
                algorithm: header.algorithm,
                method: header.method,
            }))
        }
        _ => None,
    }
}

fn member_integrity(ordinal: u64, reason: RarIntegrityReason) -> RarFailure {
    RarFailure::integrity(RarScope::Member { index: Some(ordinal) }, reason, RarPasswordEvidence::NotEncrypted, false)
}

fn volume_framing(path: &Path, reason: &'static str) -> RarFault {
    RarFault::new(
        RarFailure::integrity(
            RarScope::Header { volume: path.to_path_buf() },
            RarIntegrityReason::HeaderFraming(reason),
            RarPasswordEvidence::NotEncrypted,
            false,
        ),
        Error::Corrupt(reason),
    )
}

fn reserve_one<T>(items: &mut Vec<T>, base: u64, allowed: u64) -> RarResult<()> {
    if items.len() < items.capacity() {
        return limit(add(base, vector_bytes::<T>(items.capacity())?)?, allowed, RarResource::CatalogueCapacity);
    }
    let count = items.len().checked_add(1).ok_or_else(RarFault::counter_limit)?;
    let needed = add(base, vector_bytes::<T>(count)?)?;
    limit(needed, allowed, RarResource::CatalogueCapacity)?;
    let slots = (allowed - base) / size_of::<T>() as u64;
    let target = count.max(items.capacity().saturating_mul(2)).min(usize::try_from(slots).unwrap_or(usize::MAX));
    items.try_reserve_exact(target - items.len()).map_err(|_| allocation())?;
    limit(add(base, vector_bytes::<T>(items.capacity())?)?, allowed, RarResource::CatalogueCapacity)
}

fn vector_bytes<T>(count: usize) -> RarResult<u64> {
    (count as u64).checked_mul(size_of::<T>() as u64).ok_or_else(RarFault::counter_limit)
}

fn add(left: u64, right: u64) -> RarResult<u64> {
    left.checked_add(right).ok_or_else(RarFault::counter_limit)
}

pub(super) fn allocation() -> RarFault {
    RarFault::new(
        RarFailure::Limit { resource: RarResource::CatalogueAllocation, requested: None, allowed: None },
        Error::Unsupported("RAR catalogue allocation".into()),
    )
}

fn limit(requested: u64, allowed: u64, resource: RarResource) -> RarResult<()> {
    if requested <= allowed {
        Ok(())
    } else {
        Err(RarFault::new(
            RarFailure::Limit { resource, requested: Some(requested), allowed: Some(allowed) },
            Error::Unsupported("RAR catalogue resource limit".into()),
        ))
    }
}

fn check_cancel(cancel: &Cancellation) -> RarResult<()> {
    if cancel.is_canceled() {
        Err(RarFault::new(RarFailure::Canceled, io::Error::from(io::ErrorKind::Interrupted).into()))
    } else {
        Ok(())
    }
}

pub(super) struct ScanBudget<'a> {
    cancel: &'a Cancellation,
    limits: RarCatalogueLimits,
    usage: &'a mut RarCatalogueUsage,
}

impl ScanBudget<'_> {
    pub(super) fn check(&self) -> RarResult<()> {
        check_cancel(self.cancel)
    }

    pub(super) fn block(&mut self) -> RarResult<()> {
        self.check()?;
        let blocks = add(self.usage.header_blocks, 1)?;
        limit(blocks, self.limits.header_blocks, RarResource::CatalogueBlocks)?;
        self.usage.header_blocks = blocks;
        Ok(())
    }

    pub(super) fn read(&mut self, file: &File, path: &Path, bytes: &mut [u8], at: u64) -> RarResult<()> {
        self.check_read(bytes.len())?;
        self.usage.read_bytes += bytes.len() as u64;
        read_at_detailed(file, bytes, at)
            .map_err(|error| read_failure(error, Some(path.to_path_buf()), RarIntegrityReason::TruncatedHeader))
    }

    pub(super) fn check_read(&self, len: usize) -> RarResult<()> {
        self.check()?;
        let total = add(self.usage.read_bytes, len as u64)?;
        limit(total, self.limits.read_bytes, RarResource::CatalogueReadBytes)
    }
}

fn open_read_only(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    #[cfg(all(test, unix))]
    OPENED.with(|opened| opened.set(opened.get() + 1));
    Ok(file)
}

#[cfg(all(test, unix))]
thread_local! {
    static OPENED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SourceStamp {
    len: u64,
    device: u64,
    inode: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl SourceStamp {
    fn capture(file: &File, path: &Path) -> RarResult<Self> {
        let metadata_error = |error| RarFault::input(IoOperation::Metadata, Some(path.to_path_buf()), None, error);
        let before = Self::from_metadata(file.metadata().map_err(metadata_error)?).map_err(metadata_error)?;
        let bound = Self::from_metadata(fs::metadata(path).map_err(metadata_error)?).map_err(metadata_error)?;
        let after = Self::from_metadata(file.metadata().map_err(metadata_error)?).map_err(metadata_error)?;
        if before != bound || before != after {
            return Err(Self::changed(path));
        }
        Ok(before)
    }

    fn check(self, file: &File, path: &Path) -> RarResult<()> {
        let current = Self::capture(file, path);
        if matches!(&current, Ok(stamp) if *stamp != self) {
            return Err(Self::changed(path));
        }
        current.map(|_| ())
    }

    fn changed(path: &Path) -> RarFault {
        RarFault::new(RarFailure::SourceChanged { path: path.to_path_buf() }, Error::Corrupt("RAR source changed"))
    }

    #[cfg(unix)]
    fn from_metadata(metadata: Metadata) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        if !metadata.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "RAR source is not a regular file"));
        }
        Ok(Self {
            len: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn from_metadata(_: Metadata) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "RAR session source identity unavailable"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn opens_each_volume_once_and_keeps_it_until_drop() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("set.part1.rar");
        let second = dir.path().join("set.part2.rar");
        // CRC-checked main (no flags), end (more and final respectively).
        let main = [0xc5, 0x1a, 0x33, 0x32, 3, 1, 0, 0];
        let more = [0x8f, 0x82, 0x3d, 0x42, 3, 5, 0, 1];
        let end = [0x19, 0xb2, 0x3a, 0x35, 3, 5, 0, 0];
        for (path, tail) in [(&first, more), (&second, end)] {
            fs::write(path, [super::super::SIGNATURE.as_slice(), &main, &tail].concat()).unwrap();
        }
        OPENED.set(0);
        let session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
        assert_eq!(OPENED.get(), 2);
        assert_eq!(session.volumes.len(), 2);
        for (volume, path) in session.volumes.iter().zip([first, second]) {
            assert_eq!(volume.path, path);
            let fd = volume.file.as_raw_fd();
            // SAFETY: F_GETFL queries an open descriptor without additional arguments.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
        }
        drop(session);
    }

    #[test]
    fn checks_the_source_descriptor_against_rebound_and_modified_paths() {
        use std::fs::FileTimes;
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("volume.rar");
        fs::write(&path, b"old").unwrap();
        let held = open_read_only(&path).unwrap();
        let stamp = SourceStamp::capture(&held, &path).unwrap();
        let original_time = held.metadata().unwrap().modified().unwrap();
        let mut output = OpenOptions::new().write(true).open(&path).unwrap();
        output.write_all(b"new").unwrap();
        output.set_times(FileTimes::new().set_modified(original_time)).unwrap();
        let fault = stamp.check(&held, &path).unwrap_err();
        assert!(matches!(fault.failure.as_ref(), RarFailure::SourceChanged { path: changed } if changed == &path));

        let stamp = SourceStamp::capture(&held, &path).unwrap();
        fs::rename(&path, dir.path().join("previous")).unwrap();
        fs::write(&path, b"new").unwrap();
        let fault = stamp.check(&held, &path).unwrap_err();
        assert!(matches!(fault.failure.as_ref(), RarFailure::SourceChanged { path: changed } if changed == &path));
    }
}
