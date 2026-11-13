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

use std::cell::Cell;
use std::cmp::Ordering;
use std::ffi::OsString;
use std::fs::File;
use std::mem::size_of;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

use crate::zip::write::{EntryName, EntryOptions, EntryWritten, Method, WinZipAesRequest};

use super::*;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
#[path = "transaction.rs"]
pub(in crate::zip) mod transaction;
#[path = "unix.rs"]
pub(in crate::zip) mod unix;
#[path = "verify.rs"]
pub(in crate::zip) mod verify;

use unix::{Parent, Stamp};

const STAGE_ATTEMPTS: u64 = 64;

#[derive(Clone, Copy)]
enum NativeEncryption<'a> {
    ZipCrypto(&'a str),
    Aes(&'a WinZipAesRequest<'a>),
}

struct PreparedReceipts {
    common: Vec<EntryWritten>,
    aes_crcs: Option<Vec<u32>>,
}

impl CreateLimits {
    fn directory_entries(&self) -> u64 {
        self.directory.entries.min(self.verification_records / size_of::<zip_container::CentralRecord>() as u64)
    }
}

/// A bounded ordered plan. Dropping it closes retained handles without
/// creating or deleting files.
pub struct CreatePlan {
    parent: Parent,
    options: CreateOptions,
    entries: Vec<PlannedEntry>,
    usage: CreateUsage,
    attempts: Cell<u64>,
    variable_capacity: u64,
}

pub(in crate::zip) struct PlannedEntry {
    pub(in crate::zip) name: Vec<u8>,
    pub(in crate::zip) utf8: bool,
    pub(in crate::zip) comment: Vec<u8>,
    pub(in crate::zip) keys: Option<Vec<u8>>,
    method: Method,
    modified: crate::zip::write::DosDateTime,
    extended_mtime: Option<i32>,
    permissions: crate::zip::write::Permissions,
    pub(in crate::zip) source: Option<Source>,
}

pub(in crate::zip) struct Source {
    pub(in crate::zip) path: PathBuf,
    pub(in crate::zip) stamp: Stamp,
    // Only add_open_file retains a descriptor in the plan.
    pub(in crate::zip) file: Option<File>,
    pub(in crate::zip) directory: bool,
}

impl PlannedEntry {
    pub(in crate::zip) fn options(&self) -> EntryOptions<'_> {
        let name = if self.utf8 {
            EntryName::Utf8(std::str::from_utf8(&self.name).expect("validated UTF-8"))
        } else {
            EntryName::Raw(&self.name)
        };
        EntryOptions {
            name,
            method: self.method,
            modified: self.modified,
            extended_mtime: self.extended_mtime,
            permissions: self.permissions,
            comment: &self.comment,
        }
    }

    fn logical_name(&self) -> &[u8] {
        self.name.strip_suffix(b"/").unwrap_or(&self.name)
    }
}

impl CreatePlan {
    /// Bind the destination parent and validate options. The parent must
    /// already exist. Existing destinations, including symlinks, conflict.
    pub fn new(destination: &Path, options: CreateOptions) -> Result<Self> {
        if options.output_permissions > 0o777 || options.archive_comment.len() > MAX_FIELD {
            return Err(CreateError::InvalidOptions("invalid archive comment length or output permission bits"));
        }
        let mut usage = CreateUsage::default();
        let attempts = Cell::new(0);
        let budget = Attempts::new(&options, &attempts);
        let comment_capacity = options.archive_comment.capacity() as u64;
        let parent_budget = options
            .limits
            .plan_capacity
            .checked_sub(comment_capacity)
            .ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?;
        let parent = Parent::open(destination, &budget, parent_budget)?;
        let variable_capacity = add(parent.capacity(), comment_capacity)?;
        limit(variable_capacity, options.limits.plan_capacity, CreateLimit::PlanCapacity)?;
        usage.plan.capacity = variable_capacity;
        Ok(Self { parent, options, entries: Vec::new(), usage, attempts, variable_capacity })
    }

    /// Admit a regular path source. Its admission handle closes before
    /// return. Publication reopens and checks the original captured stamp.
    pub fn add_file(
        &mut self,
        source: &Path,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        self.admit(metadata, keys, Some((source, None, false)))
    }

    /// Admit and retain a supplied regular file bound to the named path.
    /// Failed admission closes the supplied handle.
    pub fn add_open_file(
        &mut self,
        source: &Path,
        file: File,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        self.admit(metadata, keys, Some((source, Some(file), false)))
    }

    /// Admit an explicit metadata-only Stored directory with a terminal slash.
    pub fn add_directory(&mut self, metadata: EntryOptions<'_>, keys: Option<&CollisionPath>) -> Result<CreateEntryId> {
        self.admit(metadata, keys, None)
    }

    /// Admit directory metadata bound to the source path.
    ///
    /// The plan snapshots the directory at admission and writes the supplied
    /// metadata. Callers that sampled metadata earlier must ensure it still
    /// describes the same directory when this call returns.
    pub fn add_directory_from_path(
        &mut self,
        source: &Path,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        self.admit(metadata, keys, Some((source, None, true)))
    }

    /// Admit directory metadata bound to a held handle and its path.
    ///
    /// The supplied metadata is used as is. See [Self::add_directory_from_path]
    /// for the source snapshot contract.
    pub fn add_open_directory(
        &mut self,
        source: &Path,
        file: File,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
    ) -> Result<CreateEntryId> {
        self.admit(metadata, keys, Some((source, Some(file), true)))
    }

    /// Return current component accounting.
    pub fn usage(&self) -> CreateUsage {
        CreateUsage { transaction_attempts: self.attempts.get(), ..self.usage }
    }

    fn admit(
        &mut self,
        metadata: EntryOptions<'_>,
        keys: Option<&CollisionPath>,
        source: Option<(&Path, Option<File>, bool)>,
    ) -> Result<CreateEntryId> {
        let limits = self.options.limits;
        let ordinal = CreateEntryId(self.entries.len());
        let entries = add(self.usage.plan.entries, 1)?;
        limit(entries, limits.entries, CreateLimit::Entries)?;
        writer_limit(entries, limits.writer.entries, crate::zip::write::Limit::Entries)?;
        limit(entries, limits.directory.entries, CreateLimit::Entries)?;
        limit(entries, limits.directory_entries(), CreateLimit::VerificationRecords)?;
        let held = source.as_ref().is_some_and(|(_, file, _)| file.is_some());
        let retained = add(self.usage.plan.retained_handles, u64::from(held))?;
        limit(retained, limits.retained_handles, CreateLimit::RetainedHandles)?;

        let (scan, metadata_capacity) = input_cost(metadata, keys, source.as_ref().map(|(path, _, _)| *path))?;
        work(&self.options, &mut self.usage.plan, scan)?;
        validate_input(metadata, keys, source.as_ref().is_none_or(|source| source.2), self.options.collisions)?;
        let reserved = entries
            .checked_mul((size_of::<usize>() + size_of::<EntryWritten>()) as u64)
            .ok_or(CreateError::Overflow)?;
        let fixed_min = entries
            .max(self.entries.capacity() as u64)
            .checked_mul(size_of::<PlannedEntry>() as u64)
            .ok_or(CreateError::Overflow)?;
        let remaining = limits
            .plan_capacity
            .checked_sub(add(add(self.variable_capacity, metadata_capacity)?, add(fixed_min, reserved)?)?)
            .ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?;
        let budget = Attempts::new(&self.options, &self.attempts);
        let entry = prepare_input(metadata, keys, source, ordinal, remaining, &budget)?;
        let added = entry.variable_capacity();
        let variable = add(self.variable_capacity, added)?;
        let max_fixed = limits
            .plan_capacity
            .checked_sub(add(variable, reserved)?)
            .ok_or(CreateError::Limit(CreateLimit::PlanCapacity))?;
        let entry_size = size_of::<PlannedEntry>() as u64;
        let capacity = self.entries.capacity() as u64;
        // Rejected admission leaves the already retained allocation intact.
        limit(capacity.max(entries) * entry_size, max_fixed, CreateLimit::PlanCapacity)?;
        if capacity < entries {
            let needed = entries.max(capacity.saturating_mul(2)).min(max_fixed / entry_size);
            self.entries.try_reserve_exact(needed as usize - self.entries.len())?;
        }
        let fixed = self.entries.capacity() as u64 * entry_size;
        limit(fixed, max_fixed, CreateLimit::PlanCapacity)?;
        self.entries.push(entry);
        self.variable_capacity = variable;
        self.usage.plan.entries = entries;
        self.usage.plan.retained_handles = retained;
        self.usage.plan.capacity = variable + fixed;
        Ok(ordinal)
    }

    fn preflight(&mut self, encryption: Option<NativeEncryption<'_>>) -> Result<PreparedReceipts> {
        work(&self.options, &mut self.usage.plan, 0)?;
        let limits = self.options.limits;
        let mut indices = Vec::new();
        indices.try_reserve_exact(self.entries.len())?;
        indices.extend(0..self.entries.len());
        let mut receipts = Vec::new();
        receipts.try_reserve_exact(self.entries.len())?;
        let extra = indices.capacity() as u64 * size_of::<usize>() as u64
            + receipts.capacity() as u64 * size_of::<EntryWritten>() as u64;
        let mut capacity = add(self.usage.plan.capacity, extra)?;
        limit(capacity, limits.plan_capacity, CreateLimit::PlanCapacity)?;
        let mut aes_crcs = None;
        if matches!(encryption, Some(NativeEncryption::Aes(_))) {
            // These existing buffers already overlap even if the additional
            // AES reservation or its validation later refuses the attempt.
            self.usage.plan.capacity = capacity;
            let mut regular = false;
            for entry in &self.entries {
                work(&self.options, &mut self.usage.plan, 1)?;
                if entry.payload_source().is_some() {
                    regular = true;
                    break;
                }
            }
            if regular {
                let needed =
                    (self.entries.len() as u64).checked_mul(size_of::<u32>() as u64).ok_or(CreateError::Overflow)?;
                limit(add(capacity, needed)?, limits.plan_capacity, CreateLimit::PlanCapacity)?;
                #[cfg(test)]
                if tests::event_io(tests::Event::AesCrcReserve, None).is_err() {
                    return Err(CreateError::Allocation(Vec::<u32>::new().try_reserve_exact(usize::MAX).unwrap_err()));
                }
                let mut values = Vec::new();
                values.try_reserve_exact(self.entries.len())?;
                capacity = add(
                    capacity,
                    (values.capacity() as u64).checked_mul(size_of::<u32>() as u64).ok_or(CreateError::Overflow)?,
                )?;
                self.usage.plan.capacity = capacity;
                limit(capacity, limits.plan_capacity, CreateLimit::PlanCapacity)?;
                aes_crcs = Some(values);
            }
        }
        self.usage.plan.capacity = capacity;
        check_hierarchy(&self.entries, &mut indices, &self.options, &mut self.usage.plan, false)?;
        if self.options.collisions == CollisionPolicy::CallerKeys {
            check_hierarchy(&self.entries, &mut indices, &self.options, &mut self.usage.plan, true)?;
        }
        self.check_feasibility(encryption)?;
        Ok(PreparedReceipts { common: receipts, aes_crcs })
    }

    fn check_feasibility(&mut self, encryption: Option<NativeEncryption<'_>>) -> Result<()> {
        use crate::zip::write::Limit as W;
        let options = &self.options;
        let limits = options.limits;
        let encrypted = encryption.is_some();
        writer_limit(limits.writer.central_bytes, isize::MAX as u64, W::CentralBytes)?;
        writer_limit(limits.writer.metadata_capacity, isize::MAX as u64, W::MetadataCapacity)?;
        let mut local = 0;
        let mut central = 0;
        let mut source_bytes = 0;
        let mut decoded = 0;
        let mut backpatch = 0;
        let mut wide = false;
        let mut names = 0;
        let mut comments = options.archive_comment.len() as u64;
        let mut extra = 0;
        // Parent recheck, exclusive stage open and initial stage stat.
        // The clear writer probes the sink three times. The encrypted
        // writer needs one cursor operation. Further work is charged live.
        let mut minimum_attempts =
            add(if encrypted { 5 } else { 7 }, directory_check_attempts(&self.entries, &self.parent)?)?;
        let mut minimum_writer_attempts = 0;
        for entry in &self.entries {
            work(options, &mut self.usage.plan, 1)?;
            let payload = entry.payload_source();
            let size = payload.map_or(0, |source| source.stamp.len);
            let name = entry.name.len() as u64;
            let comment = entry.comment.len() as u64;
            names = add(names, name)?;
            comments = add(comments, comment)?;
            if payload.is_some() {
                // Exact readers need a probe slot, but a successful EOF probe
                // returns zero and leaves that slot available for the next file.
                source_bytes = add(source_bytes, size)?;
                writer_limit(add(source_bytes, 1)?, limits.writer.source_bytes, W::SourceBytes)?;
                writer_limit(size, limits.writer.entry_decoded_bytes, W::EntryDecodedBytes)?;
                limit(size, limits.verification_entry_bytes, CreateLimit::VerificationEntryBytes)?;
                decoded = add(decoded, size)?;
                // Reopen and final path check, or two final checks for a
                // held file. Both modes also seek and check the handle/path
                // before and after the stream, including its EOF probe.
                minimum_attempts = add(minimum_attempts, 10 + size.div_ceil(64 << 10))?;
            }
            if encrypted {
                let (local_bytes, central_bytes, member_wide, writes) = if payload.is_some() {
                    match encryption {
                        Some(NativeEncryption::Aes(request)) => {
                            let (_, strength, variant) = request.parameters();
                            crate::zip::write::exact_winzip_aes_geometry(
                                entry.options(),
                                size,
                                local,
                                strength,
                                variant,
                            )?
                        }
                        _ => crate::zip::write::exact_zipcrypto_geometry(entry.options(), size, local)?,
                    }
                } else {
                    let geometry = crate::zip::write::exact_member_geometry(entry.options(), 0, true, local)?;
                    let writes = 2 + u64::from(entry.extended_mtime.is_some());
                    (geometry.local_bytes, geometry.central_bytes, geometry.wide, writes)
                };
                let reads = if payload.is_some() { 1 + size.div_ceil(64 << 10) } else { 0 };
                minimum_attempts = add(minimum_attempts, writes)?;
                minimum_writer_attempts = add(minimum_writer_attempts, add(writes, reads)?)?;
                wide |= member_wide;
                extra = add(extra, central_bytes - 46 - name - comment)?;
                central = add(central, central_bytes)?;
                local = add(local, local_bytes)?;
                continue;
            }
            let deflate = size != 0 && matches!(entry.method, Method::Deflate(_));
            let sizes = deflate || size >= u32::MAX as u64;
            let offset = local >= u32::MAX as u64;
            wide |= sizes || offset;
            let ut = 9 * u64::from(entry.extended_mtime.is_some());
            let zip64 = 16 * u64::from(sizes) + 8 * u64::from(offset);
            let central_extra = ut + zip64 + 4 * u64::from(zip64 != 0);
            extra = add(extra, central_extra)?;
            central = add(central, 46 + name + comment + central_extra)?;
            local = add(local, 30 + name + ut + 20 * u64::from(sizes))?;
            local = add(local, if deflate { 1 } else { size })?;
            if size != 0 {
                backpatch = add(backpatch, if sizes { 20 } else { 12 })?;
            }
        }
        let eocd = 22 + options.archive_comment.len() as u64;
        let wide_end =
            wide || self.entries.len() >= u16::MAX as usize || central >= u32::MAX as u64 || local >= u32::MAX as u64;
        let extent = add(add(local, central)?, eocd + 76 * u64::from(wide_end))?;
        if encrypted {
            let finish = central.div_ceil(64 << 10) + 2 + u64::from(!options.archive_comment.is_empty());
            minimum_attempts = add(minimum_attempts, finish)?;
            writer_limit(add(minimum_writer_attempts, finish)?, limits.writer.io_attempts, W::IoAttempts)?;
        }
        writer_limit(central, limits.writer.central_bytes, W::CentralBytes)?;
        writer_limit(
            add(central, options.archive_comment.len() as u64)?,
            limits.writer.metadata_capacity,
            W::MetadataCapacity,
        )?;
        writer_limit(extent, limits.writer.archive_extent, W::ArchiveExtent)?;
        writer_limit(add(extent, backpatch)?, limits.writer.output_bytes, W::OutputBytes)?;
        limit(decoded, limits.verification_decoded_bytes, CreateLimit::VerificationDecodedBytes)?;
        // All three passes fetch a bounded EOCD tail. The strict pass
        // also rereads the local range and central extra fields.
        let tail = extent.min(verify::DISCOVERY_TAIL_BYTES);
        let parser_minimum = 3 * tail;
        let verification_minimum = add(add(parser_minimum, local)?, extra)?;
        limit(verification_minimum, limits.verification_read_bytes, CreateLimit::VerificationReadBytes)?;
        limit(tail, limits.verification_scratch, CreateLimit::VerificationScratch)?;
        directory_limit(parser_minimum, limits.directory.fetched_bytes, zip_container::LimitKind::FetchedBytes)?;
        // The parser's exact read/work accounting is enforced while parsing.
        directory_limit(central, limits.directory.directory_bytes, zip_container::LimitKind::DirectoryBytes)?;
        directory_limit(names, limits.directory.name_bytes, zip_container::LimitKind::NameBytes)?;
        directory_limit(comments, limits.directory.comment_bytes, zip_container::LimitKind::CommentBytes)?;
        // The strict parser's variable extra ownership excludes ZIP64, UT and AES.
        // Charge all raw extras to the wrapper's independent metadata ceiling.
        limit(add(add(names, comments)?, extra)?, limits.verification_metadata, CreateLimit::VerificationMetadata)?;
        limit(
            add(self.attempts.get(), minimum_attempts)?,
            limits.transaction_attempts,
            CreateLimit::TransactionAttempts,
        )
    }
}

fn copied(bytes: &[u8]) -> Result<Vec<u8>> {
    #[cfg(test)]
    if tests::event_io(tests::Event::MetadataReserve, None).is_err() {
        let error = Vec::<u8>::new().try_reserve_exact(usize::MAX).unwrap_err();
        return Err(CreateError::Allocation(error));
    }
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(bytes.len())?;
    buffer.extend_from_slice(bytes);
    Ok(buffer)
}

fn absolute(path: &Path, max: u64, budget: &Attempts<'_>) -> Result<PathBuf> {
    let mut base =
        if path.is_absolute() { OsString::new() } else { budget.run(std::env::current_dir)?.into_os_string() };
    let required = add(base.len() as u64, path.as_os_str().len() as u64 + u64::from(!base.is_empty()))?;
    limit(required, max, CreateLimit::PlanCapacity)?;
    base.try_reserve_exact((required - base.len() as u64) as usize)?;
    let mut pathbuf = PathBuf::from(base);
    pathbuf.push(path);
    limit(pathbuf.capacity() as u64, max, CreateLimit::PlanCapacity)?;
    Ok(pathbuf)
}

fn directory_lookup_path(path: PathBuf) -> PathBuf {
    let mut path_bytes = path.into_os_string().into_vec();
    let mut bytes = path_bytes.as_slice();
    // A trailing slash or dot makes lstat follow a symlink in the preceding
    // component. Preserve the rest of the spelling, including interior '..'.
    loop {
        match bytes {
            [.., b'/'] if bytes.len() > 1 => bytes = &bytes[..bytes.len() - 1],
            [.., b'/', b'.'] => bytes = &bytes[..bytes.len() - 1],
            _ => break,
        }
    }
    let len = bytes.len();
    path_bytes.truncate(len);
    PathBuf::from(OsString::from_vec(path_bytes))
}

pub(in crate::zip) fn name_bytes<'a>(name: EntryName<'a>) -> &'a [u8] {
    match name {
        EntryName::Utf8(name) => name.as_bytes(),
        EntryName::Raw(name) => name,
    }
}

fn validate_name(metadata: EntryOptions<'_>, directory: bool) -> Result<usize> {
    let name = name_bytes(metadata.name);
    if name.is_empty() || name.len() > MAX_FIELD || metadata.comment.len() > MAX_FIELD {
        return Err(CreateError::InvalidName("empty name or ZIP metadata exceeds 65,535 bytes"));
    }
    if let EntryName::Utf8(name) = metadata.name
        && (name.chars().any(char::is_control) || std::str::from_utf8(metadata.comment).is_err())
    {
        return Err(CreateError::InvalidName("invalid UTF-8 name or member comment"));
    }
    if name.starts_with(b"/")
        || name.iter().any(|&b| b.is_ascii_control() || b == b'\\')
        || (name.get(1) == Some(&b':') && name[0].is_ascii_alphabetic())
    {
        return Err(CreateError::InvalidName("member name contains absolute path syntax or controls"));
    }
    let logical = if directory {
        if metadata.method != Method::Stored {
            return Err(CreateError::InvalidName("directories must use Stored"));
        }
        name.strip_suffix(b"/").ok_or(CreateError::InvalidName("directory must end with one slash"))?
    } else {
        name
    };
    let mut count = 0;
    for part in logical.split(|&b| b == b'/') {
        if part.is_empty() || matches!(part, b"." | b"..") {
            return Err(CreateError::InvalidName("empty, dot or parent member path component"));
        }
        count += 1;
    }
    Ok(count)
}

fn check_hierarchy(
    entries: &[PlannedEntry],
    indices: &mut [usize],
    options: &CreateOptions,
    usage: &mut PlanUsage,
    keyed: bool,
) -> Result<()> {
    let key = |index: usize| {
        let entry = &entries[index];
        if keyed { entry.keys.as_deref().expect("keys validated during admission") } else { entry.logical_name() }
    };
    // Component ordering places a directory prefix next to all descendants.
    // A fallible heapsort stops immediately when comparison work runs out.
    sort_indices(indices, |a, b| {
        let mut left = Components(key(a));
        let mut right = Components(key(b));
        loop {
            work(options, usage, 1)?;
            match (left.next(options, usage)?, right.next(options, usage)?) {
                (Some(a), Some(b)) => match compare(a, b, options, usage)? {
                    Ordering::Equal => {}
                    unequal => return Ok(unequal),
                },
                (a, b) => return Ok(a.is_some().cmp(&b.is_some())),
            }
        }
    })?;
    for pair in indices.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        let mut left = Components(key(a));
        let mut right = Components(key(b));
        let mut raw_left = Components(entries[a].logical_name());
        let mut raw_right = Components(entries[b].logical_name());
        while let (Some(l), Some(r)) = (left.next(options, usage)?, right.next(options, usage)?) {
            work(options, usage, 1)?;
            if compare(l, r, options, usage)? != Ordering::Equal {
                break;
            }
            let conflict = || CreateError::NameConflict { first: CreateEntryId(a), second: CreateEntryId(b) };
            if left.0.is_empty() && (right.0.is_empty() || entries[a].payload_source().is_some()) {
                return Err(conflict());
            }
            if keyed
                && compare(
                    raw_left.next(options, usage)?.expect("validated component count"),
                    raw_right.next(options, usage)?.expect("validated component count"),
                    options,
                    usage,
                )? != Ordering::Equal
            {
                return Err(conflict());
            }
        }
    }
    Ok(())
}

struct Components<'a>(&'a [u8]);

impl<'a> Components<'a> {
    fn next(&mut self, options: &CreateOptions, usage: &mut PlanUsage) -> Result<Option<&'a [u8]>> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let bytes = self.0;
        for (index, chunk) in bytes.chunks(64).enumerate() {
            work(options, usage, chunk.len() as u64)?;
            if let Some(slash) = chunk.iter().position(|&byte| byte == b'/') {
                let end = index * 64 + slash;
                self.0 = &bytes[end + 1..];
                return Ok(Some(&bytes[..end]));
            }
        }
        self.0 = &[];
        Ok(Some(bytes))
    }
}

fn compare(a: &[u8], b: &[u8], options: &CreateOptions, usage: &mut PlanUsage) -> Result<Ordering> {
    for (left, right) in a.chunks(64).zip(b.chunks(64)) {
        let len = left.len().min(right.len());
        work(options, usage, len as u64 + 1)?;
        let order = left[..len].cmp(&right[..len]);
        if order != Ordering::Equal {
            return Ok(order);
        }
    }
    Ok(a.len().cmp(&b.len()))
}

pub(in crate::zip) fn sort_indices(
    indices: &mut [usize],
    mut order: impl FnMut(usize, usize) -> Result<Ordering>,
) -> Result<()> {
    fn sift(
        heap: &mut [usize],
        mut root: usize,
        order: &mut impl FnMut(usize, usize) -> Result<Ordering>,
    ) -> Result<()> {
        while root < heap.len() / 2 {
            let mut child = root * 2 + 1;
            if child + 1 < heap.len() && order(heap[child], heap[child + 1])? == Ordering::Less {
                child += 1;
            }
            if order(heap[root], heap[child])? != Ordering::Less {
                break;
            }
            heap.swap(root, child);
            root = child;
        }
        Ok(())
    }
    for root in (0..indices.len() / 2).rev() {
        sift(indices, root, &mut order)?;
    }
    for end in (1..indices.len()).rev() {
        indices.swap(0, end);
        sift(&mut indices[..end], 0, &mut order)?;
    }
    Ok(())
}

pub(in crate::zip) fn input_cost(
    metadata: EntryOptions<'_>,
    keys: Option<&CollisionPath>,
    path: Option<&Path>,
) -> Result<(u64, u64)> {
    let name = name_bytes(metadata.name).len() as u64;
    let comment = metadata.comment.len() as u64;
    let key = keys.map_or(0, |keys| keys.0.len()) as u64;
    let scaled = |value: u64, scale| value.checked_mul(scale).ok_or(CreateError::Overflow);
    let scan = add(scaled(name, 4)?, scaled(comment, 2)?)?;
    let path_scan = scaled(path.map_or(0, |path| path.as_os_str().len()) as u64, 3)?;
    Ok((add(add(add(scan, scaled(key, 2)?)?, path_scan)?, 1)?, add(add(name, comment)?, key)?))
}

pub(in crate::zip) fn validate_input(
    metadata: EntryOptions<'_>,
    keys: Option<&CollisionPath>,
    directory: bool,
    policy: CollisionPolicy,
) -> Result<()> {
    let parts = validate_name(metadata, directory)?;
    match (policy, keys) {
        (CollisionPolicy::Exact, None) => Ok(()),
        (CollisionPolicy::CallerKeys, Some(keys)) if keys.0.split(|&b| b == b'/').count() == parts => Ok(()),
        _ => Err(CreateError::InvalidName("collision keys do not match the plan policy or component count")),
    }
}

pub(in crate::zip) fn prepare_input(
    metadata: EntryOptions<'_>,
    keys: Option<&CollisionPath>,
    source: Option<(&Path, Option<File>, bool)>,
    ordinal: CreateEntryId,
    remaining: u64,
    budget: &Attempts<'_>,
) -> Result<PlannedEntry> {
    let source = source
        .map(|(path, file, directory)| -> Result<_> {
            let path = absolute(path, remaining, budget)?;
            let path = if directory { directory_lookup_path(path) } else { path };
            let (file, stamp) = if directory {
                let stamp = unix::directory_stamp(&budget.run(|| std::fs::symlink_metadata(&path))?)?;
                if let Some(file) = &file
                    && unix::directory_stamp(&budget.run(|| file.metadata())?)? != stamp
                {
                    return Err(CreateError::SourceChanged(ordinal));
                }
                (file, stamp)
            } else if let Some(file) = file {
                let stamp = capture(&file, &path, ordinal, budget)?;
                (Some(file), stamp)
            } else {
                let admission = unix::open_source(&path, budget)?;
                let stamp = capture(&admission, &path, ordinal, budget)?;
                drop(admission);
                #[cfg(test)]
                tests::event(tests::Event::AfterAdmissionClose, Some(&path))?;
                (None, stamp)
            };
            Ok(Source { path, stamp, file, directory })
        })
        .transpose()?;
    Ok(PlannedEntry {
        name: copied(name_bytes(metadata.name))?,
        utf8: matches!(metadata.name, EntryName::Utf8(_)),
        comment: copied(metadata.comment)?,
        keys: keys.map(|keys| copied(&keys.0)).transpose()?,
        method: metadata.method,
        modified: metadata.modified,
        extended_mtime: metadata.extended_mtime,
        permissions: metadata.permissions,
        source,
    })
}

impl PlannedEntry {
    pub(in crate::zip) fn payload_source(&self) -> Option<&Source> {
        self.source.as_ref().filter(|source| !source.directory)
    }

    pub(in crate::zip) fn variable_capacity(&self) -> u64 {
        self.name.capacity() as u64
            + self.comment.capacity() as u64
            + self.keys.as_ref().map_or(0, |keys| keys.capacity() as u64)
            + self.source.as_ref().map_or(0, |source| source.path.capacity() as u64)
    }
}

pub(in crate::zip) fn capture(file: &File, path: &Path, id: CreateEntryId, budget: &Attempts<'_>) -> Result<Stamp> {
    let before = unix::file_stamp(file, budget)?;
    let bound = unix::path_stamp(path, budget)?;
    let after = unix::file_stamp(file, budget)?;
    if before != bound || before != after {
        return Err(CreateError::SourceChanged(id));
    }
    Ok(before)
}

pub(in crate::zip) fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or(CreateError::Overflow)
}

pub(in crate::zip) fn limit(value: u64, max: u64, kind: CreateLimit) -> Result<()> {
    if value > max { Err(CreateError::Limit(kind)) } else { Ok(()) }
}

pub(in crate::zip) fn writer_limit(value: u64, max: u64, kind: crate::zip::write::Limit) -> Result<()> {
    if value > max { Err(WriteError::Limit(kind).into()) } else { Ok(()) }
}

fn directory_limit(value: u64, max: u64, kind: zip_container::LimitKind) -> Result<()> {
    if value > max { Err(CreateError::Directory(zip_container::DirectoryError::Limit(kind))) } else { Ok(()) }
}

fn work(options: &CreateOptions, usage: &mut PlanUsage, units: u64) -> Result<()> {
    if options.cancel.is_canceled() {
        return Err(CreateError::Canceled);
    }
    let next = add(usage.work, units)?;
    limit(next, options.limits.plan_work, CreateLimit::PlanWork)?;
    usage.work = next;
    Ok(())
}

#[derive(Clone, Copy)]
pub(in crate::zip) struct Attempts<'a> {
    count: &'a Cell<u64>,
    max: u64,
    cancel: Option<&'a Cancellation>,
    limit: CreateLimit,
}

impl<'a> Attempts<'a> {
    fn new(options: &'a CreateOptions, count: &'a Cell<u64>) -> Self {
        Self::with_limits(&options.cancel, options.limits.transaction_attempts, count)
    }

    pub(in crate::zip) fn with_limits(cancel: &'a Cancellation, max: u64, count: &'a Cell<u64>) -> Self {
        Self { count, max, cancel: Some(cancel), limit: CreateLimit::TransactionAttempts }
    }

    pub(in crate::zip) fn finalization(count: &'a Cell<u64>) -> Self {
        Self { count, max: FINALIZATION_RESERVE, cancel: None, limit: CreateLimit::FinalizationAttempts }
    }

    pub(in crate::zip) fn check_cancel(&self) -> Result<()> {
        if self.cancel.is_some_and(Cancellation::is_canceled) { Err(CreateError::Canceled) } else { Ok(()) }
    }

    pub(in crate::zip) fn charge(&self) -> Result<()> {
        self.check_cancel()?;
        let next = add(self.count.get(), 1)?;
        limit(next, self.max, self.limit)?;
        self.count.set(next);
        Ok(())
    }

    pub(in crate::zip) fn run<T>(&self, mut call: impl FnMut() -> io::Result<T>) -> Result<T> {
        loop {
            self.charge()?;
            match call() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result.map_err(CreateError::from),
            }
        }
    }
}

pub(in crate::zip) fn check_directory_source(
    source: &Source,
    id: CreateEntryId,
    expected: Stamp,
    budget: &Attempts<'_>,
) -> Result<()> {
    let changed = || CreateError::SourceChanged(id);
    let path = budget.run(|| std::fs::symlink_metadata(&source.path)).map_err(|error| match error {
        CreateError::Io(io) if matches!(io.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => changed(),
        other => other,
    })?;
    if unix::directory_stamp(&path).map_err(|_| changed())? != expected {
        return Err(changed());
    }
    if let Some(file) = &source.file
        && unix::directory_stamp(&budget.run(|| file.metadata())?).map_err(|_| changed())? != expected
    {
        return Err(changed());
    }
    Ok(())
}

pub(in crate::zip) fn directory_check_attempts(entries: &[PlannedEntry], parent: &Parent) -> Result<u64> {
    let mut attempts = 0;
    let mut check_parent = false;
    for source in entries.iter().filter_map(|entry| entry.source.as_ref()).filter(|source| source.directory) {
        let is_parent = source.stamp.identity == parent.identity;
        check_parent |= is_parent;
        // Check before staging and before commit. For the stage parent,
        // also check each selected binding against the post-create stamp.
        let checks = 2 + u64::from(is_parent);
        attempts = add(attempts, checks * (1 + u64::from(source.file.is_some())))?;
    }
    add(attempts, u64::from(check_parent))
}

pub(in crate::zip) fn stage_parent_stamp(
    entries: &[PlannedEntry],
    parent: &Parent,
    budget: &Attempts<'_>,
) -> Result<Option<Stamp>> {
    let mut selected = entries.iter().enumerate().filter_map(|(index, entry)| {
        entry.source.as_ref().filter(|s| s.directory && s.stamp.identity == parent.identity).map(|s| (index, s))
    });
    let Some((index, first)) = selected.next() else { return Ok(None) };
    // Stage creation changes the output parent's times and can change its
    // size. After checking the original stamp before stage creation, reset
    // the baseline for those fields here. Identity and mode must still match.
    let stamp = unix::directory_stamp(&budget.run(|| parent.file.metadata())?)?;
    for (index, source) in std::iter::once((index, first)).chain(selected) {
        if stamp.identity != source.stamp.identity || stamp.mode != source.stamp.mode {
            return Err(CreateError::SourceChanged(CreateEntryId(index)));
        }
        check_directory_source(source, CreateEntryId(index), stamp, budget)?;
    }
    Ok(Some(stamp))
}

pub(in crate::zip) fn check_directories(
    entries: &[PlannedEntry],
    parent_stamp: Option<Stamp>,
    budget: &Attempts<'_>,
) -> Result<()> {
    for (index, entry) in entries.iter().enumerate() {
        if let Some(source) = &entry.source
            && source.directory
        {
            let expected = parent_stamp.filter(|stamp| stamp.identity == source.stamp.identity).unwrap_or(source.stamp);
            check_directory_source(source, CreateEntryId(index), expected, budget)?;
        }
    }
    Ok(())
}
