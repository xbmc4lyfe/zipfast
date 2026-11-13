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

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;

use crate::zip::write::{InputLength, IoStage, WriteSummary, WriterOptions, ZipStreamWriter, ZipWriter};

use super::unix::{NameState, PublishError, Stage};
use super::*;

impl CreatePlan {
    /// Publish with actual write receipts for the verified members.
    /// The report reuses the receipts already budgeted for verification.
    /// See [`CreateReport`] for when receipts are available.
    pub fn publish_with_receipts(self) -> CreateReport {
        let mut written = Vec::new();
        let outcome = self.publish_inner(Some(&mut written), None, None);
        CreateReport { outcome, written }
    }

    /// Publish and verify a new archive using traditional ZIP encryption.
    ///
    /// All regular files, including empty ones, use one password. Directories
    /// remain clear. Use a nonempty password of at most 65,535 UTF-8 bytes
    /// without NUL bytes. ZipCrypto is for legacy interoperability and does
    /// not authenticate content. See [`CreateReport`] for receipt semantics.
    pub fn publish_zipcrypto_with_receipts(self, password: &str) -> CreateReport {
        let mut written = Vec::new();
        let outcome = self.publish_inner(Some(&mut written), Some(password), None);
        CreateReport { outcome, written }
    }

    /// Publish with write receipts and a held binding to the verified output.
    /// A missing binding means the destination could not be proved stable
    /// through finalization. Consult the report for the publication outcome.
    pub fn publish_with_bound_receipts(self) -> (CreateReport, Option<PublishedArchiveBinding>) {
        let mut written = Vec::new();
        let mut binding = None;
        let outcome = self.publish_inner(Some(&mut written), None, Some(&mut binding));
        (CreateReport { outcome, written }, binding)
    }

    /// Write and verify a private stage and atomically publish a new archive.
    /// The plan is consumed. Inspect the publication state on failure before
    /// deciding whether another creation attempt is appropriate.
    #[allow(clippy::result_large_err, reason = "creation failures retain component usage and outcome inline")]
    pub fn publish(self) -> std::result::Result<CreatedArchive, CreateFailure> {
        self.publish_inner(None, None, None)
    }

    #[allow(clippy::result_large_err, reason = "creation failures retain component usage and outcome inline")]
    fn publish_inner(
        mut self,
        written: Option<&mut Vec<EntryWritten>>,
        password: Option<&str>,
        binding: Option<&mut Option<PublishedArchiveBinding>>,
    ) -> std::result::Result<CreatedArchive, CreateFailure> {
        if password.is_some_and(|password| {
            password.is_empty() || password.len() > u16::MAX as usize || password.as_bytes().contains(&0)
        }) {
            let cause = CreateError::InvalidOptions("ZIP password must be 1 to 65,535 UTF-8 bytes without NUL");
            return Err(self.failure(Stopped::at(CreateStage::Planning, cause), CleanupState::Clean));
        }
        let mut receipts = match self.preflight(password.is_some()) {
            Ok(receipts) => receipts,
            Err(error) => return Err(self.failure(Stopped::at(CreateStage::Planning, error), CleanupState::Clean)),
        };
        let stage = {
            let budget = Attempts::new(&self.options, &self.attempts);
            if let Err(error) = super::check_directories(&self.entries, None, &budget) {
                return Err(self.failure(Stopped::at(CreateStage::Precommit, error), CleanupState::Clean));
            }
            Stage::create(&self.parent, &budget, &mut self.usage.stage_attempts)
        };
        let mut stage = match stage {
            Ok(stage) => stage,
            Err(error) => return Err(self.failure(Stopped::at(CreateStage::StageCreate, error), CleanupState::Clean)),
        };

        let reserve_count = Cell::new(0);
        let reserve = Attempts::finalization(&reserve_count);
        let binding_count = Cell::new(0);
        let binding_budget = Attempts::finalization(&binding_count);
        let result = self.execute(&mut stage, &mut receipts, password, binding.as_ref().map(|_| &binding_budget));
        if result.is_ok()
            && let Some(written) = written
        {
            *written = receipts;
        } else {
            drop(receipts);
        }
        let publication = result.as_ref().map_or_else(|stop| stop.publication, |_| Publication::Published);
        let aftermath = cleanup(&self.parent, &stage, publication, &reserve);
        let sync =
            if publication == Publication::Published && self.options.durability == Durability::SyncFileAndDirectory {
                unix::sync_directory(&self.parent.file, &reserve)
            } else {
                Ok(())
            };
        if let (Some(binding), Ok(Some(stamp)), Ok(()), Aftermath::Clean) = (binding, &result, &sync, &aftermath) {
            *binding = unix::bound_publication(&self.parent, &stage, *stamp, &binding_budget);
        }
        let cleanup = aftermath.into_public(stage);
        self.usage.finalization_attempts = reserve_count.get() + binding_count.get();
        let summary = self.usage();
        if let Err(stopped) = result {
            return Err(self.failure(stopped, cleanup));
        }
        if let Err(error) = sync {
            return Err(self.failure(Stopped { stage: CreateStage::DirectorySync, cause: error, publication }, cleanup));
        }
        let durability = if self.options.durability == Durability::SyncFileAndDirectory {
            DurabilityState::Synced
        } else {
            DurabilityState::NotRequested
        };
        if !matches!(cleanup, CleanupState::Clean) {
            return Err(CreateFailure {
                stage: CreateStage::Cleanup,
                cause: CreateError::CleanupIncomplete,
                publication,
                durability,
                cleanup,
                summary,
            });
        }
        Ok(CreatedArchive { destination: self.parent.destination, publication, durability, cleanup, summary })
    }

    fn failure(&self, stop: Stopped, cleanup: CleanupState) -> CreateFailure {
        let durability = if self.options.durability == Durability::VisibilityOnly {
            DurabilityState::NotRequested
        } else {
            DurabilityState::Unconfirmed
        };
        CreateFailure {
            stage: stop.stage,
            cause: stop.cause,
            publication: stop.publication,
            durability,
            cleanup,
            summary: self.usage(),
        }
    }

    fn execute(
        &mut self,
        stage: &mut Stage,
        receipts: &mut Vec<EntryWritten>,
        password: Option<&str>,
        binding: Option<&Attempts<'_>>,
    ) -> std::result::Result<Option<Stamp>, Stopped> {
        let attempts = Attempts::new(&self.options, &self.attempts);
        let parent_stamp =
            super::stage_parent_stamp(&self.entries, &self.parent, &attempts).at(CreateStage::Precommit)?;
        let original = unix::file_stamp(&stage.file, &attempts).at(CreateStage::StageCreate)?;
        for (ordinal, entry) in self.entries.iter().enumerate() {
            if self.options.cancel.is_canceled() {
                return Err(Stopped::at(CreateStage::SourceRead, CreateError::Canceled));
            }
            if entry.source.as_ref().is_some_and(|source| source.stamp.identity == original.identity) {
                return Err(Stopped::at(
                    CreateStage::SourceRead,
                    CreateError::SourceAliasesStage(CreateEntryId(ordinal)),
                ));
            }
        }
        let summary = Self::write_stage(
            &self.entries,
            &self.options,
            &mut self.usage.writer,
            (stage, original),
            attempts,
            receipts,
            password,
        )?;
        #[cfg(test)]
        tests::event(tests::Event::AfterFinish, Some(stage.path())).at(CreateStage::Finish)?;
        #[cfg(test)]
        tests::event(tests::Event::BeforeVerify, Some(stage.path())).at(CreateStage::Verify)?;
        let verified = verify::verify_created(
            &mut stage.file,
            (&self.entries, receipts),
            &self.options,
            summary,
            &attempts,
            &mut self.usage.verification,
            |ordinal| {
                let password = password?;
                let source = self.entries[ordinal].payload_source()?;
                Some(verify::ZipCryptoExpectation { password, length: InputLength::Exact(source.stamp.len) })
            },
        )
        .at(CreateStage::Verify)?;
        #[cfg(test)]
        tests::event(tests::Event::AfterVerify, Some(stage.path())).at(CreateStage::Verify)?;
        if unix::file_stamp(&stage.file, &attempts).at(CreateStage::Permissions)? != verified.stamp {
            return Err(Stopped::at(CreateStage::Permissions, CreateError::StageChanged));
        }
        unix::chmod(&stage.file, self.options.output_permissions, &attempts).at(CreateStage::Permissions)?;
        let final_stamp = unix::file_stamp(&stage.file, &attempts).at(CreateStage::Permissions)?;
        if !final_stamp.same_payload(verified.stamp) || final_stamp.mode != self.options.output_permissions {
            return Err(Stopped::at(CreateStage::Permissions, CreateError::StageChanged));
        }
        if self.options.durability == Durability::SyncFileAndDirectory {
            unix::sync_stage(&stage.file, &attempts).at(CreateStage::FileSync)?;
        }
        #[cfg(test)]
        tests::event(tests::Event::BeforeFinalSourceCheck, None).at(CreateStage::Precommit)?;
        super::check_directories(&self.entries, parent_stamp, &attempts).at(CreateStage::Precommit)?;
        for (ordinal, entry) in self.entries.iter().enumerate() {
            if let Some(source) = entry.payload_source() {
                let id = CreateEntryId(ordinal);
                let bound = unix::path_stamp(&source.path, &attempts).at(CreateStage::Precommit)?;
                verify_stamp(source.stamp, bound, id).at(CreateStage::Precommit)?;
                if let Some(file) = &source.file {
                    let held = unix::file_stamp(file, &attempts).at(CreateStage::Precommit)?;
                    verify_stamp(source.stamp, held, id).at(CreateStage::Precommit)?;
                }
            }
        }
        self.parent.check(&attempts).at(CreateStage::Precommit)?;
        let held = unix::file_stamp(&stage.file, &attempts).at(CreateStage::Precommit)?;
        let named = self.parent.lookup(stage.name(), &attempts).at(CreateStage::Precommit)?;
        if held != final_stamp || !matches!(named, Some(NameState::Regular(stamp)) if stamp == held) {
            return Err(Stopped::at(CreateStage::Precommit, CreateError::StageChanged));
        }
        #[cfg(test)]
        tests::event(tests::Event::BeforeCommit, Some(stage.path())).at(CreateStage::Precommit)?;
        self.parent.publish_noreplace(stage.name(), &attempts).map_err(|error| Stopped {
            stage: CreateStage::Publish,
            publication: match error {
                PublishError::Definite(_) => Publication::NotPublished,
                PublishError::Uncertain(_) => Publication::Unknown,
            },
            cause: error.into_cause(),
        })?;
        let bound = binding.and_then(|budget| unix::publication_stamp(stage, held, budget));
        #[cfg(test)]
        let _ = tests::event(tests::Event::AfterCommit, Some(stage.path()));
        Ok(bound)
    }

    fn write_stage<'a>(
        entries: &[PlannedEntry],
        create_options: &'a CreateOptions,
        usage: &mut WriteUsage,
        stage: (&'a Stage, Stamp),
        attempts: Attempts<'a>,
        receipts: &mut Vec<EntryWritten>,
        password: Option<&str>,
    ) -> std::result::Result<WriteSummary, Stopped> {
        let options = WriterOptions {
            comment: &create_options.archive_comment,
            limits: create_options.limits.writer,
            cancel: Some(create_options.cancel.clone()),
        };
        let (stage, original) = stage;
        let mut sink = RawIo::new(&stage.file, attempts);
        let mut writer = if let Some(password) = password {
            if original.len != 0 {
                return Err(Stopped::at(CreateStage::StageCreate, CreateError::StageChanged));
            }
            if attempts.run(|| sink.seek_once(SeekFrom::Start(0))).at(CreateStage::Write)? != 0 {
                return Err(Stopped::at(CreateStage::Write, CreateError::StageChanged));
            }
            StageWriter::Encrypted(
                ZipStreamWriter::new(sink, options).map_err(writer_error).at(CreateStage::Write)?,
                password,
            )
        } else {
            match ZipWriter::new_accounted(sink, options) {
                Ok(writer) => StageWriter::Clear(writer),
                Err((error, partial)) => {
                    *usage = partial;
                    return Err(Stopped::at(CreateStage::Write, writer_error(error)));
                }
            }
        };
        for (ordinal, entry) in entries.iter().enumerate() {
            let receipt = (|| match entry.payload_source() {
                None => writer.add_directory(entry.options()).map_err(writer_error).at(CreateStage::Write),
                Some(source) => {
                    let id = CreateEntryId(ordinal);
                    let reopened = if source.file.is_none() {
                        Some(unix::open_source(&source.path, &attempts).at(CreateStage::SourceRead)?)
                    } else {
                        None
                    };
                    let file = source.file.as_ref().or(reopened.as_ref()).expect("planned source");
                    #[cfg(test)]
                    if reopened.is_some() {
                        tests::event(tests::Event::AfterSourceReopen, Some(&source.path))
                            .at(CreateStage::SourceRead)?;
                    }
                    let current = capture(file, &source.path, id, &attempts).at(CreateStage::SourceRead)?;
                    if current.identity == original.identity {
                        return Err(Stopped::at(CreateStage::SourceRead, CreateError::SourceAliasesStage(id)));
                    }
                    verify_stamp(source.stamp, current, id).at(CreateStage::SourceRead)?;
                    attempts.run(|| (&*file).seek(SeekFrom::Start(0))).at(CreateStage::SourceRead)?;
                    #[cfg(test)]
                    tests::event(tests::Event::BeforeSourceRead, Some(&source.path)).at(CreateStage::SourceRead)?;
                    let mut input = SourceInput::new(file, attempts);
                    let receipt = writer
                        .add_file(entry.options(), &mut input, InputLength::Exact(source.stamp.len), attempts)
                        .map_err(classify_member_error)?;
                    #[cfg(test)]
                    tests::event(tests::Event::AfterSourceRead, Some(&source.path)).at(CreateStage::SourceRead)?;
                    let after = capture(file, &source.path, id, &attempts).at(CreateStage::SourceRead)?;
                    verify_stamp(source.stamp, after, id).at(CreateStage::SourceRead)?;
                    #[cfg(test)]
                    let transient = reopened.is_some();
                    drop(reopened);
                    #[cfg(test)]
                    if transient {
                        tests::event(tests::Event::AfterSourceClose, Some(&source.path)).at(CreateStage::SourceRead)?;
                    }
                    Ok(receipt)
                }
            })();
            *usage = writer.usage();
            receipts.push(receipt?);
        }
        match writer.finish_accounted() {
            Ok(finished) => {
                *usage = finished.summary.usage;
                Ok(finished.summary)
            }
            Err((error, partial)) => {
                *usage = partial;
                Err(Stopped::at(CreateStage::Finish, writer_error(error)))
            }
        }
    }
}

enum StageWriter<'a, 'p> {
    Clear(ZipWriter<RawIo<'a>>),
    Encrypted(ZipStreamWriter<RawIo<'a>>, &'p str),
}

impl<'a> StageWriter<'a, '_> {
    fn add_directory(&mut self, options: EntryOptions<'_>) -> std::result::Result<EntryWritten, WriteError> {
        match self {
            Self::Clear(writer) => writer.add_directory(options),
            Self::Encrypted(writer, _) => writer.add_directory(options),
        }
    }

    fn add_file(
        &mut self,
        options: EntryOptions<'_>,
        input: &mut SourceInput<'_>,
        length: InputLength,
        attempts: Attempts<'_>,
    ) -> std::result::Result<EntryWritten, WriteError> {
        match self {
            Self::Clear(writer) => writer.add_file(options, input, length),
            Self::Encrypted(writer, password) => {
                writer.add_zipcrypto_file(options, input, length, password, |random| {
                    attempts.charge().map_err(into_io)?;
                    #[cfg(test)]
                    tests::event_io(tests::Event::EncryptionEntropy, None)?;
                    getrandom::fill(random).map_err(io::Error::other)
                })
            }
        }
    }

    fn usage(&self) -> WriteUsage {
        match self {
            Self::Clear(writer) => writer.usage(),
            Self::Encrypted(writer, _) => writer.usage(),
        }
    }

    fn finish_accounted(self) -> std::result::Result<crate::zip::write::Finished<RawIo<'a>>, (WriteError, WriteUsage)> {
        match self {
            Self::Clear(writer) => writer.finish_accounted(),
            Self::Encrypted(writer, _) => writer.finish_accounted(),
        }
    }
}

fn classify_member_error(error: WriteError) -> Stopped {
    let stage = match error {
        WriteError::Io { stage: IoStage::SourceRead, .. }
        | WriteError::SizeUnderrun { .. }
        | WriteError::SizeOverrun { .. } => CreateStage::SourceRead,
        _ => CreateStage::Write,
    };
    Stopped::at(stage, writer_error(error))
}

pub(in crate::zip) fn writer_error(error: WriteError) -> CreateError {
    if let WriteError::Io { source, .. } = &error
        && let Some(error) = source.get_ref().and_then(|e| e.downcast_ref::<CreateError>())
    {
        match error {
            CreateError::Canceled => return CreateError::Canceled,
            CreateError::Limit(kind) => return CreateError::Limit(*kind),
            CreateError::Overflow => return CreateError::Overflow,
            _ => {}
        }
    }
    error.into()
}

pub(super) fn verify_stamp(expected: Stamp, actual: Stamp, id: CreateEntryId) -> Result<()> {
    if actual == expected { Ok(()) } else { Err(CreateError::SourceChanged(id)) }
}

pub(in crate::zip) enum Aftermath {
    Clean,
    Foreign,
    Retained,
    Failed(io::Error),
}

impl Aftermath {
    pub(in crate::zip) fn into_public(self, stage: Stage) -> CleanupState {
        match self {
            Self::Clean => CleanupState::Clean,
            Self::Foreign => CleanupState::ForeignStageName { path: stage.into_path() },
            Self::Retained => CleanupState::RetainedOwnedStage { path: stage.into_path() },
            Self::Failed(error) => CleanupState::Failed { path: stage.into_path(), error },
        }
    }
}

pub(in crate::zip) fn cleanup(
    parent: &Parent,
    stage: &Stage,
    publication: Publication,
    budget: &Attempts<'_>,
) -> Aftermath {
    let examine = || -> Result<Aftermath> {
        #[cfg(test)]
        tests::event(tests::Event::BeforeCleanup, Some(stage.path()))?;
        parent.check(budget)?;
        let named = parent.lookup(stage.name(), budget)?;
        let Some(named) = named else { return Ok(Aftermath::Clean) };
        if publication == Publication::Published {
            return Ok(Aftermath::Foreign);
        }
        let held = unix::file_stamp(&stage.file, budget)?;
        if !matches!(named, NameState::Regular(stamp) if stamp.identity == held.identity) {
            return Ok(Aftermath::Foreign);
        }
        if publication == Publication::Unknown {
            return Ok(Aftermath::Retained);
        }
        parent.unlink(stage.name(), budget)?;
        Ok(Aftermath::Clean)
    };
    match examine() {
        Ok(outcome) => outcome,
        Err(CreateError::ParentChanged) => Aftermath::Retained,
        Err(error) => Aftermath::Failed(into_io(error)),
    }
}

struct Stopped {
    stage: CreateStage,
    cause: CreateError,
    publication: Publication,
}

impl Stopped {
    fn at(stage: CreateStage, cause: CreateError) -> Self {
        Self { stage, cause, publication: Publication::NotPublished }
    }
}

trait AtStage<T> {
    fn at(self, stage: CreateStage) -> std::result::Result<T, Stopped>;
}

impl<T> AtStage<T> for Result<T> {
    fn at(self, stage: CreateStage) -> std::result::Result<T, Stopped> {
        self.map_err(|cause| Stopped::at(stage, cause))
    }
}

pub(in crate::zip) struct RawIo<'a> {
    file: &'a File,
    attempts: Attempts<'a>,
    #[cfg(test)]
    position: u64,
    #[cfg(test)]
    rewrite_hooks: bool,
}

impl<'a> RawIo<'a> {
    pub(in crate::zip) fn new(file: &'a File, attempts: Attempts<'a>) -> Self {
        Self {
            file,
            attempts,
            #[cfg(test)]
            position: 0,
            #[cfg(test)]
            rewrite_hooks: false,
        }
    }

    #[cfg(test)]
    pub(in crate::zip) fn with_rewrite_hooks(mut self) -> Self {
        self.rewrite_hooks = true;
        self
    }

    fn charge(&self) -> io::Result<()> {
        self.attempts.charge().map_err(into_io)
    }
}

fn into_io(error: CreateError) -> io::Error {
    match error {
        CreateError::Io(error) | CreateError::DescriptorExhaustion(error) => error,
        other => io::Error::other(other),
    }
}

pub(in crate::zip) struct SourceInput<'a> {
    file: &'a File,
    attempts: Attempts<'a>,
    offset: u64,
}

impl<'a> SourceInput<'a> {
    pub(in crate::zip) fn new(file: &'a File, attempts: Attempts<'a>) -> Self {
        Self { file, attempts, offset: 0 }
    }
}

impl Read for SourceInput<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.attempts.charge().map_err(into_io)?;
        #[cfg(test)]
        tests::event_io(tests::Event::ReadSource, None)?;
        // Positioned reads isolate the stream even when the caller supplied
        // a handle with a shared file-description cursor.
        #[cfg(test)]
        let bytes = {
            let count = bytes.len().min(tests::source_read_cap());
            &mut bytes[..count]
        };
        let count = self.file.read_at(bytes, self.offset)?;
        self.offset = add(self.offset, count as u64).map_err(into_io)?;
        Ok(count)
    }
}

impl Write for RawIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.charge()?;
        #[cfg(test)]
        if self.rewrite_hooks {
            crate::zip::rewrite::test_event(crate::zip::rewrite::Event::Write, None)?;
        }
        #[cfg(test)]
        tests::event_io(
            tests::Event::SinkWrite { at: self.position, signature: bytes.get(..4).map(|b| b.try_into().unwrap()) },
            None,
        )?;
        #[cfg(test)]
        let bytes = &bytes[..bytes.len().min(tests::sink_write_cap())];
        let count = self.file.write(bytes)?;
        #[cfg(test)]
        {
            self.position += count as u64;
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.charge()?;
        #[cfg(test)]
        if self.rewrite_hooks {
            crate::zip::rewrite::test_event(crate::zip::rewrite::Event::Flush, None)?;
        }
        #[cfg(test)]
        tests::event_io(tests::Event::SinkFlush, None)?;
        self.file.flush()
    }
}

impl RawIo<'_> {
    // The seek caller owns attempt accounting and retry policy.
    fn seek_once(&mut self, position: SeekFrom) -> io::Result<u64> {
        #[cfg(test)]
        tests::event_io(tests::Event::SinkSeek, None)?;
        let result = self.file.seek(position)?;
        #[cfg(test)]
        {
            self.position = result;
        }
        Ok(result)
    }
}

impl Seek for RawIo<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.charge()?;
        self.seek_once(position)
    }
}
