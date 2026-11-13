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

use std::io::Write;
use std::os::unix::fs::MetadataExt;

use crate::error::RarPolicyReason;
use crate::extract::{Meta, Options, Overwrite, RarSkipReason, finish_file, make_dirs_detailed};
use crate::output::{Output, temporary};
use crate::path::sanitize;

use super::*;

impl RarSession {
    /// Extract the selected members in catalogue order. All regular-file
    /// output is staged until verification, and an existing target is
    /// checked again before replacement.
    ///
    /// Uses the destination, overwrite, flatten and protected paths in
    /// `options`. Selected extraction is synchronous. Keep the
    /// destination namespace under caller control during extraction.
    #[allow(clippy::result_large_err, reason = "reuse the typed RAR error with partial counts")]
    pub fn extract_selected(
        &mut self,
        selection: &RarSelection,
        options: &Options,
        limits: RarDecodeLimits,
        on_entry: impl FnMut(&RarEntryOutcome),
    ) -> Result<RarRunSummary, RarRunError> {
        let mut extraction = Extraction::new(options);
        self.execute_selected(selection, limits, |run, session, index| extraction.member(run, session, index), on_entry)
    }
}

struct Extraction<'a> {
    options: &'a Options,
    dirs: Vec<DirectoryOutput>,
}

struct DirectoryOutput {
    path: PathBuf,
    identity: (u64, u64),
    ordinal: usize,
    meta: Meta,
}

impl<'a> Extraction<'a> {
    fn new(options: &'a Options) -> Self {
        Self { options, dirs: Vec::new() }
    }

    fn member(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
    ) -> Result<RarOutcome, Arc<RarFailure>> {
        match self.member_inner(run, session, index) {
            Err(failure) if !is_terminal(&failure) => Ok(RarOutcome::Failed(failure)),
            result => result,
        }
    }

    fn member_inner(
        &mut self,
        run: &mut SelectedRun,
        session: &mut RarSession,
        index: usize,
    ) -> Result<RarOutcome, Arc<RarFailure>> {
        check_cancel(&session.options.cancel).map_err(own_fault)?;
        let member = &session.members[index];
        let header = &member.header;
        if let Some(version) = header.version {
            return Ok(RarOutcome::Skipped(RarSkipReason::OlderVersion(version)));
        }
        if member.issue.is_some() || header.redirection.is_some() {
            return run.test(session, index, None);
        }
        if header.name.contains('\u{fffe}') || std::str::from_utf8(&member.wire.name).is_err() {
            return Err(Arc::new(RarFailure::Unsupported(RarUnsupported::NameEncoding)));
        }
        let relative = sanitize(&header.name, !header.is_unix())
            .map_err(|_| policy(RarPolicyReason::UnsafePath, PathBuf::from(&header.name)))?;
        let meta = Meta::from(header);
        if header.is_dir() {
            let outcome = run.test(session, index, None)?;
            if !self.options.flatten && matches!(outcome, RarOutcome::Directory) {
                let path = self.options.dest.join(&relative);
                self.protect_source_name(session, &path)?;
                self.dirs.try_reserve(1).map_err(|_| own_fault(allocation()))?;
                self.ensure_root().map_err(own_fault)?;
                make_dirs_detailed(&self.options.dest, &relative).map_err(own_fault)?;
                let observed =
                    fs::symlink_metadata(&path).map_err(|source| output_fault(IoOperation::Metadata, &path, source))?;
                if !observed.is_dir() {
                    return Err(policy(RarPolicyReason::TargetChanged, path));
                }
                self.dirs.push(DirectoryOutput {
                    path,
                    identity: (observed.dev(), observed.ino()),
                    ordinal: index,
                    meta,
                });
            }
            return Ok(outcome);
        }
        let parent = relative.parent().expect("sanitized relative path");
        let name = relative.file_name().expect("sanitized relative file");
        let target =
            if self.options.flatten { self.options.dest.join(name) } else { self.options.dest.join(&relative) };
        let parent = if self.options.flatten { Path::new("") } else { parent };
        let initial = self.inspect_target(session, &target)?;
        if initial.is_some() && self.options.overwrite == Overwrite::Skip {
            return Ok(RarOutcome::Skipped(RarSkipReason::ExistingTarget));
        }
        let mut output = None;
        let mut sink = |chunk: &[u8]| {
            if output.is_none() {
                output = Some(self.open_stage(parent, &target)?);
            }
            #[cfg(test)]
            event(Event::Write, &target)
                .map_err(|source| RarFault::output(IoOperation::Write, Some(target.clone()), None, source, false))?;
            output.as_mut().unwrap().write_detailed(chunk).map_err(|error| error.detailed(false))
        };
        let outcome = run.test(session, index, Some(&mut sink))?;
        let RarOutcome::Verified { bytes, checks, .. } = outcome else {
            return Ok(outcome);
        };
        let output = match output {
            Some(output) => output,
            None => self.open_stage(parent, &target).map_err(own_fault)?,
        };
        let mut file = output.handoff_detailed().map_err(|error| own_fault(error.detailed(false)))?;
        #[cfg(test)]
        event(Event::Flush, &target).map_err(|source| output_fault(IoOperation::Flush, &target, source))?;
        file.file.flush().map_err(|source| output_fault(IoOperation::Flush, &target, source))?;
        finish_file(&file.file, &meta);
        let stage_stamp = self.stage_stamp(&file.file, &target)?;
        #[cfg(test)]
        event(Event::BeforePublish, &target).map_err(|source| output_fault(IoOperation::Publish, &target, source))?;

        check_cancel(&session.options.cancel).map_err(own_fault)?;
        let mut sources =
            if session.members[index].header.method != 0 { run.history_volumes } else { [0; VOLUME_WORDS] };
        mark_volumes(&mut sources, &session.parts[session.members[index].parts.clone()]);
        check_volumes(session, &sources)?;
        if self.inspect_target(session, &target)? != initial {
            return Err(policy(RarPolicyReason::TargetChanged, target));
        }
        if self.stage_stamp(&file.file, &target)? != stage_stamp {
            return Err(policy(RarPolicyReason::StageChanged, target));
        }
        file.publish_selected(initial.is_some()).map_err(|error| own_fault(error.detailed(false)))?;
        Ok(RarOutcome::Verified { bytes, checks, output: RarOutput::Written })
    }

    fn ensure_root(&self) -> RarResult<()> {
        let root = &self.options.dest;
        match fs::symlink_metadata(root) {
            Ok(meta) if meta.file_type().is_symlink() => Err(policy_fault(RarPolicyReason::Symlink, root.clone())),
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(policy_fault(RarPolicyReason::ParentIsFile, root.clone())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => fs::create_dir_all(root).map_err(|source| {
                RarFault::output(IoOperation::CreateDirectory, Some(root.clone()), None, source, false)
            }),
            Err(source) => Err(RarFault::output(IoOperation::Metadata, Some(root.clone()), None, source, false)),
        }
    }

    fn inspect_target(&self, session: &RarSession, target: &Path) -> Result<Option<SourceStamp>, Arc<RarFailure>> {
        let Some(parent) = target.parent() else {
            return Err(policy(RarPolicyReason::UnsafePath, target.to_path_buf()));
        };
        self.inspect_parents(parent)?;
        self.protect_source_name(session, target)?;
        let metadata = match fs::symlink_metadata(target) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(output_fault(IoOperation::Metadata, target, source)),
        };
        if metadata.file_type().is_symlink() {
            return Err(policy(RarPolicyReason::Symlink, target.to_path_buf()));
        }
        let identity = (metadata.dev(), metadata.ino());
        if session.volumes.iter().any(|volume| (volume.stamp.device, volume.stamp.inode) == identity)
            || self
                .options
                .protected_paths
                .iter()
                .any(|path| fs::metadata(path).is_ok_and(|other| (other.dev(), other.ino()) == identity))
        {
            return Err(policy(RarPolicyReason::ProtectedInput, target.to_path_buf()));
        }
        if metadata.is_dir() {
            return Err(policy(RarPolicyReason::Directory, target.to_path_buf()));
        }
        let stamp = SourceStamp::from_metadata(metadata)
            .map_err(|source| output_fault(IoOperation::Metadata, target, source))?;
        Ok(Some(stamp))
    }

    fn protect_source_name(&self, session: &RarSession, target: &Path) -> Result<(), Arc<RarFailure>> {
        let absolute =
            std::path::absolute(target).map_err(|source| output_fault(IoOperation::Metadata, target, source))?;
        let target_parent = std::cell::OnceCell::new();
        for source in session.volumes.iter().map(|volume| &volume.path).chain(self.options.protected_paths.iter()) {
            if absolute == *source
                || (target.file_name() == source.file_name()
                    && target_parent
                        .get_or_init(|| absolute.parent().and_then(|parent| fs::canonicalize(parent).ok()))
                        .as_ref()
                        .is_some_and(|parent| {
                            source.parent().and_then(|path| fs::canonicalize(path).ok()).as_ref() == Some(parent)
                        }))
            {
                return Err(policy(RarPolicyReason::ProtectedInput, target.to_path_buf()));
            }
        }
        Ok(())
    }

    fn stage_stamp(&self, file: &File, target: &Path) -> Result<SourceStamp, Arc<RarFailure>> {
        file.metadata()
            .and_then(SourceStamp::from_metadata)
            .map_err(|source| output_fault(IoOperation::Metadata, target, source))
    }

    fn inspect_parents(&self, parent: &Path) -> Result<(), Arc<RarFailure>> {
        let root = &self.options.dest;
        let relative = parent.strip_prefix(root).expect("target is under selected destination");
        let mut path = root.clone();
        for part in std::iter::once(None).chain(relative.components().map(Some)) {
            if let Some(part) = part {
                path.push(part);
            }
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => return Err(policy(RarPolicyReason::Symlink, path)),
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(policy(RarPolicyReason::ParentIsFile, path)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(source) => return Err(output_fault(IoOperation::Metadata, &path, source)),
            }
        }
        Ok(())
    }

    fn open_stage(&self, parent: &Path, target: &Path) -> RarResult<Output> {
        self.ensure_root()?;
        make_dirs_detailed(&self.options.dest, parent)?;
        let stage = temporary(target.parent().expect("target has a parent")).map_err(|source| {
            RarFault::output(IoOperation::CreateFile, Some(target.to_path_buf()), None, source, false)
        })?;
        let (file, path) = stage.into_parts();
        Output::staged_direct(file, path, target.to_path_buf())
            .map_err(|source| RarFault::output(IoOperation::Metadata, Some(target.to_path_buf()), None, source, false))
    }
}

impl Drop for Extraction<'_> {
    fn drop(&mut self) {
        use std::os::unix::fs::OpenOptionsExt;

        use std::cmp::Reverse;

        // Apply metadata once per directory, using the last selected record
        // even when an earlier record would make the directory unreadable.
        self.dirs.sort_unstable_by_key(|entry| (entry.identity, Reverse(entry.ordinal)));
        self.dirs.dedup_by_key(|entry| entry.identity);
        self.dirs.sort_unstable_by_key(|entry| Reverse(entry.path.components().count()));
        for entry in &self.dirs {
            let Some(parent) = entry.path.parent() else { continue };
            if self.inspect_parents(parent).is_err() {
                continue;
            }
            let Ok(dir) = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&entry.path)
            else {
                continue;
            };
            if dir.metadata().is_ok_and(|metadata| (metadata.dev(), metadata.ino()) == entry.identity) {
                finish_file(&dir, &entry.meta);
            }
        }
    }
}

fn policy(reason: RarPolicyReason, path: PathBuf) -> Arc<RarFailure> {
    own_fault(policy_fault(reason, path))
}

fn policy_fault(reason: RarPolicyReason, path: PathBuf) -> RarFault {
    RarFault::new(RarFailure::Policy { reason, path }, Error::Corrupt("selected RAR target refused"))
}

fn own_fault(fault: RarFault) -> Arc<RarFailure> {
    Arc::from(fault.failure)
}

fn output_fault(operation: IoOperation, path: &Path, source: io::Error) -> Arc<RarFailure> {
    own_fault(RarFault::output(operation, Some(path.to_path_buf()), None, source, false))
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum Event {
    Write,
    Flush,
    BeforePublish,
}

#[cfg(test)]
type Hook = Box<dyn FnMut(Event, &Path) -> io::Result<()>>;

#[cfg(test)]
thread_local! {
    static HOOK: std::cell::RefCell<Option<Hook>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn event(event: Event, path: &Path) -> io::Result<()> {
    HOOK.with_borrow_mut(|hook| hook.as_mut().map_or(Ok(()), |hook| hook(event, path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::Mode;
    use crate::rar5::{HEAD_END, HEAD_FILE, HEAD_MAIN, SIGNATURE};

    fn block(bytes: &mut Vec<u8>, body: &[u8], payload: &[u8]) {
        let mut framed = vec![body.len() as u8];
        framed.extend(body);
        bytes.extend(crate::crc32::hash(&framed).to_le_bytes());
        bytes.extend(framed);
        bytes.extend(payload);
    }

    fn archive(more: bool, files: &[(u8, u8)]) -> Vec<u8> {
        let mut bytes = SIGNATURE.to_vec();
        block(&mut bytes, &[HEAD_MAIN as u8, 0, u8::from(more)], &[]);
        for &(name, data) in files {
            let mut body = vec![HEAD_FILE as u8, 2, 1, 4, 1, 0x80, 0x03];
            body.extend(crate::crc32::hash(&[data]).to_le_bytes());
            body.extend([0, 1, 1, name]);
            block(&mut bytes, &body, &[data]);
        }
        block(&mut bytes, &[HEAD_END as u8, 0, u8::from(more)], &[]);
        bytes
    }

    fn options(path: &Path) -> Options {
        Options {
            mode: Mode::Extract,
            dest: path.to_path_buf(),
            overwrite: Overwrite::Always,
            flatten: false,
            threads: None,
            protected_paths: Default::default(),
            parallel_min: None,
        }
    }

    fn with_hook<T>(hook: impl FnMut(Event, &Path) -> io::Result<()> + 'static, run: impl FnOnce() -> T) -> T {
        struct Clear;
        impl Drop for Clear {
            fn drop(&mut self) {
                HOOK.with_borrow_mut(|hook| *hook = None);
            }
        }
        let _clear = Clear;
        HOOK.with_borrow_mut(|stored| *stored = Some(Box::new(hook)));
        run()
    }

    #[test]
    fn replaced_stage_name_is_neither_published_nor_removed() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("archive.rar");
        fs::write(&source, archive(false, &[(b'x', b'n')])).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let target = dest.join("x");
        fs::write(&target, b"old").unwrap();
        let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let moved = dest.join("displaced");
        let displaced = moved.clone();
        let result = with_hook(
            move |event, target| {
                if event == Event::BeforePublish {
                    let stage = fs::read_dir(target.parent().unwrap())?
                        .map(|entry| entry.unwrap().path())
                        .find(|path| path != target)
                        .expect("the same-directory stage");
                    fs::rename(&stage, &displaced)?;
                    fs::write(stage, b"foreign")?;
                }
                Ok(())
            },
            || session.extract_selected(&selection, &options(&dest), RarDecodeLimits::default(), |_| {}).unwrap(),
        );
        assert_eq!((result.files, result.failed), (0, 1));
        assert_eq!(fs::read(&target).unwrap(), b"old");
        assert_eq!(fs::read(&moved).unwrap(), b"n");
        assert!(fs::read_dir(&dest).unwrap().any(|entry| fs::read(entry.unwrap().path()).unwrap() == b"foreign"));
    }

    #[test]
    fn a_later_volume_alias_installed_before_publish_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("set.part1.rar");
        let second = dir.path().join("set.part2.rar");
        let original = archive(false, &[]);
        fs::write(&first, archive(true, &[(b'x', b'n')])).unwrap();
        fs::write(&second, &original).unwrap();
        let target = dir.path().join("x");
        fs::write(&target, b"old").unwrap();
        let mut session = RarSession::open(&first, None, RarSessionOptions::default()).unwrap();
        let selection = session.select(|_| true).unwrap();
        let alias = second.clone();
        let result = with_hook(
            move |event, target| {
                if event == Event::BeforePublish {
                    fs::remove_file(target)?;
                    fs::hard_link(&alias, target)?;
                }
                Ok(())
            },
            || {
                session
                    .extract_selected(&selection, &options(dir.path()), RarDecodeLimits::default(), |event| {
                        assert!(matches!(&event.outcome, RarOutcome::Failed(failure) if matches!(failure.as_ref(),
                            RarFailure::Policy { reason: RarPolicyReason::ProtectedInput, .. }
                        )));
                    })
                    .unwrap()
            },
        );
        assert_eq!((result.files, result.failed), (0, 1));
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read(&second).unwrap(), original);
        assert_eq!(fs::metadata(target).unwrap().ino(), fs::metadata(second).unwrap().ino());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
    }

    #[test]
    fn write_flush_and_publish_errors_keep_prior_output_and_original_target() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("archive.rar");
        fs::write(&source, archive(false, &[(b'a', b'A'), (b'b', b'B')])).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let second = dest.join("b");
        fs::write(&second, b"original").unwrap();
        for (fault, operation) in [
            (Event::Write, IoOperation::Write),
            (Event::Flush, IoOperation::Flush),
            (Event::BeforePublish, IoOperation::Publish),
        ] {
            let mut session = RarSession::open(&source, None, RarSessionOptions::default()).unwrap();
            let selection = session.select(|_| true).unwrap();
            let mut seen = Vec::new();
            let mut terminal = None;
            let failure = with_hook(
                move |event, target| {
                    if event == fault && target.ends_with("b") {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                    Ok(())
                },
                || {
                    session
                        .extract_selected(&selection, &options(&dest), RarDecodeLimits::default(), |event| {
                            seen.push(event.entry.order);
                            if let RarOutcome::Failed(failure) = &event.outcome {
                                terminal = Some(Arc::clone(failure));
                            }
                        })
                        .unwrap_err()
                },
            );
            assert!(matches!(failure.failure.as_ref(),
                RarFailure::Output { operation: actual, path: Some(path), source, .. }
                    if *actual == operation && path == &second && source.raw_os_error() == Some(libc::EIO)
            ));
            assert!(Arc::ptr_eq(&failure.failure, &terminal.unwrap()));
            assert_eq!((failure.partial.files, failure.partial.failed), (1, 1));
            assert_eq!(seen, [0, 1]);
            assert_eq!(fs::read(dest.join("a")).unwrap(), b"A");
            assert_eq!(fs::read(&second).unwrap(), b"original");
            assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
        }
    }
}
