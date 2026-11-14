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

//! Explicitly qualified, bounded other-UID kernel-control entrypoint for Task6.
use super::super::*;
use super::fixture;
use std::cell::Cell;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileExt, PermissionsExt},
};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::rc::Rc;

struct Agent {
    child: Child,
    out: ChildStdout,
}
impl Agent {
    fn start(launcher: &Path, helper: &Path, mode: &str, path: &Path) -> (Self, i32) {
        let mut child = Command::new(launcher)
            .arg(helper)
            .arg(mode)
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let mut agent = Self { child, out };
        let error = agent.status();
        (agent, error)
    }
    fn status(&mut self) -> i32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut bytes = Vec::with_capacity(128);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "qualified agent timeout");
            let mut poll = libc::pollfd { fd: self.out.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.as_millis().max(1).min(i32::MAX as u128) as i32) };
            assert!(ready > 0, "qualified agent failed/timed out");
            let mut byte = [0];
            self.out.read_exact(&mut byte).unwrap();
            if byte[0] == b'\n' {
                break;
            }
            assert!(bytes.len() < 127);
            bytes.push(byte[0]);
        }
        let line = std::str::from_utf8(&bytes).unwrap();
        let mut fields = line.split_whitespace();
        let uid = fields.next().unwrap().parse::<u32>().unwrap();
        let error = fields.next().unwrap().parse::<i32>().unwrap();
        assert!(fields.next().is_none());
        assert_ne!(uid, 0, "a privileged reader cannot qualify denial");
        assert_ne!(
            uid,
            unsafe { libc::geteuid() },
            "launcher must run the first-party agent as a distinct unprivileged UID"
        );
        error
    }
    fn mutate(&mut self) -> i32 {
        self.child.stdin.as_mut().unwrap().write_all(b"w").unwrap();
        self.status()
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn denied(launcher: &Path, helper: &Path, mode: &str, path: &Path, absent: bool) {
    let (_agent, error) = Agent::start(launcher, helper, mode, path);
    if absent {
        assert_eq!(error, libc::ENOENT);
    } else {
        assert!(matches!(error, libc::EACCES | libc::EPERM));
    }
}
/// Run only with an authorized noninteractive launcher (`launcher helper mode
/// path`) and an admitted APFS fixture root whose ancestors are searchable by
/// the other UID. No sudo/mount/credential change is performed by this test.
#[test]
#[ignore = "Task6: needs qualified other-UID launcher and searchable APFS fixture root"]
#[allow(clippy::result_large_err)] // Same fixed inline source/copy terminal evidence under qualification.
fn qualified_mac_other_uid_birth_retained_fd_and_postauth_mutation_control() {
    let launcher = PathBuf::from(std::env::var_os("ZIPFAST_TASK5_OTHER_UID_LAUNCHER").expect("qualified launcher"));
    let base = PathBuf::from(std::env::var_os("ZIPFAST_TASK5_QUALIFIED_ROOT").expect("qualified searchable APFS root"));
    let root = tempfile::Builder::new().prefix("zipfast-other-uid-").tempdir_in(base).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    let helper = root.path().join("agent");
    let compiled = Command::new("cc")
        .args(["-std=c11", "-O2"])
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common/zip_stage_other_uid.c"))
        .arg("-o")
        .arg(&helper)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{}", String::from_utf8_lossy(&compiled.stderr));
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let parent = root.path().join("data");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,write,search,file_inherit,directory_inherit"])
            .arg(&parent)
            .status()
            .unwrap()
            .success()
    );
    let directory = File::open(&parent).unwrap();
    native_policy::backend(directory.as_raw_fd()).unwrap();
    let positive = parent.join("positive");
    let mut ordinary = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&positive).unwrap();
    let (mut retained, error) = Agent::start(&launcher, &helper, "retain-mutate", &positive);
    assert_eq!(error, 0, "positive inherited-ACE open must succeed under actual other UID");
    std::fs::remove_file(&positive).unwrap();
    ordinary.write_all(b"authenticated-positive-capability").unwrap();
    assert_eq!(retained.mutate(), 0);
    let mut changed = [0];
    ordinary.read_at(&mut changed, 0).unwrap();
    assert_eq!(changed, [127]);
    drop(retained);
    // The same typed private-directory birth denies the other UID despite the
    // searchable/inheritable-ACE parent; no plaintext ever enters the empty dir.
    let parent_c = std::ffi::CString::new(parent.as_os_str().as_bytes()).unwrap();
    native_policy::atomic_directory(directory.as_raw_fd(), &parent_c, c"private-directory").unwrap();
    denied(&launcher, &helper, "directory", &parent.join("private-directory"), false);
    std::fs::remove_dir(parent.join("private-directory")).unwrap();
    let plain = vec![b'x'; 65537];
    let frame = super::cipher::framed(1, "pw", &plain);
    let extra = fixture::extra(0x9901, &[2, 0, b'A', b'E', 1, 0, 0]);
    let mut member = fixture::Member::stored(b"entry", &frame);
    member.flags = 1;
    member.method = 99;
    member.central_extra = &extra;
    member.decoded = Some(&plain);
    let bytes = fixture::build(&[member], &[0], b"", b"", false).bytes;
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(&bytes).unwrap();
    let cancel = Cancellation::default();
    let mut session = ProjectedReadSession::open(source.path(), &cancel).unwrap();
    let overrides = EncryptedReadOverrides { temp_dir: Some(parent.clone()), ..Default::default() };
    let mut context = EncryptedReadContext::for_projected(
        &mut session,
        ProjectedReadScope::Entry(0),
        Some(100000),
        ZipReadOutput::VerifiedStdout,
        Some("pw"),
        &overrides,
        &cancel,
    )
    .unwrap();
    let mut out = tempfile::tempfile().unwrap();
    session.admit_output_fd(out.as_fd(), &mut context).unwrap();
    let births = Rc::new(Cell::new(0));
    let count = births.clone();
    let cipher_fd = Rc::new(Cell::new(-1));
    let fd_copy = cipher_fd.clone();
    let cipher_name = Rc::new(std::cell::RefCell::new(None::<PathBuf>));
    let name_copy = cipher_name.clone();
    let launch = launcher.clone();
    let program = helper.clone();
    native_policy::BIRTH_HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |kind, fd, path, leaf| {
            if kind != native_policy::BirthKind::File {
                return None;
            }
            let born = native_policy::atomic_file(fd, path, leaf).unwrap();
            let name = Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()))
                .join(std::ffi::OsStr::from_bytes(leaf.to_bytes()));
            denied(&launch, &program, "read", &name, false);
            denied(&launch, &program, "write", &name, false);
            count.set(count.get() + 1);
            if count.get() == 2 {
                fd_copy.set(born);
                *name_copy.borrow_mut() = Some(name);
            }
            Some(Ok(born))
        }))
    });
    let mut stage = ZipReadStage::prepare_stdout(session.stage_entry(0).unwrap(), &cancel, &mut context).unwrap();
    let seeks = Rc::new(Cell::new(0));
    let seen = seeks.clone();
    let postauth = Rc::new(Cell::new(false));
    let attempted = postauth.clone();
    let launch = launcher.clone();
    let program = helper.clone();
    spool::hooks::HOOK.with(|h| {
        *h.borrow_mut() = Some(Box::new(move |op, fd| {
            if op == ReadIoOperation::Seek && fd == cipher_fd.get() {
                seen.set(seen.get() + 1);
                if seen.get() == 3 {
                    denied(&launch, &program, "write", cipher_name.borrow().as_ref().unwrap(), true);
                    attempted.set(true);
                }
            }
            None
        }))
    });
    session
        .read_at_with_context(0, Some("pw"), 100000, &cancel, &mut context, |b| stage.write_all(b, &cancel))
        .unwrap();
    spool::hooks::HOOK.with(|h| *h.borrow_mut() = None);
    native_policy::BIRTH_HOOK.with(|h| *h.borrow_mut() = None);
    assert_eq!(births.get(), 2);
    assert!(postauth.get(), "actual third owned-file rewind follows HMAC success and precedes decoder consumption");
    assert_eq!(
        stage.copy_verified(&mut out, &cancel, &mut context, |c| session.check_source(c)).unwrap(),
        plain.len() as u64
    );
    let mut actual = vec![0u8; plain.len()];
    out.read_at(&mut actual, 0).unwrap();
    assert_eq!(actual, plain);
    assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
}
