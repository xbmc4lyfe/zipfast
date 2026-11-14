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

//! Actual binary source-preservation and checked-policy controls.
#![cfg(any(target_os = "macos", target_os = "linux"))]
use std::fs::{self, OpenOptions};
use std::process::{Command, Stdio};

fn archive() -> Vec<u8> {
    archive_parts(b"hello", 5, 0, 0, &[], crc32fast::hash(b"hello"))
}
fn archive_parts(packed: &[u8], size: u32, method: u16, flags: u16, extra: &[u8], crc: u32) -> Vec<u8> {
    let name = b"a.txt";
    let mut out = Vec::new();
    out.extend_from_slice(&0x04034b50u32.to_le_bytes());
    for v in [20u16, flags, method, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for v in [crc, packed.len() as u32, size] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(extra);
    out.extend_from_slice(packed);
    let start = out.len() as u32;
    out.extend_from_slice(&0x02014b50u32.to_le_bytes());
    for v in [20u16, 20, flags, method, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for v in [crc, packed.len() as u32, size] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for v in [name.len() as u16, extra.len() as u16, 0, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(extra);
    let size = out.len() as u32 - start;
    out.extend_from_slice(&0x06054b50u32.to_le_bytes());
    for v in [0u16, 0, 1, 1] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}
fn aes(bad_tag: bool) -> Vec<u8> {
    use zipfast::zip::write::{
        AesStrength, AesVariant, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions,
        WinZipAesRequest, WriterOptions, ZipStreamWriter,
    };
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let receipt = writer
        .add_winzip_aes_file(
            EntryOptions {
                name: EntryName::Utf8("a.txt"),
                method: Method::Stored,
                modified: DosDateTime::default(),
                extended_mtime: None,
                permissions: Permissions::new(0o644).unwrap(),
                comment: b"",
            },
            &mut &b"hello"[..],
            InputLength::Exact(5),
            WinZipAesRequest::new("pw", AesStrength::Aes128, AesVariant::Ae2).unwrap(),
            |salt| {
                for (i, b) in salt.iter_mut().enumerate() {
                    *b = i as u8 + 1;
                }
                Ok(())
            },
        )
        .unwrap();
    let mut bytes = writer.finish().unwrap().sink;
    if bad_tag {
        let at = receipt.entry.local_offset as usize;
        let name = u16::from_le_bytes(bytes[at + 26..at + 28].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(bytes[at + 28..at + 30].try_into().unwrap()) as usize;
        bytes[at + 30 + name + extra + receipt.entry.packed_size as usize - 1] ^= 1;
    }
    bytes
}

fn alias_case(args: &[&str], stdout: bool, hardlink: bool, corrupt: bool) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    let mut bytes = archive();
    if corrupt {
        bytes[35] ^= 1;
    }
    fs::write(&input, &bytes).unwrap();
    let alias = dir.path().join("alias");
    if hardlink {
        fs::hard_link(&input, &alias).unwrap();
    }
    let sink = OpenOptions::new().append(true).open(if hardlink { &alias } else { &input }).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zipfast"));
    cmd.args(args).arg(&input);
    if stdout {
        cmd.stdout(sink).stderr(Stdio::piped());
    } else {
        cmd.stderr(sink).stdout(Stdio::piped());
    }
    let result = cmd.output().unwrap();
    assert_eq!(fs::read(&input).unwrap(), bytes, "unsafe alias output modified source; status={:?}", result.status);
    assert_eq!(result.status.code(), Some(2));
}
#[test]
fn summary_direct_source_alias_refuses() {
    alias_case(&["t"], false, false, false);
}
#[test]
fn summary_hardlink_source_alias_refuses() {
    alias_case(&["t"], false, true, false);
}
#[test]
fn member_crc_source_alias_refuses() {
    alias_case(&["t", "-q"], false, false, true);
}
#[test]
fn listing_direct_source_alias_refuses() {
    alias_case(&["l"], true, false, false);
}
#[test]
fn listing_hardlink_source_alias_refuses() {
    alias_case(&["v"], true, true, false);
}
#[test]
fn unknown_arg_source_alias_refuses() {
    alias_case(&["t", "-unknown"], false, true, false);
}
#[test]
fn invalid_encrypted_override_is_rejected_before_payload() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    fs::write(&input, archive()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q"])
        .arg(input)
        .env("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", "-1")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn encrypted_fault_and_cap_direct_hardlink_alias_matrix() {
    for hardlink in [false, true] {
        for case in 0..4 {
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input.zip");
            let bytes = if case == 3 {
                archive_parts(b"hello", 6, 0, 0, &[], crc32fast::hash(b"hello"))
            } else {
                aes(case == 1)
            };
            fs::write(&input, &bytes).unwrap();
            let alias = dir.path().join("alias");
            if hardlink {
                fs::hard_link(&input, &alias).unwrap();
            }
            let sink = OpenOptions::new().append(true).open(if hardlink { &alias } else { &input }).unwrap();
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_zipfast"));
            cmd.args(["t", "-q", if case == 0 { "-pwrong" } else { "-ppw" }]).arg(&input).stderr(sink);
            if case == 2 {
                cmd.env("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", "1");
            }
            let result = cmd.output().unwrap();
            assert_eq!(result.status.code(), Some(2));
            assert_eq!(fs::read(input).unwrap(), bytes, "case {case} hardlink{hardlink}");
        }
    }
}
#[test]
fn config_open_parse_and_listing_error_never_append_to_unproved_regular_stderr() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.zip");
        let bytes = if case == 2 || case == 3 { b"PK\x03\x04corrupt".to_vec() } else { archive() };
        fs::write(&input, &bytes).unwrap();
        let sink = OpenOptions::new().append(true).open(&input).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_zipfast"));
        cmd.arg(if case == 3 { "l" } else { "t" })
            .arg(if case == 1 { dir.path().join("missing.zip") } else { input.clone() })
            .stderr(sink);
        if case == 0 {
            cmd.env("ZIPFAST_ZIP_TEMP_BYTES", "-1");
        }
        let result = cmd.output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert_eq!(fs::read(input).unwrap(), bytes);
    }
}
#[test]
fn extraction_diagnostic_aliases_of_future_failed_skipped_and_symlink_targets_refuse() {
    for case in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.zip");
        let bytes =
            if case == 1 { archive_parts(b"hello", 5, 1, 0, &[], crc32fast::hash(b"hello")) } else { archive() };
        fs::write(&input, &bytes).unwrap();
        let dest = dir.path().join("out");
        fs::create_dir(&dest).unwrap();
        let target = dest.join("a.txt");
        let original = b"preserve target";
        let diagnostic = if case == 3 {
            let referent = dir.path().join("diagnostic");
            fs::write(&referent, original).unwrap();
            std::os::unix::fs::symlink(&referent, &target).unwrap();
            referent
        } else {
            fs::write(&target, original).unwrap();
            target.clone()
        };
        let sink = OpenOptions::new().append(true).open(&diagnostic).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
            .args(["x", if case == 2 { "-o-" } else { "-o+" }])
            .arg(&input)
            .arg(&dest)
            .stderr(sink)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert_eq!(fs::read(&input).unwrap(), bytes);
        assert_eq!(fs::read(diagnostic).unwrap(), original);
    }
}
#[test]
fn admitted_listing_normal_text_and_regular_summary_after_source_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    let bytes = archive();
    fs::write(&input, &bytes).unwrap();
    let listed = Command::new(env!("CARGO_BIN_EXE_zipfast")).arg("l").arg(&input).output().unwrap();
    assert!(listed.status.success());
    let expected = format!(
        "{:>14} {:>14} {:>8} {:>6}  name\n{:>14} {:>14} {:>8} {:>6}  a.txt\n",
        "size", "packed", "crc32", "method", 5, 5, "3610a686", "m0"
    );
    assert_eq!(listed.stdout, expected.as_bytes());
    let diag = dir.path().join("summary");
    let sink = OpenOptions::new().write(true).create_new(true).open(&diag).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast")).arg("t").arg(&input).stderr(sink).output().unwrap();
    assert!(result.status.success());
    assert!(fs::read_to_string(diag).unwrap().starts_with("1 files, 0 folders,"));
    assert_eq!(fs::read(input).unwrap(), bytes);
}
#[test]
fn quiet_retains_skip_and_member_diagnostics_and_statuses() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    fs::write(&input, archive()).unwrap();
    let dest = dir.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("a.txt"), b"old").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast")).args(["x", "-q"]).arg(&input).arg(&dest).output().unwrap();
    assert!(result.status.success());
    assert_eq!(result.stderr, b"a.txt: exists, skipped\n");
    fs::write(&input, aes(false)).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast")).args(["t", "-q", "-pwrong"]).arg(input).output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stderr, b"a.txt: corrupt archive: wrong password or damaged AES stream\n");
}

#[test]
fn override_unsigned_overflow_matrix_and_long_password_no_default_65535_cap() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    fs::write(&input, aes(false)).unwrap();
    for (key, value) in [
        ("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", "18446744073709551616"),
        ("ZIPFAST_ZIP_TEMP_BYTES", "340282366920938463463374607431768211456"),
        ("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", "+1"),
        ("ZIPFAST_ZIP_TEMP_BYTES", " 1"),
    ] {
        let result =
            Command::new(env!("CARGO_BIN_EXE_zipfast")).args(["t", "-q"]).arg(&input).env(key, value).output().unwrap();
        assert_eq!(result.status.code(), Some(2));
    }
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q"])
        .arg(format!("-p{}", "p".repeat(70_000)))
        .arg(input)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(result.stderr, b"a.txt: corrupt archive: wrong password or damaged AES stream\n");
}

#[test]
fn actual_binary_socket_write_failure_has_no_listing_fallback() {
    use std::os::fd::OwnedFd;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    let bytes = archive();
    fs::write(&input, &bytes).unwrap();
    let (out, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(peer);
    let fd: OwnedFd = out.into();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .arg("l")
        .arg(&input)
        .stdout(Stdio::from(fd))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stderr.is_empty());
    assert_eq!(fs::read(input).unwrap(), bytes);
}
#[test]
fn actual_binary_safe_socket_tty_fifo_and_nonterminal_character() {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    fn line(reader: &mut std::fs::File) -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut bytes = [0; 512];
        let mut n = 0;
        while !bytes[..n].contains(&b'\n') {
            assert!(n < bytes.len(), "native diagnostic exceeds fixture bound");
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!left.is_zero(), "native diagnostic exceeded five-second fixture deadline");
            let mut poll = libc::pollfd { fd: reader.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll, 1, left.as_millis().clamp(1, 5000) as i32) };
            if ready < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            assert!(ready > 0, "native diagnostic poll failed or timed out");
            let read = reader.read(&mut bytes[n..]).unwrap();
            assert_ne!(read, 0, "native diagnostic ended before newline");
            n += read;
        }
        bytes[..n].to_vec()
    }
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    let bytes = aes(false);
    fs::write(&input, &bytes).unwrap();
    let (out, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd: OwnedFd = out.into();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q", "-pwrong"])
        .arg(&input)
        .stderr(Stdio::from(fd))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let mut text = Vec::new();
    peer.read_to_end(&mut text).unwrap();
    assert_eq!(text, b"a.txt: corrupt archive: wrong password or damaged AES stream\n");
    let mut master = -1;
    let mut slave = -1;
    assert_eq!(
        unsafe {
            libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
        },
        0
    );
    // Fixture-only descriptors must not leak through exec outside explicit Stdio.
    for fd in [master, slave] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) }, 0);
    }
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let child_slave = slave.try_clone().unwrap();
    assert_ne!(unsafe { libc::fcntl(child_slave.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q", "-pwrong"])
        .arg(&input)
        // Keep the parent's slave open until the bounded line is drained:
        // Darwin may discard unread master data when the last slave closes.
        .stderr(child_slave)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&line(&mut master)).contains("wrong password"));
    drop(slave);
    let path = std::ffi::CString::new(dir.path().join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) };
    assert!(fd >= 0);
    let mut reader = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = OpenOptions::new().write(true).open(dir.path().join("fifo")).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q", "-pwrong"])
        .arg(&input)
        .stderr(writer)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&line(&mut reader)).contains("wrong password"));
    let null = OpenOptions::new().write(true).open("/dev/null").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["t", "-q", "-pwrong"])
        .arg(&input)
        .stderr(null)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(fs::read(input).unwrap(), bytes);
}
#[test]
fn unused_source_aliased_stdout_does_not_reject_stderr_only_test() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.zip");
    let bytes = archive();
    fs::write(&input, &bytes).unwrap();
    let unused = OpenOptions::new().append(true).open(&input).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast")).arg("t").arg(&input).stdout(unused).output().unwrap();
    assert!(result.status.success());
    assert_eq!(fs::read(input).unwrap(), bytes);
}

#[test]
fn empty_destination_keeps_original_cwd_target_diagnostic_proof() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.zip");
    let bytes = archive();
    fs::write(&input, &bytes).unwrap();
    let target = root.path().join("a.txt");
    fs::write(&target, b"original").unwrap();
    let diagnostic = OpenOptions::new().append(true).open(&target).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["x", "-o+"])
        .arg(&input)
        .arg("")
        .current_dir(root.path())
        .stderr(diagnostic)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(fs::read(input).unwrap(), bytes);
    assert_eq!(fs::read(target).unwrap(), b"original");
}

#[test]
fn r1_missing_password_existing_target_is_member_failure_even_quiet() {
    for quiet in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input.zip");
        let bytes = aes(false);
        fs::write(&input, &bytes).unwrap();
        let dest = root.path().join("out");
        fs::create_dir(&dest).unwrap();
        fs::write(dest.join("a.txt"), b"original").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_zipfast"));
        command.arg("x");
        if quiet {
            command.arg("-q");
        }
        let result = command.arg(&input).arg(&dest).output().unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains("password required"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("skip"));
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"original");
        assert_eq!(fs::read(input).unwrap(), bytes);
    }
}

#[test]
fn r1_provided_wrong_password_keeps_existing_target_skip() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("input.zip");
    let bytes = aes(false);
    fs::write(&input, &bytes).unwrap();
    let dest = root.path().join("out");
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("a.txt"), b"original").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
        .args(["x", "-q", "-pwrong"])
        .arg(&input)
        .arg(&dest)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stderr, b"a.txt: exists, skipped\n");
    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"original");
    assert_eq!(fs::read(input).unwrap(), bytes);
}

// The launcher has no format-specific heuristic: discovery must use the same
// held-file RAR probe and central ZIP parser as checked selected reads.
fn sfx_aes() -> Vec<u8> {
    let mut bytes = b"MZ tiny SFX launcher\r\n".to_vec();
    bytes.extend(aes(false));
    bytes
}
#[test]
fn r2_prefixed_zip_cli_caps_and_source_aliases() {
    for prefixed in [false, true] {
        let bytes = if prefixed { sfx_aes() } else { aes(false) };
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("archive.bin");
        fs::write(&input, &bytes).unwrap();
        for cap in [0, 24, 25] {
            let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
                .args(["t", "-ppw", "-q"])
                .arg(&input)
                .env("ZIPFAST_ZIP_ENCRYPTED_MAX_BYTES", cap.to_string())
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(if cap == 25 { 0 } else { 1 }),
                "prefix={prefixed} max={cap}: {result:?}"
            );
        }
        for cap in [0, 4, 1024] {
            let dest = dir.path().join(format!("out-{cap}"));
            let result = Command::new(env!("CARGO_BIN_EXE_zipfast"))
                .args(["x", "-ppw", "-q"])
                .arg(&input)
                .arg(&dest)
                .env("ZIPFAST_ZIP_TEMP_BYTES", cap.to_string())
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(if cap == 1024 { 0 } else { 2 }),
                "prefix={prefixed} temp={cap}: {result:?}"
            );
            if cap == 1024 {
                assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"hello");
            } else {
                assert!(!dest.join("a.txt").exists());
            }
        }
        for command in ["t", "l", "v"] {
            for hardlink in [false, true] {
                let alias = dir.path().join(format!("alias-{command}-{hardlink}"));
                if hardlink {
                    fs::hard_link(&input, &alias).unwrap();
                }
                let sink = OpenOptions::new().append(true).open(if hardlink { &alias } else { &input }).unwrap();
                let mut cmd = Command::new(env!("CARGO_BIN_EXE_zipfast"));
                cmd.args([command, "-ppw"]).arg(&input);
                if command == "t" {
                    cmd.stderr(sink);
                } else {
                    cmd.stdout(sink);
                }
                let result = cmd.output().unwrap();
                assert_eq!(result.status.code(), Some(2), "{command} prefix={prefixed} hardlink={hardlink}");
                assert_eq!(fs::read(&input).unwrap(), bytes);
            }
        }
    }
}
#[test]
fn r2_prefixed_zip_public_policy_context_and_selected_caps() {
    use zipfast::extract::{self, Cancellation, Mode, Options, Overwrite, SelectedEntry};
    use zipfast::zip::{
        EncryptedReadContext, EncryptedReadLimits, EncryptedReadOptions, EncryptedReadOverrides, ZipRunEvent,
    };
    for prefixed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("archive.bin");
        let bytes = if prefixed { sfx_aes() } else { aes(false) };
        fs::write(&input, &bytes).unwrap();
        let opts = Options {
            mode: Mode::Test,
            dest: dir.path().join("unused"),
            overwrite: Overwrite::Skip,
            flatten: false,
            threads: Some(1),
            protected_paths: Default::default(),
            parallel_min: None,
        };
        for cap in [0, 24, 25] {
            let mut overrides = EncryptedReadOverrides::default();
            overrides.member_packed_bytes = Some(cap);
            overrides.member_decoded_bytes = Some(cap);
            let report = extract::run_with_zip_policy(
                &input,
                &opts,
                Some("pw"),
                &Cancellation::default(),
                &overrides,
                |_: ZipRunEvent<'_>| Ok(()),
            )
            .unwrap();
            assert_eq!(report.failed(), u64::from(cap != 25));
            assert_eq!(report.files(), u64::from(cap == 25));
            assert_eq!(report.run_usage().records, 1);
            assert_eq!(report.usage().members, 1);
            let mut limits = EncryptedReadLimits::default();
            limits.member_packed_bytes = cap;
            limits.member_decoded_bytes = cap;
            let mut context = EncryptedReadContext::new(EncryptedReadOptions::default().with_limits(limits)).unwrap();
            let report = extract::run_with_zip_context(
                &input,
                &opts,
                Some("pw"),
                &Cancellation::default(),
                &mut context,
                |_: ZipRunEvent<'_>| Ok(()),
            )
            .unwrap();
            assert_eq!(report.failed(), u64::from(cap != 25));
            let selection = SelectedEntry::open_cancelable_with_zip_limit(
                &input,
                0,
                Some("pw"),
                u64::MAX,
                Some(cap),
                Cancellation::default(),
            );
            assert_eq!(selection.is_ok(), cap == 25);
        }
        for cap in [0, 4, 1024] {
            let mut extraction = opts.clone();
            extraction.mode = Mode::Extract;
            extraction.dest = dir.path().join(format!("public-{cap}"));
            let mut overrides = EncryptedReadOverrides::default();
            overrides.live_spool_bytes = Some(cap);
            let result = extract::run_with_zip_policy(
                &input,
                &extraction,
                Some("pw"),
                &Cancellation::default(),
                &overrides,
                |_: ZipRunEvent<'_>| Ok(()),
            );
            assert_eq!(result.is_ok(), cap == 1024);
            if cap == 1024 {
                assert_eq!(fs::read(extraction.dest.join("a.txt")).unwrap(), b"hello");
            } else {
                assert!(!extraction.dest.join("a.txt").exists());
            }
        }
        assert_eq!(fs::read(&input).unwrap(), bytes);
    }
}
