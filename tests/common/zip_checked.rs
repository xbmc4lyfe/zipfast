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

//! Original fixture and bounded full-stream comparison helpers for Task6.
use std::io::{Read, Write};
use std::path::Path;
use zipfast::zip::write::{
    AesStrength, AesVariant, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions, WinZipAesRequest,
    WriterOptions, ZipStreamWriter,
};

pub fn aes_file(
    path: &Path,
    data: &mut impl Read,
    size: u64,
    password: &str,
    strength: AesStrength,
    variant: AesVariant,
    method: Method,
) {
    let file = std::fs::File::create(path).unwrap();
    let mut writer = ZipStreamWriter::new(file, WriterOptions::default()).unwrap();
    writer
        .add_winzip_aes_file(
            EntryOptions {
                name: EntryName::Utf8("payload"),
                method,
                modified: DosDateTime::default(),
                extended_mtime: None,
                permissions: Permissions::new(0o644).unwrap(),
                comment: b"",
            },
            data,
            InputLength::Exact(size),
            WinZipAesRequest::new(password, strength, variant).unwrap(),
            |salt| {
                salt.fill(0x63);
                Ok(())
            },
        )
        .unwrap();
    writer.finish().unwrap().sink.sync_all().unwrap();
}

pub fn options(dest: &Path, extract: bool) -> zipfast::extract::Options {
    zipfast::extract::Options {
        mode: if extract { zipfast::extract::Mode::Extract } else { zipfast::extract::Mode::Test },
        dest: dest.into(),
        overwrite: zipfast::extract::Overwrite::Always,
        flatten: false,
        threads: Some(1),
        protected_paths: Default::default(),
        parallel_min: None,
    }
}

#[derive(Default)]
pub struct Digest {
    count: u64,
    hash: zipfast::blake2sp::Blake2sp,
}
impl Digest {
    pub fn update(&mut self, bytes: &[u8]) {
        self.count = self.count.checked_add(bytes.len() as u64).unwrap();
        self.hash.update(bytes);
    }
    pub fn finish(self) -> (u64, [u8; 32]) {
        (self.count, self.hash.finish())
    }
}
pub fn file_digest(path: &Path) -> (u64, [u8; 32]) {
    let mut file = std::fs::File::open(path).unwrap();
    let mut buffer = [0; 65536];
    let mut digest = Digest::default();
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    digest.finish()
}
pub fn repeated_digest(byte: u8, size: u64) -> (u64, [u8; 32]) {
    let buffer = [byte; 65536];
    let mut left = size;
    let mut digest = Digest::default();
    while left != 0 {
        let n = left.min(buffer.len() as u64) as usize;
        digest.update(&buffer[..n]);
        left -= n as u64;
    }
    digest.finish()
}
pub fn save_bytes(path: &Path, bytes: &[u8]) {
    std::fs::File::create(path).unwrap().write_all(bytes).unwrap();
}
