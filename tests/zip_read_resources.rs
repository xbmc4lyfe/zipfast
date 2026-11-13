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

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Cursor, Write};
use zipfast::zip::Archive;
use zipfast::zip::write::{
    AesStrength, AesVariant, DeflateLevel, DosDateTime, EntryName, EntryOptions, InputLength, Method, Permissions,
    WinZipAesRequest, WriterOptions, ZipStreamWriter,
};

struct Allocator;
thread_local! {
    static COUNT: Cell<Option<(usize, usize, usize)>> = const { Cell::new(None) };
}
fn record(size: usize) {
    let _ = COUNT.try_with(|counter| {
        if let Some((min, max, count)) = counter.get() {
            counter.set(Some((min, max, count + usize::from((min..=max).contains(&size)))));
        }
    });
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, size) };
        if !ptr.is_null() {
            record(size);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            System.dealloc(ptr, layout);
        }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn counted<T>(min: usize, max: usize, operation: impl FnOnce() -> T) -> (T, usize) {
    COUNT.with(|count| count.set(Some((min, max, 0))));
    let result = operation();
    let count = COUNT.with(|count| count.replace(None).unwrap().2);
    (result, count)
}
fn options(name: &str, method: Method) -> EntryOptions<'_> {
    EntryOptions {
        name: EntryName::Utf8(name),
        method,
        modified: DosDateTime::default(),
        extended_mtime: None,
        permissions: Permissions::new(0o644).unwrap(),
        comment: b"",
    }
}

#[test]
fn encrypted_reads_allocate_one_payload_buffer() {
    let mut random = 1u64;
    let data: Vec<u8> = (0..8 << 20)
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random as u8
        })
        .collect();
    for aes in [true, false] {
        for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
            let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
            let metadata = options("payload", method);
            if aes {
                writer
                    .add_winzip_aes_file(
                        metadata,
                        &mut Cursor::new(&data),
                        InputLength::Exact(data.len() as u64),
                        WinZipAesRequest::new("password", AesStrength::Aes256, AesVariant::Ae2).unwrap(),
                        |salt| {
                            salt.fill(3);
                            Ok(())
                        },
                    )
                    .unwrap();
            } else {
                writer
                    .add_zipcrypto_file(
                        metadata,
                        &mut Cursor::new(&data),
                        InputLength::Exact(data.len() as u64),
                        "password",
                        |header| {
                            header.fill(3);
                            Ok(())
                        },
                    )
                    .unwrap();
            }
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(&writer.finish().unwrap().sink).unwrap();
            let mut archive = Archive::open(file.path()).unwrap();
            assert!(archive.entries[0].packed > 4 << 20);
            let mut hash = zipfast::crc32::Hasher::new();
            let (result, allocations) = counted(4 << 20, usize::MAX, || {
                archive.read_at(0, Some("password"), 16 << 20, |bytes| {
                    hash.update(bytes);
                    Ok(())
                })
            });
            result.unwrap();
            assert_eq!(hash.finalize(), zipfast::crc32::hash(&data));
            assert_eq!(allocations, 1, "aes={aes}, method={method:?}");
        }
    }
}

#[test]
fn zip_listing_allocates_each_owned_name_once() {
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let names: Vec<_> = (0..128).map(|n| format!("{}{n:08}", "x".repeat(180))).collect();
    for name in &names {
        writer.add_file(options(name, Method::Stored), &mut Cursor::new(b""), InputLength::Exact(0)).unwrap();
    }
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&writer.finish().unwrap().sink).unwrap();
    let (entries, allocations) = counted(names[0].len(), names[0].len(), || zipfast::zip::list(file.path()).unwrap());
    assert_eq!(entries.iter().map(|e| &e.name).collect::<Vec<_>>(), names.iter().collect::<Vec<_>>());
    assert_eq!(allocations, names.len());
}

fn encrypted_bytes(
    data: &[u8],
    method: Method,
    aes: Option<(AesStrength, AesVariant)>,
) -> zipfast::zip::write::Finished<Vec<u8>> {
    let mut writer = ZipStreamWriter::new(Vec::new(), WriterOptions::default()).unwrap();
    let metadata = options("payload", method);
    if let Some((strength, variant)) = aes {
        writer
            .add_winzip_aes_file(
                metadata,
                &mut Cursor::new(data),
                InputLength::Exact(data.len() as u64),
                WinZipAesRequest::new("password", strength, variant).unwrap(),
                |salt| {
                    salt.fill(3);
                    Ok(())
                },
            )
            .unwrap();
    } else {
        writer
            .add_zipcrypto_file(
                metadata,
                &mut Cursor::new(data),
                InputLength::Exact(data.len() as u64),
                "password",
                |header| {
                    header.fill(3);
                    Ok(())
                },
            )
            .unwrap();
    }
    writer.finish().unwrap()
}
fn read_bytes(bytes: &[u8], password: &str) -> (zipfast::Result<()>, Vec<u8>) {
    read_bytes_with_limit(bytes, password, 1 << 20)
}
fn read_bytes_with_limit(bytes: &[u8], password: &str, limit: u64) -> (zipfast::Result<()>, Vec<u8>) {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    let mut archive = Archive::open(file.path()).unwrap();
    let mut out = Vec::new();
    let result = archive.read_at(0, Some(password), limit, |chunk| {
        out.extend(chunk);
        Ok(())
    });
    (result, out)
}
fn u16at(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap()) as usize
}
fn u32at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize
}

#[test]
fn encrypted_stored_and_deflate_preserve_password_authentication_and_crc_rules() {
    let data = b"encrypted member across cancellation chunks".repeat(1700);
    let mut encryptions = vec![None];
    for strength in [AesStrength::Aes128, AesStrength::Aes192, AesStrength::Aes256] {
        for variant in [AesVariant::Ae1, AesVariant::Ae2] {
            encryptions.push(Some((strength, variant)));
        }
    }
    for encryption in encryptions {
        for method in [Method::Stored, Method::Deflate(DeflateLevel::new(6).unwrap())] {
            for plain in [b"".as_slice(), data.as_slice()] {
                let finished = encrypted_bytes(plain, method, encryption);
                let cd = finished.summary.central_offset as usize;
                let bytes = finished.sink;
                let data_at = 30 + u16at(&bytes, 26) + u16at(&bytes, 28);
                let packed_at = if u32at(&bytes, cd + 20) == u32::MAX as usize {
                    let extra = cd + 46 + u16at(&bytes, cd + 28);
                    assert_eq!(u16at(&bytes, extra), 1);
                    extra + 12
                } else {
                    cd + 20
                };
                let packed = u32at(&bytes, packed_at);
                let limit = (packed as u64).max(plain.len() as u64);
                let (result, out) = read_bytes_with_limit(&bytes, "password", limit);
                result.unwrap();
                assert_eq!(out, plain);
                let (result, out) = read_bytes_with_limit(&bytes, "password", limit - 1);
                assert!(matches!(result, Err(zipfast::Error::Unsupported(_))));
                assert!(out.is_empty());
                let (result, out) = read_bytes(&bytes, "incorrect");
                assert!(result.is_err());
                assert!(out.is_empty());
                for short in [0, 8, packed - 1] {
                    let mut truncated = bytes.clone();
                    truncated[packed_at..packed_at + 4].copy_from_slice(&(short as u32).to_le_bytes());
                    let (result, out) = read_bytes(&truncated, "password");
                    assert!(result.is_err());
                    if encryption.is_some() {
                        assert!(out.is_empty());
                    }
                }
                let mut damaged = bytes.clone();
                damaged[cd + 16] ^= 1;
                let (result, out) = read_bytes(&damaged, "password");
                if matches!(encryption, Some((_, AesVariant::Ae2))) {
                    result.unwrap();
                    assert_eq!(out, plain);
                } else {
                    assert!(matches!(result, Err(zipfast::Error::BadChecksum(_))));
                }
                if encryption.is_none() {
                    let mut damaged = bytes.clone();
                    damaged[data_at + 11] ^= 1;
                    let (result, out) = read_bytes(&damaged, "password");
                    assert!(matches!(result, Err(zipfast::Error::Corrupt("wrong password"))));
                    assert!(out.is_empty());
                }
                if encryption.is_some() {
                    let mut damaged = bytes.clone();
                    damaged[data_at + packed - 1] ^= 1;
                    let (result, out) = read_bytes(&damaged, "password");
                    assert!(result.is_err());
                    assert!(out.is_empty());
                    let root = tempfile::tempdir().unwrap();
                    let archive = root.path().join("damaged.zip");
                    std::fs::write(&archive, damaged).unwrap();
                    let destination = root.path().join("out");
                    let summary = zipfast::extract::run_with_password(
                        &archive,
                        &zipfast::extract::Options {
                            mode: zipfast::extract::Mode::Extract,
                            dest: destination.clone(),
                            overwrite: zipfast::extract::Overwrite::Always,
                            flatten: false,
                            threads: Some(1),
                            protected_paths: Default::default(),
                            parallel_min: None,
                        },
                        Some("password"),
                        |_| {},
                    )
                    .unwrap();
                    assert_eq!(summary.errors.len(), 1);
                    assert!(!destination.join("payload").exists());
                }
            }
        }
    }
}
