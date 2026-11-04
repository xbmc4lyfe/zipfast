//! A tiny RAR 5.0 writer for tests: stored files only, written from the published archive layout.
#![allow(dead_code)]

pub fn vint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// A whole block: CRC32, size, then `body` (type, flags and the rest), then `data`.
pub fn block(kind: u64, flags: u64, fields: &[u8], extra: &[u8], data: &[u8], data_size_field: bool) -> Vec<u8> {
    let mut flags = flags;
    if !extra.is_empty() {
        flags |= 1;
    }
    if data_size_field {
        flags |= 2;
    }
    let mut body = Vec::new();
    vint(kind, &mut body);
    vint(flags, &mut body);
    if !extra.is_empty() {
        vint(extra.len() as u64, &mut body);
    }
    if data_size_field {
        vint(data.len() as u64, &mut body);
    }
    body.extend_from_slice(fields);
    body.extend_from_slice(extra);
    let mut sized = Vec::new();
    vint(body.len() as u64, &mut sized);
    sized.extend_from_slice(&body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
    out
}

pub struct FileSpec<'a> {
    /// leave the CRC32 out of the header, as an archive using BLAKE2sp instead does
    pub no_crc: bool,
    pub name: &'a str,
    pub data: &'a [u8],
    pub dir: bool,
    pub mtime: Option<u32>,
    pub unix_mode: Option<u64>,
    pub extra: Vec<u8>,
    pub method: u64,
}

impl<'a> FileSpec<'a> {
    pub fn new(name: &'a str, data: &'a [u8]) -> Self {
        FileSpec {
            no_crc: false,
            name,
            data,
            dir: false,
            mtime: Some(1_700_000_000),
            unix_mode: Some(0o644),
            extra: Vec::new(),
            method: 0,
        }
    }
}

/// A file header for one part. `crc` is the part's or the file's, as the caller decides.
pub fn file_block(spec: &FileSpec<'_>, part: &[u8], crc: u32, split_before: bool, split_after: bool) -> Vec<u8> {
    let mut fields = Vec::new();
    let mut file_flags = if spec.no_crc { 0 } else { 0x4 };
    if spec.dir {
        file_flags |= 1;
    }
    if spec.mtime.is_some() {
        file_flags |= 2;
    }
    vint(file_flags, &mut fields);
    vint(spec.data.len() as u64, &mut fields);
    vint(spec.unix_mode.unwrap_or(0x20), &mut fields);
    if let Some(t) = spec.mtime {
        fields.extend_from_slice(&t.to_le_bytes());
    }
    if !spec.no_crc {
        fields.extend_from_slice(&crc.to_le_bytes());
    }
    vint(spec.method << 7, &mut fields);
    vint(if spec.unix_mode.is_some() { 1 } else { 0 }, &mut fields);
    vint(spec.name.len() as u64, &mut fields);
    fields.extend_from_slice(spec.name.as_bytes());
    let mut flags = 0;
    if split_before {
        flags |= 0x8;
    }
    if split_after {
        flags |= 0x10;
    }
    block(2, flags, &fields, &spec.extra, part, true)
}

pub fn main_block(volume: bool, number: Option<u64>) -> Vec<u8> {
    let mut fields = Vec::new();
    let mut flags = 0;
    if volume {
        flags |= 1;
    }
    if number.is_some() {
        flags |= 2;
    }
    vint(flags, &mut fields);
    if let Some(n) = number {
        vint(n, &mut fields);
    }
    block(1, 0, &fields, &[], &[], false)
}

pub fn end_block(more: bool) -> Vec<u8> {
    let mut fields = Vec::new();
    vint(u64::from(more), &mut fields);
    block(5, 0, &fields, &[], &[], false)
}

pub const SIG: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// One archive holding `files`, each stored whole.
pub fn archive(files: &[FileSpec<'_>]) -> Vec<u8> {
    let mut out = SIG.to_vec();
    out.extend(main_block(false, None));
    for f in files {
        out.extend(file_block(f, f.data, crc32fast::hash(f.data), false, false));
    }
    out.extend(end_block(false));
    out
}

/// One stored file cut into volumes of at most `chunk` data bytes each.
pub fn volumes(spec: &FileSpec<'_>, chunk: usize) -> Vec<Vec<u8>> {
    let parts: Vec<&[u8]> = spec.data.chunks(chunk).collect();
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| {
            let mut out = SIG.to_vec();
            out.extend(main_block(true, if i == 0 { None } else { Some(i as u64) }));
            let last = i + 1 == n;
            let crc = if last { crc32fast::hash(spec.data) } else { crc32fast::hash(part) };
            out.extend(file_block(spec, part, crc, i > 0, !last));
            out.extend(end_block(!last));
            out
        })
        .collect()
}

/// An extra-area hash record holding `hash` as BLAKE2sp.
pub fn blake_record(hash: [u8; 32]) -> Vec<u8> {
    let mut rec = Vec::new();
    vint(2, &mut rec);
    vint(0, &mut rec);
    rec.extend_from_slice(&hash);
    let mut out = Vec::new();
    vint(rec.len() as u64, &mut out);
    out.extend(rec);
    out
}

pub fn blake(data: &[u8]) -> [u8; 32] {
    let mut h = zipfast::blake2sp::Blake2sp::new();
    h.update(data);
    h.finish()
}
