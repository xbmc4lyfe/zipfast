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

//! Turns a name stored in an archive into a path under the destination, refusing anything that would escape it.

use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

/// `windows_names`: the archive was made on Windows, so a backslash is a separator there and a drive letter or
/// a reserved character means nothing on this side.
pub fn sanitize(name: &str, windows_names: bool) -> Result<PathBuf> {
    let unsafe_path = || Error::UnsafePath(name.to_string());
    let normalized: String = if windows_names { name.replace('\\', "/") } else { name.to_string() };
    let mut out = PathBuf::new();
    for (i, part) in normalized.split('/').enumerate() {
        match part {
            "" if i == 0 && !normalized.is_empty() => return Err(unsafe_path()),
            "" | "." => continue,
            ".." => return Err(unsafe_path()),
            _ => {}
        }
        if part.contains('\0') {
            return Err(unsafe_path());
        }
        if windows_names && i == 0 && part.len() == 2 && part.ends_with(':') {
            return Err(unsafe_path());
        }
        let cleaned: String = if cfg!(windows) || windows_names {
            part.chars().map(|c| if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') { '_' } else { c }).collect()
        } else {
            part.to_string()
        };
        out.push(cleaned);
    }
    // a final check against whatever the platform's own parser makes of it
    if out.as_os_str().is_empty() || out.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(unsafe_path());
    }
    Ok(out)
}

/// Whether `target` resolves inside `root` once joined to `link_dir`, without touching the file system.
pub fn link_stays_inside(link_dir: &Path, target: &str) -> bool {
    if target.starts_with('/') || target.starts_with('\\') || target.contains(':') {
        return false;
    }
    let mut depth: i64 = link_dir.components().count() as i64;
    for part in target.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_escapes() {
        for bad in ["../x", "a/../../x", "/etc/passwd", "a/..", "", "a/\0b"] {
            assert!(sanitize(bad, false).is_err(), "{bad:?}");
        }
        assert!(sanitize("C:/x", true).is_err());
        assert!(sanitize("..\\x", true).is_err());
    }

    #[test]
    fn keeps_normal_names() {
        assert_eq!(sanitize("a/b/c.mkv", false).unwrap(), Path::new("a/b/c.mkv"));
        assert_eq!(sanitize("./a//b", false).unwrap(), Path::new("a/b"));
        assert_eq!(sanitize("a\\b.txt", true).unwrap(), Path::new("a/b.txt"));
    }

    #[test]
    fn links() {
        assert!(link_stays_inside(Path::new("a/b"), "../c"));
        assert!(!link_stays_inside(Path::new("a"), "../../c"));
        assert!(!link_stays_inside(Path::new(""), "/etc"));
    }
}
