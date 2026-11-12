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

//! Names of the volumes after the first in a multi-volume set.

use std::path::{Path, PathBuf};

/// The volume after `path`: `name.part01.rar` becomes `name.part02.rar` (keeping the width, growing it when the
/// number overflows), and `name.rar` becomes `name.r00`, then `name.r01` and so on.
pub fn next_volume(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();
    let next = if let Some(stem) = lower.strip_suffix(".rar") {
        match part_number(stem) {
            Some((digits_at, width, n)) => {
                let digits = format!("{:0width$}", n + 1, width = width);
                format!("{}{}{}", &name[..digits_at], digits, &name[digits_at + width..])
            }
            // keep the extension's case: set.RAR goes on in set.R00
            None => {
                let r = if name.ends_with(".RAR") || name.ends_with(".Rar") { 'R' } else { 'r' };
                format!("{}.{r}00", &name[..name.len() - 4])
            }
        }
    } else {
        // .r00 .. .r99, then .s00 and onwards
        let (base, ext) = name.rsplit_once('.')?;
        let mut chars = ext.chars();
        let letter = chars.next()?;
        let digits = chars.as_str();
        if digits.len() < 2 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let n: u32 = digits.parse().ok()?;
        let limit = 10u32.pow(digits.len() as u32);
        if n + 1 < limit {
            format!("{base}.{letter}{:0w$}", n + 1, w = digits.len())
        } else {
            let next_letter = (letter as u8 + 1) as char;
            format!("{base}.{next_letter}{:0w$}", 0, w = digits.len())
        }
    };
    Some(path.with_file_name(next))
}

/// In `name.partNN`, where the digits start, how many there are, and their value.
fn part_number(stem: &str) -> Option<(usize, usize, u64)> {
    let digits_len = stem.bytes().rev().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 {
        return None;
    }
    let digits_at = stem.len() - digits_len;
    if !stem[..digits_at].ends_with(".part") {
        return None;
    }
    let n = stem[digits_at..].parse().ok()?;
    Some((digits_at, digits_len, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(s: &str) -> String {
        next_volume(Path::new(s)).unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn numbering() {
        assert_eq!(next("a.part1.rar"), "a.part2.rar");
        assert_eq!(next("a.part09.rar"), "a.part10.rar");
        assert_eq!(next("a.part99.rar"), "a.part100.rar");
        assert_eq!(next("dir/Movie.2026.PART001.RAR"), "dir/Movie.2026.PART002.RAR");
        assert_eq!(next("a.rar"), "a.r00");
        assert_eq!(next("a.r00"), "a.r01");
        assert_eq!(next("SET.RAR"), "SET.R00");
        assert_eq!(next("SET.R00"), "SET.R01");
        assert_eq!(next("a.r99"), "a.s00");
    }
}
