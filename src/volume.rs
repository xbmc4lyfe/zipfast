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
        match part_digits_at(stem) {
            Some(digits_at) => {
                let suffix = &stem[digits_at..];
                let n: u64 = suffix.parse().ok()?;
                let digits = format!("{:0width$}", n.checked_add(1)?, width = suffix.len());
                format!("{}{}{}", &name[..digits_at], digits, &name[stem.len()..])
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
        if !letter.is_ascii_alphabetic() || digits.len() < 2 || !digits.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let n: u32 = digits.parse().ok()?;
        let limit = 10u32.checked_pow(digits.len().try_into().ok()?)?;
        let next_number = n.checked_add(1)?;
        if next_number < limit {
            format!("{base}.{letter}{next_number:0w$}", w = digits.len())
        } else {
            let next_letter = (letter as u8 + 1) as char;
            if !next_letter.is_ascii_alphabetic() {
                return None;
            }
            format!("{base}.{next_letter}{:0w$}", 0, w = digits.len())
        }
    };
    Some(path.with_file_name(next))
}

/// In `name.partNN`, where the digits start.
fn part_digits_at(stem: &str) -> Option<usize> {
    let digits_len = stem.bytes().rev().take_while(u8::is_ascii_digit).count();
    if digits_len == 0 {
        return None;
    }
    let digits_at = stem.len() - digits_len;
    stem[..digits_at].ends_with(".part").then_some(digits_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(s: &str) -> String {
        next_volume(Path::new(s)).unwrap().to_string_lossy().into_owned()
    }

    #[test]
    fn rejects_an_overflowing_part_number() {
        assert_eq!(next_volume(Path::new("a.part18446744073709551615.rar")), None);
        assert_eq!(next_volume(Path::new("a.part18446744073709551616.rar")), None);
    }

    #[test]
    fn rejects_an_overflowing_old_style_suffix() {
        assert_eq!(next_volume(Path::new("a.r0000000001")), None);
        assert_eq!(next_volume(Path::new("a.r4294967295")), None);
    }

    #[test]
    fn rejects_suffixes_without_an_ascii_letter_successor() {
        for name in ["a.é00", "a.100", "a.z99", "a.Z99"] {
            assert_eq!(next_volume(Path::new(name)), None, "{name}");
        }
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
