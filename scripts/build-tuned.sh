#!/bin/sh
# Copyright (C) 2026 xbmc4lyfe
# SPDX-License-Identifier: RPL-1.5
#
# Unless explicitly acquired and licensed from Licensor under another license,
# the contents of this file are subject to the Reciprocal Public License
# ("RPL") Version 1.5, or subsequent versions as allowed by the RPL, and You
# may not copy or use this file in either source code or executable form,
# except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR
# HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT LIMITATION, ANY
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, QUIET
# ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing
# rights and limitations under the RPL.

# Builds zipfast tuned for particular processors, into dist/.
#
#   scripts/build-tuned.sh          every variant this machine can build
#   scripts/build-tuned.sh v3 m4    just these
#
#   v3  x86-64-v3: AVX2, BMI2, FMA (Intel Haswell, AMD Zen 1 and later)   dist/zipfast-x86_64-v3
#   v4  x86-64-v4: AVX-512 (Intel Skylake-X and Ice Lake, AMD Zen 4)      dist/zipfast-x86_64-v4
#   m4  Apple M4 and later                                                dist/zipfast-apple-m4
#   m5  Apple M5 and later                                                dist/zipfast-apple-m5
#
# The x86 variants build on an x86-64 machine and the Apple ones on an Apple silicon Mac. A tuned build stops on
# an illegal instruction on a processor that lacks what it was built for; a plain `cargo build --release` runs on
# any processor of its kind, and picks AVX2 at run time where that pays.
set -eu
cd "$(dirname "$0")/.."
case "$(uname -s)-$(uname -m)" in
    *-x86_64 | *-amd64) all="v3 v4" ;;
    Darwin-arm64) all="m4 m5" ;;
    *) all="" ;;
esac
[ $# -gt 0 ] || set -- $all
[ $# -gt 0 ] || { echo "nothing to build here: tuned builds are for x86-64 and Apple silicon" >&2; exit 1; }
# naming the target keeps the tuning off build scripts, which run here, on what may be an older processor
host=$(rustc -vV | sed -n 's/^host: //p')
mkdir -p dist
for v in "$@"; do
    case "$v" in
        v3) cpu=x86-64-v3 name=x86_64-v3 ;;
        v4) cpu=x86-64-v4 name=x86_64-v4 ;;
        m4) cpu=apple-m4 name=apple-m4 ;;
        m5) cpu=apple-m5 name=apple-m5 ;;
        *) echo "unknown variant $v: use v3, v4, m4 or m5" >&2; exit 2 ;;
    esac
    case " $all " in *" $v "*) ;; *) echo "$v doesn't build on this machine" >&2; exit 2 ;; esac
    # each variant keeps its own target folder, so switching between them doesn't rebuild everything
    RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=$cpu" cargo build --release --target "$host" --target-dir "target/tuned-$v"
    cp "target/tuned-$v/$host/release/zipfast" "dist/zipfast-$name"
    echo "dist/zipfast-$name"
done
