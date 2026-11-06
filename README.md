# zipfast

A fast, universal archive extractor written in Rust. Work in progress.

## What works

- RAR 5.0 archives: listing, testing and extracting stored and compressed files (every method, solid archives,
  filters), including files split across `name.partNN.rar` or `name.rar`/`name.r00` volume sets, self-extracting
  stubs, CRC32 and BLAKE2sp checks, modification times and Unix permissions. Big files decode on several cores.
- ZIP archives: stored, deflated, bzip2, LZMA, xz and zstd entries, ZIP64, self-extracting stubs, UTF-8 and code page 437 names,
  Unix permissions, and extended or NTFS timestamps.
- tar archives, plain or compressed with gzip, xz, zstd or bzip2 (`.tar.gz`, `.tgz`, `.tar.xz`, `.tar.zst`,
  `.tar.bz2` and so on): POSIX ustar and pax (long names, big sizes, fractional times), GNU long names and base-256
  sizes, and pre-POSIX headers. A compressed file that holds no tar archive comes out as the one file it
  compresses. xz files written in blocks (`xz -T0`) decode on several cores.
- Extraction never writes outside the destination: `..`, absolute paths, drive letters and links in the way are
  refused.

Encrypted archives, links, RAR 4.x, 7z and the rarer ZIP methods (Deflate64, PPMd) are next.

## Usage

```
zipfast l archive.rar             # list
zipfast t archive.rar             # test every checksum, write nothing
zipfast x archive.part01.rar out  # extract with folders
zipfast e archive.rar out         # extract without folders
```

Switches: `-o+`/`-y` overwrite existing files, `-o-` skip them (default), `-q` quiet, `-mt<n>` use up to n
threads (default: one per core).

Exit status: 0 all good, 1 some files failed, 2 the archive couldn't be read.

## Builds tuned for a processor

A plain `cargo build --release` runs on any x86-64 or Apple silicon processor, and picks AVX2 at run time where
that pays. `scripts/build-tuned.sh` builds variants tuned for newer processors into `dist/`:

| Build | For |
|---|---|
| `zipfast-x86_64-v3` | x86-64-v3: AVX2, BMI2, FMA (Intel Haswell, AMD Zen 1 and later) |
| `zipfast-x86_64-v4` | x86-64-v4: AVX-512 (Intel Skylake-X and Ice Lake, AMD Zen 4 and later) |
| `zipfast-apple-m4` | Apple M4 and later |
| `zipfast-apple-m5` | Apple M5 and later |

The x86 builds are made on an x86-64 machine and the Apple ones on an Apple silicon Mac; `scripts/build-tuned.sh v3`
makes just one. A tuned build uses its processor's instructions everywhere, the Rust runtime included, so on a
processor that lacks them it stops on an illegal instruction.

## Sources

ZIP follows PKWARE's published APPNOTE. tar follows the POSIX ustar and pax interchange formats and GNU tar's
manual for its extensions. The RAR 5.0 block layout follows RARLAB's published "RAR 5.0 archive format" technical note.
