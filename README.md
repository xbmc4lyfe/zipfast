# zipfast

A fast, universal archive extractor written in Rust. Work in progress.

## What works

- RAR 5.0 archives: listing, testing and extracting **stored** (`-m0`) files, including files split across
  `name.partNN.rar` or `name.rar`/`name.r00` volume sets, self-extracting stubs, header and data CRC32 checks,
  modification times and Unix permissions.
- ZIP archives: stored and deflated entries, ZIP64, self-extracting stubs, UTF-8 and code page 437 names,
  Unix permissions, and extended or NTFS timestamps.
- Extraction never writes outside the destination: `..`, absolute paths, drive letters and links in the way are
  refused.

Compressed RAR data, encrypted archives, links, RAR 4.x, zip, 7z and tar are next.

## Usage

```
zipfast l archive.rar             # list
zipfast t archive.rar             # test every checksum, write nothing
zipfast x archive.part01.rar out  # extract with folders
zipfast e archive.rar out         # extract without folders
```

Switches: `-o+`/`-y` overwrite existing files, `-o-` skip them (default), `-q` quiet.

Exit status: 0 all good, 1 some files failed, 2 the archive couldn't be read.

## Sources

ZIP follows PKWARE's published APPNOTE. The RAR 5.0 block layout follows RARLAB's published "RAR 5.0 archive format" technical note.
