# Engine baseline and downstream inventory

## Source revisions

| Project | Baseline revision |
| --- | --- |
| Standalone zipfast | `4443e1c2923c2cbeb10d8559b56effd76c9e31b1` |
| Standalone zipview | `2c3d73a06b29987cea1510e903e437a482076745` |
| Prybar compatibility branch | `d3b8aa32a7c7214919b9c973588a9aa97a6a0e88` |

The standalone baselines passed `cargo test --locked` on macOS arm64 with
Rust 1.99.1. Zipfast passed 122 tests and zipview passed 39. These runs
included the working-tree RPL-1.5 changes. The revision table records the
committed bases. The [workspace integration report](zipview-workspace.md)
records the preservation and import commits, Rust 1.87 verification, and
clean Git consumer tests.

Prybar's manifests still use the vendored sibling paths
`crates/zipfast` and `crates/zipview`. The compatibility branch keeps both
snapshots from Prybar's original vendor commit, `7ddfeaa`. The zipview
vendor matches the committed standalone tree except for its Cargo manifest.
The vendor declares GPL-3.0. The zipfast vendor manifest adds `subtle = "2.6"`
and `tempfile = "3.27"` and leaves release profiles to its workspace root.

The [compatibility plan](superpowers/plans/2026-11-11-zipview-merge-and-compatibility.md)
leaves the Prybar pin and release licensing decision open. It calls for
reviewing the dependency terms and combined distribution before changing the
engine pins or shipping a release with them. The existing GPL-covered
snapshots and dependencies retain their applicable terms. The previous
engine snapshots remain the rollback point.

## Engine callers

Paths in this section are relative to the named repository at its baseline
revision.

| Caller | Engine APIs and behavior |
| --- | --- |
| Prybar `crates/pry/src/archive.rs` | Uses `extract::list_with_password` for listing and `extract::run_with_password` with `Options` for bulk extraction and testing. It uses `volume::next_volume` to collect input paths for overwrite protection. Selected extraction calls `SelectedEntry::open_cancelable` and reads by zero-based index with an 8 GiB cap. The caller stages the file and checks its guard before publication. |
| Prybar `crates/pry/src/archive.rs` and `browse.rs` | Opens `zipview::ZipIndex` with a seek/read callback and a 129 MiB metadata budget. The caller checks the count, order, names, sizes, CRCs, and directory flags against the engine listing. It uses `by_index` and reads the `ZipEntry` compression name, effective method, flags, local-header offset, creator version and host, Unix mode, and AES strength. |
| Prybar `crates/pry/src/browse.rs` | Calls `extract::list_with_password` for navigation and `SelectedEntry::open_cancelable` for a preview with a 64 MiB decode cap. The terminal event loop, cancellation controls, and metadata display live in Prybar. |
| Prybar `crates/pry/src/archive_compat.rs` | Uses `rar5::reader::Volume::open_with_password`, `extract::list_with_password`, `SelectedEntry::open` with an 8 GiB cap, and `zip::run` for ZIP tests. The argument and status adapters live in Prybar, along with `gzip_compat.rs` and `parity.rs`. |
| Zipfast `src/main.rs` | Routes `l` and `v` to `extract::list_with_password`. Routes `t`, `x`, and `e` to `extract::run_with_password`, with flattened paths for `e`. The Prybar vendor's copy of this binary supplies an empty protection set. |

Zipview's public API includes the slice-based `ZipReader`, the range-based
`ZipIndex`, and the incremental `ZipIndexOpener`. It also exposes entry and
timestamp types, password checks, and ZIP64, AES, and ZipCrypto helpers.
Prybar's ZIP metadata callers use the indexed subset. Zipfast handles their
member decoding.

## Vendor reconciliation

The first two rows record changes already committed in the workspace.
The remaining rows describe vendor behavior and pending acceptance work.

| Area | Status and scope |
| --- | --- |
| WinZip AES | `bfdf2bf622f913b8a333a29f179693f59e59416b` authenticates complete payloads in zipfast. The full read checks length and the 10-byte HMAC-SHA1 tag before returning plaintext. A prefix read remains provisional. The historical zipview API is unchanged by this commit. |
| AArch64 CRC | `ea51228e932066e6958852a60cdfdf92977f0f1d` applies the vendor's equivalent narrowing of the intrinsic unsafe scope. |
| Selected reads | Reconcile cancellable, indexed ZIP, RAR5, and TAR reads with provisional sink delivery. Preserve RAR solid and split history, enforce cumulative packed and decoded budgets and the 256 MiB selected RAR window cap, and account for compressed TAR wrapper input and output. |
| Input preservation | The vendor accepts caller-supplied canonical input paths. Cover the archive and relevant RAR volumes at engine entry points, including calls from the standalone CLI and paths reached through directory aliases. |
| Staged publication | The vendor carries temporary-file ownership through serial and parallel verification. Compressed TAR defers publication until the stream drains, then publishes per member. Preserve existing outputs on prepublication failures and document the per-member publication boundary. |
| Encrypted RAR5 | The vendor verifies keyed BLAKE2sp and separates compressed blocks from final cipher padding. Check stored padding bounds and handling of a final-volume BLAKE2sp record when CRC also exists. Require independent encrypted RAR fixtures for acceptance. |
| Listing limits | The vendor bounds ZIP central directories to 128 MiB and one million entries. It caps RAR and TAR listing names at 64 MiB across one million entries and uses an 8 GiB compressed-stream TAR listing budget. |
| Decoder limits | The vendor caps encrypted ZIP packed data at 128 MiB, LZMA and XZ memory at 256 MiB, and Zstandard window log at 27. These are individual resource limits. |
| Volume names | The vendor checks numeric increments and decimal width arithmetic and validates old-style volume suffix letters. |

The standalone base already provides RAR5 keyed CRC, short-write
optimization, and ZIP codec and encryption plumbing. The zipview import
already includes its upstream range reader. Prybar-specific argument
parsing, terminal UI, display policy, and metadata matching stay with
Prybar.

## Compatibility references

The Linux arm64 reference build ran in Debian 12 with GCC 12.2.0 in Docker
image `rust@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c`.

| Reference | Verified source | Reported version |
| --- | --- | --- |
| GNU gzip | `b4ed8e73401968bcad749afb0e636dd3ec205ca7` with gnulib `331c8d065a8a753de71f084f068473ccd5e4c34a` | 1.15.2-b4ed-modified |
| Info-ZIP Zip | Apple OSS `c8d52ed44169a71e362af3814988685aa39ee7b4` | 3.0 |
| Info-ZIP UnZip | `unzip_6.0.orig.tar.gz`, SHA-256 `036d96991646d0449ed0aa952e4fbe21b476ce994abc276e49d30e686708bd37` | 6.00 |
| 7-Zip | `d3296e39e1f1f92c7b41c0c3848e65640428d42d` | 26.06 |
| UnRAR | `160dcb5c9c1babbbdd3f0f1fc78cf48a7f8150cf` | 7.30 beta 1 |

The encrypted RAR5 smoke fixture, `rar5-psw.rar`, comes from rarfile revision
`d2f7df6fc843dae356fd6b0a85971dc36fd6e757` and has SHA-256
`b6840e95152a1c3b5acd736dc34f988509866f04158b67da1b5a29e166a31355`.
Reference binaries cross-read Deflate ZIP and gzip, extracted from a ZIP64
archive with 65,536 small entries, and agreed on both encrypted RAR5 member
payloads. These smoke tests exercised only the reference binaries.

Prybar's Ubuntu workflow builds tools with
`scripts/build-compatibility-references.sh`, builds the CLI with
`cargo build -p prybar --locked`, and runs
`scripts/check-compatibility.py target/debug/pry "$RUNNER_TEMP/prybar-references/bin"`.
The Prybar build script also pins par2cmdline and par2cmdline-turbo. The
separate Debian arm64 smoke build adds Info-ZIP UnZip. Its local build and
smoke commands, logs, and binary checksums are in
`/tmp/zipfast-reference.SZkt27` while that scratch directory is available.
Prybar's `scripts/check-encryption.py` uses pyzipper 0.3.6 and pinned rarfile
fixtures for independent interoperability checks.
