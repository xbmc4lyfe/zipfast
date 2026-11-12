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
The vendored zipview manifest declares `license = "GPL-3.0"`. The vendored
zipfast manifest has no `license` field. It adds `subtle = "2.6"` and
`tempfile = "3.27"` and leaves release profiles to its workspace root.

The [compatibility plan](superpowers/plans/2026-11-11-zipview-merge-and-compatibility.md)
leaves the Prybar pin and release licensing decision open. It calls for
reviewing the dependency terms and combined distribution before changing the
engine pins or shipping a release with them. The existing GPL-covered
snapshots and dependencies retain their applicable terms. The previous
engine snapshots remain the rollback point.

RPL 1.5 section 1.2 excludes internal research and personal use from its
definition of deployment. Section 6 requires covered extension source
within one month of deployment and for at least 12 months after deployment
ceases. It also requires documenting modifications, preserving notices,
providing the license text or access instructions, notifying the community
within one month of initial deployment, and preserving Exhibit B attribution
in applicable displays and documentation. The FSF's nonfree license list
links to the FSF RPL 1.3 record. Its classification applies to the linked
record. Compatibility review for an RPL 1.5 engine in a combined Prybar
release remains open.
[OSI RPL 1.5 text](https://opensource.org/license/RPL-1.5) ·
[FSF license list](https://www.gnu.org/licenses/license-list.html#RPL) ·
[FSF RPL 1.3 record](https://directory.fsf.org/wiki/License:ReciprocalPLv1.3)

The new direct dependencies declare BSD-3-Clause for `subtle` 2.6.1 and
MIT or Apache-2.0 for `tempfile` 3.27.0. The new lockfile entries for
`rustix` and `linux-raw-sys` also list Apache-2.0 with the LLVM exception
as an alternative. The remaining new transitive entries declare MIT or
Apache-2.0. Existing dependencies and the native XZ and Zstandard sources
retain their own terms and notices.

## Engine callers

Paths in this section are relative to the named repository at its baseline
revision.

| Caller | Engine APIs and behavior |
| --- | --- |
| Prybar `crates/pry/src/archive.rs` | Uses `extract::list_with_password` for listing and `extract::run_with_password` with `Options` for bulk extraction and testing. It uses `volume::next_volume` to collect input paths for overwrite protection. Selected extraction calls `SelectedEntry::open_cancelable` and reads by zero-based index with an 8 GiB cap. The caller stages the file and checks its guard before publication. |
| Prybar `crates/pry/src/archive.rs` and `browse.rs` | Calls `zipview::ZipIndex::open()` with a seek/read callback and a 129 MiB metadata budget. The caller compares `ZipIndex::len()` with the engine entry count and walks `ZipIndex::entries()` in listing order. It compares `ZipEntry::name()`, `size()` for decoded size, `compressed_size()` for packed size, `crc32()` wrapped in `Some`, and `is_dir()` with the corresponding engine fields. Inspection and browse use `ZipIndex::by_index()` for member details and display `ZipEntry::compression_name()`, `effective_compression()`, `flags()`, `local_header_offset()`, `version_made_by()`, `unix_mode()`, and `aes_info()`. Archive inspection displays `ZipIndex::comment()` when it is nonempty. |
| Prybar `crates/pry/src/browse.rs` | Calls `extract::list_with_password` for navigation and `SelectedEntry::open_cancelable` for a preview with a 64 MiB decode cap. The terminal event loop, cancellation controls, and metadata display live in Prybar. |
| Prybar `crates/pry/src/archive_compat.rs` | Uses `rar5::reader::Volume::open_with_password`, `extract::list_with_password`, `SelectedEntry::open` with an 8 GiB cap, and `zip::run` for ZIP tests. The argument and status adapters live in Prybar, along with `gzip_compat.rs` and `parity.rs`. |
| Zipfast `src/main.rs` | Routes `l` and `v` to `extract::list_with_password`. Routes `t`, `x`, and `e` to `extract::run_with_password`, with flattened paths for `e`. The Prybar vendor's copy of this binary supplies an empty protection set. |

Zipview's public API includes the slice-based `ZipReader`, the range-based
`ZipIndex`, and the incremental `ZipIndexOpener`. It also exposes entry and
timestamp types, password checks, and ZIP64, AES, and ZipCrypto helpers.
Prybar's ZIP metadata callers use the indexed subset. Zipfast handles their
member decoding.

## Vendor reconciliation

The following changes are present in the reviewed Phase 1 engine revision,
`14e68d5196304656c76062b7f7c435f7c21e9a5c`.

| Area | Status and scope |
| --- | --- |
| WinZip AES | `bfdf2bf` ports full authentication to zipfast. `1d8609b` extends full authentication to zipview's slice and range readers. Both check packed length and the 10-byte HMAC-SHA1 tag before decryption. Password checks and prefix previews remain provisional. |
| AArch64 CRC | `ea51228e932066e6958852a60cdfdf92977f0f1d` applies the vendor's equivalent narrowing of the intrinsic unsafe scope. |
| Selected reads | `14e68d5` adds cancellable, indexed ZIP, RAR5, and TAR reads with provisional sink delivery. The engine preserves RAR solid history and split-member state, enforces cumulative packed and decoded budgets and a 256 MiB selected RAR window cap, and counts compressed TAR wrapper input and output through verification. |
| Input preservation | `cefdc28` makes the engine reserve the archive and discoverable consecutive RAR volume names automatically, including at direct format entry points and through directory aliases. Caller-supplied `Options::protected_paths` adds protections. The standalone CLI inherits automatic protection. |
| Staged publication | `cefdc28` keeps temporary-file ownership in output handles through serial and parallel verification. Compressed TAR waits for outer stream verification before publishing members in archive order. |
| Encrypted RAR5 | `ac74b2e` ports keyed BLAKE2sp and compressed block framing, bounds cipher padding, and rejects a late BLAKE2sp record when hash state is unavailable. Split members honor each volume header's checksum mode. `14e68d5` carries the same checks into selected reads and retains encrypted solid history when bulk extraction skips an output. |
| Listing limits | `8644202` caps ZIP central directories at 128 MiB and one million entries, and verifies the exact record count. `14e68d5` caps RAR and TAR listing metadata at one million entries and 64 MiB of names, and compressed TAR listing at 8 GiB each for packed and decoded data. |
| Decoder limits | `8644202` caps encrypted ZIP packed data at 128 MiB, LZMA and XZ memory at 256 MiB, and Zstandard window log at 27. ZIP shares decoder limits across its encrypted and unencrypted paths. |
| Volume names | `8644202` checks numeric increments and decimal width arithmetic and validates old-style volume suffix letters. |

The standalone base already provides RAR5 keyed CRC, short-write
optimization, and ZIP codec and encryption plumbing. The zipview import
already includes its upstream range reader. Prybar-specific argument
parsing, terminal UI, display policy, and metadata matching stay with
Prybar.

The implementation ports and regression additions in the table were
AI-assisted. The root AES, archive limits, staging, RAR5 verification, and
selected-read changes use Prybar's recorded vendor snapshot as their
starting point. The imported zipview code comes from the recorded RPL
snapshot, and its later AES verification and regression additions are local
work. AES test vectors were reproduced independently with Python PBKDF2 and
HMAC and OpenSSL AES. The added RAR5 regression fixtures are generated in
tests from format records and locally constructed payloads.

## Safety behavior

Selected reads use zero-based listing indices and stream provisional bytes
to the caller. Callers must wait for a successful return before publishing.
Cancellation is cooperative at parser and decoder checkpoints. Archive
identity across separate opens is deferred to Phase 2.

The engine refuses an output that resolves to its own archive name or a
reserved RAR volume. An existing consecutive name can be reserved even if
the archive terminates earlier. Replacing a separate hard-link name leaves
the input inode and bytes intact. A same-filesystem rename publishes each
staged replacement after verification. Compressed TAR stages payloads and
archive-supplied directory metadata until the outer wrapper verifies, then
publishes per member. A later publication failure can leave earlier members
in place. Staging uses available disk space and can change the staging
directory's modification time. Path checks can race a concurrent directory
replacement. Crash durability depends on the filesystem.

Encrypted RAR5 rejects alignment padding beyond 15 bytes when the plaintext
or final compression block defines the boundary, partial final cipher
blocks, and unverifiable final-only BLAKE2sp metadata even with a matching
CRC. Full WinZip AES reads reject damaged ciphertext or tags. In the
zipview release microbenchmark on an Apple M4, authenticating a prebuilt
1 MiB AES-256 payload increased median time from 195.416 µs to 1,817.979 µs
(9.30×). The test measured the payload helper and excluded parsing and I/O.

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

Phase 1 interoperability checks used the pinned 7-Zip to produce and test
Stored and Deflate WinZip AES-256 archives. Zipfast's CLI and selected reader
and zipview's slice and range readers reproduced the original bytes. Pinned
UnRAR and 7-Zip also validated format-generated and RARLAB writer fixtures.
The reviewed zipfast CLI verified and extracted the writer archives, and
four split and solid selected reads reproduced the writer inputs. Two
members of the pinned rarfile archive matched fresh UnRAR output.

Reference binaries and externally sourced archives were used in local
scratch and carry their original terms. The UnRAR sources and the affected
7-Zip RAR decoder files carry UnRAR restrictions. The RARLAB 7.23 trial
writer and the archives it generated were kept for private evaluation
pending redistribution review. The upstream rarfile fixture was fetched by
revision and checksum for comparison. The new regression tests use
locally generated fixtures.

Prybar's Ubuntu workflow builds tools with
`scripts/build-compatibility-references.sh`, builds the CLI with
`cargo build -p prybar --locked`, and runs
`scripts/check-compatibility.py target/debug/pry "$RUNNER_TEMP/prybar-references/bin"`.
The Prybar build script also pins par2cmdline at
`3f247813023c9721fae3543309e977b1272c840e` and par2cmdline-turbo at
`3e60f6fcfed52bf257e79c46deae616cb6135d59`. The separate Debian arm64
smoke covers the five tools in the table, including Info-ZIP UnZip. The local
build and smoke commands, logs, and binary checksums are in
`/tmp/zipfast-reference.SZkt27` while that scratch directory is available.
Prybar's `scripts/check-encryption.py` uses pyzipper 0.3.6 and pinned rarfile
fixtures for independent interoperability checks.
