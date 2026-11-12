# Zipview merge and archive compatibility implementation plan

## Codex handoff

Start from the root of the `zipfast` repository. This is the destination
workspace. The source checkout is `../zipview`.

Use `superpowers:subagent-driven-development` to implement this plan
milestone by milestone. Use `superpowers:executing-plans` for inline
execution if subagents are unavailable.

Start with Phase 1. Inspect both working trees and preserve the local
RPL 1.5 changes. Import the RPL-licensed `zipview` revision recorded
in Git. Complete Phase 1's acceptance checks before starting parser
consolidation or compatibility work.

### Subagent models and reasoning effort

Run the lead session on GPT-6 Astra with `high` effort. The lead owns
phase ordering, cross-repository decisions, and integration. Delegate
implementation and independent review through the Superpowers skill.
Set the model and reasoning effort explicitly for each dispatch.

| Assignment | Model and effort | Use in this plan |
| --- | --- | --- |
| Mechanical work | `gpt-6-luna` · `low` | Inventory paths, summarize existing test results, or apply a fully specified edit with a deterministic check. |
| Default implementer | `gpt-6.1-sol` · `medium` | Port a bounded upstream change, implement a specified Rust API, add interoperability tests, or wire CI. Use this as the starting point for implementation that requires judgment. |
| Integration and focused review | `gpt-6.1-sol` · `high` | Reconcile Cargo features and MSRV, diagnose disagreements with reference tools, or independently review a behavior-changing diff. Use `medium` for routine reviews with clear acceptance criteria. |
| High-risk design and review | `gpt-6-astra` · `high` | Resolve parser and public API boundaries, review archive-controlled resource limits, encryption integrity, or atomic publication, and conduct the final whole-branch adversarial review. |

Give each implementer the milestone brief, relevant interfaces, assigned
files, and acceptance commands. Give the independent reviewer the base
revision, diff, and test evidence. Run agents in parallel when their
files and decisions are independent. Batch related mechanical work.

Escalate when an agent cannot establish a failing reproduction, retries
without new evidence, or discovers a cross-crate invariant. Narrow the
brief first, then move from Luna to Sol or raise Sol to `high`. Use Astra
`high` for unresolved design or safety decisions. Reserve `xhigh` for
a specific unresolved high-risk question after a focused `high` pass.
If a model is unavailable, choose an available model for the same role
and record the substitution in the execution ledger.

[OpenAI Docs on model selection](https://learn.chatgpt.com/docs/models) ·
[OpenAI Docs on Codex subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents)

**Goal**. Bring zipview into the zipfast repository, converge on one ZIP
container parser, and supply the engine APIs Prybar needs for GNU gzip,
Info-ZIP Zip, and UnRAR compatibility.

**Architecture**. Keep `zipfast` and `zipview` as separate Cargo packages in
the zipfast workspace. Zipview retains its slice and range-reading APIs.
Zipfast owns filesystem extraction, archive writers, and additional codecs.
Prybar owns command syntax, prompts, output formatting, and exit codes.

**Execution**. Use independently testable PRs within each phase. Add failing
regression or interoperability tests before each behavior change. Review each phase
independently and run its acceptance checks before switching callers.

## Baselines and constraints

| Repository | Reviewed revision | Relevant behavior |
| --- | --- | --- |
| zipfast | `4443e1c2923c2cbeb10d8559b56effd76c9e31b1` | ZIP reading and extraction, RAR5 algorithm version 0, and tar and compressed stream decoding |
| zipview | `2c3d73a06b29987cea1510e903e437a482076745` | `ZipReader`, `ZipIndex`, `ZipIndexOpener`, entry metadata, bounded reads, and password APIs |
| Prybar | `d3b8aa32a7c7214919b9c973588a9aa97a6a0e88` | Compatibility adapters and a vendored zipfast snapshot with selected reads, output staging, integrity fixes, and decoder limits |

- Record source revisions and licenses in the importing repository.
  Select the zipview revision with the RPL 1.5 license and attribution
  notices for the import. Keep historical notices and third-party terms.
  Check the obligations for distributing the merged workspace and for
  updating downstream pins.
- Preserve the existing crate names, zipfast binary, root package layout, and
  zipview's default API and codec backend. Keep the shared parser free of
  third-party dependencies and keep filesystem and native codec dependencies
  out of zipview's dependency graph. Test zipview on its
  declared Rust 1.87 floor independently of newer workspace packages.
- Preserve intentional safety limits and typed errors. Match reference
  behavior for supported cases and record intentional differences in the
  compatibility matrix.
- Treat archive paths, offsets, declared sizes, and metadata as untrusted.
  Preserve original files on verification, cancellation, or prepublication
  errors.

## Licensing and contribution policy

The maintainer confirmed ownership and sign-offs and selected Reciprocal
Public License 1.5 for the first-party zipfast and zipview source. The
project attribution in Exhibit B names each library and xbmc4lyfe.
Section 6 describes public source availability, community notice, and
attribution for covered deployed extensions. The projects welcome
patches through their repositories.
[RPL 1.5, sections 1.2 and 6](https://opensource.org/license/rpl-1-5)

- Import the RPL-licensed zipview revision once it is recorded in Git.
  The baseline table identifies the earlier code used for technical
  comparison. Preserve the terms granted on earlier copies.
- Keep records for original work, commissioned code, imported files,
  fixtures, and AI-assisted source. For any future outside code,
  obtain a copyright assignment or an explicit relicensing grant before
  inclusion if the maintainer needs to relicense it.
- Review the terms of dependencies and downstream combinations before
  changing Prybar's engine pins. Its existing GPL-covered snapshots
  and dependencies retain their applicable terms. Resolve licensing for
  the combined distribution before shipping a release with the new pins.
- Retain both project attribution notices when incorporating code from
  both libraries. Keep the required source notices and license text with
  distributed copies.

## First compatibility release

Ship ZIP creation and staged add or replace, with Stored and Deflate, a
safe recursive file list, and `-T`. Ship the shared gzip engine with
Prybar's current stream commands plus `-N`, `-S`, and `-r`. Extend
the existing RAR5 path with typed failures, literal member selection,
and verified printing. Deliver each independently once its engine and
CLI tests pass. Advanced ZIP updates, encryption, splitting and recovery,
additional gzip options, and RAR decoder expansion follow in their own PRs.

## Phase 1. Import zipview and reconcile the engine baseline

- [ ] Capture locked test results for both standalone checkouts. Record
  downstream call sites for public zipview APIs and the zipfast CLI.
- [ ] Add a workspace to the root `Cargo.toml`. Keep the root `zipfast`
  package and import zipview under `crates/zipview/` at the recorded RPL revision.
  Preserve import provenance and keep its source notices, tests, examples,
  fuzz targets, and seed corpus.
  Exclude the fuzz package from the main workspace if it retains its own
  lockfile and toolchain. Port applicable CI jobs to the repository root.
- [ ] Reconcile the unified lockfile and effective Cargo profiles. Run the
  old standalone build and workspace build on equivalent inputs. Check
  examples, fuzz target compilation, public API imports, and dependency
  features when building zipview alone and with zipfast. Use
  `cargo +1.87.0 test -p zipview --locked` and
  `cargo tree -p zipview -e features`. Compare the resolved dependency
  tree with a clean consumer using zipview alone.
- [ ] Inventory the differences in Prybar's vendored zipfast. Port behavior
  and tests together in small changes, including selected reads, archive
  input protection, staged output, WinZip AES authentication, encrypted RAR
  verification, listing budgets, and decoder limits. Record any local
  changes that are CLI-specific or superseded upstream.
- [ ] Document new source locations for direct Git dependencies. Build a
  clean consumer for each package and plan a downstream pin update before
  retiring the standalone zipview repository. Check the current publishing
  path before introducing a shared path dependency. If zipview is packaged
  for a registry, provide a publishable versioned parser dependency and
  validate packaging in dependency order.

## Phase 2. Use one ZIP container parser

- [ ] Add fixture parity tests before changing either reader. Compare central
  directory order, duplicate names, raw and decoded names, archive comments,
  timestamps, Unix attributes, encryption fields, ZIP64, prefixed archives,
  and local payload offsets. Exercise slice and ranged readers with the same
  inputs. Record existing disagreements and choose the required result for
  each case.
- [ ] Start with the existing zipview directory and range implementation.
  Move only format parsing shared by both readers into an internal workspace
  package under `crates/zip-container/`. Give it bounded slice and range
  access and entry records that retain raw names, entry comments, AES
  vendor version, strength, and method alongside normalized fields.
  Preserve unknown extras and distinguish local headers from central
  records. Retain raw record ranges so rewrite can copy metadata without
  storing every byte in memory. Keep decoding, file I/O, path policy, and
  password handling with the caller. Preserve public `ZipEntry`,
  `ZipReadError`, and `PasswordCheck` types through the existing APIs,
  including zipfast's public entry fields.
- [ ] Define caller-supplied limits for directory bytes, entry count, total
  owned name, extra-field, and comment bytes, cumulative fetched bytes,
  individual ranges, and parser work. Support cancellation between range
  requests. Check arithmetic before allocating or requesting bytes.
  Keep zipview's 256 MiB in-memory inflation cap and 16 MiB directory
  request limit at its API boundary. Preserve Prybar's 129 MiB cumulative
  metadata read ceiling during the cutover. Keep zipfast's streaming
  extraction and decoder limits at its boundary. Test that a large
  streamed entry succeeds while the equivalent zipview allocation fails.
- [ ] Adapt zipfast's `src/zip.rs` to the shared records. Preserve ZIP
  method dispatch, data descriptor handling, bounds, full CRC and AES tag
  checks, and the exact entry selected when names repeat. Keep packed and
  unpacked read limits.
- [ ] Expose ZIP metadata and stable entry IDs from the same open archive
  that supports selected reads. Bind IDs to the archive instance and reject
  reuse against a different archive or a changed input. Test replacement
  and in-place mutation between listing and reading. Switch Prybar's ZIP
  inspect and explorer paths to that API. Remove the second open and
  metadata matching once the CLI and terminal tests pass against the new
  revision.
- [ ] Compare cold and warm metadata lookup on large ZIP directories,
  ranged bytes and request counts, peak allocation, and extraction
  throughput. Record results against the original builds with the same
  inputs and backend features. Investigate material regressions before
  removing either old parser path.

## Phase 3. Build the ZIP writer and Info-ZIP adapter

| Milestone | zipfast engine | Prybar adapter and acceptance |
| --- | --- | --- |
| Create | Add a writer under `src/zip/write.rs`. Start with streaming entry input and seekable output. Implement Stored and Deflate, ZIP64, UTF-8 and raw names, timestamps, permissions, comments, empty entries, and regular directories. Add nonseekable output and descriptors after seekable output passes interoperability tests. | Support `zip archive.zip files...`, recursive input, Store and compression levels, and testing the result with `-T`. Extract and test output using independent Info-ZIP UnZip and 7-Zip. |
| Modify | Add a copy-and-rewrite transaction. Preserve untouched compressed bytes and metadata, recalculate offsets, and publish a verified replacement from the same filesystem. Define duplicate selection, order, unsupported entry handling, and failure results. | Map add or replace, `-u`, `-f`, `-d`, and then `-m`. Remove source files for move only after publication, with identity checks and per-file failures. |
| Encryption | Add interoperable ZipCrypto for legacy compatibility and a separate authenticated WinZip AES write mode. Specify salt or header randomness, tag and CRC rules, and unsupported combinations. | Compare Info-ZIP `-e` with independent readers. Keep AES explicitly separate and test against an AES-capable reference. Test wrong passwords and changed data. |
| Recovery and splitting | Define split-volume output and a recovery scanner as separate engine changes. Recover bounded, verifiable members from damaged structures and write a new archive. | Compare split archives and `-F` and `-FF` behavior using independent fixtures. Report partial recovery and preserve the source archive. |

- [ ] Start with creation and explicit finalization. Verify the ZIP32 to
  ZIP64 transition at size, offset, and entry-count boundaries. Test
  descriptor widths, unknown input lengths, empty archives, and simulated
  short writes. Use a sparse or synthetic fixture for boundary cases where
  practical.
- [ ] Define the publication contract before adding updates. For path
  output, stage in the destination directory, flush and finalize, verify,
  then publish with explicit no-clobber or replacement semantics. Check
  source and destination identity before commit and define concurrent
  writer behavior. State which guarantees apply to atomic visibility and
  which require file and directory synchronization for crash durability.
  A nonseekable sink can receive a partial stream if writing fails.
- [ ] Implement update planning before mutation. Assert the old archive
  remains byte-for-byte intact when writing, verification, or replacement
  fails. Cover existing destinations, source aliases, duplicate names,
  unknown metadata fields, and unsupported codecs in untouched entries.
  Verify structural consistency and byte preservation for raw-copied
  entries. Verify decoded bytes and CRC for new or replaced entries.
  Report entries that could only be checked structurally. If the caller
  requests full testing with `-T`, fail before publication when a member
  cannot be verified.
- [ ] Inject failures at write, flush, finalization, verification, rename,
  directory sync, and source deletion. Assert temporary-file cleanup and
  distinguish failure before publication from a committed archive with
  durability or cleanup errors. For `-m`, keep a successfully published
  archive when some source deletions fail and report the remaining files.
- [ ] Add Info-ZIP command fixtures for option precedence, pattern selection,
  return codes, and no-op outcomes. Keep interactive prompts and recursion
  rules in Prybar.

See [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT),
the [WinZip AES specification](https://www.winzip.com/en/support/aes-encryption/),
and the [pinned Info-ZIP source](https://github.com/apple-oss-distributions/zip/tree/c8d52ed44169a71e362af3814988685aa39ee7b4/zip/zip30).

## Phase 4. Share gzip functionality

- [ ] Extract reusable gzip framing and streaming operations from Prybar's
  `crates/pry/src/gzip_compat.rs` into `src/stream/gzip.rs` in zipfast.
  Expose compression, verified decompression, test and list statistics, and
  bounded member metadata. Reuse the flate2 backend already in use.
- [ ] Define member metadata and counters precisely. Report compressed and
  decoded bytes as checked 64-bit totals, report member headers through a
  bounded callback or iterator, and
  verify CRC and ISIZE per member. Make padding, trailing bytes, and format
  detection behavior explicit. Keep gzip header names separate from path
  selection. Compare the new API with zipfast's tar.gz and standalone gzip
  paths before replacing shared internals.
- [ ] Keep GNU command behavior in Prybar. Preserve stdin and stdout,
  default replacement, `-c`, `-d`, `-t`, `-l`, `-k`, `-f`, and
  compression levels. Add `-N`, `-S`, `-r`, and `-v` with safe
  filename restoration, explicit symlink policy, and differential fixtures.
  Scope `--rsyncable` and legacy formats separately based on codec support.
- [ ] Compare both directions with the pinned GNU gzip. Test concatenated
  members, empty streams, invalid CRC or size, trailing bytes, interrupted
  writes, counters beyond 4 GiB, terminal safeguards, and preservation of
  both source and destination on a failed file operation. Compare bytes
  after decoding and compare listing fields and statuses directly.

See [RFC 1952](https://www.rfc-editor.org/rfc/rfc1952) and the
[GNU gzip manual](https://www.gnu.org/software/gzip/manual/gzip.html).

## Phase 5. Extend UnRAR compatibility

- [ ] Add a typed per-entry outcome API alongside existing string reports in
  `src/extract.rs` and `src/error.rs`. Distinguish bad passwords, integrity
  errors, unsupported methods, no matches, and input and output failures.
  Preserve verified output and report ordering across parallel extraction.
- [ ] Expose structured RAR metadata and ordered member selection. Add a
  verified spool for stdout output when integrity checks finish after
  decoding. Publish one member at a time after verification. Define
  temporary storage limits and retain the existing archive order and
  solid-history semantics.
- [ ] In Prybar, extend `l`, `lb`, `t`, `x`, `e`, and `p` with
  technical and verbose listing, literal and wildcard selection, listfiles,
  output path and overwrite options, and documented status mappings. Cover
  the case where wrong member-data passwords currently return status 3
  instead of the reference's 11.
- [ ] Plan RAR4 reading and RAR5 algorithm version 1 as separate decoder
  changes. Generate fixtures with checksummed RARLAB writer builds where
  available. Record the version, commands, checksums, and fixture
  redistribution terms. Test stored and
  compressed files, solid history, encrypted headers and data, split
  volumes, dictionary limits, and unsupported-method errors. Review any
  third-party source terms before choosing an implementation.
- [ ] Keep RAR creation outside the UnRAR compatibility milestones. The
  reference CLI extracts, lists, tests, and prints members.

See the [RARLAB format notes](https://www.rarlab.com/technote.htm) and the
[pinned UnRAR mirror](https://github.com/pmachapman/unrar/tree/160dcb5c9c1babbbdd3f0f1fc78cf48a7f8150cf).

## Reference tests and delivery

| Reference | Baseline pin | Use |
| --- | --- | --- |
| GNU gzip | `b4ed8e73401968bcad749afb0e636dd3ec205ca7` | Stream, file, metadata, and status parity |
| Info-ZIP Zip | `c8d52ed44169a71e362af3814988685aa39ee7b4` | Apple's downstream Git tree for Zip command behavior |
| Info-ZIP UnZip | `036d96991646d0449ed0aa952e4fbe21b476ce994abc276e49d30e686708bd37` | SHA-256 of the [Debian-hosted upstream 6.0 source](https://deb.debian.org/debian/pool/main/u/unzip/unzip_6.0.orig.tar.gz), a secondary ZIP reader |
| 7-Zip | `d3296e39e1f1f92c7b41c0c3848e65640428d42d` | Independent ZIP interoperability |
| UnRAR | `160dcb5c9c1babbbdd3f0f1fc78cf48a7f8150cf` | Git mirror for read and CLI parity |

- [ ] Verify reference heads before implementation. Build at the recorded
  full commits and keep stable release source or a separately pinned reader
  as a secondary oracle where an official Git repository is unavailable.
- [ ] Extend Prybar's `scripts/build-compatibility-references.sh` and
  `scripts/check-compatibility.py` for each newly supported behavior.
  Add a Linux UnZip source build from the checked archive using its
  Unix makefile. Record the working compiler flags and ZIP64 support
  in the reference build script. Retain 7-Zip as a second reader.
  Run the corresponding differential tests whenever a reference or engine
  commit changes. Fail if a required tool cannot build or run.
- [ ] Record supported options, intentional differences, and reproducible
  fixtures in a compatibility matrix. Fix locale and timezone for
  comparisons. Check bytes, metadata, standard output, standard error,
  and status independently. Keep coverage for malformed end records,
  conflicting local and central metadata, checksum and authentication
  failures, missing split volumes, and unsafe extraction paths.
- [ ] Run workspace formatting, Clippy, locked tests, Google Vale, and
  relevant fuzz checks. Run clean-checkout consumer tests on Linux and
  macOS. Save the exact commands, source revisions, and benchmark results
  in each implementation PR.
- [ ] Land engine APIs before the dependent Prybar pin and adapter changes.
  Keep the previous engine pin available for rollback and update the
  compatibility matrix from verified command behavior.

## Astra adversarial review

Astra reviewed the draft against the three repository baselines. The plan
now requires lossless ZIP metadata, separate parser and decoder limits,
archive-bound entry IDs, and explicit structural and payload verification.
It also distinguishes publication from later durability and cleanup
failures, splits advanced format work into independent PRs, and pins an
independent UnZip source and RAR fixture provenance.
