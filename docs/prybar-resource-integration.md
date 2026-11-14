# Prybar resource-efficiency integration

The historical resource-efficiency audit below compares Prybar `95a0fccb696c4e8e3b46ecceed760cc7941fc2ba` and its live Zipfast/zip-container Git dependencies at `82e88a6dabd2025dde0342583fa41345287dde73` with the Resource Maxxer audit of standalone Zipfast `f41aae515472ce25b6309d777fcc3e738b2a98ec` and Prybar `3149c2437b8f7db74ee810b336610661d91a8404`.

Prybar now resolves its runtime engines from the Git dependencies in `crates/pry/Cargo.toml`. Its excluded bundled source directories are historical snapshots, with some fixture references. Confirm the Cargo resolution when adopting this change.

## Engine update

Update **both** `zipfast` and the direct `zip-container` dependency in `crates/pry/Cargo.toml` to the reviewed squash commit containing the resource changes. Refresh `Cargo.lock` and verify that both packages resolve from the same immutable Git revision. Review the lockfile diff for unrelated updates. Different Git revisions can produce duplicate package/type identities and break nested error matching.

The engine changes add private owned-buffer paths behind the existing ZIP reader. `Archive::read_at`, `ReadSession` selections and ordinary extraction retain their public interfaces. AES authenticates ciphertext before in-place decryption. ZIP, TAR and RAR listing conversions consume their owned names and link metadata. Existing Prybar callers receive those changes through the dependency update.

Legacy encrypted ZIP APIs retain their 128 MiB packed-member ceiling. The additive checked reader and ordinary engine CLI now use bounded streaming; see [checked ZIP reads](zip-checked-reads.md). Engine qualification does not claim that Prybar's live adapters have adopted these APIs.

For the checked-reader update, pin both Git engine dependencies to the actual reviewed, merged engine revision recorded by the coordinator. No future merge SHA is available at qualification time. Use `EncryptedReadContext::for_session` with the original retained `EntryId`, a fresh context per retry and `SelectedZipEntry::read_with_context`. A generic ZIP selection can instead use `open_cancelable_with_zip_limit`, `zip_read_context` and `read_with_zip_context` while retaining its original owner through output completion. Keep Prybar's selected extraction/print 8 GiB policy, preview 64 MiB full-verification ceiling and 4096-byte displayed prefix. These are caller policies, independent of the engine's catalogue-derived CLI allowances and conservative library defaults.

Bind verified print output with `ZipReadStage`, admit the actual stdout FD and retain the original source through `copy_verified`'s final check. `EntryGuard::default()` does not justify dropping or reopening the original source. Preserve typed failures, partial accepted counts and publication state. Source/namespace checks remain optimistic under the storage threat model documented in the checked-reader guide. Task7 still owns actual printing/preview/extraction, UI/status, aliases, BrokenPipe and source-mutation qualification; no engine-only result closes those caller gates.

## Checked extraction storage and legacy error channels

The milestone deliberately restricts checked ZIP extraction, including clear members, to ownership-enforced local APFS on macOS or ext-family/XFS/Btrfs/tmpfs on Linux, with the implemented trusted procfs descriptor and ACL facilities. Linux overlayfs/container root, network mounts, exFAT and macOS HFS+ are common refused destinations. Provide supported mounted output and encrypted-snapshot temporary locations; changing temp storage cannot enable an unsupported destination, and permissions cannot enable an unlisted backend. Physical qualification covers APFS/ext4/Btrfs/tmpfs; XFS is admitted but not physically qualified and no other ext variant is claimed tested. Preserve this visible restriction in the release PR and caller handoff; full filesystem compatibility remains open. See [release notes](zip-checked-release-notes.md).

For generic non-ZIP run fallback, preserve Prybar's existing LEGACY sink path. `LegacyDiagnostic` is the original mixed progress/skip/failure callback text. Normal output prints that channel and ignores `LegacyError`. Quiet output ignores mixed diagnostics and prints only ordered borrowed `LegacyError` strings from the original successful `Summary.errors`; silent output ignores both. Both channels reach a plain closure observer, so explicitly choose which to render. Legacy preparation remains skipped and its scope has no checked `emit` capability. No string matching or newly typed failure inference is needed. Observer failure suppresses every later callback/error replay/RunEnded; returned partial counts remain available.

## Catalogue reuse

Current inspection and ZIP browsing already retain one `zipfast::zip::ReadSession`. Inspection metadata and background browser reads share its source-bound catalogue. The audit's older two-catalogue browser implementation has been replaced.

Use `ReadSession::open`, `metadata`, `Metadata::entry_id`, `ReadSession::select`, the selected entry's `read`, and `check_source` for any further caller migration. IDs belong to their metadata snapshot. Preserve source-change checks, sticky invalidation, cancellation, directory/link admission, byte ceilings and full member verification. A successful prefix preview still requires verification of the complete selected member.

Two concrete adapter seams remain.

- `crates/pry/src/archive_compat.rs` legacy ZIP printing lists first and then opens `SelectedEntry`, producing two parses. Inspect once, match IDs from `Inspection::Zip`, and read through its retained session. Fully verify into the existing spool, recheck source and cancellation, then copy to the retained stdout writer. Preserve ambiguity and status handling.
- `crates/pry/src/archive.rs::extract_entry` can use a session for direct `--entry` ZIP operations. Its existing browser helper `extract_zip_entry` fixes flattening and overwrite policy. Factor a policy-aware staging helper so CLI options and browser skip behavior retain their respective semantics. This route currently parses once per operation. Repeated operations can benefit from retaining the session at their owning caller.

Retained sessions carry richer raw/canonical metadata than the lean listing API. Measure the actual caller before using one solely to reduce listing memory.

## RAR chains and legacy names

The current engine already implements the two source-level fixes identified in the older bundled Prybar audit.

- Legacy `SelectedEntry` discovery tracks the nearest independent compressed reset in `src/extract.rs`. `rar_read_at` decodes predecessors only within the selected chain. Current `RarSession` also tracks chains and required predecessors. Native UnRAR `p` and `t` each execute one ordered selection, reusing required history within that execution. Browser Other/direct legacy selection can still reopen metadata and repeat required history across separate jobs. A session does not retain a decoder between separate execution calls.
- `src/zip.rs::CP437_HIGH` is a constant table. The valid-UTF-8 fallback and invalid-EFS replacement behavior are already implemented at the current engine pin. No per-name CP437 table construction is required in live Prybar.

`src/extract.rs`, `src/rar5/unpack.rs` and `src/zip.rs` were each byte-identical between audited standalone f41aae5 and baseline82e88a6. Adoption of those existing fixes occurred through Prybar's current engine pin. The new resource patch addresses encrypted buffers and owned listing conversions.

Prybar `archive::display` still allocates per character while escaping names. That is an additional adapter opportunity with its own output and measurement requirements.

## Regression gates

Run the full Prybar macOS/Linux suite, strict Clippy/format/docs checks and relevant compatibility/PTY controls after the engine pin update. Include these cases through real adapters.

- Stored/Deflate encrypted reads, empty members, all AES strengths and AE variants, ZipCrypto header checks, passwords, damaged tags/ciphertext, truncation, exact selection limits and packed ceiling behavior. Failed integrity or cancellation must preserve existing destinations and keep provisional output private.
- Long-name and legacy-name listing metadata, duplicate names by ordinal, directory/link classification, UTF-8/EFS/Unicode extra handling and control/bidi display escaping.
- Browser corruption beyond the displayed 4 KiB, changed source paths/inodes/symlinks and restored timestamps, sticky stale state, cancellation, lock poisoning and terminal restoration.
- Session adapter changes with flatten/overwrite policy, no matches, ambiguous names, zero/out-of-range ordinals, source/output aliases, successful members followed by failure, and final source validation before publication or stdout copying.
- A large unrelated earlier RAR chain followed by a tiny independent compressed member must fit a budget below the earlier chain's work. A dependent solid member must still verify its required predecessors. Retain failed-predecessor, split-volume, password and hash regressions.

Measure an engine-pin-only Prybar build before adding adapter changes. Match compiler, release profile, lockfile, features, backend, inputs and threads across that comparison. Current Prybar enables flate2 zlib-rs/runtime detection and has its own lockfile/profile. Standalone Zipfast's measured miniz_oxide release comparison does not quantify Prybar wrapper or session-adapter costs.
