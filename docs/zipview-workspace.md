# Zipview workspace integration

## Source and attribution

The root package is `zipfast`. The `zipview` library lives in
[`crates/zipview`](../crates/zipview/README.md).

| Project | Preservation commit | Upstream parent |
| --- | --- | --- |
| zipfast | `8e835ae08ebe3c0419b4647c6c26f910dd86ba10` | `4443e1c2923c2cbeb10d8559b56effd76c9e31b1` |
| zipview | `a90d138d2b82d41350abd382ca345871e3698fe1` | `2c3d73a06b29987cea1510e903e437a482076745` |

The zipview import came from the local preservation branch
`codex/rpl-import-source` at
`/Users/allen/.codex/worktrees/fea1/zipview-rpl-source`. Its Git origin was the
local standalone checkout at `/Users/allen/git.xbmc4lyfe/zipview`, whose
`origin/main` was the recorded parent.
[Standalone upstream](https://github.com/xbmc4lyfe/zipview/tree/2c3d73a06b29987cea1510e903e437a482076745)

At import commit `c0830e592e4cd008baba6a046621694ee2d3d7d8`, the
committed tree was copied with `git archive`. That commit preserves the
library and test source, examples, fuzz target, seed generator, all 11
curated seeds, and the crate's RPL notices byte for byte. The standalone
workflow moved to `.github/workflows/ci.yml` and now runs at workspace
scope. The standalone library lockfile was consolidated into the root
lockfile. The two zipview manifests and the local rustfmt configuration
account for the remaining integration changes.

The workspace retains both Exhibit B attributions and the applicable
licenses.
[Zipfast license](../LICENSE) · [Zipview license](../crates/zipview/LICENSE)

## Cargo behavior

A root `cargo build`, `cargo run`, or `cargo test` selects zipfast by default.
Use `-p zipview` to select the library or `--workspace` to select all
packages. The separate fuzz workspace has its own lockfile under
`crates/zipview/fuzz`.

At import, the root lockfile retained every dependency version from the two
standalone library lockfiles and added the zipview package entry. The root
release profile applies fat LTO, one codegen unit, and abort on panic.
Zipview's previous standalone profile set abort on panic and used Cargo's
other profile defaults. A downstream Cargo root controls its own profile.

A build of zipview alone enables flate2's `zlib-rs` and
`runtime_detection` features. Its active dependency graph contains `flate2`,
`zlib-rs`, `subtle`, and the dependency-free workspace crate `zip-container`.
WinZip AES uses `subtle` for constant-time verifier
and authentication tag comparisons. The packaged lockfile also records
`crc32fast` and `cfg-if`. A workspace-wide build also enables zipfast's
flate2 defaults, adding miniz_oxide and its dependencies to the graph.
Flate2 1.1.10 selects zlib-rs when both Rust backends are enabled.
A zipfast-only build selects miniz_oxide. A downstream build that selects a
native flate2 backend can affect backend selection through feature
unification.
[Flate2 backend selection](https://docs.rs/flate2/1.1.10/src/flate2/ffi/mod.rs.html)

## Git dependencies and packaging

Once the reviewed engine revision is available on the zipfast remote, pin its full
revision. Cargo finds each package by name within the repository.

```toml
[dependencies]
zipfast = { git = "https://github.com/xbmc4lyfe/zipfast", rev = "<full engine revision>" }
zipview = { git = "https://github.com/xbmc4lyfe/zipfast", rev = "<full engine revision>" }
```

Set `ENGINE_REV` to the full engine revision to install the binary.

```sh
cargo install --git https://github.com/xbmc4lyfe/zipfast --rev "$ENGINE_REV" --locked --bin zipfast zipfast
```

Record the full remote revision and resolved
`Cargo.lock` when updating a downstream consumer. Validate the new pin
against its caller tests before retiring the standalone source. Preserve
the previous pin for rollback.

At the reviewed revision, zipview retains the same public slice and range
APIs and the same Deflate backend. Full WinZip AES reads verify the payload
tag, while header password checks and prefix previews remain provisional.
Zipfast retains its default command, root package, and skip-existing
extraction default. Callers constructing `zipfast::extract::Options` must
initialize the new `protected_paths` field, which accepts an empty set.
The engine supplies its own archive and volume protections. See
[engine behavior and limits](engine-baseline.md#safety-behavior).

At the Phase 1 gate, Cargo verified the zipview 0.1.0 package from the workspace. It includes
the crate license, examples, and test sources. The independent fuzz workspace
and seed corpus are available from Git. A crates.io lookup found no release for
that version at the time of the import. Zipfast declares `publish = false`.

Zipview declares the `zip-container` dependency with both a version and a
workspace path. Package and verify the parser first. Until it is published,
verify zipview against an isolated source built from the parser's packaged
artifact. Publishing zipview requires the parser's registry release to
resolve from zipview's normalized manifest.
[Cargo dependency locations](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations)

## Import verification

The standalone baseline used `cargo test --locked` on macOS arm64 with
Homebrew Rust 1.99.1 and separate build directories. Zipfast passed 122 tests
and zipview passed 39. The baseline included the RPL notice changes captured
in the preservation commits above.

The following commands ran on macOS arm64 and in a Debian Bookworm arm64
Docker container, both with Rust 1.99.1.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
```

The macOS suite passed 175 tests and three doctests. The Linux suite passed
173 tests and three doctests. The benchmark example contributes 17 tests on
each platform. Two zipfast unit tests are specific to macOS.

Strict Clippy on Linux arm64 initially reported an unnecessary `unsafe`
block in zipfast's CRC folding code, also present on the standalone base.
A separate commit applied the equivalent change from Prybar's
`d3b8aa32a7c7214919b9c973588a9aa97a6a0e88` vendor snapshot. The explicit
unsafe scope now covers the SHA3 intrinsic. The existing CRC parity test
passed on both platforms and with SHA3 enabled on macOS.

These checks ran on macOS arm64 using the root manifest unless a command
changes the working directory.

| Command | Observed result |
| --- | --- |
| `cargo +1.87.0 test -p zipview --locked` | 39 passed on macOS and 39 passed in the Linux arm64 container. The macOS rustup installation lived in scratch and left shell configuration alone. |
| `cargo build --workspace --locked --examples` | Both packages' examples compiled. |
| `cargo check --manifest-path crates/zipview/fuzz/Cargo.toml --locked --bin fuzz_zip` | Fuzz target compiled with the independent lockfile. |
| `cd crates/zipview && cargo +nightly fuzz run fuzz_zip "$SMOKE_CORPUS" fuzz/seeds -- -max_total_time=120 -rss_limit_mb=4096` | 649,687 executions in 121 seconds using cargo-fuzz 0.13.2 and Rust nightly 1.102.0 (2026-11-11). The generated corpus was in scratch. |
| `cargo audit --file Cargo.lock` and `cargo audit --file crates/zipview/fuzz/Cargo.lock` | Both passed with cargo-audit 0.23.0 and RustSec database revision `fd6f39814c4d3c359fdbe223d0280dec4933f78f`. |
| `cargo package -p zipview --locked` and `cargo package -p zipview --locked --list` | Cargo packaged and verified 15 files. The unpacked package passed `cargo +1.87.0 test --locked` with 39 tests. |
| `cargo info zipview@0.1.0 --registry crates-io` | Cargo found no release for this version. |
| `vale --config=/Users/allen/git.xbmc4lyfe/prybar/.vale.ini README.md docs/zipview-workspace.md` | Vale 3.26.0 with Google style 0.7.1 reported zero findings in the two changed documents. |

At import, `cargo tree --locked -p zipview -e features` matched the archived
standalone checkout's `cargo tree --locked -e features` apart from the package
path. The feature graph also matched clean consumers on both platforms. The
clean consumer lockfiles initially selected flate2 1.1.11. Pinning the macOS
consumer to 1.1.10 with `cargo update -p flate2 --precise 1.1.10` produced
the same graph with identical versions. The combined feature graph was
recorded using `cargo tree --locked --workspace -e features`.

Clean Git consumers pinned `c0830e592e4cd008baba6a046621694ee2d3d7d8` in a
local bare mirror. On each platform, two independent consumer projects ran
`cargo generate-lockfile` and `cargo run --locked -- <stored seed>`.
The zipview consumer used `ZipReader`, `ZipIndex`, and `ZipIndexOpener`.
The zipfast consumer used `zipfast::extract::list`. The command installed
with `cargo install --git "$GIT_URL" --rev "$IMPORT_REV" --locked --bin zipfast --root "$INSTALL_DIR" zipfast`
and passed `zipfast t` on the same seed on each platform. The Linux
install emitted the unused-unsafe warning from the initial import
revision. The workspace Clippy and CRC parity results above cover the
subsequent CRC adjustment in `ea51228e932066e6958852a60cdfdf92977f0f1d`.

Archived standalone and workspace builds of zipview ran
`cargo run --release --locked --example seedcheck` from their respective
package directories. Both accepted all 11 curated seeds and produced
identical output. Standalone and workspace `zipfast` binaries built with
`cargo build --release --locked --bin zipfast` produced identical listing
and test summaries on the stored, deflated, and Unicode seeds after
normalizing the elapsed time and throughput in test output.

Workspace formatting passed at import. The separate fuzz formatting command
`cargo fmt --manifest-path crates/zipview/fuzz/Cargo.toml -- --check` reports
one line wrap in the original fuzz target on Rust 1.99.1. The standalone
snapshot produces the same diff. Commit `5cd2502` wraps that line after the
byte-preserving import. The workflow passed actionlint 1.7.7.

## Phase 1 verification

The reviewed code revision is `14e68d5196304656c76062b7f7c435f7c21e9a5c`.
The results below cover that revision. The final documentation edit restores
the spaces in two zipview README example strings.

| Check | Observed result |
| --- | --- |
| Workspace formatting, strict Clippy, locked all-target tests and doctests | Passed on native macOS arm64 and Debian Bookworm arm64 in Docker with Rust 1.99.1. macOS passed 246 tests and three doctests. Linux passed 244 tests and three doctests. |
| Zipview on Rust 1.87.0 | `cargo +1.87.0 test -p zipview --locked` passed 41 tests and three doctests on both platforms. |
| Examples and default package | Both packages' examples compiled on both platforms. Zipview's seed checker accepted all 11 curated seeds on macOS. A root `cargo build --locked` selected zipfast, and `cargo run --locked -- t <seed>` succeeded on both platforms. |
| Clean Git consumers | Independent zipview and zipfast consumers built and ran from a bare local Git mirror on both platforms. The installed root CLI verified the same seed. The zipview-only feature trees matched the workspace package after aligning flate2 to 1.1.10 and removing the package source path. |
| Prybar callers | A temporary archive of Prybar `d3b8aa3` built with both Git dependencies pinned to the reviewed engine revision. Its original checkout, vendored snapshots, and recorded pins stay in place. This was a local research build. |
| Zipview packaging | `cargo package -p zipview --locked` verified 15 files. The extracted package passed 41 tests and three doctests on Rust 1.87.0. |
| Independent fuzz workspace | Formatting and locked compilation passed. A seeded nightly smoke run completed 560,438 executions in 121 seconds. |
| Dependency audits | Both lockfiles passed with cargo-audit 0.23.0 and RustSec revision `fd6f39814c4d3c359fdbe223d0280dec4933f78f`. |

GitHub-hosted runs and remote Git consumer verification are pending.
Review the combined distribution terms and run the downstream caller
checks before changing Prybar's pins or retiring the standalone repository.
[Licensing and downstream inventory](engine-baseline.md)
