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

The import copied the committed tree with `git archive`. It preserves the
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
Use `-p zipview` to select the library or `--workspace` to select both
packages. The separate fuzz workspace has its own lockfile under
`crates/zipview/fuzz`.

The root lockfile retains every dependency version from the two standalone
library lockfiles. It adds the zipview package entry to the original zipfast
lockfile. The root release profile applies fat LTO, one codegen unit, and
abort on panic. Zipview's previous standalone profile set abort on panic and
used Cargo's other profile defaults. A downstream Cargo root controls its own
profile.

A build of zipview alone enables flate2's `zlib-rs` and
`runtime_detection` features. Its dependency graph contains flate2,
zlib-rs, crc32fast, and cfg-if. A workspace-wide build also enables
zipfast's flate2 defaults, adding miniz_oxide and its dependencies to the
graph. Flate2 1.1.10 selects zlib-rs when both Rust backends are enabled.
A zipfast-only build selects miniz_oxide. A downstream build that selects a
native flate2 backend can affect backend selection through feature
unification.
[Flate2 backend selection](https://docs.rs/flate2/1.1.10/src/flate2/ffi/mod.rs.html)

## Git dependencies and packaging

Once the import commit is available on the zipfast remote, pin its full
revision. Cargo finds each package by name within the repository.

```toml
[dependencies]
zipfast = { git = "https://github.com/xbmc4lyfe/zipfast", rev = "<import commit>" }
zipview = { git = "https://github.com/xbmc4lyfe/zipfast", rev = "<import commit>" }
```

Use `cargo install --git https://github.com/xbmc4lyfe/zipfast --rev <import commit> --locked --bin zipfast zipfast`
to install the binary. Record the full remote revision and resolved
`Cargo.lock` when updating a downstream consumer. Validate the new pin
against its caller tests before retiring the standalone source. Preserve
the previous pin for rollback.

Zipview 0.1.0 can be packaged from the workspace. A crates.io lookup found
no release for that version at the time of the import. Zipfast declares
`publish = false`.

If zipview later depends on a shared `zip-container` package, add a
registry version alongside the local path in zipview's manifest. Package
and verify the parser first, publish it before zipview, and verify zipview's
packaged build resolves that registry release before publishing zipview.
[Cargo dependency locations](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#multiple-locations)
