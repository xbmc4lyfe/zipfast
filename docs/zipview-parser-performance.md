# Zipview shared parser verification

Code revision `4d1f39d618eb086c1eb3881f08bea25e6963cca4` uses the
shared checked parser for slice and range opening. Each borrowed central
record becomes a public entry directly. The default shared parser API
still retains raw records for consumers that need lossless metadata.

## Correctness and packaging

Independent reviews of the adapter and direct projection found no actionable
correctness defects. The final revision passed 317 workspace tests and five
doctests. Including the 25 writer tests compiled through the bench example,
the comparable all-target count is 342. Rust 1.87 parser and zipview checks,
strict Clippy, documentation, all 11 fuzz seeds, and 10,000 fuzz iterations
from the exact commit passed. Clean Git consumers passed on Rust 1.87 and
1.99.1, including existing public signatures and default parser inference.

Two clone regressions were reproduced on the preceding implementation.
Preserving walk scratch capacity keeps partial-supply work checks consistent
between the original and clone. Fallible discovery tail reservation prevents
a partial clone from growing its buffer beyond the intended reservation.

Cargo packaged the parser first, then zipview. The normalized zipview
manifest uses only parser version 0.1.0. A checksummed local Cargo directory
source supplied the actual parser archive; removing it made resolution fail.
Extracted packages passed on Rust 1.87 and 1.99.1. This validates package
order and resolution, not a registry publication. Neither package version
was present in the public index during these checks.

## Public API measurements

The benchmark compares Phase 1 `914e005`, the first adapter `1249c00`, and
`4d1f39d`. All consumers used flate2 1.1.10, zlib-rs 0.6.8 with runtime
detection, fat LTO, one codegen unit, and abort on panic. The host was an
Apple M4 running macOS 27.3 and Rust 1.99.1. Each condition used five paired
trials with alternating order. The table shows file-primed medians; OS
caches were not evicted. Separate paired runs have their own control values.

| 200,000-entry fixture | API | Phase 1 to direct projection, ms | First adapter to direct projection, ms |
| --- | --- | ---: | ---: |
| Short names | Slice | 3.741 to 7.526 | 8.446 to 7.620 |
| Short names | Range | 6.150 to 8.752 | 9.841 to 9.418 |
| Rich metadata | Slice | 7.269 to 11.370 | 18.278 to 11.400 |
| Rich metadata | Range | 21.741 to 21.119 | 28.091 to 20.944 |
| Unicode extras | Slice | 7.119 to 11.222 | 12.360 to 11.336 |
| Unicode extras | Range | 18.532 to 19.465 | 20.462 to 19.206 |

Direct projection removes the intermediate raw-record vector and copies of
entry comments that zipview does not expose. Rich slice peak allocation
falls from 100.96 to 54.42 MiB, with 54.36 MiB retained. Rich range peak
falls from 116.08 to 69.91 MiB; Phase 1 used 101.14 MiB. Short range peak
falls from 45.77 to 27.46 MiB; Phase 1 used 32.27 MiB. These allocation
counts exclude the caller's slice buffer. Process RSS includes that buffer
and allocator residency and is not a parser budget.

An additional control uses 200,000 identical 205-byte invalid UTF-8 names.
Each decodes to 615 bytes, preserving the old lossy output. Exact reservation
reduces retained allocation from 180,000,014 to 139,000,014 bytes by removing
unused String capacity. The valid-name control retains 57,000,014 bytes.
The name budget counts raw bytes; decoded storage can be three times larger.

All 968 timing and allocation invocations passed. Correctness checks covered
seven primary fixtures and both invalid/valid name controls, duplicate
ordinal payloads, and selected reads. The root reader streamed and verified
a 257 MiB member that zipview rejected before allocating or fetching its
payload. All 27 callback traces matched the first adapter exactly across
nine fixtures. Short, rich and Unicode directories use 4, 11 and 9 opening
requests, respectively: two more than Phase 1, while transferring about
64 KiB less. The local-file benchmark does not measure network latency.

## Remaining costs

The first adapter's avoidable staging cost is removed, but opening remains
slower than Phase 1 for several workloads. Short slice and range medians
remain 101% and 42% slower; rich slice remains 56% slower. Rich range is
within the Phase 1 spread. These are documented regressions, not claims of
performance parity. Historical sources and benchmark artifacts remain
available for rollback and further comparison. No downstream pin changes
are part of this adapter.

A focused three-second sample of a warmed public short-directory open loop
reproduced the gap. Of 1,900 samples inside candidate opening, 61.5% had
leaves in shared walker functions and 36.2% were within entry projection.
Symbols identified checked layout/header work, borrowed view construction,
projection dispatch and result handling. The short fixture has no extras,
so Unicode CRC is not responsible. Sampling does not isolate the cost of
individual checks or predict the gain from changing dispatch.

The adapter accepts this measured tradeoff after investigating the original
regression, removing staging costs, and verifying identical request traces
and correctness. It does not relax checks to recover baseline timing.
Further dispatch optimization remains possible; the root adapter and final
Phase 2 caller measurements have separate acceptance gates.
