# Encrypted streaming qualification

This qualification was performed on 2026-11-14 from checked engine base `291daba52e32edee2e8af3ff31d20547bee5b9ec`. The filename retains the plan date. Exact final source, binary, fixture, platform and raw evidence identities are kept with the private engine report. Engine merge review and Prybar adoption remain separate gates.

Finite tests in `tests/zip_checked_resources.rs` cover real projected/retained/generic selection, explicit/policy ZIP and generic run methods, verified stages and the actual CLI. Native AES strengths128/192/256 and AE-1/AE-2 use Stored/Deflate, empty and nonempty payloads. Scoped unit-test source/plaintext caps exercise actual public reads for all six codecs at one-byte fragmentation, including full65536/65537-byte output windows; native pumps keep their real coalescing behavior. Public hooks cover typed allocation denial, ENOSPC without plaintext/fallback, once-only ambiguous close and provisional source mutation. A source change before verified stage copying accepts zero output bytes and preserves the destination. Release APIs expose no test injector.

Ignored `zip_checked_large` tests actually decode the retained AES U134217729/P134217757 fixture (SHA256 `6dbd96a30a8248d729d401182ed8161e537209348bbd728f7bb13194afcccfb3`) and the native-writer AES Deflate U8589934593/P83006459 fixture (SHA256 `15a3847e08a0c43a202ce38eebc8c870fa46ef6addfd96ddf1b094c12c4b3f3f`). Bounded expected zero-stream counts/BLAKE2sp hashes match complete old/new API reads. Explicit/policy runs and actual old/new CLI test paths consume the full decoded bytes; old packed-cap refusal is capability evidence only. The larger fixture is genuine compressed ciphertext. Catalogue-derived staged-files admission covers its U and combined ciphertext/plaintext allowance without retaining an8GiB+ extraction. Conservative new library defaults intentionally refuse U>8GiB.

Correct65535/65536/100000-byte passwords use retained independent Python/OpenSSL reference ciphertext and pass old/new engines. Writer metadata validation is unchanged. Wrong, absent, empty and explicitly lower-capped attempts remain separate tests. A distinct external Cargo consumer compiles the new APIs and hashes actual134217729-byte output. Existing old-cap tests/consumers remain unchanged. Retained independently reference-qualified native fixtures contribute42 full public member comparisons, including Deflate levels1/6/9 and raw/Unicode names.

## Matched standalone CLI resources

The preserved old release binary SHA256 is `ae9029025acbac5524f02e907c2c5aa84d5518452dd8e52d5faa15c66754fd7e`; candidate SHA256 is `8d647c96a5bcb354c50f1bca39b1d184d063b0b5dfbfb0f2673c53737d063c08`. Both use rustc1.99.1, the identical lock, default miniz backend/features and repository release profile. Normal scheduling, mt1, sequential explicit input warming, no global cache purge and a root-verified no-concurrent-build slot were recorded. The48 original baseline trials remain preserved; this fresh campaign alternates old/new order across three pairs per workload (96 trials). All96 statuses and full output file/hash manifests pass.

Each cell below is the median of three observations. Wall time includes process spawn/wait4 completion and10ms polling; CPU and process peak RSS come from wait4. Input warming, output hash checking and post-exit synchronization are outside child metrics. Tiny wall values near16ms are limited by polling and cannot establish small throughput differences. Physical I/O is unavailable/null on this Mac, not zero. This standalone miniz comparison does not measure Prybar's zlib-rs or UI overhead.

| Workload | Wall old/new (ms) | Wall change | CPU old/new (ms) | Peak RSS old/new (MiB) |
|---|---:|---:|---:|---:|
| aes-stored-16mib | 151.78 / 166.92 | +10.0% | 139.82 / 152.14 | 25.19 / 2.77 |
| zipcrypto-stored-16mib | 121.76 / 121.63 | -0.1% | 110.69 / 109.90 | 25.17 / 2.77 |
| aes-stored-127mib | 1096.79 / 1174.22 | +7.1% | 1082.39 / 1170.11 | 136.19 / 2.77 |
| zipcrypto-stored-127mib | 912.61 / 872.71 | -4.4% | 861.61 / 855.36 | 136.17 / 2.77 |
| aes-deflate-32mib | 166.81 / 178.12 | +6.8% | 155.17 / 161.07 | 26.41 / 2.86 |
| zipcrypto-deflate-32mib | 121.81 / 136.70 | +12.2% | 118.55 / 119.02 | 26.39 / 2.84 |
| aes-deflate-252mib | 1165.80 / 1314.92 | +12.8% | 1134.16 / 1247.13 | 137.00 / 2.88 |
| zipcrypto-deflate-252mib | 939.22 / 943.13 | +0.4% | 925.54 / 925.71 | 136.98 / 2.84 |
| aes-tiny | 16.51 / 16.54 | +0.2% | 4.11 / 5.35 | 1.88 / 2.70 |
| zipcrypto-tiny | 16.52 / 16.57 | +0.3% | 1.82 / 2.68 | 1.86 / 2.70 |
| aes-threshold | 16.39 / 16.34 | -0.3% | 4.76 / 5.65 | 2.12 / 2.81 |
| zipcrypto-threshold | 16.53 / 16.50 | -0.2% | 2.25 / 2.96 | 2.11 / 2.77 |
| aes-threshold-plus-one | 16.47 / 16.62 | +0.9% | 4.66 / 5.90 | 2.12 / 2.78 |
| zipcrypto-threshold-plus-one | 16.52 / 16.53 | +0.0% | 2.34 / 3.09 | 2.11 / 2.77 |
| aes-many-small | 346.94 / 451.13 | +30.0% | 336.89 / 440.20 | 2.25 / 2.92 |
| zipcrypto-many-small | 31.57 / 136.79 | +333.3% | 19.12 / 127.58 | 2.25 / 2.92 |

Large-member memory falls substantially, with throughput tradeoffs: AES large workloads take7–13% longer here. Synchronous checked staging and policy/source/diagnostic operations cost more on many-small workloads: AES +30%, ZipCrypto +333% (31.6→136.8ms). These results do not support a general speedup claim or isolate the cost of individual safety operations.

## Actual public small-entry resources

A separate prebuilt release test measures45 actual checked callback reads: U1/65535/65536/65537/1048576 × thresholds65535/65536/65537 × three observations. It records authentication-to-first-callback delay, full byte/hash equality, successful Rust allocation requests/peak-live bytes and real ledger totals. Setup, input warming, expected hashes and native fixture generation are outside each read; action teardown is recorded separately. Fixed-slot thread-local allocation observation excludes native C malloc, allocator metadata, stack, source/catalogue setup before scope and arbitrary caller storage. The CLI timing binary is uninstrumented. The ordered threshold trials are descriptive, not a randomized causal estimate.

At U65536, threshold65535 spools and records262202 logical I/O bytes with135168 peak-live observed Rust bytes; threshold65536 stays in memory and records65594 logical I/O bytes with196608 observed Rust bytes. At U65537, threshold65536 spools (262206 logical bytes,135168 Rust bytes), while threshold65537 uses memory (65595 logical bytes,196609 Rust bytes). For successful disk-backed callback reads, measured total I/O equals observed source bytes plus one ciphertext write and two ciphertext reads; the spool breakdown and peak ciphertext reservation are derived from that audited path and checked against the actual totals. Callback byte counts are externally hashed and lie outside controlled output I/O accounting. Private stage reservation bounds additionally include the original U. These reservation amounts are logical resource charges, not physical disk-block or RSS measurements.

Process FD highwaters are10ms samples and therefore lower bounds. Explicit close/cleanup semantics are verified separately through public hooked operations and zero released-resource ledgers after successful reads/action teardown; process exit or an empty scratch directory alone is not offered as proof of explicit cleanup.

## Verification and remaining integration

The final amended code passed macOS workspace format, all-target tests (1309 passed/27 ignored),15 doc tests and strict Clippy. Native Linux qualification uses the retained pinned Rust1.99.1 ARM64 image, fresh private source/cache/target, real native ext-family/tmpfs fixtures and root/nobody controls; consult the private final qualification receipt for its exact commit, kernel, filesystem, command exits and scope. Earlier private cipher/codec/ledger/storage/source/publication evidence remains attributed by numbered item in the engine report. Huge aggregate geometry and >100000 bulk KDF cases are accounting simulations supplemented by real crypto here, not actual terabyte reads or a bulk-crypto throughput claim.

Root still owns exact-head whole-engine review, PR, merged tree/CI and the actual merged engine SHA. Task7 owns real Prybar selected extraction/printing/preview, aliases, UI/status, EntryGuard/mutex/source lifetime, BorrowedFd and BrokenPipe. No engine-only result closes those caller gates. The [checked-reader guide](../zip-checked-reads.md) documents provisional callbacks, verified publication, conservative defaults versus derived policy, finite retries, external accounting scopes and storage/source/namespace threat limitations.
