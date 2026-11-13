# Resource-efficiency qualification, 2026-11-13

The baseline is standalone Zipfast `82e88a6dabd2025dde0342583fa41345287dde73`. Its `src/zip.rs` is identical to audited `f41aae515472ce25b6309d777fcc3e738b2a98ec`. Baseline release binaries and the first twelve verified CLI workloads were captured before product edits. The candidate reuses the owned encrypted member, authenticates AES before mutation, and moves owned ZIP/TAR/RAR catalogue names and link values. Public APIs and the 128 MiB encrypted packed-member ceiling are preserved.

Resource Maxxer source, reports and fixture recipe came from the clean `codex-skills` revision `0e768cfef5e4eee1cfba7168b56dcb2f3546b004` through SSH alias `m5air`. Its older application comparisons use different engine copies, features and profiles. The measurements below compare builds made locally from the same current baseline.

Both CLI builds used Homebrew rustc1.99.1 (58cf8f9c3), Cargo1.99.1, aarch64-apple-darwin, LLVM23.1.3, `cargo build --release --locked`, fat LTO, one codegen unit, panic=abort and unset Rust flags. Cargo.lock and Cargo.toml are identical. Compiled feature fingerprints match flate2 1.1.10 with miniz_oxide 0.9.1, runtime detection and rust_backend. zlib-rs is absent from these CLI builds.

All trials ran on this M4 Mac's local APFS filesystem with ordinary scheduling and `-mt1`. Background services continued normally. Other implementation builds were stopped during comparison trials. Each tool ran in a fresh private trial directory. Resource Maxxer warmed the same immutable archive bytes before each trial and alternated tool order over five rounds. Fixture generation, compilation, output synchronization and correctness hashing were outside child wall time. CPU and process peak RSS come from wait4. RSS is the OS process metric, with its platform-defined waited-child behavior.

The deterministic bounded-buffer payload recipe combines 512 KiB of SHAKE-derived bytes and 512 KiB of repeated text. Encrypted Stored sources were16 and127MiB. Deflate sources were32 and252MiB. The near-limit payload packed sizes are133169180/133169164 bytes for AES/ZipCrypto Stored and132830103/132830087 for Deflate. AES uses256-bit AE-2 for these measurements. Each archive also contains an empty member. Catalogue cases contain10000 or100000 empty files plus three directories, with474-byte file paths and47400606 total name bytes in the larger case. ZIP uses Stored and TAR uses PAX names. AES salts are generated once, then the exact archived bytes and SHA-256 fingerprints are shared by both tools.

Every one of120 comparisons passed. Extraction checks the complete path/type/size/SHA-256 inventory. Listing checks names, sizes and directory types. The separate API allocation runs additionally fingerprint returned order and all exposed metadata fields, including link values.

The table gives wall medians with min/max ranges, total user-plus-system CPU medians and process RSS medians. B and C denote baseline and candidate. Values are seconds and MiB.

| Workload | B wall (range) | C wall (range) | B CPU | C CPU | B RSS | C RSS |
| --- | --- | --- | --- | --- | --- | --- |
| aes-deflate-252mib | 1.2198 (1.1992–1.4693) | 1.2307 (1.1658–1.5126) | 1.1811 | 1.1642 | 263.72 | 136.97 |
| aes-deflate-32mib | 0.1936 (0.1769–0.2156) | 0.1811 (0.1651–0.1869) | 0.1838 | 0.1706 | 42.52 | 26.39 |
| aes-stored-127mib | 1.1652 (1.1443–1.5925) | 1.1765 (1.1091–1.2754) | 1.1108 | 1.1155 | 263.20 | 136.17 |
| aes-stored-16mib | 0.1480 (0.1448–0.1527) | 0.1456 (0.1388–0.2196) | 0.1455 | 0.1432 | 41.20 | 25.19 |
| catalogue-10000-tar | 0.0891 (0.0867–0.0962) | 0.0935 (0.0902–0.0964) | 0.0164 | 0.0166 | 8.89 | 8.89 |
| catalogue-10000-zip | 0.0896 (0.0849–0.0932) | 0.0871 (0.0821–0.0920) | 0.0115 | 0.0112 | 18.75 | 13.89 |
| catalogue-100000-tar | 0.8733 (0.8347–0.8918) | 0.8817 (0.8459–0.8874) | 0.3164 | 0.3163 | 63.62 | 63.66 |
| catalogue-100000-zip | 0.8130 (0.7744–0.8286) | 0.8247 (0.6455–0.8287) | 0.2474 | 0.2530 | 126.86 | 77.88 |
| zipcrypto-deflate-252mib | 1.0058 (0.9783–1.3074) | 0.9591 (0.9388–1.0886) | 0.9388 | 0.9258 | 263.67 | 136.95 |
| zipcrypto-deflate-32mib | 0.1499 (0.1457–0.1654) | 0.1449 (0.1433–0.1503) | 0.1435 | 0.1439 | 42.50 | 26.38 |
| zipcrypto-stored-127mib | 1.0717 (1.0630–1.0880) | 1.0621 (1.0435–1.0828) | 1.0283 | 1.0104 | 263.19 | 136.17 |
| zipcrypto-stored-16mib | 0.1133 (0.1118–0.1209) | 0.1119 (0.1103–0.1173) | 0.1122 | 0.1101 | 41.19 | 25.17 |

Near-limit encrypted RSS fell by about127MiB, approximately48%. ZIP100k listing RSS fell about49MiB, approximately39%. Timing ranges overlap on several workloads. The largest AES medians are slightly higher while their ranges overlap. The results establish memory savings and do not establish a general throughput improvement. TAR listing RSS and CPU are essentially flat in this workload.

Allocation profiling uses a separate release consumer with matching dependency/compiler/profile settings. `Archive::open` occurs before the read window, which covers `Archive::read_at` and incremental SHA-256 output verification. The listing window covers `extract::list` with the returned entries alive. Metadata fingerprint formatting follows that window. A System allocator wrapper counts Rust requests and peak requested live bytes. Native allocations, allocator metadata and resident pages have different scope. Three alternating rounds produced identical counters and equivalent output fingerprints for every case. These instrumented executables supply allocation evidence, while CLI timings above use the ordinary executable.

| Workload | B allocation calls | C allocation calls | B requested bytes | C requested bytes | B peak live growth | C peak live growth |
| --- | --- | --- | --- | --- | --- | --- |
| aes-deflate-252mib | 7 | 4 | 267800732 | 134970551 | 267800626 | 134970551 |
| aes-deflate-32mib | 7 | 4 | 35873720 | 19007045 | 35873614 | 19007045 |
| aes-stored-127mib | 5 | 2 | 267387014 | 134217756 | 267386994 | 134217756 |
| aes-stored-16mib | 5 | 2 | 34603142 | 17825820 | 34603122 | 17825820 |
| catalogue-10000-tar | 60034 | 50031 | 29325440 | 24584834 | 7559702 | 7559702 |
| catalogue-10000-zip | 20024 | 10021 | 18321119 | 13580513 | 11481812 | 10902088 |
| catalogue-100000-tar | 600037 | 500034 | 276380544 | 228979938 | 62147254 | 62147254 |
| catalogue-100000-zip | 200027 | 100024 | 144293296 | 96892690 | 114801812 | 73844217 |
| zipcrypto-deflate-252mib | 5 | 4 | 267800610 | 134970535 | 267800610 | 134970535 |
| zipcrypto-deflate-32mib | 5 | 4 | 35873598 | 19007029 | 35873598 | 19007029 |
| zipcrypto-stored-127mib | 3 | 2 | 267386892 | 134217740 | 267386892 | 134217740 |
| zipcrypto-stored-16mib | 3 | 2 | 34603020 | 17825804 | 34603020 | 17825804 |

Both large catalogues eliminate100003 name allocations and47400606 requested bytes. TAR's peak live growth stays flat because earlier parsing/retained output determines that peak. RAR's equivalent owned conversion was source-reviewed and passed existing listing regressions. A large RAR allocation/CPU comparison remains unmeasured.

Resource Maxxer's macOS cgroup I/O and memory fields are null. Supplemental direct-child wait4 probes covered three alternating rounds of AES Stored127MiB, ZipCrypto Deflate252MiB and ZIP100k listing, with equivalent results. All input/output block counters were zero. A known64MiB write also returned zero counters, so these counters do not establish physical I/O volume on this host. Logical verified output bytes and input fingerprints are recorded. Physical device traffic, native allocator attribution and writeback of unlinked temporary files remain unmeasured.

Regression tests first demonstrated two payload allocations and256 name allocations for128 names at baseline. Candidate tests assert one large payload allocation for both methods/ciphers and one name allocation per ZIP entry. Additional tests cover all AES strengths and AE variants, Stored/Deflate, empty/nonempty data, wrong passwords, damaged tags, truncated framing/payload, correct-password ZipCrypto header rejection, exact/one-under selection budgets, AE-1/AE-2 CRC rules and failed verified publication. Independent AES vectors check unchanged ciphertext on rejection. Deterministic cancellation controls stop authentication and decryption at each chunk boundary.

Physical CLI qualification also exercised valid encrypted Stored members with exactly134217728 packed bytes and one byte over, for AES and ZipCrypto. Both baseline and candidate extracted/hash-verified the exact-boundary members and refused the over-boundary payloads without publication. Eight additional password/header/tag/truncated-file/truncated-member cases produced identical exit codes/stdout/stderr between both tools. Deflate packed/decoded selection-limit boundaries are covered in the public regression matrix.

The scoped independent Astra review found no actionable correctness, security or compatibility issue. It inspected source and regression scope with builds stopped during timing. Final macOS gates passed818 workspace/all-target tests and8 doctests. Linux ext4 gates passed816 workspace/all-target tests,8 doctests and the explicit filesystem qualification control. Strict workspace/all-target Clippy, formatting and diff checks passed. Review/merge provenance is maintained in ZIPFAST_HANDOFF.md and the SDD ledger. The committed Prybar integration handoff names the engine pins, retained-session APIs, adapter changes and regression gates in `docs/prybar-resource-integration.md`.

Raw benchmark provenance, fixture hashes, tool hashes, feature fingerprints, suites, fixture generation, consumer source, output trees and complete reports are retained in the fresh private directory below. Runtime comparison and I/O probe scopes are recorded independently. The user-requested historical transcript index is linked from ZIPFAST_HANDOFF.md.

```
/var/folders/8l/gf2khwb964l3byy2k613hlzm0000gn/T/zipfast-resource-efficiency.pk9i2vge
  baseline-manifest.json
  artifact-manifest.json
  fixtures/manifest.json
  generate-fixtures.py
  comparison-suite.json
  entrypoint-driver/
  profile-allocations.py
  io-counters.py
  qualify-boundaries.py
  linux-gates.sh
  results/baseline-before-edit/{report.json,summary.md}
  results/comparison-five-rounds/{report.json,summary.md}
  results/allocation-comparison-three-rounds.json
  results/io-probes.json
  results/boundary-qualification/report.json
  results/resource-regressions-red.log
  results/final-macos-gate-*.log
  results/linux-ext4-gates.log
```
