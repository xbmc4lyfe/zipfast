# Fixed RAR4 LZ vectors

These packed bytes are hand-transcribed fixed test vectors specified in
`phase5-rar4-compressed-bitstream-worksheet.md` and its companion
`phase5-rar4-compressed-vectors/vectors.json` in the shared SDD folder.
No external decoder implementation or general compressor produced them.
Nine positive vectors were independently replayed with checksummed UnRAR
at source pin `160dcb5c9c1babbbdd3f0f1fc78cf48a7f8150cf`.
The three negative prefixes are boundary controls, not valid complete
PPM/VM streams. Their exact status/output is recorded in `reference.json`.

The test harness wraps only these immutable bytes with ordinary RAR4
container headers and a known expected CRC. It cannot encode input data.
This is a local RED checkpoint. Production decoding remains unchanged.

`official-lz-m3.packed` is the payload region of the locally generated
RARLAB 6.24 `-ma4 -m3 -mc- -s- -md64k` archive documented in
`phase5-rar4-compressed-evidence/observations.json`.
Archive SHA-256 is 66128c817b5134fe504b6bd959332429298b142962e8a8b1cb135d5eb5994712.
Packed SHA-256 is d8fc14b15e1f597e722342623c466e6f561b0b24dff92cbd3bbde1f0cc0aeef1.
The source is our deterministic 302,400-byte control, not third-party data.

The additional official-lz-m1/m2/m4/m5 packed fixtures use the same
recorded writer controls, sources and source timestamps as level3.
The six DD/threshold fixtures and three low/recent fixtures are fixed
hand-specified codebooks and token topologies from the worksheet. Exact
bytes, expected output lengths/hashes, and pinned independent replay are
recorded in `branch-vectors.json` and `branch-reference.json`.
No general compression API or third-party decoder code is included.
