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
