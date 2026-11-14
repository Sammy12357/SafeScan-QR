# QR format and byte fixtures

These small PNGs exercise ZXing's QR-family decoder independently of the
camera scene benchmark. `micro.png` and `rmqr.png` contain `SQR123` in Micro QR
and rMQR formats. `unicode.png` contains Japanese Kanji text whose encoded QR
bytes are Shift-JIS. `sjis_bytes.png` contains the same bytes as opaque binary
data; `binary.png` contains a NUL and invalid UTF-8 bytes.

`structured-01.png` is the first of a three-symbol Structured Append set and
looks like a plausible partial URL. `structured-all.png` contains all three
symbols. The pinned zxing-cpp Python binding exposes their decoded text and
position but not the sequence index or size. The server therefore refuses
the combined image as ambiguous, but cannot reliably identify an isolated
fragment. The browser WASM reader has sequence metadata and rejects it.
