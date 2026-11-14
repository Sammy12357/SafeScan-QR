# QR scanner benchmarks

Phase 0 establishes a reproducible baseline before changing camera or server decoding. The synthetic images and labels are committed under `tests/qr_corpus/synthetic/`. The browser benchmark uses the pinned, self-hosted `zxing-wasm` reader under `static/vendor/`; no website behavior changes in this phase.

## Run

From the repository root, with `requirements.txt` installed:

```bash
python scripts/qr_bench/make_synthetic.py
python scripts/qr_bench/bench_server.py --corpus synthetic
cd scripts/qr_bench && npm ci && cd ../..
node scripts/qr_bench/bench_client.mjs --corpus synthetic
```

Node 20.9+ is required. `npm ci` is only for the benchmark tool; the site stays build-free. Reports go to ignored `.cache/qr_bench/` files. Reports contain file names, outcomes, counts, and timings; they contain no decoded payloads or image bytes.

For the real-photo corpus, run `python scripts/qr_bench/fetch_boofcv.py` and then use `--corpus boofcv` with both benchmark scripts. The downloader gets the [BoofCV QR image dataset](https://boofcv.org/index.php?title=Performance:QrCode) from its official page into ignored `.cache/qr_corpus/boofcv/`. The downloaded V3 archive used for this baseline has SHA-256 `a136c676448e9bafbe5c2fe9487728b0da3c823aeace6bc74d1c7fb2f86fe7be`. Its `detection` images have coordinate labels, not payload text, so the BoofCV read rate means “at least one valid QR payload decoded,” while synthetic results compare exact payloads.

## Phase 0 baseline

Recorded on the checked-in 24-image synthetic corpus with the current `zxing-cpp==3.0.0` server and current 720px jsQR fallback. The first 18 images are the core scenario set; the six additions cover curvature, screen moiré, stylized QR, two-code ambiguity, overlap, and Micro QR.

| Decoder | Core 18 exact | All 24 exact |
| --- | ---: | ---: |
| Current jsQR fallback at 720px | 11/18 | 13/24 |
| Vendored zxing-wasm capture options | 16/18 | 21/24 |
| Current server full decoder | 14/18 | 19/24 |

The server reads 17/22 single-code cases exactly and refuses both multi-code uploads. The synthetic corpus is a regression tool, not a device test: later phases must also use the real-photo corpus and the device matrix in `docs/plans/camera-scanning-v3.md`.

The first BoofCV browser baseline is 271/562 for jsQR at 720px and 432/562 for zxing-wasm capture. This is a read count, not exact payload correctness, because the detection categories do not include payload labels. Local timing measurements are machine-specific and should be compared on the same machine without other heavy jobs running.
