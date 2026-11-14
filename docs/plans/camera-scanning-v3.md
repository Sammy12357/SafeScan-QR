# SafeScan — Camera Scanning Upgrade Plan (for Codex)

**Repo:** `Sammy12357/SafeScan-QR` (main site + Render backend). Mobile app (`Sammy12357/SafeScan-QR-App`) is covered only in Phase 8 — per `AGENTS.md`, mobile work goes in the mobile repo.
**Suggested location in repo:** `docs/plans/camera-scanning-v3.md`
**Goal:** Read more QR codes on the first try — small, far, off-center, tilted, dim, glary, inverted, on any browser — without weakening SafeScan's safety rules (deliberate capture, refuse ambiguous multi-code scans, no third-party script supply chain).

---

## 0. Kickoff prompt (paste into Codex)

> Read `docs/plans/camera-scanning-v3.md` and `AGENTS.md`. Implement the plan **one phase per PR**, in order, on branches named `codex/scanner-phase-N`. Phase 0 (benchmark + corpus) must land first and every later PR must include before/after benchmark numbers in its description. Do not change risk scoring, verdict logic, or the multi-QR ambiguity refusal. Keep the frontend as plain static JS (no bundler). Bump the `?v=` cache-bust strings in `templates/index.html` for any static file you change. Add every new test file to the `pytest` line in `.github/workflows/ci.yml`. Stop and ask before anything listed under "Decisions for Sam" (§10).

---

## 1. What exists today (read these first)

| Area | File | Notes |
|---|---|---|
| Web camera modal | `static/qr-camera.js` (367 lines) | `getUserMedia` 1280×720 ideal, rear camera via `facingMode: environment`. **Manual capture** — decodes one frame when user taps "Take picture". |
| Web decoder | same file | `BarcodeDetector` if present, else **jsQR 1.4.0 loaded from cdn.jsdelivr.net** (no SRI). jsQR frames are **downscaled to 720px max** (`FALLBACK_MAX_DIM`). Extra pass: 8 global thresholds. |
| Hook-up | `static/app-core.js` ~L606–636 | `onResult(value)` puts payload into `#urlInput` and submits `#urlForm` → `/search_qr_api`. |
| Server decode | `hackabull/qr_decode.py` | `decode_qr_image()` → candidate ladder (gray / autocontrast / sharpen / contrast / 24 thresholded / 1400px upscale) × (zxing-cpp + pyzbar ×4 rotations). `decode_barcodes_with_zxing()` loops 4 binarizers × 2 text modes × 2 `is_pure`. |
| Upload routes | `hackabull/routes_scan_auth.py` `/search_qr_api` (anonymous OK), `hackabull/routes_api.py` `/api/scan/file` (login) | Both are `async def` but call the CPU-bound `decode_qr_upload()` **synchronously → blocks the event loop**. |
| CSP | `hackabull/app_module.py` L197–213 | `script-src` + `connect-src` include `https://cdn.jsdelivr.net` only for jsQR. No `'wasm-unsafe-eval'`. |
| Deps | `requirements.txt` | `zxing-cpp==3.0.0`, `pyzbar==0.1.9`, Pillow. No OpenCV. |
| Static tests that will break if you're careless | `tests/test_wallet_security_static.py` | `test_camera_scanner_requires_deliberate_capture` asserts `>Take picture</button>`, `captureBtn.addEventListener("click", capture)`, and **absence of** `requestAnimationFrame(tick)`. `test_stylized_qr_preprocessing_uses_low_threshold_zxing_path` asserts `"55, 70, 85"` and `decode_barcodes_with_zxing(candidate, qr_only=True)` in server code. Update these tests deliberately (keep their intent), don't just delete them. |
| Storage of uploads | `hackabull/history.py` L279 (`storage_upload_bytes`) | Check when upload artifacts are retained. Camera frames sent to the server must **not** be retained (see Phase 5). |

---

## 2. Baseline measurements (done before writing this plan)

Synthetic test: one QR (≈70-char URL, ECC M) composited onto a cluttered 1280×720 background with 18 degradations. "jsQR@720" reproduces today's iOS/Firefox/Windows-Chrome path; "zxing-wasm" is the proposed client engine at native resolution; "server now" is `decode_qr_image()` as written.

| Case | jsQR@720 (today's fallback) | zxing-wasm 3.1.6 (proposed client) | server, zxing-cpp **3.0.0** (pinned) | server, zxing-cpp **3.1.1** | OpenCV WeChat | pyzbar alone |
|---|---|---|---|---|---|---|
| clean, centered | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| off-center corner (220px) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| off-center, quiet zone cut by frame edge | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| small/far (90px) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| small/far **and** off-center (80px, corner) | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| small/far after 720px downscale | ❌ | ❌ | ✅ (via 1400px upscale) | ✅ | ✅ | ❌ |
| rotated 35° | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **perspective tilt** | ❌ | ✅ | **❌ (3.4 s to fail)** | ✅ (66 ms) | ❌ | ❌ |
| **perspective + off-center + small** | ❌ | ✅ | **❌ (3.9 s)** | ✅ | ❌ | ❌ |
| gaussian blur | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **motion blur** | ❌ | ❌ | ❌ (3.6 s) | ❌ | ❌ | ❌ |
| low contrast + noise | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| glare spot | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| low light | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| inverted (light on dark) | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| mirrored | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| JPEG q35, small | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| blur + small + off-center | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Total** | **10/18** | **16/18** | 15/18 | **17/18** | 15/18 | 12/18 |

Takeaways that drive the plan:
1. **The browser fallback is the weakest link.** jsQR + 720px downscale misses 8/18. zxing-wasm at native resolution misses 2. Desktop Chrome on Windows/Linux, Firefox, and **every iOS browser** use this fallback today, because `BarcodeDetector` only ships on Android, macOS, and ChromeOS Chromium, and is behind a flag in Safari.
2. **Never downscale before decoding.** The downscale is what kills small codes. A 2× upscale of the ROI brings them back (verified: 2× and 3× decode, 1.5× doesn't).
3. **Bumping zxing-cpp 3.0.0 → 3.1.1 fixes perspective on the server** with no other change.
4. **Server failure path takes ~3.5 s** (the full candidate ladder), and it blocks the event loop.
5. **Motion blur defeats every decoder.** It has to be fixed at capture time (burst + pick the sharpest frame + "hold steady" guidance), not in post-processing. A quick unsharp mask did not recover it.
6. **OpenCV WeChat** only added value for tiny or low-res codes (super-resolution model) and *failed* perspective cases. Use it as an optional last tier, not a replacement.

Caveat: synthetic data, one payload. Phase 0 adds real-photo datasets before any tuning.

---

## 3. Constraints and non-goals

- **Keep deliberate capture as the default.** Nothing gets analyzed until the user taps. Live *locating* for guidance is fine if it never submits (see §10, decision 1).
- **Keep the ambiguity refusal.** If more than one distinct payload is seen, refuse and explain. Make that refusal smarter (show the codes, detect stacked stickers), not weaker.
- **No third-party runtime scripts.** Vendor everything under `static/vendor/` with pinned versions and recorded SHA-256 values. Remove `cdn.jsdelivr.net` from the CSP when jsQR goes.
- **No frontend build step.** Plain ES5/ES2017 + a classic Web Worker, using `importScripts`.
- **Render CPU and RAM are small.** Server decode needs a time budget and bounded concurrency.
- **Privacy.** Camera frames sent to the server get decoded in memory and are never stored or logged. Telemetry never includes payloads or images.
- Out of scope: risk scoring, ML classifier, verdict UI, payments.

---

## 4. Library decisions

| Use | Library | Why | Rejected alternatives |
|---|---|---|---|
| Browser decoder (all browsers) | **zxing-wasm** (`zxing-wasm/reader`, v3.1.6 at time of writing; Sec-ant; MIT; wraps zxing-cpp Apache-2.0) | Same engine as the server, so results stay consistent. Handles QR, Micro QR, and rMQR, plus perspective, inversion, and mirroring. ~0.9 MB wasm plus a 40 KB IIFE loader that works in a classic worker (`importScripts`, global `ZXingWASM`). Has `tryHarder`, `tryDenoise`, `tryRotate`, `tryInvert`, `tryDownscale`, `maxNumberOfSymbols`, and `returnErrors`. | **jsQR** (unmaintained; weakest in the benchmark). **@zxing/browser** (Java-port JS; slower and weaker). **html5-qrcode** (wraps the zxing-js port; not maintained). **barcode-detector** polyfill (same wasm, but adds an extra abstraction layer; using zxing-wasm directly gives `returnErrors` and positions). |
| Browser fast path | Native **BarcodeDetector** where `getSupportedFormats()` includes `qr_code` | Close to free on Android Chrome. Keep it as the *first* pass only; always fall through to zxing-wasm before reporting "not found". | — |
| Server primary | **zxing-cpp 3.1.1** (pip `zxing-cpp`) | Already in use. 3.1.x fixes perspective and improves detection of small and Version 1 symbols. | — |
| Server secondary | **pyzbar** (keep) | Cheap second opinion that sometimes reads damaged codes. | — |
| Server tertiary (optional, behind a flag) | **OpenCV WeChat QR** (`opencv-contrib-python-headless`, `cv2.wechat_qrcode_WeChatQRCode`, ~1 MB caffe models from `WeChatCV/opencv_3rdparty` branch `wechat_qrcode`) | CNN detector plus a super-resolution model. Strong on tiny, far, glare, and monitor-screen codes in the public BoofCV-dataset benchmark. | **BoofCV** reads best overall in that benchmark, but it's Java (`pyboof` needs a JVM, too heavy for Render). **quirc**: fast but weak. |
| Corpus / benchmark | **BoofCV QR dataset** (536 images, 16 categories: blurred, bright_spots, brightness, close, curved, damaged, glare, high_version, lots, monitor, nominal, noncompliant, pathological, perspective, rotations, shadows) + the synthetic generator below + SafeScan's own `github/judge-qr-0*.png` | Real photos of exactly the edge cases we care about. | — |

---

## 5. Phases

### Phase 0 — Corpus + benchmark harness (land first, no behavior change)

**Create**
- `tests/qr_corpus/synthetic/` with a generator script `scripts/qr_bench/make_synthetic.py`. Port the attached `make_cases.py`: cases from §2, plus *curved* (cylindrical warp), *screen moiré* (photo of a code on an LCD: add a fine sinusoidal grid), *stylized/logo QR* (center logo covering ~20%, rounded modules, coloured foreground), *two different codes in frame*, *two overlapping codes (sticker over sticker)*, and *Micro QR*. Commit the generated PNGs (small) **and** the generator. Ground truth lives in `tests/qr_corpus/synthetic/labels.json` as `{file: [payloads...]}`.
- `scripts/qr_bench/fetch_boofcv.py` downloads the BoofCV QR dataset into `.cache/qr_corpus/boofcv/` (git-ignored; never committed). Link it from the BoofCV QR performance page (`https://boofcv.org/index.php?title=Performance:QrCode`). Get the URL from that page; don't guess it.
- `scripts/qr_bench/bench_server.py` runs `decode_qr_image` (and each tier separately) over a corpus and prints a per-category read rate plus p50/p95/max ms. Writes JSON to `.cache/qr_bench/server-<git-sha>.json`.
- `scripts/qr_bench/bench_client.mjs` (Node 20+) runs the **vendored** zxing-wasm build with the *exact* option sets the browser worker will use (import them from a shared `static/qr-decode-options.json`), plus a jsQR@720 baseline column for the "before" numbers. Uses `sharp` for image loading. Lives with its own `package.json` under `scripts/qr_bench/` so the site stays build-free.
- `tests/test_qr_corpus_regression.py` covers synthetic corpus only (fast, CI-safe). It asserts that the **server read rate ≥ the recorded floor** and that the ambiguity cases raise `QRDecodeAmbiguityError`. Start the floor at today's number and ratchet it up in later phases.

**Acceptance:** `python scripts/qr_bench/bench_server.py --corpus synthetic` and `node scripts/qr_bench/bench_client.mjs --corpus synthetic` both run locally. Baseline numbers are pasted in the PR.

---

### Phase 1 — Server decode: faster, stronger, non-blocking

**1a. Dependency bump**
- `requirements.txt`: `zxing-cpp==3.1.1`. Run the full test suite and the benchmark. 3.1.1 also fixes Python kwargs handling, so check `read_barcodes(...)` keyword usage.

**1b. Restructure `decode_qr_image()` into tiers with a deadline**
Keep the public function names and return types so `decode_qr_upload`, the ML path, and the tests keep working.

```
deadline = now + QR_DECODE_BUDGET_S (env, default 1.5)
gray = to_grayscale_numpy(exif_transposed(image))      # decode at native resolution
Tier A  zxing(gray)                        # default LocalAverage, try_rotate/invert/downscale on
Tier B  if no result and max(side) < 1600: zxing(upscale(gray, 2x, INTER_CUBIC))
Tier C  pyzbar(gray) (0° only; zxing already handles rotation)
Tier D  if QR_WECHAT_ENABLED: wechat.detectAndDecode(gray_bgr)
Tier E  existing enhancement ladder (autocontrast, sharpen, contrast, thresholds 55..185, LANCZOS 1400px)
        → zxing first, then pyzbar; check deadline between every candidate; drop the 90/180/270
          pyzbar rotations (zxing covers rotation) unless the image is ≤ 800px.
```
- **Remove the `TextMode` loop** in `decode_barcodes_with_zxing`. Text mode only changes how bytes are transcoded, not detection, so it doubles the calls for nothing. Use `TextMode.Plain` for the payload (keep HRI out of security analysis). Keep the binarizer loop only inside Tier E. Keep `is_pure=True` only for SVG/PDF-rendered images.
- At the first tier that produces results, collect **all** symbols from that tier (zxing returns every code in the image). Run the existing distinct-payload ambiguity check across them. Don't return after the first symbol.
- Keep `"55, 70, 85"` and a `decode_barcodes_with_zxing(candidate, qr_only=True)` call in Tier E, or update `test_stylized_qr_preprocessing_uses_low_threshold_zxing_path` to assert the new structure without losing its intent (stylized codes still get the low-threshold zxing path).
- Large photos: set `Image.MAX_IMAGE_PIXELS` to a sane cap (for example 40 MP) and catch `DecompressionBombError`. If the long side is over 4000px, run Tier A at native resolution first, then a 0.5× copy.
- Return quad corner points alongside payloads internally (new optional field). The camera UI can draw outlines from server results later.

**1c. Stop blocking the event loop**
- In `/search_qr_api` and `/api/scan/file`, call `await run_in_threadpool(decode_qr_upload, contents, filename, content_type)`.
- Add a module-level `asyncio.Semaphore(int(os.getenv("QR_DECODE_CONCURRENCY", "2")))` around it.

**1d. Optional Tier D: OpenCV WeChat (feature-flagged, default off until benchmarked on Render)**
- Add `opencv-contrib-python-headless` pinned to a 4.x release. Do **not** also install `opencv-python`, because the two conflict.
- Commit models to `models/wechat_qr/{detect,sr}.{prototxt,caffemodel}` (~1 MB total). Record SHA-256s in `models/wechat_qr/SHA256SUMS` and verify them at load time. Include the upstream license file.
- Use a lazy singleton plus `cv2.setNumThreads(1)`. Env flag `QR_WECHAT_ENABLED=false`.
- Measure container RSS and cold-start delta on Render before enabling.

**1e. Metrics** (prometheus-client is already wired in `hackabull/config.py`)
- `safescan_qr_decode_total{tier, outcome}` and `safescan_qr_decode_seconds` histogram. No payloads in labels.

**Acceptance**
- Synthetic corpus: server ≥ 17/18 (motion blur may fail), ambiguity cases still refuse.
- BoofCV corpus: read rate ≥ baseline in *every* category, with an overall improvement reported.
- p95 decode time for **failed** images ≤ 1.6 s (was ~3.5 s).
- `pytest tests/ -q` is green, and the new tests are added to CI.

---

### Phase 2 — Browser decode engine: zxing-wasm in a Web Worker

**2a. Vendor**
- `static/vendor/zxing-wasm/3.1.6/reader/index.js` (IIFE build: `dist/iife/reader/index.js`) and `static/vendor/zxing-wasm/3.1.6/reader/zxing_reader.wasm` (`dist/reader/zxing_reader.wasm`).
- Add `static/vendor/zxing-wasm/3.1.6/VERSION.md` with the npm version, the SHA-256 of both files, and the license.
- Make sure `.wasm` is served as `application/wasm`: call `mimetypes.add_type("application/wasm", ".wasm")` before mounting `StaticFiles`. Verify with a test.

**2b. Worker** `static/qr-worker.js` (classic worker)
```js
importScripts('/static/vendor/zxing-wasm/3.1.6/reader/index.js');
ZXingWASM.prepareZXingModule({
  overrides: { locateFile: (p, prefix) => p.endsWith('.wasm')
      ? '/static/vendor/zxing-wasm/3.1.6/reader/zxing_reader.wasm' : prefix + p },
  fireImmediately: true,
});
```
- Messages: `{type:'decode', id, bitmap|imageData, mode:'capture'|'locate', roi?}` → `{id, symbols:[{text, valid, quad, format}], ms, stage}`.
- Option sets live in `static/qr-decode-options.json` and are shared with `bench_client.mjs`:
  - `locate`: `{formats:['QRCode','MicroQRCode','rMQRCode'], tryHarder:false, tryDownscale:true, maxNumberOfSymbols:4, returnErrors:true}` (positions of codes found but not decodable drive the guidance)
  - `capture`: `{formats:[...same], tryHarder:true, tryRotate:true, tryInvert:true, tryDownscale:true, tryDenoise:true, maxNumberOfSymbols:4}`
- Check the result field names (`isValid`, `text`, `position.topLeft…`) against the vendored version's `.d.ts`. Don't trust this doc for exact names.
- Convert `ImageBitmap` → `ImageData` inside the worker with `OffscreenCanvas` when available. Otherwise convert on the main thread and transfer `imageData.data.buffer`.

**2c. Decode strategy on capture (per frame, ~400 ms budget on a mid-range phone)**
1. Full frame at **native** resolution. No `FALLBACK_MAX_DIM` downscale.
2. If a code was *located* (from locate mode, BarcodeDetector `boundingBox`, or `returnErrors` positions), crop that quad's bounding box plus 25% margin and upscale so the code is ≥ 600px. Decode.
3. If nothing was located, **tile for off-center small codes:** 5 overlapping tiles (4 quadrants plus center, each 60% of the frame), upscaled 2×. Stop at the first valid result, but finish that tile's symbol list for the ambiguity check.
4. If that still finds nothing, run 2–3 of the existing global thresholds (pick from the benchmark; don't run all 8).

**2d. Remove jsQR**
- Delete the CDN loader. Remove `https://cdn.jsdelivr.net` from `script-src` and `connect-src`. Add `'wasm-unsafe-eval'` to `script-src`, which is required to compile WebAssembly under CSP. `worker-src` falls back to `script-src 'self'`.
- Update `tests/test_security.py`, or add a test, asserting that the CSP has no jsdelivr and that `qr-camera.js` contains no `http`-scheme script URLs.

**Acceptance:** `bench_client.mjs` capture mode ≥ 16/18 synthetic, ≥ server Tier A on BoofCV. Worker cold load ≤ 1.5 s on throttled "Fast 4G" in DevTools. Main thread never blocks for more than 50 ms during decode (Performance panel).

---

### Phase 3 — Camera acquisition quality

All in `static/qr-camera.js`, and all feature-detected through `track.getCapabilities?.()`. Never assume a capability exists.

1. **Resolution:** request `{width:{ideal:1920}, height:{ideal:1080}, frameRate:{ideal:30}}`. If that throws `OverconstrainedError`, retry with 1280×720 and then with `{facingMode}` only.
2. **Camera choice on multi-lens phones.** `facingMode: 'environment'` can land on an ultra-wide or a lens that can't focus close. On iPhone Pro models the 1× wide lens can't focus closer than roughly 15–20 cm, so codes held close come out blurry.
   - After permission is granted, `enumerateDevices()` and list back cameras. Show a **"Switch camera"** button when there's more than one.
   - Remember the chosen `deviceId` in `localStorage`, wrapped in try/catch, keyed per origin.
   - Default: the device that `facingMode:'environment'` returns. Don't hard-code label heuristics as the only path, because labels are localized and vary by vendor.
3. **Zoom:** if `capabilities.zoom` exists, show a 1×/2× toggle. Two uses: (a) it lets users hold the phone *farther away*, past the minimum focus distance, with the code still large in frame. This is Apple's own guidance for barcode scanning on Pro iPhones. (b) Guidance can suggest it (Phase 4). Apply it with `applyConstraints({advanced:[{zoom}]})`.
4. **Focus/exposure:** if supported, apply `focusMode:'continuous'` and `exposureMode:'continuous'`. **Tap-to-focus:** on tap inside the video, if `pointsOfInterest` is supported, apply `{pointsOfInterest:[{x,y}], focusMode:'single-shot'}` with normalized coordinates, then return to continuous after 2 s.
5. **Torch:** if `capabilities.torch`, show a flashlight button that toggles `torch` through `applyConstraints`.
6. **Front/laptop cameras:** mirror only the *preview* (CSS `transform: scaleX(-1)` when `settings.facingMode === 'user'` or there's no facingMode). Always decode the unmirrored frame. zxing handles mirrored codes anyway. Fixed-focus webcams can't focus close, so show "Hold the code 20–30 cm from the camera."
7. **Lifecycle:** stop the tracks on `visibilitychange` → hidden and on `pagehide`. Restart when visible again if the modal is still open. Handle `devicechange` and `track.onended` (camera taken by another app) with a clear message and a retry button. Re-read `videoWidth/Height` on `resize` and orientation changes.
8. **iOS specifics:** keep `playsinline muted autoplay`. Call `video.play()` after `srcObject`. Don't call `getUserMedia` again on every open within one page session; reuse the stream while the modal is open.

**Acceptance:** manual device matrix (§7) passes. No regression in the existing static tests.

---

### Phase 4 — Capture strategy + guidance UX (handles off-center, far, tilted, shaky)

**4a. Burst capture (fixes motion blur and focus hunting)**
- On "Take picture": collect **6 frames over ~500 ms** with `video.requestVideoFrameCallback` (fallback `setTimeout(80)`) → `createImageBitmap(video)` → transfer to the worker.
- Worker scores sharpness on a 320px-wide gray copy (variance of Laplacian). Decode frames in sharpness order with the §2c strategy. Stop at the first valid result.
- **Consensus/ambiguity:** if any frame yields ≥2 distinct valid payloads → ambiguous. If two frames yield *different* single payloads → ambiguous ("The camera saw two different codes, aim at one and try again"). The same payload from multiple frames gives extra confidence and needs no extra wait.
- Optional: if `ImageCapture` exists (Chrome Android) and the burst fails, call `takePhoto()` once for a full-sensor still and decode it. This is slower and can refocus, so use it only as the last local attempt.

**4b. Live locate (guidance only, never submits)**
- While the modal is open, every ~200 ms (use `requestVideoFrameCallback`, not a `requestAnimationFrame(tick)` loop), send a ≤960px frame to the worker in `locate` mode, or use `BarcodeDetector.detect` when native.
- Draw the detected quad(s) on an overlay canvas. **The decoded text from locate mode is never passed to `onResult`.** Only `capture()` can do that. Rewrite the static test to assert this invariant: `onResult` is referenced only inside `capture`.
- Guidance rules (one message at a time, priority order):

| Condition (from quad + frame stats) | Message | Action offered |
|---|---|---|
| ≥2 quads, overlapping bounding boxes | "One code is stuck on top of another. This is a common scam trick." | none (scan blocked) |
| ≥2 quads, separate | "Two codes in view. Aim at just one." | highlight both |
| quad touches frame edge (within 2% of the edge) | "Move the code toward the center" (say which direction) | — |
| quad short side < 15% of frame short side | "Move closer" (or "Tap 2× zoom" if zoom is supported) | zoom toggle pulses |
| Laplacian variance below threshold for 1 s | "Hold steady. Tap the code to focus." | tap-to-focus |
| mean luma in quad < 50 | "Too dark" | torch button pulses |
| >8% saturated pixels in quad | "Glare. Tilt the phone a little." | — |
| quad side-length ratio > 1.6 (strong perspective) | "Face the code straight on" | — |
| located but `valid=false` (returnErrors) | "Almost. Hold still and take the picture" | — |
| nothing located for 4 s | "Can't see a code. Try more light or upload a photo instead." | link to upload |

- **The reticle/frame becomes a hint, not a requirement.** We decode the whole frame, so off-center codes work. The reticle just encourages good framing.
- Accessibility: guidance goes to the existing `aria-live="polite"` status element, throttled so it changes at most once per 1.5 s. Add a haptic `navigator.vibrate?.(30)` when a valid code is located (Android only, no-op elsewhere).

**4c. Server fallback for the hard cases**
- If burst + local decode fail, show **"Couldn't read it here. Send this photo to SafeScan to try harder?"** with a button (see §10, decision 2).
- On confirm, encode the sharpest frame as JPEG q0.92 and submit it through the existing **`/search_qr_api` `file` field**: build a `File`, put it in the upload input with `DataTransfer`, and submit the form. That reuses the anonymous-friendly path, rate limits, ambiguity handling, and the Phase 1 decoder.
- Tag the upload with a hidden `capture_source=camera_frame` form field, and make sure the server **does not store** the image artifact for that source. Read `history.py` and `tests/test_private_qr_storage.py` for the current retention rules. Add a test.

**Acceptance:** on the device matrix, these scenarios read within 2 taps: small code at arm's length, code in a frame corner, 30–40° tilted code, a code on a laptop screen, and a dim room with the torch on. The overlapping-sticker and two-code scenes are refused with the right message.

---

### Phase 5 — Hardening and edge cases

- **Payload sanity before analysis** (client and server): reject empty or whitespace-only text, cap length at 4096 (already enforced on `/api/scan`, so mirror it). Treat `valid=false` as not decoded.
- **Micro QR / rMQR:** now decoded. Make sure `detect_payload` and analysis handle them as normal QR payloads. Add a corpus case.
- **Binary/non-UTF-8 payloads:** keep `errors="replace"` server-side, and add a test with a Shift-JIS/Kanji-mode QR and a raw-bytes QR.
- **Structured Append** (one message split across several QR symbols): out of scope. If zxing reports a sequence index, treat it as ambiguous with the message "This code is split across multiple QR codes."
- **Inverted / dark-mode codes, mirrored codes:** covered by zxing options. Keep the corpus cases.
- **Curved surfaces (bottles, cans):** no decoder handles strong curvature reliably. Guidance: "Turn the item so the code faces you." Keep the corpus case as a tracked known weakness.
- **Screens / moiré:** if a screen-photo case fails, add Tier E's Gaussian-blur(σ≈1) candidate before thresholding, and measure.
- **Permissions:** keep the existing NotAllowed/NotFound messages. Add `NotReadableError` ("camera is in use by another app") and `OverconstrainedError` (retry ladder in Phase 3).
- **Insecure context / no `mediaDevices`:** keep the existing messages, and always offer Upload as the escape hatch.

---

### Phase 6 — Telemetry + rollout

- Feature flag `SCANNER_V3` (env → template variable). When off, the old `qr-camera.js` is served under a different `?v=`. Ship behind the flag, test on the live Render URL, then flip it.
- Client beacon (optional, see §10, decision 4): `POST /api/telemetry/scan` with `{engine, stage, frames_tried, ms, outcome, guidance_shown[]}`. **No payloads, no images, no device IDs.** Rate-limited. Counters only.
- Server metrics from Phase 1e. Add a small admin card if it's cheap.
- Bump `?v=` strings: `qr-camera.js`, the new `qr-worker.js`, and `app-core.js` if it changed.

---

### Phase 7 — Docs

- Update `SECURITY.md`/`COMPLIANCE.md` (camera frames are decoded in memory, never stored; third-party CDN removed) and the in-app privacy text if it mentions camera use.
- Add `docs/qr-scanning.md` covering the architecture diagram, the tier order, option sets, how to run the benchmarks, and how to add a corpus image.

---

### Phase 8 — Mobile app (SafeScan-QR-App repo, separate PRs)

Lower priority. The app already falls back to uploading a photo to `/api/scan/file`, so it gets the Phase 1 server gains automatically.
- `app/(tabs)/scanner.tsx` `CameraView`: set `autofocus="on"` (expo-camera's iOS default is `off`). Add a torch toggle (`enableTorch`) and a 1×/2× zoom control (`zoom` is 0–1 of max zoom, so calibrate per platform). Check the expo-camera 17 types for any pinch-to-zoom prop.
- `handleQrDetected` currently ignores codes whose box isn't inside the frame, which hurts off-center codes. Accept any single code whose **center** is within the frame expanded by 15%. Keep the multi-code refusal. Show an outline for codes outside the frame plus a "center it" hint.
- `useScanner.captureAndScan`: keep `quality: 0.9`. Make sure EXIF orientation survives (the server already calls `exif_transpose`).
- Later option: evaluate `CameraView.launchScanner()` (Google code scanner on Android with auto-zoom; VisionKit DataScanner on iOS 16+) or react-native-vision-camera for zoom and focus control. Do this only if the field data shows focus problems.

---

## 6. Special-case matrix (what handles what)

| Situation | Root cause | Fix | Phase |
|---|---|---|---|
| Code off-center / in a corner | Old UX implied it must be inside the reticle; small codes get lost in full frame | Whole-frame decode + tiled 2× pass + "move toward center" guidance | 2c, 4b |
| Code partly outside the frame | Finder pattern cut off | Edge-touch detection → directional hint | 4b |
| Small / far code | 720px downscale; too few pixels per module | Native resolution, ROI 2× upscale, zoom toggle, "move closer" | 2c, 3, 4b |
| Too close / blurry on Pro iPhones | Minimum focus distance of the main lens | Zoom toggle so the user can stand back; camera switcher; "hold steady / tap to focus" | 3, 4b |
| Shaky hands | Motion blur (no decoder recovers it) | Burst of 6 frames, pick sharpest | 4a |
| Tilted / perspective | jsQR and zxing-cpp 3.0 fail | zxing-cpp 3.1.1 (server), zxing-wasm (client), "face it straight on" | 1a, 2 |
| Rotated / upside down | — | zxing `tryRotate` | 2 |
| Dim light | Noise, low contrast | Torch, continuous exposure, LocalAverage binarizer, `tryDenoise` | 3, 2 |
| Glare / laminated / glossy | Saturated modules | Guidance to tilt, WeChat tier, burst gives a different glare position | 4b, 1d |
| Inverted (light on dark) | — | `tryInvert` | 2 |
| Mirrored (photo through glass, selfie cam) | — | zxing handles it; preview-only mirroring | 2, 3 |
| Laptop/desktop webcam | Fixed focus, low resolution, front-facing, no BarcodeDetector on Windows | Wasm engine, distance hint, upload fallback | 2, 3 |
| Code on a phone/laptop screen | Moiré, refresh banding | Burst; optional blur candidate; WeChat tier | 4a, 5 |
| Stylized / logo / colored QR | Low contrast between colors, center logo | Grayscale plus the existing low-threshold ladder (keep it) | 1b |
| Two codes in view | Possible QR-over-QR swap or a poster with multiple codes | Refuse + outline both; overlapping boxes get a "sticker scam" warning | 4b |
| Very large photo upload | Memory / decompression bomb | Pixel cap + early downscale copy | 1b |
| Server busy | Sync decode blocks the event loop | Thread pool + semaphore + deadline | 1c |
| Camera in use / unplugged | `NotReadableError`, track ended | Clear message + retry | 3, 5 |

---

## 7. Test plan

**Automated (CI)**
- `tests/test_qr_corpus_regression.py` checks the read-rate floor and ambiguity on the synthetic corpus.
- `tests/test_qr_decode_tiers.py`:
  - Tier order and deadline: monkeypatch the clock, assert Tier E stops.
  - TextMode loop removed.
  - `run_in_threadpool` used in both upload routes (static check, matching the repo's existing style).
- `tests/test_security.py` additions:
  - CSP has no `cdn.jsdelivr.net`.
  - CSP has `'wasm-unsafe-eval'`.
  - `.wasm` is served with `application/wasm`.
- Static JS tests, extending `tests/test_wallet_security_static.py`:
  - The "Take picture" button still exists.
  - `onResult` is called only inside `capture`.
  - No `http(s)://` script URLs in `qr-camera.js` or `qr-worker.js`.
- Storage test: a `capture_source=camera_frame` upload leaves no stored artifact.
- Optional CI job: `node scripts/qr_bench/bench_client.mjs --corpus synthetic --min 16`.

**Manual device matrix (record results in the PR)**

| Device / browser | Engine expected | Must pass |
|---|---|---|
| iPhone 13–16 Pro, Safari | zxing-wasm | close-up small code (zoom flow), tilted, dim + torch (if exposed) |
| iPhone SE / non-Pro, Safari and Chrome (WebKit) | zxing-wasm | all standard scenarios |
| Pixel (recent), Chrome | BarcodeDetector → wasm | all + torch + tap-to-focus |
| Samsung Galaxy (multi-lens), Chrome + Samsung Internet | BarcodeDetector → wasm | camera switcher, corner code |
| Android Firefox | zxing-wasm | all standard scenarios |
| Windows laptop, Chrome/Edge (webcam) | zxing-wasm | phone-screen code at 25 cm |
| macOS Chrome + Safari | BarcodeDetector / wasm | phone-screen code |

Scenarios: clean poster, small code on a receipt, code in a corner of the viewfinder, a 35° tilted table tent, a glossy restaurant menu, a dim bar, a code on another phone's screen, two codes side by side, a sticker over a sticker, an inverted code, a curved bottle (expected guidance only).

---

## 8. Overall acceptance criteria

- Synthetic corpus: client capture ≥ 16/18 (from 10/18 on fallback browsers), server ≥ 17/18.
- BoofCV corpus: server and client read rates ≥ baseline in every category, overall up.
- Failed server decode p95 ≤ 1.6 s, and no event-loop blocking.
- No third-party script origins in the CSP.
- Deliberate-capture and ambiguity invariants are enforced by tests.
- All existing tests are green.

---

## 9. Order of work and size

| Phase | Size | Depends on |
|---|---|---|
| 0 Corpus + bench | M | — |
| 1 Server tiers / bump / threadpool | M | 0 |
| 2 Wasm worker engine | M | 0 |
| 3 Camera acquisition | M | 2 |
| 4 Burst + guidance + server fallback | L | 2, 3 (and 1 for fallback) |
| 5 Hardening | S | 1, 2 |
| 6 Telemetry + rollout | S | 4 |
| 7 Docs | S | all |
| 8 Mobile | M | 1 |

Phases 1 and 2 can run in parallel after Phase 0.

---

## 10. Decisions for Sam (Codex: ask, don't assume)

1. **Live locate overlay.** Should the scanner *locate* codes continuously and show guidance and outlines, while still only analyzing on tap? (Recommended: yes. It's the main fix for off-center and far codes and doesn't change the deliberate-capture rule.) Also: offer an opt-in "auto-capture when steady" toggle? (Recommended: not now.)
2. **Server fallback for camera frames.** OK to send the captured frame to SafeScan when local decode fails, with a confirm prompt, decoded in memory and never stored? Should anonymous users get it?
3. **OpenCV WeChat tier** on Render: worth roughly 60 MB of image size and some RAM for better tiny/glare reads? (Recommended: build it behind the flag, decide after the Phase 1 BoofCV numbers.)
4. **Client telemetry beacon** (counts only, no payloads)? Needed to tune the guidance thresholds with real data.
5. **Two separate codes in view:** keep refusing (current behavior), or allow "tap the one you mean" when the boxes *don't* overlap? (Recommended: keep refusing for now. Revisit with telemetry.)

---

## 11. References

- zxing-wasm (ZXing-C++ → WebAssembly, ES/IIFE builds, reader ~1 MiB): https://github.com/Sec-ant/zxing-wasm · docs https://zxing-wasm.deno.dev/
- zxing-cpp releases (3.1.x: QR detection improvements for many small symbols; 3.1.1: Version 1 detection and Python kwargs fixes): https://github.com/zxing-cpp/zxing-cpp/releases
- BarcodeDetector support (Android/macOS/ChromeOS Chromium only; Safari behind a flag): https://caniuse.com/mdn-api_barcodedetector
- OpenCV WeChat QR (CNN detector + super-resolution): https://docs.opencv.org/4.x/dd/d63/group__wechat__qrcode.html · models: https://github.com/WeChatCV/opencv_3rdparty/tree/wechat_qrcode
- BoofCV QR benchmark and dataset: https://boofcv.org/index.php?title=Performance:QrCode
- Open-source vs commercial QR benchmark on the BoofCV dataset (BoofCV ~61%, WeChat ~49%, ZBar ~39%, Java ZXing ~32%; note these are the *Java* ZXing numbers, not zxing-cpp): https://www.dynamsoft.com/codepool/qr-code-reading-benchmark-and-comparison.html
- Apple WWDC21 "What's new in camera capture": minimum focus distance and zoom-to-stand-back for barcode scanning: https://developer.apple.com/videos/play/wwdc2021/10047/
- WebKit bug: `facingMode: environment` selecting ultra-wide on iOS 16.4 beta: https://bugs.webkit.org/show_bug.cgi?id=253186
- Image Capture API (zoom, torch, focus, `takePhoto`): https://developer.chrome.com/blog/imagecapture
- expo-camera docs (autofocus, zoom, torch, launchScanner): https://docs.expo.dev/versions/latest/sdk/camera/
