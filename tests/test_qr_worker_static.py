"""Guard the browser decoder's security and capture-only contract."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
WORKER = (ROOT / "static" / "qr-worker.js").read_text(encoding="utf-8")
CAMERA = (ROOT / "static" / "qr-camera.js").read_text(encoding="utf-8")
APP_CORE = (ROOT / "static" / "app-core.js").read_text(encoding="utf-8")
INDEX = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")


def test_worker_loads_only_the_pinned_same_origin_reader():
    assert 'const READER_ROOT = "/static/vendor/zxing-wasm/3.1.6/reader/"' in WORKER
    assert 'importScripts(READER_ROOT + "index.js")' in WORKER
    assert 'const OPTIONS_URL = "/static/qr-decode-options.json?v=scanner-phase-2"' in WORKER
    assert not re.search(r"https?://", WORKER)


def test_capture_only_returns_valid_bounded_payloads():
    assert "result.isValid === true" in WORKER
    assert "text.trim().length > 0" in WORKER
    assert "text.length <= MAX_PAYLOAD_LENGTH" in WORKER
    assert "MAX_PAYLOAD_LENGTH = 4096" in WORKER
    assert "onResult" not in WORKER
    assert CAMERA.count("opts.onResult(value)") == 1
    assert "opts.onResult(value)" in CAMERA[CAMERA.index("async function capture()"):]
    assert 'if (result.structuredAppend === true) return { ambiguous: true, structuredAppend: true };' in CAMERA


def test_tile_search_checks_for_a_second_distinct_code():
    # A first tile can contain a harmless QR while a different one appears
    # elsewhere. The worker must finish the bounded search before returning
    # one payload, and may return early only once ambiguity is established.
    start = WORKER.index("for (const rect of tileRects(image.width, image.height))")
    end = WORKER.index("if (collection.valid.size === 0)", start)
    tile_search = WORKER[start:end]
    assert "collectSymbols(collection" in tile_search
    assert "if (hasMultipleCodes(collection)) return" in tile_search
    assert "if (collection.valid.size === 1) return" not in tile_search
    assert "checkSecondWithMask(image, collection)" in WORKER[:start]
    assert "collection.validLocations.length > 1" in WORKER


def test_camera_frame_upload_requires_a_separate_send_action():
    assert 'class="qr-camera-server-send"' in CAMERA
    assert 'serverSendBtn.addEventListener("click"' in CAMERA
    assert "opts.onServerFallback(fallbackBlob)" in CAMERA
    assert 'name="capture_source" value=""' in INDEX
    assert 'source.value = "camera_frame"' in APP_CORE
    assert 'new File([blob], "safescan-camera-frame.jpg"' in APP_CORE
    assert 'new DataTransfer()' in APP_CORE


def test_structured_append_is_refused_even_with_unknown_total():
    assert "symbol.sequenceIndex >= 0 || symbol.sequenceSize >= 0" in WORKER
    assert "result.structuredAppend === true" in CAMERA
