"""Safety and latency invariants of the bounded server QR decode path."""

import importlib
import hashlib
import io
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from PIL import Image
import pytest
import qrcode


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/qr_corpus/synthetic"


@pytest.fixture()
def decoder(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'decode-tiers.db').as_posix()}")
    return importlib.import_module("hackabull.qr_decode")


def test_native_then_upscale_tier_order_stops_on_first_hit(decoder, monkeypatch):
    calls = []

    def zxing(image, **kwargs):
        calls.append((image.size, kwargs))
        if len(calls) == 2:
            return [decoder.DecodedBarcode("https://example.com/")]
        return []

    monkeypatch.setattr(decoder, "_zxing_barcodes", zxing)
    monkeypatch.setattr(decoder, "_pyzbar_barcodes", lambda *_args, **_kwargs: pytest.fail("ZBar ran after a hit"))
    monkeypatch.delenv("QR_WECHAT_ENABLED", raising=False)

    with Image.new("L", (120, 90), "white") as image:
        found = decoder.decode_qr_image(image)

    assert [size for size, _kwargs in calls] == [(120, 90), (240, 180)]
    assert [item.data for item in found] == [b"https://example.com/"]


def test_deadline_prevents_later_expensive_tiers(decoder, monkeypatch):
    calls = []
    monkeypatch.setenv("QR_DECODE_BUDGET_S", "0.1")
    monkeypatch.delenv("QR_WECHAT_ENABLED", raising=False)

    def slow_native(*_args, **_kwargs):
        calls.append("native")
        time.sleep(0.12)
        return []

    monkeypatch.setattr(decoder, "_zxing_barcodes", slow_native)
    monkeypatch.setattr(decoder, "_pyzbar_barcodes", lambda *_args, **_kwargs: calls.append("pyzbar"))
    monkeypatch.setattr(decoder, "_enhanced_candidates", lambda *_args: pytest.fail("enhancement ran after deadline"))

    with Image.new("L", (120, 90), "white") as image:
        assert decoder.decode_qr_image(image) == []
    assert calls == ["native"]


def test_zxing_helper_uses_one_plain_text_call_per_binarizer(decoder, monkeypatch):
    options = []
    fake = SimpleNamespace(
        BarcodeFormat=SimpleNamespace(QRCode="qr", MicroQRCode="micro", RMQRCode="rmqr", All="all"),
        Binarizer=SimpleNamespace(LocalAverage="local", GlobalHistogram="global", FixedThreshold="fixed", BoolCast="bool"),
        TextMode=SimpleNamespace(Plain="plain", HRI="hri"),
        read_barcodes=lambda _image, **kwargs: options.append(kwargs) or [],
    )
    monkeypatch.setitem(sys.modules, "zxingcpp", fake)
    with Image.new("L", (50, 50), "white") as image:
        assert decoder.decode_barcodes_with_zxing(image, qr_only=True) == []
    assert len(options) == 4
    assert {kwargs["binarizer"] for kwargs in options} == {"local", "global", "fixed", "bool"}
    assert {kwargs["text_mode"] for kwargs in options} == {"plain"}
    assert all(kwargs["is_pure"] is False for kwargs in options)


def test_first_tier_collects_multiple_distinct_payloads(decoder, monkeypatch):
    monkeypatch.setattr(decoder, "_zxing_barcodes", lambda *_args, **_kwargs: [
        decoder.DecodedBarcode("https://first.example/"),
        decoder.DecodedBarcode("https://second.example/"),
    ])
    with Image.new("L", (120, 90), "white") as image:
        with pytest.raises(decoder.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
            decoder._decode_qr_from_pil_image(image)


def test_two_physical_codes_with_the_same_payload_are_refused(decoder):
    code = qrcode.make("https://same.example/").convert("RGB")
    canvas = Image.new("RGB", (code.width * 2 + 120, code.height + 40), "white")
    canvas.paste(code, (20, 20))
    canvas.paste(code, (code.width + 100, 20))
    with pytest.raises(decoder.QRDecodeAmbiguityError, match="Multiple QR codes were found"):
        decoder._decode_qr_from_pil_image(canvas)


def test_zbar_single_hit_does_not_hide_second_code_in_enhanced_tier(decoder, monkeypatch):
    first = decoder.DecodedBarcode("https://first.example/", quad=((0, 0), (20, 0), (20, 20), (0, 20)))
    second = decoder.DecodedBarcode("https://second.example/", quad=((80, 60), (100, 60), (100, 80), (80, 80)))
    monkeypatch.setattr(decoder, "_zxing_barcodes", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(decoder, "_pyzbar_barcodes", lambda *_args, **_kwargs: [first])
    monkeypatch.setattr(decoder, "decode_barcodes_with_zxing", lambda *_args, **_kwargs: [second])
    monkeypatch.delenv("QR_WECHAT_ENABLED", raising=False)

    with Image.new("L", (120, 90), "white") as image:
        with pytest.raises(decoder.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
            decoder._decode_qr_from_pil_image(image)


def test_zbar_single_hit_fails_closed_if_second_code_check_times_out(decoder, monkeypatch):
    monkeypatch.setenv("QR_DECODE_BUDGET_S", "0.1")
    monkeypatch.delenv("QR_WECHAT_ENABLED", raising=False)
    monkeypatch.setattr(decoder, "_zxing_barcodes", lambda *_args, **_kwargs: [])

    def slow_zbar(*_args, **_kwargs):
        time.sleep(0.12)
        return [decoder.DecodedBarcode("https://first.example/")]

    monkeypatch.setattr(decoder, "_pyzbar_barcodes", slow_zbar)
    with Image.new("L", (120, 90), "white") as image:
        with pytest.raises(decoder.QRDecodeSafetyError, match="second code"):
            decoder.decode_qr_image(image)


def test_same_payload_on_two_pdf_pages_is_refused(decoder):
    fitz = pytest.importorskip("fitz")
    qr = qrcode.make("https://same.example/").convert("RGB")
    png = io.BytesIO()
    qr.save(png, format="PNG")
    document = fitz.open()
    try:
        for _ in range(2):
            page = document.new_page(width=300, height=300)
            page.insert_image(fitz.Rect(20, 20, 280, 280), stream=png.getvalue())
        contents = document.tobytes()
    finally:
        document.close()
    with pytest.raises(decoder.QRDecodeAmbiguityError, match="Multiple QR codes"):
        decoder.decode_qr_upload(contents, "two-pages.pdf", "application/pdf")


def test_pdf_worker_returns_the_selected_rendered_page(decoder):
    fitz = pytest.importorskip("fitz")
    qr = qrcode.make("https://page.example/").convert("RGB")
    png = io.BytesIO()
    qr.save(png, format="PNG")
    document = fitz.open()
    try:
        page = document.new_page(width=300, height=300)
        page.insert_image(fitz.Rect(20, 20, 280, 280), stream=png.getvalue())
        contents = document.tobytes()
    finally:
        document.close()
    payload, preview = decoder.decode_qr_upload(contents, "one-page.pdf", "application/pdf")
    try:
        assert payload == "https://page.example/"
        assert preview is not None and preview.size == (750, 750)
        assert preview.mode == "RGB"
    finally:
        if preview is not None:
            preview.close()


def test_repeated_read_of_one_physical_code_is_not_ambiguous(decoder):
    first = decoder.DecodedBarcode("https://same.example/", quad=((0, 0), (100, 0), (100, 100), (0, 100)))
    second = decoder.DecodedBarcode("https://same.example/", quad=((4, 3), (104, 3), (104, 103), (4, 103)))
    assert decoder._distinct_barcodes([first, second]) == [first]


def test_oversized_image_is_rejected_before_copying_pixels(decoder):
    huge = SimpleNamespace(width=8000, height=6000)
    with pytest.raises(decoder.QRDecodeSafetyError, match="40 megapixel"):
        decoder.decode_qr_image(huge)


def test_upload_worker_is_killed_when_native_decode_stalls(decoder, monkeypatch, tmp_path):
    worker = tmp_path / "qr_decode_worker.py"
    worker.write_text("import time\ntime.sleep(30)\n")
    monkeypatch.setattr(decoder, "__file__", str(tmp_path / "qr_decode.py"))
    monkeypatch.setenv("QR_DECODE_BUDGET_S", "0.1")
    started = time.monotonic()
    with pytest.raises(decoder.QRDecodeSafetyError, match="time limit"):
        decoder.decode_qr_upload(b"untrusted image bytes", "frame.png", "image/png")
    assert time.monotonic() - started < 2.5


@pytest.mark.parametrize("filename", ["21_stylized_logo.png", "24_micro_qr.png"])
def test_stylized_and_micro_qr_corpus_cases_still_decode(decoder, filename):
    expected = json.loads((CORPUS / "labels.json").read_text())[filename]
    with Image.open(CORPUS / filename) as image:
        found = {item.data.decode("utf-8", errors="replace") for item in decoder.decode_qr_image(image)}
    assert found == set(expected)


def test_both_upload_routes_run_decode_in_bounded_threadpool():
    for name in ("routes_scan_auth.py", "routes_api.py"):
        source = (ROOT / "hackabull" / name).read_text()
        assert "async with QR_DECODE_SEMAPHORE:" in source
        assert "await run_in_threadpool(" in source
        assert "await file.read(MAX_QR_UPLOAD_BYTES + 1)" in source


def test_optional_wechat_models_match_pinned_hashes():
    models = ROOT / "models/wechat_qr"
    lines = (models / "SHA256SUMS").read_text().splitlines()
    checked = set()
    for line in lines:
        if not line or line.startswith("#"):
            continue
        digest, filename = line.split(maxsplit=1)
        filename = filename.lstrip("*")
        assert hashlib.sha256((models / filename).read_bytes()).hexdigest() == digest
        checked.add(filename)
    assert {"detect.prototxt", "detect.caffemodel", "sr.prototxt", "sr.caffemodel", "LICENSE"} <= checked


def test_optional_wechat_reader_can_decode_a_clean_qr(decoder):
    pytest.importorskip("cv2")
    expected = json.loads((CORPUS / "labels.json").read_text())["01_clean_centered.png"][0]
    with Image.open(CORPUS / "01_clean_centered.png") as image:
        found = decoder._wechat_barcodes(image.convert("L"))
    assert {item.data.decode("utf-8", errors="replace") for item in found} == {expected}
