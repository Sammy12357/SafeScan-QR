"""Branded QR generation must fail closed when a scan is risky or incomplete."""

import asyncio
import importlib
import io
import json
import sys
from pathlib import Path

from fastapi.responses import JSONResponse
from PIL import Image, ImageDraw, ImageFont
import pytest
import qrcode
from qrcode.exceptions import DataOverflowError


@pytest.fixture
def generator_api(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'generator.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    api = importlib.import_module("hackabull.routes_api")
    monkeypatch.setattr(api, "get_session_user", lambda _request: None)
    monkeypatch.setattr(api, "enforce_rate_limit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, "validate_public_url", lambda url: url)
    monkeypatch.setattr(api, "audit_log", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, "render_safescan_logo", lambda _size: None)
    return api


@pytest.mark.parametrize(
    ("risk", "score"),
    [("suspicious", 35), ("suspicious", 79), ("high", 80), ("high", 89)],
)
def test_generator_refuses_every_non_safe_verdict(generator_api, monkeypatch, risk, score):
    async def analyze(_url):
        return {"overallRisk": risk, "confidenceScore": score, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/"}))
    assert caught.value.status_code == 400


def test_generator_refuses_safe_score_with_incomplete_checks(generator_api, monkeypatch):
    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "incomplete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/"}))
    assert caught.value.status_code == 503


def test_generator_allows_only_complete_safe_scan(generator_api, monkeypatch):
    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    response = asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/"}))
    assert response.media_type == "image/png"
    assert response.headers["X-SafeScan-Verdict"] == "safe"
    assert response.body.startswith(b"\x89PNG\r\n\x1a\n")


@pytest.mark.parametrize("format_option", [{}, {"format": "ascii"}, {"format": "ascii", "animation": True}])
def test_plain_generator_never_checks_or_claims_a_safe_verdict(generator_api, monkeypatch, format_option):
    async def analyze(_url):
        pytest.fail("Plain QR started a safety scan")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *_args, **_kwargs: pytest.fail("Plain QR claimed a checked audit"))
    response = asyncio.run(generator_api.api_qr_generate_plain(
        object(), {"url": "https://example.com/", **format_option},
    ))

    assert response.headers["X-SafeScan-Mode"] == "plain"
    assert response.headers["X-SafeScan-Verification"] == "not_checked"
    assert response.headers["Cache-Control"] == "no-store"
    assert "X-SafeScan-Verdict" not in response.headers
    assert "X-SafeScan-Score" not in response.headers

    if not format_option:
        assert response.media_type == "image/png"
        assert response.headers["Content-Disposition"] == 'inline; filename="plain-qr.png"'
        image = Image.open(io.BytesIO(response.body)).convert("RGB")
        expected_qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            border=4,
            box_size=10,
        )
        expected_qr.add_data("https://example.com/")
        expected_qr.make(fit=True)
        expected = expected_qr.make_image(fill_color="black", back_color="white").convert("RGB")
        assert image.size == expected.size
        assert image.tobytes() == expected.tobytes()  # No logo, badge or other overlay.
        assert image.crop((0, 0, image.width, 40)).getextrema() == ((255, 255),) * 3
        decoder = importlib.import_module("hackabull.qr_decode")
        assert {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(image)} == {"https://example.com/"}
    else:
        frames = json.loads(response.body)["frames"] if format_option.get("animation") else [response.body.decode("utf-8")]
        if format_option.get("animation"):
            assert response.media_type == "application/json"
            assert json.loads(response.body)["text"] == frames[0]
            assert len(set(frames)) == 4
        else:
            assert response.media_type == "text/plain; charset=utf-8"
        decoder = importlib.import_module("hackabull.qr_decode")
        for frame in frames:
            assert "Sqafe" not in frame and "SafeScan" not in frame
            rows = frame.splitlines()
            assert len({len(row) for row in rows}) == 1
            assert all(row == " " * len(row) for row in rows[:2] + rows[-2:])
            assert all(row.startswith(" " * 4) and row.endswith(" " * 4) for row in rows)
            image = _module_image_from_text(rows)
            assert {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(image)} == {"https://example.com/"}


@pytest.mark.parametrize("format_option", [{}, {"format": "ascii"}, {"format": "ascii", "animation": True}])
def test_plain_generator_shares_screened_rate_limit(generator_api, monkeypatch, format_option):
    calls = []

    def limited(_request, key, limit, period, *, user_key):
        calls.append((key, limit, period, user_key))
        return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": "47"})

    monkeypatch.setattr(generator_api, "enforce_rate_limit", limited)
    monkeypatch.setattr(generator_api, "qr_plain_png_from_payload", lambda *_args: pytest.fail("Rate-limited plain PNG rendered"))
    monkeypatch.setattr(generator_api, "qr_ascii_from_payload", lambda *_args, **_kwargs: pytest.fail("Rate-limited plain text QR rendered"))
    response = asyncio.run(generator_api.api_qr_generate_plain(
        object(), {"url": "https://example.com/", **format_option},
    ))
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "47"
    assert calls == [("qr_generate", 5, 3600, None)]


@pytest.mark.parametrize("bad_url", [None, 123, "http://localhost/", "http://127.0.0.1/"])
def test_plain_generator_rejects_missing_or_private_urls(generator_api, monkeypatch, bad_url):
    security = importlib.import_module("hackabull.security")
    monkeypatch.setattr(generator_api, "validate_public_url", security.validate_public_url)
    monkeypatch.setattr(generator_api, "qr_plain_png_from_payload", lambda *_args: pytest.fail("Invalid URL rendered"))
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate_plain(object(), {"url": bad_url}))
    assert caught.value.status_code == 400


@pytest.mark.parametrize("payload,field", [
    ({"url": "https://example.com/", "format": "svg"}, "format"),
    ({"url": "https://example.com/", "animation": True}, "animation"),
    ({"url": "https://example.com/", "format": "ascii", "animation": "true"}, "animation"),
])
def test_plain_generator_rejects_invalid_render_options(generator_api, monkeypatch, payload, field):
    monkeypatch.setattr(generator_api, "qr_plain_png_from_payload", lambda *_args: pytest.fail("Invalid options rendered"))
    monkeypatch.setattr(generator_api, "qr_ascii_from_payload", lambda *_args, **_kwargs: pytest.fail("Invalid options rendered"))
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate_plain(object(), payload))
    assert caught.value.code == "invalid_request"
    assert caught.value.field == field


def test_plain_generator_oversized_qr_has_actionable_error(generator_api, monkeypatch):
    monkeypatch.setattr(generator_api, "qr_plain_png_from_payload", lambda *_args: (_ for _ in ()).throw(DataOverflowError("too long")))
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate_plain(object(), {"url": "https://example.com/"}))
    assert caught.value.code == "qr_generation_too_long"


@pytest.mark.parametrize("format_option", [{}, {"format": "ascii"}, {"format": "ascii", "animation": True}])
@pytest.mark.parametrize("risk,status,expected_status", [
    ("high", "complete", 400),
    ("safe", "incomplete", 503),
])
def test_every_format_refuses_unsafe_or_incomplete_scan(
    generator_api, monkeypatch, format_option, risk, status, expected_status,
):
    events = []

    async def analyze(_url):
        return {"overallRisk": risk, "confidenceScore": 95, "verificationStatus": status}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(generator_api, "qr_ascii_from_payload", lambda *_args, **_kwargs: pytest.fail("Rendered unsafe text QR"))
    monkeypatch.setattr(generator_api, "_render_branded_qr_png", lambda *_args: pytest.fail("Rendered unsafe PNG"))
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/", **format_option}))
    assert caught.value.status_code == expected_status
    assert events == []


@pytest.mark.parametrize("format_option", [{}, {"format": "ascii"}, {"format": "ascii", "animation": True}])
def test_rate_limit_applies_before_any_format_is_rendered(generator_api, monkeypatch, format_option):
    calls = []

    def limited(_request, key, limit, period, *, user_key):
        calls.append((key, limit, period, user_key))
        return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": "47"})

    async def analyze(_url):
        pytest.fail("Rate-limited QR attempted scanning")

    monkeypatch.setattr(generator_api, "enforce_rate_limit", limited)
    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "qr_ascii_from_payload", lambda *_args, **_kwargs: pytest.fail("Rate-limited QR rendered"))
    monkeypatch.setattr(generator_api, "_render_branded_qr_png", lambda *_args: pytest.fail("Rate-limited QR rendered"))
    response = asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/", **format_option}))
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "47"
    assert response.body == b'{"error":"rate_limited"}'
    assert calls == [("qr_generate", 5, 3600, None)]


@pytest.mark.parametrize("format_option,field", [
    ({"format": "svg"}, "format"),
    ({"format": None}, "format"),
    ({"animation": True}, "animation"),
    ({"format": "png", "animation": True}, "animation"),
    ({"format": "ascii", "animation": 1}, "animation"),
    ({"format": "ascii", "animation": None}, "animation"),
    ({"format": "ascii", "animation": "true"}, "animation"),
])
def test_generator_rejects_invalid_format_or_animation(generator_api, monkeypatch, format_option, field):
    async def analyze(_url):
        pytest.fail("Invalid format reached scanning")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/", **format_option}))
    assert caught.value.status_code == 400
    assert caught.value.field == field


@pytest.mark.parametrize("animation", [False, True])
def test_text_qr_requires_safe_verdict_and_audits_once(generator_api, monkeypatch, animation):
    audit_events = []
    scans = []

    async def analyze(url):
        scans.append(url)
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: audit_events.append((args, kwargs)))
    response = asyncio.run(generator_api.api_qr_generate(
        object(), {"url": "https://example.com/", "format": "ascii", "animation": animation},
    ))
    assert scans == ["https://example.com/"]
    assert response.headers["X-SafeScan-Verdict"] == "safe"
    assert response.headers["X-SafeScan-Verification"] == "complete"
    assert response.headers["X-SafeScan-Score"] == "8"
    assert response.headers["Cache-Control"] == "no-store"
    if animation:
        assert response.media_type == "application/json"
        data = json.loads(response.body)
        assert data["text"] == data["frames"][0]
        assert len(data["frames"]) == 4
        assert len(set(data["frames"])) == 4
        assert all(frame.endswith("Generated by Sqafe · sqafe.com\n") for frame in data["frames"])
    else:
        assert response.media_type == "text/plain; charset=utf-8"
        assert response.body.decode("utf-8").endswith("Generated by Sqafe · sqafe.com\n")
    assert len(audit_events) == 1
    assert audit_events[0][0] == ("qr.generated",)
    assert audit_events[0][1]["metadata"]["format"] == "ascii"
    assert audit_events[0][1]["metadata"]["animation"] is animation


def test_failed_text_render_is_not_audited(generator_api, monkeypatch):
    events = []

    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(generator_api, "qr_ascii_from_payload", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("render failed")))
    with pytest.raises(ValueError, match="render failed"):
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/", "format": "ascii"}))
    assert events == []


@pytest.mark.parametrize("format_option", [{}, {"format": "ascii"}, {"format": "ascii", "animation": True}])
def test_oversized_qr_has_actionable_error_without_audit(generator_api, monkeypatch, format_option):
    events = []

    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    def overflow(*_args, **_kwargs):
        raise DataOverflowError("QR data too long")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: events.append((args, kwargs)))
    monkeypatch.setattr(generator_api, "qr_ascii_from_payload", overflow)
    monkeypatch.setattr(generator_api, "_render_branded_qr_png", overflow)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/", **format_option}))
    assert caught.value.code == "qr_generation_too_long"
    assert caught.value.status_code == 400
    assert events == []


@pytest.mark.parametrize("bad_url", [None, 123, [], {}])
def test_generator_rejects_non_string_url(generator_api, monkeypatch, bad_url):
    security = importlib.import_module("hackabull.security")
    monkeypatch.setattr(generator_api, "validate_public_url", security.validate_public_url)

    async def analyze(_url):
        pytest.fail("Invalid URL reached scanning")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": bad_url, "format": "ascii"}))
    assert caught.value.status_code == 400


def _text_qr_rows(text):
    code, label = text.split("\n\nGenerated by Sqafe · sqafe.com\n")
    assert label == ""
    rows = code.splitlines()
    assert len({len(row) for row in rows}) == 1
    # Two text rows are the four-module top and bottom quiet zones.
    assert all(row == " " * len(row) for row in rows[:2] + rows[-2:])
    assert all(row.startswith(" " * 4) and row.endswith(" " * 4) for row in rows)
    return rows


def _module_image_from_text(rows):
    """Rasterize each half-block into its exact pair of square QR modules."""
    scale = 8
    image = Image.new("RGB", (len(rows[0]) * scale, len(rows) * 2 * scale), "white")
    draw = ImageDraw.Draw(image)
    pairs = {" ": (False, False), "▀": (True, False), "▄": (False, True), "█": (True, True)}
    for row_index, row in enumerate(rows):
        for column_index, glyph in enumerate(row):
            for half, dark in enumerate(pairs[glyph]):
                if dark:
                    draw.rectangle(
                        (column_index * scale, (row_index * 2 + half) * scale,
                         (column_index + 1) * scale - 1, (row_index * 2 + half + 1) * scale - 1),
                        fill="black",
                    )
    return image


@pytest.mark.parametrize("url", [
    "https://sqafe.com/",
    "https://sqafe.com/generate-qr?test=" + "long" * 45,
])
def test_text_qr_and_each_animation_mask_round_trip_through_project_decoder(generator_api, url):
    decoder = importlib.import_module("hackabull.qr_decode")
    frames = [generator_api.qr_ascii_from_payload(url, mask_pattern=mask) for mask in (0, 1, 2, 3)]
    assert len(set(frames)) == 4
    for frame in frames:
        image = _module_image_from_text(_text_qr_rows(frame))
        decoded = {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(image)}
        assert decoded == {url}


def test_text_qr_round_trips_when_drawn_in_a_monospace_font(generator_api):
    # These are common system monospace fonts on macOS and Ubuntu CI. The
    # semantic module test above still runs if neither font is installed.
    candidates = (
        Path("/System/Library/Fonts/Menlo.ttc"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    )
    font_path = next((path for path in candidates if path.exists()), None)
    if font_path is None:
        pytest.skip("No tested monospace font is installed")
    font = ImageFont.truetype(str(font_path), 40)
    url = "https://sqafe.com/generate-qr?type=text"
    rows = _text_qr_rows(generator_api.qr_ascii_from_payload(url))
    cell_width = round(font.getlength("█"))
    line_height = 40
    top_offset = font.getbbox("█")[1]
    image = Image.new("RGB", (len(rows[0]) * cell_width, len(rows) * line_height), "white")
    draw = ImageDraw.Draw(image)
    for row_index, row in enumerate(rows):
        draw.text((0, row_index * line_height - top_offset), row, fill="black", font=font)
    decoder = importlib.import_module("hackabull.qr_decode")
    decoded = {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(image)}
    assert decoded == {url}
