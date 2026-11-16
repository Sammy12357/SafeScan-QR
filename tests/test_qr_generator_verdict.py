"""Branded QR generation must fail closed when a scan is risky or incomplete."""

import asyncio
import base64
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


def _assert_art_png_decodes(png, url):
    decoder = importlib.import_module("hackabull.qr_decode")
    image = Image.open(io.BytesIO(png)).convert("RGB")
    for candidate in (
        image,
        image.resize(
            (320, round(image.height * 320 / image.width)), Image.Resampling.LANCZOS,
        ),
    ):
        decoded = {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(candidate)}
        assert decoded == {url}
    return image


@pytest.mark.parametrize("art_style", ["cat", "flame"])
@pytest.mark.parametrize("plain", [False, True])
def test_ascii_art_qr_api_is_scannable_and_preserves_verdict_mode(
    generator_api, monkeypatch, art_style, plain,
):
    url = "https://sqafe.com/"
    audits = []

    async def analyze(_url):
        if plain:
            pytest.fail("Plain ASCII art QR ran a safety scan")
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: audits.append((args, kwargs)))
    route = generator_api.api_qr_generate_plain if plain else generator_api.api_qr_generate
    response = asyncio.run(route(object(), {
        "url": url, "format": "ascii_art", "art_style": art_style,
    }))
    assert response.media_type == "image/png"
    assert response.body.startswith(b"\x89PNG\r\n\x1a\n")
    assert response.headers["Cache-Control"] == "no-store"
    image = _assert_art_png_decodes(response.body, url)
    if plain:
        assert response.headers["X-SafeScan-Verification"] == "not_checked"
        assert "X-SafeScan-Verdict" not in response.headers
        assert response.headers["Content-Disposition"] == 'inline; filename="plain-ascii-art-qr.png"'
        assert image.height == image.width  # No Sqafe or checked footer.
        assert audits == []
    else:
        assert response.headers["X-SafeScan-Verification"] == "complete"
        assert response.headers["X-SafeScan-Verdict"] == "safe"
        assert response.headers["Content-Disposition"] == 'inline; filename="sqafe-ascii-art-qr.png"'
        assert image.height == image.width + 52  # Attribution outside the QR.
        assert len(audits) == 1
        assert audits[0][1]["metadata"]["art_style"] == art_style


@pytest.mark.parametrize("url", [
    "https://a.co/",  # The drawing needs a minimum QR version for this URL.
    "https://sqafe.com/generate-qr?test=" + "long" * 45,
])
@pytest.mark.parametrize("art_style", ["cat", "flame"])
def test_ascii_art_qr_short_and_long_urls_decode_at_mobile_size(generator_api, art_style, url):
    png = generator_api.qr_ascii_art_png_from_payload(
        url, art_style=art_style, include_attribution=False,
    )
    image = _assert_art_png_decodes(png, url)
    assert image.width == image.height
    assert image.width <= 121 * 26


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("art_style", [None, 2, "", "rocket", "cat" * 100])
def test_ascii_art_rejects_unsupported_styles_before_render_or_scan(
    generator_api, monkeypatch, plain, art_style,
):
    async def analyze(_url):
        pytest.fail("Invalid ASCII art style reached scanning")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(
        generator_api, "qr_ascii_art_png_from_payload",
        lambda *_args, **_kwargs: pytest.fail("Invalid ASCII art style rendered"),
    )
    route = generator_api.api_qr_generate_plain if plain else generator_api.api_qr_generate
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(route(object(), {
            "url": "https://sqafe.com/", "format": "ascii_art", "art_style": art_style,
        }))
    assert caught.value.code == "invalid_request"
    assert caught.value.field == "art_style"


@pytest.mark.parametrize("plain", [False, True])
def test_ascii_art_rejects_animation_option(generator_api, monkeypatch, plain):
    async def analyze(_url):
        pytest.fail("Invalid ASCII art option reached scanning")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    route = generator_api.api_qr_generate_plain if plain else generator_api.api_qr_generate
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(route(object(), {
            "url": "https://sqafe.com/", "format": "ascii_art",
            "art_style": "cat", "animation": True,
        }))
    assert caught.value.field == "animation"


@pytest.mark.parametrize("url_length", [500, 1300])
def test_ascii_art_qr_limits_render_work_and_does_not_audit_failed_generation(
    generator_api, monkeypatch, url_length,
):
    events = []

    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: events.append((args, kwargs)))
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {
            "url": "https://sqafe.com/" + "a" * url_length,
            "format": "ascii_art", "art_style": "cat",
        }))
    assert caught.value.code == "qr_generation_too_long"
    assert events == []


def _assert_ascii_finder_corners(frame):
    """All three finder squares show glyphs without losing their clear rings."""
    def luminance(pixel):
        linear = []
        for value in pixel:
            channel = value / 255
            linear.append(channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4)
        return sum(weight * channel for weight, channel in zip((0.2126, 0.7152, 0.0722), linear))

    cell = 26
    border = 4
    assert frame.width % cell == 0
    modules = frame.width // cell
    code_size = frame.width
    white = ((255, 255),) * 3
    clear_border = border * cell
    for quiet_zone in (
        (0, 0, code_size, clear_border),
        (0, 0, clear_border, code_size),
        (code_size - clear_border, 0, code_size, code_size),
        (0, code_size - clear_border, code_size, code_size),
    ):
        assert frame.crop(quiet_zone).getextrema() == white

    origins = (
        (border, border),
        (modules - border - 7, border),
        (border, modules - border - 7),
    )
    def assert_white_cell(x, y):
        box = (x * cell, y * cell, (x + 1) * cell, (y + 1) * cell)
        assert frame.crop(box).getextrema() == white

    for corner_index, (origin_x, origin_y) in enumerate(origins):
        # The complete one-module white ring must be untouched by glyphs.
        for inner_y in range(1, 6):
            for inner_x in range(1, 6):
                if inner_x not in (1, 5) and inner_y not in (1, 5):
                    continue
                assert_white_cell(origin_x + inner_x, origin_y + inner_y)

        # The one-module separator is white on both inward sides of each
        # corner marker, including its inner junction cell.
        if corner_index == 0:  # top left: right and bottom
            separator = [(origin_x + 7, origin_y + offset) for offset in range(8)]
            separator += [(origin_x + offset, origin_y + 7) for offset in range(8)]
        elif corner_index == 1:  # top right: left and bottom
            separator = [(origin_x - 1, origin_y + offset) for offset in range(8)]
            separator += [(origin_x - 1 + offset, origin_y + 7) for offset in range(8)]
        else:  # bottom left: right and top
            separator = [(origin_x + 7, origin_y - 1 + offset) for offset in range(8)]
            separator += [(origin_x + offset, origin_y - 1) for offset in range(8)]
        for x, y in separator:
            assert_white_cell(x, y)

        # The outer border and center must remain mostly dark for detection,
        # while their visible glyph contrast rules out solid-filled squares.
        for inner_x, inner_y in ((0, 0), (3, 0), (3, 3)):
            x = (origin_x + inner_x) * cell
            y = (origin_y + inner_y) * cell
            pixels = list(frame.crop((x, y, x + cell, y + cell)).getdata())
            ink_pixels = sum(max(pixel) < 220 for pixel in pixels)
            lightness = sorted(luminance(pixel) for pixel in pixels)
            # These percentiles require visible clusters of at least 5% of
            # the cell for both the dark field and contrasting ASCII glyph.
            darkest = lightness[int(len(lightness) * 0.05)]
            lightest = lightness[int(len(lightness) * 0.95)]
            assert ink_pixels >= cell * cell * 0.3
            assert (lightest + 0.05) / (darkest + 0.05) >= 1.5

    return tuple(
        frame.crop((x * cell, y * cell, (x + 7) * cell, (y + 7) * cell)).tobytes()
        for x, y in origins
    )


def _assert_ascii_motion_bundle_decodes(response, url, *, checked):
    body = json.loads(response.body)
    assert set(body) == {
        "still_png_base64", "animated_png_base64", "frame_count", "frame_duration_ms",
    }
    assert body["frame_count"] == 4
    assert body["frame_duration_ms"] == 350
    still_bytes = base64.b64decode(body["still_png_base64"], validate=True)
    animated_bytes = base64.b64decode(body["animated_png_base64"], validate=True)
    assert still_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    assert animated_bytes.startswith(b"\x89PNG\r\n\x1a\n")

    still = Image.open(io.BytesIO(still_bytes)).convert("RGB")
    animated = Image.open(io.BytesIO(animated_bytes))
    assert animated.n_frames == 4
    assert still.height == still.width + (52 if checked else 0)
    decoder = importlib.import_module("hackabull.qr_decode")
    frame_bytes = []
    finder_bytes = []
    for index in range(animated.n_frames):
        animated.seek(index)
        frame = animated.convert("RGB")
        frame_bytes.append(frame.tobytes())
        finder_bytes.append(_assert_ascii_finder_corners(frame))
        for candidate in (
            frame,
            frame.resize((320, round(frame.height * 320 / frame.width)), Image.Resampling.LANCZOS),
        ):
            decoded = {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(candidate)}
            assert decoded == {url}
    assert still.tobytes() == frame_bytes[0]
    assert len(set(frame_bytes)) == 4  # The ASCII glyphs really move.
    assert all(len({corners[index] for corners in finder_bytes}) == 4 for index in range(3))
    # Every corner gets changing ASCII texture while its dark/white geometry
    # remains recognizable in every frame (checked above).


@pytest.mark.parametrize("plain", [False, True])
def test_ascii_motion_api_screens_once_or_stays_unchecked(generator_api, monkeypatch, plain):
    url = "https://a.co/"
    scans = []
    audits = []

    async def analyze(target):
        scans.append(target)
        if plain:
            pytest.fail("Plain ASCII motion QR ran a safety scan")
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: audits.append((args, kwargs)))
    route = generator_api.api_qr_generate_plain if plain else generator_api.api_qr_generate
    response = asyncio.run(route(object(), {"url": url, "format": "ascii_motion"}))
    assert response.media_type == "application/json"
    assert response.headers["Cache-Control"] == "no-store"
    _assert_ascii_motion_bundle_decodes(response, url, checked=not plain)
    if plain:
        assert scans == []
        assert audits == []
        assert response.headers["X-SafeScan-Mode"] == "plain"
        assert response.headers["X-SafeScan-Verification"] == "not_checked"
        assert "X-SafeScan-Verdict" not in response.headers
    else:
        assert scans == [url]
        assert response.headers["X-SafeScan-Verdict"] == "safe"
        assert response.headers["X-SafeScan-Verification"] == "complete"
        assert len(audits) == 1
        assert audits[0][1]["metadata"]["format"] == "ascii_motion"
        assert audits[0][1]["metadata"]["animation"] is True


def test_ascii_motion_custom_gradient_and_long_url_decode(generator_api):
    url = "https://sqafe.com/generate-qr?test=" + "long" * 45
    response = asyncio.run(generator_api.api_qr_generate_plain(object(), {
        "url": url, "format": "ascii_motion",
        "gradient_start": "#093D3A", "gradient_end": "#4A245F",
    }))
    _assert_ascii_motion_bundle_decodes(response, url, checked=False)


@pytest.mark.parametrize("color", ["#000000", "#000080"])
def test_ascii_motion_dark_gradient_keeps_finders_visible_and_scannable(generator_api, color):
    url = "https://a.co/"
    response = asyncio.run(generator_api.api_qr_generate_plain(object(), {
        "url": url, "format": "ascii_motion",
        "gradient_start": color, "gradient_end": color,
    }))
    _assert_ascii_motion_bundle_decodes(response, url, checked=False)


@pytest.mark.parametrize("plain", [False, True])
@pytest.mark.parametrize("field,value", [
    ("gradient_start", "red"),
    ("gradient_end", None),
    ("gradient_start", "#FFFFFF"),
    ("gradient_end", "#FFFF00"),
])
def test_ascii_motion_rejects_malformed_or_light_colors_before_scanning(
    generator_api, monkeypatch, plain, field, value,
):
    async def analyze(_url):
        pytest.fail("Invalid gradient reached safety scan")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(
        generator_api, "qr_ascii_motion_pngs_from_payload",
        lambda *_args, **_kwargs: pytest.fail("Invalid gradient rendered"),
    )
    route = generator_api.api_qr_generate_plain if plain else generator_api.api_qr_generate
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(route(object(), {
            "url": "https://a.co/", "format": "ascii_motion", field: value,
        }))
    assert caught.value.code == "invalid_request"
    assert caught.value.field == field
    assert caught.value.status_code == 400


def test_ascii_motion_too_large_url_and_undecodable_frame_do_not_audit(
    generator_api, monkeypatch,
):
    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    audits = []
    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: audits.append((args, kwargs)))
    with pytest.raises(generator_api.SafeScanError) as too_long:
        asyncio.run(generator_api.api_qr_generate(object(), {
            "url": "https://sqafe.com/" + "a" * 300, "format": "ascii_motion",
        }))
    assert too_long.value.code == "qr_generation_too_long"
    assert audits == []

    def failed_decode(*_args, **_kwargs):
        raise generator_api.QRAsciiMotionDecodeError("failed")

    monkeypatch.setattr(generator_api, "qr_ascii_motion_pngs_from_payload", failed_decode)
    with pytest.raises(generator_api.SafeScanError) as unscannable:
        asyncio.run(generator_api.api_qr_generate(object(), {
            "url": "https://a.co/", "format": "ascii_motion",
        }))
    assert unscannable.value.code == "qr_generation_unscannable"
    assert audits == []


def test_ascii_motion_rejects_concurrent_render_and_releases_slot(generator_api, monkeypatch):
    async def scenario():
        started = asyncio.Event()
        finish = asyncio.Event()
        renders = []

        async def slow_render(function, *args, **kwargs):
            renders.append((function, args, kwargs))
            started.set()
            await finish.wait()
            return b"still", b"animated"

        monkeypatch.setattr(generator_api, "run_in_threadpool", slow_render)
        first = asyncio.create_task(generator_api.api_qr_generate_plain(object(), {
            "url": "https://a.co/", "format": "ascii_motion",
        }))
        await started.wait()
        try:
            with pytest.raises(generator_api.SafeScanError) as caught:
                await generator_api.api_qr_generate_plain(object(), {
                    "url": "https://b.co/", "format": "ascii_motion",
                })
            assert caught.value.code == "qr_generation_busy"
            assert caught.value.status_code == 503
            assert len(renders) == 1
        finally:
            finish.set()
            await first

        # A finished render returns its memory slot to subsequent requests.
        response = await generator_api.api_qr_generate_plain(object(), {
            "url": "https://b.co/", "format": "ascii_motion",
        })
        assert response.status_code == 200
        assert len(renders) == 2

    asyncio.run(scenario())
