"""Photo QR output must be bounded, scannable, and honest about screening."""

import asyncio
import importlib
import io
import sys

import httpx
from fastapi import UploadFile
from fastapi.responses import JSONResponse
from PIL import Image, ImageDraw
import pytest
from starlette.datastructures import Headers


URL = "https://sqafe.com/"


@pytest.fixture
def generator_api(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'halftone.db'}")
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
    return api


def _photo_bytes(format_name="PNG", *, size=(240, 240)):
    photo = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(photo)
    draw.ellipse((38, 20, 202, 198), fill="#606060")
    draw.ellipse((74, 82, 98, 101), fill="#ffffff")
    draw.ellipse((143, 82, 167, 101), fill="#ffffff")
    draw.arc((91, 108, 151, 171), 12, 168, fill="#f0f0f0", width=8)
    data = io.BytesIO()
    photo.save(data, format=format_name)
    photo.close()
    return data.getvalue()


def _upload(data, content_type="image/png", filename="portrait.png"):
    return UploadFile(
        file=io.BytesIO(data), filename=filename,
        headers=Headers({"content-type": content_type}),
    )


def _decoded_payloads(png, *, preview=False):
    decoder = importlib.import_module("hackabull.qr_decode")
    with Image.open(io.BytesIO(png)) as exported:
        image = exported.convert("RGB")
    if preview:
        small = image.resize((320, round(image.height * 320 / image.width)), Image.Resampling.LANCZOS)
        image.close()
        image = small
    try:
        return {barcode.data.decode("utf-8") for barcode in decoder.decode_qr_image(image)}
    finally:
        image.close()


@pytest.mark.parametrize(("format_name", "mime"), [
    ("PNG", "image/png"), ("JPEG", "image/jpeg"), ("WEBP", "image/webp"),
])
def test_uploaded_photo_qr_round_trips_at_native_and_phone_size(generator_api, format_name, mime):
    image_api = importlib.import_module("hackabull.qr_image")
    png = image_api.qr_photo_halftone_png_from_payload(
        URL, _photo_bytes(format_name), mime, include_attribution=False,
    )
    assert _decoded_payloads(png) == {URL}
    assert _decoded_payloads(png, preview=True) == {URL}
    with Image.open(io.BytesIO(png)) as exported:
        assert exported.size == (592, 592)
        assert exported.getpixel((0, 0)) == (255, 255, 255)


def test_plain_halftone_skips_screening_and_closes_upload(generator_api, monkeypatch):
    async def unexpected_scan(_url):
        pytest.fail("Plain photo QR started a safety scan")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", unexpected_scan)
    monkeypatch.setattr(generator_api, "audit_log", lambda *_args, **_kwargs: pytest.fail("Plain photo QR wrote a checked audit"))
    upload = _upload(_photo_bytes())
    response = asyncio.run(generator_api.api_qr_generate_halftone(
        object(), mode="plain", url=URL, image=upload,
    ))
    assert upload.file.closed
    assert response.media_type == "image/png"
    assert response.headers["X-SafeScan-Mode"] == "plain"
    assert response.headers["X-SafeScan-Verification"] == "not_checked"
    assert "X-SafeScan-Verdict" not in response.headers
    assert "X-SafeScan-Score" not in response.headers
    assert response.headers["Cache-Control"] == "no-store"
    assert _decoded_payloads(response.body, preview=True) == {URL}


def test_screened_halftone_requires_complete_safe_and_audits_only_success(generator_api, monkeypatch):
    verdict = {"overallRisk": "safe", "verificationStatus": "complete", "confidenceScore": 9}
    async def analyze(_url):
        return verdict

    events = []
    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "audit_log", lambda *args, **kwargs: events.append((args, kwargs)))
    for risk, status, expected_code in (
        ("high", "complete", "qr_generation_blocked"),
        ("safe", "incomplete", "scan_incomplete"),
    ):
        verdict.update(overallRisk=risk, verificationStatus=status)
        upload = _upload(_photo_bytes())
        with pytest.raises(generator_api.SafeScanError) as caught:
            asyncio.run(generator_api.api_qr_generate_halftone(
                object(), mode="screened", url=URL, image=upload,
            ))
        assert caught.value.code == expected_code
        assert upload.file.closed
        assert events == []

    verdict.update(overallRisk="safe", verificationStatus="complete")
    upload = _upload(_photo_bytes())
    response = asyncio.run(generator_api.api_qr_generate_halftone(
        object(), mode="screened", url=URL, image=upload,
    ))
    assert upload.file.closed
    assert response.headers["X-SafeScan-Verdict"] == "safe"
    assert response.headers["X-SafeScan-Verification"] == "complete"
    assert response.headers["X-SafeScan-Score"] == "9"
    assert _decoded_payloads(response.body, preview=True) == {URL}
    assert len(events) == 1
    assert events[0][0] == ("qr.generated",)
    assert events[0][1]["metadata"] == {
        "url": URL, "risk": "safe", "score": 9, "guest": True,
        "format": "halftone", "animation": False,
    }


@pytest.mark.parametrize(("data", "mime", "expected_code"), [
    (b"not an image", "image/png", "invalid_request"),
    (_photo_bytes(), "image/jpeg", "invalid_request"),
    (_photo_bytes(), "image/gif", "invalid_request"),
])
def test_bad_image_uploads_close_and_return_clear_errors(generator_api, data, mime, expected_code):
    upload = _upload(data, mime)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate_halftone(
            object(), mode="plain", url=URL, image=upload,
        ))
    assert caught.value.code == expected_code
    assert caught.value.field == "image"
    assert upload.file.closed


def test_halftone_shares_generation_limit_and_closes_rejected_upload(generator_api, monkeypatch):
    calls = []

    def limited(_request, key, limit, period, *, user_key):
        calls.append((key, limit, period, user_key))
        return JSONResponse({"error": "rate_limited"}, status_code=429)

    monkeypatch.setattr(generator_api, "enforce_rate_limit", limited)
    monkeypatch.setattr(generator_api, "_render_photo_halftone", lambda *_args, **_kwargs: pytest.fail("Rate-limited photo rendered"))
    upload = _upload(_photo_bytes())
    response = asyncio.run(generator_api.api_qr_generate_halftone(
        object(), mode="plain", url=URL, image=upload,
    ))
    assert response.status_code == 429
    assert calls == [("qr_generate", 5, 3600, None)]
    assert upload.file.closed


def test_unscannable_export_fails_without_checked_audit(generator_api, monkeypatch):
    async def analyze(_url):
        return {"overallRisk": "safe", "verificationStatus": "complete", "confidenceScore": 5}

    async def unreadable(*_args, **_kwargs):
        raise generator_api.QRHalftoneDecodeError("unreadable")

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    monkeypatch.setattr(generator_api, "_render_photo_halftone", unreadable)
    monkeypatch.setattr(generator_api, "audit_log", lambda *_args, **_kwargs: pytest.fail("Unscannable photo was audited"))
    upload = _upload(_photo_bytes())
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate_halftone(
            object(), mode="screened", url=URL, image=upload,
        ))
    assert caught.value.code == "qr_generation_unscannable"
    assert caught.value.field == "image"
    assert upload.file.closed


def test_halftone_file_bytes_are_bounded(generator_api, monkeypatch):
    monkeypatch.setattr(generator_api, "_HALFTONE_MAX_IMAGE_BYTES", 16)
    monkeypatch.setattr(generator_api, "_render_photo_halftone", lambda *_args, **_kwargs: pytest.fail("Oversize photo rendered"))
    upload = _upload(_photo_bytes())
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate_halftone(
            object(), mode="plain", url=URL, image=upload,
        ))
    assert caught.value.code == "upload_too_large"
    assert caught.value.status_code == 413
    assert upload.file.closed


def test_image_decoder_rejects_animation_and_excess_pixels(generator_api):
    image_api = importlib.import_module("hackabull.qr_image")
    first = Image.new("RGB", (80, 80), "red")
    second = Image.new("RGB", (80, 80), "blue")
    animated = io.BytesIO()
    first.save(animated, format="WEBP", save_all=True, append_images=[second], duration=100)
    first.close()
    second.close()
    with pytest.raises(image_api.QRHalftoneImageError, match="still photo"):
        image_api.qr_photo_halftone_png_from_payload(URL, animated.getvalue(), "image/webp")

    oversized = Image.new("L", (3500, 3500), 128)
    data = io.BytesIO()
    oversized.save(data, format="PNG")
    oversized.close()
    with pytest.raises(image_api.QRHalftoneImageError) as caught:
        image_api.qr_photo_halftone_png_from_payload(URL, data.getvalue(), "image/png")
    assert caught.value.too_large


def test_halftone_route_returns_scannable_png_over_multipart(generator_api, monkeypatch):
    monkeypatch.setattr(generator_api, "audit_log", lambda *_args, **_kwargs: pytest.fail("Plain photo QR wrote a checked audit"))

    async def make_request():
        transport = httpx.ASGITransport(app=generator_api.qr_app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            return await client.post(
                "/api/qr/generate-halftone",
                data={"mode": "plain", "url": URL},
                files={"image": ("portrait.png", _photo_bytes(), "image/png")},
            )

    response = asyncio.run(make_request())
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/png"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-SafeScan-Verification"] == "not_checked"
    assert _decoded_payloads(response.content, preview=True) == {URL}


def test_halftone_route_rejects_oversize_multipart_before_parser(generator_api, monkeypatch):
    app_module = importlib.import_module("hackabull.app_module")
    monkeypatch.setattr(app_module, "QR_REQUEST_BODY_LIMIT", 256)
    monkeypatch.setattr(generator_api, "_render_photo_halftone", lambda *_args, **_kwargs: pytest.fail("Oversize upload rendered"))

    async def make_request():
        transport = httpx.ASGITransport(app=generator_api.qr_app)
        async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as client:
            return await client.post(
                "/api/qr/generate-halftone",
                data={"mode": "plain", "url": URL},
                files={"image": ("portrait.png", _photo_bytes(), "image/png")},
            )

    response = asyncio.run(make_request())
    assert response.status_code == 413
    assert response.json()["code"] == "upload_too_large"
