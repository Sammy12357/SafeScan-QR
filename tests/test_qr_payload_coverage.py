"""Focused regression cases for actionable and competing QR payloads."""

import asyncio
import io

import pytest
import qrcode
from PIL import Image

from hackabull import qr_decode, qr_detect


@pytest.mark.parametrize(
    ("payload", "kind"),
    [
        ("wc:pairing@2?relay-protocol=irn", "Crypto/payment"),
        ("upi://pay?pa=example@bank&am=100", "Crypto/payment"),
        ("tel:+18005550100", "Phone"),
        ("intent://scan/#Intent;scheme=example;end", "App/deep link"),
        ("otpauth://totp/example?secret=ABCDEF", "Authentication"),
        ("custom-action://transfer?amount=100", "App/deep link"),
    ],
)
def test_actionable_schemes_are_not_plain_text_safe(monkeypatch, payload, kind):
    monkeypatch.setattr(qr_detect, "classify_qr_with_ml", lambda *_: {"enabled": False})
    monkeypatch.setattr(qr_detect, "blend_ml_score", lambda score, *_: score)
    monkeypatch.setattr(qr_detect, "ml_signal_from_result", lambda *_, **__: None)

    assert qr_detect.detect_payload(payload)[0] == kind
    analysis = qr_detect.analyze_qr_payload(payload)
    assert analysis["status"] == "CAUTION"
    assert int(analysis["score"]) >= 40
    assert analysis["verificationStatus"] == "unverified"


def test_extract_all_distinct_embedded_urls_including_encoded():
    payload = (
        "intent://scan/#Intent;S.browser_fallback_url=https%3A%2F%2Ffirst.example%2Fgo;"
        "S.other=https://second.example/path;S.repeat=https://second.example/path;end"
    )
    urls = qr_detect.extract_urls(payload)
    assert "https://first.example/go" in urls
    assert "https://second.example/path" in urls
    assert len(urls) == 2


def test_embedded_url_entrypoint_never_fetches_private_payload_fields(monkeypatch):
    monkeypatch.setattr(qr_detect, "classify_qr_with_ml", lambda *_: {"enabled": False})
    monkeypatch.setattr(qr_detect, "blend_ml_score", lambda score, *_: score)
    monkeypatch.setattr(qr_detect, "ml_signal_from_result", lambda *_, **__: None)
    async def pipeline(*_args, **_kwargs):
        raise AssertionError("non-URL QR content must stay local")

    monkeypatch.setattr(qr_detect, "analyze_full_pipeline", pipeline)
    raw = "SMS:123:Visit https://good.example/ and https://bad.example/drain then http://127.0.0.1/"
    analysis = asyncio.run(qr_detect.analyze_embedded_url_payload(raw, "https://good.example/"))

    assert analysis["status"] == "MALICIOUS"
    assert int(analysis["score"]) >= 80
    assert analysis["normalized"] == raw
    assert analysis["analyzedUrls"] == []
    assert "Embedded links not fetched" in analysis["unverifiedChecks"]
    assert "No embedded destination was fetched" in analysis["verdict"]


def test_too_many_embedded_urls_is_explicitly_incomplete(monkeypatch):
    monkeypatch.setattr(qr_detect, "classify_qr_with_ml", lambda *_: {"enabled": False})
    monkeypatch.setattr(qr_detect, "blend_ml_score", lambda score, *_: score)
    monkeypatch.setattr(qr_detect, "ml_signal_from_result", lambda *_, **__: None)

    async def unexpected_pipeline(*_args, **_kwargs):
        raise AssertionError("network pipeline should not run on over-limit input")

    monkeypatch.setattr(qr_detect, "analyze_full_pipeline", unexpected_pipeline)
    raw = "SMS:123:" + " ".join(f"https://destination{i}.example/" for i in range(qr_detect.MAX_EMBEDDED_URLS + 1))
    result = asyncio.run(qr_detect.analyze_embedded_url_payload(raw, "https://destination0.example/"))
    assert result["status"] == "CAUTION"
    assert result["normalized"] == raw
    assert "No embedded destination was fetched" in result["verdict"]
    assert "Embedded URLs beyond local scan limit" in result["unverifiedChecks"]


def test_upload_with_two_different_qr_codes_is_ambiguous():
    first = qrcode.make("https://first.example/").convert("RGB")
    second = qrcode.make("https://second.example/").convert("RGB")
    canvas = Image.new("RGB", (first.width + second.width + 120, max(first.height, second.height) + 60), "white")
    canvas.paste(first, (20, 20))
    canvas.paste(second, (first.width + 100, 20))
    output = io.BytesIO()
    canvas.save(output, format="PNG")

    with pytest.raises(qr_decode.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
        qr_decode.decode_qr_upload(output.getvalue(), "two-qr.png", "image/png")
