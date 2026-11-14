"""Real QR-family symbols whose contents or format can mislead a scanner."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from hackabull import qr_decode, qr_detect


EDGE_CASES = Path(__file__).resolve().parent / "qr_corpus" / "edge_cases"


def decoded_upload(filename):
    payload, image = qr_decode.decode_qr_upload(
        (EDGE_CASES / filename).read_bytes(), filename, "image/png"
    )
    if image is not None:
        image.close()
    return payload


@pytest.mark.parametrize("filename", ["micro.png", "rmqr.png"])
def test_micro_and_rmqr_use_normal_payload_analysis(filename):
    assert decoded_upload(filename) == "SQR123"
    assert qr_detect.detect_payload(decoded_upload(filename))[0] == "Plain text"


def test_kanji_text_keeps_zxing_unicode_transcoding():
    # The source QR's bytes are Shift-JIS, but ZXing's Text content has a
    # correctly transcoded Unicode `.text`. Raw UTF-8 decoding would corrupt it.
    assert decoded_upload("unicode.png") == "日本語と漢字"


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("sjis_bytes.png", b"\x93\xfa\x96\x7b\x8c\xea".decode("utf-8", errors="replace")),
        ("binary.png", b"\x00\xff\xfeABC".decode("utf-8", errors="replace")),
    ],
)
def test_binary_bytes_are_replaced_and_never_called_safe_text(filename, expected, monkeypatch):
    payload = decoded_upload(filename)
    assert payload == expected
    assert qr_detect.detect_payload(payload)[0] == "Unrecognized data"
    monkeypatch.setattr(qr_detect, "classify_qr_with_ml", lambda *_: {"enabled": False})
    monkeypatch.setattr(qr_detect, "blend_ml_score", lambda score, *_: score)
    monkeypatch.setattr(qr_detect, "ml_signal_from_result", lambda *_, **__: None)
    analysis = qr_detect.analyze_qr_payload(payload)
    assert analysis["status"] == "CAUTION"
    assert analysis["verificationStatus"] == "unverified"
    assert any(reason["label"] == "Undecodable QR bytes" for reason in analysis["reasons"])


def test_oversized_blank_and_invalid_symbols_are_not_accepted():
    for result in (
        SimpleNamespace(text=" " * 12, valid=True),
        SimpleNamespace(text="x" * 4097, valid=True),
        SimpleNamespace(text="https://example.com", valid=False),
    ):
        assert qr_decode._barcode_from_result(result) is None


def test_multiple_structured_append_fragments_are_ambiguous():
    with pytest.raises(qr_decode.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
        decoded_upload("structured-all.png")


@pytest.mark.xfail(strict=True, reason="zxing-cpp 3.1.1 Python result has no Structured Append sequence fields")
def test_single_structured_append_fragment_is_refused():
    # Keep this known gap visible. ZXing's WASM result exposes sequence
    # metadata, but the pinned Python binding currently drops it.
    with pytest.raises(qr_decode.QRDecodeAmbiguityError):
        decoded_upload("structured-01.png")
