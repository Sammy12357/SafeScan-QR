"""Real QR-family symbols whose contents or format can mislead a scanner."""

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest

EDGE_CASES = Path(__file__).resolve().parent / "qr_corpus" / "edge_cases"


@pytest.fixture()
def qr_modules(tmp_path, monkeypatch):
    # The package creates SQLite on import. CI's default relative URL can
    # resolve to an unwritable root path before any test fixtures run.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'qr_edges.db').as_posix()}")
    # These corpus tests check decode correctness, not the production timeout.
    # Hosted runners can spend several seconds starting a fresh Python worker;
    # deadline behavior is tested separately in test_qr_decode_tiers.py.
    monkeypatch.setenv("QR_DECODE_BUDGET_S", "5.0")
    return importlib.import_module("hackabull.qr_decode"), importlib.import_module("hackabull.qr_detect")


def decoded_upload(filename, qr_decode):
    payload, image = qr_decode.decode_qr_upload(
        (EDGE_CASES / filename).read_bytes(), filename, "image/png"
    )
    if image is not None:
        image.close()
    return payload


@pytest.mark.parametrize("filename", ["micro.png", "rmqr.png"])
def test_micro_and_rmqr_use_normal_payload_analysis(filename, qr_modules):
    qr_decode, qr_detect = qr_modules
    assert decoded_upload(filename, qr_decode) == "SQR123"
    assert qr_detect.detect_payload(decoded_upload(filename, qr_decode))[0] == "Plain text"


def test_kanji_text_keeps_zxing_unicode_transcoding(qr_modules):
    # The source QR's bytes are Shift-JIS, but ZXing's Text content has a
    # correctly transcoded Unicode `.text`. Raw UTF-8 decoding would corrupt it.
    qr_decode, _ = qr_modules
    assert decoded_upload("unicode.png", qr_decode) == "日本語と漢字"


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("sjis_bytes.png", b"\x93\xfa\x96\x7b\x8c\xea".decode("utf-8", errors="replace")),
        ("binary.png", b"\x00\xff\xfeABC".decode("utf-8", errors="replace")),
    ],
)
def test_binary_bytes_are_replaced_and_never_called_safe_text(filename, expected, monkeypatch, qr_modules):
    qr_decode, qr_detect = qr_modules
    payload = decoded_upload(filename, qr_decode)
    assert payload == expected
    assert qr_detect.detect_payload(payload)[0] == "Unrecognized data"
    monkeypatch.setattr(qr_detect, "classify_qr_with_ml", lambda *_: {"enabled": False})
    monkeypatch.setattr(qr_detect, "blend_ml_score", lambda score, *_: score)
    monkeypatch.setattr(qr_detect, "ml_signal_from_result", lambda *_, **__: None)
    analysis = qr_detect.analyze_qr_payload(payload)
    assert analysis["status"] == "CAUTION"
    assert analysis["verificationStatus"] == "unverified"
    assert any(reason["label"] == "Undecodable QR bytes" for reason in analysis["reasons"])


def test_oversized_blank_and_invalid_symbols_are_not_accepted(qr_modules):
    qr_decode, _ = qr_modules
    for result in (
        SimpleNamespace(text=" " * 12, valid=True),
        SimpleNamespace(text="x" * 4097, valid=True),
        SimpleNamespace(text="https://example.com", valid=False),
    ):
        assert qr_decode._barcode_from_result(result) is None


def test_multiple_structured_append_fragments_are_ambiguous(qr_modules, monkeypatch):
    qr_decode, _ = qr_modules
    # This checks detection semantics rather than process-startup scheduling.
    # The killable worker's timeout is covered separately in tier tests.
    monkeypatch.setenv("QR_DECODE_BUDGET_S", "3.0")
    with pytest.raises(qr_decode.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
        qr_decode._decode_qr_upload_inprocess(
            (EDGE_CASES / "structured-all.png").read_bytes(), "structured-all.png", "image/png"
        )


@pytest.mark.xfail(strict=True, reason="zxing-cpp 3.1.1 Python result has no Structured Append sequence fields")
def test_single_structured_append_fragment_is_refused(qr_modules):
    qr_decode, _ = qr_modules
    # Keep this known gap visible. ZXing's WASM result exposes sequence
    # metadata, but the pinned Python binding currently drops it.
    with pytest.raises(qr_decode.QRDecodeAmbiguityError):
        decoded_upload("structured-01.png", qr_decode)
