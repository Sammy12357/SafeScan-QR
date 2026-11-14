"""Guard the recorded synthetic QR read rate and multi-code refusal."""

import json
from pathlib import Path

from PIL import Image
import pytest

from hackabull import qr_decode


CORPUS = Path(__file__).parent / "qr_corpus" / "synthetic"
# Pinned zxing-cpp 3.0.0 baseline on the 22 single-code synthetic images.
# The two multi-code scenes are checked separately for refusal.
RECORDED_BASELINE_CORRECT = 17


def _labels():
    labels = json.loads((CORPUS / "labels.json").read_text())
    assert isinstance(labels, dict) and labels, "The synthetic QR corpus must have labels."
    assert all(isinstance(values, list) and values for values in labels.values())
    return labels


def _decoded_payloads(image):
    return {barcode.data.decode("utf-8", errors="replace") for barcode in qr_decode.decode_qr_image(image)}


def test_synthetic_read_rate_does_not_fall_below_recorded_baseline():
    single_code_cases = [(name, values[0]) for name, values in _labels().items() if len(values) == 1]
    assert len(single_code_cases) >= 18, "The baseline corpus should cover the original 18 scenarios."
    correct = 0
    misses = []
    for filename, expected in single_code_cases:
        path = CORPUS / filename
        with Image.open(path) as image:
            actual = _decoded_payloads(image)
        if actual == {expected}:
            correct += 1
        else:
            misses.append(filename)
    assert correct >= RECORDED_BASELINE_CORRECT, (
        f"Decoded {correct}/{len(single_code_cases)} synthetic cases; "
        f"Phase 0 floor is {RECORDED_BASELINE_CORRECT}. Misses: {', '.join(misses)}"
    )


def test_synthetic_multi_code_cases_refuse_ambiguous_uploads():
    multi_code_cases = [name for name, values in _labels().items() if len(values) > 1]
    assert len(multi_code_cases) >= 2, "Include both separated and overlapping QR cases."
    for filename in multi_code_cases:
        path = CORPUS / filename
        with pytest.raises(qr_decode.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
            qr_decode.decode_qr_upload(path.read_bytes(), filename, "image/png")
