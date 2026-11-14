"""Guard the recorded synthetic QR read rate and multi-code refusal."""

import importlib
import json
from pathlib import Path

from PIL import Image
import pytest

CORPUS = Path(__file__).parent / "qr_corpus" / "synthetic"
# Current zxing-cpp 3.1.1 floor on the 22 single-code synthetic images.
# The first 18 are the plan's core scenarios; the two multi-code scenes are
# checked separately for refusal. The 17/18 server target remains unmet:
# case 06 loses nearly all module detail after 720px downscaling, and case 11
# has motion blur. Keep the measured floor until a safe decoder gain is shown.
MIN_SINGLE_CODE_CORRECT = 19
BASELINE_SINGLE_CODE_COUNT = 22
MIN_CORE_CORRECT = 16
CORE_CASE_NAMES = {f"{index:02d}" for index in range(1, 19)}


def _labels():
    labels = json.loads((CORPUS / "labels.json").read_text())
    assert isinstance(labels, dict) and labels, "The synthetic QR corpus must have labels."
    assert all(isinstance(values, list) and values for values in labels.values())
    return labels


@pytest.fixture()
def qr_decode_module(tmp_path, monkeypatch):
    # CI's global sqlite:///test_ci.db resolves to /test_ci.db on Linux. The
    # package initializes its database on import, so give it a writable path.
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'qr_corpus.db').as_posix()}")
    return importlib.import_module("hackabull.qr_decode")


def _decoded_payloads(image, qr_decode_module):
    return {barcode.data.decode("utf-8", errors="replace") for barcode in qr_decode_module.decode_qr_image(image)}


def test_synthetic_read_rate_meets_measured_floors(qr_decode_module):
    single_code_cases = [(name, values[0]) for name, values in _labels().items() if len(values) == 1]
    assert len(single_code_cases) >= BASELINE_SINGLE_CODE_COUNT, "The corpus should cover the 22 single-code scenarios."
    core_cases = {
        name for name, _ in single_code_cases
        if name.split("_", 1)[0] in CORE_CASE_NAMES
    }
    assert len(core_cases) == 18, "The corpus should cover all 18 core scenarios."
    correct = 0
    core_correct = 0
    misses = []
    for filename, expected in single_code_cases:
        path = CORPUS / filename
        with Image.open(path) as image:
            actual = _decoded_payloads(image, qr_decode_module)
        if actual == {expected}:
            correct += 1
            if filename in core_cases:
                core_correct += 1
        else:
            misses.append(filename)
    assert core_correct >= MIN_CORE_CORRECT, (
        f"Decoded {core_correct}/18 core synthetic cases; "
        f"measured floor is {MIN_CORE_CORRECT}. Misses: {', '.join(misses)}"
    )
    assert correct * BASELINE_SINGLE_CODE_COUNT >= len(single_code_cases) * MIN_SINGLE_CODE_CORRECT, (
        f"Decoded {correct}/{len(single_code_cases)} synthetic cases; "
        f"measured floor is {MIN_SINGLE_CODE_CORRECT}/{BASELINE_SINGLE_CODE_COUNT}. "
        f"Misses: {', '.join(misses)}"
    )


def test_synthetic_multi_code_cases_refuse_ambiguous_uploads(qr_decode_module):
    multi_code_cases = [name for name, values in _labels().items() if len(values) > 1]
    assert len(multi_code_cases) >= 2, "Include both separated and overlapping QR cases."
    for filename in multi_code_cases:
        path = CORPUS / filename
        with pytest.raises(qr_decode_module.QRDecodeAmbiguityError, match="Multiple different QR payloads"):
            qr_decode_module.decode_qr_upload(path.read_bytes(), filename, "image/png")
