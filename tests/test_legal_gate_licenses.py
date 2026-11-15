"""License and no-biometric-processing release safeguards."""

import ast
import importlib.util
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/check_runtime_licenses.py"


def _checker():
    spec = importlib.util.spec_from_file_location("check_runtime_licenses", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_locked_runtime_licenses_are_reviewed():
    checker = _checker()
    register = json.loads((ROOT / "docs/legal/runtime-dependency-licenses.json").read_text())
    assert checker.check_runtime_licenses((ROOT / "requirements.lock").read_text(), register) == []


def test_license_gate_rejects_unknown_and_strong_copyleft():
    checker = _checker()
    sample = {"packages": {"sample": {"version": "1.0", "license": "UNKNOWN", "evidence": "https://example.org"}}}
    assert "license is unknown" in "\n".join(checker.check_runtime_licenses("sample==1.0", sample))
    sample["packages"]["sample"]["license"] = "AGPL-3.0-only"
    assert "strong copyleft" in "\n".join(checker.check_runtime_licenses("sample==1.0", sample))
    sample["packages"]["sample"]["license"] = "MIT"
    assert "no reviewed license entry" in "\n".join(checker.check_runtime_licenses("sample==1.0\nnew-package==2.0", sample))
    assert "Unreviewed requirement syntax" in "\n".join(checker.check_runtime_licenses("sample==1.0\nnew-package @ https://example.org/pkg.whl", sample))


def test_every_runtime_dependency_has_retained_license_text():
    register = json.loads((ROOT / "docs/legal/runtime-dependency-licenses.json").read_text())
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    for name, item in register["packages"].items():
        assert f"| {name} {item['version']} |" in notices
        if name == "pypdfium2":
            folder = ROOT / "third_party_licenses/pypdfium2-5.15.2-linux-x86_64"
        else:
            folder = ROOT / "third_party_licenses/runtime" / f"{name}-{item['version']}"
        assert any(path.is_file() and path.stat().st_size for path in folder.rglob("*")), name
    for target in re.findall(r"\]\(([^)]+)\)", notices):
        if not target.startswith("https://"):
            assert (ROOT / target).exists(), target


def test_no_face_voice_or_fingerprint_analysis_code_is_added():
    banned_import_roots = {"face_recognition", "mediapipe", "deepface", "insightface", "dlib", "speech_recognition"}
    banned_call = re.compile(r"\b(?:CascadeClassifier|FaceDetector|FaceLandmarker|FaceRecognizer|detectMultiScale|fingerprint_recognition)\s*\(")
    for directory in (ROOT / "hackabull", ROOT / "static", ROOT / "scripts"):
        for path in directory.rglob("*"):
            if path.suffix not in {".py", ".js"}:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            assert not banned_call.search(source), path
            if path.suffix == ".py":
                tree = ast.parse(source, filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        assert all(alias.name.split(".")[0] not in banned_import_roots for alias in node.names), path
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        assert node.module.split(".")[0] not in banned_import_roots, path
            else:
                assert not re.search(r"\b(?:from|import|require)\s*\(?\s*['\"](?:face-api|@mediapipe/|deepface)", source), path
    for path in ROOT.glob("*.py"):
        source = path.read_text(encoding="utf-8", errors="replace")
        assert not banned_call.search(source), path


def test_unlicensed_brand_assets_are_absent():
    home = (ROOT / "templates/index.html").read_text()
    model = (ROOT / "static/safescan-3d.js").read_text()
    assert "Powered By</span><svg" not in home
    assert "Solana Mobile 3D scan model" not in home
    assert "SEED VAULT" not in model
    assert "createSolanaBackTexture" not in model
    assert not (ROOT / "static/safescan-3d-fallback.png").exists()
