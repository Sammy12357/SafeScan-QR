from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = (ROOT / "hackabull.py").read_text(encoding="utf-8")
REQUIREMENTS = (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_pipeline_uses_local_ml_model_probability():
    assert "import ml_model as _ml_mod" in SERVER
    assert "_ml_mod.predict(image)" in SERVER
    assert "blend_ml_score" in SERVER
    assert '"confidenceScore": final_score' in SERVER
    assert "keras.models.load_model" not in SERVER
    assert "tensorflow" not in SERVER


def test_virustotal_is_optional_and_separate_from_local_ml_runtime():
    assert "VIRUSTOTAL_API_KEY" in SERVER
    assert "virustotal_reputation_signal" in SERVER
    assert "import ml_model as _ml_mod" in SERVER
    assert "tensorflow" not in SERVER


def test_ml_runtime_dependencies_are_declared():
    assert "numpy" in REQUIREMENTS
    assert "h5py" in REQUIREMENTS
    assert "qrcode" in REQUIREMENTS
    assert "tensorflow-cpu" not in REQUIREMENTS
    assert "keras==" not in REQUIREMENTS
