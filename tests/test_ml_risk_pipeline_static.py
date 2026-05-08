from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = (ROOT / "hackabull.py").read_text(encoding="utf-8")
REQUIREMENTS = (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_pipeline_uses_local_ml_model_probability():
    assert "def ml_model_prediction" in SERVER
    assert "predict_from_url" in SERVER
    assert "blended_probability_score(signals, ml_prediction)" in SERVER
    assert "confidenceScore\": confidence_score" in SERVER
    assert "signals.append(ml_signal)" not in SERVER


def test_virustotal_removed_from_active_pipeline():
    assert "virustotal_reputation_signal" not in SERVER
    assert "VirusTotal Reputation" not in SERVER
    assert "api.virustotal.com" not in SERVER
    assert "VIRUSTOTAL_API_KEY" not in SERVER


def test_ml_runtime_dependencies_are_declared():
    assert "numpy" in REQUIREMENTS
    assert "h5py" in REQUIREMENTS
    assert "qrcode" in REQUIREMENTS
