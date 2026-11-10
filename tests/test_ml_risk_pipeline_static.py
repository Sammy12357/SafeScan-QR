from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
# The backend was split from a single hackabull.py into a hackabull/ package;
# scan every module so these source assertions are location-independent.
SERVER = "\n".join(
    p.read_text(encoding="utf-8") for p in sorted((ROOT / "hackabull").glob("*.py"))
)
INDEX = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
REQUIREMENTS = (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_pipeline_uses_local_ml_model_probability():
    assert "import ml_model_final as _ml_mod" in SERVER
    assert "_ml_mod.predict_url(payload)" in SERVER
    assert "_ml_mod.predict_image(generated_image)" in SERVER
    assert "blend_ml_score" in SERVER
    assert '"confidenceScore": final_score' in SERVER


def test_retired_virustotal_provider_has_no_live_lookup_code():
    assert "VIRUSTOTAL_API_KEY" not in SERVER
    assert "virustotal_lookup_result" not in SERVER
    assert "www.virustotal.com/api" not in SERVER
    assert "import ml_model_final as _ml_mod" in SERVER


def test_ml_runtime_dependencies_are_declared():
    assert "numpy" in REQUIREMENTS
    assert "tensorflow" in REQUIREMENTS
    assert "keras" in REQUIREMENTS
    assert "qrcode" in REQUIREMENTS


def test_result_template_keeps_core_analysis_panels():
    assert "ML model analysis" in INDEX
    assert "Optional VirusTotal enrichment" not in INDEX
    assert "View on VirusTotal" not in INDEX
    assert "Unverified checks:" in INDEX
    assert "Exact decoded QR payload" in INDEX
    assert "Domain age" in INDEX
    assert "ml-probability-bars" in INDEX
