from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = (ROOT / "hackabull.py").read_text(encoding="utf-8")
INDEX = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
REQUIREMENTS = (ROOT / "requirements.txt").read_text(encoding="utf-8")


def test_pipeline_uses_local_ml_model_probability():
    assert "import ml_model_final as _ml_mod" in SERVER
    assert "_ml_mod.predict(image)" in SERVER
    assert "blend_ml_score" in SERVER
    assert '"confidenceScore": final_score' in SERVER


def test_virustotal_is_optional_and_separate_from_local_ml_runtime():
    assert "VIRUSTOTAL_API_KEY" in SERVER
    assert "virustotal_reputation_signal" in SERVER
    assert "import ml_model_final as _ml_mod" in SERVER


def test_ml_runtime_dependencies_are_declared():
    assert "numpy" in REQUIREMENTS
    assert "tensorflow" in REQUIREMENTS
    assert "keras" in REQUIREMENTS
    assert "qrcode" in REQUIREMENTS


def test_embedded_urls_use_full_pipeline():
    assert "async def analyze_embedded_url_payload" in SERVER
    assert "await analyze_full_pipeline(embedded_url, qr_image)" in SERVER
    assert "embedded_urls = extract_urls(normalized_payload)" in SERVER
    assert "await analyze_embedded_url_payload(url_qr, embedded_urls[0], qr_image_for_ml)" in SERVER
    assert "virusTotal" in SERVER
    assert "domainAge" in SERVER
    assert "mlRisk" in SERVER


def test_result_template_restores_analysis_panels():
    assert "ML model analysis" in INDEX
    assert "VirusTotal vendor scan" in INDEX
    assert "Domain age" in INDEX
    assert "ml-probability-bars" in INDEX
