"""Public risk labels must reflect check coverage, including legacy results."""

import re
from pathlib import Path

import pytest
from jinja2 import ChainableUndefined, Environment, FileSystemLoader, select_autoescape


TEMPLATES = Environment(
    loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
    undefined=ChainableUndefined,
    autoescape=select_autoescape(["html"]),
)


@pytest.mark.parametrize(
    ("status", "risk", "coverage", "expected", "card_class"),
    [
        ("SAFE", "safe", "complete", "No threats found in checks", "risk-modal-safe"),
        ("SAFE", "safe", "incomplete", "Could not fully check", "risk-modal-caution"),
        ("SAFE", "safe", None, "Could not fully check", "risk-modal-caution"),
        ("SAFE", "safe", "not_applicable", "Content decoded", "risk-modal-caution"),
        ("CAUTION", "suspicious", "complete", "Needs review", "risk-modal-caution"),
        ("CAUTION", "suspicious", "incomplete", "Could not fully check", "risk-modal-caution"),
        ("MALICIOUS", "high", "incomplete", "High-risk indicators", "risk-modal-dangerous"),
    ],
)
def test_result_label_and_visual_state_follow_coverage(status, risk, coverage, expected, card_class):
    html = TEMPLATES.get_template("index.html").render(
        results_visible=True,
        status=status,
        overall_risk=risk,
        verification_status=coverage,
        score="8",
        url_found="https://example.org/",
        payload_type="URL",
    )

    assert f'<h2 id="riskVerdictTitle">{expected}</h2>' in html
    assert re.search(rf'<div class="risk-modal-card {card_class}">', html)
    assert '<div class="screen-verdict">SAFE</div>' not in html
    assert '<h2 id="riskVerdictTitle">SAFE</h2>' not in html
    if coverage != "complete":
        assert 'class="risk-modal-card risk-modal-safe"' not in html


def test_history_uses_bounded_legacy_labels():
    from hackabull.fraud import SCAN_CLASSIFICATION_LABELS

    assert SCAN_CLASSIFICATION_LABELS["SAFE"] == "Lower risk score at scan time"
    assert SCAN_CLASSIFICATION_LABELS["MALICIOUS"] == "High-risk indicators"
