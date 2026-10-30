"""Check that the rendered scan result offers actions appropriate to its verdict."""

from html.parser import HTMLParser
from pathlib import Path

from jinja2 import ChainableUndefined, Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = Environment(
    loader=FileSystemLoader(str(ROOT / "templates")),
    undefined=ChainableUndefined,
    autoescape=select_autoescape(["html"]),
)


class ElementIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.by_id = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.by_id[attributes["id"]] = (tag, attributes)


def render_result(status, overall_risk, payload_type, url, **overrides):
    context = {
        "results_visible": True,
        "status": status,
        "overall_risk": overall_risk,
        "payload_type": payload_type,
        "url_found": url,
        "raw_payload": url,
        "score": "40",
        "threat_class": "Test result",
        "risk_reasons": [],
        "verification_status": "complete",
        "unverified_checks": [],
    }
    context.update(overrides)
    html = TEMPLATES.get_template("index.html").render(**context)
    elements = ElementIndex()
    elements.feed(html)
    return html, elements.by_id


def test_dangerous_verdict_has_no_open_action():
    html, elements = render_result("MALICIOUS", "high", "URL", "https://danger.example/")

    assert "continueSafelyButton" not in elements
    assert "blockReportButton" in elements
    assert "Do not open this destination" in html


def test_caution_requires_confirmation_before_link_gets_href():
    html, elements = render_result("CAUTION", "suspicious", "URL", "https://review.example/")

    _, action = elements["continueSafelyButton"]
    assert "cautionOpenConsent" in elements
    assert "href" not in action
    assert action["aria-disabled"] == "true"
    assert action["data-destination"] == "https://review.example/"
    assert "Open link anyway" in html


def test_safe_link_requires_complete_verification():
    _, complete = render_result("SAFE", "safe", "URL", "https://example.com/")
    _, incomplete = render_result(
        "SAFE", "safe", "URL", "https://example.com/",
        verification_status="incomplete", unverified_checks=["Google Safe Browsing"],
    )

    assert complete["continueSafelyButton"][1]["href"] == "https://example.com/"
    assert "continueSafelyButton" not in incomplete


def test_optional_virustotal_outage_is_labeled_without_blocking_required_checks():
    html, elements = render_result(
        "SAFE", "safe", "URL", "https://example.com/",
        virus_total={
            "mode": "unavailable",
            "summary": {"clean": 0, "unrated": 0, "malicious": 0, "total": 0},
            "statusMessage": "VirusTotal is not enabled.",
        },
    )

    assert elements["continueSafelyButton"][1]["href"] == "https://example.com/"
    assert "Optional VirusTotal enrichment" in html
    assert "Required URL checks use Google reputation" in html
    assert "VirusTotal vendor scan" not in html


def test_non_url_payload_is_shown_exactly_and_cannot_be_reported_as_url():
    payload = "WIFI:S:Cafe;<script>alert(1)</script>\nT:WPA;;"
    html, elements = render_result("CAUTION", "suspicious", "Wi-Fi", payload)

    assert "continueSafelyButton" not in elements
    assert "blockReportButton" not in elements
    assert "Reports currently support web URLs only." in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;\nT:WPA;;" in html


def test_manual_entry_accepts_qr_payload_text():
    _, elements = render_result("CAUTION", "suspicious", "Wi-Fi", "WIFI:S:Cafe;;")

    tag, attributes = elements["urlInput"]
    assert tag == "textarea"
    assert attributes["name"] == "manual_url"
