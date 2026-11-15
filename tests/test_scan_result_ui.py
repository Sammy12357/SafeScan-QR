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


def test_retired_provider_data_does_not_render_or_block_required_checks():
    html, elements = render_result(
        "SAFE", "safe", "URL", "https://example.com/",
        virus_total={
            "mode": "live",
            "summary": {"clean": 1, "unrated": 0, "malicious": 0, "total": 1},
            "statusMessage": "Retired provider data must not be shown.",
        },
    )

    assert elements["continueSafelyButton"][1]["href"] == "https://example.com/"
    assert "VirusTotal" not in html
    assert "Retired provider data" not in html


def test_non_url_payload_is_shown_exactly_and_cannot_be_reported_as_url():
    payload = "WIFI:S:Cafe;<script>alert(1)</script>\nT:WPA;;"
    html, elements = render_result("CAUTION", "suspicious", "Wi-Fi", payload)

    assert "continueSafelyButton" not in elements
    assert "blockReportButton" not in elements
    assert "Reports currently support web URLs only." in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;\nT:WPA;;" in html


def test_internationalized_hostname_shows_both_non_clickable_forms():
    html, elements = render_result(
        "MALICIOUS", "high", "URL", "https://xn--pple-43d.com/login",
        host_forms={"unicode": "аpple.com", "ascii": "xn--pple-43d.com"},
    )

    assert "hostIdentityBox" in elements
    box = html.split('id="hostIdentityBox"', 1)[1].split("</div>", 1)[0]
    assert "аpple.com" in box
    assert "xn--pple-43d.com" in box
    assert "href=" not in box


def test_host_identity_box_only_appears_for_different_url_host_forms():
    _, ascii_elements = render_result(
        "CAUTION", "suspicious", "URL", "https://paypal.com.evil.net/",
        host_forms={"unicode": "paypal.com.evil.net", "ascii": "paypal.com.evil.net"},
    )
    _, private_elements = render_result(
        "CAUTION", "suspicious", "Wi-Fi", "WIFI:S:Cafe;;",
        host_forms={"unicode": "аpple.com", "ascii": "xn--pple-43d.com"},
    )

    assert "hostIdentityBox" not in ascii_elements
    assert "hostIdentityBox" not in private_elements


def test_host_identity_text_is_escaped():
    html, _ = render_result(
        "CAUTION", "suspicious", "URL", "https://example.com/",
        host_forms={"unicode": "<script>alert(1)</script>", "ascii": "xn--example.com"},
    )

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html


def test_manual_entry_accepts_qr_payload_text():
    _, elements = render_result("CAUTION", "suspicious", "Wi-Fi", "WIFI:S:Cafe;;")

    tag, attributes = elements["urlInput"]
    assert tag == "textarea"
    assert attributes["name"] == "manual_url"
