"""Saved scan results must not offer an easy route to unsafe hosts."""

from html.parser import HTMLParser
from pathlib import Path

from jinja2 import ChainableUndefined, Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = Environment(
    loader=FileSystemLoader(str(ROOT / "templates")),
    undefined=ChainableUndefined,
    autoescape=select_autoescape(["html"]),
)


class HistoryLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.destinations = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            attributes = dict(attrs)
            href = attributes.get("href", "")
            if "history-url" in attributes.get("class", "").split() and href.startswith(("https://", "http://")):
                self.destinations.append(href)


def render(scans):
    groups = [{"label": "Recent scans", "count": len(scans), "scans": scans}]
    return TEMPLATES.get_template("history.html").render(
        email="user@example.test", scans=scans, scan_groups=groups,
    )


def scan(url, classification, host_forms=None):
    return {
        "url": url,
        "classification": classification,
        "classificationLabel": classification,
        "risk_score": 85 if classification == "MALICIOUS" else 8,
        "created_at": "2026-11-15T12:00:00Z",
        "hostForms": host_forms,
    }


def test_dangerous_or_non_web_history_is_plain_text():
    html = render([
        scan("https://xn--pple-43d.com/login", "MALICIOUS", {"unicode": "аpple.com", "ascii": "xn--pple-43d.com"}),
        scan("https://review.example/", "CAUTION"),
        scan("[Private QR payload hidden]", "SAFE"),
    ])
    links = HistoryLinks()
    links.feed(html)

    assert links.destinations == []
    assert "Unicode host: аpple.com" in html
    assert "ASCII (punycode): xn--pple-43d.com" in html


def test_verified_safe_history_link_keeps_visible_host_identity():
    html = render([
        scan("https://xn--mnchen-3ya.de/", "SAFE", {"unicode": "münchen.de", "ascii": "xn--mnchen-3ya.de"}),
    ])
    links = HistoryLinks()
    links.feed(html)

    assert links.destinations == ["https://xn--mnchen-3ya.de/"]
    assert "münchen.de" in html
    assert "xn--mnchen-3ya.de" in html
