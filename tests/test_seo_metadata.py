"""Reviewed landing pages have one coherent search and share identity."""

from html.parser import HTMLParser
from pathlib import Path

from PIL import Image

from test_seo_foundation import seo_client  # noqa: F401 - shared isolated app fixture


class HeadIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_head = False
        self.in_title = False
        self.titles = []
        self.metas = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self.in_head = True
        if not self.in_head:
            return
        if tag == "title":
            self.in_title = True
            self.titles.append("")
        elif tag == "meta":
            self.metas.append(dict(attrs))
        elif tag == "link":
            self.links.append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "head":
            self.in_head = False

    def handle_data(self, data):
        if self.in_head and self.in_title:
            self.titles[-1] += data

    def values(self, attr, key):
        return [item.get("content") for item in self.metas if item.get(attr) == key]

    def links_by_rel(self, rel):
        return [item.get("href") for item in self.links if item.get("rel") == rel]


def parse_head(html):
    result = HeadIndex()
    result.feed(html)
    return result


def test_reviewed_pages_have_unique_canonical_and_share_metadata(seo_client):
    expected = {
        "/": (
            "Check a QR Code Before Opening It | Sqafe",
            "Scan a QR code or paste its contents to review the destination and available risk signals before deciding whether to open it.",
        ),
        "/learn": (
            "QR Code Safety and Quishing Guide | Sqafe",
            "Learn how QR phishing works, what a QR code can contain, and how to inspect links, payment requests, and wallet prompts before opening them.",
        ),
        "/contact": (
            "Contact Sqafe | Support and Security Reports",
            "Find Sqafe contact options for account help, privacy questions, partnerships, and reporting a security concern.",
        ),
    }
    for path, (title, description) in expected.items():
        response = seo_client.get(path + "?ref=seo-test")
        assert response.status_code == 200, path
        head = parse_head(response.text)
        canonical = "https://sqafe.com" + path
        assert head.titles == [title], path
        assert head.values("name", "description") == [description], path
        assert head.values("name", "robots") == ["index, follow"], path
        assert head.links_by_rel("canonical") == [canonical], path
        assert head.values("property", "og:type") == ["website"], path
        assert head.values("property", "og:site_name") == ["Sqafe"], path
        assert head.values("property", "og:title") == [title], path
        assert head.values("property", "og:description") == [description], path
        assert head.values("property", "og:url") == [canonical], path
        assert head.values("property", "og:image") == ["https://sqafe.com/static/og-sqafe.png"], path
        assert head.values("name", "twitter:card") == ["summary_large_image"], path
        assert head.values("name", "twitter:title") == [title], path
        assert head.values("name", "twitter:description") == [description], path
        assert head.values("name", "twitter:image") == ["https://sqafe.com/static/og-sqafe.png"], path
        if path == "/learn":
            assert response.text.count("<h1>QR code safety center</h1>") == 1
    assert len({title for title, _ in expected.values()}) == len(expected)
    assert len({description for _, description in expected.values()}) == len(expected)


def test_withheld_and_private_pages_are_noindex_without_share_metadata(seo_client):
    for path in (
        "/test-site", "/plans", "/generate-qr", "/malicious-database",
        "/risk-engine", "/legal/privacy-policy", "/legal/data-request", "/login",
    ):
        response = seo_client.get(path)
        assert response.status_code == 200, path
        head = parse_head(response.text)
        assert head.values("name", "robots") == ["noindex, follow"], path
        assert head.links_by_rel("canonical") == [], path
        assert head.values("property", "og:url") == [], path
        assert response.headers["X-Robots-Tag"] == "noindex, follow", path


def test_og_image_is_served_at_declared_size(seo_client):
    response = seo_client.get("/static/og-sqafe.png")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    image = Image.open(Path("static/og-sqafe.png"))
    assert image.size == (1200, 630)


def test_scan_result_post_does_not_publish_share_metadata(seo_client):
    response = seo_client.post("/search_qr_api", data={"manual_url": "A plain-text QR payload"})
    assert response.status_code == 200
    head = parse_head(response.text)
    assert head.values("name", "robots") == ["noindex, follow"]
    assert head.links_by_rel("canonical") == []
    assert head.values("property", "og:url") == []
    assert response.headers["X-Robots-Tag"] == "noindex, follow"


def test_every_page_template_has_a_noindex_fallback():
    for path in Path("templates").rglob("*.html"):
        source = path.read_text()
        if "<head>" not in source:
            continue
        assert "{% include '_seo_head.html' %}" in source or '<meta name="robots" content="noindex">' in source, path
