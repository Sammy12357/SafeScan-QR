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


class SourceIndex(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.source_refs = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        if tag == "a" and attrs.get("href", "").startswith("#source-"):
            self.source_refs.add(attrs["href"][1:])


def parse_head(html):
    result = HeadIndex()
    result.feed(html)
    return result


def test_reviewed_pages_have_unique_canonical_and_share_metadata(seo_client):
    expected = {
        "/": (
            "Check a QR Code Before Opening It | Sqafe",
            "Sqafe helps you inspect a QR code's decoded content and available risk signals before deciding whether to open a destination.",
        ),
        "/about": (
            "About Sqafe | QR Code Inspection",
            "Learn what Sqafe and its SafeScan QR scanner do, how a scan result works, and where to find the project and contact details.",
        ),
        "/learn": (
            "QR Code Safety and Quishing Guide | Sqafe",
            "Learn how QR phishing works, what a QR code can contain, and how to inspect links, payment requests, and wallet prompts before opening them.",
        ),
        "/learn/after-scanning-suspicious-qr": (
            "Scanned a Suspicious QR Code? What to Do Next | Sqafe",
            "A practical response guide for a suspicious QR scan: what to do if you only opened a page, entered account or payment details, or installed an app.",
        ),
        "/learn/parking-meter-qr-scams": (
            "Parking Meter QR Scams: Check the Code Before You Pay | Sqafe",
            "Learn how fake QR stickers on parking meters redirect drivers, how to verify the official payment method, and what to do if you entered card details.",
        ),
        "/learn/scan-qr-code-from-screenshot": (
            "How to Scan a QR Code From a Screenshot | Sqafe",
            "Learn how to scan a QR code from a screenshot or saved photo on the same phone, read its link before opening it, and understand incomplete scan results.",
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


def test_home_and_about_explain_the_brand_and_scanner_relationship(seo_client):
    home = seo_client.get("/").text
    about = seo_client.get("/about").text
    assert "<h1>Sqafe</h1>" in home
    assert "Sqafe is a QR code inspection site." in home
    assert 'aria-label="Sqafe home"' in home
    assert '<span class="footer-brand-name">Sqafe</span>' in home
    assert 'href="/about"' in home
    assert about.count("<h1>") == 1
    assert "<h1>About Sqafe</h1>" in about
    assert "SafeScan QR is the scanner used here." in about
    assert 'href="/#scanner"' in about
    assert 'href="/learn"' in about
    assert 'href="/contact"' in about


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


def test_guides_have_practical_content_sources_and_hub_links(seo_client):
    hub = seo_client.get("/learn").text
    for path in (
        "/learn/after-scanning-suspicious-qr",
        "/learn/parking-meter-qr-scams",
        "/learn/scan-qr-code-from-screenshot",
    ):
        assert f'href="{path}"' in hub
        response = seo_client.get(path)
        assert response.status_code == 200
        assert response.text.count("<h1>") == 1
        assert 'href="https://www.ic3.gov/PSA/2022/PSA220118"' in response.text
        assert 'href="https://consumer.ftc.gov/' in response.text
        assert 'href="/#scanner"' in response.text
        assert "cannot" in response.text.lower()
        sources = SourceIndex()
        sources.feed(response.text)
        assert sources.source_refs
        assert sources.source_refs <= sources.ids
    after = seo_client.get("/learn/after-scanning-suspicious-qr").text
    assert "You entered a password or verification code" in after
    assert "You entered card or bank details" in after
    assert "You sent cryptocurrency" in after
    assert "You installed an app or gave device access" in after
    parking = seo_client.get("/learn/parking-meter-qr-scams").text
    assert "Find the operator without using the QR link" in parking
    assert "Read the destination before opening it" in parking
    screenshot = seo_client.get("/learn/scan-qr-code-from-screenshot").text
    home = seo_client.get("/").text
    assert "How to scan a QR code from a screenshot without opening its link" in screenshot
    assert "QR scan could not finish" in screenshot
    assert "Could not fully check" in screenshot
    assert "By Sqafe" in screenshot
    assert "Upload QR file/photo" in screenshot
    assert 'href="/learn/scan-qr-code-from-screenshot"' in home
