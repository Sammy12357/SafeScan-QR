"""Public metadata, crawler routes, and safe browser error responses."""

import importlib
import re
import sys
from io import BytesIO
from html.parser import HTMLParser
from pathlib import Path
from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SITE = "https://sqafe.com"


@pytest.fixture
def site(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'launch.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("PUBLIC_SITE_ORIGIN", SITE)
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage", "safescan_model_calibration"} or name.startswith(("hackabull.", "safescan_model_calibration.")):
            sys.modules.pop(name, None)
    module = importlib.import_module("hackabull")
    with TestClient(module.qr_app, base_url="https://testserver", raise_server_exceptions=False) as client:
        yield module, client


def test_browser_error_pages_and_api_json_negotiation(site):
    module, client = site
    missing = client.get("/missing-page", headers={"Accept": "text/html"})
    assert missing.status_code == 404
    assert missing.headers["content-type"].startswith("text/html")
    assert "no-store" in missing.headers["cache-control"]
    assert "We can’t find that page" in missing.text
    assert '<meta name="robots" content="noindex, nofollow">' in missing.text
    assert 'property="og:image"' not in missing.text

    json_missing = client.get("/missing-page", headers={"Accept": "application/json"})
    assert json_missing.status_code == 404
    assert json_missing.json() == {"error": "Not found."}
    api_missing = client.get("/api/missing-page", headers={"Accept": "text/html"})
    assert api_missing.status_code == 404
    assert api_missing.headers["content-type"].startswith("application/json")

    @module.qr_app.get("/_test/raise")
    async def raise_error():
        raise RuntimeError("private diagnostic message")

    @module.qr_app.get("/api/_test/raise")
    async def raise_api_error():
        raise RuntimeError("private diagnostic message")

    broken = client.get("/_test/raise", headers={"Accept": "text/html"})
    assert broken.status_code == 500
    assert broken.headers["content-type"].startswith("text/html")
    assert "We couldn’t complete that request" in broken.text
    assert "private diagnostic message" not in broken.text
    assert '<meta name="robots" content="noindex, nofollow">' in broken.text
    assert 'property="og:image"' not in broken.text
    api_broken = client.get("/api/_test/raise", headers={"Accept": "text/html"})
    assert api_broken.status_code == 500
    assert api_broken.json() == {"error": "Something went wrong on our end."}


def test_public_heads_canonical_aliases_and_assets(site):
    _, client = site
    pages = [
        "/", "/generate-qr", "/learn", "/plans", "/go-ghost", "/token",
        "/leaderboard", "/malicious-database", "/legal/privacy-policy",
        "/legal/cookie-policy", "/login", "/test-site",
    ]
    for path in pages:
        response = client.get(path, headers={"Accept": "text/html"})
        assert response.status_code == 200, (path, response.status_code, response.text[:160])
        html = response.text
        canonical_path = "/" if path == "/test-site" else path
        assert len(re.findall(r"<title>.*?</title>", html)) == 1, path
        assert len(re.findall(r'<meta name="description" ', html)) == 1, path
        assert f'<link rel="canonical" href="{SITE}{canonical_path}">' in html, path
        if path == "/login":
            assert 'property="og:image"' not in html, path
            assert 'name="twitter:image"' not in html, path
            assert 'name="robots" content="noindex, nofollow"' in html, path
        else:
            assert f'<meta property="og:url" content="{SITE}{canonical_path}">' in html, path
            assert f'<meta property="og:image" content="{SITE}/static/safescan-social-card.png">' in html, path
            assert '<meta property="og:image:width" content="1200">' in html, path
            assert '<meta property="og:image:height" content="630">' in html, path
            assert '<meta name="twitter:card" content="summary_large_image">' in html, path
            assert f'<meta name="twitter:image" content="{SITE}/static/safescan-social-card.png">' in html, path
        assert 'href="/static/safescan-logo.svg?v=rose-theme-v1"' in html, path
        assert ('name="robots" content="noindex, nofollow"' in html) == (path == "/login"), path
    favicon = client.get("/static/safescan-logo.svg")
    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/svg+xml")
    card = client.get("/static/safescan-social-card.png")
    assert card.status_code == 200
    assert card.headers["content-type"].startswith("image/png")
    with Image.open(BytesIO(card.content)) as image:
        assert image.format == "PNG"
        assert image.size == (1200, 630)


def test_robots_and_sitemap_list_only_live_public_pages(site):
    module, client = site
    robots = client.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.headers["content-type"].startswith("text/plain")
    assert f"Sitemap: {SITE}/sitemap.xml" in robots.text
    assert "Disallow: /api/" in robots.text
    assert "Disallow: /history" in robots.text

    sitemap = client.get("/sitemap.xml")
    assert sitemap.status_code == 200
    assert sitemap.headers["content-type"].startswith("application/xml")
    namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    locations = [node.text for node in ElementTree.fromstring(sitemap.content).findall("s:url/s:loc", namespace)]
    assert locations == [SITE + path for path in module.PUBLIC_SITEMAP_PATHS]
    assert all(not path.startswith((SITE + "/api/", SITE + "/history", SITE + "/profile")) for path in locations)
    for path in module.PUBLIC_SITEMAP_PATHS:
        response = client.get(path)
        assert response.status_code == 200, (path, response.status_code)


class _ImageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.images = []

    def handle_starttag(self, tag, attrs):
        if tag == "img":
            self.images.append(dict(attrs))


def test_all_server_templates_share_head_and_images_have_alt():
    for path in (ROOT / "templates").glob("*.html"):
        content = path.read_text()
        if "<html" in content or "<head" in content:
            assert content.count('{% include "_site_head.html" %}') == 1, path.name
        parser = _ImageParser()
        parser.feed(content)
        assert all("alt" in attrs for attrs in parser.images), path.name


def test_consent_text_matches_count_only_scanner_behavior(site):
    _, client = site
    home = client.get("/")
    privacy = client.get("/legal/privacy-policy")
    cookie = client.get("/legal/cookie-policy")
    assert all(response.status_code == 200 for response in (home, privacy, cookie))
    assert "scanner performance counts" in home.text
    assert "your choice is still recorded" in home.text
    assert "account cookies, or device identifiers" in privacy.text
    assert "safeScanConsent and safeScanConsentId" in cookie.text
    assert "Browser local storage" in cookie.text
