"""Public crawl signals must not expose app pages or break the mobile API."""

import importlib
import sys
from xml.etree import ElementTree

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def seo_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'seo.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://sqafe.com")
    monkeypatch.setenv("MOCK_MODE", "false")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    module = importlib.import_module("hackabull")
    yield TestClient(module.qr_app, base_url="https://sqafe.com")
    for name in list(sys.modules):
        if name in {"hackabull", "db", "storage"} or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def test_robots_and_sitemap_are_canonical_and_parseable(seo_client):
    robots = seo_client.get("/robots.txt")
    assert robots.status_code == 200
    assert robots.headers["content-type"].startswith("text/plain")
    assert "Sitemap: https://sqafe.com/sitemap.xml" in robots.text
    assert "Disallow: /api/" in robots.text
    assert "Disallow: /profile" not in robots.text
    assert "Disallow: /static/" not in robots.text
    assert seo_client.head("/robots.txt").status_code == 200

    sitemap = seo_client.get("/sitemap.xml")
    assert sitemap.status_code == 200
    assert sitemap.headers["content-type"].startswith("application/xml")
    namespace = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    root = ElementTree.fromstring(sitemap.content)
    assert root.tag == "{http://www.sitemaps.org/schemas/sitemap/0.9}urlset"
    locations = [node.text for node in root.findall("s:url/s:loc", namespace)]
    assert locations == ["https://sqafe.com/", "https://sqafe.com/learn", "https://sqafe.com/contact"]
    assert root.findall("s:url/s:lastmod", namespace) == []
    assert all("?" not in location and "onrender.com" not in location for location in locations)
    assert seo_client.head("/sitemap.xml").status_code == 200


def test_public_pages_redirect_to_one_host_and_path_shape(seo_client):
    cases = (
        ("https://safescan-qr.onrender.com/", "https://sqafe.com/"),
        ("https://safescan-qr.onrender.com/learn/?q=qr", "https://sqafe.com/learn?q=qr"),
        ("https://www.sqafe.com/learn", "https://sqafe.com/learn"),
        ("https://sqafe.com/Learn/", "https://sqafe.com/learn"),
        ("https://sqafe.com/contact/", "https://sqafe.com/contact"),
        ("https://safescan-qr.onrender.com/?ref=abc123", "https://sqafe.com/?ref=abc123"),
        ("https://safescan-qr.onrender.com/plans", "https://sqafe.com/plans"),
    )
    for source, expected in cases:
        response = seo_client.get(source, follow_redirects=False)
        assert response.status_code == 301, source
        assert response.headers["location"] == expected
        assert response.headers["X-Frame-Options"] == "DENY"


def test_render_api_and_private_pages_remain_on_requested_host(seo_client):
    for path in ("/api/health", "/health", "/api/app-runtime"):
        response = seo_client.get("https://safescan-qr.onrender.com" + path, follow_redirects=False)
        assert response.status_code == 200, path
        assert "location" not in response.headers

    for path in ("/login", "/test-site", "/legal/data-request"):
        response = seo_client.get("https://safescan-qr.onrender.com" + path, follow_redirects=False)
        assert response.status_code == 200, path
        assert response.headers["X-Robots-Tag"] == "noindex, follow"
        assert "location" not in response.headers


def test_only_reviewed_public_html_is_indexable(seo_client):
    for path in ("/", "/learn", "/contact"):
        response = seo_client.get(path)
        assert response.status_code == 200, path
        assert "noindex" not in response.headers.get("X-Robots-Tag", "")

    for path in (
        "/login", "/profile", "/history", "/leaderboard", "/test-site",
        "/legal/data-request", "/generate-qr", "/malicious-database", "/plans",
        "/risk-engine", "/legal/privacy-policy",
    ):
        response = seo_client.get(path, follow_redirects=False)
        if response.status_code == 200:
            assert response.headers["X-Robots-Tag"] == "noindex, follow", path
    error = seo_client.get("/no-such-seo-page", headers={"Accept": "text/html"})
    assert error.status_code == 404
    assert error.headers["X-Robots-Tag"] == "noindex, follow"
