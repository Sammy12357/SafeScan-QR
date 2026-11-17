"""Breadcrumb markup follows the visible guide navigation and canonical URLs."""

import json
import re

from test_seo_foundation import seo_client  # noqa: F401 - shared isolated app fixture


JSON_LD_SCRIPT = re.compile(
    r'<script\s+type="application/ld\+json"[^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def breadcrumb_lists(html):
    breadcrumbs = []
    for script in JSON_LD_SCRIPT.findall(html):
        document = json.loads(script)
        nodes = document if isinstance(document, list) else [document]
        breadcrumbs.extend(node for node in nodes if node.get("@type") == "BreadcrumbList")
    return breadcrumbs


def test_canonical_guides_have_breadcrumbs_matching_visible_navigation(seo_client):
    guides = {
        "/learn/after-scanning-suspicious-qr": "After a suspicious scan",
        "/learn/parking-meter-qr-scams": "Parking meter QR scams",
        "/learn/scan-qr-code-from-screenshot": "Scan a QR screenshot",
    }
    for path, label in guides.items():
        response = seo_client.get(path + "?ref=breadcrumb-test")
        assert response.status_code == 200
        assert '<a href="/">Home</a>' in response.text
        assert '<a href="/learn">Learn</a>' in response.text
        assert f'<span aria-current="page">{label}</span>' in response.text
        assert breadcrumb_lists(response.text) == [{
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {
                    "@type": "ListItem",
                    "position": 1,
                    "name": "Home",
                    "item": "https://sqafe.com/",
                },
                {
                    "@type": "ListItem",
                    "position": 2,
                    "name": "Learn",
                    "item": "https://sqafe.com/learn",
                },
                {
                    "@type": "ListItem",
                    "position": 3,
                    "name": label,
                    "item": "https://sqafe.com" + path,
                },
            ],
        }]


def test_breadcrumbs_are_limited_to_reviewed_canonical_guides(seo_client):
    for path in ("/", "/learn", "/contact", "/plans", "/login"):
        response = seo_client.get(path)
        assert response.status_code == 200
        assert breadcrumb_lists(response.text) == [], path

    redirect = seo_client.get(
        "https://www.sqafe.com/learn/after-scanning-suspicious-qr",
        follow_redirects=False,
    )
    assert redirect.status_code == 301
    assert breadcrumb_lists(redirect.text) == []

    result = seo_client.post("/search_qr_api", data={"manual_url": "A plain-text QR payload"})
    assert result.status_code == 200
    assert breadcrumb_lists(result.text) == []
