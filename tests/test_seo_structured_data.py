"""The homepage's structured data reflects only verified public facts."""

import json
from html.parser import HTMLParser

from test_seo_foundation import seo_client  # noqa: F401 - shared isolated app fixture


class JsonLdParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_json_ld = False
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script" and dict(attrs).get("type") == "application/ld+json":
            self.in_json_ld = True
            self.scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_json_ld = False

    def handle_data(self, data):
        if self.in_json_ld:
            self.scripts[-1] += data


def structured_data(response):
    parser = JsonLdParser()
    parser.feed(response.text)
    return [json.loads(script) for script in parser.scripts]


def test_homepage_identifies_sqafe_without_unverified_claims(seo_client):
    response = seo_client.get("/")
    assert response.status_code == 200
    documents = structured_data(response)
    assert len(documents) == 1
    document = documents[0]
    assert document["@context"] == "https://schema.org"
    nodes = {node["@type"]: node for node in document["@graph"]}
    assert set(nodes) == {"WebSite", "Organization"}
    website = nodes["WebSite"]
    organization = nodes["Organization"]
    assert website["url"] == "https://sqafe.com/"
    assert website["name"] == "Sqafe"
    assert "alternateName" not in website
    assert website["publisher"] == {"@id": organization["@id"]}
    assert organization["url"] == "https://sqafe.com/"
    assert organization["name"] == "Sqafe"
    assert organization["description"] == "Sqafe publishes a QR code scanner and QR safety guidance."
    assert organization["logo"] == "https://sqafe.com/static/safescan-logo.svg"
    assert not ({"legalName", "address", "telephone", "sameAs", "aggregateRating", "review"} & set(organization))


def test_no_schema_is_published_on_non_home_or_private_pages(seo_client):
    for path in ("/about", "/learn", "/contact", "/plans", "/login"):
        assert structured_data(seo_client.get(path)) == [], path

    post_response = seo_client.post("/search_qr_api", data={"manual_url": "A plain-text QR payload"})
    assert structured_data(post_response) == []
