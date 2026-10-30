"""Regression tests for verdict precedence and incomplete check coverage."""

import asyncio
import importlib
import sys

import pytest
import requests


@pytest.fixture()
def modules(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'verdict.db').as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    pipeline = importlib.import_module("hackabull.pipeline")
    reputation = importlib.import_module("hackabull.reputation")
    scoring = importlib.import_module("hackabull.scoring")
    redirects = importlib.import_module("hackabull.redirects")
    security = importlib.import_module("hackabull.security")
    monkeypatch.setattr(security, "is_private_hostname", lambda _: False)
    yield pipeline, reputation, scoring, redirects
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def _finding(pipeline, check, severity="low", passed=True, verified=True):
    result = pipeline.signal(check, "test result", severity, "test detail", passed)
    result["verified"] = verified
    return result


def _redirect(pipeline, url, verified=True):
    finding = _finding(pipeline, "Redirect Chain", verified=verified)
    return {"signal": finding, "redirectChain": [{"url": url, "domain": "example.org", "statusCode": 200, "domainChanged": False}]}


def _vt(url, malicious=0, mode="live"):
    return {
        "url": url,
        "mode": mode,
        "summary": {"clean": 1 if mode == "live" and not malicious else 0,
                    "unrated": 0, "malicious": malicious,
                    "total": max(1, malicious) if mode == "live" else 0},
        "engines": [],
        "groups": {"clean": [], "unrated": [], "malicious": []},
        "statusMessage": "Lookup unavailable.",
    }


def test_popular_url_with_virustotal_detection_is_high_risk(modules, monkeypatch):
    pipeline, _, _, _ = modules
    url = "https://www.youtube.com/watch?v=abc123"
    monkeypatch.setattr(pipeline, "should_short_circuit", lambda _: (True, "ok"))
    monkeypatch.setattr(pipeline, "google_reputation_signal", lambda _: _finding(pipeline, "Google Safe Browsing"))
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda _: _vt(url, malicious=1))
    monkeypatch.setattr(pipeline, "trace_redirect_chain", lambda _: _redirect(pipeline, url))

    result = asyncio.run(pipeline.analyze_full_pipeline(url))

    assert result["overallRisk"] == "high"
    assert result["confidenceScore"] >= 80
    assert result["verificationStatus"] == "complete"
    assert result["virusTotal"]["summary"]["malicious"] == 1
    assert any(item["check"] == "VirusTotal Reputation" and item["severity"] == "high" for item in result["signals"])


def test_unavailable_virustotal_prevents_green_fast_path(modules, monkeypatch):
    pipeline, _, _, _ = modules
    url = "https://www.youtube.com/watch?v=abc123"
    monkeypatch.setattr(pipeline, "should_short_circuit", lambda _: (True, "ok"))
    monkeypatch.setattr(pipeline, "google_reputation_signal", lambda _: _finding(pipeline, "Google Safe Browsing"))
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda _: _vt(url, mode="unavailable"))
    monkeypatch.setattr(pipeline, "trace_redirect_chain", lambda _: _redirect(pipeline, url))

    result = asyncio.run(pipeline.analyze_full_pipeline(url))

    assert result["overallRisk"] == "suspicious"
    assert result["verificationStatus"] == "incomplete"
    assert result["unverifiedChecks"] == ["VirusTotal Reputation"]
    assert next(item for item in result["signals"] if item["check"] == "VirusTotal Reputation")["passed"] is False


def test_confirmed_google_hit_overrides_bad_model_and_prose(modules, monkeypatch):
    pipeline, _, _, _ = modules
    url = "https://example.org/"
    monkeypatch.setattr(pipeline, "should_short_circuit", lambda _: (False, "test"))
    monkeypatch.setattr(pipeline, "trace_redirect_chain", lambda _: _redirect(pipeline, url))
    monkeypatch.setattr(pipeline, "check_domain_intelligence", lambda _: [])
    monkeypatch.setattr(pipeline, "check_reputation_signals", lambda _: [_finding(pipeline, "Google Safe Browsing", "high", False)])
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda _: _vt(url))
    monkeypatch.setattr(pipeline, "check_crypto_pattern_signals", lambda _: [])
    monkeypatch.setattr(pipeline, "classify_qr_with_ml", lambda *args: {"enabled": False})
    monkeypatch.setattr(pipeline, "blend_ml_score", lambda *args: 0)
    monkeypatch.setattr(pipeline, "generate_ai_verdict", lambda _: {"overallRisk": "safe", "confidenceScore": 0, "verdict": "all clear"})

    result = asyncio.run(pipeline.analyze_full_pipeline(url))

    assert result["overallRisk"] == "high"
    assert result["confidenceScore"] >= 85
    assert result["ruleScore"] >= 85


def test_provider_and_redirect_failures_are_unverified(modules, monkeypatch):
    _, reputation, scoring, redirects = modules
    monkeypatch.setattr(reputation, "check_url_reputation", lambda _: {
        "status": "UNCONFIGURED", "detail": "No provider key.", "matches": []
    })
    gsb = reputation.google_reputation_signal("https://example.org/")
    vt = scoring.virustotal_breakdown_signal(_vt("https://example.org/", mode="pending"))
    monkeypatch.setattr(redirects, "follow_safe_redirects", lambda _: (_ for _ in ()).throw(requests.ConnectionError("offline")))
    redirect = redirects.trace_redirect_chain("https://example.org/")["signal"]

    for finding in (gsb, vt, redirect):
        assert finding["verified"] is False
        assert finding["passed"] is False
        assert finding["severity"] != "low"


@pytest.mark.parametrize(
    ("body", "expected"),
    [({}, "CLEAR"), ({"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}}, "MALICIOUS")],
)
def test_web_risk_is_preferred_when_configured(modules, monkeypatch, body, expected):
    _, reputation, _, _ = modules
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")
    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return body

    def fake_get(url, *, params, timeout):
        calls.append((url, params, timeout))
        return Response()

    monkeypatch.setattr(reputation.requests, "get", fake_get)
    monkeypatch.setattr(reputation.requests, "post", lambda *args, **kwargs: pytest.fail("Safe Browsing fallback was used"))

    result = reputation.check_url_reputation("https://example.org/")
    finding = reputation.google_reputation_signal("https://example.org/")

    assert result["provider"] == "Google Web Risk"
    assert result["status"] == expected
    assert finding["check"] == "Google Web Risk"
    assert finding["verified"] is True
    assert calls[0][0] == "https://webrisk.googleapis.com/v1/uris:search"
    assert ("uri", "https://example.org/") in calls[0][1]
    assert sum(key == "threatTypes" for key, _ in calls[0][1]) == 3


@pytest.mark.parametrize("key_name", ["GOOGLE_SAFE_BROWSING_API_KEY", "googe_api_key"])
def test_legacy_safe_browsing_key_requires_explicit_noncommercial_opt_in(modules, monkeypatch, key_name):
    _, reputation, _, _ = modules
    monkeypatch.delenv("GOOGLE_WEB_RISK_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("googe_api_key", raising=False)
    monkeypatch.setenv(key_name, "legacy-test-key")
    monkeypatch.delenv("SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING", raising=False)
    monkeypatch.setattr(reputation, "validate_public_url", lambda url: url)
    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {}

    monkeypatch.setattr(reputation.requests, "post", lambda url, **kwargs: calls.append((url, kwargs)) or Response())
    blocked = reputation.check_url_reputation("https://example.org/")
    finding = reputation.google_reputation_signal("https://example.org/")

    assert blocked["status"] == "UNCONFIGURED"
    assert blocked["provider"] == "Google Web Risk"
    assert finding["verified"] is False
    assert calls == []

    monkeypatch.setenv("SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING", "true")
    allowed = reputation.check_url_reputation("https://example.org/")

    assert allowed["status"] == "CLEAR"
    assert allowed["provider"] == "Google Safe Browsing"
    assert calls[0][0] == "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    assert calls[0][1]["params"] == {"key": "legacy-test-key"}


def test_virustotal_requires_license_and_does_not_submit_unknown_urls_by_default(modules, monkeypatch):
    _, reputation, scoring, _ = modules
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test-key")
    monkeypatch.delenv("SAFESCAN_VIRUSTOTAL_LICENSED", raising=False)
    monkeypatch.delenv("SAFESCAN_VIRUSTOTAL_SUBMIT_UNKNOWN_URLS", raising=False)
    calls = []

    class MissingResponse:
        status_code = 404

        def raise_for_status(self):
            return None

    monkeypatch.setattr(scoring.requests, "get", lambda *args, **kwargs: calls.append("get") or MissingResponse())
    monkeypatch.setattr(scoring.requests, "post", lambda *args, **kwargs: calls.append("post") or MissingResponse())

    disabled = scoring.virustotal_lookup_result("https://example.org/private?token=secret")
    disabled_signal = reputation.virustotal_reputation_signal("https://example.org/private?token=secret")
    assert disabled["mode"] == "unavailable"
    assert disabled_signal["verified"] is False
    assert calls == []

    monkeypatch.setenv("SAFESCAN_VIRUSTOTAL_LICENSED", "true")
    unknown = scoring.virustotal_lookup_result("https://example.org/private?token=secret")
    unknown_signal = reputation.virustotal_reputation_signal("https://example.org/private?token=secret")
    assert unknown["mode"] == "unavailable"
    assert "not submitted" in unknown["statusMessage"]
    assert unknown_signal["verified"] is False
    assert calls == ["get", "get"]

    monkeypatch.setenv("SAFESCAN_VIRUSTOTAL_SUBMIT_UNKNOWN_URLS", "true")
    submitted = scoring.virustotal_lookup_result("https://example.org/private?token=secret")
    assert submitted["mode"] == "pending"
    assert calls[-2:] == ["get", "post"]


def test_standalone_reputation_endpoint_uses_same_unverified_vt_result(modules, monkeypatch):
    pipeline, _, _, _ = modules
    routes = importlib.import_module("hackabull.routes_api")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(routes, "validate_public_url", lambda url: url)
    monkeypatch.setattr(routes, "google_reputation_signal", lambda _: _finding(pipeline, "Google Web Risk"))

    result = asyncio.run(routes.api_check_reputation({"url": "https://example.org/"}))

    vt = next(item for item in result["signals"] if item["check"] == "VirusTotal Reputation")
    assert vt["verified"] is False
    assert vt["passed"] is False


def test_redirected_popular_url_checks_landing_page_even_if_first_check_is_incomplete(modules, monkeypatch):
    pipeline, _, _, _ = modules
    start = "https://www.youtube.com/go"
    end = "https://example.org/landing"
    monkeypatch.setattr(pipeline, "should_short_circuit", lambda _: (True, "ok"))
    monkeypatch.setattr(pipeline, "google_reputation_signal", lambda _: _finding(pipeline, "Google Safe Browsing"))
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda url: _vt(url, mode="pending" if url == start else "live"))
    monkeypatch.setattr(pipeline, "trace_redirect_chain", lambda _: {
        "signal": _finding(pipeline, "Redirect Chain", "medium", False),
        "redirectChain": [
            {"url": start, "domain": "www.youtube.com", "statusCode": 302, "domainChanged": False},
            {"url": end, "domain": "example.org", "statusCode": 200, "domainChanged": True},
        ],
    })
    seen = []
    monkeypatch.setattr(pipeline, "check_domain_intelligence", lambda url: seen.append(url) or [])
    monkeypatch.setattr(pipeline, "check_crypto_pattern_signals", lambda _: [])
    monkeypatch.setattr(pipeline, "classify_qr_with_ml", lambda *args: {"enabled": False})

    result = asyncio.run(pipeline.analyze_full_pipeline(start))

    assert end in seen
    assert result["verificationStatus"] == "incomplete"
    assert "VirusTotal Reputation" in result["unverifiedChecks"]
    assert result["overallRisk"] != "safe"


def test_malicious_first_hop_cannot_be_cleared_by_clean_final_hop(modules, monkeypatch):
    pipeline, _, _, _ = modules
    start = "https://example.org/redirect"
    end = "https://example.net/clean"
    monkeypatch.setattr(pipeline, "should_short_circuit", lambda _: (False, "test"))
    monkeypatch.setattr(pipeline, "trace_redirect_chain", lambda _: {
        "signal": _finding(pipeline, "Redirect Chain", "medium", False),
        "redirectChain": [
            {"url": start, "domain": "example.org", "statusCode": 302, "domainChanged": False},
            {"url": end, "domain": "example.net", "statusCode": 200, "domainChanged": True},
        ],
    })
    seen = []

    def reputation_for(url):
        seen.append(url)
        return [_finding(pipeline, "Google Safe Browsing", "high", False)] if url == start else [_finding(pipeline, "Google Safe Browsing")]

    monkeypatch.setattr(pipeline, "check_reputation_signals", reputation_for)
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda url: _vt(url))
    monkeypatch.setattr(pipeline, "check_domain_intelligence", lambda _: [])
    monkeypatch.setattr(pipeline, "check_crypto_pattern_signals", lambda _: [])
    monkeypatch.setattr(pipeline, "classify_qr_with_ml", lambda *args: {"enabled": False})

    result = asyncio.run(pipeline.analyze_full_pipeline(start))

    assert set(seen) == {start, end}
    assert result["overallRisk"] == "high"
    assert result["confidenceScore"] >= 85
    assert next(item for item in result["signals"] if item["check"] == "Google Safe Browsing")["checkedUrl"] == start


def test_first_party_shortcut_requires_completed_checks(modules, monkeypatch):
    pipeline, _, _, _ = modules
    url = "https://safescan-qr.onrender.com/"
    monkeypatch.setattr(pipeline, "is_first_party", lambda _: True)
    monkeypatch.setattr(pipeline, "google_reputation_signal", lambda _: _finding(pipeline, "Google Safe Browsing", "medium", False, False))
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda _: _vt(url, mode="unavailable"))
    monkeypatch.setattr(pipeline, "trace_redirect_chain", lambda _: _redirect(pipeline, url))

    result = asyncio.run(pipeline.analyze_full_pipeline(url))

    assert result["overallRisk"] == "suspicious"
    assert result["verificationStatus"] == "incomplete"
    assert set(result["unverifiedChecks"]) == {"Google Safe Browsing", "VirusTotal Reputation"}

    monkeypatch.setattr(pipeline, "google_reputation_signal", lambda _: _finding(pipeline, "Google Safe Browsing"))
    monkeypatch.setattr(pipeline, "virustotal_lookup_result", lambda _: _vt(url))
    verified = asyncio.run(pipeline.analyze_full_pipeline(url))

    assert verified["overallRisk"] == "safe"
    assert verified["verificationStatus"] == "complete"
    assert verified["fastPath"]["reason"] == "first_party"
