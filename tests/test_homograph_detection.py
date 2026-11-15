"""A QR's visible host must not impersonate a trusted destination."""

import asyncio
import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / "tests/qr_corpus/edge_cases/url_threat_payloads.json").read_text(encoding="utf-8"))


def load_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'homograph.db').as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    return importlib.import_module("hackabull")


@pytest.mark.parametrize("url, official", [
    ("https://аpple.com/", "apple.com"),  # Cyrillic a
    ("https://xn--pple-43d.com/", "apple.com"),
    ("https://paypaI.com/", "paypal.com"),  # uppercase i, not lowercase l
    ("https://rnicrosoft.com/", "microsoft.com"),
    ("https://paypal.com.evil.net/login", "paypal.com"),
    ("https://paypal-login.example.net/", "paypal.com"),
    ("https://paypal-verify-identity.evil.net/", "paypal.com"),
    ("https://secure-paypal.evil.net/", "paypal.com"),
    ("https://paypaI-login.evil.net/", "paypal.com"),
    ("https://login.paypaI.com.evil.net/", "paypal.com"),
    ("https://раураl-login.evil.net/", "paypal.com"),
    ("https://paypaI。com/", "paypal.com"),
    ("https://vvellsfargo.com/", "wellsfargo.com"),
    ("https://аpple-login.example.net/", "apple.com"),
    ("https://аpple.com.evil.net/", "apple.com"),
    ("https://apple.cοm/", "apple.com"),
])
def test_brand_lookalikes_get_specific_high_signal(tmp_path, monkeypatch, url, official):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    findings = check_url_deception_signals(url)

    assert any(
        finding["check"] == "Brand Impersonation"
        and finding["severity"] == "high"
        and official in finding["detail"]
        for finding in findings
    )


@pytest.mark.parametrize("url", [
    "https://paypal.com/",
    "https://accounts.paypal.com/login",
    "https://münchen.de/",
    "https://xn--mnchen-3ya.de/",
    "https://例え.jp/",
    "https://google.de/",
    "https://amazon.co.uk/",
    "https://paypal.co.uk/",
    "https://login.paypal.co.uk/",
    "https://example.com/",
])
def test_legitimate_hosts_have_no_impersonation_signal(tmp_path, monkeypatch, url):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    assert not any(finding["check"] == "Brand Impersonation" for finding in check_url_deception_signals(url))


def test_exact_brand_word_on_other_tld_is_not_scored_as_impersonation(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    assert not check_url_deception_signals("https://apple.net/")


def test_hidden_direction_control_in_path_is_high_risk(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    findings = check_url_deception_signals("https://example.com/file\u202e/moc.lapyap")

    assert any(finding["check"] == "Hidden Direction Control" and finding["severity"] == "high" for finding in findings)


def test_percent_encoded_hidden_controls_are_inspected(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    assert any(item["check"] == "Hidden Direction Control" for item in check_url_deception_signals("https://example.com/%E2%80%AEevil"))
    assert any(item["check"] == "Invisible Character" for item in check_url_deception_signals("https://example.com/%E2%80%8Bevil"))


def test_unrelated_mixed_script_host_needs_review(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    findings = check_url_deception_signals("https://eхample.net/")  # Cyrillic ha

    assert any(finding["check"] == "Mixed Script Host" and finding["severity"] == "medium" for finding in findings)


def test_host_forms_display_unicode_and_alabel(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import host_forms

    assert host_forms("https://xn--pple-43d.com/") == {"unicode": "аpple.com", "ascii": "xn--pple-43d.com"}
    assert host_forms("https://example.com/") == {"unicode": "example.com", "ascii": "example.com"}


def test_bare_internationalized_domain_is_treated_as_url(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    assert module.detect_payload("аpple.com")[0] == "URL"
    assert module.detect_payload("例え.jp/path")[0] == "URL"
    assert module.detect_payload("WIFI:S:Café;;")[0] == "Wi-Fi"


def test_idna_2008_form_is_shared_with_feed_matching(tmp_path, monkeypatch):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import host_forms
    from hackabull.idna_hosts import canonical_ascii_host
    from hackabull.phish_feed import canonical_feed_url

    assert canonical_ascii_host("faß.de") == "xn--fa-hia.de"
    assert host_forms("https://faß.de/") == {"unicode": "faß.de", "ascii": "xn--fa-hia.de"}
    assert canonical_feed_url("https://faß.de/") == "https://xn--fa-hia.de/"


def test_original_lookalike_survives_redirect_to_clean_host(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    for name, value in (
        ("is_private_hostname", lambda _: False),
        ("google_reputation_signal", lambda url: module.signal("Google Web Risk", "No match", "low", "No match", True)),
        ("phishtank_signal", lambda url: module.signal("PhishTank", "No match", "low", "No match", True)),
        ("classify_qr_with_ml", lambda *args, **kwargs: {"enabled": False, "reason": "test"}),
    ):
        for loaded_name, loaded in list(sys.modules.items()):
            if (loaded_name == "hackabull" or loaded_name.startswith("hackabull.")) and hasattr(loaded, name):
                monkeypatch.setattr(loaded, name, value)

    redirect = {
        "signal": module.signal("Redirect Chain", "1 hop", "low", "Redirected", True),
        "redirectChain": [{"url": "https://аpple.com/"}, {"url": "https://example.com/"}],
    }
    for loaded_name, loaded in list(sys.modules.items()):
        if (loaded_name == "hackabull" or loaded_name.startswith("hackabull.")) and hasattr(loaded, "trace_redirect_chain"):
            monkeypatch.setattr(loaded, "trace_redirect_chain", lambda url: redirect)

    result = asyncio.run(module.analyze_full_pipeline("https://аpple.com/"))

    assert result["overallRisk"] == "high"
    assert any(item["check"] == "Brand Impersonation" for item in result["signals"])


def test_middle_lookalike_hop_survives_reputation_lookup_cap(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    for name, value in (
        ("is_private_hostname", lambda _: False),
        ("google_reputation_signal", lambda url: module.signal("Google Web Risk", "No match", "low", "No match", True)),
        ("phishtank_signal", lambda url: module.signal("PhishTank", "No match", "low", "No match", True)),
        ("classify_qr_with_ml", lambda *args, **kwargs: {"enabled": False, "reason": "test"}),
    ):
        for loaded_name, loaded in list(sys.modules.items()):
            if (loaded_name == "hackabull" or loaded_name.startswith("hackabull.")) and hasattr(loaded, name):
                monkeypatch.setattr(loaded, name, value)

    hops = ["https://example.com/", "https://one.example/", "https://two.example/", "https://аpple.com/", "https://four.example/", "https://five.example/", "https://six.example/"]
    redirect = {
        "signal": module.signal("Redirect Chain", "6 hops", "low", "Redirected", True),
        "redirectChain": [{"url": url} for url in hops],
    }
    for loaded_name, loaded in list(sys.modules.items()):
        if (loaded_name == "hackabull" or loaded_name.startswith("hackabull.")) and hasattr(loaded, "trace_redirect_chain"):
            monkeypatch.setattr(loaded, "trace_redirect_chain", lambda url: redirect)

    result = asyncio.run(module.analyze_full_pipeline(hops[0]))
    assert result["overallRisk"] == "high"
    assert any(item["check"] == "Brand Impersonation" and item.get("checkedUrl") == hops[3] for item in result["signals"])


def test_embedded_link_uses_same_local_lookalike_check(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    score, reason = module.local_embedded_url_risk("https://xn--pple-43d.com/")
    assert score >= 80
    assert reason["label"] == "Brand Impersonation"
    assert "apple.com" in reason["detail"]

    score, reason = module.local_embedded_url_risk("https://münchen.de/")
    assert score < 80
    assert reason["label"] != "Encoded embedded domain"

    score, reason = module.local_embedded_url_risk("https://eхample.net/seed")
    assert score >= 70
    assert reason["severity"] == "high"


@pytest.mark.parametrize("case", CORPUS, ids=lambda case: case["payload"].encode("unicode_escape").decode())
def test_qr_payload_threat_corpus(tmp_path, monkeypatch, case):
    load_app(tmp_path, monkeypatch)
    from hackabull.homograph import check_url_deception_signals

    findings = check_url_deception_signals(case["payload"])
    if case["check"] is None:
        assert not any(item["severity"] in {"high", "medium"} for item in findings)
    else:
        assert any(item["check"] == case["check"] and item["severity"] == case["severity"] for item in findings)


def test_pinned_unicode_data_is_unchanged():
    data = ROOT / "hackabull/data/confusables-18.0.0.txt"
    assert hashlib.sha256(data.read_bytes()).hexdigest() == "6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92"
    assert (ROOT / "hackabull/data/UNICODE-LICENSE.txt").is_file()
