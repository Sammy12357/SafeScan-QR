"""Branded QR generation must fail closed when a scan is risky or incomplete."""

import asyncio
import importlib
import sys

import pytest


@pytest.fixture
def generator_api(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'generator.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    api = importlib.import_module("hackabull.routes_api")
    monkeypatch.setattr(api, "get_session_user", lambda _request: None)
    monkeypatch.setattr(api, "enforce_rate_limit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, "validate_public_url", lambda url: url)
    monkeypatch.setattr(api, "audit_log", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api, "render_safescan_logo", lambda _size: None)
    return api


@pytest.mark.parametrize(
    ("risk", "score"),
    [("suspicious", 35), ("suspicious", 79), ("high", 80), ("high", 89)],
)
def test_generator_refuses_every_non_safe_verdict(generator_api, monkeypatch, risk, score):
    async def analyze(_url):
        return {"overallRisk": risk, "confidenceScore": score, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/"}))
    assert caught.value.status_code == 400


def test_generator_refuses_safe_score_with_incomplete_checks(generator_api, monkeypatch):
    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "incomplete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    with pytest.raises(generator_api.SafeScanError) as caught:
        asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/"}))
    assert caught.value.status_code == 503


def test_generator_allows_only_complete_safe_scan(generator_api, monkeypatch):
    async def analyze(_url):
        return {"overallRisk": "safe", "confidenceScore": 8, "verificationStatus": "complete"}

    monkeypatch.setattr(generator_api, "analyze_full_pipeline", analyze)
    response = asyncio.run(generator_api.api_qr_generate(object(), {"url": "https://example.com/"}))
    assert response.media_type == "image/png"
    assert response.headers["X-SafeScan-Verdict"] == "safe"
    assert response.body.startswith(b"\x89PNG\r\n\x1a\n")
