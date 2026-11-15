"""The public token switch and owner-only distribution gate fail closed."""

import importlib
import re
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def token_app(tmp_path, monkeypatch):
    database = tmp_path / "token-controls.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("OWNER_EMAILS", "owner@example.com")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("TOKEN_FEATURES_ENABLED", "false")
    monkeypatch.setenv("TOKEN_DISTRIBUTION_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    auth_routes = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(auth_routes, "LOCAL_AUTH_ENABLED", True)
    app.RATE_LIMITS.clear()
    yield app, database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def _registered(app, email):
    client = TestClient(app.qr_app, base_url="https://testserver")
    response = client.post("/auth/register", data={"email": email, "password": "password123"})
    assert response.status_code in (200, 303)
    return client


def test_token_off_hides_prompts_and_eligibility_but_allows_wallet_disconnect(token_app):
    app, database = token_app
    guest = TestClient(app.qr_app, base_url="https://testserver")
    assert "Token features are not available" in guest.get("/token").text
    assert "Token features are not available" in guest.get("/tokenomics").text
    home = guest.get("/").text
    assert 'href="/token"' not in home
    assert "Reward tiers" not in home
    plans = guest.get("/plans").text
    assert "Free + Airdrop" not in plans
    assert guest.get("/trigger-airdrop-secret").status_code == 410
    assert guest.post("/api/wallet/nonce", json={"walletAddress": "x"}).status_code == 503

    client = _registered(app, "person@example.com")
    profile = client.get("/api/user/profile").json()
    assert profile["tier"] is None
    assert profile["tokenFeaturesEnabled"] is False
    assert client.get("/api/airdrop/status").status_code == 503
    assert client.get("/api/referral").status_code == 503
    with sqlite3.connect(database) as conn:
        conn.execute("INSERT INTO wallets (id, user_id, address, verified, connected_at) VALUES (?, ?, ?, 1, ?)",
                     ("wallet-1", "person@example.com", "existing-wallet", "2026-11-15T00:00:00Z"))
    assert client.get("/api/wallet").json()["connected"] is True
    assert client.delete("/api/wallet").status_code == 200
    assert client.get("/api/wallet").json() == {"connected": False}


def test_distribution_requires_owner_and_both_flags(token_app, monkeypatch):
    app, database = token_app
    owner = _registered(app, "owner@example.com")
    admin = _registered(app, "admin@example.com")
    assert owner.post("/admin/airdrop/distribute").status_code == 503
    monkeypatch.setenv("TOKEN_FEATURES_ENABLED", "true")
    monkeypatch.setenv("TOKEN_DISTRIBUTION_ENABLED", "true")
    assert admin.post("/admin/airdrop/distribute").status_code == 403
    assert owner.post("/admin/airdrop/distribute").status_code == 403
    with sqlite3.connect(database) as conn:
        owner_id = conn.execute("SELECT google_id FROM users WHERE email = 'owner@example.com'").fetchone()[0]
        conn.execute("UPDATE age_eligibility SET minimum_age = 18, adult_attested_at = ? WHERE user_id = ?",
                     ("2026-11-15T00:00:00Z", owner_id))

    distribute = importlib.import_module("distribute")
    calls = []

    async def fake_sweep(*, owner_authorized=False):
        calls.append(owner_authorized)
        return {"status": "dry-run", "eligible": 0, "sent": [], "total_tokens_sent": 0}

    monkeypatch.setattr(distribute, "airdrop_sweep", fake_sweep)
    page = owner.get("/admin/airdrop")
    assert page.status_code == 200
    token = re.search(r'name="distribution_token" value="([^"]+)"', page.text).group(1)
    assert owner.post("/admin/airdrop/distribute", data={"distribution_token": token}).status_code == 200
    assert owner.post("/admin/airdrop/distribute", data={"distribution_token": token}).status_code == 403
    assert calls == [True]


def test_distribution_engine_refuses_a_direct_call_without_owner(monkeypatch):
    monkeypatch.setenv("TOKEN_FEATURES_ENABLED", "true")
    monkeypatch.setenv("TOKEN_DISTRIBUTION_ENABLED", "true")
    monkeypatch.setenv("AIRDROP_ENABLED", "true")
    monkeypatch.setenv("SOLANA_MAINNET_ENABLED", "true")
    monkeypatch.setenv("AIRDROP_ADMIN_SECRET", "x" * 32)
    # Module-level settings are read at import, matching the production worker.
    sys.modules.pop("distribute", None)
    distribution = importlib.import_module("distribute")
    with pytest.raises(RuntimeError, match="owner session"):
        distribution.validate_airdrop_runtime()


def test_enabled_token_page_does_not_promise_an_allocation(token_app):
    app, _ = token_app
    html = app.templates.get_template("token.html").render(scan_count=5, token_features_enabled=lambda: True)
    assert "Five scans recorded. Any token eligibility remains subject to separate review." in html
    assert "Base allocation unlocked" not in html
    assert "2x allocation" not in html
