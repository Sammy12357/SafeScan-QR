"""Website Auth0 cutover: one-use OAuth flow and existing Google account ownership."""

import importlib
import sqlite3
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.exceptions import InvalidSignature
from fastapi.testclient import TestClient


@pytest.fixture()
def auth0_web_app(tmp_path, monkeypatch):
    db_path = tmp_path / "auth0-web.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("AUTH0_DOMAIN", "safe-scan-qr.us.auth0.com")
    monkeypatch.setenv("AUTH0_WEB_ENABLED", "true")
    monkeypatch.setenv("AUTH0_WEB_CLIENT_ID", "web-client")
    monkeypatch.setenv("AUTH0_WEB_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    app.RATE_LIMITS.clear()
    monkeypatch.setattr(routes, "run_fraud_checks", lambda *args, **kwargs: [])
    yield app, routes, db_path
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def _start(client):
    response = client.get("/auth/auth0/start?next=/profile", follow_redirects=False)
    assert response.status_code == 302
    params = parse_qs(urlparse(response.headers["location"]).query)
    return response, params


def _mock_google_identity(routes, monkeypatch):
    seen = []
    monkeypatch.setattr(routes, "exchange_web_code", lambda code, verifier: seen.append((code, verifier)) or "id-token")
    monkeypatch.setattr(routes, "web_identity_from_token", lambda token, nonce: {
        "provider": "google_auth0_web", "subject": "google-1", "email": "person@example.com",
        "display_name": "Person", "picture": "",
    })
    return seen


def test_auth0_start_uses_code_pkce_google_and_browser_cookie(auth0_web_app):
    app, _, db_path = auth0_web_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    page = client.get("/login")
    assert page.status_code == 200
    assert 'action="/auth/auth0/start"' in page.text
    assert "accounts.google.com/gsi/client" not in page.text
    assert 'action="/auth/login"' not in page.text
    response, params = _start(client)
    assert urlparse(response.headers["location"]).netloc == "safe-scan-qr.us.auth0.com"
    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["web-client"]
    assert params["redirect_uri"] == ["https://testserver/auth/auth0/callback"]
    assert params["connection"] == ["google-oauth2"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["state"] and params["nonce"] and params["code_challenge"]
    assert "__Host-safescan_auth0_web" in client.cookies
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "Secure" in response.headers["set-cookie"]
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM auth0_web_flows").fetchone()[0] == 1


def test_existing_google_account_survives_auth0_login(auth0_web_app, monkeypatch):
    app, routes, db_path = auth0_web_app
    app.save_user_to_db("google-1", "person@example.com")
    importlib.import_module("hackabull.age_gate").record_account_eligibility("google-1")
    seen = _mock_google_identity(routes, monkeypatch)
    client = TestClient(app.qr_app, base_url="https://testserver")
    _, params = _start(client)
    callback = client.get(f"/auth/auth0/callback?code=valid-code&state={params['state'][0]}", follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers["location"] == "/profile"
    assert "__Host-safescan_session" in client.cookies
    assert "__Host-safescan_auth0_web" not in client.cookies
    assert seen[0][0] == "valid-code"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT google_id FROM users").fetchall() == [("google-1",)]
        assert conn.execute("SELECT count(*) FROM auth0_web_flows").fetchone()[0] == 0
    replay = client.get(f"/auth/auth0/callback?code=valid-code&state={params['state'][0]}", follow_redirects=False)
    assert replay.status_code == 303
    assert replay.headers["location"].startswith("/login?")
    assert len(seen) == 1


def test_new_google_account_still_requires_age_decision(auth0_web_app, monkeypatch):
    app, routes, db_path = auth0_web_app
    _mock_google_identity(routes, monkeypatch)
    client = TestClient(app.qr_app, base_url="https://testserver")
    _, params = _start(client)
    callback = client.get(f"/auth/auth0/callback?code=valid-code&state={params['state'][0]}", follow_redirects=False)
    assert callback.status_code == 303
    assert callback.headers["location"] == "/auth/confirm-age"
    assert "__Host-safescan_session" not in client.cookies
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0
    birth_year = str(datetime.now(timezone.utc).year - 20)
    confirmed = client.post("/auth/confirm-age", data={"birth_year": birth_year}, follow_redirects=False)
    assert confirmed.status_code == 303
    assert confirmed.headers["location"] == "/profile"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT google_id FROM users").fetchall() == [("google-1",)]


def test_wrong_state_or_browser_cannot_exchange_code(auth0_web_app, monkeypatch):
    app, routes, db_path = auth0_web_app
    seen = _mock_google_identity(routes, monkeypatch)
    client = TestClient(app.qr_app, base_url="https://testserver")
    _, params = _start(client)
    stranger = TestClient(app.qr_app, base_url="https://testserver")
    denied = stranger.get(f"/auth/auth0/callback?code=valid-code&state={params['state'][0]}", follow_redirects=False)
    assert denied.headers["location"].startswith("/login?")
    denied = client.get("/auth/auth0/callback?code=valid-code&state=wrong", follow_redirects=False)
    assert denied.headers["location"].startswith("/login?")
    denied = client.get(f"/auth/auth0/callback?code=valid-code&state={params['state'][0]}", follow_redirects=False)
    assert denied.headers["location"].startswith("/login?")
    assert not seen
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_malformed_callback_state_fails_closed(auth0_web_app, monkeypatch):
    app, routes, _ = auth0_web_app
    seen = _mock_google_identity(routes, monkeypatch)
    client = TestClient(app.qr_app, base_url="https://testserver")
    _start(client)
    denied = client.get("/auth/auth0/callback?code=valid-code&state=%C3%A9", follow_redirects=False)
    assert denied.status_code == 303
    assert denied.headers["location"].startswith("/login?")
    assert not seen


def test_auth0_web_without_credentials_stays_closed(auth0_web_app, monkeypatch):
    app, routes, _ = auth0_web_app
    monkeypatch.setattr(routes, "AUTH0_WEB_CLIENT_SECRET", "")
    client = TestClient(app.qr_app, base_url="https://testserver")
    page = client.get("/login")
    assert "Sign-in is temporarily unavailable" in page.text
    assert 'action="/auth/auth0/start"' not in page.text
    assert client.get("/auth/auth0/start").status_code == 503
    assert client.post("/auth/google", data={"credential": "token"}).status_code == 404


def test_cutover_disables_direct_google_endpoint(auth0_web_app):
    app, _, _ = auth0_web_app
    client = TestClient(app.qr_app, base_url="https://testserver")
    assert client.post("/auth/google", data={"credential": "token"}).status_code == 404
    assert client.post("/auth/register", data={"email": "x@example.com", "password": "password123"}).status_code == 404


def test_auth0_logout_revokes_local_session_and_auth0_session(auth0_web_app, monkeypatch):
    app, routes, _ = auth0_web_app
    app.save_user_to_db("google-1", "person@example.com")
    importlib.import_module("hackabull.age_gate").record_account_eligibility("google-1")
    _mock_google_identity(routes, monkeypatch)
    client = TestClient(app.qr_app, base_url="https://testserver")
    _, params = _start(client)
    assert client.get(f"/auth/auth0/callback?code=valid-code&state={params['state'][0]}",
                      follow_redirects=False).status_code == 303
    response = client.post("/auth/logout", follow_redirects=False)
    assert response.status_code == 303
    logout = urlparse(response.headers["location"])
    assert logout.netloc == "safe-scan-qr.us.auth0.com"
    assert logout.path == "/v2/logout"
    assert parse_qs(logout.query)["returnTo"] == ["https://testserver/"]
    assert "__Host-safescan_session" not in client.cookies


def test_auth0_web_claims_require_verified_google_subject_and_nonce(auth0_web_app, monkeypatch):
    import time
    app, _, _ = auth0_web_app
    web = importlib.import_module("hackabull.auth0_web")
    claims = {"sub": "google-oauth2|google-1", "email": "person@example.com",
              "email_verified": True, "iat": int(time.time()), "exp": int(time.time()) + 600}
    observed = []
    monkeypatch.setattr(web, "verify_auth0_id_token", lambda token, **kwargs: observed.append(kwargs) or claims)
    assert web.web_identity_from_token("token", "expected-nonce")["subject"] == "google-1"
    assert observed == [{"expected_audiences": {"web-client"}, "expected_nonce": "expected-nonce"}]
    for bad in ({"sub": "auth0|google-1"}, {"email_verified": False}, {"iat": 0},
                {"exp": 0}, {"aud": ["web-client", "other-client"]}):
        claims.update(bad)
        with pytest.raises(ValueError):
            web.web_identity_from_token("token", "expected-nonce")
        claims.update({"sub": "google-oauth2|google-1", "email_verified": True,
                       "iat": int(time.time()), "exp": int(time.time()) + 600, "aud": "web-client"})


def test_auth0_web_rejects_wrong_audience_nonce_and_signature(auth0_web_app):
    import base64
    import json
    import time
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    auth = importlib.import_module("hackabull.auth0")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private_key.public_key().public_numbers()

    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    auth._AUTH0_JWKS_CACHE.update({
        "keys": [{"kid": "test-key", "n": b64(public.n.to_bytes(256, "big")),
                  "e": b64(public.e.to_bytes(3, "big"))}],
        "fetched_at": time.time(),
    })
    header = b64(json.dumps({"alg": "RS256", "kid": "test-key"}).encode())
    claims = {"iss": "https://safe-scan-qr.us.auth0.com/", "aud": "web-client",
              "sub": "google-oauth2|google-1", "email": "person@example.com",
              "email_verified": True, "nonce": "login-nonce", "iat": int(time.time()),
              "exp": int(time.time()) + 600}

    def token(payload):
        signing_input = f"{header}.{b64(json.dumps(payload).encode())}"
        signature = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{b64(signature)}"

    good = token(claims)
    assert auth.verify_auth0_id_token(good, expected_audiences={"web-client"},
                                      expected_nonce="login-nonce")["sub"] == "google-oauth2|google-1"
    with pytest.raises(ValueError, match="audience"):
        auth.verify_auth0_id_token(good, expected_audiences={"mobile-client"},
                                   expected_nonce="login-nonce")
    with pytest.raises(ValueError, match="nonce"):
        auth.verify_auth0_id_token(good, expected_audiences={"web-client"},
                                   expected_nonce="other-nonce")
    forged_claims = {**claims, "email": "other@example.com"}
    forged = f"{header}.{b64(json.dumps(forged_claims).encode())}.{good.rsplit('.', 1)[1]}"
    with pytest.raises(InvalidSignature):
        auth.verify_auth0_id_token(forged, expected_audiences={"web-client"},
                                   expected_nonce="login-nonce")
