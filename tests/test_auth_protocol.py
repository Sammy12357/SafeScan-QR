"""Protocol-level regression tests for Google and Auth0 sign-in."""

import base64
import importlib
import json
import re
import sys
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(private_key, claims, *, kid="test-kid", typ="JWT"):
    header = {"alg": "RS256", "kid": kid, "typ": typ}
    if typ is None:
        header.pop("typ")
    encoded = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(claims).encode())}"
    signature = private_key.sign(encoded.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded}.{_b64(signature)}"


@pytest.fixture()
def auth0_verifier(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'auth.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("AUTH0_DOMAIN", "test-tenant.auth0.com")
    monkeypatch.setenv("AUTH0_CLIENT_IDS", "test-client")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-google-client")
    monkeypatch.setenv("MOCK_MODE", "false")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    auth0 = importlib.import_module("hackabull.auth0")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kty": "RSA", "kid": "test-kid", "alg": "RS256", "use": "sig",
        "n": _b64(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    auth0._AUTH0_JWKS_CACHE.update({"keys": [jwk], "fetched_at": time.time()})
    yield auth0, private_key
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def _claims(auth0, **changes):
    now = int(time.time())
    result = {
        "iss": auth0.AUTH0_ISSUER, "aud": "test-client", "sub": "google-oauth2|123",
        "email": "person@example.com", "iat": now - 30, "exp": now + 600,
    }
    result.update(changes)
    return result


def test_valid_auth0_token_is_accepted(auth0_verifier):
    auth0, key = auth0_verifier
    assert auth0.verify_auth0_id_token(_token(key, _claims(auth0)))["sub"] == "google-oauth2|123"


@pytest.mark.parametrize("change", [
    {"iat": None},
    {"iat": lambda now: now + 3600},
    {"nbf": lambda now: now + 3600},
    {"sub": ""},
])
def test_auth0_rejects_missing_or_future_claims(auth0_verifier, change):
    auth0, key = auth0_verifier
    now = int(time.time())
    changed = {name: value(now) if callable(value) else value for name, value in change.items()}
    claims = _claims(auth0, **changed)
    if claims.get("iat") is None:
        claims.pop("iat")
    with pytest.raises(ValueError):
        auth0.verify_auth0_id_token(_token(key, claims))


@pytest.mark.parametrize("token_type", ["at+jwt", None])
def test_auth0_rejects_wrong_token_type(auth0_verifier, token_type):
    auth0, key = auth0_verifier
    with pytest.raises(ValueError):
        auth0.verify_auth0_id_token(_token(key, _claims(auth0), typ=token_type))


@pytest.mark.parametrize("claim", ["iss", "aud"])
def test_auth0_rejects_wrong_issuer_or_audience(auth0_verifier, claim):
    auth0, key = auth0_verifier
    bad_value = "https://other-tenant.auth0.com/" if claim == "iss" else "other-client"
    with pytest.raises(ValueError):
        auth0.verify_auth0_id_token(_token(key, _claims(auth0, **{claim: bad_value})))


def test_unknown_key_does_not_trigger_repeated_jwks_fetches(auth0_verifier, monkeypatch):
    auth0, key = auth0_verifier
    jwks = auth0._AUTH0_JWKS_CACHE["keys"]
    auth0._AUTH0_JWKS_CACHE.update({"keys": None, "fetched_at": 0.0, "last_attempt_at": 0.0})
    calls = []
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"keys": jwks}

    def counted(*args, **kwargs):
        calls.append(1)
        return Response()

    monkeypatch.setattr(auth0.requests, "get", counted)
    unknown = _token(key, _claims(auth0), kid="unknown-kid")
    for _ in range(3):
        with pytest.raises(ValueError):
            auth0.verify_auth0_id_token(unknown)
    assert len(calls) == 1


def test_failed_jwks_fetch_is_cooled_down(auth0_verifier, monkeypatch):
    auth0, key = auth0_verifier
    auth0._AUTH0_JWKS_CACHE.update({"keys": None, "fetched_at": 0.0, "last_attempt_at": 0.0})
    calls = []

    def unavailable(*args, **kwargs):
        calls.append(1)
        raise auth0.requests.Timeout("tenant unavailable")

    monkeypatch.setattr(auth0.requests, "get", unavailable)
    token = _token(key, _claims(auth0))
    for _ in range(3):
        with pytest.raises(ValueError):
            auth0.verify_auth0_id_token(token)
    assert len(calls) == 1


def _google_login_client(auth0, monkeypatch, *, token_nonce=None):
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_scan_auth")
    client = TestClient(app.qr_app, base_url="https://testserver")
    page = client.get("/login")
    assert page.status_code == 200
    match = re.search(r'data-nonce="([A-Za-z0-9_-]+)"', page.text)
    assert match, "The Google button needs a server-issued nonce."
    nonce = match.group(1)
    browser_cookie = client.cookies.get("__Host-safescan_google_nonce")
    assert browser_cookie
    monkeypatch.setattr(
        routes.id_token, "verify_oauth2_token",
        lambda *args: {
            "sub": "google-sub", "email": "person@example.com",
            "email_verified": True,
            "nonce": token_nonce if token_nonce is not None else nonce,
        },
    )
    monkeypatch.setattr(routes, "run_fraud_checks", lambda *args, **kwargs: [])
    client.cookies.set("g_csrf_token", "gis-random-token")
    return client, nonce, browser_cookie


def test_google_redirect_requires_double_submit_and_single_use_nonce(auth0_verifier, monkeypatch):
    auth0, _ = auth0_verifier
    client, nonce, browser_cookie = _google_login_client(auth0, monkeypatch)
    missing = client.post("/auth/google", data={"credential": "valid-token"})
    assert missing.status_code == 401
    forged = client.post("/auth/google", data={"credential": "valid-token", "g_csrf_token": "attacker-token"})
    assert forged.status_code == 401

    valid = client.post("/auth/google", data={"credential": "valid-token", "g_csrf_token": "gis-random-token"})
    assert valid.status_code == 200
    assert "__Host-safescan_session" in client.cookies

    client.cookies.set("__Host-safescan_google_nonce", browser_cookie)
    replay = client.post("/auth/google", data={"credential": "valid-token", "g_csrf_token": "gis-random-token"})
    assert replay.status_code == 401


@pytest.mark.parametrize("token_nonce", ["someone-elses-nonce", "unicode-ñ-nonce"])
def test_google_redirect_rejects_token_with_wrong_nonce(auth0_verifier, monkeypatch, token_nonce):
    auth0, _ = auth0_verifier
    client, nonce, _ = _google_login_client(auth0, monkeypatch, token_nonce=token_nonce)
    response = client.post("/auth/google", data={"credential": "valid-token", "g_csrf_token": "gis-random-token"})
    assert response.status_code == 401


def test_google_login_page_redirects_to_canonical_nonce_host(auth0_verifier):
    app = importlib.import_module("hackabull")
    alternate = TestClient(app.qr_app, base_url="https://alternate.example")

    response = alternate.get("/login", follow_redirects=False)

    assert response.status_code in {302, 303, 307, 308}
    assert response.headers["location"] == "https://testserver/login"
    assert "__Host-safescan_google_nonce" not in response.cookies
