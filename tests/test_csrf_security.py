"""Browser state changes require a session-bound CSRF token."""

import re

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from test_auth_persistence import auth_app, db_rows


def _token(html):
    match = re.search(r'<meta name="csrf-token" content="([a-f0-9]{64})"', html)
    assert match, "HTML page must expose a same-origin CSRF token"
    return match.group(1)


@pytest.fixture()
def signed_in(auth_app):
    module, client, db_path = auth_app
    login = client.get("/login")
    guest_token = _token(login.text)
    registered = client.post(
        "/auth/register",
        data={"email": "csrf@example.com", "password": "password123", "csrf_token": guest_token},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert registered.status_code == 303
    profile = client.get("/profile")
    assert profile.status_code == 200
    assert profile.headers["cache-control"] == "no-store"
    return module, client, db_path, _token(profile.text)


def test_cookie_authenticated_post_rejects_missing_origin_and_token(signed_in):
    _, client, db_path, token = signed_in
    response = client.post("/profile/username", data={"username": "alice"}, follow_redirects=False)
    assert response.status_code == 403
    assert db_rows(db_path, "SELECT username FROM users") == [{"username": None}]


def test_cross_site_post_rejected_even_with_token(signed_in):
    _, client, db_path, token = signed_in
    response = client.post(
        "/profile/username", data={"username": "alice", "csrf_token": token},
        headers={"Origin": "https://attacker.example", "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert db_rows(db_path, "SELECT username FROM users") == [{"username": None}]


def test_missing_origin_rejected_even_with_valid_token(signed_in):
    _, client, db_path, token = signed_in
    response = client.post(
        "/profile/username", data={"username": "alice", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert db_rows(db_path, "SELECT username FROM users") == [{"username": None}]


def test_fetch_metadata_rejects_cross_site_even_with_allowed_origin(signed_in):
    _, client, db_path, token = signed_in
    response = client.post(
        "/profile/username", data={"username": "alice", "csrf_token": token},
        headers={"Origin": "https://testserver", "Sec-Fetch-Site": "cross-site"},
        follow_redirects=False,
    )
    assert response.status_code == 403
    assert db_rows(db_path, "SELECT username FROM users") == [{"username": None}]


def test_same_origin_post_with_token_succeeds(signed_in):
    _, client, db_path, token = signed_in
    response = client.post(
        "/profile/username", data={"username": "alice", "csrf_token": token},
        headers={"Origin": "https://testserver", "Sec-Fetch-Site": "same-origin"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert db_rows(db_path, "SELECT username FROM users") == [{"username": "alice"}]


def test_mobile_bearer_post_without_browser_cookie_does_not_need_csrf(signed_in):
    module, client, _, _ = signed_in
    session = client.cookies.get(module.SESSION_COOKIE_NAME)
    mobile = TestClient(module.qr_app, base_url="https://testserver")
    response = mobile.post(
        "/api/scan", json={"payload": ""},
        headers={"Authorization": f"Bearer {session}"},
    )
    assert response.status_code == 400


def test_json_browser_mutation_requires_header_token(signed_in):
    _, client, _, token = signed_in
    payload = {"consentType": "essential_only", "bannerVersion": "test"}
    missing = client.post("/api/consent", json=payload, headers={"Origin": "https://testserver"})
    assert missing.status_code == 403
    valid = client.post(
        "/api/consent", json=payload,
        headers={"Origin": "https://testserver", "X-CSRF-Token": token},
    )
    assert valid.status_code == 200


def test_stripe_webhook_keeps_signature_validation_without_browser_csrf(signed_in):
    _, client, _, _ = signed_in
    response = client.post("/webhooks/stripe", content=b"{}")
    assert response.status_code == 400
    assert response.json().get("error") != "CSRF check failed."


def test_logout_get_is_confirmation_only(signed_in):
    module, client, db_path, token = signed_in
    response = client.get("/auth/logout", follow_redirects=False)
    assert response.status_code == 200
    assert "confirm" in response.text.lower()
    assert db_rows(db_path, "SELECT revoked_at FROM sessions") == [{"revoked_at": None}]
    post = client.post(
        "/auth/logout", data={"csrf_token": token}, headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert post.status_code == 303
    assert db_rows(db_path, "SELECT revoked_at FROM sessions")[0]["revoked_at"] is not None


def test_mobile_bearer_logout_revokes_without_csrf(signed_in):
    module, browser, db_path, _ = signed_in
    session = browser.cookies.get(module.SESSION_COOKIE_NAME)
    mobile = TestClient(module.qr_app, base_url="https://testserver")
    response = mobile.post(
        "/auth/logout", headers={"Authorization": f"Bearer {session}"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert db_rows(db_path, "SELECT revoked_at FROM sessions")[0]["revoked_at"] is not None


def test_remembered_browser_uses_restored_session_token(signed_in):
    module, browser, db_path, _ = signed_in
    remember = browser.cookies.get(module.REMEMBER_ME_COOKIE_NAME)
    assert remember
    reopened = TestClient(module.qr_app, base_url="https://testserver")
    reopened.cookies.set(module.REMEMBER_ME_COOKIE_NAME, remember)
    profile = reopened.get("/profile")
    assert profile.status_code == 200
    token = _token(profile.text)
    response = reopened.post(
        "/profile/username", data={"username": "reopened", "csrf_token": token},
        headers={"Origin": "https://testserver"}, follow_redirects=False,
    )
    assert response.status_code == 303
    assert db_rows(db_path, "SELECT username FROM users") == [{"username": "reopened"}]


def test_all_browser_form_routes_require_csrf(auth_app):
    module, _, _ = auth_app
    from hackabull.csrf import require_csrf_form

    form_routes = [
        route for route in module.qr_app.routes
        if isinstance(route, APIRoute) and "POST" in route.methods
        and not route.path.startswith("/api/")
        and route.path not in {"/auth/google", "/auth/verify", "/webhooks/stripe"}
    ]
    form_routes += [
        route for route in module.qr_app.routes
        if isinstance(route, APIRoute) and route.path == "/api/scan/file"
    ]
    missing = [
        route.path for route in form_routes
        if not any(dependency.call is require_csrf_form for dependency in route.dependant.dependencies)
    ]
    assert not missing
