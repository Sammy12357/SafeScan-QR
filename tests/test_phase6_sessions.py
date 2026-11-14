"""Account-wide sign-out must invalidate every active authentication token."""

from browser_client import BrowserTestClient as TestClient

from test_auth_persistence import auth_app, browser_post, db_rows, login, register


def test_sign_out_all_devices_revokes_sessions_and_remembered_devices(auth_app):
    module, first, db_path = auth_app
    assert register(first).status_code == 200
    first_session = first.cookies.get(module.SESSION_COOKIE_NAME)

    second = TestClient(module.qr_app, base_url="https://testserver")
    assert login(second).status_code == 200
    second_session = second.cookies.get(module.SESSION_COOKIE_NAME)
    second_remember = second.cookies.get(module.REMEMBER_ME_COOKIE_NAME)
    assert first_session and second_session and first_session != second_session
    assert second_remember
    assert "action=\"/profile/sign-out-all\"" in first.get("/profile").text

    blocked = first.post("/profile/sign-out-all", follow_redirects=False)
    assert blocked.status_code == 403
    assert db_rows(db_path, "SELECT COUNT(*) AS total FROM sessions WHERE revoked_at IS NULL")[0]["total"] == 2

    response = browser_post(first, "/profile/sign-out-all", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert first.cookies.get(module.SESSION_COOKIE_NAME) is None
    assert first.cookies.get(module.REMEMBER_ME_COOKIE_NAME) is None
    assert db_rows(db_path, "SELECT COUNT(*) AS total FROM sessions WHERE revoked_at IS NULL")[0]["total"] == 0
    assert db_rows(db_path, "SELECT COUNT(*) AS total FROM persistent_sessions WHERE revoked_at IS NULL")[0]["total"] == 0

    assert second.get("/profile").status_code == 401
    bearer = TestClient(module.qr_app, base_url="https://testserver")
    assert bearer.get("/profile", headers={"Authorization": f"Bearer {first_session}"}).status_code == 401
    remembered = TestClient(module.qr_app, base_url="https://testserver")
    remembered.cookies.set(module.REMEMBER_ME_COOKIE_NAME, second_remember)
    assert remembered.get("/profile").status_code == 401


def test_sign_out_all_devices_requires_authentication(auth_app):
    module, client, db_path = auth_app
    response = browser_post(client, "/profile/sign-out-all", follow_redirects=False)
    assert response.status_code == 401
    assert db_rows(db_path, "SELECT COUNT(*) AS total FROM sessions")[0]["total"] == 0
