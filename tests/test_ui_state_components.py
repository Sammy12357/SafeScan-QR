"""The state gallery and mock fixtures must never surface in production."""

import importlib
import html
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(params=[False, True], ids=["production", "mock"])
def state_app(tmp_path, monkeypatch, request):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'states.db'}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true" if request.param else "false")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    yield TestClient(app.qr_app, base_url="https://testserver"), request.param
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def test_state_gallery_only_exists_in_mock_mode(state_app):
    client, mock = state_app
    response = client.get("/__states", headers={"Accept": "text/html"})

    if mock:
        assert response.status_code == 200
        assert "UI state gallery" in response.text
        assert 'role="alert"' in response.text
        assert 'role="status"' in response.text
        assert 'href="/static/icons/states.svg#scan"' in response.text
        assert "/static/ui-states.js?v=" in response.text
    else:
        assert response.status_code == 404
        assert "UI state gallery" not in response.text


def test_mock_state_query_does_not_change_production_home(state_app):
    client, mock = state_app
    if mock:
        pytest.skip("Production-only invariant")
    regular = client.get("/")
    injected = client.get("/?__state=error")
    assert regular.status_code == injected.status_code == 200
    assert regular.text == injected.text


def test_mock_gallery_fixture_switch_is_allowlisted(state_app):
    client, mock = state_app
    fixtures = {
        "empty": ("No scans yet", "Scan history didn't load"),
        "first-use": ("No scans yet", "No results for"),
        "no-results": ("No results for", "No scans yet"),
        "no-access": ("Sign in to see your history", "No scans yet"),
        "loading": ("Loading scan history", "No scans yet"),
        "loading-compact": ("Checking the QR code", "Loading scan history"),
        "error": ("Scan history didn't load", "No scans yet"),
        "offline": ("You're offline", "Scan history didn't load"),
        "notice": ("Your preference was saved", "No scans yet"),
        "info": ("Your scan is ready to review", "Your preference was saved"),
        "success": ("Your preference was saved", "Your scan is ready to review"),
        "warning": ("We could not verify this destination", "Your preference was saved"),
        "danger": ("We could not complete that request", "Your preference was saved"),
        "content": ("Example content loaded", "No scans yet"),
    }
    for state, (present, absent) in fixtures.items():
        response = client.get(f"/__states?__state={state}", headers={"Accept": "text/html"})
        if mock:
            assert response.status_code == 200, state
            rendered = html.unescape(response.text)
            assert present in rendered, state
            assert absent not in rendered, state
        else:
            assert response.status_code == 404, state
            assert present not in response.text, state

    all_states = client.get("/__states", headers={"Accept": "text/html"})
    if mock:
        assert all_states.status_code == 200
        assert "JavaScript states" in all_states.text
        assert "No scans yet" in all_states.text
    else:
        assert all_states.status_code == 404

    invalid = client.get("/__states?__state=%3Cscript%3Ebad%3C/script%3E", headers={"Accept": "text/html"})
    assert invalid.status_code == 404
    assert "<script>bad</script>" not in invalid.text
