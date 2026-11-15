"""The state gallery and mock fixtures must never surface in production."""

import importlib
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
        assert "ui-states.js?v=ui-states-v1" in response.text
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
