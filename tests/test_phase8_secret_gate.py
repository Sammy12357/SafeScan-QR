"""Production must refuse missing or obvious placeholder security secrets."""

import importlib
import secrets

import pytest
from fastapi.testclient import TestClient


def _valid_environment():
    return {
        "RENDER": "true",
        "PRIVACY_HASH_SALT": secrets.token_urlsafe(32),
        "STRIPE_WEBHOOK_SECRET": "whsec_" + secrets.token_urlsafe(32),
        "METRICS_TOKEN": secrets.token_urlsafe(32),
        "CSRF_SECRET": secrets.token_urlsafe(32),
    }


def test_production_secret_gate_rejects_missing_and_placeholders():
    config = importlib.import_module("hackabull.config")
    config.validate_production_secrets(_valid_environment())
    for name in ("PRIVACY_HASH_SALT", "STRIPE_WEBHOOK_SECRET", "METRICS_TOKEN", "CSRF_SECRET"):
        missing = _valid_environment()
        missing.pop(name)
        with pytest.raises(RuntimeError, match=name) as error:
            config.validate_production_secrets(missing)
        assert all(secret not in str(error.value) for secret in missing.values() if len(secret) >= 32)
        weak = _valid_environment()
        weak[name] = "replace-with-random-32-byte-value"
        with pytest.raises(RuntimeError, match=name):
            config.validate_production_secrets(weak)
    config.validate_production_secrets({"ENVIRONMENT": "development"})


def test_csrf_token_is_bound_to_server_secret_and_session(monkeypatch):
    csrf = importlib.import_module("hackabull.csrf")
    monkeypatch.setattr(csrf, "CSRF_SECRET", "first-server-secret")
    first = csrf._token_for_key("session:opaque-session-id")
    assert first == csrf._token_for_key("session:opaque-session-id")
    assert first != csrf._token_for_key("session:another-session-id")
    monkeypatch.setattr(csrf, "CSRF_SECRET", "second-server-secret")
    assert first != csrf._token_for_key("session:opaque-session-id")


def test_app_startup_fails_before_jobs_when_production_secret_is_missing(monkeypatch):
    app = importlib.import_module("hackabull")
    valid = _valid_environment()
    valid.pop("CSRF_SECRET")
    for name, value in valid.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("CSRF_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="CSRF_SECRET"):
        with TestClient(app.qr_app):
            pass
