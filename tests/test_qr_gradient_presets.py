"""Account-bound QR gradient slots use stable IDs and survive repeat sessions."""

import importlib
import sqlite3
import sys
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def gradient_site(tmp_path, monkeypatch):
    db_path = tmp_path / "gradients.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()

    now = datetime.utcnow()
    with sqlite3.connect(db_path) as conn:
        for user_id, email, status in (
            ("provider-a", "a@example.com", "active"),
            ("provider-b", "b@example.com", "active"),
            ("provider-suspended", "suspended@example.com", "suspended"),
        ):
            conn.execute(
                "INSERT INTO users (google_id, email, status) VALUES (?, ?, ?)",
                (user_id, email, status),
            )
            conn.execute(
                "INSERT INTO age_eligibility (user_id, minimum_age, confirmed_at) "
                "VALUES (?, 18, ?)", (user_id, now.isoformat() + "Z"),
            )
            conn.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, NULL, NULL, 'test')",
                (
                    f"{user_id}-session", user_id, now.isoformat() + "Z",
                    (now + timedelta(hours=1)).isoformat() + "Z",
                    now.isoformat() + "Z",
                ),
            )
    with TestClient(app.qr_app, base_url="https://testserver") as client:
        yield app, client, db_path

    for name in tuple(sys.modules):
        if name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    sys.modules.pop("db", None)


def _auth(user_id):
    return {"Authorization": f"Bearer {user_id}-session"}


def _colors(start="#2A1B36", end="#8A280C"):
    return {"gradient_start": start, "gradient_end": end}


def test_saved_slots_are_private_fixed_and_idempotent(gradient_site):
    app, client, db_path = gradient_site
    first = client.put(
        "/api/qr/gradients/1", json=_colors("#2a1b36", "#8a280c"),
        headers=_auth("provider-a"),
    )
    assert first.status_code == 200
    assert first.json() == {"slot": 1, **_colors()}
    assert first.headers["Cache-Control"] == "private, no-store"

    second = client.put(
        "/api/qr/gradients/3", json=_colors("#153E3E", "#4B246B"),
        headers=_auth("provider-a"),
    )
    assert second.status_code == 200
    one = client.get("/api/qr/gradients", headers=_auth("provider-a"))
    assert one.status_code == 200
    assert one.headers["Cache-Control"] == "private, no-store"
    assert one.json() == {"slots": [first.json(), second.json()]}
    assert client.get("/api/qr/gradients", headers=_auth("provider-b")).json() == {"slots": []}

    replacement = client.put(
        "/api/qr/gradients/1", json=_colors("#153E3E", "#4B246B"),
        headers=_auth("provider-a"),
    )
    assert replacement.status_code == 200
    app.init_db()  # A repeat startup migration must not overwrite preferences.
    assert client.get("/api/qr/gradients", headers=_auth("provider-a")).json()["slots"][0] == replacement.json()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM qr_gradient_presets WHERE user_id = ?", ("provider-a",)
        ).fetchone()[0] == 2
        assert [row[1] for row in conn.execute("PRAGMA table_info(qr_gradient_presets)")] == [
            "user_id", "slot", "gradient_start", "gradient_end", "updated_at",
        ]

def test_account_separation_and_inactive_or_guest_denial(gradient_site):
    _, client, _ = gradient_site
    assert client.put("/api/qr/gradients/2", json=_colors(), headers=_auth("provider-a")).status_code == 200
    assert client.put(
        "/api/qr/gradients/2", json=_colors("#153E3E", "#4B246B"),
        headers=_auth("provider-b"),
    ).status_code == 200
    assert client.get("/api/qr/gradients", headers=_auth("provider-a")).json()["slots"][0] == {
        "slot": 2, **_colors(),
    }
    assert client.get("/api/qr/gradients", headers=_auth("provider-b")).json()["slots"][0] == {
        "slot": 2, **_colors("#153E3E", "#4B246B"),
    }
    assert len(client.get("/api/qr/gradients", headers=_auth("provider-a")).json()["slots"]) == 1
    for headers in ({}, _auth("provider-suspended")):
        assert client.get("/api/qr/gradients", headers=headers).status_code == 401
        assert client.put("/api/qr/gradients/1", json=_colors(), headers=headers).status_code == 401


@pytest.mark.parametrize("slot,payload", [
    (0, _colors()),
    (4, _colors()),
    (1, _colors("#FFFFFF", "#8A280C")),
    (1, _colors("red", "#8A280C")),
    (1, {"gradient_start": "#2A1B36"}),
    (1, {**_colors(), "url": "https://secret.example/path"}),
])
def test_invalid_slots_and_colors_are_not_saved(gradient_site, slot, payload):
    _, client, db_path = gradient_site
    response = client.put(f"/api/qr/gradients/{slot}", json=payload, headers=_auth("provider-a"))
    assert response.status_code == 400
    assert isinstance(response.json()["error"], str)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM qr_gradient_presets").fetchone()[0] == 0


def test_write_limit_and_origin_guard(gradient_site):
    _, client, _ = gradient_site
    cross_origin = client.put(
        "/api/qr/gradients/1", json=_colors(),
        headers={**_auth("provider-a"), "Origin": "https://attacker.example"},
    )
    assert cross_origin.status_code == 403
    assert client.get("/api/qr/gradients", headers=_auth("provider-a")).json() == {"slots": []}
    for _ in range(60):
        assert client.put("/api/qr/gradients/1", json=_colors(), headers=_auth("provider-a")).status_code == 200
    limited = client.put(
        "/api/qr/gradients/2", json=_colors("#153E3E", "#4B246B"),
        headers=_auth("provider-a"),
    )
    assert limited.status_code == 429
    assert limited.headers["Cache-Control"] == "private, no-store"
    assert client.get("/api/qr/gradients", headers=_auth("provider-a")).json()["slots"] == [
        {"slot": 1, **_colors()},
    ]


def test_account_export_and_deletion_include_only_owned_gradients(gradient_site):
    app, client, db_path = gradient_site
    assert client.put("/api/qr/gradients/1", json=_colors(), headers=_auth("provider-a")).status_code == 200
    assert client.put(
        "/api/qr/gradients/1", json=_colors("#153E3E", "#4B246B"),
        headers=_auth("provider-b"),
    ).status_code == 200
    export = app.get_user_export("a@example.com", "provider-a")
    assert len(export["qrGradientPresets"]) == 1
    assert export["qrGradientPresets"][0]["gradient_start"] == "#2A1B36"
    assert all(row["user_id"] == "provider-a" for row in export["qrGradientPresets"])
    assert app.delete_user_data("a@example.com", "provider-a") is True
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM qr_gradient_presets WHERE user_id = ?", ("provider-a",)
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM qr_gradient_presets WHERE user_id = ?", ("provider-b",)
        ).fetchone()[0] == 1
    assert client.get("/api/qr/gradients", headers=_auth("provider-a")).status_code == 401
