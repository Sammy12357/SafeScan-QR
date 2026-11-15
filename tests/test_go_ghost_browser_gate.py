"""The public web service must not start a third-party browser session."""

import importlib
import json
import re
import sqlite3
import subprocess
import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]


def test_production_image_excludes_unused_browser_runtime():
    """The fixed-off server automation gate must not ship Chromium or Playwright."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    runtime_requirements = (ROOT / "requirements.txt").read_text()
    runtime_lock = (ROOT / "requirements.lock").read_text()
    dev_requirements = (ROOT / "requirements-dev.txt").read_text()
    dev_lock = (ROOT / "requirements-dev.lock").read_text()

    assert "playwright" not in dockerfile.lower()
    assert "chromium" not in dockerfile.lower()
    assert "ms-playwright" not in dockerfile.lower()
    assert not re.search(r"^playwright(?:[=<>]|$)", runtime_requirements, re.MULTILINE)
    assert not re.search(r"^playwright==", runtime_lock, re.MULTILINE)
    assert re.search(r"^playwright(?:[=<>]|$)", dev_requirements, re.MULTILINE)
    assert re.search(r"^playwright==", dev_lock, re.MULTILINE)


@pytest.fixture()
def go_ghost_app(tmp_path, monkeypatch, request):
    database = tmp_path / "go-ghost-gate.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://sqafe.com" if request.param else "http://localhost:8000")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    if request.param:
        monkeypatch.setenv("RENDER", "true")
    else:
        monkeypatch.delenv("RENDER", raising=False)
    # Even a plausible-sounding environment switch cannot authorize an
    # unsandboxed browser inside the app service.
    monkeypatch.setenv("GO_GHOST_BROWSER_AUTOMATION_ENABLED", "true")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    routes = importlib.import_module("hackabull.routes_pages")
    app.RATE_LIMITS.clear()
    yield TestClient(app.qr_app, base_url="https://testserver"), routes, database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


@pytest.mark.parametrize("go_ghost_app", [True, False], indirect=True)
def test_browser_automation_is_closed_before_engine_import_or_job_creation(go_ghost_app, monkeypatch):
    client, routes, database = go_ghost_app
    assert routes.GO_GHOST_BROWSER_AUTOMATION_AVAILABLE is False
    payload = {"name": "Example Person", "email": "person@example.com"}
    anonymous = client.post("/api/go-ghost/removals/fastpeoplesearch", json=payload)
    assert anonymous.status_code == 401

    monkeypatch.setattr(routes, "require_user", lambda request: {"google_id": "user-1", "email": "person@example.com"})
    # Importing this sentinel would fail. A 503 proves the route stops before
    # importing the engine, even for an authenticated, valid broker request.
    monkeypatch.setitem(sys.modules, "removals.engine", types.ModuleType("removals.engine"))
    response = client.post("/api/go-ghost/removals/fastpeoplesearch", json=payload)

    assert response.status_code == 503
    assert "Assisted broker submissions are unavailable" in response.json()["error"]
    assert "Copy details" in response.json()["error"]
    assert response.headers["Cache-Control"] == "no-store"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM go_ghost_removal_jobs").fetchone()[0] == 0


@pytest.mark.parametrize("go_ghost_app", [True], indirect=True)
def test_production_page_keeps_manual_opt_out_controls(go_ghost_app):
    client, _, _ = go_ghost_app
    response = client.get("/go-ghost")

    assert response.status_code == 200
    assert 'data-browser-automation-available="false"' in response.text
    assert "Assisted browser submissions are temporarily unavailable." in response.text
    assert "Broker search links may include your name and city/state" in response.text
    assert "Search next broker" in response.text
    assert 'id="goGhostScopeSearchButton"' in response.text
    assert 'id="goGhostScopeOptOutButton"' in response.text
    assert 'id="goGhostScopeCopyButton"' in response.text
    assert 'id="startGhostQueueButton"' not in response.text
    assert 'id="goGhostScopeAutoFillButton"' not in response.text
    assert "Backend does" not in response.text
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("go_ghost_app", [True], indirect=True)
def test_go_ghost_browser_scope_uses_session_owner_id(go_ghost_app, monkeypatch):
    client, routes, _ = go_ghost_app
    monkeypatch.setattr(routes, "get_session_user", lambda request: {
        "google_id": "account-a", "email": "person@example.com",
        "display_name": "Amy & Lee", "role": "user",
    })
    response = client.get("/go-ghost")
    assert response.status_code == 200
    assert 'data-account-id="account-a"' in response.text
    assert 'data-account-name="Amy &amp; Lee"' in response.text
    assert 'data-account-email="person@example.com"' in response.text
    assert 'id="ghostFirstNameInput"' in response.text
    assert 'id="ghostStateInput"' in response.text
    assert 'value="DC">District of Columbia</option>' in response.text
    assert response.text.count('<option value="') >= 52
    assert response.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("go_ghost_app", [True], indirect=True)
def test_go_ghost_refuses_authenticated_user_without_owner_id(go_ghost_app, monkeypatch):
    client, routes, _ = go_ghost_app
    monkeypatch.setattr(routes, "get_session_user", lambda request: {
        "email": "person@example.com", "role": "user",
    })
    response = client.get("/go-ghost")
    assert response.status_code == 503
    assert "Go Ghost account identity is unavailable" in response.json()["error"]


@pytest.mark.parametrize("go_ghost_app", [True], indirect=True)
def test_retired_legacy_go_ghost_page_is_not_public(go_ghost_app):
    client, _, _ = go_ghost_app
    assert client.get("/static/go-ghost.html").status_code == 404
    assert client.get("/go-ghost").status_code == 200


@pytest.mark.parametrize("go_ghost_app", [True], indirect=True)
def test_broker_api_and_embedded_manual_directory_agree(go_ghost_app):
    client, _, _ = go_ghost_app
    response = client.get("/api/go-ghost/brokers")
    assert response.status_code == 200
    records = response.json()["brokers"]
    assert len(records) == len({broker["id"] for broker in records}) == 18
    assert all("automationEnabled" not in broker for broker in records)
    assert all(broker["lastVerified"] is None for broker in records)

    page = client.get("/go-ghost").text
    embedded = re.search(
        r'<script id="goGhostBrokerRegistry" type="application/json">(.*?)</script>',
        page,
        re.DOTALL,
    )
    assert embedded is not None
    assert json.loads(embedded.group(1)) == records

    by_id = {broker["id"]: broker for broker in records}
    assert by_id["peoplelooker"]["sourceCheckedAt"] == "2026-11-14"
    assert "sourceCheckedAt" not in by_id["radaris"]
    assert {by_id[brand]["group"] for brand in ("intelius", "ussearch", "instantcheckmate", "truthfinder")} == {"peopleconnect"}
    assert len({by_id[brand]["group"] for brand in ("beenverified", "peoplelooker", "neighborwho")}) == 3

    from removals.engine import BROKER_CONFIGS

    assert all(config.optout_url == by_id[broker_id]["removalUrl"] for broker_id, config in BROKER_CONFIGS.items())


def test_public_broker_registry_rejects_profile_fields_and_offsite_links(tmp_path, monkeypatch):
    from removals import registry

    original_records = json.loads(registry.REGISTRY_PATH.read_text(encoding="utf-8"))
    sample = tmp_path / "brokers.json"
    monkeypatch.setattr(registry, "REGISTRY_PATH", sample)
    try:
        for change in ("profile", "userinfo", "search_fields", "offsite_search"):
            records = json.loads(json.dumps(original_records))
            if change == "profile":
                records[0]["email"] = "person@example.test"
            elif change == "userinfo":
                records[0]["removalUrl"] = "https://person:secret@www.fastpeoplesearch.com/optout"
            elif change == "search_fields":
                records[0]["search"]["profile"] = {"name": "Example Person"}
            else:
                records[0]["search"]["baseUrl"] = "https://other.example/name/"
            sample.write_text(json.dumps(records), encoding="utf-8")
            registry.load_brokers.cache_clear()
            with pytest.raises(ValueError):
                registry.load_brokers()
    finally:
        registry.load_brokers.cache_clear()


def test_manual_browser_ui_has_no_automation_button_or_personal_details_in_url():
    script = r"""
const fs = require('fs');
const vm = require('vm');
const elements = {
  goGhostBrokerList: {innerHTML: ''},
  goGhostAutomationRows: {innerHTML: ''},
  goGhostBrokerRegistry: {textContent: fs.readFileSync('data/go_ghost/brokers.json', 'utf8')}
};
const context = vm.createContext({
  document: {getElementById: id => elements[id] || null}, window: {}, URL,
  readJsonStorage: (_key, fallback) => fallback, escapeHtml: value => String(value)
});
vm.runInContext(fs.readFileSync('static/app-go-ghost.js', 'utf8'), context);
vm.runInContext(fs.readFileSync('static/app-go-ghost-ui.js', 'utf8'), context);
vm.runInContext('renderGoGhostBrokers(); renderGoGhostAutomationScope();', context);
const result = vm.runInContext(`({
  available: GO_GHOST_BROWSER_AUTOMATION_AVAILABLE,
  url: goGhostBrokerOptOutUrl({removalUrl: 'https://broker.example/optout'},
    {name: 'Example Person', email: 'person@example.com'}),
  lane: ghostEffortLane({automationEnabled: true, requiredInfo: []}).label,
  packet: goGhostCopyPacket({name: 'Example Broker', removalUrl: 'https://broker.example/optout', requiredInfo: []},
    {name: 'Example Person', email: 'person@example.com'}, 'https://broker.example/search')
})`, context);
if (result.available !== false || result.url !== 'https://broker.example/optout' ||
    result.lane !== 'Manual' || !result.packet.includes('complete the request in your browser.') ||
    elements.goGhostBrokerList.innerHTML.includes('data-ghost-auto=') ||
    !elements.goGhostBrokerList.innerHTML.includes('data-ghost-copy=') ||
    !elements.goGhostBrokerList.innerHTML.includes('data-ghost-optout=') ||
    !elements.goGhostAutomationRows.innerHTML.includes('Manual')) {
  process.exit(1);
}
"""
    subprocess.run(["node", "-e", script], cwd=ROOT, check=True)
