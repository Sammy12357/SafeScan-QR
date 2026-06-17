"""Static-source checks for the Go Ghost multi-broker automation wiring.

These assert the frontend and backend agree on the eight automation-enabled
brokers and the assisted-queue flow, without needing a browser or Playwright.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
# app.js was split into ordered app-*.js files; scan them all together.
APP_JS = "\n".join(
    p.read_text(encoding="utf-8") for p in sorted((ROOT / "static").glob("app-*.js"))
)
# The backend was split from a single hackabull.py into a hackabull/ package;
# scan every module so these source assertions are location-independent.
SERVER = "\n".join(
    p.read_text(encoding="utf-8") for p in sorted((ROOT / "hackabull").glob("*.py"))
)
ENGINE = (ROOT / "removals" / "engine.py").read_text(encoding="utf-8")


def test_frontend_enables_eight_brokers_for_automation():
    assert APP_JS.count("automationEnabled: true") == 8


def test_assisted_queue_runs_backend_autofill_sequentially():
    # The "Start assisted queue" button must drive the backend runner for each
    # pending broker, not just scroll to the next one.
    assert "async function startGhostAssistedQueue" in APP_JS
    assert "runGhostBrokerAutomation(broker, null)" in APP_JS
    assert "broker.automationEnabled" in APP_JS


def test_queue_treats_manual_checkpoints_explicitly():
    assert 'GHOST_MANUAL_STATUSES = ["captcha_required", "email_required", "needs_profile_url"]' in APP_JS


def test_email_required_counts_as_submitted():
    assert 'automation.status === "email_required"' in APP_JS


def test_status_labels_cover_new_checkpoints():
    assert "email_required:" in APP_JS
    assert "needs_profile_url:" in APP_JS


def test_backend_dispatches_through_supported_broker_registry():
    assert "from removals.engine import RemovalProfile, run_broker_removal, supported_broker" in SERVER
    assert "broker_config = supported_broker(normalized_broker)" in SERVER
    # The old single-broker guard must be gone.
    assert 'if normalized_broker != "fastpeoplesearch"' not in SERVER


def test_engine_is_config_driven():
    assert "BROKER_CONFIGS" in ENGINE
    assert "async def run_broker_removal" in ENGINE
    # Record-based checkpoint and email-verification checkpoint are returned.
    assert '"status": "needs_profile_url"' in ENGINE
    assert '"status": "email_required"' in ENGINE
    assert '"status": "captcha_required"' in ENGINE
