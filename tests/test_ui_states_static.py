"""Guard against regressions to browser dialogs and swallowed request failures."""

import re
from pathlib import Path


STATIC_JS = Path(__file__).resolve().parents[1] / "static"

# Request-bearing page scripts must add a reviewed terminal UI path whenever
# they add a raw fetch. Camera telemetry and worker bootstrap are intentional
# best-effort background requests and are outside this user-facing inventory.
RAW_FETCH_COUNTS = {
    "admin.js": 1,
    "app-core.js": 1,
    "app-generate-qr.js": 1,
    "app-go-ghost-ui.js": 2,
    "app-widgets.js": 2,
    "global_timer.js": 1,
    "token-unavailable.js": 2,
}
FETCH_ERROR_GUARDS = {
    "admin.js": ("showActorLookupWarning()",),
    "app-core.js": ("boundedWalletStep(", "showWalletFeedback(\"error\"", "showScanTimeout(form)"),
    "app-generate-qr.js": ("showError(", "controller.abort()"),
    "app-go-ghost-ui.js": ("ghostShowIssue(", "lockGhostWorkspace()"),
    "app-widgets.js": ("reportStatus.setAttribute(\"role\", \"alert\")", "UIStates.notice(feedback",),
    "global_timer.js": ("renderRuntimeUnavailable()", "controller.abort()"),
    "token-unavailable.js": ("Wallet status could not be checked", "Wallet disconnect did not complete"),
}


def test_page_scripts_do_not_use_blocking_alert_dialogs():
    offenders = [
        path.name
        for path in STATIC_JS.glob("*.js")
        if re.search(r"\bwindow\.alert\s*\(", path.read_text())
    ]
    assert offenders == []


def test_page_scripts_do_not_swallow_empty_promise_catches():
    offenders = [
        path.name
        for path in STATIC_JS.glob("*.js")
        if path.name not in {"qr-camera.js", "qr-camera-phase3.js", "qr-worker.js"}
        and re.search(
            r"\.catch\s*\(\s*(?:function\s*\([^)]*\)|(?:\([^)]*\)|\w+)\s*=>)\s*\{\s*\}\s*\)",
            path.read_text(),
        )
    ]
    assert offenders == []


def test_page_fetches_have_reviewed_terminal_error_paths():
    found = {}
    for path in STATIC_JS.glob("*.js"):
        if path.name in {"qr-camera.js", "qr-camera-phase3.js", "qr-worker.js", "ui-states.js"}:
            continue
        count = len(re.findall(r"(?<!\.)\bfetch\s*\(", path.read_text()))
        if count:
            found[path.name] = count
    assert found == RAW_FETCH_COUNTS
    for filename, guards in FETCH_ERROR_GUARDS.items():
        source = (STATIC_JS / filename).read_text()
        for guard in guards:
            assert guard in source, (filename, guard)
    for filename, terminal in {
        "leaderboard.js": "UIStates.notice(refreshState",
        "malicious-database.js": "UIStates.error(stateEl",
    }.items():
        source = (STATIC_JS / filename).read_text()
        assert "UIStates.fetchJson(" in source
        assert ".catch(function (problem)" in source
        assert terminal in source
