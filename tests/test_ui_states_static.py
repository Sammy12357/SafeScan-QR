"""Guard against regressions to browser dialogs and swallowed request failures."""

import re
from pathlib import Path


STATIC_JS = Path(__file__).resolve().parents[1] / "static"


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
        if re.search(r"\.catch\s*\(\s*function\s*\([^)]*\)\s*\{\s*\}\s*\)", path.read_text())
    ]
    assert offenders == []
