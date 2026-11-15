"""Fail when first-party storage or blocked trackers are added without review."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
TEMPLATES = ROOT / "templates"
INVENTORY = (ROOT / "docs/legal/storage-inventory.md").read_text()

# These hosts are not in SafeScan's vendor inventory. A proposed addition
# requires an explicit design, disclosure, and attorney review before this
# guard is changed. Search the shipped assets, not documentation or tests.
BLOCKED_TRACKERS = (
    "hotjar.com", "google-analytics.com", "googletagmanager.com",
    "doubleclick.net", "facebook.com/tr", "fullstory.com",
    "clarity.ms", "segment.io", "mixpanel.com", "posthog.com",
    "intercom.io",
)


def test_no_unreviewed_tracking_hosts_in_shipped_assets():
    sources = [*STATIC.glob("*.js"), *STATIC.glob("*.css"), *TEMPLATES.glob("*.html"), ROOT / "hackabull/app_module.py"]
    offenders = [f"{path.relative_to(ROOT)}: {host}" for path in sources
                 for host in BLOCKED_TRACKERS if host in path.read_text().lower()]
    assert not offenders, "Unreviewed tracker host in shipped asset: " + ", ".join(offenders)


def test_literal_browser_storage_writes_are_in_inventory():
    written = set()
    for path in STATIC.glob("*.js"):
        source = path.read_text()
        assignments = dict(re.findall(r"\b(?:const|let|var)\s+(\w+)\s*=\s*['\"]([^'\"]+)['\"]", source))
        for match in re.finditer(r"\b(?:localStorage|sessionStorage)\.setItem\(\s*([^,]+),", source):
            expression = match.group(1).strip()
            if expression.startswith(('"', "'")):
                written.add(expression[1:-1])
            elif expression in assignments:
                written.add(assignments[expression])
    assert written
    assert all(key in INVENTORY for key in written), written - {key for key in written if key in INVENTORY}


def test_dynamic_browser_keys_and_server_cookies_are_in_inventory():
    ghost = (STATIC / "app-go-ghost.js").read_text()
    admin = (STATIC / "admin.js").read_text()
    assert "safeScanGoGhostV2:account:" in ghost and "safeScanGoGhostV2:account:" in INVENTORY
    assert "safeScanGoGhostV2:guest" in ghost and "safeScanGoGhostV2:guest" in INVENTORY
    assert "safescan:actor-email:" in admin and "safescan:actor-email:" in INVENTORY
    config = (ROOT / "hackabull/config.py").read_text()
    cookies = re.findall(r"\b\w*COOKIE_NAME\s*=\s*['\"]([^'\"]+)['\"]", config)
    assert cookies
    assert all(cookie in INVENTORY for cookie in cookies), set(cookies) - {c for c in cookies if c in INVENTORY}
