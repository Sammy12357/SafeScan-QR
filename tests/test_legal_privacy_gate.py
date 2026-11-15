"""Fail when first-party storage or blocked trackers are added without review."""

from __future__ import annotations

import ast
from html import unescape
import importlib
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
    age_gate = (ROOT / "hackabull/age_gate.py").read_text()
    cookies += re.findall(r"\b\w*COOKIE\s*=\s*['\"]([^'\"]+)['\"]", age_gate)
    assert cookies
    assert all(cookie in INVENTORY for cookie in cookies), set(cookies) - {c for c in cookies if c in INVENTORY}


def test_cookie_policy_table_matches_first_party_storage_inventory_and_runtime_names():
    """Source and runtime guard; production browser/provider storage still needs audit."""
    admin_source = (ROOT / "hackabull/admin_data.py").read_text()
    assignment = next(node for node in ast.parse(admin_source).body
                      if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                      and target.id == "COOKIE_POLICY_HTML" for target in node.targets))
    policy = ast.literal_eval(assignment.value)
    snapshot = (ROOT / "hackabull/legal_published/cookie.v1.1.html").read_text()
    assert snapshot == policy
    rows = re.findall(r"<tr><td><code>(.*?)</code></td><td>(Cookie|Local storage|Session storage)</td>", policy)
    policy_by_kind = {
        kind: {unescape(name) for name, storage in rows if storage == kind}
        for kind in ("Cookie", "Local storage", "Session storage")
    }
    assert len(rows) == sum(len(names) for names in policy_by_kind.values())
    inventory_by_kind = {}
    section_titles = (("Cookie", "## First-party cookies", "## First-party `localStorage`"),
                      ("Local storage", "## First-party `localStorage`", "## First-party `sessionStorage`"),
                      ("Session storage", "## First-party `sessionStorage`", "## Legacy and policy-only keys"))
    for kind, start, end in section_titles:
        section = INVENTORY.split(start, 1)[1].split(end, 1)[0]
        inventory_by_kind[kind] = set(re.findall(r"^\| `([^`]+)` \|", section, re.M))

    config = importlib.import_module("hackabull.config")
    age_gate = importlib.import_module("hackabull.age_gate")
    cookie_names = {config.SESSION_COOKIE_NAME, config.REMEMBER_ME_COOKIE_NAME,
                    age_gate.PENDING_COOKIE, age_gate.ADULT_CHALLENGE_COOKIE,
                    age_gate.GUEST_ADULT_COOKIE}

    literal_writes = {"Local storage": set(), "Session storage": set()}
    for path in STATIC.glob("*.js"):
        source = path.read_text()
        assignments = dict(re.findall(r"\b(?:const|let|var)\s+(\w+)\s*=\s*['\"]([^'\"]+)['\"]", source))
        for storage, key_expression in re.findall(r"\b(?:window\.)?(localStorage|sessionStorage)\.setItem\(\s*([^,]+),", source):
            expression = key_expression.strip()
            key = expression[1:-1] if expression.startswith(("'", '"')) else assignments.get(expression)
            if key:
                literal_writes["Local storage" if storage == "localStorage" else "Session storage"].add(key)
    ghost = (STATIC / "app-go-ghost.js").read_text()
    admin = (STATIC / "admin.js").read_text()
    assert "safeScanGoGhostV2:account:${encodeURIComponent(goGhostAccountId)}" in ghost
    assert '"safeScanGoGhostV2:guest"' in ghost
    assert "safescan:actor-email:${rawActor}" in admin
    expected_by_kind = {
        "Cookie": cookie_names,
        "Local storage": literal_writes["Local storage"] | {"safeScanGoGhostV2:account:<encoded account id>"},
        "Session storage": literal_writes["Session storage"] | {"safeScanGoGhostV2:guest", "safescan:actor-email:<actor id>"},
    }
    for kind, expected in expected_by_kind.items():
        assert expected, kind
        assert policy_by_kind[kind] == expected, (kind, policy_by_kind[kind] ^ expected)
        assert inventory_by_kind[kind] == expected, (kind, inventory_by_kind[kind] ^ expected)
    assert "safeScanReports" not in policy
