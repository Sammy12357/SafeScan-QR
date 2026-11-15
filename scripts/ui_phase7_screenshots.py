"""Capture Phase 7 empty-state views with synthetic before/after data.

Usage:
  python scripts/ui_phase7_screenshots.py --before-templates ../safescan-qr/templates

Before and after pages use their own static assets. Requires Playwright Chromium.
No application server, account, or production data is used.
"""

from __future__ import annotations

import argparse
import subprocess
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from jinja2 import Environment, FileSystemLoader, select_autoescape
from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (375, 768, 1440)
THEMES = ("dark", "light")
ADMIN_USER = {"email": "admin@example.test", "role": "owner"}
EMPTY_SCAN_STATS = {"total": 0, "flagged_today": 0, "avg_risk": 0, "common_tld": "—"}
EMPTY_USER_FILTERS = {"search": "", "status": "", "role": "", "tier": "", "flag": ""}


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass


def environment(directory: Path) -> Environment:
    env = Environment(loader=FileSystemLoader(str(directory)), autoescape=select_autoescape(["html"]))
    env.filters["time_only"] = lambda value: str(value or "")
    return env


def admin_fixture(title: str, page: str, data: dict, path: str, query: dict | None = None) -> tuple[str, dict]:
    url = type("URL", (), {"path": path})()
    request = type("AdminRequest", (), {"query_params": query or {}, "url": url})()
    return "admin_shell.html", {
        "request": request, "title": title, "page": page, "data": data,
        "admin_user": ADMIN_USER, "avatar": "A", "is_owner": True,
    }


def fixture_contexts() -> dict[str, tuple[str, dict]]:
    empty_users = {"filters": EMPTY_USER_FILTERS.copy(), "rows": [], "page": 1, "pages": 1, "total": 0}
    filtered_users = {**empty_users, "filters": {**EMPTY_USER_FILTERS, "search": "no-match@example.test"}}
    empty_scans = {"rows": [], "stats": EMPTY_SCAN_STATS.copy()}
    empty_waitlist = {"total": 0, "rows": [], "filters": {"search": ""}}
    empty_airdrop = {
        "wallet_users": [], "qualified": [], "estimated_total": 0,
        "distributed_total": 0, "tier_counts": {"Scanner": 0, "Referrer": 0, "Guardian": 0},
        "flagged": [], "base_allocation": 0,
    }
    detail_user = {
        "email": "scanner@example.test", "display_name": "Test Scanner", "status": "active",
        "role": "user", "created_at": "2026-11-01", "last_login_at": None,
        "last_login": None, "scan_count": 0, "wallet_address": None,
    }
    ambiguous_user = {
        "google_id": "account-A", "email": "shared@example.test", "display_name": "Shared Email A",
        "status": "active", "role": "user", "tier": "Registered", "scan_count": 0,
        "referral_count": 0, "wallet_address": None, "created_at": "2026-11-01",
        "last_login_at": None, "last_login": None, "ambiguous_email": 1,
    }
    ghost_context = {
        "browser_automation_available": False, "go_ghost_account_id": "",
        "go_ghost_account_name": "", "go_ghost_account_email": "",
        "go_ghost_us_states": [], "go_ghost_brokers": [], "logged_in": False,
    }
    return {
        "history": ("history.html", {"email": "scanner@example.test", "scans": [], "scan_groups": []}),
        "history_guest": ("history.html", {"email": "", "scans": [], "scan_groups": []}),
        "leaderboard": ("leaderboard.html", {"leaders": [], "current_user_id": None}),
        "profile": ("profile.html", {
            "email": "scanner@example.test", "username": "", "error": "",
            "discord_enabled": True, "discord_error": "", "discord_link": None, "is_admin": False,
        }),
        "scan_result": ("index.html", {
            "results_visible": True, "risk_reasons": [{"check": "ML Risk Model"}],
            "status": "CAUTION", "score": 50, "url_found": "", "overall_risk": "medium",
            "logged_in": False, "payload_type": "TEXT", "verification_status": "unverified",
            "decoded_payload": "Synthetic QR payload", "threat_class": "Unverified content",
        }),
        "go_ghost": ("go_ghost.html", ghost_context),
        "go_ghost_brokers": ("go_ghost.html", ghost_context),
        "consent_log": ("admin_table.html", {
            "title": "Consent Log", "body_html": "<table class='legal-table'><thead><tr><th>Time</th><th>User</th></tr></thead><tbody></tbody></table>",
            "message": "", "empty_state_title": "No consent records yet",
            "empty_state_body": "Consent decisions will appear here when they are recorded.",
        }),
        "admin_dashboard": admin_fixture("Dashboard", "dashboard", {
            "stats": [], "chart_rows": [], "verdict_rows": [], "recent_users": [],
            "recent_reports": [], "activity": [],
        }, "/admin"),
        "admin_activity": admin_fixture("Activity Feed", "logs", {"rows": [], "actions": []}, "/admin/activity"),
        "admin_users": admin_fixture("All Users", "users", empty_users, "/admin/users"),
        "admin_users_filtered": admin_fixture("All Users", "users", filtered_users, "/admin/users", {"search": "no-match@example.test"}),
        "admin_users_ambiguous": admin_fixture("All Users", "users", {
            "filters": EMPTY_USER_FILTERS.copy(), "rows": [ambiguous_user],
            "page": 1, "pages": 1, "total": 1,
        }, "/admin/users"),
        "admin_user_drawer": admin_fixture("User Detail", "user_drawer", {
            "user": detail_user, "flags": [], "logs": [], "scans": [],
        }, "/admin/users/scanner@example.test/drawer"),
        "admin_user_drawer_ambiguous": admin_fixture("User Detail", "user_drawer", {
            "user": {**detail_user, "email": "shared@example.test", "display_name": "Shared Email A",
                     "ownership_ambiguous": True, "scan_history_withheld": True},
            "flags": [], "logs": [], "scans": [],
        }, "/admin/users/detail", {"account_id": "account-A"}),
        "admin_scans": admin_fixture("All Scans", "scans", empty_scans, "/admin/scans"),
        "admin_scans_filtered": admin_fixture("All Scans", "scans", empty_scans, "/admin/scans", {"search": "no-match"}),
        "admin_risk_logs": admin_fixture("Risk Engine Logs", "scans", empty_scans, "/admin/risk-logs"),
        "admin_waitlist": admin_fixture("Waitlist", "waitlist", empty_waitlist, "/admin/waitlist"),
        "admin_waitlist_filtered": admin_fixture("Waitlist", "waitlist", {
            **empty_waitlist, "filters": {"search": "no-match@example.test"},
        }, "/admin/waitlist", {"search": "no-match@example.test"}),
        "admin_reports": admin_fixture("Reported URLs", "reports", {"tab": "reports", "reports": []}, "/admin/reports"),
        "admin_blocklist": admin_fixture("Blocklist", "reports", {"tab": "blocklist", "blocklist": []}, "/admin/reports", {"tab": "blocklist"}),
        "admin_airdrop": admin_fixture("Tier Overview", "airdrop", empty_airdrop, "/admin/airdrop"),
        "admin_airdrop_ambiguous": admin_fixture("Tier Overview", "airdrop", {
            **empty_airdrop, "wallet_users": [{
                **ambiguous_user, "wallet_address": "SyntheticWalletAddress",
                "estimated_sqr": 0, "distribution_status": "pending", "fraud_flags": 0,
            }],
        }, "/admin/airdrop"),
        "admin_wallet_registry": admin_fixture("Wallet Registry", "airdrop", empty_airdrop, "/admin/airdrop/wallets"),
        "admin_fraud": admin_fixture("Fraud Flags", "fraud", {"rows": []}, "/admin/airdrop/fraud"),
        "admin_fraud_unassigned": admin_fixture("Fraud Flags", "fraud", {"rows": [{
            "google_id": None, "email": "shared@example.test", "fraud_score": 0,
            "signal_count": 1, "highest_severity": "medium", "wallet_address": None,
            "airdrop_status": "Unassigned", "flag_date": "2026-11-04", "ambiguous_email": 1,
        }]}, "/admin/airdrop/fraud"),
        "admin_logs": admin_fixture("Audit Logs", "logs", {"rows": [], "actions": []}, "/admin/logs"),
        "admin_logs_filtered": admin_fixture("Audit Logs", "logs", {"rows": [], "actions": []}, "/admin/logs", {"action": "no-match"}),
        "admin_api_keys": admin_fixture("API Keys", "api_keys", {"keys": []}, "/admin/api-keys"),
    }


def serve(directory: Path) -> tuple[ThreadingHTTPServer, Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=str(directory)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def prepare_page(page, name: str, label: str, theme: str) -> None:
    page.evaluate("theme => document.documentElement.setAttribute('data-theme', theme)", theme)
    page.evaluate("""() => {
        const banner = document.getElementById('cookieConsentBanner');
        if (banner) banner.style.display = 'none';
    }""")
    if name.startswith("go_ghost"):
        page.evaluate("""showBrokerState => {
            const workspace = document.getElementById('goGhostWorkspace');
            workspace.hidden = false;
            workspace.style.display = 'grid';
            document.getElementById('goGhostConsentModal').style.display = 'none';
            document.getElementById('goGhostSessionNotice').style.display = 'none';
            if (showBrokerState && document.getElementById('goGhostNoBrokerState')) {
                document.getElementById('goGhostNoBrokerState').hidden = false;
            }
        }""", name == "go_ghost_brokers")
    page.evaluate("() => document.fonts.ready")
    if name == "scan_result":
        page.locator(".reason-accordion").scroll_into_view_if_needed()
    if name == "go_ghost":
        page.locator("#ghostFirstUseState" if label == "after" else "#goGhostProfileForm").scroll_into_view_if_needed()
    if name == "go_ghost_brokers":
        page.locator("#goGhostNoBrokerState" if label == "after" else ".ghost-automation-table").scroll_into_view_if_needed()


def write_readme(output: Path, fixtures: dict, before_templates: Path) -> None:
    result = subprocess.run(
        ["git", "-C", str(before_templates.parent), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    baseline = result.stdout.strip() if result.returncode == 0 else "unknown"
    rows = [
        "# Phase 7 empty-state comparisons",
        "",
        f"Before baseline: `{baseline}`. After: current `codex/ui-phase-7` working tree.",
        "",
        "Synthetic, nonproduction data is rendered through Jinja. Each side uses the matching tree's CSS and assets. "
        "JavaScript is disabled to keep the server-rendered states stable. Captures cover the full page at 375, 768, and 1440 px in both themes.",
        "",
        "| View | Dark 375 | Dark 768 | Dark 1440 | Light 375 | Light 768 | Light 1440 |",
        "|---|---|---|---|---|---|---|",
    ]
    for name in fixtures:
        links = []
        for theme in THEMES:
            for width in WIDTHS:
                links.append(
                    f"[before](before/{theme}/{width}/{name}.jpg) / [after](after/{theme}/{width}/{name}.jpg)"
                )
        rows.append(f"| {name.replace('_', ' ').title()} | " + " | ".join(links) + " |")
    rows.extend(["", "The `admin_user_drawer` before image shows the previously blank main area for an existing account. The ambiguous-account fixtures use synthetic rows on both sides to show how the new controls handle shared email ownership; no production account data appears in these images.", ""])
    (output / "README.md").write_text("\n".join(rows), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before-templates", required=True, type=Path)
    parser.add_argument("--before-static", type=Path, help="Defaults to the static directory beside --before-templates")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/design/screenshots/ui-phase-7")
    args = parser.parse_args()
    before_templates = args.before_templates.resolve()
    before_static = (args.before_static or before_templates.parent / "static").resolve()
    if not before_static.is_dir():
        parser.error(f"Before static assets not found: {before_static}")
    fixtures = fixture_contexts()
    output = args.output.resolve()

    with TemporaryDirectory(prefix="safescan-ui-phase7-") as temp:
        temp_path = Path(temp)
        servers = {}
        for label, template_dir, static_dir in (
            ("before", before_templates, before_static),
            ("after", ROOT / "templates", ROOT / "static"),
        ):
            root = temp_path / label
            root.mkdir()
            (root / "static").symlink_to(static_dir, target_is_directory=True)
            env = environment(template_dir)
            for name, (template, context) in fixtures.items():
                (root / f"{name}.html").write_text(env.get_template(template).render(**context), encoding="utf-8")
            servers[label] = serve(root)

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                for theme in THEMES:
                    for width in WIDTHS:
                        page = browser.new_page(viewport={"width": width, "height": 900}, device_scale_factor=1)
                        page.route("**/*", lambda route: route.abort() if route.request.url.split("?", 1)[0].endswith(".js") else route.continue_())
                        for label in ("before", "after"):
                            server, _ = servers[label]
                            for name in fixtures:
                                page.goto(f"http://127.0.0.1:{server.server_port}/{name}.html", wait_until="domcontentloaded")
                                prepare_page(page, name, label, theme)
                                destination = output / label / theme / str(width)
                                destination.mkdir(parents=True, exist_ok=True)
                                page.screenshot(path=str(destination / f"{name}.jpg"), type="jpeg", quality=74, full_page=True)
                        page.close()
                browser.close()
            write_readme(output, fixtures, before_templates)
        finally:
            for server, thread in servers.values():
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    main()
