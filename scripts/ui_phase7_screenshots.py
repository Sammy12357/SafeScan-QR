"""Render Phase 7 before/after empty states with local, synthetic data.

Usage:
  python scripts/ui_phase7_screenshots.py --before-templates ../safescan-qr-ui-phase-3/templates

Requires Playwright and its Chromium browser in the local development environment.
No application server, account, or production data is used.
"""

from __future__ import annotations

import argparse
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


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass


def environment(directory: Path) -> Environment:
    env = Environment(loader=FileSystemLoader(str(directory)), autoescape=select_autoescape(["html"]))
    env.filters["time_only"] = lambda value: str(value or "")
    return env


def fixture_contexts() -> dict[str, tuple[str, dict]]:
    admin_request = type("AdminRequest", (), {
        "query_params": {}, "url": type("URL", (), {"path": "/admin/users"})(),
    })()
    return {
        "history": ("history.html", {"email": "scanner@example.test", "scans": [], "scan_groups": []}),
        "leaderboard": ("leaderboard.html", {"leaders": [], "current_user_id": None}),
        "profile": ("profile.html", {"email": "scanner@example.test", "username": "", "error": "",
                                    "discord_enabled": True, "discord_error": "", "discord_link": None,
                                    "is_admin": False}),
        "admin_users": ("admin_shell.html", {"request": admin_request, "title": "All Users", "page": "users",
                                              "data": {"filters": {"search": "", "status": "", "role": "", "tier": "", "flag": ""},
                                                       "rows": [], "page": 1, "pages": 1, "total": 0},
                                              "admin_user": {"email": "admin@example.test", "role": "owner"},
                                              "avatar": "A", "is_owner": True}),
        "consent_log": ("admin_table.html", {"title": "Consent Log", "body_html": "<table class='legal-table'><thead><tr><th>Time</th><th>User</th></tr></thead><tbody></tbody></table>",
                                             "message": "", "empty_state_title": "No consent records yet",
                                             "empty_state_body": "Consent decisions will appear here when they are recorded."}),
        "go_ghost": ("go_ghost.html", {"browser_automation_available": False,
                                       "go_ghost_account_id": "", "go_ghost_account_name": "",
                                       "go_ghost_account_email": "", "go_ghost_us_states": [],
                                       "go_ghost_brokers": [], "logged_in": False}),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--before-templates", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/design/screenshots/ui-phase-7")
    args = parser.parse_args()
    before = environment(args.before_templates.resolve())
    after = environment(ROOT / "templates")
    output = args.output.resolve()

    with TemporaryDirectory(prefix="safescan-ui-phase7-") as temp:
        temp_path = Path(temp)
        (temp_path / "static").symlink_to(ROOT / "static", target_is_directory=True)
        for name, (template, context) in fixture_contexts().items():
            for label, env in (("before", before), ("after", after)):
                destination = temp_path / label
                destination.mkdir(exist_ok=True)
                (destination / f"{name}.html").write_text(env.get_template(template).render(**context), encoding="utf-8")

        handler = partial(QuietHandler, directory=str(temp_path))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                for theme in THEMES:
                    for width in WIDTHS:
                        page = browser.new_page(viewport={"width": width, "height": 900}, device_scale_factor=1)
                        page.route("**/*", lambda route: route.abort() if route.request.url.split("?", 1)[0].endswith(".js") else route.continue_())
                        for label in ("before", "after"):
                            for name in fixture_contexts():
                                page.goto(f"http://127.0.0.1:{server.server_port}/{label}/{name}.html", wait_until="domcontentloaded")
                                page.evaluate("theme => document.documentElement.setAttribute('data-theme', theme)", theme)
                                page.evaluate("""() => {
                                    const banner = document.getElementById('cookieConsentBanner');
                                    if (banner) banner.style.display = 'none';
                                }""")
                                if name == "admin_users":
                                    page.locator(".admin-content").scroll_into_view_if_needed()
                                if name == "go_ghost":
                                    page.evaluate("""() => {
                                        document.getElementById('goGhostWorkspace').hidden = false;
                                        document.getElementById('goGhostWorkspace').style.display = 'grid';
                                        document.getElementById('goGhostConsentModal').style.display = 'none';
                                        document.getElementById('goGhostSessionNotice').style.display = 'none';
                                    }""")
                                page.evaluate("() => document.fonts.ready")
                                if name == "go_ghost":
                                    target = "#ghostFirstUseState" if label == "after" else "#goGhostProfileForm"
                                    page.locator(target).scroll_into_view_if_needed()
                                destination = output / label / theme / str(width)
                                destination.mkdir(parents=True, exist_ok=True)
                                page.screenshot(path=str(destination / f"{name}.jpg"), type="jpeg", quality=74)
                        page.close()
                browser.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    main()
