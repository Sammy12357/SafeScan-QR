#!/usr/bin/env python3
"""Capture SafeScan UI baselines with an isolated, local mock-mode server.

Requires the development dependency ``playwright`` and an installed Chromium:

    python -m pip install -r requirements-dev.txt
    python -m playwright install chromium
    python scripts/ui_screenshots.py
    python scripts/ui_screenshots.py --views states_empty,states_loading,states_error,states_notice,states_content

The script uses a throwaway SQLite database, synthetic local-only accounts,
and a child process without inherited credentials or .env loading. It never
targets the production SafeScan service, changes app behavior, or injects UI
states. Existing external font requests in the templates may still load.
The mock-only gallery fixture views include empty, loading, error, notice,
and content examples. Query values come from an allowlist in the server route.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
WIDTHS = (375, 768, 1440)
THEMES = ("dark", "light")


@dataclass(frozen=True)
class View:
    name: str
    path: str
    audience: str = "guest"  # guest, member, owner
    final_path: str | None = None
    consent_prompt: bool = False


# Distinct current page views and route variants. Secret-bearing POST responses,
# real scan payloads, and personal export data are intentionally excluded.
VIEWS = (
    View("home", "/"),
    View("cookie_preferences", "/", consent_prompt=True),
    View("test_site", "/test-site"),
    View("history_signed_out", "/history"),
    View("history_first_use", "/history", "member"),
    View("leaderboard", "/leaderboard"),
    View("malicious_database", "/malicious-database"),
    View("go_ghost_guest", "/go-ghost", final_path="/auth/confirm-adult"),
    View("go_ghost_signed_in", "/go-ghost", "member"),
    View("generate_qr", "/generate-qr"),
    View("login", "/login"),
    View("confirm_adult", "/auth/confirm-adult"),
    View("profile", "/profile", "member"),
    View("onboarding_redirect", "/onboarding/username", "member", "/profile"),
    View("data_request", "/legal/data-request"),
    View("token_guest", "/token", final_path="/auth/confirm-adult"),
    View("token_member", "/token", "member"),
    View("plans", "/plans"),
    View("learn", "/learn"),
    View("alpha_payment", "/pay/alpha", final_path="/auth/confirm-adult"),
    View("alpha_success", "/pay/alpha/success"),
    View("privacy", "/legal/privacy-policy"),
    View("terms", "/legal/terms-of-use"),
    View("cookies", "/legal/cookie-policy"),
    View("security", "/legal/security"),
    View("contact", "/contact"),
    View("risk_engine", "/risk-engine"),
    View("resources_docs", "/resources/docs"),
    View("do_not_sell", "/legal/do-not-sell"),
    View("account_settings", "/account/settings", "member"),
    View("admin_dashboard", "/admin", "owner"),
    View("admin_activity", "/admin/activity", "owner"),
    View("admin_users", "/admin/users", "owner"),
    View("admin_user_drawer", "/admin/users/ui-shots-owner%40example.test/drawer", "owner"),
    View("admin_users_filtered", "/admin/users?status=suspended", "owner"),
    View("admin_scans", "/admin/scans", "owner"),
    View("admin_risk_logs", "/admin/risk-logs", "owner"),
    View("admin_waitlist", "/admin/waitlist", "owner"),
    View("admin_reports", "/admin/reports", "owner"),
    View("admin_blocklist", "/admin/reports?tab=blocklist", "owner"),
    View("admin_airdrop", "/admin/airdrop", "owner"),
    View("admin_wallets", "/admin/airdrop/wallets", "owner"),
    View("admin_fraud", "/admin/airdrop/fraud", "owner"),
    View("admin_audit", "/admin/audit-logs", "owner"),
    View("admin_api_keys", "/admin/api-keys", "owner"),
    View("admin_settings", "/admin/settings", "owner"),
    View("consent_log", "/legal/consent-log", "owner"),
    View("data_processing_log", "/admin/data-processing-log", "owner"),
    View("breach_report", "/admin/report-breach", "owner"),
    View("states_all", "/__states"),
    View("states_empty", "/__states?__state=empty"),
    View("states_loading", "/__states?__state=loading"),
    View("states_error", "/__states?__state=error"),
    View("states_notice", "/__states?__state=notice"),
    View("states_content", "/__states?__state=content"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--views", help="Comma-separated view names; default: all")
    parser.add_argument("--extra-view", action="append", default=[], metavar="NAME=/path", help="Capture a mock-only view not yet in the baseline inventory; may be repeated")
    parser.add_argument("--app-root", type=Path, default=ROOT, help="Repository worktree to run; default: this script's worktree")
    parser.add_argument("--widths", default=",".join(map(str, WIDTHS)))
    parser.add_argument("--themes", default=",".join(THEMES))
    parser.add_argument("--output", type=Path, help="Output directory; default: .cache/ui-shots/<git-sha>")
    parser.add_argument("--list", action="store_true", help="List available views and exit")
    return parser.parse_args()


def choose_views(raw: str | None) -> list[View]:
    if raw == "none":
        return []
    if not raw:
        return list(VIEWS)
    selected = {name.strip() for name in raw.split(",") if name.strip()}
    unknown = selected - {view.name for view in VIEWS}
    if unknown:
        raise ValueError(f"Unknown view(s): {', '.join(sorted(unknown))}")
    return [view for view in VIEWS if view.name in selected]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_server(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Local server exited with status {process.returncode}")
        try:
            with urlopen(base_url + "/health/live", timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, URLError):
            pass
        time.sleep(0.2)
    raise TimeoutError("Local SafeScan server did not become ready in 30 seconds")


def git_sha(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=root, text=True).strip()


def isolated_server_env(temp_dir: str, base_url: str) -> dict[str, str]:
    """Give the mock server no inherited secrets or access to a worktree .env."""
    runtime_names = ("PATH", "PYTHONPATH", "TMPDIR", "VIRTUAL_ENV")
    env = {name: os.environ[name] for name in runtime_names if name in os.environ}
    # A private home also prevents SDKs from finding ~/.aws or similar files.
    env["HOME"] = temp_dir
    env["XDG_CACHE_HOME"] = str(Path(temp_dir) / "cache")
    env["TMPDIR"] = temp_dir
    env["PYTHON_DOTENV_DISABLED"] = "1"
    env.update({
        "APP_URL": base_url,
        "MOCK_MODE": "true",
        "ENVIRONMENT": "development",
        "DATABASE_URL": f"sqlite:///{Path(temp_dir) / 'ui-shots.db'}",
        "DATA_DIR": temp_dir,
        "OWNER_EMAILS": "ui-shots-owner@example.test",
        "ADMIN_EMAILS": "ui-shots-owner@example.test",
        "ADMIN_EMAIL": "ui-shots-owner@example.test",
        "ADMIN_ACCESS_DENYLIST": "",
        "SAFESCAN_ML_ENABLED": "false",
        "SAFESCAN_ML2_ENABLED": "false",
        "SAFESCAN_PHISHTANK_TERMS_CONFIRMED": "false",
        "DOMAIN_AGE_CHECK_ENABLED": "false",
        "STORAGE_BACKEND": "local",
        "AIRDROP_ENABLED": "false",
        "SOLANA_MAINNET_ENABLED": "false",
        "SOLANA_RPC_URL": "http://127.0.0.1:9",
    })
    # These are empty even if a future config path reads one directly. The
    # allowlist above and PYTHON_DOTENV_DISABLED are the primary safeguards.
    credential_names = (
        "GOOGLE_CLIENT_ID", "googe_client_id", "GOOGLE_WEB_RISK_API_KEY",
        "GOOGLE_SAFE_BROWSING_API_KEY", "googe_api_key", "AUTH0_DOMAIN",
        "AUTH0_CLIENT_ID", "AUTH0_CLIENT_IDS", "AUTH0_CLIENT_SECRET",
        "VIRUSTOTAL_API_KEY", "PHISHTANK_APP_KEY", "WHOISXML_API_KEY",
        "SECURITYTRAILS_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
        "STRIPE_WEBHOOK_SECRET", "ALPHA_STRIPE_PAYMENT_LINK",
        "ALPHA_SOLANA_RECIPIENT", "ALPHA_SOLANA_AMOUNT_SOL",
        "SOLANA_USD_PRICE_URL", "SOLANA_USD_PRICE_FALLBACK",
        "DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", "DISCORD_BOT_TOKEN",
        "SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "EMAIL_FROM",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_BUCKET_NAME",
        "S3_ENDPOINT_URL", "S3_REGION", "SOLANA_PRIVATE_KEY",
        "AIRDROP_ADMIN_SECRET", "SESSION_SECRET", "PRIVACY_HASH_SALT",
        "QR_PAYLOAD_FINGERPRINT_KEY",
        "METRICS_TOKEN", "TURNSTILE_SECRET_KEY", "TURNSTILE_SITE_KEY",
    )
    env.update({name: "" for name in credential_names})
    return env


def context_for(browser, base_url: str, audience: str):
    context = browser.new_context(
        base_url=base_url,
        viewport={"width": 1440, "height": 900},
        device_scale_factor=1,
        reduced_motion="reduce",
    )
    if audience != "guest":
        email = f"ui-shots-{audience}@example.test"
        response = context.request.post(
            "/auth/register",
            form={"email": email, "password": "local-screenshot-only-passphrase", "remember_me": "0"},
        )
        if response.status not in (200, 303):
            raise RuntimeError(f"Could not create synthetic {audience} session: HTTP {response.status}")
        check = context.request.get("/api/me")
        if check.status != 200:
            raise RuntimeError(f"Synthetic {audience} session did not persist: HTTP {check.status}")
        # Synthetic local accounts skip OAuth onboarding; give the screenshot
        # fixture adult access so gated feature pages can still be reviewed.
        from datetime import datetime, timezone
        adult_page = context.request.get("/auth/confirm-adult")
        if adult_page.status != 200:
            raise RuntimeError(f"Could not open synthetic {audience} adult check: HTTP {adult_page.status}")
        adult = context.request.post("/auth/confirm-adult", form={
            "birth_year": str(datetime.now(timezone.utc).year - 25),
            "birthday_this_year": "yes", "adult_attestation": "yes",
        }, max_redirects=0)
        if adult.status != 303:
            raise RuntimeError(f"Could not complete synthetic {audience} adult check: HTTP {adult.status}")
    return context


def capture(browser, base_url: str, views: list[View], widths: list[int], themes: list[str], output: Path) -> list[dict]:
    contexts = {audience: context_for(browser, base_url, audience) for audience in sorted({v.audience for v in views})}
    manifest: list[dict] = []
    try:
        for index, view in enumerate(views, start=1):
            context = contexts[view.audience]
            context.set_default_navigation_timeout(20_000)
            for theme in themes:
                page = context.new_page()
                page.set_viewport_size({"width": widths[0], "height": 900})
                page.add_init_script(
                    "localStorage.setItem('safescan_theme', " + json.dumps(theme) + ");"
                    + (
                        "localStorage.removeItem('safeScanConsent');"
                        if view.consent_prompt else
                        "localStorage.setItem('safeScanConsent', JSON.stringify({"
                        "consentType: 'essential_only', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()}));"
                    )
                )
                try:
                    response = page.goto(view.path, wait_until="domcontentloaded")
                    page.wait_for_timeout(450)
                    status = response.status if response else None
                    final_path = page.url.removeprefix(base_url).split("?", 1)[0]
                    expected = view.final_path or view.path.split("?", 1)[0]
                    if status != 200 or final_path != expected:
                        raise RuntimeError(
                            f"{view.name}: expected HTTP 200 at {expected}, got HTTP {status} at {page.url}"
                        )
                    rendered_theme = page.locator("html").get_attribute("data-theme")
                    if rendered_theme != theme:
                        raise RuntimeError(f"{view.name}: expected {theme} theme, got {rendered_theme!r}")
                    title = page.title()
                    for width in widths:
                        page.set_viewport_size({"width": width, "height": 900})
                        page.wait_for_timeout(100)
                        folder = output / theme / str(width)
                        folder.mkdir(parents=True, exist_ok=True)
                        filename = folder / f"{view.name}.jpg"
                        page.screenshot(path=str(filename), type="jpeg", quality=76, full_page=True, animations="disabled")
                        manifest.append({
                            "view": view.name,
                            "requested_path": view.path,
                            "final_path": final_path,
                            "audience": view.audience,
                            "theme": theme,
                            "rendered_theme": rendered_theme,
                            "width": width,
                            "status": status,
                            "title": title,
                            "file": str(filename.relative_to(output)),
                        })
                finally:
                    page.close()
            if index % 8 == 0 or index == len(views):
                print(f"Captured {index}/{len(views)} views at {len(widths)} widths in {len(themes)} themes", flush=True)
    finally:
        for context in contexts.values():
            context.close()
    return manifest


def main() -> int:
    args = parse_args()
    if args.list:
        for view in VIEWS:
            print(f"{view.name:26} {view.audience:6} {view.path}")
        return 0

    views = choose_views(args.views)
    for extra in args.extra_view:
        name, separator, path = extra.partition("=")
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_]*", name) or not path.startswith("/") or path.startswith("//"):
            raise ValueError(f"Invalid --extra-view {extra!r}; expected NAME=/path")
        views.append(View(name, path))
    if not views:
        raise ValueError("No views selected")
    app_root = args.app_root.resolve()
    if not (app_root / "hackabull" / "__init__.py").is_file():
        raise ValueError(f"Not a SafeScan worktree: {app_root}")
    widths = [int(part) for part in args.widths.split(",")]
    themes = [part.strip() for part in args.themes.split(",")]
    if not widths or any(width < 320 or width > 2400 for width in widths):
        raise ValueError("Widths must be between 320 and 2400 CSS px")
    if not themes or any(theme not in THEMES for theme in themes):
        raise ValueError("Themes must be dark or light")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise SystemExit("Install development dependencies: python -m pip install -r requirements-dev.txt") from exc

    output = (args.output or app_root / ".cache" / "ui-shots" / git_sha(app_root)).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="safescan-ui-shots-") as temp_dir:
        port = free_port()
        base_url = f"http://localhost:{port}"
        env = isolated_server_env(temp_dir, base_url)
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
            cwd=app_root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_server(base_url, process)
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    manifest = capture(browser, base_url, views, widths, themes, output)
                finally:
                    browser.close()
        except Exception:
            process.terminate()
            try:
                _, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
            if stderr:
                print(stderr[-6000:], file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    (output / "manifest.json").write_text(json.dumps({
        "source_commit": git_sha(app_root),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "mode": "local MOCK_MODE with throwaway SQLite",
        "entries": manifest,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(manifest)} screenshots to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
