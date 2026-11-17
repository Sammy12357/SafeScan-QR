"""Audit SafeScan's public HTML pages in dark and light themes with pinned axe.

This starts a disposable, mock-only local server. No production data, secrets,
or external requests are used. Serious and critical WCAG A/AA findings fail CI.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from legal_network_gate import first_party_request, record_attempt
from ui_screenshots import (
    ROOT,
    View,
    VIEWS,
    context_for,
    free_port,
    isolated_server_env,
    wait_for_server,
)


THEMES = ("dark", "light")
WIDTHS = (375, 1440)
EXTRA_PUBLIC_VIEWS = (
    View("accessibility", "/accessibility"),
    View("learn_after_scanning", "/learn/after-scanning-suspicious-qr"),
    View("learn_parking_meter", "/learn/parking-meter-qr-scams"),
    View("learn_scan_screenshot", "/learn/scan-qr-code-from-screenshot"),
    View("not_found", "/__accessibility_missing_page__"),
    View("waitlist", "/waitlist"),
    View("waitlist_joined", "/waitlist?joined=1"),
    View("waitlist_confirm_expired", "/waitlist/confirm"),
    View("waitlist_unsubscribe_expired", "/waitlist/unsubscribe"),
    View("confirm_age_expired", "/auth/confirm-age"),
    View("auth_google_landing", "/auth/google"),
    View("terms_history", "/legal/terms-history"),
    View("privacy_alias", "/legal/privacy"),
    View("terms_alias", "/legal/terms"),
    View("license", "/legal/license"),
    View("changelog", "/changelog"),
    View("product_install", "/product/install"),
    View("product_getting_started", "/product/getting-started"),
    View("product_wedges", "/product/wedges"),
    View("product_pricing", "/product/pricing"),
    View("resources_architecture", "/resources/architecture"),
    View("resources_roadmap", "/resources/roadmap"),
    View("tokenomics", "/tokenomics", "member"),
)
PUBLIC_VIEWS = tuple(
    view for view in VIEWS if view.audience != "owner" and not view.name.startswith("states_")
) + EXTRA_PUBLIC_VIEWS
FAIL_IMPACTS = {"serious", "critical"}
EXPECTED_STATUSES = {
    "not_found": 404,
    "confirm_age_expired": 410,
    "waitlist_confirm_expired": 410,
    "waitlist_unsubscribe_expired": 410,
}


def check_public_route_inventory() -> None:
    """Keep the page list current when a new public GET HTML route is added."""
    audited_paths = {view.path.split("?", 1)[0] for view in PUBLIC_VIEWS}
    route_paths = set()
    for path in (ROOT / "hackabull").glob("routes*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                    continue
                if not isinstance(decorator.func.value, ast.Name) or decorator.func.value.id != "qr_app" or decorator.func.attr != "get":
                    continue
                if not decorator.args or not isinstance(decorator.args[0], ast.Constant) or not isinstance(decorator.args[0].value, str):
                    continue
                if not any(keyword.arg == "response_class" and isinstance(keyword.value, ast.Name)
                           and keyword.value.id == "HTMLResponse" for keyword in decorator.keywords):
                    continue
                route = decorator.args[0].value
                if route.startswith("/admin/") or route == "/admin" or route in {"/__states", "/legal/consent-log"}:
                    continue
                route_paths.add(route)
    missing = sorted(route_paths - audited_paths)
    if missing:
        raise RuntimeError(f"Public GET HTML routes missing from accessibility audit: {', '.join(missing)}")


def audit(base_url: str, axe_path: Path, views: tuple[View, ...]) -> dict:
    findings = []
    outbound_attempts = []
    checked = 0
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        contexts = {audience: context_for(browser, base_url, audience) for audience in sorted({v.audience for v in views})}
        active_views = {}
        try:
            for audience, context in contexts.items():
                # Keep the run local even for the one permitted login script.
                context.route("**/*", lambda route: route.continue_() if first_party_request(route.request.url, base_url) else route.abort())
                def handle_websocket(route, audience=audience):
                    if active := active_views.get(audience):
                        view_name, path, theme, attempts = active
                        record_attempt(route.url, "websocket", base_url,
                                       view_name, path, theme, attempts)
                    if first_party_request(route.url, base_url):
                        route.connect_to_server()
                    else:
                        route.close()
                context.route_web_socket("**/*", handle_websocket)
                context.add_init_script(path=str(axe_path))
            for index, view in enumerate(views, start=1):
                context = contexts[view.audience]
                for theme in THEMES:
                    page_attempts = []
                    page_path = view.path.split("?", 1)[0]

                    def record_request(request):
                        record_attempt(request.url, request.resource_type, base_url,
                                       view.name, page_path, theme, page_attempts)

                    # Context listeners also see requests from workers and popups.
                    active_views[view.audience] = (view.name, page_path, theme, page_attempts)
                    context.on("request", record_request)
                    page = context.new_page()
                    page.add_init_script(
                        "localStorage.setItem('safescan_theme', " + json.dumps(theme) + ");"
                        + (
                            # A fresh anonymous visit has not made a consent choice.
                            "localStorage.removeItem('safeScanConsent');"
                            if view.audience == "guest" or view.consent_prompt else
                            "localStorage.setItem('safeScanConsent', JSON.stringify({"
                            "consentType: 'essential_only', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()}));"
                        )
                    )
                    try:
                        try:
                            response = page.goto(base_url + view.path, wait_until="networkidle", timeout=20_000)
                        except Exception:
                            if page_attempts:
                                destinations = ", ".join(sorted({item["destination"] for item in page_attempts}))
                                raise RuntimeError(f"{view.name} {theme} {page_path}: "
                                                   f"attempted outbound request to {destinations}") from None
                            raise
                        status = response.status if response else None
                        expected = view.final_path or view.path.split("?", 1)[0]
                        final_path = urlsplit(page.url).path if first_party_request(page.url, base_url) else "<external origin>"
                        expected_status = EXPECTED_STATUSES.get(view.name, 200)
                        if status != expected_status or final_path != expected:
                            raise RuntimeError(f"{view.name}: expected {expected_status} at {expected}; "
                                               f"got {status} at {final_path}")
                        if page.locator("html").get_attribute("data-theme") != theme:
                            raise RuntimeError(f"{view.name}: {theme} theme did not render")
                        for width in WIDTHS:
                            page.set_viewport_size({"width": width, "height": 900})
                            results = page.evaluate(
                                """async () => {
                                  const report = await axe.run(document);
                                  return report.violations.map(v => ({
                                    id: v.id, impact: v.impact, description: v.help, tags: v.tags,
                                    nodes: v.nodes.map(n => ({target: n.target, summary: n.failureSummary}))
                                  }));
                                }""",
                            )
                            checked += 1
                            if results:
                                findings.append({"view": view.name, "path": view.path, "theme": theme,
                                                 "width": width, "violations": results})
                    finally:
                        page.close()
                        context.remove_listener("request", record_request)
                        active_views.pop(view.audience, None)
                        outbound_attempts.extend(page_attempts)
                if index % 10 == 0 or index == len(views):
                    print(f"Audited {index}/{len(views)} public views", flush=True)
        finally:
            for context in contexts.values():
                context.close()
            browser.close()
    return {"checked": checked, "pages": len(views), "widths": WIDTHS,
            "axe_version": "4.14.0", "findings": findings,
            "outbound_attempts": outbound_attempts}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--view", action="append", help="Run only these named views (for development)")
    parser.add_argument("--output", type=Path, default=ROOT / ".cache" / "legal-accessibility-audit.json")
    args = parser.parse_args()
    axe_path = ROOT / "scripts" / "a11y" / "node_modules" / "axe-core" / "axe.min.js"
    if not axe_path.is_file():
        parser.error("Install pinned axe first: npm ci --prefix scripts/a11y")
    selected = tuple(view for view in PUBLIC_VIEWS if not args.view or view.name in args.view)
    if not selected or (args.view and set(args.view) != {view.name for view in selected}):
        parser.error("Unknown or empty --view selection")
    check_public_route_inventory()
    with tempfile.TemporaryDirectory(prefix="safescan-legal-a11y-") as temporary:
        port = free_port()
        base_url = f"http://localhost:{port}"
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
            cwd=ROOT,
            env=isolated_server_env(temporary, base_url),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_server(base_url, server)
            report = audit(base_url, axe_path, selected)
        except Exception:
            server.terminate()
            _, stderr = server.communicate(timeout=5)
            if stderr:
                print(stderr[-4000:], file=sys.stderr)
            raise
        finally:
            if server.poll() is None:
                server.terminate()
                server.wait(timeout=5)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    blocking = [
        (finding, violation)
        for finding in report["findings"] for violation in finding["violations"]
        if violation["impact"] in FAIL_IMPACTS
    ]
    print(f"Axe {report['axe_version']} checked {report['checked']} renders of {report['pages']} public views at widths {WIDTHS} in dark/light themes")
    for finding, violation in blocking[:20]:
        print(f"{finding['view']} {finding['theme']} {finding['width']}px: {violation['impact']} {violation['id']} {violation['nodes'][0]['target']}")
    for attempt in report["outbound_attempts"][:20]:
        print(f"{attempt['view']} {attempt['theme']} {attempt['path']}: "
              f"attempted {attempt['resource_type']} to {attempt['destination']}")
    if blocking or report["outbound_attempts"]:
        print(f"{len(blocking)} serious/critical axe hits; "
              f"{len(report['outbound_attempts'])} unexpected pre-action outbound requests; "
              f"full report: {args.output}")
        raise SystemExit(1)
    print(f"No serious/critical axe findings or unexpected pre-action outbound requests; full report: {args.output}")


if __name__ == "__main__":
    main()
