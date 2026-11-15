"""Check keyboard containment and focus return for public dialogs locally."""

from __future__ import annotations

import subprocess
import sys
import tempfile

from playwright.sync_api import sync_playwright

from ui_screenshots import ROOT, context_for, free_port, isolated_server_env, wait_for_server


def inside(page, selector: str) -> bool:
    return page.evaluate(
        "(selector) => Boolean(document.activeElement?.closest(selector))", selector,
    )


def run(base_url: str) -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            guest = context_for(browser, base_url, "guest")
            page = guest.new_page()
            page.set_viewport_size({"width": 375, "height": 812})
            page.goto("/", wait_until="domcontentloaded")

            page.get_by_role("button", name="Open menu").click()
            assert inside(page, "#sideNav")
            page.locator("#sideNav .sidenav-close").focus()
            page.keyboard.press("Shift+Tab")
            assert inside(page, "#sideNav"), "menu let focus move behind it"
            page.keyboard.press("Escape")
            assert not inside(page, "#sideNav")
            assert page.evaluate("document.activeElement?.classList.contains('sidenav-toggle')")

            page.get_by_role("button", name="Scan with camera").click()
            modal = page.locator(".qr-camera-modal")
            modal.wait_for()
            assert inside(page, ".qr-camera-modal")
            page.keyboard.press("Shift+Tab")
            assert inside(page, ".qr-camera-modal"), "camera let focus move behind it"
            page.keyboard.press("Escape")
            assert not modal.count()
            assert page.evaluate("document.activeElement?.id === 'scanCameraButton'")

            page.evaluate("showSignInWalletModal()")
            wallet = page.locator(".wallet-modal")
            wallet.wait_for()
            assert inside(page, ".wallet-modal")
            page.keyboard.press("Shift+Tab")
            assert inside(page, ".wallet-modal"), "wallet dialog let focus move behind it"
            page.keyboard.press("Escape")
            assert not wallet.count()
            print("PASS menu, camera, and wallet keyboard containment and return focus", flush=True)

            page.locator("#urlInput").fill("https://example.com")
            page.locator("#urlForm").get_by_role("button", name="Analyze Payload").click()
            risk = page.locator("#riskVerdictModal")
            risk.wait_for(timeout=30_000)
            page.locator("#riskModalCloseButton").focus()
            page.keyboard.press("Shift+Tab")
            assert inside(page, "#riskVerdictModal"), "result dialog let focus move behind it"
            page.keyboard.press("Escape")
            assert not risk.count()
            assert page.evaluate("document.activeElement?.id === 'scannerTitle'")
            print("PASS scan result dialog keyboard containment and return focus", flush=True)

            member = context_for(browser, base_url, "member")
            ghost = member.new_page()
            ghost.goto("/go-ghost", wait_until="domcontentloaded")
            consent = ghost.locator("#goGhostConsentModal")
            assert consent.is_visible()
            assert inside(ghost, "#goGhostConsentModal")
            ghost.keyboard.press("Shift+Tab")
            assert inside(ghost, "#goGhostConsentModal"), "Go Ghost consent let focus move behind it"
            ghost.get_by_role("button", name="Yes, start Go Ghost").click()
            assert consent.is_hidden()
            rows = ghost.locator("#goGhostAutomationRows [data-ghost-scope]")
            rows.first.wait_for()
            rows.first.click()
            scope = ghost.locator("#goGhostScopeModal")
            assert scope.is_visible() and inside(ghost, "#goGhostScopeModal")
            ghost.keyboard.press("Shift+Tab")
            assert inside(ghost, "#goGhostScopeModal"), "Go Ghost site details let focus move behind it"
            ghost.keyboard.press("Escape")
            assert scope.is_hidden()
            assert ghost.evaluate("document.activeElement?.hasAttribute('data-ghost-scope')")
            print("PASS Go Ghost consent and site detail keyboard containment and return focus", flush=True)
        finally:
            browser.close()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="safescan-legal-keyboard-") as temporary:
        port = free_port()
        base_url = f"http://127.0.0.1:{port}"
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
            run(base_url)
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


if __name__ == "__main__":
    main()
