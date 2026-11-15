"""Check scanner navigation and focus in an isolated mock browser session."""

import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
harness = runpy.run_path(str(ROOT / "scripts/ui_screenshots.py"))


with tempfile.TemporaryDirectory(prefix="safescan-nav-qa-") as temp:
    port = harness["free_port"]()
    url = f"http://127.0.0.1:{port}"
    env = harness["isolated_server_env"](temp, url)
    # Local developer harness: executable and argv are fixed here; no shell or user-provided command.
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        harness["wait_for_server"](url, proc)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = harness["context_for"](browser, url, "guest")
            page = context.new_page()
            page.set_viewport_size({"width": 375, "height": 812})
            page.goto("/", wait_until="domcontentloaded")

            hero = page.locator(".hero-actions").get_by_role("link", name="Scan QR", exact=True)
            hero.focus()
            page.keyboard.press("Enter")
            page.wait_for_function("() => document.activeElement?.id === 'scannerTitle'")
            assert page.evaluate("location.hash") == "#scanner"
            print("PASS hero scanner link moves focus to scanner heading", flush=True)

            menu = page.get_by_role("button", name="Open menu")
            menu.click()
            assert page.evaluate("document.activeElement?.classList.contains('sidenav-close')")
            page.locator("#sideNav .sidenav-close").click()
            assert page.evaluate("document.activeElement?.classList.contains('sidenav-toggle')")
            print("PASS explicit drawer close restores Menu focus", flush=True)

            menu.click()
            scanner = page.locator("#sideNav").get_by_role("link", name="Scanner")
            scanner.focus()
            page.keyboard.press("Enter")
            page.wait_for_function("() => document.activeElement?.id === 'scannerTitle'")
            assert not page.locator("body").evaluate("element => element.classList.contains('sidenav-open')")
            print("PASS drawer scanner link closes without returning focus to Menu", flush=True)

            page.goto("about:blank")
            page.goto("/#scanner", wait_until="domcontentloaded")
            page.wait_for_function("() => document.activeElement?.id === 'scannerTitle'")
            print("PASS direct scanner fragment focuses heading", flush=True)

            trigger = page.get_by_role("button", name="Scan with camera")
            trigger.click()
            page.locator(".qr-camera-modal").wait_for()
            assert page.evaluate("document.activeElement?.classList.contains('qr-camera-close')")
            page.locator(".qr-camera-close").click()
            assert page.evaluate("document.activeElement?.id === 'scanCameraButton'")
            print("PASS camera dialog restores focus to Scan with camera", flush=True)
            browser.close()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
