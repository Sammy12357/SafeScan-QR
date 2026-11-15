"""Exercise a slow threat-feed request and loss of network mid-request."""

import asyncio
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.async_api import async_playwright


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / ".cache" / "ui-shots" / "phase8-network"
harness = runpy.run_path(str(ROOT / "scripts/ui_screenshots.py"))


async def capture_matrix(page, name):
    for theme in ("dark", "light"):
        await page.evaluate("""theme => {
          localStorage.setItem('safescan_theme', theme);
          document.documentElement.dataset.theme = theme;
        }""", theme)
        for width in (375, 768, 1440):
            await page.set_viewport_size({"width": width, "height": 900})
            path = OUTPUT / theme / str(width) / f"{name}.jpg"
            path.parent.mkdir(parents=True, exist_ok=True)
            await page.screenshot(path=str(path), full_page=True, type="jpeg", quality=82)
            print("SHOT", path, flush=True)


async def run(url):
    request_started = asyncio.Event()
    release_request = asyncio.Event()
    request_count = 0

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(base_url=url, viewport={"width": 375, "height": 900}, reduced_motion="reduce")
        await context.add_init_script("""localStorage.setItem('safeScanConsent', JSON.stringify({
          consentType: 'essential', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()
        }));""")
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
        await cdp.send("Network.enable")
        await cdp.send("Network.emulateNetworkConditions", {
            "offline": False,
            "latency": 150,
            "downloadThroughput": 1_600_000 / 8,
            "uploadThroughput": 750_000 / 8,
            "connectionType": "cellular4g",
        })

        async def delayed_feed(route):
            nonlocal request_count
            request_count += 1
            if request_count > 1:
                await route.continue_()
                return
            request_started.set()
            await release_request.wait()
            await route.abort(error_code="internetdisconnected")

        await page.route("**/api/malicious-qr?*", delayed_feed)
        await page.goto("/malicious-database", wait_until="domcontentloaded")
        await asyncio.wait_for(request_started.wait(), timeout=10)
        await page.locator("#mqState .state-loading").wait_for(timeout=5000)
        assert await page.locator("#mqGrid").get_attribute("aria-busy") == "true"
        await capture_matrix(page, "threat_feed_slow4g_loading")
        print("PASS Slow 4G loading state and aria-busy", flush=True)

        await context.set_offline(True)
        release_request.set()
        await page.locator("#mqState .state-error").wait_for(timeout=10000)
        error = await page.locator("#mqState").inner_text()
        assert "offline" in error.lower() and "Try again" in error
        assert await page.locator("#mqGrid").get_attribute("aria-busy") is None
        await capture_matrix(page, "threat_feed_offline_error")
        print("PASS offline mid-request terminal error and retry", flush=True)

        await context.set_offline(False)
        await page.locator("#mqState").get_by_role("button", name="Try again").click()
        await page.wait_for_function("() => !document.getElementById('mqGrid').hasAttribute('aria-busy')", timeout=10000)
        assert await page.locator("#mqState .state-error").count() == 0
        assert await page.locator("#mqGrid").get_attribute("aria-busy") is None
        print("PASS online retry clears error and busy state", flush=True)
        await browser.close()


with tempfile.TemporaryDirectory(prefix="safescan-phase8-network-") as temp:
    port = harness["free_port"]()
    url = f"http://127.0.0.1:{port}"
    env = harness["isolated_server_env"](temp, url)
    # Local developer harness: executable and argv are fixed; no shell or user-provided command.
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        harness["wait_for_server"](url, proc)
        asyncio.run(run(url))
    finally:
        proc.terminate()
        proc.wait(timeout=5)
