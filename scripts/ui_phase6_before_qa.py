#!/usr/bin/env python3
"""Capture the pre-hardening wallet/scan states from a Phase 6 base checkout.

Example: python scripts/ui_phase6_before_qa.py --app-root ../safescan-qr-ui-phase-6
The target checkout should be commit 0ae0867 or its equivalent before the
request-bound changes. All requests are held on an isolated local mock server.
"""

import argparse
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--app-root', type=Path, required=True)
parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'docs/design/screenshots/ui-phase-6-hardening/before')
args = parser.parse_args()
app_root = args.app_root.resolve()
if not app_root.is_dir() or not (app_root / 'scripts/ui_screenshots.py').is_file():
    parser.error('--app-root must point to a local SafeScan checkout')
harness = runpy.run_path(str(app_root / 'scripts/ui_screenshots.py'))


def capture_matrix(page, name):
    for theme in ('dark', 'light'):
        page.evaluate('''theme => {
          localStorage.setItem('safescan_theme', theme);
          document.documentElement.dataset.theme = theme;
        }''', theme)
        for width in (375, 768, 1440):
            page.set_viewport_size({'width': width, 'height': 900})
            path = args.output / theme / str(width) / f'{name}.jpg'
            path.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(path), full_page=True, type='jpeg', quality=82)
            print('SHOT', path, flush=True)


held_routes = []


def hold_route(route):
    held_routes.append(route)


def release_routes():
    while held_routes:
        try:
            held_routes.pop().abort(error_code='failed')
        except Exception:
            pass


with tempfile.TemporaryDirectory(prefix='safescan-phase6-before-') as temp:
    port = harness['free_port']()
    url = f'http://127.0.0.1:{port}'
    env = harness['isolated_server_env'](temp, url)
    # This developer-only harness accepts a local checkout path for cwd. The
    # executable and argv are fixed, shell=False, and port is a local integer;
    # no data from the checkout is interpolated into a shell command.
    proc = subprocess.Popen(
        [sys.executable, '-m', 'uvicorn', 'hackabull:qr_app', '--host', '127.0.0.1', '--port', str(port), '--no-access-log'],  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        cwd=app_root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        harness['wait_for_server'](url, proc)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = harness['context_for'](browser, url, 'member')
            context.add_init_script('''localStorage.setItem('safeScanConsent', JSON.stringify({
              consentType: 'essential', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()
            }));''')

            busy = context.new_page()
            busy.add_init_script('''window.solana = {
              isPhantom: true,
              connect: () => new Promise(resolve => { window.releaseWalletConnect = resolve; })
            };''')
            busy.goto('/token', wait_until='domcontentloaded')
            busy.locator('#connectWalletButton').click()
            busy.locator('.wallet-choice-button').first.click()
            busy.locator('.wallet-modal h3').filter(has_text='Connecting wallet').wait_for()
            capture_matrix(busy, 'wallet_busy')
            busy.close()

            status = context.new_page()
            status.route(re.compile(r'/api/wallet$'), hold_route)
            status.goto('/token', wait_until='domcontentloaded')
            status.wait_for_timeout(13000)
            capture_matrix(status, 'wallet_error')
            release_routes()
            status.close()

            # A pending old native navigation blocks Playwright screenshot and
            # CDP viewport changes. Use the already committed Phase 6 progress
            # matrix for a stable visual before of the same loading component.
            for theme in ('dark', 'light'):
                for width in (375, 768, 1440):
                    source = app_root / 'docs/design/screenshots/ui-phase-6/states' / theme / str(width) / 'scanner_progress.jpg'
                    path = args.output / theme / str(width) / 'scan_timeout.jpg'
                    path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, path)
                    print('SHOT', path, flush=True)
            browser.close()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
