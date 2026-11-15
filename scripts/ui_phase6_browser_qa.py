"""Exercise held wallet, scanner, and runtime requests in an isolated mock server."""

import re
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
OUTPUT = ROOT / '.cache' / 'ui-shots' / 'phase6-request-bounds'
harness = runpy.run_path(str(ROOT / 'scripts/ui_screenshots.py'))


def capture_matrix(page, name):
    for theme in ('dark', 'light'):
        page.evaluate('''theme => {
          localStorage.setItem('safescan_theme', theme);
          document.documentElement.dataset.theme = theme;
        }''', theme)
        for width in (375, 768, 1440):
            page.set_viewport_size({'width': width, 'height': 900})
            path = OUTPUT / theme / str(width) / f'{name}.jpg'
            path.parent.mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(path), full_page=True, type='jpeg', quality=82)
            print('SHOT', path, flush=True)


held_routes = []


def hold_route(route):
    held_routes.append(route)


def release_routes():
    while held_routes:
        route = held_routes.pop()
        try:
            route.abort(error_code='failed')
        except Exception:
            pass


with tempfile.TemporaryDirectory(prefix='safescan-phase6-qa-') as temp:
    port = harness['free_port']()
    url = f'http://127.0.0.1:{port}'
    env = harness['isolated_server_env'](temp, url)
    proc = subprocess.Popen(
        [PYTHON, '-m', 'uvicorn', 'hackabull:qr_app', '--host', '127.0.0.1', '--port', str(port), '--no-access-log'],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    try:
        harness['wait_for_server'](url, proc)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = harness['context_for'](browser, url, 'member')
            context.add_init_script('''localStorage.setItem('safeScanConsent', JSON.stringify({
              consentType: 'essential', bannerVersion: 'consent-v1', timestamp: new Date().toISOString()
            }));''')

            # A wallet provider that never resolves its connect request. Closing
            # the modal must cancel the UI operation and discard its late result.
            provider = context.new_page()
            provider.add_init_script('''window.solana = {
              isPhantom: true,
              connect: () => new Promise(resolve => { window.releaseWalletConnect = resolve; }),
              signMessage: () => Promise.resolve({signature: new Uint8Array(64).fill(1)})
            };''')
            provider.goto('/token', wait_until='domcontentloaded')
            provider.locator('#connectWalletButton').click()
            provider.locator('.wallet-choice-button').first.click()
            provider.locator('.wallet-modal h3').filter(has_text='Connecting wallet').wait_for()
            assert provider.locator('#connectWalletButton').get_attribute('aria-busy') == 'true'
            capture_matrix(provider, 'wallet_busy')
            provider.locator('.wallet-modal-close').click()
            provider.evaluate('''() => window.releaseWalletConnect({
              publicKey: {toString: () => '11111111111111111111111111111111'}
            })''')
            provider.wait_for_timeout(150)
            assert provider.locator('.wallet-modal').count() == 0
            assert provider.locator('#walletStatus').inner_text().startswith('Connect and sign')
            assert provider.locator('#connectWalletButton').get_attribute('aria-busy') is None
            assert provider.locator('#connectWalletButton').is_enabled()
            print('PASS provider cancellation and busy recovery', flush=True)
            provider.close()

            for stage in ('nonce', 'verify'):
                pending = context.new_page()
                pending.add_init_script('''window.solana = {
                  isPhantom: true,
                  connect: () => Promise.resolve({publicKey: {toString: () => '11111111111111111111111111111111'}}),
                  signMessage: () => Promise.resolve({signature: new Uint8Array(64).fill(1)})
                };''')
                pending.route(re.compile(r'/api/wallet/nonce$'),
                              hold_route if stage == 'nonce'
                              else (lambda route: route.fulfill(status=200, content_type='application/json', body='{"message":"test challenge"}')))
                pending.route(re.compile(r'/api/wallet/verify$'), hold_route)
                pending.goto('/token', wait_until='domcontentloaded')
                pending.locator('#connectWalletButton').click()
                pending.locator('.wallet-choice-button').first.click()
                if stage == 'verify':
                    pending.locator('.wallet-modal h3').filter(has_text='Verifying wallet').wait_for()
                else:
                    pending.locator('.wallet-modal h3').filter(has_text='Connecting wallet').wait_for()
                pending.locator('.wallet-modal-close').click()
                pending.wait_for_timeout(150)
                assert pending.locator('.wallet-modal').count() == 0
                assert 'Connected:' not in pending.locator('#walletStatus').inner_text()
                assert pending.locator('#connectWalletButton').is_enabled()
                print(f'PASS held {stage} cancellation', flush=True)
                release_routes()
                pending.close()

            disconnect = context.new_page()
            disconnect.add_init_script('''window.solana = {
              isPhantom: true,
              connect: () => Promise.resolve({publicKey: {toString: () => '11111111111111111111111111111111'}}),
              disconnect: () => new Promise(resolve => { window.releaseWalletDisconnect = resolve; })
            };''')
            disconnect.route(re.compile(r'/api/wallet$'), lambda route: route.fulfill(
                status=200, content_type='application/json',
                body='{"connected":true,"walletAddress":"11111111111111111111111111111111"}'
            ))
            disconnect.goto('/token', wait_until='domcontentloaded')
            disconnect.locator('#walletStatus').filter(has_text='Connected:').wait_for()
            disconnect.evaluate('connectWallet()')
            disconnect.locator('.wallet-disconnect-button').first.click()
            disconnect.locator('.wallet-modal h3').filter(has_text='Disconnecting wallet').wait_for()
            disconnect.locator('.wallet-modal-close').click()
            disconnect.evaluate('window.releaseWalletDisconnect()')
            disconnect.wait_for_timeout(150)
            assert disconnect.locator('.wallet-modal').count() == 0
            assert disconnect.locator('#walletStatus').inner_text().startswith('Connected:')
            assert disconnect.locator('#connectWalletButton').is_disabled()
            print('PASS held provider disconnect cancellation', flush=True)
            disconnect.close()

            # Held wallet status must time out into a persistent retry state.
            status = context.new_page()
            status.route(re.compile(r'/api/wallet$'), hold_route)
            status.goto('/token', wait_until='domcontentloaded')
            status.locator('#walletFeedback .state-error').wait_for(timeout=16000)
            assert status.locator('#walletFeedback button').inner_text() == 'Try again'
            assert 'Connected:' not in status.locator('#walletStatus').inner_text()
            capture_matrix(status, 'wallet_error')
            print('PASS wallet status deadline and retry', flush=True)
            release_routes()
            status.close()

            # Native POST navigation can remain pending; the old page must
            # surface a terminal error and preserve the entered payload.
            scanner = context.new_page()
            scanner.route(re.compile(r'/search_qr_api$'), hold_route)
            scanner.goto('/', wait_until='domcontentloaded')
            scanner.locator('#urlInput').fill('https://example.test/held-scan')
            scanner.locator('#urlForm button[type=submit]').evaluate('(button) => button.click()')
            scanner.locator('#analysisLoadingState .state-error').wait_for(timeout=20000)
            assert scanner.locator('#urlInput').input_value() == 'https://example.test/held-scan'
            assert scanner.locator('#urlForm button[type=submit]').is_enabled()
            assert scanner.locator('#analysisLoadingState button').inner_text() == 'Try again'
            capture_matrix(scanner, 'scan_timeout')
            print('PASS native scan deadline and recovery', flush=True)
            release_routes()
            scanner.close()

            runtime = context.new_page()
            runtime.route(re.compile(r'/api/app-runtime$'), hold_route)
            runtime.goto('/leaderboard', wait_until='domcontentloaded')
            runtime.locator('[data-runtime-timer]').filter(has_text='Runtime unavailable').wait_for(timeout=12000)
            assert runtime.locator('[data-runtime-timer]').inner_text() == 'Runtime unavailable'
            print('PASS runtime deadline copy', flush=True)
            release_routes()
            runtime.close()
            browser.close()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
