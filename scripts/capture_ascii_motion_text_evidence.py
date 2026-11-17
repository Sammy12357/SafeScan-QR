#!/usr/bin/env python3
"""Capture local before/after generator panels for the ASCII text motion change."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

from hackabull.qr_image import (
    qr_ascii_from_payload,
    qr_ascii_motion_frames_from_payload,
    qr_ascii_motion_pngs_from_payload,
)
from scripts.ui_screenshots import free_port, isolated_server_env, wait_for_server


ROOT = Path(__file__).resolve().parents[1]
URL = "https://sqafe.com/"
WIDTHS = (375, 768, 1440)
THEMES = ("dark", "light")


def responses() -> dict[str, dict]:
    still, animated = qr_ascii_motion_pngs_from_payload(URL, include_attribution=False)
    return {
        "before": {
            "still_png_base64": base64.b64encode(still).decode("ascii"),
            "animated_png_base64": base64.b64encode(animated).decode("ascii"),
            "text": qr_ascii_from_payload(URL, ec="H", include_attribution=False),
            "frame_count": 4,
            "frame_duration_ms": 350,
        },
        "after": {
            "ascii_frames": qr_ascii_motion_frames_from_payload(URL, include_attribution=False),
            "frame_count": 4,
            "frame_duration_ms": 350,
        },
    }


def capture(browser, phase: str, base_url: str, response: dict, output: Path) -> list[dict]:
    results = []
    for theme in THEMES:
        for width in WIDTHS:
            context = browser.new_context(base_url=base_url, viewport={"width": width, "height": 900})
            page = context.new_page()
            page.add_init_script(
                "localStorage.setItem('safescan_theme', " + json.dumps(theme) + ");"
                "localStorage.setItem('safeScanConsent', JSON.stringify({"
                "consentType:'essential_only',bannerVersion:'consent-v1',"
                "timestamp:new Date().toISOString()}));"
            )
            page.route("**/api/qr/generate-plain", lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                headers={"X-SafeScan-Mode": "plain", "X-SafeScan-Verification": "not_checked"},
                body=json.dumps(response),
            ))
            try:
                page.goto("/generate-qr", wait_until="domcontentloaded")
                page.locator('input[name="generateQrMode"][value="plain"]').check()
                page.locator('input[name="generateQrFormat"][value="ascii_motion"]').check()
                page.locator("#generateQrUrlInput").fill(URL)
                page.locator("#generateQrButton").click()
                page.locator("#generatedMotionTextWrap").wait_for(state="visible", timeout=30_000)
                page.evaluate("document.fonts.ready")
                if phase == "before":
                    page.wait_for_function("() => document.querySelector('#generatedQrImage').complete && document.querySelector('#generatedQrImage').naturalWidth > 0")
                else:
                    page.wait_for_function("() => document.querySelector('#generatedMotionTextArt').textContent.length > 0")
                panel = page.locator("#generate-qr-section")
                panel.screenshot(path=str(output / f"{phase}-{theme}-{width}.jpg"), type="jpeg", quality=82, animations="allow")
                result = page.evaluate("""() => {
                  const panel = document.querySelector('#generate-qr-section');
                  const paper = document.querySelector('#generatedMotionTextPaper');
                  const pre = document.querySelector('#generatedMotionTextArt');
                  return {
                    theme: document.documentElement.getAttribute('data-theme'),
                    viewport: innerWidth,
                    document_width: document.documentElement.scrollWidth,
                    panel_width: Math.round(panel.getBoundingClientRect().width),
                    paper_width: Math.round(paper.getBoundingClientRect().width),
                    pre_width: Math.round(pre.getBoundingClientRect().width),
                    pre_scroll_width: pre.scrollWidth,
                    text_length: pre.textContent.length,
                    image_visible: getComputedStyle(document.querySelector('#generatedQrImage')).display !== 'none',
                    play_button_count: document.querySelectorAll('#generatedMotionToggle').length,
                  };
                }""")
                result["phase"] = phase
                results.append(result)
            finally:
                context.close()
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True, help="Clean worktree at origin/main")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    response = responses()
    records = []
    with tempfile.TemporaryDirectory(prefix="safescan-ascii-motion-evidence-") as temp_dir:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                for phase, repo in (("before", args.baseline), ("after", ROOT)):
                    port = free_port()
                    base_url = f"http://localhost:{port}"
                    phase_temp = Path(temp_dir) / phase
                    phase_temp.mkdir()
                    process = subprocess.Popen(
                        [sys.executable, "-m", "uvicorn", "hackabull:qr_app", "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
                        cwd=repo,
                        env=isolated_server_env(str(phase_temp), base_url),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    try:
                        wait_for_server(base_url, process)
                        records.extend(capture(browser, phase, base_url, response[phase], args.output))
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.communicate(timeout=5)
            finally:
                browser.close()
    (args.output / "metrics.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
