"""Run axe on every Phase 7 synthetic state at the Phase 8 viewport matrix."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import sync_playwright

from ui_phase7_screenshots import WIDTHS, THEMES, environment, fixture_contexts, prepare_page, serve


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--axe-path", required=True, type=Path, help="Installed axe-core axe.min.js")
    args = parser.parse_args()
    axe_path = args.axe_path.resolve()
    if not axe_path.is_file():
        parser.error(f"Axe script not found: {axe_path}")
    fixtures = fixture_contexts()
    violations = []
    checked = 0

    with TemporaryDirectory(prefix="safescan-phase8-axe-") as temp:
        site = Path(temp)
        (site / "static").symlink_to(ROOT / "static", target_is_directory=True)
        templates = environment(ROOT / "templates")
        for name, (template, context) in fixtures.items():
            (site / f"{name}.html").write_text(templates.get_template(template).render(**context), encoding="utf-8")
        server, thread = serve(site)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(reduced_motion="reduce")
                context.add_init_script(path=str(axe_path))
                page = context.new_page()
                page.route("**/*.js*", lambda route: route.abort())
                for theme in THEMES:
                    for width in WIDTHS:
                        page.set_viewport_size({"width": width, "height": 900})
                        for name in fixtures:
                            page.goto(f"http://127.0.0.1:{server.server_port}/{name}.html", wait_until="domcontentloaded")
                            prepare_page(page, name, "after", theme)
                            results = page.evaluate("""async () => {
                              const audit = await axe.run(document, {runOnly: {type: 'tag', values: [
                                'wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa'
                              ]}});
                              return audit.violations.map(v => ({id: v.id, nodes: v.nodes.map(n => n.target)}));
                            }""")
                            checked += 1
                            if results:
                                violations.append({"view": name, "theme": theme, "width": width, "violations": results})
                browser.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)

    report = {"checked": checked, "fixtures": len(fixtures), "violations": violations}
    output = ROOT / ".cache" / "ui-shots" / "phase8-axe-report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Axe checked {checked} combinations of {len(fixtures)} fixtures; {len(violations)} combinations with violations")
    if violations:
        print(json.dumps(violations[:5], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
