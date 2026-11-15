"""Keep layout spacing on the shared token scale as new UI is added."""

from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
TEMPLATES = ROOT / "templates"

SPACING_DECLARATION = re.compile(
    r"(?<![\w-])"
    r"(?P<property>(?:padding|margin)(?:-[\w-]+)?|"
    r"(?:row|column)-gap|gap|inset(?:-[\w-]+)?)"
    r"\s*:\s*(?P<value>[^;{}]+)(?=;|\})"
)
RAW_LENGTH = re.compile(
    r"(?<![\w-])-?(?:\d*\.)?\d+"
    r"(?:px|rem|em|vh|vw|vmin|vmax|ch|ex|pt|cm|mm|in|pc)\b"
)
RAW_ZERO = re.compile(r"(?<![\w.%#-])0(?![\w.%])")
CSS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
STYLE_BLOCK = re.compile(r"<style(?:\s[^>]*)?>.*?</style>", re.IGNORECASE | re.DOTALL)

# A full-bleed section must offset itself by half of the viewport difference.
# This is viewport geometry, so forcing it onto a fixed spacing token would
# change the layout at every width other than the one captured in a screenshot.
ALLOWED_RAW_SPACING = {
    ("styles-scanner.css", "margin-left", "calc(50% - 50vw)"),
}


def spacing_errors(css: str, source: str) -> list[str]:
    without_comments = CSS_COMMENT.sub(lambda match: "\n" * match.group().count("\n"), css)
    errors = []
    for match in SPACING_DECLARATION.finditer(without_comments):
        prop = match.group("property")
        value = match.group("value").strip()
        if (source, prop, value) in ALLOWED_RAW_SPACING:
            continue
        if RAW_LENGTH.search(value) or RAW_ZERO.search(value):
            line = without_comments.count("\n", 0, match.start()) + 1
            errors.append(f"{source}:{line}: {prop}: {value}")
    return errors


@pytest.mark.parametrize("css_file", sorted(STATIC.glob("*.css")), ids=lambda path: path.name)
def test_stylesheet_spacing_uses_tokens(css_file: Path) -> None:
    if "vendor" in css_file.parts:
        pytest.skip("Third-party CSS is outside the design system")
    errors = spacing_errors(css_file.read_text(), css_file.name)
    assert not errors, "Raw layout spacing found:\n" + "\n".join(errors)


def test_templates_have_no_inline_style_blocks() -> None:
    offenders = [path.name for path in TEMPLATES.glob("*.html") if STYLE_BLOCK.search(path.read_text())]
    assert not offenders, "Move template <style> blocks to static stylesheets: " + ", ".join(offenders)
