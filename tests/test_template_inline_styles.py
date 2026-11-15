"""Keep inline styles limited to reviewed chart dimensions and defaults."""

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"

# File, element, class, exact style value. These express data-driven widths and
# heights that a shared stylesheet cannot know before rendering.
ALLOWED_INLINE_STYLES = Counter({
    ("index.html", "div", "score-gauge", "--score: 0;"): 1,
    ("index.html", "span", "ml-safe-bar", "width: {{ (ml_risk.benignProbability * 100) | round(2) }}%;"): 1,
    ("index.html", "span", "ml-malicious-bar", "width: {{ (ml_risk.maliciousProbability * 100) | round(2) }}%;"): 1,
    ("admin_shell.html", "span", "", "height: {{ [8, row.total * 8]|max }}px"): 1,
    ("admin_shell.html", "b", "", "height: {{ [4, row.flagged * 10]|max }}px"): 1,
})


class StyleAttributeParser(HTMLParser):
    def __init__(self, filename: str) -> None:
        super().__init__()
        self.filename = filename
        self.styles: Counter[tuple[str, str, str, str]] = Counter()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if "style" in attributes:
            self.styles[(self.filename, tag, attributes.get("class") or "", attributes["style"] or "")] += 1


def test_template_style_attributes_stay_on_explicit_allowlist() -> None:
    found: Counter[tuple[str, str, str, str]] = Counter()
    for template in sorted(TEMPLATES.rglob("*.html")):
        parser = StyleAttributeParser(str(template.relative_to(TEMPLATES)))
        parser.feed(template.read_text())
        found.update(parser.styles)
    unexpected = found - ALLOWED_INLINE_STYLES
    assert not unexpected, "Unreviewed template style attributes: " + repr(list(unexpected.elements()))
