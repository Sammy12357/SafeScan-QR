"""Render the public social preview from the current SafeScan SVG mark.

Run with ``python scripts/build_social_card.py`` after changing the logo or
brand colors. This is a build-time asset; the deployed app serves the PNG.
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
LOGO = ROOT / "static" / "safescan-logo.svg"
OUTPUT = ROOT / "static" / "safescan-social-card.png"
SCALE = 2
WIDTH, HEIGHT = 1200, 630
PINK = "#ff668e"
PALE = "#fff8fa"


def _font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = (
        ("/System/Library/Fonts/Avenir Next.ttc", 8 if bold else 7),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 0) if bold
        else ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 0),
        ("/Library/Fonts/Arial.ttf", 0),
    )
    for filename, index in candidates:
        if Path(filename).exists():
            return ImageFont.truetype(filename, size * SCALE, index=index)
    return ImageFont.truetype("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf", size * SCALE)


def _rect(draw: ImageDraw.ImageDraw, box, *, fill, radius=0, outline=None, width=1) -> None:
    scaled = tuple(round(value * SCALE) for value in box)
    draw.rounded_rectangle(scaled, radius=round(radius * SCALE), fill=fill,
                           outline=outline, width=round(width * SCALE))


def _text(draw: ImageDraw.ImageDraw, xy, value: str, *, size: int, color: str, bold=False) -> None:
    draw.text((xy[0] * SCALE, xy[1] * SCALE), value, font=_font(size, bold=bold),
              fill=color, stroke_width=0)


def _logo_tiles():
    root = ElementTree.parse(LOGO).getroot()
    ns = "{http://www.w3.org/2000/svg}"
    for tile in root.findall(f"{ns}g/{ns}rect"):
        yield tuple(float(tile.attrib[key]) for key in ("x", "y", "width", "height", "rx")), tile.attrib["fill"]


def build() -> None:
    size = (WIDTH * SCALE, HEIGHT * SCALE)
    image = Image.new("RGB", size, "#08090d")

    glow = Image.new("RGBA", size, (0, 0, 0, 0))
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.ellipse((-100 * SCALE, -160 * SCALE, 700 * SCALE, 680 * SCALE),
                      fill=(255, 45, 104, 98))
    glow = glow.filter(ImageFilter.GaussianBlur(140 * SCALE))
    image = Image.alpha_composite(image.convert("RGBA"), glow)
    draw = ImageDraw.Draw(image)

    _rect(draw, (38, 38, 1162, 592), fill="#10131b", radius=32,
          outline="#49313e", width=2)
    _rect(draw, (89, 138, 431, 480), fill="#08090d", radius=56,
          outline="#8e3a56", width=2)

    # Draw the exact current tile layout from the favicon SVG, scaled into the
    # social card. A soft duplicate produces the favicon's pink glow.
    tile_glow = Image.new("RGBA", size, (0, 0, 0, 0))
    tile_glow_draw = ImageDraw.Draw(tile_glow)
    logo_x, logo_y, logo_size = 89, 138, 342
    for (x, y, width, height, radius), color in _logo_tiles():
        box = (logo_x + x * logo_size / 512, logo_y + y * logo_size / 512,
               logo_x + (x + width) * logo_size / 512,
               logo_y + (y + height) * logo_size / 512)
        _rect(tile_glow_draw, box, fill=(255, 96, 145, 120),
              radius=radius * logo_size / 512)
    image = Image.alpha_composite(image, tile_glow.filter(ImageFilter.GaussianBlur(6 * SCALE)))
    draw = ImageDraw.Draw(image)
    for (x, y, width, height, radius), color in _logo_tiles():
        box = (logo_x + x * logo_size / 512, logo_y + y * logo_size / 512,
               logo_x + (x + width) * logo_size / 512,
               logo_y + (y + height) * logo_size / 512)
        _rect(draw, box, fill=color, radius=radius * logo_size / 512)

    draw.line([(475 * SCALE, 97 * SCALE), (475 * SCALE, 533 * SCALE)],
              fill="#49313e", width=2 * SCALE)
    draw.line([(508 * SCALE, 137 * SCALE), (590 * SCALE, 137 * SCALE)],
              fill=PINK, width=7 * SCALE)
    _text(draw, (505, 161), "SafeScan QR", size=70, color=PALE, bold=True)
    _text(draw, (507, 279), "Check before you open.", size=40, color=PINK, bold=True)
    _text(draw, (508, 368), "Scan QR codes. Review the destination", size=26,
          color="#c7c4cd")
    _text(draw, (508, 408), "and risk signals before you act.", size=26,
          color="#c7c4cd")
    draw.line([(508 * SCALE, 477 * SCALE), (1103 * SCALE, 477 * SCALE)],
              fill="#49313e", width=2 * SCALE)
    _text(draw, (508, 503), "SQAFE.COM", size=24, color="#ff8ba9", bold=True)

    image.convert("RGB").resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS).save(
        OUTPUT, format="PNG", optimize=True
    )


if __name__ == "__main__":
    build()
