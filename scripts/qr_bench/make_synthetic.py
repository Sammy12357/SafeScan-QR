"""Build the deterministic synthetic camera QR corpus.

Run from the repository root with ``python scripts/qr_bench/make_synthetic.py``.
The checked-in PNGs are generated, not hand-edited.  All random texture and
noise uses fixed seeds so regenerating the corpus produces identical files.
The labels list *every* QR payload placed in a scene, including overlapping
or intentionally hard-to-read symbols.  A decoder may return fewer symbols;
that is what the benchmark is meant to measure.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import random
from pathlib import Path

import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter, ImageFont, ImageOps
import zxingcpp


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = ROOT / "tests" / "qr_corpus" / "synthetic"
FRAME = (1280, 720)
PAYLOAD = "https://sqafe.com/scan/corpus?case=sample-2026&source=synthetic"
PAYLOAD_A = PAYLOAD + "&code=A"
PAYLOAD_B = PAYLOAD + "&code=B"
MICRO_PAYLOAD = "SQR123"


def seed_for(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode("ascii")).digest()[:8], "big")


def scene(name: str, *, dark: bool = False) -> Image.Image:
    """A mildly cluttered, reproducible camera background without QR motifs."""
    background = (35, 39, 45) if dark else (234, 238, 242)
    image = Image.new("RGB", FRAME, background)
    draw = ImageDraw.Draw(image)
    rng = random.Random(seed_for(name))
    palette = [(54, 58, 65), (64, 68, 73)] if dark else [(213, 219, 225), (222, 227, 231)]
    for _ in range(26):
        x = rng.randrange(FRAME[0])
        y = rng.randrange(FRAME[1])
        width = rng.randrange(40, 230)
        color = palette[rng.randrange(len(palette))]
        if rng.random() < 0.65:
            draw.line((x, y, min(FRAME[0], x + width), y), fill=color, width=2)
        else:
            draw.ellipse((x, y, x + 8, y + 8), fill=color)
    return image


def qr_image(
    payload: str = PAYLOAD,
    size: int = 320,
    *,
    error_correction: int = qrcode.constants.ERROR_CORRECT_M,
    foreground: tuple[int, int, int] = (20, 24, 30),
    background: tuple[int, int, int] = (255, 255, 255),
) -> Image.Image:
    qr = qrcode.QRCode(
        version=None,
        error_correction=error_correction,
        box_size=8,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color=foreground, back_color=background).convert("RGB").resize(
        (size, size), Image.Resampling.NEAREST
    )


def paste(image: Image.Image, code: Image.Image, x: int, y: int) -> Image.Image:
    image.paste(code, (x, y))
    return image


def perspective_coefficients(
    source_size: tuple[int, int], target_points: tuple[tuple[float, float], ...]
) -> tuple[float, ...]:
    """Map target quadrilateral pixels back to the source square for Pillow."""
    width, height = source_size
    source_points = ((0, 0), (width, 0), (width, height), (0, height))
    equations = []
    values = []
    for (x, y), (u, v) in zip(target_points, source_points, strict=True):
        equations.append((x, y, 1, 0, 0, 0, -u * x, -u * y))
        values.append(u)
        equations.append((0, 0, 0, x, y, 1, -v * x, -v * y))
        values.append(v)
    return tuple(np.linalg.solve(np.asarray(equations), np.asarray(values)))


def tilted(code: Image.Image, output_size: tuple[int, int], points: tuple[tuple[int, int], ...]) -> Image.Image:
    return code.transform(
        output_size,
        Image.Transform.PERSPECTIVE,
        perspective_coefficients(code.size, points),
        resample=Image.Resampling.BICUBIC,
        fillcolor=(255, 255, 255),
    )


def motion_blur(code: Image.Image, distance: int = 24) -> Image.Image:
    source = np.asarray(code, dtype=np.float32)
    accumulator = np.zeros_like(source)
    for shift in range(distance):
        # A handheld exposure smears along a short diagonal, not a perfect
        # horizontal line. Edge extension avoids np.roll wrap-around.
        xs = np.clip(np.arange(source.shape[1]) - shift, 0, source.shape[1] - 1)
        ys = np.clip(np.arange(source.shape[0]) - round(shift * 0.28), 0, source.shape[0] - 1)
        accumulator += source[ys[:, None], xs[None, :]]
    return Image.fromarray(np.uint8(np.rint(accumulator / distance)))


def curved(code: Image.Image) -> Image.Image:
    """Approximate a label wrapped around a cylinder with horizontal pinching."""
    source = np.asarray(code)
    height, width = source.shape[:2]
    target = np.full_like(source, 255)
    center = (width - 1) / 2
    for x in range(width):
        normalized = (x - center) / center
        source_x = int(round(center + center * math.sin(normalized * 1.12) / math.sin(1.12)))
        vertical_shift = int(round(13 * normalized * normalized))
        target[:, x] = source[np.clip(np.arange(height) + vertical_shift, 0, height - 1), source_x]
    return Image.fromarray(target)


def moire(code: Image.Image) -> Image.Image:
    source = np.asarray(code, dtype=np.float32)
    height, width = source.shape[:2]
    xs = np.arange(width, dtype=np.float32)[None, :]
    ys = np.arange(height, dtype=np.float32)[:, None]
    interference = 14 * np.sin(xs * 1.18 + ys * 0.24) + 10 * np.sin(ys * 1.54)
    source += interference[:, :, None]
    return Image.fromarray(np.uint8(np.clip(source, 0, 255)))


def stylized_logo(size: int = 360) -> Image.Image:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=8,
        border=4,
    )
    qr.add_data(PAYLOAD)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    width = len(matrix)
    module = size / width
    image = Image.new("RGB", (size, size), (255, 250, 249))
    draw = ImageDraw.Draw(image)
    for row, bits in enumerate(matrix):
        for col, bit in enumerate(bits):
            if bit:
                x0 = round(col * module)
                y0 = round(row * module)
                x1 = round((col + 1) * module) - 1
                y1 = round((row + 1) * module) - 1
                draw.rounded_rectangle((x0, y0, x1, y1), radius=max(1, round(module * 0.2)), fill=(182, 40, 82))
    # A center mark hides some data modules; ECC H should tolerate its size.
    margin = round(size * 0.08)
    logo = size // 2
    draw.rounded_rectangle(
        (logo - margin, logo - margin, logo + margin, logo + margin),
        radius=12,
        fill=(255, 250, 249),
    )
    draw.text((logo, logo), "S", font=ImageFont.load_default(), fill=(182, 40, 82), anchor="mm")
    return image


def micro_qr(size: int = 250) -> Image.Image:
    barcode = zxingcpp.create_barcode(MICRO_PAYLOAD, zxingcpp.MicroQRCode)
    pixels = np.asarray(zxingcpp.write_barcode_to_image(barcode, scale=14))
    return Image.fromarray(pixels).convert("RGB").resize((size, size), Image.Resampling.NEAREST)


def build_cases() -> dict[str, tuple[Image.Image, list[str]]]:
    cases: dict[str, tuple[Image.Image, list[str]]] = {}

    def add(name: str, image: Image.Image, payloads: list[str] | None = None) -> None:
        cases[name + ".png"] = (image, payloads or [PAYLOAD])

    add("01_clean_centered", paste(scene("clean"), qr_image(), 480, 200))
    add("02_off_center_corner", paste(scene("corner"), qr_image(size=220), 1010, 40))
    add("03_quiet_zone_clipped", paste(scene("edge"), qr_image(size=300), -22, 210))
    add("04_small_far_90", paste(scene("far"), qr_image(size=90), 595, 305))
    add("05_small_far_corner_80", paste(scene("far-corner"), qr_image(size=80), 1140, 35))

    downscaled = paste(scene("downscaled"), qr_image(size=85), 590, 295)
    add("06_small_after_720_downscale", downscaled.resize((720, 405), Image.Resampling.BICUBIC))

    rotated = qr_image(size=310).rotate(35, expand=True, fillcolor=(255, 255, 255), resample=Image.Resampling.BICUBIC)
    add("07_rotated_35_degrees", paste(scene("rotated"), rotated, 420, 130))

    # The far edge is about half the width of the near edge, like a table-tent
    # photographed from above at a sharp angle. A simple shear is too easy.
    skewed = tilted(qr_image(size=340), (420, 330), ((155, 20), (285, 5), (405, 320), (8, 290)))
    add("08_perspective_tilt", paste(scene("tilted"), skewed, 430, 175))

    # Render at high source resolution before projecting into a small region;
    # this avoids accidental nearest-neighbor aliasing in the test fixture.
    small_skewed = tilted(qr_image(size=600), (210, 175), ((72, 10), (154, 2), (205, 168), (3, 145)))
    add("09_perspective_small_corner", paste(scene("tilted-small"), small_skewed, 1040, 30))

    add("10_gaussian_blur", paste(scene("gaussian"), qr_image().filter(ImageFilter.GaussianBlur(1.7)), 480, 200))
    add("11_motion_blur", paste(scene("motion"), motion_blur(qr_image()), 480, 200))

    low_contrast = qr_image(size=320, foreground=(115, 120, 126), background=(211, 213, 215))
    noisy = np.asarray(low_contrast, dtype=np.int16) + np.random.default_rng(20261113).normal(0, 9, (320, 320, 1))
    add("12_low_contrast_noise", paste(scene("noise"), Image.fromarray(np.uint8(np.clip(noisy, 0, 255))), 480, 200))

    glare = qr_image().copy()
    glare_overlay = Image.new("RGBA", glare.size, (0, 0, 0, 0))
    glare_draw = ImageDraw.Draw(glare_overlay)
    for radius in range(82, 8, -6):
        alpha = round(4 + (82 - radius) * 1.3)
        glare_draw.ellipse((210 - radius, 130 - radius, 210 + radius, 130 + radius), fill=(255, 255, 255, alpha))
    glare = Image.alpha_composite(glare.convert("RGBA"), glare_overlay).convert("RGB")
    add("13_glare_spot", paste(scene("glare"), glare, 480, 200))

    dim = paste(scene("dim", dark=True), qr_image(size=320, foreground=(0, 0, 0), background=(115, 119, 122)), 480, 200)
    add("14_low_light", ImageEnhance.Brightness(dim).enhance(0.52))
    add("15_inverted", paste(scene("inverted", dark=True), qr_image(size=320, foreground=(250, 250, 250), background=(25, 26, 27)), 480, 200))
    add("16_mirrored", paste(scene("mirrored"), ImageOps.mirror(qr_image()), 480, 200))

    jpeg_scene = paste(scene("jpeg"), qr_image(size=145), 1020, 80)
    buffer = io.BytesIO()
    jpeg_scene.save(buffer, format="JPEG", quality=35, subsampling=2)
    buffer.seek(0)
    add("17_jpeg_q35_small", Image.open(buffer).convert("RGB"))

    blurred_small = qr_image(size=125).filter(ImageFilter.GaussianBlur(0.9))
    add("18_blur_small_corner", paste(scene("blur-small"), blurred_small, 1080, 45))

    add("19_curved_cylinder", paste(scene("curved"), curved(qr_image(size=350)), 465, 175))
    screen = scene("screen", dark=True)
    draw = ImageDraw.Draw(screen)
    draw.rounded_rectangle((345, 95, 935, 610), radius=18, fill=(28, 34, 43), outline=(17, 20, 25), width=10)
    screen.paste(moire(qr_image(size=365)), (456, 165))
    add("20_screen_moire", screen)

    add("21_stylized_logo", paste(scene("stylized"), stylized_logo(), 460, 180))

    two = scene("two")
    paste(two, qr_image(PAYLOAD_A, 300), 280, 180)
    paste(two, qr_image(PAYLOAD_B, 275), 720, 210)
    add("22_two_codes", two, [PAYLOAD_A, PAYLOAD_B])

    overlap = scene("overlap")
    paste(overlap, qr_image(PAYLOAD_A, 400, error_correction=qrcode.constants.ERROR_CORRECT_H), 320, 120)
    paste(overlap, qr_image(PAYLOAD_B, 185), 660, 405)
    add("23_overlapping_stickers", overlap, [PAYLOAD_A, PAYLOAD_B])

    add("24_micro_qr", paste(scene("micro"), micro_qr(), 510, 220), [MICRO_PAYLOAD])
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="Destination for PNGs and labels.json")
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    cases = build_cases()
    labels = {}
    for filename, (image, payloads) in cases.items():
        image.save(output / filename, format="PNG", optimize=True)
        labels[filename] = payloads
    (output / "labels.json").write_text(json.dumps(labels, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(cases)} cases to {output}")


if __name__ == "__main__":
    main()
