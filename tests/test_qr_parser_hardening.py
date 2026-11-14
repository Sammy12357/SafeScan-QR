"""Untrusted QR images, SVGs, and PDFs stay inside explicit parser limits."""

import importlib
import io
import time

import pytest
import qrcode
from PIL import Image
from qrcode.image.svg import SvgPathImage


@pytest.fixture()
def decoder(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'parser.db'}")
    return importlib.import_module("hackabull.qr_decode")


def test_svg_entity_bomb_is_rejected_before_expansion(decoder):
    document = b'''<!DOCTYPE svg [
    <!ENTITY a "abcdefghij">
    <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
    <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
    ]><svg xmlns="http://www.w3.org/2000/svg"><text>&c;</text></svg>'''

    started = time.monotonic()
    with pytest.raises(decoder.QRDecodeSafetyError, match="prohibited XML"):
        decoder._decode_qr_upload_inprocess(document, "bomb.svg", "image/svg+xml")
    assert time.monotonic() - started < 1.0


def test_svg_long_regex_attribute_and_deep_tree_are_rejected(decoder):
    long_viewbox = b'<svg viewBox="' + b"1" * 4097 + b'"/>'
    with pytest.raises(decoder.QRDecodeSafetyError, match="attributes"):
        decoder._parse_safe_svg(long_viewbox)

    deep = b"<svg>" + b"<g>" * 65 + b"</g>" * 65 + b"</svg>"
    with pytest.raises(decoder.QRDecodeSafetyError, match="structure"):
        decoder._parse_safe_svg(deep)


def test_valid_qr_svg_path_can_exceed_parsed_attribute_cap(decoder):
    # The path data is not parsed by SafeScan's SVG geometry regexes. A normal
    # QR generator can put thousands of path commands into that one attribute.
    svg = qrcode.make("https://example.com/", image_factory=SvgPathImage).to_string()
    assert len(svg) > 4096
    assert decoder._parse_safe_svg(svg).tag.endswith("svg")


@pytest.mark.parametrize("format_name", ["TIFF", "EPS"])
def test_unsupported_raster_is_rejected_before_decode(decoder, monkeypatch, format_name):
    output = io.BytesIO()
    Image.new("RGB", (80, 80), "white").save(output, format=format_name)
    monkeypatch.setattr(decoder, "_decode_qr_from_pil_image", lambda *_args, **_kwargs: pytest.fail("decoded unsupported format"))

    with pytest.raises(decoder.QRDecodeSafetyError, match="Unsupported QR image format"):
        decoder._decode_qr_upload_inprocess(output.getvalue(), f"image.{format_name.lower()}")


def test_animated_png_is_rejected(decoder):
    output = io.BytesIO()
    first = Image.new("RGB", (40, 40), "white")
    second = Image.new("RGB", (40, 40), "black")
    first.save(output, format="PNG", save_all=True, append_images=[second], duration=100)

    with pytest.raises(decoder.QRDecodeSafetyError, match="multi-frame"):
        decoder._decode_qr_upload_inprocess(output.getvalue(), "animated.png")


def test_pillow_decompression_warning_is_rejected(decoder, monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (6, 6), "white").save(output, format="PNG")
    monkeypatch.setattr(decoder.PILImage, "MAX_IMAGE_PIXELS", 20)

    with pytest.raises(decoder.QRDecodeSafetyError, match="40 megapixel"):
        decoder._decode_qr_upload_inprocess(output.getvalue(), "oversized.png")


def test_pdf_page_over_render_budget_is_rejected_before_rasterization(decoder):
    fitz = pytest.importorskip("fitz")
    document = fitz.open()
    try:
        document.new_page(width=3000, height=3000)
        contents = document.tobytes()
    finally:
        document.close()

    with pytest.raises(decoder.QRDecodeSafetyError, match="12 megapixel"):
        decoder._decode_qr_upload_inprocess(contents, "giant.pdf", "application/pdf")
