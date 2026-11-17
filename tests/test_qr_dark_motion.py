"""Dark gradients retain the moving ASCII look and scan in exported files."""

import io

import cv2
import numpy as np
import pytest
import zxingcpp
from PIL import Image

from hackabull.qr_image import ascii_motion_color_rgb, qr_ascii_motion_pngs_from_payload
from hackabull.qr_motion_gif import qr_ascii_motion_gif_from_apng


URL = "https://example.com/dark-test"


@pytest.mark.parametrize("start,end,checked", [
    ("#2A1B36", "#8A280C", True),
    ("#153E3E", "#4B246B", False),
    ("#10264A", "#42316B", False),
])
def test_dark_gradient_apng_and_gif_frames_scan_at_phone_size(start, end, checked):
    still_bytes, apng_bytes = qr_ascii_motion_pngs_from_payload(
        URL, gradient_start=start, gradient_end=end, include_attribution=checked,
    )
    gif_bytes = qr_ascii_motion_gif_from_apng(apng_bytes, URL)
    for name, data in (("APNG", apng_bytes), ("GIF", gif_bytes)):
        with Image.open(io.BytesIO(data)) as image:
            assert image.n_frames == 4
            frames = []
            for index in range(image.n_frames):
                image.seek(index)
                frame = image.convert("RGB")
                frames.append(frame.tobytes())
                if name == "APNG" and index == 0:
                    with Image.open(io.BytesIO(still_bytes)) as still:
                        assert still.convert("RGB").tobytes() == frame.tobytes()
                preview = frame.resize(
                    (279, round(frame.height * 279 / frame.width)), Image.Resampling.LANCZOS,
                )
                pixels = cv2.cvtColor(np.asarray(preview), cv2.COLOR_RGB2BGR)
                cv_value, _, _ = cv2.QRCodeDetector().detectAndDecode(pixels)
                assert cv_value == URL, (name, start, end, index)
                assert {result.text for result in zxingcpp.read_barcodes(preview)} == {URL}
            assert len(set(frames)) == 4, f"{name} must contain four distinct frames"


@pytest.mark.parametrize("color", ["#5A5A5A", "#FFFFFF", "#FFEE00", "#0000000"])
def test_bright_or_malformed_gradient_colors_are_rejected(color):
    with pytest.raises(ValueError, match="darker color|six-digit hex color"):
        ascii_motion_color_rgb(color)


def test_contrast_boundary_allows_a_valid_dark_gray():
    assert ascii_motion_color_rgb("#595959") == (89, 89, 89)
