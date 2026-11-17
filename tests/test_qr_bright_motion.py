"""Bright ASCII outlines retain a normal-polarity QR across moving frames."""

import io

import cv2
import numpy as np
import pytest
import zxingcpp
from PIL import Image, ImageChops

from hackabull.qr_image import qr_ascii_motion_pngs_from_payload


URL = "https://example.com/bright-test"


@pytest.mark.parametrize("start,end,checked", [
    ("#FFFFFF", "#FFEE00", False),
    ("#000000", "#FFFFFF", False),
    ("#FF0000", "#0000FF", True),
])
def test_bright_gradient_apng_scans_with_two_independent_readers(start, end, checked):
    still_bytes, animated_bytes = qr_ascii_motion_pngs_from_payload(
        URL, gradient_start=start, gradient_end=end, include_attribution=checked,
    )
    with Image.open(io.BytesIO(animated_bytes)) as animated:
        assert animated.n_frames == 4
        previews = []
        compact_previews = []
        finder_motion = [[], [], []]
        for index in range(4):
            animated.seek(index)
            frame = animated.convert("RGB")
            modules = frame.width // 26
            origins = ((4, 4), (modules - 11, 4), (4, modules - 11))
            for corner, (x, y) in enumerate(origins):
                finder_motion[corner].append(
                    frame.crop((x * 26, y * 26, (x + 7) * 26, (y + 7) * 26)).tobytes()
                )
            if index == 0:
                with Image.open(io.BytesIO(still_bytes)) as still:
                    assert still.convert("RGB").tobytes() == frame.tobytes()
                # Conventional polarity needs a complete light quiet zone.
                assert frame.crop((0, 0, frame.width, 4 * 26)).getextrema() == ((255, 255),) * 3
            preview = frame.resize(
                (320, round(frame.height * 320 / frame.width)), Image.Resampling.LANCZOS,
            )
            compact_preview = frame.resize(
                (279, round(frame.height * 279 / frame.width)), Image.Resampling.LANCZOS,
            )
            previews.append(preview)
            compact_previews.append(np.asarray(compact_preview, dtype=np.int16))
            for candidate in (frame, preview, compact_preview):
                pixels = cv2.cvtColor(np.asarray(candidate), cv2.COLOR_RGB2BGR)
                cv_value, _, _ = cv2.QRCodeDetector().detectAndDecode(pixels)
                assert cv_value == URL, (start, end, index, candidate.size)
                zx_values = {result.text for result in zxingcpp.read_barcodes(candidate)}
                assert zx_values == {URL}, (start, end, index, candidate.size)
        assert all(
            ImageChops.difference(previews[0], other).getbbox()
            for other in previews[1:]
        ), "The small displayed QR must visibly change in every frame"
        assert all(
            np.count_nonzero(np.max(np.abs(compact_previews[0] - other), axis=2) > 20) >= 10000
            for other in compact_previews[1:]
        ), "The compact preview must visibly animate, including its dark QR cells"
        assert all(len(set(corners)) == 4 for corners in finder_motion)
        if start == "#000000":
            top_data = previews[0].crop((100, 30, 215, 95))
            assert any(0 < max(pixel) < 255 for pixel in top_data.getdata())
