"""Turn the verified ASCII-motion APNG into a widely playable GIF download."""

import io

from PIL import Image, ImageChops

from .qr_decode import decode_qr_image
from .qr_image import QRAsciiMotionDecodeError


_FRAME_COUNT = 4
_FRAME_DURATION_MS = 350


def qr_ascii_motion_gif_from_apng(animated_png: bytes, payload: str) -> bytes:
    """Export full GIF frames and verify each frame still scans as ``payload``.

    The APNG is generated and checked by ``qr_ascii_motion_pngs_from_payload``.
    Its first-frame PNG remains the fallback, and the APNG remains the browser
    preview. GIF is only the downloaded animation because many image viewers
    display APNG files as a still PNG.
    """
    with Image.open(io.BytesIO(animated_png)) as source:
        if source.format != "PNG" or source.n_frames != _FRAME_COUNT:
            raise QRAsciiMotionDecodeError("The animated PNG lost a frame.")
        frames = []
        for index in range(source.n_frames):
            source.seek(index)
            frames.append(source.convert("RGB").copy())

    output = io.BytesIO()
    frames[0].save(
        output, format="GIF", save_all=True, append_images=frames[1:],
        duration=_FRAME_DURATION_MS, loop=0, disposal=2, optimize=True,
    )
    gif_bytes = output.getvalue()

    with Image.open(io.BytesIO(gif_bytes)) as exported:
        if exported.format != "GIF" or exported.n_frames != _FRAME_COUNT or exported.info.get("loop") != 0:
            raise QRAsciiMotionDecodeError("The animated GIF lost its motion.")
        first_frame = None
        for index in range(exported.n_frames):
            exported.seek(index)
            if exported.info.get("duration") != _FRAME_DURATION_MS:
                raise QRAsciiMotionDecodeError("The animated GIF lost its timing.")
            frame = exported.convert("RGB")
            if first_frame is None:
                first_frame = frame
            elif not ImageChops.difference(first_frame, frame).getbbox():
                raise QRAsciiMotionDecodeError("The animated GIF lost its motion.")
            preview = frame.resize(
                (320, round(frame.height * 320 / frame.width)), Image.Resampling.LANCZOS,
            )
            for candidate in (frame, preview):
                decoded = {barcode.data.decode("utf-8") for barcode in decode_qr_image(candidate)}
                if decoded != {payload}:
                    raise QRAsciiMotionDecodeError("The animated GIF did not decode reliably.")

    return gif_bytes
