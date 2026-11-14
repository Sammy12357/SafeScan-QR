"""Isolated QR upload worker. Communicates only over stdin/stdout JSON.

The parent enforces the wall-clock deadline and terminates this process if a
native decoder fails to return. No decoded payload or image is logged here.
"""

from __future__ import annotations

import base64
import io
import json
import sys
from pathlib import Path
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hackabull.qr_decode import (
    QRDecodeAmbiguityError,
    QRDecodeSafetyError,
    _QR_TIER_EVENTS,
    _decode_qr_upload_inprocess,
    _looks_like_pdf,
    _looks_like_svg,
)


def main() -> None:
    header_size = int.from_bytes(sys.stdin.buffer.read(4), "big")
    if not 0 < header_size <= 4096:
        raise ValueError("Invalid QR worker metadata length")
    metadata = json.loads(sys.stdin.buffer.read(header_size))
    filename = metadata.get("filename", "")
    content_type = metadata.get("content_type", "")
    contents = sys.stdin.buffer.read()
    events = []
    token = _QR_TIER_EVENTS.set(events)
    result = {"payload": None, "image": None, "error": None, "tier_events": events}
    image = None
    try:
        payload, image = _decode_qr_upload_inprocess(contents, filename, content_type)
        result["payload"] = payload
        # Raster uploads can be reopened by the parent from the original bytes.
        # PDF and SVG scans return their selected rendered page to the parent.
        if payload and image is not None and (
            _looks_like_pdf(contents, filename, content_type)
            or _looks_like_svg(contents, filename, content_type)
        ):
            preview = image.copy()
            try:
                # The analysis pipeline uses this image only to mark the
                # upload source today. Keep a useful rendered preview while
                # bounding the PNG carried back over the worker pipe.
                preview.thumbnail((1024, 1024), Image.Resampling.LANCZOS)
                output = io.BytesIO()
                preview.save(output, format="PNG")
                if output.tell() > 4 * 1024 * 1024:
                    raise QRDecodeSafetyError("Rendered QR preview exceeds the size limit.")
                result["image"] = base64.b64encode(output.getvalue()).decode("ascii")
            finally:
                preview.close()
    except QRDecodeAmbiguityError as exc:
        result.update(error="ambiguity", message=str(exc))
    except QRDecodeSafetyError as exc:
        result.update(error="safety", message=str(exc))
    except Exception:
        result["error"] = "internal"
    finally:
        if image is not None:
            image.close()
        _QR_TIER_EVENTS.reset(token)
    sys.stdout.write(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
