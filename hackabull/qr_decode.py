from __future__ import annotations
import requests
import json
import warnings
import io
import sqlite3
import hashlib
import hmac
import math
import re
import asyncio
import base64
import ipaddress
import secrets
import socket
import time
import csv
import threading
import subprocess
import sys
import contextvars
from decimal import Decimal, InvalidOperation
from html import escape as escape_html
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree

from PIL import Image as PILImage

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import os
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from db import (
    assert_owns_row,
    clear_rls_context,
    database_path,
    database_storage_status,
    get_conn,
    rls_user_id,
    set_rls_context,
    user_scoped_select,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .config import MAX_QR_PDF_PAGES
from .config import QR_DECODE_SECONDS
from .config import QR_DECODE_TOTAL
from .config import image_libs

# =============================================================================
# QR IMAGE / SVG DECODING (read the payload out of an uploaded image)
# =============================================================================
class QRDecodeAmbiguityError(ValueError):
    """The upload cannot be safely reduced to one fully inspected QR action."""


class QRDecodeSafetyError(ValueError):
    """The image exceeds a safe decoding limit."""


MAX_QR_IMAGE_PIXELS = 40_000_000
MAX_QR_PAYLOAD_LENGTH = 4096
PILImage.MAX_IMAGE_PIXELS = MAX_QR_IMAGE_PIXELS


def _positive_env_int(name, default, maximum):
    try:
        return max(1, min(int(os.getenv(name, str(default))), maximum))
    except ValueError:
        return default


QR_DECODE_SEMAPHORE = asyncio.Semaphore(_positive_env_int("QR_DECODE_CONCURRENCY", 2, 8))
_WECHAT_LOCK = threading.Lock()
_WECHAT_DECODER = None
_WECHAT_UNAVAILABLE = False
_QR_TIER_EVENTS = contextvars.ContextVar("qr_tier_events", default=None)


def _record_qr_tier(tier, outcome):
    QR_DECODE_TOTAL.labels(tier=tier, outcome=outcome).inc()
    events = _QR_TIER_EVENTS.get()
    if events is not None:
        events.append((tier, outcome))


def _decode_budget_seconds():
    try:
        return max(0.1, min(float(os.getenv("QR_DECODE_BUDGET_S", "1.5")), 10.0))
    except ValueError:
        return 1.5


def _qr_image_libs():
    # ZXing can decode QR codes even when the optional native ZBar library is
    # absent. The shared image_libs helper imports ZBar eagerly, so keep the
    # image upload path usable with the installed ZXing decoder alone.
    try:
        return image_libs()
    except (ImportError, OSError):
        from PIL import Image, ImageEnhance, ImageFilter, ImageOps
        return Image, ImageEnhance, ImageFilter, ImageOps, lambda _image: []


def _assert_safe_dimensions(image):
    if image.width * image.height > MAX_QR_IMAGE_PIXELS:
        raise QRDecodeSafetyError("QR image dimensions exceed the 40 megapixel limit.")


def _barcode_from_result(result, scale_x=1.0, scale_y=1.0):
    if getattr(result, "valid", True) is False:
        return None
    # ZXing's Plain text mode still renders binary bytes through Latin-1 in
    # `.text` (for example b"\xff" becomes "ÿ"). Do not present that as a
    # correctly decoded Unicode payload. Text-mode QR data can contain Kanji
    # bytes, however, so retain ZXing's correctly transcoded `.text` there.
    content_type = str(getattr(result, "content_type", "")).split(".")[-1]
    text = None if content_type in {"Binary", "Mixed", "UnknownECI"} else getattr(result, "text", None)
    if not text:
        raw = getattr(result, "data", None)
        if raw is None:
            raw = getattr(result, "bytes", b"")
        text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw or "")
    if not text.strip() or len(text) > MAX_QR_PAYLOAD_LENGTH:
        return None
    position = getattr(result, "position", None)
    quad = None
    if position is not None:
        try:
            quad = tuple(
                (round(getattr(position, corner).x * scale_x), round(getattr(position, corner).y * scale_y))
                for corner in ("top_left", "top_right", "bottom_right", "bottom_left")
            )
        except AttributeError:
            pass
    elif getattr(result, "polygon", None):
        quad = tuple((round(point.x * scale_x), round(point.y * scale_y)) for point in result.polygon[:4])
    return DecodedBarcode(text, str(getattr(result, "format", getattr(result, "type", "Unknown"))), quad=quad)


def _distinct_barcodes(results):
    found = []

    def same_symbol(first, second):
        if first.data != second.data:
            return False
        if not first.quad or not second.quad:
            return True
        ax0 = min(x for x, _ in first.quad)
        ay0 = min(y for _, y in first.quad)
        ax1 = max(x for x, _ in first.quad)
        ay1 = max(y for _, y in first.quad)
        bx0 = min(x for x, _ in second.quad)
        by0 = min(y for _, y in second.quad)
        bx1 = max(x for x, _ in second.quad)
        by1 = max(y for _, y in second.quad)
        overlap = max(0, min(ax1, bx1) - max(ax0, bx0)) * max(0, min(ay1, by1) - max(ay0, by0))
        smaller = min((ax1 - ax0) * (ay1 - ay0), (bx1 - bx0) * (by1 - by0))
        return smaller <= 0 or overlap / smaller >= 0.5

    for result in results:
        if result is not None and not any(same_symbol(result, previous) for previous in found):
            found.append(result)
    return found


def _zxing_barcodes(image, *, qr_only=True, binarizer=None, is_pure=False, scale_x=1.0, scale_y=1.0):
    try:
        import zxingcpp
    except ImportError:
        return []
    formats = (
        [zxingcpp.BarcodeFormat.QRCode, zxingcpp.BarcodeFormat.MicroQRCode, zxingcpp.BarcodeFormat.RMQRCode]
        if qr_only else zxingcpp.BarcodeFormat.All
    )
    options = {
        "formats": formats,
        "try_rotate": True,
        "try_downscale": True,
        "try_invert": True,
        "text_mode": zxingcpp.TextMode.Plain,
        "is_pure": is_pure,
    }
    if binarizer is not None:
        options["binarizer"] = binarizer
    try:
        results = zxingcpp.read_barcodes(image, **options)
    except Exception:
        return []
    return _distinct_barcodes(_barcode_from_result(result, scale_x, scale_y) for result in results)


def _pyzbar_barcodes(image, decode, *, scale_x=1.0, scale_y=1.0):
    try:
        from pyzbar.pyzbar import ZBarSymbol
        results = decode(image, symbols=[ZBarSymbol.QRCODE])
    except (ImportError, OSError):
        return []
    except Exception:
        return []
    return _distinct_barcodes(_barcode_from_result(result, scale_x, scale_y) for result in results)


def _enhanced_candidates(gray, Image, ImageEnhance, ImageFilter, ImageOps):
    """Yield the existing stylized/low-threshold ladder without building it eagerly."""
    yield gray
    contrast = ImageOps.autocontrast(gray)
    yield contrast
    sharpened = contrast.filter(ImageFilter.SHARPEN)
    yield sharpened
    high_contrast = ImageEnhance.Contrast(sharpened).enhance(1.8)
    yield high_contrast
    for source in (gray, contrast, high_contrast):
        for threshold in (55, 70, 85, 95, 115, 135, 155, 185):
            yield source.point(lambda pixel, limit=threshold: 255 if pixel > limit else 0)
    if max(gray.size) < 1400:
        factor = 1400 / max(gray.size)
        resized = gray.resize((int(gray.width * factor), int(gray.height * factor)), Image.Resampling.LANCZOS)
        yield resized
        resized_contrast = ImageOps.autocontrast(resized)
        yield resized_contrast
        for threshold in (55, 70, 85, 95, 115, 135, 155, 185):
            yield resized_contrast.point(lambda pixel, limit=threshold: 255 if pixel > limit else 0)


def _get_wechat_decoder():
    global _WECHAT_DECODER, _WECHAT_UNAVAILABLE
    if _WECHAT_UNAVAILABLE:
        return None
    with _WECHAT_LOCK:
        if _WECHAT_DECODER is not None:
            return _WECHAT_DECODER
        try:
            import cv2
            import hashlib
            from pathlib import Path

            models = Path(__file__).resolve().parents[1] / "models/wechat_qr"
            for line in (models / "SHA256SUMS").read_text().splitlines():
                if not line or line.startswith("#"):
                    continue
                digest, filename = line.split(maxsplit=1)
                filename = filename.lstrip("*")
                if hashlib.sha256((models / filename).read_bytes()).hexdigest() != digest:
                    raise ValueError("WeChat QR model hash mismatch")
            cv2.setNumThreads(1)
            _WECHAT_DECODER = cv2.wechat_qrcode_WeChatQRCode(
                str(models / "detect.prototxt"), str(models / "detect.caffemodel"),
                str(models / "sr.prototxt"), str(models / "sr.caffemodel"),
            )
        except Exception:
            _WECHAT_UNAVAILABLE = True
            return None
        return _WECHAT_DECODER


def _wechat_barcodes(image, *, scale_x=1.0, scale_y=1.0):
    decoder = _get_wechat_decoder()
    if decoder is None:
        return []
    try:
        import numpy as np
        with _WECHAT_LOCK:
            texts, points = decoder.detectAndDecode(np.asarray(image))
    except Exception:
        return []
    if isinstance(texts, str):
        texts = [texts]
    found = []
    for index, text in enumerate(texts):
        if not text or not text.strip():
            continue
        quad = None
        if points is not None and index < len(points):
            quad = tuple((round(x * scale_x), round(y * scale_y)) for x, y in points[index])
        found.append(DecodedBarcode(text, "QRCode", quad=quad))
    return _distinct_barcodes(found)


def decode_qr_image(image, *, is_pure=False):
    """Decode QR-family symbols in bounded tiers; return every distinct first-tier payload.

    The deadline is checked between native calls. A single C++ call cannot be
    interrupted, so it can exceed the budget slightly on a pathological image.
    """
    started = time.monotonic()
    deadline = started + _decode_budget_seconds()
    Image, ImageEnhance, ImageFilter, ImageOps, decode = _qr_image_libs()
    _assert_safe_dimensions(image)
    oriented = ImageOps.exif_transpose(image)
    _assert_safe_dimensions(oriented)
    gray = ImageOps.grayscale(oriented)
    work = gray

    def run_tier(name, operation):
        if time.monotonic() >= deadline:
            _record_qr_tier(name, "deadline")
            return []
        try:
            results = _distinct_barcodes(operation())
        except QRDecodeSafetyError:
            _record_qr_tier(name, "error")
            raise
        except Exception:
            _record_qr_tier(name, "error")
            return []
        outcome = "hit" if results else "deadline" if time.monotonic() >= deadline else "miss"
        _record_qr_tier(name, outcome)
        return results

    try:
        # Tier A: native grayscale, including Micro QR and rMQR.
        found = run_tier("native", lambda: _zxing_barcodes(gray))
        if found:
            return found

        scale_x = scale_y = 1.0
        if max(gray.size) > 4000:
            work = gray.resize((max(1, gray.width // 2), max(1, gray.height // 2)), Image.Resampling.BICUBIC)
            scale_x, scale_y = gray.width / work.width, gray.height / work.height

        # Tier B: 2x upscale for small, distant codes.
        if max(work.size) < 1600:
            def upscale():
                enlarged = work.resize((work.width * 2, work.height * 2), Image.Resampling.BICUBIC)
                try:
                    return _zxing_barcodes(enlarged, scale_x=scale_x / 2, scale_y=scale_y / 2)
                finally:
                    enlarged.close()

            found = run_tier("upscale", upscale)
            if found:
                return found

        # Tier C: ZBar is a cheap independent second opinion.
        found = run_tier("pyzbar", lambda: _pyzbar_barcodes(work, decode, scale_x=scale_x, scale_y=scale_y))
        if found:
            return found

        # Tier D is optional and disabled until its Render resource cost is measured.
        if os.getenv("QR_WECHAT_ENABLED", "false").lower() in ("1", "true", "yes", "on"):
            found = run_tier("wechat", lambda: _wechat_barcodes(work, scale_x=scale_x, scale_y=scale_y))
            if found:
                return found

        # Tier E: preserve low thresholds for stylized/logo codes. Collect all
        # distinct results across candidates before returning, so a candidate
        # that exposes a second QR cannot silently narrow an ambiguous image.
        def enhanced():
            all_found = []
            candidates = _enhanced_candidates(work, Image, ImageEnhance, ImageFilter, ImageOps)
            try:
                for candidate in candidates:
                    if time.monotonic() >= deadline:
                        break
                    candidate_scale_x = gray.width / candidate.width
                    candidate_scale_y = gray.height / candidate.height
                    all_found.extend(decode_barcodes_with_zxing(
                        candidate, qr_only=True, deadline=deadline,
                        scale_x=candidate_scale_x, scale_y=candidate_scale_y,
                    ))
                    if is_pure and not all_found and time.monotonic() < deadline:
                        all_found.extend(decode_barcodes_with_zxing(
                            candidate, qr_only=True, is_pure=True, deadline=deadline,
                            scale_x=candidate_scale_x, scale_y=candidate_scale_y,
                        ))
                    if time.monotonic() < deadline:
                        all_found.extend(_pyzbar_barcodes(
                            candidate, decode, scale_x=candidate_scale_x, scale_y=candidate_scale_y,
                        ))
                    if len(_distinct_barcodes(all_found)) > 1:
                        break
            finally:
                candidates.close()
            return all_found

        return run_tier("enhanced", enhanced)
    finally:
        QR_DECODE_SECONDS.observe(time.monotonic() - started)
        if work is not gray:
            work.close()
        gray.close()
        oriented.close()

def _decode_qr_from_pil_image(image, *, is_pure=False):
    decoded_qr = decode_qr_image(image, is_pure=is_pure)
    if not decoded_qr:
        return None, None
    if len(decoded_qr) > 1:
        if len({result.data for result in decoded_qr}) > 1:
            raise QRDecodeAmbiguityError("Multiple different QR payloads were found. Crop to one QR code and scan it again.")
        raise QRDecodeAmbiguityError("Multiple QR codes were found. Aim at one QR code and scan it again.")
    return decoded_qr[0].data.decode("utf-8", errors="replace"), image.copy()

def _looks_like_svg(contents, filename="", content_type=""):
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    if name.endswith(".svg") or "svg" in ctype:
        return True
    prefix = contents[:512].lstrip().lower()
    return prefix.startswith(b"<svg") or b"<svg" in prefix

def _looks_like_pdf(contents, filename="", content_type=""):
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    return name.endswith(".pdf") or "pdf" in ctype or contents[:5] == b"%PDF-"

def _svg_candidates(contents):
    candidates = [contents]
    try:
        root = ElementTree.fromstring(contents)
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        nested_svgs = root.findall(".//svg:svg", namespace)
        if not nested_svgs:
            nested_svgs = [node for node in root.iter() if str(node.tag).endswith("svg") and node is not root]
        for nested in nested_svgs[:3]:
            candidates.append(ElementTree.tostring(nested, encoding="utf-8"))
    except Exception:
        pass
    return candidates

def _local_name(tag):
    return str(tag).split("}", 1)[-1]

def _float_attr(element, name, default=0.0):
    value = element.attrib.get(name)
    if value is None:
        return default
    match = re.match(r"[-+]?\d*\.?\d+", str(value).strip())
    return float(match.group(0)) if match else default

def _parse_viewbox(element, fallback_width=100.0, fallback_height=100.0):
    raw = element.attrib.get("viewBox") or element.attrib.get("viewbox")
    if raw:
        parts = [float(part) for part in re.split(r"[\s,]+", raw.strip()) if part]
        if len(parts) == 4 and parts[2] and parts[3]:
            return tuple(parts)
    return (0.0, 0.0, fallback_width, fallback_height)

def _render_basic_svg_qr(svg_bytes):
    Image, _, _, _, _ = _qr_image_libs()
    try:
        root = ElementTree.fromstring(svg_bytes)
    except Exception:
        return None

    root_width = _float_attr(root, "width", 2000.0)
    root_height = _float_attr(root, "height", 2000.0)
    _, _, view_width, view_height = _parse_viewbox(root, root_width, root_height)
    output_size = 2000
    image = Image.new("RGB", (output_size, output_size), "white")
    from PIL import ImageDraw
    draw = ImageDraw.Draw(image)

    def map_point(transform, x, y):
        origin_x, origin_y, min_x, min_y, scale_x, scale_y = transform
        return (
            origin_x + (x - min_x) * scale_x,
            origin_y + (y - min_y) * scale_y,
        )

    root_transform = (0.0, 0.0, 0.0, 0.0, output_size / view_width, output_size / view_height)

    def walk(element, transform):
        tag = _local_name(element.tag)
        fill = (element.attrib.get("fill") or "").lower()

        if tag == "svg" and element is not root:
            x = _float_attr(element, "x")
            y = _float_attr(element, "y")
            width = _float_attr(element, "width", 0.0)
            height = _float_attr(element, "height", width)
            min_x, min_y, child_view_width, child_view_height = _parse_viewbox(element, width, height)
            child_x, child_y = map_point(transform, x, y)
            child_right, child_bottom = map_point(transform, x + width, y + height)
            child_transform = (
                child_x,
                child_y,
                min_x,
                min_y,
                (child_right - child_x) / child_view_width,
                (child_bottom - child_y) / child_view_height,
            )

            has_path = any(_local_name(child.tag) == "path" for child in element)
            if has_path and width and height:
                # QR finder patterns are often embedded as compound SVG paths.
                # Draw the standard 7x7 finder ring so scanners see the anchor.
                x0, y0 = child_x, child_y
                x1, y1 = child_right, child_bottom
                module_w = (x1 - x0) / 7
                module_h = (y1 - y0) / 7
                draw.rectangle([x0, y0, x1, y1], fill="black")
                draw.rectangle([x0 + module_w, y0 + module_h, x1 - module_w, y1 - module_h], fill="white")

            for child in element:
                walk(child, child_transform)
            return

        if tag == "rect":
            x = _float_attr(element, "x")
            y = _float_attr(element, "y")
            width = _float_attr(element, "width")
            height = _float_attr(element, "height")
            x0, y0 = map_point(transform, x, y)
            x1, y1 = map_point(transform, x + width, y + height)
            color = "white" if fill in ("#ffffff", "white") else "black" if fill in ("#000000", "black") else None
            if color:
                draw.rectangle([x0, y0, x1, y1], fill=color)

        elif tag == "polygon" and fill in ("#000000", "black"):
            raw_points = element.attrib.get("points", "")
            values = [float(part) for part in re.split(r"[\s,]+", raw_points.strip()) if part]
            points = [map_point(transform, values[index], values[index + 1]) for index in range(0, len(values) - 1, 2)]
            if points:
                draw.polygon(points, fill="black")

        for child in element:
            walk(child, transform)

    walk(root, root_transform)
    return image

def _decode_qr_upload_inprocess(contents, filename="", content_type=""):
    Image, _, _, _, _ = _qr_image_libs()

    selected_payload = None
    selected_image = None

    def remember(payload, qr_image, *, distinct_source=False):
        nonlocal selected_payload, selected_image
        if not payload:
            return
        if selected_payload is None:
            selected_payload, selected_image = payload, qr_image
        elif payload != selected_payload or distinct_source:
            qr_image.close()
            selected_image.close()
            if payload != selected_payload:
                raise QRDecodeAmbiguityError("Multiple different QR payloads were found. Crop to one QR code and scan it again.")
            raise QRDecodeAmbiguityError("Multiple QR codes were found. Upload a page with only one QR code.")
        else:
            qr_image.close()

    try:
        with Image.open(io.BytesIO(contents)) as image:
            payload, qr_image = _decode_qr_from_pil_image(image)
            if payload:
                return payload, qr_image
    except Image.DecompressionBombError as exc:
        raise QRDecodeSafetyError("QR image dimensions exceed the 40 megapixel limit.") from exc
    except (QRDecodeAmbiguityError, QRDecodeSafetyError):
        raise
    except Exception:
        pass

    if _looks_like_svg(contents, filename, content_type):
        for svg_bytes in _svg_candidates(contents):
            image = _render_basic_svg_qr(svg_bytes)
            if image is None:
                continue
            try:
                payload, qr_image = _decode_qr_from_pil_image(image, is_pure=True)
                remember(payload, qr_image)
            finally:
                image.close()
        if selected_payload:
            return selected_payload, selected_image

    if _looks_like_pdf(contents, filename, content_type):
        try:
            import fitz
            document = fitz.open(stream=contents, filetype="pdf")
            try:
                if document.page_count > MAX_QR_PDF_PAGES:
                    raise QRDecodeAmbiguityError(
                        f"This PDF has more than {MAX_QR_PDF_PAGES} pages, so SafeScan cannot inspect every page. Upload a shorter PDF or crop one QR code."
                    )
                for page_index in range(min(document.page_count, MAX_QR_PDF_PAGES)):
                    page = document.load_page(page_index)
                    if page.rect.width * page.rect.height * 2.5 * 2.5 > MAX_QR_IMAGE_PIXELS:
                        raise QRDecodeSafetyError("Rendered PDF page exceeds the 40 megapixel QR image limit.")
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(2.5, 2.5), alpha=False)
                    with Image.open(io.BytesIO(pixmap.tobytes("png"))) as image:
                        payload, qr_image = _decode_qr_from_pil_image(image, is_pure=True)
                        remember(payload, qr_image, distinct_source=True)
            finally:
                document.close()
        except (QRDecodeAmbiguityError, QRDecodeSafetyError):
            raise
        except Exception:
            pass

    if selected_payload:
        return selected_payload, selected_image

    return None, None


def decode_qr_upload(contents, filename="", content_type=""):
    """Decode in a killable process so native library stalls have a hard limit.

    This runs from the bounded upload thread pool. The per-image tier budget
    applies inside the worker; one extra second covers process startup and IPC.
    """
    from pathlib import Path

    started = time.monotonic()
    timeout = _decode_budget_seconds() + (3.5 if _looks_like_pdf(contents, filename, content_type) else 1.0)
    worker = Path(__file__).with_name("qr_decode_worker.py")
    worker_filename = str(filename or "")[:255].replace("\x00", "")
    worker_content_type = str(content_type or "")[:255].replace("\x00", "")
    header = json.dumps({"filename": worker_filename, "content_type": worker_content_type}).encode("utf-8")
    packet = len(header).to_bytes(4, "big") + header + contents
    try:
        process = subprocess.run(
            [sys.executable, str(worker)],
            input=packet,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        _record_qr_tier("worker", "deadline")
        raise QRDecodeSafetyError("QR decoding exceeded the time limit. Try a clearer image or crop to one code.") from exc
    except (OSError, ValueError) as exc:
        _record_qr_tier("worker", "error")
        raise QRDecodeSafetyError("QR decoder could not inspect this file.") from exc
    finally:
        QR_DECODE_SECONDS.observe(time.monotonic() - started)

    if process.returncode != 0:
        _record_qr_tier("worker", "error")
        raise QRDecodeSafetyError("QR decoder could not inspect this file.")
    if len(process.stdout) > 8 * 1024 * 1024:
        _record_qr_tier("worker", "error")
        raise QRDecodeSafetyError("QR decoder response exceeded the size limit.")
    try:
        result = json.loads(process.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _record_qr_tier("worker", "error")
        raise QRDecodeSafetyError("QR decoder could not inspect this file.") from exc

    allowed_tiers = {"native", "upscale", "pyzbar", "wechat", "enhanced"}
    allowed_outcomes = {"hit", "miss", "deadline", "error"}
    for event in result.get("tier_events", []):
        if (isinstance(event, list) and len(event) == 2
                and event[0] in allowed_tiers and event[1] in allowed_outcomes):
            _record_qr_tier(event[0], event[1])
    error = result.get("error")
    if error == "ambiguity":
        raise QRDecodeAmbiguityError(result.get("message") or "Multiple QR codes were found.")
    if error == "safety":
        raise QRDecodeSafetyError(result.get("message") or "QR image exceeds a safe decoding limit.")
    if error:
        _record_qr_tier("worker", "error")
        raise QRDecodeSafetyError("QR decoder could not inspect this file.")

    payload = result.get("payload")
    if not isinstance(payload, str) or not payload:
        _record_qr_tier("worker", "miss")
        return None, None
    encoded_image = result.get("image")
    try:
        image_bytes = base64.b64decode(encoded_image, validate=True) if encoded_image else contents
        with PILImage.open(io.BytesIO(image_bytes)) as image:
            _assert_safe_dimensions(image)
            copied = image.copy()
            _record_qr_tier("worker", "hit")
            return payload, copied
    except (OSError, ValueError, PILImage.DecompressionBombError) as exc:
        _record_qr_tier("worker", "error")
        raise QRDecodeSafetyError("QR decoder could not inspect this image.") from exc

class DecodedBarcode:
    def __init__(self, text, barcode_format="Unknown", *, quad=None):
        self.data = text.encode("utf-8", errors="replace")
        self.type = barcode_format
        self.quad = quad

def decode_barcodes_with_zxing(image, qr_only=False, *, is_pure=False, deadline=None, scale_x=1.0, scale_y=1.0):
    """Try alternate ZXing binarizers on a difficult candidate, once each."""
    try:
        import zxingcpp
    except ImportError:
        return []
    binarizers = (
        zxingcpp.Binarizer.LocalAverage,
        zxingcpp.Binarizer.GlobalHistogram,
        zxingcpp.Binarizer.FixedThreshold,
        zxingcpp.Binarizer.BoolCast,
    )
    found = []
    for binarizer in binarizers:
        if deadline is not None and time.monotonic() >= deadline:
            break
        found.extend(_zxing_barcodes(
            image, qr_only=qr_only, binarizer=binarizer, is_pure=is_pure,
            scale_x=scale_x, scale_y=scale_y,
        ))
        if len(_distinct_barcodes(found)) > 1:
            break
    return _distinct_barcodes(found)

