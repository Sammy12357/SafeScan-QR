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
from decimal import Decimal, InvalidOperation
from html import escape as escape_html
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree

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
from .config import image_libs

# =============================================================================
# QR IMAGE / SVG DECODING (read the payload out of an uploaded image)
# =============================================================================
def decode_qr_image(image):
    """Extract the text payload from a PIL image of a QR code.

    Corrects orientation, then tries progressively harder decode strategies
    (contrast/threshold enhancement, ZXing fallback) since real-world photos are
    often low-contrast, rotated, or noisy. Returns the decoded string or None.
    """
    Image, ImageEnhance, ImageFilter, ImageOps, decode = image_libs()
    image = ImageOps.exif_transpose(image)

    def normalize_candidate(candidate):
        if candidate.mode not in ("RGB", "L"):
            candidate = candidate.convert("RGB")
        return candidate

    def grayscale_candidates(candidate):
        gray = ImageOps.grayscale(candidate)
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

    def candidate_images():
        yield normalize_candidate(image)
        yield from grayscale_candidates(image)

        max_side = max(image.size)
        if max_side < 1400:
            scale = 1400 / max_side
            resized = image.resize(
                (int(image.width * scale), int(image.height * scale)),
                Image.Resampling.LANCZOS
            )
            yield resized
            yield from grayscale_candidates(resized)

    for candidate in candidate_images():
        zxing_result = decode_barcodes_with_zxing(candidate, qr_only=True)
        if zxing_result:
            return zxing_result

        for angle in (0, 90, 180, 270):
            rotated = candidate if angle == 0 else candidate.rotate(angle, expand=True)
            try:
                from pyzbar.pyzbar import ZBarSymbol
                decoded = decode(rotated, symbols=[ZBarSymbol.QRCODE])
            except Exception:
                decoded = decode(rotated)
            if decoded:
                return decoded

        zxing_result = decode_barcodes_with_zxing(candidate)
        if zxing_result:
            return zxing_result
    return []

def _decode_qr_from_pil_image(image):
    decoded_qr = decode_qr_image(image)
    if not decoded_qr:
        return None, None
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
    Image, _, _, _, _ = image_libs()
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

def decode_qr_upload(contents, filename="", content_type=""):
    Image, _, _, _, _ = image_libs()

    try:
        with Image.open(io.BytesIO(contents)) as image:
            payload, qr_image = _decode_qr_from_pil_image(image)
            if payload:
                return payload, qr_image
    except Exception:
        pass

    if _looks_like_svg(contents, filename, content_type):
        for svg_bytes in _svg_candidates(contents):
            image = _render_basic_svg_qr(svg_bytes)
            if image is None:
                continue
            try:
                payload, qr_image = _decode_qr_from_pil_image(image)
                if payload:
                    return payload, qr_image
            finally:
                image.close()

    if _looks_like_pdf(contents, filename, content_type):
        try:
            import fitz
            document = fitz.open(stream=contents, filetype="pdf")
            try:
                for page_index in range(min(document.page_count, MAX_QR_PDF_PAGES)):
                    page = document.load_page(page_index)
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(2.5, 2.5), alpha=False)
                    with Image.open(io.BytesIO(pixmap.tobytes("png"))) as image:
                        payload, qr_image = _decode_qr_from_pil_image(image)
                        if payload:
                            return payload, qr_image
            finally:
                document.close()
        except Exception:
            pass

    return None, None

class DecodedBarcode:
    def __init__(self, text, barcode_format="Unknown"):
        self.data = text.encode("utf-8", errors="replace")
        self.type = barcode_format

def decode_barcodes_with_zxing(image, qr_only=False):
    try:
        import zxingcpp
    except ImportError:
        return []
    results = []
    formats = zxingcpp.BarcodeFormat.QRCode if qr_only else zxingcpp.BarcodeFormat.All
    binarizers = (
        zxingcpp.Binarizer.LocalAverage,
        zxingcpp.Binarizer.GlobalHistogram,
        zxingcpp.Binarizer.FixedThreshold,
        zxingcpp.Binarizer.BoolCast,
    )
    text_modes = (zxingcpp.TextMode.Plain, zxingcpp.TextMode.HRI)
    for binarizer in binarizers:
        for text_mode in text_modes:
            for is_pure in (False, True):
                try:
                    results = zxingcpp.read_barcodes(
                        image,
                        formats=formats,
                        try_rotate=True,
                        try_downscale=True,
                        try_invert=True,
                        text_mode=text_mode,
                        binarizer=binarizer,
                        is_pure=is_pure,
                    )
                except Exception:
                    continue
                if results:
                    break
            if results:
                break
        if results:
            break
    decoded = []
    for result in results:
        text = (getattr(result, "text", "") or "").strip()
        if not text:
            continue
        decoded.append(DecodedBarcode(text, str(getattr(result, "format", "Unknown"))))
    return decoded

