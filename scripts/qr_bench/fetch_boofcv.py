#!/usr/bin/env python3
"""Fetch the BoofCV real-photo QR corpus into the local benchmark cache.

The archive URL is the "Image Dataset" link on BoofCV's QR performance page:
https://boofcv.org/index.php?title=Performance:QrCode

The corpus is intentionally kept out of Git. Extraction checks every ZIP member
before writing it, and only publishes a complete extraction to the cache path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

import requests


SOURCE_PAGE = "https://boofcv.org/index.php?title=Performance:QrCode"
ARCHIVE_URL = "https://boofcv.org/notwiki/regression/fiducial/qrcodes_v3.zip"
DEFAULT_DESTINATION = Path(__file__).resolve().parents[2] / ".cache/qr_corpus/boofcv"
MAX_ARCHIVE_BYTES = 350_000_000
MAX_MEMBER_BYTES = 150_000_000
MAX_EXTRACTED_BYTES = 2_000_000_000
MAX_MEMBERS = 10_000
CHUNK_BYTES = 1024 * 1024
SOURCE_RECORD = ".safescan-source.json"


def download_archive(destination: Path) -> str:
    """Stream the official ZIP to *destination* and return its SHA-256 hash."""
    digest = hashlib.sha256()
    total = 0
    with requests.get(
        ARCHIVE_URL,
        headers={"User-Agent": "SafeScan-QR-benchmark/1.0"},
        stream=True,
        timeout=(15, 60),
    ) as response, destination.open("wb") as output:
        response.raise_for_status()
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > MAX_ARCHIVE_BYTES:
            raise ValueError("BoofCV archive exceeds the download size limit")
        for chunk in response.iter_content(chunk_size=CHUNK_BYTES):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError("BoofCV archive exceeds the download size limit")
            digest.update(chunk)
            output.write(chunk)
    return digest.hexdigest()


def _member_path(name: str) -> Path:
    """Validate a ZIP name without trusting ZIP extraction path handling."""
    if not name or "\\" in name or "\x00" in name:
        raise ValueError(f"Unsafe ZIP member name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"Unsafe ZIP member path: {name!r}")
    if ":" in path.parts[0]:
        raise ValueError(f"Unsafe ZIP member drive path: {name!r}")
    return Path(*path.parts)


def extract_archive(archive: Path, destination: Path) -> int:
    """Extract regular files only, with path and expanded-size limits."""
    count = 0
    expanded = 0
    seen: set[Path] = set()
    with ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > MAX_MEMBERS:
            raise ValueError("BoofCV archive has too many members")
        for member in members:
            relative = _member_path(member.filename)
            if relative in seen:
                raise ValueError(f"Duplicate ZIP member: {member.filename!r}")
            seen.add(relative)
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"Non-regular ZIP member: {member.filename!r}")
            if member.file_size > MAX_MEMBER_BYTES:
                raise ValueError(f"Oversized ZIP member: {member.filename!r}")
            expanded += member.file_size
            if expanded > MAX_EXTRACTED_BYTES:
                raise ValueError("BoofCV archive exceeds the expanded-size limit")
            target = destination / relative
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            with package.open(member) as source, target.open("wb") as output:
                while chunk := source.read(CHUNK_BYTES):
                    copied += len(chunk)
                    if copied > member.file_size or copied > MAX_MEMBER_BYTES:
                        raise ValueError(f"ZIP member exceeded its declared size: {member.filename!r}")
                    output.write(chunk)
            count += 1
    return count


def fetch(destination: Path = DEFAULT_DESTINATION) -> Path:
    destination = destination.resolve()
    if destination.exists():
        if (destination / SOURCE_RECORD).is_file():
            print(f"BoofCV corpus already cached at {destination}")
            return destination
        raise FileExistsError(f"Destination exists without a source record: {destination}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=".boofcv-download-", suffix=".zip", dir=destination.parent, delete=False
    ) as temporary:
        archive = Path(temporary.name)
    staging = Path(tempfile.mkdtemp(prefix=".boofcv-extract-", dir=destination.parent))
    try:
        print(f"Downloading {ARCHIVE_URL}")
        digest = download_archive(archive)
        files = extract_archive(archive, staging)
        if not files:
            raise ValueError("BoofCV archive contained no files")
        (staging / SOURCE_RECORD).write_text(
            json.dumps(
                {
                    "source_page": SOURCE_PAGE,
                    "archive_url": ARCHIVE_URL,
                    "archive_sha256": digest,
                    "fetched_at": datetime.now(timezone.utc).isoformat(),
                    "file_count": files,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        staging.rename(destination)
        print(f"Cached {files} files at {destination} (SHA-256 {digest})")
        return destination
    finally:
        archive.unlink(missing_ok=True)
        if staging.exists():
            shutil.rmtree(staging)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--destination", type=Path, default=DEFAULT_DESTINATION,
        help="Extraction directory (default: .cache/qr_corpus/boofcv)",
    )
    args = parser.parse_args()
    fetch(args.destination)
