"""Benchmark the current server QR decoder without changing scan behavior.

Run from the repository root with::

    python scripts/qr_bench/bench_server.py --corpus synthetic

The report records file names, timings, and match counts, but never QR payloads.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageOps


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from hackabull.qr_decode import decode_qr_image  # noqa: E402


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}


def _percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * percent / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _payloads(results: object) -> set[str]:
    payloads: set[str] = set()
    for result in results or []:
        raw = getattr(result, "data", None)
        if isinstance(raw, bytes):
            value = raw.decode("utf-8", errors="replace")
        else:
            value = str(getattr(result, "text", "") or "")
        if value.strip():
            payloads.add(value)
    return payloads


def _stage_functions():
    stages = {"server_full": decode_qr_image}
    unavailable = []
    try:
        import zxingcpp

        def zxing_native(image):
            return zxingcpp.read_barcodes(
                image,
                formats=zxingcpp.BarcodeFormat.QRCode,
                try_rotate=True,
                try_downscale=True,
                try_invert=True,
                text_mode=zxingcpp.TextMode.Plain,
            )

        stages["zxing_native"] = zxing_native
    except ImportError:
        unavailable.append("zxing_native (zxing-cpp not installed)")

    try:
        from pyzbar.pyzbar import ZBarSymbol, decode

        def pyzbar_native(image):
            return decode(image, symbols=[ZBarSymbol.QRCODE])

        stages["pyzbar_native"] = pyzbar_native
    except (ImportError, OSError):
        unavailable.append("pyzbar_native (ZBar not installed)")

    return stages, unavailable


def _corpus_paths(corpus: str) -> tuple[Path, list[Path], dict[str, list[str]]]:
    if corpus == "synthetic":
        directory = ROOT / "tests/qr_corpus/synthetic"
    elif corpus == "boofcv":
        directory = ROOT / ".cache/qr_corpus/boofcv"
    else:
        directory = Path(corpus).expanduser().resolve()
    if not directory.is_dir():
        raise FileNotFoundError(f"Corpus directory does not exist: {directory}")
    files = sorted(path for path in directory.rglob("*") if path.suffix.lower() in IMAGE_EXTENSIONS)
    if not files:
        raise ValueError(f"No images found in {directory}")
    labels_file = directory / "labels.json"
    labels = json.loads(labels_file.read_text()) if labels_file.exists() else {}
    if not isinstance(labels, dict):
        raise ValueError(f"Expected an object in {labels_file}")
    if corpus == "synthetic" and not labels:
        raise ValueError(f"Synthetic corpus needs labels.json in {directory}")
    return directory, files, labels


def _category(path: Path, directory: Path, corpus: str) -> str:
    relative = path.relative_to(directory)
    if corpus == "synthetic":
        return path.stem.split("__", 1)[0]
    # BoofCV images live under qrcodes/detection/<category>/imageNNN.jpg.
    return relative.parts[-2] if len(relative.parts) > 1 else path.stem.split("__", 1)[0]


def _sample_files(files: list[Path], directory: Path, corpus: str, limit: int | None) -> list[Path]:
    if limit is None or len(files) <= limit:
        return files
    # A small run should cover different categories rather than just the
    # alphabetically first directory in the BoofCV archive.
    groups: dict[str, list[Path]] = defaultdict(list)
    for path in files:
        groups[_category(path, directory, corpus)].append(path)
    selected = []
    index = 0
    while len(selected) < limit:
        progressed = False
        for category in sorted(groups):
            if index < len(groups[category]):
                selected.append(groups[category][index])
                progressed = True
                if len(selected) == limit:
                    break
        if not progressed:
            break
        index += 1
    return selected


def _summary(records: list[dict]) -> dict:
    elapsed = [record["ms"] for record in records]
    labeled = [record for record in records if record["labeled"]]
    return {
        "images": len(records),
        "read": sum(record["read"] for record in records),
        "read_rate": round(sum(record["read"] for record in records) / len(records), 4) if records else 0,
        "labeled": len(labeled),
        "correct": sum(record["correct"] for record in labeled),
        "correct_rate": round(sum(record["correct"] for record in labeled) / len(labeled), 4) if labeled else None,
        "p50_ms": round(statistics.median(elapsed), 2) if elapsed else 0,
        "p95_ms": round(_percentile(elapsed, 95), 2),
        "max_ms": round(max(elapsed), 2) if elapsed else 0,
    }


def benchmark(corpus: str, limit: int | None = None) -> dict:
    directory, files, labels = _corpus_paths(corpus)
    files = _sample_files(files, directory, corpus, limit)
    stages, unavailable = _stage_functions()
    cases = defaultdict(list)
    for path in files:
        relative = path.relative_to(directory).as_posix()
        expected = labels.get(relative, labels.get(path.name))
        if expected is not None and (not isinstance(expected, list) or not all(isinstance(v, str) for v in expected)):
            raise ValueError(f"Expected a list of payload strings for {relative}")
        category = _category(path, directory, corpus)
        for stage, decoder in stages.items():
            started = time.perf_counter()
            error = None
            found = set()
            try:
                with Image.open(path) as source:
                    image = ImageOps.exif_transpose(source)
                    try:
                        found = _payloads(decoder(image))
                    finally:
                        if image is not source:
                            image.close()
            except Exception as exc:
                error = type(exc).__name__
            cases[stage].append({
                "file": relative,
                "category": category,
                "ms": round((time.perf_counter() - started) * 1000, 2),
                "read": bool(found),
                "labeled": expected is not None,
                "correct": expected is not None and found == set(expected),
                "symbols": len(found),
                "expected_symbols": len(expected) if expected is not None else None,
                "error_type": error,
            })

    try:
        git_sha = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        git_sha = "unknown"
    return {
        "corpus": corpus,
        "limit": limit,
        "root": str(directory),
        "git_sha": git_sha,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "unavailable_stages": unavailable,
        "stages": {
            stage: {
                "overall": _summary(records),
                "categories": {
                    category: _summary([record for record in records if record["category"] == category])
                    for category in sorted({record["category"] for record in records})
                },
                "cases": records,
            }
            for stage, records in cases.items()
        },
    }


def _print_report(report: dict) -> None:
    scope = f"  Sample limit: {report['limit']}" if report["limit"] is not None else ""
    print(f"Corpus: {report['corpus']}  Git: {report['git_sha']}{scope}")
    for unavailable in report["unavailable_stages"]:
        print(f"Unavailable: {unavailable}")
    print(f"{'Stage':<18} {'Category':<32} {'Read':>8} {'Correct':>9} {'p50 ms':>9} {'p95 ms':>9} {'max ms':>9}")
    for stage, details in report["stages"].items():
        for category, stats in [("ALL", details["overall"]), *details["categories"].items()]:
            read = f"{stats['read']}/{stats['images']}"
            correct = f"{stats['correct']}/{stats['labeled']}" if stats["labeled"] else "n/a"
            print(f"{stage:<18} {category:<32} {read:>8} {correct:>9} {stats['p50_ms']:>9.1f} {stats['p95_ms']:>9.1f} {stats['max_ms']:>9.1f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default="synthetic", help="synthetic, boofcv, or a corpus directory")
    parser.add_argument("--output", type=Path, help="override the default JSON report path")
    parser.add_argument("--limit", type=int, help="quick run: sample up to this many images across categories")
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    report = benchmark(args.corpus, args.limit)
    suffix = f"-limit{args.limit}" if args.limit is not None else ""
    corpus_slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", Path(args.corpus).name).strip("-") or "corpus"
    default_output = ROOT / ".cache/qr_bench" / f"server-{corpus_slug}-{report['git_sha']}{suffix}.json"
    output = args.output or default_output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    _print_report(report)
    print(f"JSON: {output}")


if __name__ == "__main__":
    main()
