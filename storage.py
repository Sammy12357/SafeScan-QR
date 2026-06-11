"""
Blob storage abstraction for uploaded QR images.

Presents one small API (``object_key`` / ``upload_bytes`` / ``download_file`` /
``backend_status``) that works against either an S3-compatible bucket (AWS S3 or
Cloudflare R2) or the local filesystem, selected by the ``STORAGE_BACKEND`` env
var. Callers never need to know which backend is active.
"""
from __future__ import annotations
import hashlib
import os
import posixpath
from datetime import datetime
from pathlib import Path


# --- Configuration (all from environment variables) ------------------------
STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").lower()
S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "")
S3_ACCESS_KEY_ID = os.getenv("S3_ACCESS_KEY_ID", "")
S3_SECRET_ACCESS_KEY = os.getenv("S3_SECRET_ACCESS_KEY", "")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "")
S3_REGION = os.getenv("S3_REGION", "auto")
QR_UPLOAD_RETENTION_DAYS = int(os.getenv("QR_UPLOAD_RETENTION_DAYS", "7"))


def data_dir() -> Path:
    """Pick the base directory for local data.

    Prefers an explicit ``DATA_DIR``, then the Render persistent disk mounts,
    falling back to a ``data`` folder beside the app for local development.
    """
    configured = os.getenv("DATA_DIR")
    if configured:
        return Path(configured)
    default_render_disk = Path("/var/data")
    if default_render_disk.is_dir() and os.access(default_render_disk, os.W_OK):
        return default_render_disk
    legacy_render_disk = Path("/app/data")
    if legacy_render_disk.exists() or (legacy_render_disk.parent.is_dir() and os.access(legacy_render_disk.parent, os.W_OK)):
        return legacy_render_disk
    return Path("data")


def storage_enabled() -> bool:
    """True if the configured backend is one we support."""
    return STORAGE_BACKEND in ("s3", "r2", "local")


def _safe_name(value: str, default: str = "upload") -> str:
    """Sanitise a string for use in a path: keep alnum/-/_/., replace the rest
    with '_', and cap the length. Prevents path traversal and odd characters."""
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in (value or default))
    return cleaned[:120] or default


def object_key(prefix: str, filename: str, user_id: str | None = None, content: bytes = b"") -> str:
    """Build a stable, collision-resistant storage key for an upload.

    Layout: ``<prefix>/<YYYY/MM/DD>/<user>/<contenthash>-<filename>``. The
    content hash deduplicates identical files and the date prefix keeps the
    bucket browsable; all components are sanitised.
    """
    today = datetime.utcnow().strftime("%Y/%m/%d")
    digest = hashlib.sha256(content or os.urandom(16)).hexdigest()[:24]
    user_part = _safe_name(user_id or "guest")
    return posixpath.join(_safe_name(prefix), today, user_part, f"{digest}-{_safe_name(filename)}")


def _local_path(key: str) -> Path:
    """Resolve a storage key to an absolute path under the local uploads dir,
    rejecting any key that would escape that directory (path traversal)."""
    root = (data_dir() / "uploads").resolve()
    path = (root / key).resolve()
    if root not in path.parents and path != root:
        raise ValueError("Invalid storage key.")
    return path


def _s3_client():
    """Return a configured boto3 S3 client, or None when S3/R2 is not in use or
    its credentials are incomplete (in which case callers use local storage)."""
    if STORAGE_BACKEND not in ("s3", "r2"):
        return None
    if not (S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY and S3_BUCKET_NAME):
        return None
    import boto3

    kwargs = {
        "aws_access_key_id": S3_ACCESS_KEY_ID,
        "aws_secret_access_key": S3_SECRET_ACCESS_KEY,
        "region_name": S3_REGION,
    }
    if S3_ENDPOINT_URL:
        kwargs["endpoint_url"] = S3_ENDPOINT_URL
    return boto3.client("s3", **kwargs)


def upload_bytes(content: bytes, key: str, content_type: str = "application/octet-stream") -> dict:
    """Store raw bytes at ``key`` on the active backend and return where it went.

    Writes to S3/R2 (server-side encrypted) when configured, otherwise to the
    local uploads directory.
    """
    client = _s3_client()
    if client:
        client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=key,
            Body=content,
            ContentType=content_type or "application/octet-stream",
            ServerSideEncryption="AES256",
        )
        return {"backend": STORAGE_BACKEND, "bucket": S3_BUCKET_NAME, "key": key}

    path = _local_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {"backend": "local", "bucket": None, "key": key, "path": str(path)}


def download_file(key: str, destination: str | os.PathLike) -> bool:
    """Fetch the object at ``key`` into ``destination``.

    Returns True on success; for local storage, False when the key is missing.
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    client = _s3_client()
    if client:
        client.download_file(S3_BUCKET_NAME, key, str(destination))
        return True

    path = _local_path(key)
    if not path.exists():
        return False
    destination.write_bytes(path.read_bytes())
    return True


def backend_status() -> dict:
    """Describe the active storage backend for health/admin reporting."""
    client = _s3_client()
    if client:
        return {"backend": STORAGE_BACKEND, "configured": True, "bucket": S3_BUCKET_NAME}
    return {"backend": "local", "configured": STORAGE_BACKEND == "local", "bucket": None}
