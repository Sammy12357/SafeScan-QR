"""Private SQLite files must not be readable through Unix mode bits or /static."""

import importlib
import os
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from private_files import assert_outside_static, secure_sqlite_path


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.skipif(os.name != "posix", reason="Unix file modes")
def test_secure_sqlite_path_creates_private_and_repairs_existing_file(tmp_path):
    new = tmp_path / "new.sqlite"
    assert secure_sqlite_path(new) == str(new)
    assert mode(new) == 0o600
    with sqlite3.connect(new) as live:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("CREATE TABLE secret (value TEXT)")
        live.execute("INSERT INTO secret VALUES ('private')")
        live.commit()
        assert mode(tmp_path / "new.sqlite-wal") == 0o600
        assert mode(tmp_path / "new.sqlite-shm") == 0o600

    old = tmp_path / "old.sqlite"
    with sqlite3.connect(old) as conn:
        conn.execute("CREATE TABLE proof (value TEXT)")
        conn.execute("INSERT INTO proof VALUES ('preserved')")
    old.chmod(0o644)
    assert secure_sqlite_path(old) == str(old)
    assert mode(old) == 0o600
    with sqlite3.connect(old) as conn:
        assert conn.execute("SELECT value FROM proof").fetchone()[0] == "preserved"


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="No O_NOFOLLOW")
def test_secure_sqlite_path_rejects_symlink_without_chmodding_target(tmp_path):
    target = tmp_path / "target.sqlite"
    target.write_bytes(b"do not change")
    target.chmod(0o644)
    link = tmp_path / "link.sqlite"
    link.symlink_to(target)
    with pytest.raises(OSError):
        secure_sqlite_path(link)
    assert mode(target) == 0o644


def test_data_directory_inside_static_is_rejected(monkeypatch):
    storage = importlib.import_module("storage")
    static_root = Path(__file__).resolve().parents[1] / "static"
    with pytest.raises(RuntimeError, match="outside the public static"):
        assert_outside_static(static_root / "private")
    monkeypatch.setenv("DATA_DIR", str(static_root / "uploads"))
    with pytest.raises(RuntimeError, match="outside the public static"):
        storage.data_dir()


@pytest.mark.skipif(os.name != "posix", reason="Unix file modes")
def test_app_import_repairs_existing_main_database_mode(tmp_path):
    database = tmp_path / "qr_cache.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE proof (value TEXT)")
        conn.execute("INSERT INTO proof VALUES ('preserved')")
    database.chmod(0o644)
    environment = dict(os.environ)
    environment.update({
        "DATABASE_URL": f"sqlite:///{database}",
        "DATA_DIR": str(tmp_path),
        "APP_URL": "https://testserver",
        "MOCK_MODE": "true",
        "SAFESCAN_ML2_ENABLED": "false",
    })
    result = subprocess.run(
        [sys.executable, "-c", "import hackabull"],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert mode(database) == 0o600
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT value FROM proof").fetchone()[0] == "preserved"


@pytest.mark.skipif(os.name != "posix", reason="Unix file modes")
def test_ml_cache_repairs_existing_file_mode(tmp_path, monkeypatch):
    cache = importlib.import_module("safescan_model_calibration.cache")
    path = tmp_path / "ml_cache.sqlite"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE proof (value TEXT)")
        conn.execute("INSERT INTO proof VALUES ('preserved')")
    path.chmod(0o644)
    monkeypatch.setattr(cache, "_CACHE_PATH", str(path))
    monkeypatch.setattr(cache, "_CACHE_ENABLED", True)
    monkeypatch.setattr(cache, "_cache_conn", None)
    connection = cache._cache_connection()
    assert connection is not None
    try:
        assert mode(path) == 0o600
        assert connection.execute("SELECT value FROM proof").fetchone()[0] == "preserved"
    finally:
        connection.close()


@pytest.mark.parametrize("backend,expects_sse", [("s3", True), ("r2", False)])
def test_object_upload_requests_supported_encryption(backend, expects_sse, monkeypatch):
    storage = importlib.import_module("storage")
    calls = []

    class Client:
        def put_object(self, **kwargs):
            calls.append(kwargs)

    monkeypatch.setattr(storage, "STORAGE_BACKEND", backend)
    monkeypatch.setattr(storage, "S3_BUCKET_NAME", "private-bucket")
    monkeypatch.setattr(storage, "_s3_client", lambda: Client())
    result = storage.upload_bytes(b"qr", "qr-uploads/2026/11/14/key.png", "image/png")

    assert result["backend"] == backend
    assert calls[0]["Bucket"] == "private-bucket"
    assert calls[0]["Key"] == "qr-uploads/2026/11/14/key.png"
    assert (calls[0].get("ServerSideEncryption") == "AES256") is expects_sse


def test_configured_object_backend_never_silently_writes_local(tmp_path, monkeypatch):
    storage = importlib.import_module("storage")
    monkeypatch.setattr(storage, "STORAGE_BACKEND", "s3")
    monkeypatch.setattr(storage, "S3_ACCESS_KEY_ID", "")
    monkeypatch.setattr(storage, "S3_SECRET_ACCESS_KEY", "")
    monkeypatch.setattr(storage, "S3_BUCKET_NAME", "")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    with pytest.raises(RuntimeError, match="credentials or bucket"):
        storage.upload_bytes(b"qr", "qr-uploads/key.png")
    monkeypatch.setattr(storage, "STORAGE_BACKEND", "typo")
    with pytest.raises(RuntimeError, match="Unknown object storage backend"):
        storage.upload_bytes(b"qr", "qr-uploads/key.png")
    assert not (tmp_path / "uploads").exists()


@pytest.mark.skipif(os.name != "posix", reason="Unix file modes")
def test_local_retained_upload_is_private_even_when_replacing_old_file(tmp_path, monkeypatch):
    storage = importlib.import_module("storage")
    monkeypatch.setattr(storage, "STORAGE_BACKEND", "local")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    key = "qr-uploads/2026/11/14/guest/image.png"
    path = tmp_path / "uploads" / key
    path.parent.mkdir(parents=True)
    path.write_bytes(b"old")
    path.chmod(0o644)
    path.parent.chmod(0o755)

    storage.upload_bytes(b"new", key, "image/png")

    assert path.read_bytes() == b"new"
    assert mode(path) == 0o600
    assert mode(path.parent) == 0o700
    assert mode(tmp_path / "uploads") == 0o700


@pytest.mark.skipif(os.name != "posix", reason="Unix file modes")
def test_online_sqlite_backup_is_private_consistent_and_never_overwrites(tmp_path):
    from scripts.security.backup_sqlite import backup_database

    source = tmp_path / "live.sqlite"
    output = tmp_path / "snapshot.sqlite"
    with sqlite3.connect(source) as live:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("CREATE TABLE proof (value TEXT)")
        live.execute("INSERT INTO proof VALUES ('backed up')")
        live.commit()
        backup_database(source, output)
        live.execute("INSERT INTO proof VALUES ('later write')")
    assert mode(output) == 0o600
    with sqlite3.connect(output) as snapshot:
        assert snapshot.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert snapshot.execute("SELECT value FROM proof").fetchall() == [("backed up",)]
    with pytest.raises(FileExistsError):
        backup_database(source, output)
    with sqlite3.connect(output) as snapshot:
        assert snapshot.execute("SELECT COUNT(*) FROM proof").fetchone()[0] == 1
