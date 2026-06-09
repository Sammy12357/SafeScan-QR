import importlib
import sqlite3
import sys


def create_db(path, users=0, scans=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY)")
        conn.executemany("INSERT INTO users DEFAULT VALUES", [() for _ in range(users)])
        conn.executemany("INSERT INTO scans DEFAULT VALUES", [() for _ in range(scans)])


def load_db_module(monkeypatch, legacy_path, default_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.delenv("SQLITE_DB_PATH", raising=False)
    sys.modules.pop("db", None)
    module = importlib.import_module("db")
    monkeypatch.setattr(module, "LEGACY_SQLITE_PATH", str(legacy_path))
    monkeypatch.setattr(module, "DEFAULT_SQLITE_PATH", str(default_path))
    return module


def test_database_path_prefers_existing_legacy_data(tmp_path, monkeypatch):
    legacy_path = tmp_path / "app" / "data" / "qr_cache.db"
    default_path = tmp_path / "var" / "data" / "qr_cache.db"
    create_db(legacy_path, users=2, scans=3)
    create_db(default_path, users=0, scans=0)
    module = load_db_module(monkeypatch, legacy_path, default_path)

    assert module.database_path() == str(legacy_path)


def test_database_path_keeps_explicit_default_when_it_has_more_data(tmp_path, monkeypatch):
    legacy_path = tmp_path / "app" / "data" / "qr_cache.db"
    default_path = tmp_path / "var" / "data" / "qr_cache.db"
    create_db(legacy_path, users=1, scans=0)
    create_db(default_path, users=2, scans=2)
    module = load_db_module(monkeypatch, legacy_path, default_path)
    monkeypatch.setenv("SQLITE_DB_PATH", str(default_path))

    assert module.database_path() == str(default_path)


def test_database_path_prefers_sqlite_path_over_data_dir(tmp_path, monkeypatch):
    legacy_path = tmp_path / "app" / "data" / "qr_cache.db"
    default_path = tmp_path / "var" / "data" / "qr_cache.db"
    explicit_path = tmp_path / "persistent" / "custom.db"
    data_dir = tmp_path / "ephemeral"
    create_db(explicit_path, users=3, scans=4)
    create_db(data_dir / "qr_cache.db", users=1, scans=1)
    module = load_db_module(monkeypatch, legacy_path, default_path)
    monkeypatch.setenv("SQLITE_DB_PATH", str(explicit_path))
    monkeypatch.setenv("DATA_DIR", str(data_dir))

    assert module.database_path() == str(explicit_path)


def test_database_path_rejects_relative_fallback_in_production(tmp_path, monkeypatch):
    legacy_path = tmp_path / "missing-app" / "data" / "qr_cache.db"
    default_path = tmp_path / "missing-var" / "data" / "qr_cache.db"
    module = load_db_module(monkeypatch, legacy_path, default_path)
    monkeypatch.setenv("RENDER", "true")

    try:
        module.database_path()
    except RuntimeError as exc:
        assert "Production SQLite storage is not configured" in str(exc)
    else:
        raise AssertionError("Expected production relative SQLite fallback to be rejected.")


def test_database_storage_status_marks_default_path_persistent(tmp_path, monkeypatch):
    legacy_path = tmp_path / "app" / "data" / "qr_cache.db"
    default_path = tmp_path / "var" / "data" / "qr_cache.db"
    create_db(default_path, users=1, scans=1)
    module = load_db_module(monkeypatch, legacy_path, default_path)

    status = module.database_storage_status()

    assert status["path"] == str(default_path)
    assert status["persistent"] is True
    assert status["warning"] is None


def test_database_storage_status_warns_on_volatile_fallback(tmp_path, monkeypatch):
    legacy_path = tmp_path / "app" / "data" / "qr_cache.db"
    default_path = tmp_path / "var" / "data" / "qr_cache.db"
    volatile_dir = tmp_path / "tmp"
    volatile_path = volatile_dir / "qr_cache.db"
    volatile_dir.mkdir()
    module = load_db_module(monkeypatch, legacy_path, default_path)
    monkeypatch.setenv("SQLITE_DB_PATH", str(volatile_path))

    status = module.database_storage_status()

    assert status["path"] == str(volatile_path)
    assert status["persistent"] is False
    assert "can reset" in status["warning"]
