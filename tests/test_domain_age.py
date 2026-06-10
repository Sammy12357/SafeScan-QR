import importlib
import sqlite3
import sys


def load_app(tmp_path, monkeypatch):
    db_path = tmp_path / "domain-age.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "true")
    sys.modules.pop("hackabull", None)
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    module = importlib.import_module("hackabull")
    return module, db_path


def age_result(module, domain, age_days, source="test"):
    return module.domain_age_lookup_to_ui(domain, {
        "creation_date": "2026-06-01T00:00:00Z",
        "age_days": age_days,
        "source": source,
        "expires_on": None,
        "registrar": "Example Registrar",
        "error": None,
    })


def test_new_domain_generates_high_signal(tmp_path, monkeypatch):
    module, _ = load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "lookup_domain_age_result", lambda url: age_result(module, "new.test", 5))

    signals = module.check_domain_intelligence("https://new.test/login")

    domain_signal = next(item for item in signals if item["check"] == "Domain Age")
    assert domain_signal["severity"] == "high"
    assert domain_signal["domainAge"]["signalLevel"] == "very_new"


def test_established_domain_adds_no_age_signal(tmp_path, monkeypatch):
    module, _ = load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "lookup_domain_age_result", lambda url: age_result(module, "example.com", 730))

    signals = module.check_domain_intelligence("https://example.com")

    assert all(item["check"] != "Domain Age" for item in signals)


def test_cache_hit_skips_fetch(tmp_path, monkeypatch):
    module, db_path = load_app(tmp_path, monkeypatch)
    module.domain_age_cache_save("cached.test", {
        "creation_date": "2026-01-01T00:00:00Z",
        "age_days": 160,
        "source": "whois",
        "expires_on": None,
        "registrar": "Cached Registrar",
        "error": None,
    })
    monkeypatch.setattr(module, "fetch_domain_age", lambda domain: (_ for _ in ()).throw(AssertionError("cache missed")))

    result = module.get_domain_age_days("cached.test")

    assert result["ageDays"] == 160
    assert result["source"] == "whois"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM domain_age_cache").fetchone()[0] == 1


def test_all_sources_fail_returns_low_unknown_signal(tmp_path, monkeypatch):
    module, _ = load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "fetch_domain_age", lambda domain: {
        "creation_date": None,
        "age_days": None,
        "source": "unavailable",
        "expires_on": None,
        "registrar": None,
        "error": "all sources failed",
    })

    signals = module.check_domain_intelligence("https://unknown.test")

    domain_signal = next(item for item in signals if item["check"] == "Domain Age")
    assert domain_signal["severity"] == "low"
    assert domain_signal["domainAge"]["riskLevel"] == "unknown"


def test_ip_url_skips_domain_age(tmp_path, monkeypatch):
    module, _ = load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "lookup_domain_age_result", lambda url: (_ for _ in ()).throw(AssertionError("IP should skip age lookup")))

    assert module.check_domain_intelligence("https://8.8.8.8/path") == []


def test_wayback_fallback(tmp_path, monkeypatch):
    module, _ = load_app(tmp_path, monkeypatch)
    monkeypatch.setattr(module, "fetch_domain_age_whois", lambda domain: None)
    monkeypatch.setattr(module, "fetch_domain_age_rdap", lambda domain: None)
    monkeypatch.setattr(module, "fetch_domain_age_whoisxml", lambda domain: None)
    monkeypatch.setattr(module, "fetch_domain_age_securitytrails", lambda domain: None)
    monkeypatch.setattr(module, "fetch_domain_age_wayback", lambda domain: {
        "creation_date": "2024-01-01T00:00:00Z",
        "age_days": 891,
        "source": "wayback_lower_bound",
        "expires_on": None,
        "registrar": None,
        "error": None,
    })

    result = module.fetch_domain_age("fallback.test")

    assert result["source"] == "wayback_lower_bound"
    assert result["age_days"] == 891
