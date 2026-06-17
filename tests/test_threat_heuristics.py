import importlib
import sys


def load_app(tmp_path, monkeypatch):
    db_path = tmp_path / "threat-heuristics.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "false")
    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    return importlib.import_module("hackabull")


def test_typosquat_detects_roblox_lookalike(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    sig = module.check_typosquat_signal("www.robiox.com.py")

    assert sig is not None
    assert sig["check"] == "Brand Impersonation"
    assert "roblox" in sig["result"].lower()
    assert sig["severity"] == "high"
    assert sig["passed"] is False


def test_typosquat_detects_steamcommunity_lookalike(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    sig = module.check_typosquat_signal("stleamcommuunity.com")

    assert sig is not None
    assert "steamcommunity" in sig["result"].lower()


def test_typosquat_ignores_real_brand_domain(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    assert module.check_typosquat_signal("www.roblox.com") is None
    assert module.check_typosquat_signal("steamcommunity.com") is None


def test_typosquat_ignores_unrelated_domain(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    assert module.check_typosquat_signal("example.com") is None


def test_dga_signal_flags_wannacry_killswitch_domain(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    sig = module.check_dga_signal("iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com")

    assert sig is not None
    assert sig["check"] == "Algorithmically Generated Domain"
    assert sig["severity"] == "medium"
    assert sig["passed"] is False


def test_dga_signal_ignores_normal_domains(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    assert module.check_dga_signal("google.com") is None
    assert module.check_dga_signal("steamcommunity.com") is None


def test_high_risk_tld_flags_sbs_and_com_py(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    sbs_signals = module.check_domain_intelligence("https://smartconcil.sbs/")
    py_signals = module.check_domain_intelligence("https://www.robiox.com.py/users/282744267386/profile")

    assert any(s["check"] == "TLD Risk" and ".sbs" in s["result"] for s in sbs_signals)
    assert any(s["check"] == "TLD Risk" and ".com.py" in s["result"] for s in py_signals)
    # The .com.py case should also catch the brand-impersonation typosquat.
    assert any(s["check"] == "Brand Impersonation" for s in py_signals)


def test_steam_gift_typosquat_flagged_end_to_end(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)

    signals = module.check_domain_intelligence("https://stleamcommuunity.com/gift/33435345")

    assert any(s["check"] == "Brand Impersonation" for s in signals)
