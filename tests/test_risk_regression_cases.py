import asyncio
import importlib
import sys


def patch_everywhere(monkeypatch, name, value):
    """Patch ``name`` on every loaded ``hackabull`` submodule that defines it.

    The backend is a package now, so a helper imported ``from .x import foo``
    has its own binding inside each consumer module; patching only the
    top-level package would miss those copies.
    """
    for mod_name, mod in list(sys.modules.items()):
        if (mod_name == "hackabull" or mod_name.startswith("hackabull.")) and hasattr(mod, name):
            monkeypatch.setattr(mod, name, value, raising=False)


def load_app(tmp_path, monkeypatch):
    db_path = tmp_path / "risk-regressions.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("SAFESCAN_ML2_ENABLED", "false")
    monkeypatch.setenv("DOMAIN_AGE_CHECK_ENABLED", "false")
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    [sys.modules.pop(_m, None) for _m in list(sys.modules) if _m == "hackabull" or _m.startswith("hackabull.")]
    sys.modules.pop("db", None)
    sys.modules.pop("storage", None)
    return importlib.import_module("hackabull")


def stub_external_services(module, monkeypatch):
    patch_everywhere(
        monkeypatch,
        "trace_redirect_chain",
        lambda url: {
            "signal": module.signal("Redirect Chain", "0 hop(s)", "low", "Redirect chain is simple.", True),
            "redirectChain": [],
        },
    )
    patch_everywhere(
        monkeypatch,
        "google_reputation_signal",
        lambda url: module.signal("Google Safe Browsing", "No matches", "low", "No known unsafe match returned.", True),
    )
    patch_everywhere(
        monkeypatch,
        "virustotal_lookup_result",
        lambda url: {
            "url": url,
            "mode": "unavailable",
            "summary": {"clean": 0, "unrated": 0, "malicious": 0, "total": 0},
            "engines": [],
            "groups": {"clean": [], "unrated": [], "malicious": []},
            "statusMessage": "Not configured.",
        },
    )
    patch_everywhere(monkeypatch, "classify_qr_with_ml", lambda *args, **kwargs: {"enabled": False, "reason": "test"})


def analyze(module, url):
    return asyncio.run(module.analyze_full_pipeline(url))


def assert_malicious(result, threat_type):
    assert result["overallRisk"] == "high"
    assert result["confidenceScore"] >= 80
    assert result["threatType"] == threat_type
    assert result.get("fastPath") is None


def test_brand_impersonation_qr_is_malicious_even_without_reputation_apis(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    stub_external_services(module, monkeypatch)

    result = analyze(module, "https://www.robiox.com.py/users/282744267386/profile")

    assert_malicious(result, "Brand Impersonation")
    assert any(signal["check"] == "Brand Impersonation" for signal in result["signals"])


def test_wallet_drain_signature_is_malicious_even_without_reputation_apis(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    stub_external_services(module, monkeypatch)

    result = analyze(module, "https://claim.example/airdrop?method=setApprovalForAll&operator=11111111111111111111111111111111")

    assert_malicious(result, "NFT Approval Pattern")
    assert any(signal["check"] == "NFT Approval Pattern" for signal in result["signals"])


def test_popular_clean_url_stays_safe_on_fast_path(tmp_path, monkeypatch):
    module = load_app(tmp_path, monkeypatch)
    stub_external_services(module, monkeypatch)

    result = analyze(module, "https://www.youtube.com/watch?v=abc123")

    assert result["overallRisk"] == "safe"
    assert result["confidenceScore"] < 40
    assert result["threatType"] == "Benign popular destination"
    assert result["fastPath"]["reason"] == "tranco_allowlist"
