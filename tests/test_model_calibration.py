"""Unit tests for safescan_model_calibration."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Allow `import safescan_model_calibration` from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Point the cache at a temp file BEFORE the module loads so tests don't
# write to the real cache.
_TMP_DIR = tempfile.mkdtemp(prefix="safescan-ml-cache-")
os.environ["SAFESCAN_ML_CACHE_PATH"] = os.path.join(_TMP_DIR, "ml_cache.sqlite")
os.environ["SAFESCAN_ML_CACHE_TTL"] = "60"

import safescan_model_calibration as smc  # noqa: E402


class TestInterpretProbability:
    def test_clearly_benign(self):
        d = smc.interpret_probability(0.05)
        assert d.bucket == "benign"
        assert d.severity == "low"
        assert d.passed is True
        assert d.trust_signal is True

    def test_uncertain_band_lower(self):
        d = smc.interpret_probability(0.30)
        assert d.bucket == "uncertain"
        # The whole point of the uncertain band is to suppress the signal.
        assert d.trust_signal is False

    def test_uncertain_band_middle(self):
        d = smc.interpret_probability(0.45)
        assert d.bucket == "uncertain"
        assert d.trust_signal is False

    def test_suspicious(self):
        d = smc.interpret_probability(0.65)
        assert d.bucket == "suspicious"
        assert d.severity == "medium"
        assert d.trust_signal is True

    def test_confidently_malicious(self):
        d = smc.interpret_probability(0.95)
        assert d.bucket == "malicious"
        assert d.severity == "high"
        assert d.trust_signal is True

    def test_clamps_out_of_range(self):
        assert smc.interpret_probability(-0.5).bucket == "benign"
        assert smc.interpret_probability(1.5).bucket == "malicious"


class TestLexicalFeatureBonus:
    def test_clean_url_no_bonus(self):
        bonus, reasons = smc.lexical_feature_bonus("https://github.com/user/repo")
        assert bonus == 0.0
        assert reasons == []

    def test_high_risk_tld_adds_bonus(self):
        bonus, reasons = smc.lexical_feature_bonus("https://airdrop.xyz/")
        assert bonus > 0.0
        assert any("xyz" in r for r in reasons)

    def test_brand_impersonation_detected(self):
        bonus, reasons = smc.lexical_feature_bonus("https://apple-secure-login.tk/")
        assert bonus > 0.0
        assert any("apple" in r.lower() for r in reasons)
        assert any("tk" in r for r in reasons)

    def test_hyphen_storm_flagged(self):
        bonus, reasons = smc.lexical_feature_bonus("https://my-super-cool-airdrop-site.com/")
        assert bonus > 0.0
        assert any("hyphen" in r.lower() for r in reasons)

    def test_bonus_capped_at_20pct(self):
        # Every red flag at once.
        bonus, _ = smc.lexical_feature_bonus(
            "https://login-apple-secure-account-verify-1234567890.xyz.test.evil/"
        )
        assert bonus <= 0.20

    def test_empty_url_handled(self):
        assert smc.lexical_feature_bonus("")[0] == 0.0
        assert smc.lexical_feature_bonus(None)[0] == 0.0  # type: ignore[arg-type]

    def test_legitimate_brand_domain_no_bonus(self):
        # apple.com should not trigger the apple brand-impersonation rule.
        bonus, reasons = smc.lexical_feature_bonus("https://apple.com/account")
        # May still trigger something but not brand impersonation.
        assert not any("brand" in r.lower() for r in reasons)


class TestPredictionCache:
    def setup_method(self):
        # Clear cache before each test for isolation.
        conn = smc._cache_connection()
        if conn is not None:
            conn.execute("DELETE FROM ml_cache")

    def test_roundtrip(self):
        smc.cache_put("https://example.com/", {"label": "Benign (ML)", "score": 5.0})
        got = smc.cache_get("https://example.com/")
        assert got is not None
        assert got["label"] == "Benign (ML)"

    def test_normalization_collapses_trailing_slash(self):
        smc.cache_put("https://example.com/", {"label": "Benign"})
        # Same URL with no trailing slash should hit the same row.
        got = smc.cache_get("https://example.com")
        assert got is not None
        assert got["label"] == "Benign"

    def test_normalization_collapses_case(self):
        smc.cache_put("https://Example.com/", {"label": "Benign"})
        got = smc.cache_get("https://example.com/")
        assert got is not None

    def test_miss_returns_none(self):
        assert smc.cache_get("https://never-seen.test/") is None

    def test_empty_url_returns_none(self):
        assert smc.cache_get("") is None
        assert smc.cache_get(None) is None  # type: ignore[arg-type]

    def test_stats(self):
        smc.cache_put("https://a.test/", {"x": 1})
        smc.cache_put("https://b.test/", {"x": 2})
        stats = smc.cache_stats()
        assert stats["enabled"] is True
        assert stats["entries"] >= 2

    def test_overwrite_updates_value(self):
        smc.cache_put("https://overwrite.test/", {"label": "Benign"})
        smc.cache_put("https://overwrite.test/", {"label": "Malicious"})
        got = smc.cache_get("https://overwrite.test/")
        assert got["label"] == "Malicious"
