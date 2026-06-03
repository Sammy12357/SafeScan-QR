"""Unit tests for safescan_allowlist."""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `import safescan_allowlist` when tests are run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safescan_allowlist import (  # noqa: E402
    is_known_popular,
    load_allowlist,
    registrable_domain,
    safety_screen,
    should_short_circuit,
)


class TestRegistrableDomain:
    def test_simple_apex(self):
        assert registrable_domain("google.com") == "google.com"

    def test_strips_subdomains(self):
        assert registrable_domain("accounts.google.com") == "google.com"
        assert registrable_domain("a.b.c.d.shopify.com") == "shopify.com"

    def test_strips_www(self):
        assert registrable_domain("www.example.com") == "example.com"

    def test_strips_port(self):
        assert registrable_domain("example.com:8080") == "example.com"

    def test_two_label_public_suffix(self):
        assert registrable_domain("www.bbc.co.uk") == "bbc.co.uk"
        assert registrable_domain("foo.bar.com.au") == "bar.com.au"

    def test_handles_empty_and_garbage(self):
        assert registrable_domain("") == ""
        assert registrable_domain(".") == ""
        assert registrable_domain("localhost") == "localhost"


class TestLoadAllowlist:
    def test_loads_real_csv(self):
        allowlist = load_allowlist()
        # If the file shipped, we should have ~10k entries.
        assert len(allowlist) > 5000
        assert "google.com" in allowlist
        assert "facebook.com" in allowlist
        assert "wikipedia.org" in allowlist

    def test_obviously_fake_not_in_list(self):
        allowlist = load_allowlist()
        assert "claim-airdrop-drain-wallet.xyz" not in allowlist


class TestIsKnownPopular:
    def test_apex(self):
        assert is_known_popular("google.com") is True

    def test_subdomain(self):
        assert is_known_popular("accounts.google.com") is True
        assert is_known_popular("translate.google.com") is True

    def test_unknown(self):
        assert is_known_popular("claim-airdrop-drain-wallet.xyz") is False


class TestSafetyScreen:
    def test_clean_https_passes(self):
        ok, _ = safety_screen("https://google.com/")
        assert ok is True

    def test_clean_https_with_path_passes(self):
        ok, _ = safety_screen("https://github.com/user/repo")
        assert ok is True

    def test_http_rejected(self):
        ok, reason = safety_screen("http://google.com/")
        assert ok is False
        assert "non-https" in reason

    def test_at_sign_rejected(self):
        ok, reason = safety_screen("https://google.com@evil.test/")
        assert ok is False
        assert "@" in reason

    def test_raw_ip_rejected(self):
        ok, reason = safety_screen("https://203.0.113.10/")
        assert ok is False
        assert "ip" in reason.lower()

    def test_punycode_rejected(self):
        ok, reason = safety_screen("https://xn--80ak6aa92e.com/")
        assert ok is False
        assert "punycode" in reason

    def test_shortener_rejected(self):
        ok, reason = safety_screen("https://bit.ly/abc")
        assert ok is False
        assert "shortener" in reason

    def test_redirect_param_rejected(self):
        ok, reason = safety_screen("https://google.com/url?q=evil.test")
        assert ok is False
        assert "redirect" in reason

        ok, reason = safety_screen("https://facebook.com/l.php?u=evil.test")
        assert ok is False

    def test_empty_url_rejected(self):
        ok, _ = safety_screen("")
        assert ok is False


class TestShouldShortCircuit:
    def test_clean_popular_passes(self):
        ok, _ = should_short_circuit("https://www.youtube.com/watch?v=abc123")
        assert ok is True

    def test_popular_subdomain_passes(self):
        ok, _ = should_short_circuit("https://accounts.google.com/login")
        assert ok is True

    def test_unknown_domain_falls_through(self):
        ok, reason = should_short_circuit("https://claim-airdrop-drain-wallet.xyz/")
        assert ok is False
        assert "Tranco" in reason

    def test_popular_but_http_falls_through(self):
        ok, reason = should_short_circuit("http://google.com/")
        assert ok is False
        assert "safety screen" in reason

    def test_popular_with_open_redirect_falls_through(self):
        # google.com is popular, but the URL has the classic ?q= open redirect.
        ok, reason = should_short_circuit("https://www.google.com/url?q=https://evil.test/")
        assert ok is False
        assert "redirect" in reason.lower()

    def test_at_deception_against_popular_host_falls_through(self):
        # `urlparse` resolves the hostname AFTER the @, so this URL actually
        # points at google.com and the @ is treated as credentials. The
        # safety screen still rejects it because the netloc contains @.
        ok, reason = should_short_circuit("https://user@google.com/")
        assert ok is False
        assert "@" in reason

    def test_at_deception_to_evil_falls_through(self):
        # Here `urlparse` resolves the hostname to evil.test, so this gets
        # caught by the Tranco lookup before the safety screen runs.
        # Either way we don't short-circuit.
        ok, _ = should_short_circuit("https://google.com@evil.test/")
        assert ok is False

    def test_homograph_falls_through(self):
        # Cyrillic 'а' (U+0430) in place of Latin 'a'.
        ok, reason = should_short_circuit("https://gooаle.com/")
        assert ok is False
