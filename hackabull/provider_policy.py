"""Configuration gates for third-party URL reputation providers.

Keys alone never imply permission to use a provider in a commercial service.
The explicit flags below are operator attestations, not license verification.
"""

import os


_TRUE_VALUES = {"1", "true", "yes", "on"}


def _enabled(name):
    return os.getenv(name, "").strip().lower() in _TRUE_VALUES


def web_risk_key():
    return os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()


def legacy_safe_browsing_key():
    return (os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("googe_api_key") or "").strip()


def legacy_safe_browsing_enabled():
    return bool(legacy_safe_browsing_key()) and _enabled("SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING")


def reputation_configuration():
    """Report configuration and local-feed state without claiming live uptime."""
    from .phish_feed import feed_status

    phishtank = feed_status()
    if web_risk_key():
        google = "web_risk_configured"
    elif legacy_safe_browsing_enabled():
        google = "safe_browsing_noncommercial_enabled"
    elif legacy_safe_browsing_key():
        google = "legacy_key_disabled"
    else:
        google = "unconfigured"

    return {
        "google": google,
        "phishtank": phishtank["state"],
        "phishtankFeedAgeSeconds": phishtank.get("ageSeconds"),
        "completeChecksConfigured": google in {"web_risk_configured", "safe_browsing_noncommercial_enabled"}
        and phishtank["state"] == "fresh",
    }
