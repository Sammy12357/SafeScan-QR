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


def virustotal_key():
    if not _enabled("SAFESCAN_VIRUSTOTAL_LICENSED"):
        return ""
    return os.getenv("VIRUSTOTAL_API_KEY", "").strip()


def virustotal_submit_unknown_urls():
    return bool(virustotal_key()) and _enabled("SAFESCAN_VIRUSTOTAL_SUBMIT_UNKNOWN_URLS")


def reputation_configuration():
    """Report configuration state without exposing keys or claiming live uptime."""
    if web_risk_key():
        google = "web_risk_configured"
    elif legacy_safe_browsing_enabled():
        google = "safe_browsing_noncommercial_enabled"
    elif legacy_safe_browsing_key():
        google = "legacy_key_disabled"
    else:
        google = "unconfigured"

    if virustotal_key():
        virustotal = "licensed_configured"
    elif os.getenv("VIRUSTOTAL_API_KEY", "").strip():
        virustotal = "license_confirmation_required"
    else:
        virustotal = "unconfigured"

    return {
        "google": google,
        "virustotal": virustotal,
        "completeChecksConfigured": google in {"web_risk_configured", "safe_browsing_noncommercial_enabled"}
        and virustotal == "licensed_configured",
    }
