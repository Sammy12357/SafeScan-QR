"""Source-level release gates for public claims and controlled flows.

These supplement behavioral tests for billing and email. Pattern checks cannot
establish legal compliance or what production vendors actually receive.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_no_unreviewed_tracker_hosts_in_shipped_sources():
    blocked = (
        "hotjar.com", "google-analytics.com", "googletagmanager.com",
        "doubleclick.net", "facebook.com/tr", "fullstory.com",
        "clarity.ms", "segment.io", "mixpanel.com", "posthog.com",
        "intercom.io",
    )
    files = [
        *ROOT.joinpath("static").rglob("*.js"),
        *ROOT.joinpath("static").rglob("*.css"),
        *ROOT.joinpath("templates").rglob("*.html"),
        ROOT / "hackabull/app_module.py",
    ]
    hits = [f"{path.relative_to(ROOT)}: {host}" for path in files
            for host in blocked if host in path.read_text(encoding="utf-8").lower()]
    assert not hits, "Unreviewed tracking host: " + ", ".join(hits)


def test_browser_storage_and_cookie_names_are_in_inventory():
    inventory = _source("docs/legal/storage-inventory.md")
    written: set[str] = set()
    for path in ROOT.joinpath("static").rglob("*.js"):
        source = path.read_text(encoding="utf-8")
        literals = dict(re.findall(r"\b(?:const|let|var)\s+(\w+)\s*=\s*['\"]([^'\"]+)['\"]", source))
        for match in re.finditer(r"\b(?:localStorage|sessionStorage)\.setItem\(\s*([^,]+),", source):
            expression = match.group(1).strip()
            if expression.startswith(("'", '"')):
                written.add(expression[1:-1])
            elif expression in literals:
                written.add(literals[expression])
    assert written
    assert not (written - {key for key in written if key in inventory})
    for source_path in ("hackabull/config.py", "hackabull/age_gate.py"):
        source = _source(source_path)
        cookies = re.findall(r"\b\w*COOKIE(?:_NAME)?\s*=\s*['\"]([^'\"]+)['\"]", source)
        assert all(cookie in inventory for cookie in cookies), set(cookies) - {cookie for cookie in cookies if cookie in inventory}
    for family in ("safeScanGoGhostV2:account:", "safeScanGoGhostV2:guest", "safescan:actor-email:"):
        assert family in inventory


def test_data_map_has_field_level_purpose_and_retention():
    data_map = json.loads(_source("docs/legal/data-map.yaml"))
    assert data_map["tables"]
    for table, entry in data_map["tables"].items():
        assert entry["fields"], table
        assert all(entry.get(field) for field in ("source", "purpose", "storage", "recipients", "retention")), table


def test_marketing_sender_keeps_postal_and_one_click_footer():
    source = _source("hackabull/email_util.py")
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    configured = ast.get_source_segment(source, functions["marketing_email_configured"])
    sender = ast.get_source_segment(source, functions["send_email"])
    assert "COMPANY_LEGAL_NAME" in configured and "COMPANY_POSTAL_ADDRESS" in configured
    assert "_subscribed_and_unsuppressed" in sender
    assert "COMPANY_POSTAL_ADDRESS" in sender and "unsubscribe_url" in sender
    assert 'message["List-Unsubscribe"]' in sender
    assert 'message["List-Unsubscribe-Post"]' in sender
    assert 'raise ValueError("Unknown email template classification")' in sender


def test_public_copy_avoids_unsubstantiated_absolute_claims():
    files = [*ROOT.joinpath("templates").rglob("*.html"), ROOT / "hackabull/routes_pages.py", ROOT / "hackabull/admin_data.py"]
    banned = re.compile(r"\b(?:100%\s+(?:safe|secure|effective)|guaranteed\s+(?:safety|protection|removal)|bank.grade|fully\s+compliant|zero\s+false\s+positives)\b", re.I)
    hits = [f"{path.relative_to(ROOT)}:{number}" for path in files
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if banned.search(line)]
    assert not hits, "Unsupported absolute public claim: " + ", ".join(hits)
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bguarantee(?:d|s)?\b", line, re.I):
                assert re.search(r"\b(?:no|not|cannot|never|without)\b", line, re.I), f"{path.relative_to(ROOT)}:{number}: guarantee needs disclaimer context"


def test_payment_action_remains_beside_terms_and_requires_explicit_consent():
    source = _source("hackabull/routes_pages.py")
    section = source[source.index("async def alpha_payment_page("):source.index("@qr_app.post(\"/pay/alpha/stripe/checkout\")")]
    assert "terms = escape_html(billing_terms_text())" in section
    assert section.index("<p>{terms}</p>") < section.index("{stripe_button}")
    assert "name='recurring_consent' value='yes' required" in section
    assert "if stripe_token else" in section
    checkout = source[source.index("async def alpha_stripe_checkout("):]
    assert 'if recurring_consent != "yes":' in checkout
    billing = _source("hackabull/payments_stripe.py")
    assert "billed monthly until you cancel" in billing
    assert "BILLING_REFUND_POLICY_TEXT" in billing
    assert "billing_identity_ready()" in billing


def test_account_agreement_gate_when_versioned_flow_exists():
    agreement = ROOT / "hackabull/legal_agreements.py"
    if not agreement.exists():
        # Phase 2 has its own draft PR. This gate becomes active on merge.
        return
    source = agreement.read_text(encoding="utf-8")
    age_form = _source("templates/confirm_age.html")
    reaccept_form = _source("templates/accept_terms.html")
    route = _source("hackabull/routes_account.py")
    assert "terms_acceptances" in source and "validate_acceptance" in source
    for form in (age_form, reaccept_form):
        assert re.search(r'<input\s+type="checkbox"\s+name="legal_consent"[^>]*\brequired\b', form)
        assert "checked" not in re.search(r'<input\s+type="checkbox"\s+name="legal_consent"[^>]*>', form).group(0)
        assert 'name="terms_version"' in form and 'name="privacy_version"' in form
    assert 'legal_consent == "yes"' in route


def test_license_and_no_biometric_gates_when_license_phase_exists():
    license_gate = ROOT / "scripts/check_runtime_licenses.py"
    if not license_gate.exists():
        # Phase 3 replaces the known AGPL dependency; see attorney packet.
        return
    source = license_gate.read_text(encoding="utf-8")
    assert "DENIED" in source and "AGPL" in source and "SSPL" in source
    assert "license is unknown" in source
    assert (ROOT / "docs/legal/runtime-dependency-licenses.json").exists()
    assert (ROOT / "tests/test_legal_gate_licenses.py").exists()
    assert (ROOT / "docs/legal/data-rules.md").exists()


def test_no_face_voice_or_fingerprint_analysis_is_added():
    denied_imports = {"face_recognition", "mediapipe", "deepface", "insightface", "dlib", "speech_recognition"}
    denied_call = re.compile(r"\b(?:CascadeClassifier|FaceDetector|FaceLandmarker|FaceRecognizer|detectMultiScale|fingerprint_recognition)\s*\(")
    for directory in ("hackabull", "static", "scripts"):
        for path in ROOT.joinpath(directory).rglob("*"):
            if path.suffix not in {".py", ".js"}:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            assert not denied_call.search(source), path
            if path.suffix == ".py":
                tree = ast.parse(source, filename=str(path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        assert all(alias.name.split(".")[0] not in denied_imports for alias in node.names), path
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        assert node.module.split(".")[0] not in denied_imports, path
            else:
                assert not re.search(r"\b(?:from|import|require)\s*\(?\s*['\"](?:face-api|@mediapipe/|deepface)", source), path
