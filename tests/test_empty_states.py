"""Server-rendered empty states should explain the next useful action."""

from contextlib import contextmanager
import sqlite3

import pytest
from starlette.requests import Request

from hackabull.config import templates


def render(name, **context):
    return templates.env.get_template(name).render(**context)


def admin_request(path, query=""):
    return Request({
        "type": "http", "method": "GET", "path": path,
        "query_string": query.encode(), "headers": [],
        "scheme": "https", "server": ("example.test", 443),
    })


def render_admin(page, data, path=None, query=""):
    return render(
        "admin_shell.html",
        request=admin_request(path or f"/admin/{page}", query),
        title="Admin", page=page, data=data, avatar="A", is_owner=True,
        admin_user={"email": "admin@example.test", "role": "owner"},
    )


def assert_empty_state(html, heading, action_href, heading_level=2):
    assert 'class="state state-empty' in html
    assert 'role="status"' in html
    assert f'<h{heading_level} class="state-title">{heading}</h{heading_level}>' in html
    assert f'href="{action_href}"' in html


def test_history_signed_out_and_first_scan():
    signed_out = render("history.html", email="", scans=[], scan_groups=[])
    assert_empty_state(signed_out, "Sign in to see your scans", "/login")
    first_scan = render("history.html", email="user@example.test", scans=[], scan_groups=[])
    assert_empty_state(first_scan, "No saved scans yet", "/#scanner")


def test_leaderboard_keeps_live_refresh_hook():
    html = render("leaderboard.html", leaders=[], current_user_id=None)
    assert '<div class="lb-empty"' in html
    assert_empty_state(html, "No scanners on the board yet", "/#scanner")
    assert 'class="lb-table lb-initially-hidden" id="lbTable"' in html


def test_profile_first_use_states():
    html = render(
        "profile.html", email="user@example.test", username="", error="",
        discord_enabled=True, discord_error="", discord_link=None, is_admin=False,
    )
    assert_empty_state(html, "No public username yet", "#usernameForm")
    assert_empty_state(html, "No Discord account linked", "/auth/discord", heading_level=3)


def test_scan_result_without_visible_reasons_has_guidance():
    html = render(
        "index.html", results_visible=True, risk_reasons=[{"check": "ML Risk Model"}],
        status="CAUTION", score=50, url_found="", overall_risk="medium", logged_in=False,
    )
    assert_empty_state(html, "No additional risk details", "/#scanner", heading_level=3)
    with_reason = render(
        "index.html", results_visible=True,
        risk_reasons=[{"check": "ML Risk Model"}, {"check": "URL", "label": "URL check", "severity": "low", "detail": "Checked"}],
        status="CAUTION", score=50, url_found="", overall_risk="medium", logged_in=False,
    )
    assert "No additional risk details" not in with_reason
    assert '<details class="reason-row" open>' in with_reason


def test_go_ghost_has_first_use_and_no_broker_fallbacks():
    html = render("go_ghost.html", browser_automation_available=False,
                  go_ghost_account_id="", go_ghost_account_name="", go_ghost_account_email="",
                  go_ghost_us_states=[], go_ghost_brokers=[], logged_in=False)
    assert 'id="ghostFirstUseState"' in html
    assert_empty_state(html, "Start with your details", "#goGhostProfileForm", heading_level=3)
    assert 'id="goGhostNoBrokerState" hidden' in html
    assert "No broker sites available" in html


def test_empty_dashboard_panels_have_actions():
    html = render_admin("dashboard", {
        "stats": [], "chart_rows": [], "verdict_rows": [],
        "recent_users": [], "recent_reports": [], "activity": [],
    }, path="/admin")
    for heading in ("No scan activity yet", "No verdicts yet", "No signups yet",
                    "No reports to review", "No recent activity"):
        assert f'<h3 class="state-title">{heading}</h3>' in html


def test_standalone_consent_log_empty_state():
    html = render("admin_table.html", title="Consent Log", body_html="<table></table>",
                  message="", empty_state_title="No consent records yet",
                  empty_state_body="Consent decisions will appear here when they are recorded.")
    assert_empty_state(html, "No consent records yet", "/admin")
    assert "<table></table>" not in html


@pytest.mark.parametrize(("page", "data", "path", "heading", "action"), [
    ("users", {"rows": [], "filters": {"search": "", "status": "", "role": "", "tier": "", "flag": ""}, "page": 1, "pages": 1, "total": 0}, "/admin/users", "No users yet", "/admin"),
    ("scans", {"rows": [], "stats": {"total": 0, "flagged_today": 0, "avg_risk": 0, "common_tld": "—"}}, "/admin/scans", "No scans yet", "/#scanner"),
    ("scans", {"rows": [], "stats": {"total": 0, "flagged_today": 0, "avg_risk": 0, "common_tld": "—"}}, "/admin/risk-logs", "No malicious scans logged", "/admin/scans"),
    ("waitlist", {"rows": [], "total": 0, "filters": {"search": ""}}, "/admin/waitlist", "No waitlist signups yet", "/admin"),
    ("reports", {"tab": "reports", "reports": []}, "/admin/reports", "No reports to review", "/admin/scans"),
    ("reports", {"tab": "blocklist", "blocklist": []}, "/admin/reports", "Blocklist is empty", "/admin/reports"),
    ("airdrop", {"wallet_users": [], "qualified": [], "estimated_total": 0, "distributed_total": 0, "tier_counts": {"Scanner": 0, "Referrer": 0, "Guardian": 0}, "flagged": [], "base_allocation": 0}, "/admin/airdrop", "No wallets connected yet", "/admin/users"),
    ("fraud", {"rows": []}, "/admin/airdrop/fraud", "No fraud flags to review", "/admin/airdrop"),
    ("logs", {"rows": [], "actions": []}, "/admin/logs", "No audit logs yet", "/admin"),
    ("api_keys", {"keys": []}, "/admin/api-keys", "No API keys yet", "#createApiKeyForm"),
])
def test_admin_empty_table(page, data, path, heading, action):
    html = render_admin(page, data, path)
    assert_empty_state(html, heading, action, heading_level=3 if page == "airdrop" else 2)
    assert '<table class="admin-table"' not in html


def test_admin_filtered_empty_states_offer_clear_filter():
    users = {"rows": [], "filters": {"search": "", "status": "", "role": "", "tier": "", "flag": "review"}, "page": 1, "pages": 1, "total": 0}
    assert_empty_state(render_admin("users", users), "No users match these filters", "/admin/users")
    scans = {"rows": [], "stats": {"total": 0, "flagged_today": 0, "avg_risk": 0, "common_tld": "—"}}
    assert_empty_state(render_admin("scans", scans, query="search=none"), "No scans match these filters", "/admin/scans")
    waitlist = {"rows": [], "total": 0, "filters": {"search": "none"}}
    assert_empty_state(render_admin("waitlist", waitlist), "No signups match this search", "/admin/waitlist")
    logs = {"rows": [], "actions": []}
    assert_empty_state(render_admin("logs", logs, query="action=none"), "No logs match these filters", "/admin/logs")


def test_admin_user_detail_has_content_and_contextual_empty_subsections():
    user = {
        "email": "scanner@example.test", "display_name": "Test Scanner", "status": "active",
        "role": "user", "created_at": "2026-11-01", "last_login_at": None,
        "last_login": None, "scan_count": 0, "wallet_address": None,
    }
    html = render_admin("user_drawer", {"user": user, "flags": [], "logs": [], "scans": []}, path="/admin/users/scanner@example.test/drawer")
    assert '<h2 id="admin-detail-name">Test Scanner</h2>' in html
    assert "scanner@example.test" in html
    for heading, href in (
        ("No verified wallet", "/admin/airdrop/wallets"),
        ("No fraud flags", "/admin/airdrop/fraud"),
        ("No saved scans", "/admin/scans"),
        ("No account activity logged", "/admin/logs"),
    ):
        assert_empty_state(html, heading, href, heading_level=3)

    populated = render_admin("user_drawer", {
        "user": {**user, "wallet_address": "SyntheticWalletAddress", "wallet_verified": 1, "scan_count": 1},
        "flags": [{"check_name": "scan_velocity", "severity": "medium", "reason": "Burst of scans", "reviewed": 0, "created_at": "2026-11-02"}],
        "logs": [{"action": "user.login", "created_at": "2026-11-03"}],
        "scans": [{"url": "https://example.test/<script>", "verdict": "CAUTION", "risk_score": 42, "created_at": "2026-11-04"}],
    })
    assert "SyntheticWalletAddress" in populated
    assert "Burst of scans" in populated
    assert "User Login" in populated
    assert "Risk 42" in populated
    assert "&lt;script&gt;" in populated
    assert "No fraud flags" not in populated
    assert "No saved scans" not in populated


def test_admin_user_detail_link_is_reachable_from_user_list():
    html = render_admin("users", {
        "rows": [{"email": "scanner@example.test", "display_name": "Test Scanner", "role": "user", "status": "active", "tier": "Registered", "scan_count": 0, "referral_count": 0, "wallet_address": None, "created_at": "2026-11-01", "last_login_at": None, "last_login": None}],
        "filters": {"search": "", "status": "", "role": "", "tier": "", "flag": ""},
        "page": 1, "pages": 1, "total": 1,
    })
    assert 'href="/admin/users/scanner%40example.test/drawer"' in html


def test_fetch_user_detail_resolves_account_id_and_keeps_other_users_out(tmp_path, monkeypatch):
    from hackabull import admin_data

    database = tmp_path / "user-detail.db"
    with sqlite3.connect(database) as conn:
        conn.executescript("""
            CREATE TABLE users (google_id TEXT, email TEXT, display_name TEXT, role TEXT, status TEXT, created_at TEXT, last_login TEXT, last_login_at TEXT);
            CREATE TABLE scans (email TEXT, wallet_address TEXT, scan_count INTEGER);
            CREATE TABLE wallets (user_id TEXT, address TEXT, verified INTEGER, sol_balance REAL, tx_count INTEGER, wallet_age_days INTEGER, onchain_verified_at TEXT);
            CREATE TABLE fraud_flags (id TEXT, user_id TEXT, check_name TEXT, severity TEXT, reason TEXT, metadata TEXT, reviewed INTEGER, created_at TEXT);
            CREATE TABLE audit_logs (id TEXT, actor_user_id TEXT, action TEXT, target_id TEXT, created_at TEXT);
            CREATE TABLE scan_history (id TEXT, email TEXT, url TEXT, risk_score INTEGER, verdict TEXT, signals TEXT, created_at TEXT);
            INSERT INTO users VALUES ('account-1', 'one@example.test', 'One', 'user', 'active', '2026-11-01', NULL, NULL);
            INSERT INTO users VALUES ('account-2', 'two@example.test', 'Two', 'user', 'active', '2026-11-01', NULL, NULL);
            INSERT INTO scans VALUES ('one@example.test', 'stale-unverified-wallet', 1);
            INSERT INTO wallets VALUES ('account-2', 'verified-legacy-wallet', 1, 0, 0, 0, '2026-11-01');
            INSERT INTO fraud_flags VALUES ('flag-1', 'account-1', 'scan_velocity', 'medium', 'Burst of scans', '{}', 0, '2026-11-02');
            INSERT INTO fraud_flags VALUES ('flag-2', 'account-2', 'scan_velocity', 'medium', 'Other account', '{}', 0, '2026-11-02');
            INSERT INTO audit_logs VALUES ('log-1', 'account-1', 'user.login', NULL, '2026-11-03');
            INSERT INTO audit_logs VALUES ('log-2', 'account-2', 'user.login', NULL, '2026-11-03');
            INSERT INTO scan_history VALUES ('scan-1', 'one@example.test', 'https://one.example.test', 42, 'CAUTION', '[]', '2026-11-04');
            INSERT INTO scan_history VALUES ('scan-2', 'two@example.test', 'https://two.example.test', 10, 'SAFE', '[]', '2026-11-04');
        """)

    @contextmanager
    def get_test_conn():
        conn = sqlite3.connect(database)
        try:
            yield conn
        finally:
            conn.close()

    monkeypatch.setattr(admin_data, "get_conn", get_test_conn)
    detail = admin_data.fetch_user_detail("ONE@example.test")
    assert detail["user"]["google_id"] == "account-1"
    assert detail["user"]["wallet_address"] is None
    assert [flag["id"] for flag in detail["flags"]] == ["flag-1"]
    assert [log["id"] for log in detail["logs"]] == ["log-1"]
    assert [scan["id"] for scan in detail["scans"]] == ["scan-1"]
    legacy_detail = admin_data.fetch_user_detail("account-2")
    assert legacy_detail["user"]["wallet_address"] == "verified-legacy-wallet"
    assert legacy_detail["user"]["wallet_verified"] == 1
    assert admin_data.fetch_user_detail("missing@example.test") == {"user": None, "flags": [], "logs": [], "scans": []}
