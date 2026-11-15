"""Server-rendered empty states should explain the next useful action."""

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
    assert 'id="lbTable" style="display:none"' in html


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
