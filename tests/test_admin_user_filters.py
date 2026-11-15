"""Admin user lists must paginate filtered, account-scoped records."""

from contextlib import contextmanager
import sqlite3

from hackabull import admin_data


def user_list_database(tmp_path, monkeypatch):
    path = tmp_path / "admin-users.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE users (
                google_id TEXT PRIMARY KEY, email TEXT, display_name TEXT,
                role TEXT, status TEXT, created_at TEXT, last_login TEXT, last_login_at TEXT
            );
            CREATE TABLE scans (
                email TEXT PRIMARY KEY, user_id TEXT, scan_count INTEGER,
                wallet_address TEXT, tokens_sent INTEGER, airdrop_tokens_sent INTEGER,
                airdrop_sent_at TEXT
            );
            CREATE TABLE wallets (
                user_id TEXT UNIQUE, address TEXT, verified INTEGER,
                sol_balance REAL, tx_count INTEGER, wallet_age_days INTEGER,
                onchain_verified_at TEXT
            );
            CREATE TABLE referrals (referrer_email TEXT, counted INTEGER);
            CREATE TABLE fraud_flags (user_id TEXT, reviewed INTEGER);
        """)

    @contextmanager
    def get_test_conn():
        conn = sqlite3.connect(path)
        try:
            yield conn
        finally:
            conn.close()

    monkeypatch.setattr(admin_data, "get_conn", get_test_conn)
    return path


def test_tier_and_review_filters_apply_before_pagination(tmp_path, monkeypatch):
    path = user_list_database(tmp_path, monkeypatch)
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO users VALUES (?, ?, ?, 'user', 'active', ?, NULL, NULL)",
            [(f"account-{index:02d}", f"person-{index:02d}@example.test", str(index),
              f"2026-11-{30-index:02d}") for index in range(30)],
        )
        conn.execute("INSERT INTO scans VALUES ('person-29@example.test', 'account-29', 5, NULL, 0, 0, NULL)")
        conn.execute("INSERT INTO fraud_flags VALUES ('account-29', 0)")

    scanner = admin_data.fetch_admin_users(tier="Scanner", page=1, limit=25)
    assert scanner["total"] == scanner["pages"] == 1
    assert [row["google_id"] for row in scanner["rows"]] == ["account-29"]

    review = admin_data.fetch_admin_users(flag="review", page=1, limit=25)
    assert review["total"] == review["pages"] == 1
    assert [row["google_id"] for row in review["rows"]] == ["account-29"]

    registered = admin_data.fetch_admin_users(tier="Registered", page=2, limit=25)
    assert registered["total"] == 29
    assert registered["pages"] == 2
    assert len(registered["rows"]) == 4

    beyond = admin_data.fetch_admin_users(tier="Scanner", page=99, limit=25)
    assert beyond["page"] == 1
    assert [row["google_id"] for row in beyond["rows"]] == ["account-29"]


def test_ambiguous_email_legacy_data_is_not_attributed_to_either_account(tmp_path, monkeypatch):
    path = user_list_database(tmp_path, monkeypatch)
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO users VALUES (?, ?, ?, 'user', 'active', '2026-11-01', NULL, NULL)",
            [("account-A", "Shared@EXAMPLE.test", "A"),
             ("account-B", "shared@example.test", "B")],
        )
        conn.execute("INSERT INTO scans VALUES ('shared@example.test', NULL, 50, 'stale-wallet', 0, 0, NULL)")
        conn.execute("INSERT INTO wallets VALUES ('shared@example.test', 'legacy-wallet', 1, NULL, NULL, NULL, NULL)")
        conn.execute("INSERT INTO referrals VALUES ('shared@example.test', 1)")
        conn.execute("INSERT INTO fraud_flags VALUES ('shared@example.test', 0)")

    result = admin_data.fetch_admin_users(search="shared")
    assert result["total"] == 2
    for row in result["rows"]:
        assert row["ambiguous_email"] == 1
        assert row["scan_count"] == 0
        assert row["wallet_address"] is None
        assert row["referral_count"] == 0
        assert row["fraud_flags"] == 0
        assert row["tier"] == "Registered"
    assert admin_data.fetch_admin_users(tier="Guardian")["total"] == 0
    assert admin_data.fetch_admin_users(flag="review")["total"] == 0


def test_stable_id_records_survive_email_collision_and_unique_legacy_fallback(tmp_path, monkeypatch):
    path = user_list_database(tmp_path, monkeypatch)
    with sqlite3.connect(path) as conn:
        conn.executemany(
            "INSERT INTO users VALUES (?, ?, ?, 'user', 'active', '2026-11-01', NULL, NULL)",
            [("account-A", "Shared@EXAMPLE.test", "A"),
             ("account-B", "shared@example.test", "B"),
             ("account-C", "unique@example.test", "C")],
        )
        conn.execute("INSERT INTO scans VALUES ('old@example.test', 'account-A', 5, NULL, 0, 0, NULL)")
        conn.execute("INSERT INTO scans VALUES ('unique@example.test', NULL, 5, NULL, 0, 0, NULL)")
        conn.execute("INSERT INTO wallets VALUES ('account-B', 'verified-B', 1, NULL, NULL, NULL, NULL)")
        conn.execute("INSERT INTO wallets VALUES ('unique@example.test', 'legacy-C', 1, NULL, NULL, NULL, NULL)")
        conn.execute("INSERT INTO referrals VALUES ('unique@example.test', 1)")
        conn.execute("INSERT INTO fraud_flags VALUES ('account-B', 0)")
        conn.execute("INSERT INTO fraud_flags VALUES ('unique@example.test', 0)")

    rows = {row["google_id"]: row for row in admin_data.fetch_admin_users()["rows"]}
    assert rows["account-A"]["scan_count"] == 5
    assert rows["account-A"]["ambiguous_email"] == 1
    assert rows["account-A"]["tier"] == "Scanner"
    assert rows["account-B"]["wallet_address"] == "verified-B"
    assert rows["account-B"]["fraud_flags"] == 1
    assert rows["account-C"]["wallet_address"] == "legacy-C"
    assert rows["account-C"]["ambiguous_email"] == 0
    assert rows["account-C"]["tier"] == "Referrer"
    assert rows["account-C"]["fraud_flags"] == 1


def test_waitlist_search_filters_before_result_limit(tmp_path, monkeypatch):
    path = tmp_path / "waitlist.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE waitlist_signups (email TEXT, source TEXT, created_at TEXT)")
        conn.executemany(
            "INSERT INTO waitlist_signups VALUES (?, 'footer', ?)",
            [(f"person-{index:02d}@example.test", f"2026-11-{30-index:02d}")
             for index in range(29)] +
            [("needle@example.test", "2026-11-01")],
        )
    monkeypatch.setattr(admin_data, "database_path", lambda: str(path))

    result = admin_data.fetch_waitlist(search="needle", limit=5)
    assert result["total"] == 1
    assert [row["email"] for row in result["rows"]] == ["needle@example.test"]
