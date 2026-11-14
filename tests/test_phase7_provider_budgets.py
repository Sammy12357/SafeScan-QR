"""Paid-provider ceilings must preserve incomplete verification coverage."""

import importlib
import sys
from datetime import datetime, timezone

import pytest


@pytest.fixture()
def providers(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'provider-budget.db'}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("PROVIDER_BUDGETS_ENABLED", "true")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    budget = importlib.import_module("hackabull.provider_budget")
    reputation = importlib.import_module("hackabull.reputation")
    security = importlib.import_module("hackabull.security")
    feed = importlib.import_module("hackabull.phish_feed")
    pipeline = importlib.import_module("hackabull.pipeline")
    monkeypatch.setattr(security, "is_private_hostname", lambda _: False)
    yield budget, reputation, feed, pipeline
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def test_monthly_budget_counts_attempts_and_resets_at_utc_month(providers, monkeypatch):
    budget, _, _, _ = providers
    monkeypatch.setenv("WEB_RISK_MONTHLY_BUDGET", "2")
    instant = [datetime(2026, 1, 31, 23, 59, tzinfo=timezone.utc).timestamp()]
    monkeypatch.setattr(budget.time, "time", lambda: instant[0])

    for _ in range(2):
        with budget.outbound_provider("web_risk"):
            pass
    with pytest.raises(budget.ProviderUnavailable, match="budget_exhausted"):
        with budget.outbound_provider("web_risk"):
            pytest.fail("A third network call would exceed the cap")
    assert budget.usage_snapshot()["providers"]["web_risk"]["attempts"] == 2

    instant[0] = datetime(2026, 2, 1, 0, 1, tzinfo=timezone.utc).timestamp()
    with budget.outbound_provider("web_risk"):
        pass
    assert budget.usage_snapshot()["providers"]["web_risk"]["attempts"] == 1


def test_three_provider_errors_open_circuit_then_success_resets_it(providers, monkeypatch):
    budget, _, _, _ = providers
    monkeypatch.setenv("WEB_RISK_MONTHLY_BUDGET", "10")
    instant = [1_800_000_000.0]
    monkeypatch.setattr(budget.time, "time", lambda: instant[0])

    for _ in range(3):
        with pytest.raises(RuntimeError, match="upstream timeout"):
            with budget.outbound_provider("web_risk"):
                raise RuntimeError("upstream timeout")
    snapshot = budget.usage_snapshot()["providers"]["web_risk"]
    assert snapshot["attempts"] == snapshot["failures"] == 3
    assert snapshot["circuitOpen"] is True

    with pytest.raises(budget.ProviderUnavailable, match="circuit_open"):
        with budget.outbound_provider("web_risk"):
            pytest.fail("The open circuit must skip the call")
    instant[0] += 61
    with budget.outbound_provider("web_risk"):
        pass
    assert budget.usage_snapshot()["providers"]["web_risk"]["circuitOpen"] is False


def test_busy_provider_slot_does_not_spend_budget(providers, monkeypatch):
    budget, _, _, _ = providers
    monkeypatch.setenv("PHISHTANK_FEED_MONTHLY_BUDGET", "1")
    slot = budget._SLOTS["phishtank_feed"]
    assert slot.acquire(blocking=False)
    try:
        with pytest.raises(budget.ProviderUnavailable, match="provider_busy"):
            with budget.outbound_provider("phishtank_feed"):
                pytest.fail("Busy provider should not be called")
    finally:
        slot.release()
    assert budget.usage_snapshot()["providers"]["phishtank_feed"]["attempts"] == 0


def test_missing_web_risk_cap_is_unverified_without_outbound_call(providers, monkeypatch):
    budget, reputation, _, pipeline = providers
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")
    monkeypatch.delenv("WEB_RISK_MONTHLY_BUDGET", raising=False)
    monkeypatch.setattr(reputation.requests, "get", lambda *_a, **_kw: pytest.fail("No network call allowed"))

    finding = reputation.google_reputation_signal("https://example.org/")

    assert finding["check"] == "Google Web Risk"
    assert finding["verified"] is False
    assert finding["passed"] is False
    assert finding["severity"] == "medium"
    assert pipeline.verification_coverage([finding])[0] == "incomplete"
    assert budget.usage_snapshot()["providers"]["web_risk"]["attempts"] == 0


def test_malformed_web_risk_response_is_unverified_and_counts_as_failure(providers, monkeypatch):
    budget, reputation, _, pipeline = providers
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")
    monkeypatch.setenv("WEB_RISK_MONTHLY_BUDGET", "2")

    class Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {"threat": "not-an-object"}

    monkeypatch.setattr(reputation.requests, "get", lambda *_a, **_kw: Response())
    finding = reputation.google_reputation_signal("https://example.org/")
    assert finding["verified"] is False
    assert finding["passed"] is False
    assert pipeline.verification_coverage([finding])[0] == "incomplete"
    usage = budget.usage_snapshot()["providers"]["web_risk"]
    assert usage["attempts"] == usage["failures"] == 1


def test_denied_feed_refresh_keeps_existing_freshness_semantics(providers, monkeypatch):
    _, _, feed, _ = providers
    monkeypatch.setenv("PHISHTANK_APP_KEY", "test-app-key")
    monkeypatch.setenv("SAFESCAN_PHISHTANK_TERMS_CONFIRMED", "true")
    monkeypatch.delenv("PHISHTANK_FEED_MONTHLY_BUDGET", raising=False)
    monkeypatch.setattr(feed, "_download_feed", lambda _key: pytest.fail("No feed download allowed"))

    result = feed.refresh_feed(force=True)

    assert result == {"state": "missing", "refresh": "unavailable"}
    assert feed.phishtank_signal("https://example.org/")["verified"] is False


def test_phishtank_trickle_cannot_extend_refresh_forever(providers, monkeypatch):
    _, _, feed, _ = providers
    clock = iter([0, 1, 61])
    monkeypatch.setattr(feed.time, "monotonic", lambda: next(clock))

    class Response:
        status_code = 200
        headers = {}

        def iter_content(self, chunk_size):
            yield b"small chunk"

        def close(self):
            pass

    class Session:
        trust_env = True

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def get(self, *_args, **_kwargs):
            return Response()

    monkeypatch.setattr(feed.requests, "Session", Session)
    with pytest.raises(TimeoutError, match="deadline"):
        feed._download_feed("test-app-key")
