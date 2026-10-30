"""Local PhishTank feed checks must be fresh, exact, bounded, and private."""

import gzip
import importlib
import time

import pytest


@pytest.fixture()
def feed(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("PHISHTANK_APP_KEY", "test-app-key")
    monkeypatch.setenv("SAFESCAN_PHISHTANK_TERMS_CONFIRMED", "true")
    return importlib.import_module("hackabull.phish_feed")


def install_session(feed, monkeypatch, get):
    sessions = []

    class Session:
        trust_env = True

        def __enter__(self):
            sessions.append(self)
            return self

        def __exit__(self, *args):
            return None

        def get(self, url, **kwargs):
            return get(url, **kwargs)

    monkeypatch.setattr(feed.requests, "Session", Session)
    return sessions


def test_fresh_feed_matches_exact_url_and_stale_feed_is_unverified(feed):
    csv_bytes = (
        b"phish_id,url,verified,online\n"
        b"1,https://PHISH.example:443/pay?account=one,yes,yes\n"
        b"2,https://offline.example/,yes,no\n"
        b"3,https://unverified.example/,no,yes\n"
    )
    feed._write_snapshot(csv_bytes, feed._feed_path(), time.time())

    hit = feed.phishtank_signal("https://phish.example/pay?account=one#receipt")
    changed_payee = feed.phishtank_signal("https://phish.example/pay?account=two")
    offline = feed.phishtank_signal("https://offline.example/")

    assert hit["severity"] == "high" and hit["verified"] is True and hit["passed"] is False
    assert changed_payee["result"] == "No known match" and changed_payee["verified"] is True
    assert offline["result"] == "No known match"
    assert all(item["severity"] in {"low", "medium", "high"} for item in (hit, changed_payee, offline))

    feed._write_snapshot(csv_bytes, feed._feed_path(), time.time() - feed.MAX_FEED_AGE_SECONDS - 1)
    stale = feed.phishtank_signal("https://phish.example/pay?account=one")
    assert feed.feed_status()["state"] == "stale"
    assert stale["verified"] is False


def test_refresh_follows_only_phishtank_cdn_and_preserves_last_good_feed(feed, monkeypatch):
    old_csv = b"url,verified,online\nhttps://old-phish.example/,yes,yes\n"
    feed._write_snapshot(old_csv, feed._feed_path(), time.time())
    new_csv = b"url,verified,online\nhttps://new-phish.example/path,yes,yes\n"
    calls = []

    class Response:
        def __init__(self, status, headers=None, payload=b""):
            self.status_code = status
            self.headers = headers or {}
            self.payload = payload

        def iter_content(self, chunk_size):
            yield self.payload

        def close(self):
            pass

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError("test response failed")

    def get(url, **kwargs):
        calls.append((url, kwargs))
        if url.startswith("https://data.phishtank.com/"):
            return Response(302, {"Location": "https://cdn.phishtank.com/datadumps/verified_online.csv.gz"})
        return Response(200, {"Content-Length": "100"}, gzip.compress(new_csv))

    sessions = install_session(feed, monkeypatch, get)
    refreshed = feed.refresh_feed(force=True)

    assert refreshed == {"state": "fresh", "entries": 1}
    assert len(calls) == 2
    assert sessions[0].trust_env is False
    assert all(kwargs["allow_redirects"] is False for _, kwargs in calls)
    assert calls[0][0].startswith("https://data.phishtank.com/data/test-app-key/")
    assert feed.phishtank_signal("https://new-phish.example/path")["severity"] == "high"
    assert feed.phishtank_signal("https://old-phish.example/")["result"] == "No known match"

    install_session(feed, monkeypatch, lambda *args, **kwargs: Response(
        302, {"Location": "https://attacker.example/feed.csv.gz"}
    ))
    with pytest.raises(ValueError, match="outside its approved hosts"):
        feed.refresh_feed(force=True)
    assert feed.phishtank_signal("https://new-phish.example/path")["severity"] == "high"


def test_oversized_or_disabled_feed_never_becomes_verified(feed, monkeypatch):
    monkeypatch.setattr(feed, "MAX_UNCOMPRESSED_BYTES", 40)

    class Response:
        status_code = 200
        headers = {}

        def iter_content(self, chunk_size):
            yield gzip.compress(b"url,verified,online\nhttps://phish.example/,yes,yes\n")

        def close(self):
            pass

    install_session(feed, monkeypatch, lambda *args, **kwargs: Response())
    with pytest.raises(ValueError, match="expanded size limit"):
        feed.refresh_feed(force=True)
    assert feed.feed_status()["state"] == "missing"
    assert feed.phishtank_signal("https://phish.example/")["verified"] is False

    monkeypatch.setenv("SAFESCAN_PHISHTANK_TERMS_CONFIRMED", "false")
    assert feed.refresh_feed(force=True)["state"] == "terms_not_confirmed"
    assert feed.phishtank_signal("https://phish.example/")["verified"] is False
