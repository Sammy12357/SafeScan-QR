"""The live crawl probes redirect responses before a client follows them."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from scripts import seo_smoke


def test_redirect_fetch_uses_get_and_stops_at_first_response():
    paths = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            if self.path == "/old":
                self.send_response(301)
                self.send_header("Location", "/new")
            else:
                self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, location = seo_smoke.fetch_redirect(
            f"http://127.0.0.1:{server.server_port}/old", timeout=2,
        )
        assert (status, location) == (301, "/new")
        assert paths == ["/old"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_redirect_check_requires_exact_status_and_location(monkeypatch):
    responses = {
        source: (301, target)
        for source, target in seo_smoke.REDIRECT_CASES
    }
    responses.update({target: (200, "") for _, target in seo_smoke.REDIRECT_CASES})
    monkeypatch.setattr(seo_smoke, "fetch_redirect", lambda source, _timeout: responses[source])
    problems, rows = seo_smoke.check_redirects(2)
    assert problems == []
    assert len(rows) == len(seo_smoke.REDIRECT_CASES)
    assert all(row["errors"] == [] for row in rows)
    assert all(row["destination_status"] == 200 for row in rows)

    permanent_source = seo_smoke.REDIRECT_CASES[0][0]
    responses[permanent_source] = (308, seo_smoke.REDIRECT_CASES[0][1])
    problems, rows = seo_smoke.check_redirects(2)
    assert problems == []
    assert rows[0]["status"] == 308

    broken_source = seo_smoke.REDIRECT_CASES[1][0]
    responses[broken_source] = (302, "https://sqafe.com/wrong")
    problems, rows = seo_smoke.check_redirects(2)
    assert len(problems) == 2
    assert any("expected permanent HTTP 301 or 308, got 302" in problem for problem in problems)
    assert any("expected Location https://sqafe.com/learn?x=1" in problem for problem in problems)
    report = seo_smoke.report(problems, [], rows)
    assert "## Redirect checks" in report
    assert "| https://safescan-qr.onrender.com/learn?x=1 | 302 | https://sqafe.com/wrong |  |" in report
    assert "not evidence of search-engine indexing or ranking" in report


def test_redirect_check_rejects_chained_and_broken_destinations(monkeypatch):
    responses = {
        source: (301, target)
        for source, target in seo_smoke.REDIRECT_CASES
    }
    responses.update({target: (200, "") for _, target in seo_smoke.REDIRECT_CASES})
    monkeypatch.setattr(seo_smoke, "fetch_redirect", lambda source, _timeout: responses[source])
    source, target = seo_smoke.REDIRECT_CASES[2]  # Unique /plans target.

    responses[target] = (302, "https://sqafe.com/another")
    problems, rows = seo_smoke.check_redirects(2)
    assert len(problems) == 1
    assert source in problems[0]
    assert "expected redirect target HTTP 200 without another hop, got 302" in problems[0]
    assert rows[2]["destination_status"] == 302

    responses[target] = (404, "")
    problems, rows = seo_smoke.check_redirects(2)
    assert len(problems) == 1
    assert source in problems[0]
    assert "expected redirect target HTTP 200 without another hop, got 404" in problems[0]
    assert rows[2]["destination_status"] == 404
