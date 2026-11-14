"""Browser-shaped test client for legacy feature tests.

The security tests use plain TestClient to exercise rejected requests.
"""

import re
from urllib.parse import urlsplit

from fastapi.testclient import TestClient


class BrowserTestClient(TestClient):
    def post(self, url, *, data=None, files=None, json=None, content=None, headers=None, **kwargs):
        path = urlsplit(str(url)).path
        supplied_headers = dict(headers or {})
        authorization = next((value for key, value in supplied_headers.items() if key.lower() == "authorization"), "")
        if path in {"/auth/google", "/webhooks/stripe", "/api/telemetry/scan"} or authorization.lower().startswith("bearer "):
            return super().post(url, data=data, files=files, json=json, content=content, headers=headers, **kwargs)

        page = super().get("/")
        match = re.search(r'<meta name="csrf-token" content="([a-f0-9]{64})"', page.text)
        assert match, "SafeScan page must expose a CSRF token"
        supplied_headers.setdefault("Origin", str(self.base_url).rstrip("/"))
        if data is not None or files is not None or (json is None and content is None):
            data = {**(data or {}), "csrf_token": match.group(1)}
        else:
            supplied_headers["X-CSRF-Token"] = match.group(1)
        return super().post(url, data=data, files=files, json=json, content=content, headers=supplied_headers, **kwargs)
