"""Small, process-local budget for public component inspection endpoints.

The shared global cap limits work even before the trusted client-IP migration
lands. Per-client keys are hashed so this store does not retain raw IPs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque

from .errors import error_response
from .request_helpers import request_ip


class ComponentBudget:
    WINDOW_SECONDS = 60 * 60
    CLIENT_LIMIT = 10
    CLIENT_OUTBOUND_LIMIT = 5
    GLOBAL_LIMIT = 120
    GLOBAL_OUTBOUND_LIMIT = 60
    MAX_CLIENTS = 4096

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._key = secrets.token_bytes(32)
        self._clients: OrderedDict[str, tuple[deque[float], deque[float]]] = OrderedDict()
        self._global: deque[float] = deque()
        self._global_outbound: deque[float] = deque()

    @staticmethod
    def _expire(hits: deque[float], cutoff: float) -> None:
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def check(self, request, *, outbound: bool = False):
        identity = request_ip(request)
        # Bound the cost of hashing a hostile forwarded header. Phase 3 will
        # replace request_ip with a trusted ingress resolver.
        if not isinstance(identity, str) or len(identity) > 256:
            identity = "unverified"
        client_key = hmac.new(self._key, identity.encode("utf-8", "replace"), hashlib.sha256).hexdigest()

        with self._lock:
            # Sample after acquiring the lock so concurrent appends preserve
            # timestamp order for the rolling-window deques.
            now = time.monotonic()
            cutoff = now - self.WINDOW_SECONDS
            self._expire(self._global, cutoff)
            self._expire(self._global_outbound, cutoff)
            while self._clients:
                oldest_all, oldest_outbound = next(iter(self._clients.values()))
                self._expire(oldest_all, cutoff)
                self._expire(oldest_outbound, cutoff)
                if oldest_all or oldest_outbound:
                    break
                self._clients.popitem(last=False)

            all_hits, outbound_hits = self._clients.get(client_key, (deque(), deque()))
            self._expire(all_hits, cutoff)
            self._expire(outbound_hits, cutoff)
            budgets = [(all_hits, self.CLIENT_LIMIT), (self._global, self.GLOBAL_LIMIT)]
            if outbound:
                budgets.extend(((outbound_hits, self.CLIENT_OUTBOUND_LIMIT), (self._global_outbound, self.GLOBAL_OUTBOUND_LIMIT)))
            exhausted = [hits for hits, limit in budgets if len(hits) >= limit]
            if exhausted:
                retry_after = max(1, int(max(self.WINDOW_SECONDS - (now - hits[0]) for hits in exhausted)) + 1)
                return error_response(
                    request, 429, code="rate_limited", message="Too many requests",
                    headers={"Retry-After": str(retry_after)},
                )

            all_hits.append(now)
            self._global.append(now)
            if outbound:
                outbound_hits.append(now)
                self._global_outbound.append(now)
            self._clients[client_key] = (all_hits, outbound_hits)
            self._clients.move_to_end(client_key)
            while len(self._clients) > self.MAX_CLIENTS:
                self._clients.popitem(last=False)
        return None


COMPONENT_BUDGET = ComponentBudget()
