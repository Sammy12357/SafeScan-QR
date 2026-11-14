"""Bounded, process-local sliding-window request budgets."""

from __future__ import annotations

import math
import threading
from collections import OrderedDict


class RateLimitStore(OrderedDict):
    """Keep only recent buckets and evict the least recently used at capacity.

    The mapping interface remains available for existing diagnostics and tests.
    Application requests use ``check_and_record`` so multiple identity buckets
    are checked and updated together under one lock.
    """

    def __init__(self, max_buckets: int = 4096):
        super().__init__()
        if max_buckets < 2:
            raise ValueError("Rate-limit capacity must allow two identity buckets.")
        self.max_buckets = max_buckets
        self._expires_at: dict[str, float] = {}
        self._lock = threading.RLock()
        self._operations = 0

    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)
            self.move_to_end(key)
            while len(self) > self.max_buckets:
                oldest, _ = super().popitem(last=False)
                self._expires_at.pop(oldest, None)

    def clear(self):
        with self._lock:
            super().clear()
            self._expires_at.clear()
            self._operations = 0

    def _sweep_expired(self, now: float):
        if len(self) < self.max_buckets and self._operations % 64:
            return
        for key, expiry in list(self._expires_at.items()):
            if expiry <= now or key not in self:
                super().pop(key, None)
                self._expires_at.pop(key, None)

    def check_and_record(self, budgets: list[tuple[str, int]], window_seconds: int, now: float) -> int | None:
        """Return Retry-After seconds when any budget is exhausted."""
        if window_seconds <= 0 or any(limit <= 0 for _, limit in budgets):
            raise ValueError("Rate-limit settings must be positive.")
        with self._lock:
            self._operations += 1
            self._sweep_expired(now)
            cutoff = now - window_seconds
            recent = {}
            retry_after = 0
            for key, limit in budgets:
                hits = [stamp for stamp in super().get(key, []) if stamp > cutoff]
                recent[key] = hits
                if len(hits) >= limit:
                    retry_after = max(retry_after, math.ceil(hits[0] + window_seconds - now))
            if retry_after:
                return max(1, retry_after)
            for key, _ in budgets:
                hits = recent[key]
                hits.append(now)
                self[key] = hits
                self._expires_at[key] = now + window_seconds
        return None
