"""Bounded, opt-in security alert counts with no customer data in delivery."""

from __future__ import annotations

import logging
import os
import queue
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

LOG = logging.getLogger(__name__)

# Fixed event names only. No route, account, IP, URL, token, or metadata is
# stored in the alert counters or sent to a notification destination.
DEFAULT_RULES = {
    "auth.failed": (20, 600),
    "auth.permission_denied.admin": (1, 600),
    "admin.role_changed": (1, 600),
    "api_key.created": (1, 600),
    "airdrop.sweep_executed": (1, 600),
    "airdrop.sweep_failed": (1, 600),
    "stripe.signature_failed": (5, 600),
    "http.5xx": (10, 300),
}
COOLDOWN_SECONDS = 600
QUEUE_MAX = 32
QUEUE_RETRY_SECONDS = 30
DELIVERY_RETRY_DELAYS = (1.0, 4.0)
ENABLED = os.getenv("SECURITY_ALERTS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
DISCORD_WEBHOOK_URL = os.getenv("SECURITY_ALERT_DISCORD_WEBHOOK_URL", "").strip()
EMAIL_TO = os.getenv("SECURITY_ALERT_EMAIL_TO", "").strip()


@dataclass(frozen=True)
class Alert:
    code: str
    count: int
    window_seconds: int


class SecurityAlertMonitor:
    def __init__(self, *, enabled=False, rules=None, cooldown=COOLDOWN_SECONDS, clock=None, dispatch=None):
        self.enabled = enabled
        self.rules = dict(rules or DEFAULT_RULES)
        self.cooldown = cooldown
        self.clock = clock or time.monotonic
        self.dispatch = dispatch or _enqueue
        self._lock = threading.Lock()
        self._events = {
            code: deque(maxlen=max(1, min(1000, threshold)))
            for code, (threshold, _window) in self.rules.items()
        }
        self._last_alert = {code: float("-inf") for code in self.rules}

    def record(self, code: str) -> Alert | None:
        if not self.enabled or code not in self.rules:
            return None
        threshold, window = self.rules[code]
        if threshold < 1 or window < 1:
            return None
        now = self.clock()
        with self._lock:
            observed = self._events[code]
            while observed and now - observed[0] >= window:
                observed.popleft()
            observed.append(now)
            if len(observed) < threshold or now - self._last_alert[code] < self.cooldown:
                return None
            self._last_alert[code] = now
            alert = Alert(code, len(observed), window)
        try:
            self.dispatch(alert)
        except Exception as exc:  # alert failures must not break a user request
            with self._lock:
                if self._last_alert[code] == now:
                    self._last_alert[code] = now - self.cooldown + QUEUE_RETRY_SECONDS
            LOG.warning("Security alert enqueue failed: %s", type(exc).__name__)
            return None
        return alert

    def retained_count(self) -> int:
        """Count bounded timestamps for tests and operator diagnostics."""
        with self._lock:
            return sum(len(items) for items in self._events.values())

    def delivery_failed(self, code: str) -> None:
        """Allow another alert after a short pause if delivery exhausted retries."""
        if code not in self._last_alert:
            return
        now = self.clock()
        with self._lock:
            self._last_alert[code] = min(
                self._last_alert[code], now - self.cooldown + QUEUE_RETRY_SECONDS
            )


_QUEUE: queue.Queue[Alert] = queue.Queue(maxsize=QUEUE_MAX)
_WORKER_LOCK = threading.Lock()
_WORKER_STARTED = False


def _valid_discord_webhook(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme == "https"
            and parsed.hostname == "discord.com"
            and parsed.port in (None, 443)
            and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment
            and bool(re.fullmatch(r"/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", parsed.path))
        )
    except ValueError:
        return False


def validate_alert_configuration() -> None:
    """Fail startup when an enabled destination lacks valid configuration."""
    if not ENABLED:
        return
    if DISCORD_WEBHOOK_URL and not _valid_discord_webhook(DISCORD_WEBHOOK_URL):
        raise RuntimeError("Invalid security alert Discord webhook configuration.")
    if EMAIL_TO:
        from .email_util import email_sending_configured

        if not email_sending_configured() or not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", EMAIL_TO):
            raise RuntimeError("Security alert email delivery is not configured.")
    if not (DISCORD_WEBHOOK_URL or EMAIL_TO):
        raise RuntimeError("Security alerts are enabled without a delivery destination.")


def _deliver(alert: Alert) -> None:
    # Values come solely from the fixed rules and bounded counters.
    if alert.code not in DEFAULT_RULES:
        raise ValueError("Unknown alert code.")
    message = (
        f"SafeScan security alert: {alert.code}\n"
        f"Observed events: {alert.count} in {alert.window_seconds} seconds.\n"
        "Review the private audit log and service health."
    )
    failures = []
    if DISCORD_WEBHOOK_URL:
        try:
            response = requests.post(
                DISCORD_WEBHOOK_URL, json={"content": message},
                timeout=(2, 5), allow_redirects=False,
            )
            if response.status_code not in (200, 204):
                raise RuntimeError("Discord alert delivery returned an error.")
        except Exception as exc:
            failures.append(type(exc).__name__)
    if EMAIL_TO:
        from .email_util import send_email

        if not send_email(EMAIL_TO, f"SafeScan security alert: {alert.code}", message, message):
            failures.append("EmailDeliveryError")
    if failures:
        raise RuntimeError("Security alert destination failed: " + ",".join(failures))


def _deliver_with_retries(alert: Alert, *, sleep=time.sleep) -> bool:
    """Retry transient sink failures off the request path, with a fixed bound."""
    error_type = "DeliveryError"
    for delay in (0.0, *DELIVERY_RETRY_DELAYS):
        if delay:
            sleep(delay)
        try:
            _deliver(alert)
            return True
        except Exception as exc:
            error_type = type(exc).__name__
    LOG.warning("Security alert delivery failed after retries: %s", error_type)
    return False


def _worker() -> None:
    while True:
        alert = _QUEUE.get()
        try:
            if not _deliver_with_retries(alert):
                MONITOR.delivery_failed(alert.code)
        finally:
            _QUEUE.task_done()


def _enqueue(alert: Alert) -> None:
    global _WORKER_STARTED
    with _WORKER_LOCK:
        if not _WORKER_STARTED:
            threading.Thread(target=_worker, name="safescan-security-alerts", daemon=True).start()
            _WORKER_STARTED = True
    _QUEUE.put_nowait(alert)


MONITOR = SecurityAlertMonitor(enabled=ENABLED)


def record_security_event(code: str) -> Alert | None:
    return MONITOR.record(code)


def record_audit_event(action: str, path: str = "") -> Alert | None:
    if action == "auth.permission_denied":
        if not path.startswith("/admin"):
            return None
        return record_security_event("auth.permission_denied.admin")
    return record_security_event(action)
