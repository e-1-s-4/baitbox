"""IP-level rate limiting and block-list for BaitBox honeypot."""

from __future__ import annotations

import threading
import time
from typing import Any

from .config import settings

_LOCK = threading.RLock()
# ip -> list of timestamps of recent connections
_CONN_LOG: dict[str, list[float]] = {}
# Manually blocked IPs (from dashboard action)
_BLOCKED: set[str] = set()

# Thresholds (overridable via environment variables)
RATE_WINDOW_SECS = 60
RATE_LIMIT_SSH = settings.rate_limit_ssh
RATE_LIMIT_HTTP = settings.rate_limit_http
RATE_LIMIT_TELNET = settings.rate_limit_telnet


def _limit_for(protocol: str) -> int:
    """Return the per-window connection limit for a protocol."""
    if protocol == "SSH":
        return settings.rate_limit_ssh
    if protocol == "Telnet":
        return settings.rate_limit_telnet
    return settings.rate_limit_http


def record_connection(ip: str, protocol: str = "SSH") -> None:
    """Record a connection from an IP for rate-limit tracking."""
    with _LOCK:
        now = time.time()
        log = _CONN_LOG.setdefault(ip, [])
        log.append(now)
        # Trim old entries
        cutoff = now - RATE_WINDOW_SECS
        _CONN_LOG[ip] = [t for t in log if t >= cutoff]


def is_blocked(ip: str) -> bool:
    """Return True if the IP is manually blocked."""
    return ip in _BLOCKED


def is_rate_limited(ip: str, protocol: str = "SSH") -> bool:
    """Return True if the IP has exceeded connection rate limits."""
    with _LOCK:
        now = time.time()
        cutoff = now - RATE_WINDOW_SECS
        log = [t for t in _CONN_LOG.get(ip, []) if t >= cutoff]
        return len(log) > _limit_for(protocol)


def block_ip(ip: str) -> None:
    with _LOCK:
        _BLOCKED.add(ip)


def unblock_ip(ip: str) -> None:
    with _LOCK:
        _BLOCKED.discard(ip)


def get_blocked_ips() -> list[str]:
    with _LOCK:
        return sorted(_BLOCKED)


def get_connection_counts(window_secs: int = RATE_WINDOW_SECS) -> list[dict[str, Any]]:
    """Return per-IP connection counts in the last window_secs seconds."""
    with _LOCK:
        now = time.time()
        cutoff = now - window_secs
        result = []
        for ip, timestamps in _CONN_LOG.items():
            count = sum(1 for t in timestamps if t >= cutoff)
            if count > 0:
                result.append({"ip": ip, "count": count, "blocked": ip in _BLOCKED})
        return sorted(result, key=lambda x: -x["count"])
