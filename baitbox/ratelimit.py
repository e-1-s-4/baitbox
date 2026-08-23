"""IP-level rate limiting and block-list for BaitBox honeypot."""

from __future__ import annotations

import threading
import time
from typing import Any

from .config import settings

_LOCK = threading.RLock()
# ip -> list of timestamps of recent connections
_CONN_LOG: dict[str, list[float]] = {}
# Manually blocked IPs (from dashboard action; optionally persisted to the DB)
_BLOCKED: set[str] = set()

# Thresholds (overridable via environment variables)
RATE_WINDOW_SECS = 60
RATE_LIMIT_SSH = settings.rate_limit_ssh
RATE_LIMIT_HTTP = settings.rate_limit_http
RATE_LIMIT_TELNET = settings.rate_limit_telnet

_records_since_prune = 0


def _limit_for(protocol: str) -> int:
    """Return the per-window connection limit for a protocol."""
    if protocol == "SSH":
        return settings.rate_limit_ssh
    if protocol == "Telnet":
        return settings.rate_limit_telnet
    return settings.rate_limit_http


def record_connection(ip: str, protocol: str = "SSH") -> None:
    """Record a connection from an IP for rate-limit tracking."""
    global _records_since_prune
    with _LOCK:
        now = time.time()
        log = _CONN_LOG.setdefault(ip, [])
        log.append(now)
        # Trim old entries
        cutoff = now - RATE_WINDOW_SECS
        _CONN_LOG[ip] = [t for t in log if t >= cutoff]
        _records_since_prune += 1
        if _records_since_prune >= 1000:
            _records_since_prune = 0
            prune_connection_log()


def prune_connection_log(max_ips: int = 5000, idle_secs: float = 600.0) -> int:
    """Remove tracking entries for IPs that stopped connecting recently."""
    now = time.time()
    with _LOCK:
        stale = [
            ip for ip, timestamps in _CONN_LOG.items()
            if not timestamps or (now - timestamps[-1]) > idle_secs
        ]
        for ip in stale:
            del _CONN_LOG[ip]
        return len(stale)


def is_blocked(ip: str) -> bool:
    """Return True if the IP is manually blocked."""
    with _LOCK:
        return ip in _BLOCKED


def is_rate_limited(ip: str, protocol: str = "SSH") -> bool:
    """Return True if the IP has exceeded connection rate limits."""
    with _LOCK:
        now = time.time()
        cutoff = now - RATE_WINDOW_SECS
        log = [t for t in _CONN_LOG.get(ip, []) if t >= cutoff]
        return len(log) > _limit_for(protocol)


def load_blocked_ips(ips: list[str]) -> None:
    """Seed the in-memory block list (e.g. from persistent storage)."""
    with _LOCK:
        _BLOCKED.update(ips)


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
