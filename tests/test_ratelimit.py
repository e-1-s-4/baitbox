"""Tests for the rate limiter module."""

from __future__ import annotations
import time
import pytest
from baitbox import ratelimit


@pytest.fixture(autouse=True)
def reset_state():
    """Clear rate-limit state between tests."""
    ratelimit._CONN_LOG.clear()
    ratelimit._BLOCKED.clear()
    yield
    ratelimit._CONN_LOG.clear()
    ratelimit._BLOCKED.clear()


def test_block_and_is_blocked():
    ratelimit.block_ip("1.2.3.4")
    assert ratelimit.is_blocked("1.2.3.4")


def test_unblock():
    ratelimit.block_ip("1.2.3.4")
    ratelimit.unblock_ip("1.2.3.4")
    assert not ratelimit.is_blocked("1.2.3.4")


def test_unblock_nonexistent_is_safe():
    ratelimit.unblock_ip("9.9.9.9")  # should not raise


def test_get_blocked_ips():
    ratelimit.block_ip("10.0.0.1")
    ratelimit.block_ip("10.0.0.2")
    blocked = ratelimit.get_blocked_ips()
    assert "10.0.0.1" in blocked
    assert "10.0.0.2" in blocked


def test_record_and_count():
    for _ in range(5):
        ratelimit.record_connection("5.5.5.5", "SSH")
    counts = ratelimit.get_connection_counts()
    entry = next((c for c in counts if c["ip"] == "5.5.5.5"), None)
    assert entry is not None
    assert entry["count"] == 5


def test_not_rate_limited_normally():
    ratelimit.record_connection("6.6.6.6", "SSH")
    assert not ratelimit.is_rate_limited("6.6.6.6", "SSH")


def test_rate_limited_when_over_threshold():
    ip = "7.7.7.7"
    # Inject timestamps directly to simulate many connections
    now = time.time()
    ratelimit._CONN_LOG[ip] = [now] * (ratelimit.RATE_LIMIT_SSH + 1)
    assert ratelimit.is_rate_limited(ip, "SSH")


def test_rate_limit_http_threshold():
    ip = "8.8.8.8"
    now = time.time()
    ratelimit._CONN_LOG[ip] = [now] * (ratelimit.RATE_LIMIT_HTTP + 1)
    assert ratelimit.is_rate_limited(ip, "HTTP")


def test_old_connections_pruned():
    ip = "9.9.9.1"
    old_time = time.time() - ratelimit.RATE_WINDOW_SECS - 10
    ratelimit._CONN_LOG[ip] = [old_time] * 50
    # A new connection should prune the old ones
    ratelimit.record_connection(ip, "SSH")
    assert not ratelimit.is_rate_limited(ip, "SSH")


def test_blocked_flag_in_counts():
    ratelimit.block_ip("11.22.33.44")
    ratelimit.record_connection("11.22.33.44", "SSH")
    counts = ratelimit.get_connection_counts()
    entry = next((c for c in counts if c["ip"] == "11.22.33.44"), None)
    assert entry is not None
    assert entry["blocked"] is True
