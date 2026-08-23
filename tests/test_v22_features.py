"""Tests for v2.2 features: webhook filtering, login rate limiting, retention, pruning."""

from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from baitbox.webhooks import _send_webhook_sync, send_webhook_notification


# ── Webhook threat-level filtering ──────────────────────────────────────────

def _settings(**kwargs):
    defaults = {
        "webhook_url": "https://discord.example/hook",
        "webhook_type": "discord",
        "webhook_min_threat_level": "LOW",
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class WebhookFilterTests(unittest.TestCase):
    def setUp(self):
        self.captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"ok"

        def fake_urlopen(req, timeout=5):
            self.captured["body"] = json.loads(req.data.decode())
            return FakeResponse()

        self._patcher = patch("baitbox.webhooks.urllib.request.urlopen", fake_urlopen)
        self._patcher.start()

    def tearDown(self):
        self._patcher.stop()

    def test_min_threat_medium_blocks_low_events(self):
        with patch("baitbox.webhooks.settings", _settings(webhook_min_threat_level="MEDIUM")):
            send_webhook_notification({
                "src_ip": "1.2.3.4", "protocol": "SSH",
                "event_type": "request", "threat_level": "LOW", "payload": {},
            })
        self.assertNotIn("body", self.captured)

    def test_min_threat_medium_allows_critical_events(self):
        with patch("baitbox.webhooks.settings", _settings(webhook_min_threat_level="MEDIUM")):
            send_webhook_notification({
                "src_ip": "1.2.3.4", "protocol": "SSH",
                "event_type": "command", "threat_level": "CRITICAL",
                "payload": {"command": "wget http://x"},
            })
        self.assertIn("body", self.captured)

    def test_discord_description_is_truncated(self):
        huge_command = "A" * 10000
        with patch("baitbox.webhooks.settings", _settings()):
            _send_webhook_sync({
                "src_ip": "1.2.3.4", "protocol": "SSH", "event_type": "command",
                "threat_level": "HIGH", "payload": {"command": huge_command},
            })
        description = self.captured["body"]["embeds"][0]["description"]
        self.assertLessEqual(len(description), 3900)
        self.assertTrue(description.endswith("[truncated by BaitBox]"))

    def test_slack_text_is_truncated(self):
        with patch("baitbox.webhooks.settings", _settings(webhook_type="slack")):
            _send_webhook_sync({
                "src_ip": "1.2.3.4", "protocol": "SSH", "event_type": "command",
                "threat_level": "LOW", "payload": {"command": "B" * 9000},
            })
        self.assertLessEqual(len(self.captured["body"]["text"]), 3500)


# ── Dashboard login brute-force protection ──────────────────────────────────

class LoginRateLimitTests(unittest.TestCase):
    def setUp(self):
        from baitbox.servers.http_server import (
            _clear_login_failures,
            _login_failures,
            _record_login_failure,
            login_is_rate_limited,
        )
        self._failures = _login_failures
        self._record = _record_login_failure
        self._clear = _clear_login_failures
        self._limited = login_is_rate_limited
        self._failures.clear()

    def tearDown(self):
        self._failures.clear()

    def test_below_limit_not_limited(self):
        for _ in range(9):
            self._record("203.0.113.1")
        self.assertFalse(self._limited("203.0.113.1"))

    def test_at_limit_blocked(self):
        for _ in range(10):
            self._record("203.0.113.2")
        self.assertTrue(self._limited("203.0.113.2"))

    def test_other_ips_unaffected(self):
        for _ in range(12):
            self._record("203.0.113.3")
        self.assertFalse(self._limited("198.51.100.1"))

    def test_clear_resets_counter(self):
        for _ in range(10):
            self._record("203.0.113.4")
        self._clear("203.0.113.4")
        self.assertFalse(self._limited("203.0.113.4"))

    def test_old_failures_expire_from_window(self):
        ip = "203.0.113.5"
        stale = time.time() - 3600
        self._failures[ip] = [stale] * 20
        self.assertFalse(self._limited(ip))


# ── Anomaly + ratelimit pruning (memory-leak regression) ────────────────────

class PruningTests(unittest.TestCase):
    def test_anomaly_prune_drops_idle_ips(self):
        from baitbox.anomaly import _ip_metrics, _last_activity, prune_metrics

        _ip_metrics.clear()
        _last_activity.clear()
        now = time.time()
        for i in range(50):
            ip = f"10.1.0.{i}"
            _ip_metrics[ip]
            _last_activity[ip] = now - 7200 if i < 40 else now
        removed = prune_metrics(max_ips=20)
        self.assertGreater(removed, 0)
        self.assertLessEqual(len(_ip_metrics), 25)
        # Recent entries survive
        self.assertIn("10.1.0.45", _ip_metrics)

    def test_ratelimit_prune_drops_idle_ips(self):
        from baitbox import ratelimit

        ratelimit._CONN_LOG.clear()
        old = time.time() - 1200
        for i in range(30):
            ratelimit._CONN_LOG[f"10.2.0.{i}"] = [old] if i < 20 else [time.time()]
        removed = ratelimit.prune_connection_log()
        self.assertEqual(removed, 20)
        self.assertNotIn("10.2.0.1", ratelimit._CONN_LOG)
        self.assertIn("10.2.0.25", ratelimit._CONN_LOG)
        ratelimit._CONN_LOG.clear()


if __name__ == "__main__":
    unittest.main()
