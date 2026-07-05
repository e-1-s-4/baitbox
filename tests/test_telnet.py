"""Tests for the Telnet honeypot protocol handler."""

from __future__ import annotations

import asyncio

from baitbox.servers.telnet_server import TelnetHoneypot, _strip_telnet_options


class FakeTransport:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False
        self._peername = ("203.0.113.50", 44123)

    def write(self, data: bytes) -> None:
        self.written.append(data)

    def close(self) -> None:
        self.closed = True

    def get_extra_info(self, key: str):
        if key == "peername":
            return self._peername
        return None


def test_strip_telnet_options_removes_iac_sequences():
    raw = b"root\xff\xfb\x01\xff\xfd\x01\r\n"
    assert _strip_telnet_options(raw) == b"root\r\n"


def test_telnet_fake_response_known_commands():
    honeypot = TelnetHoneypot()
    assert honeypot._fake_response("whoami") == b"root"
    assert b"uid=0" in honeypot._fake_response("id")
    assert b"command not found" in honeypot._fake_response("totally-unknown-cmd")


async def _run_login_flow(monkeypatch):
    events: list[dict] = []

    async def fake_log_event(src_ip, protocol, event_type, payload):
        event = {
            "src_ip": src_ip,
            "protocol": protocol,
            "event_type": event_type,
            "payload": payload,
        }
        events.append(event)
        return event

    async def fake_publish(event):
        return None

    monkeypatch.setattr("baitbox.servers.telnet_server.log_event", fake_log_event)
    monkeypatch.setattr("baitbox.servers.telnet_server.pubsub.publish", fake_publish)
    monkeypatch.setattr("baitbox.servers.telnet_server.is_blocked", lambda ip: False)
    monkeypatch.setattr("baitbox.servers.telnet_server.is_rate_limited", lambda ip, proto: False)
    monkeypatch.setattr("baitbox.servers.telnet_server.record_connection", lambda ip, proto: None)

    honeypot = TelnetHoneypot()
    transport = FakeTransport()
    honeypot.connection_made(transport)
    assert any(b"login:" in chunk for chunk in transport.written)

    honeypot.data_received(b"root\r\n")
    await asyncio.sleep(0)
    assert any(b"Password:" in chunk for chunk in transport.written)

    honeypot.data_received(b"secret123\r\n")
    await asyncio.sleep(0)

    assert honeypot.state == "shell"
    assert len(events) == 1
    assert events[0]["event_type"] == "auth_attempt"
    assert events[0]["payload"]["username"] == "root"
    assert events[0]["payload"]["password"] == "secret123"


async def _run_shell_flow(monkeypatch):
    events: list[dict] = []

    async def fake_log_event(src_ip, protocol, event_type, payload):
        event = {
            "src_ip": src_ip,
            "protocol": protocol,
            "event_type": event_type,
            "payload": payload,
        }
        events.append(event)
        return event

    async def fake_publish(event):
        return None

    monkeypatch.setattr("baitbox.servers.telnet_server.log_event", fake_log_event)
    monkeypatch.setattr("baitbox.servers.telnet_server.pubsub.publish", fake_publish)
    monkeypatch.setattr("baitbox.servers.telnet_server.is_blocked", lambda ip: False)
    monkeypatch.setattr("baitbox.servers.telnet_server.is_rate_limited", lambda ip, proto: False)
    monkeypatch.setattr("baitbox.servers.telnet_server.record_connection", lambda ip, proto: None)

    honeypot = TelnetHoneypot()
    transport = FakeTransport()
    honeypot.connection_made(transport)
    honeypot.state = "shell"
    honeypot.username = "root"

    honeypot.data_received(b"whoami\r\n")
    await asyncio.sleep(0)
    assert events[-1]["event_type"] == "command"
    assert events[-1]["payload"]["command"] == "whoami"

    honeypot.data_received(b"exit\r\n")
    await asyncio.sleep(0)
    assert transport.closed is True


def test_telnet_login_flow(monkeypatch):
    asyncio.run(_run_login_flow(monkeypatch))


def test_telnet_shell_command_and_exit(monkeypatch):
    asyncio.run(_run_shell_flow(monkeypatch))
