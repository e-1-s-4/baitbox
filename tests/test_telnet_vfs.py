"""Tests for Telnet IAC parsing, the shared VFS shell, and session tracking."""

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


# ── IAC parsing ─────────────────────────────────────────────────────────────

def test_strip_removes_will_wont_do_dont():
    raw = b"root\xff\xfb\x01\xff\xfd\x01\r\n"
    assert _strip_telnet_options(raw) == b"root\r\n"


def test_strip_preserves_literal_0xff_via_iac_iac():
    assert _strip_telnet_options(b"a\xff\xffb") == b"a\xffb"


def test_strip_handles_two_byte_commands():
    # IAC NOP (241), IAC GO AHEAD (249)
    assert _strip_telnet_options(b"ls\xff\xf1ps\xff\xf9aux") == b"lspsaux"


def test_strip_handles_subnegotiation():
    # IAC SB ... payload ... IAC SE
    raw = b"user\xff\xfa\x18\x00TERM\xff\xf0\r\n"
    assert _strip_telnet_options(raw) == b"user\r\n"


def test_strip_incomplete_trailing_sequence_spans_chunks():
    # The incomplete WILL sequence is dropped from a lone chunk...
    assert _strip_telnet_options(b"root\xff\xfb") == b"root"
    # ...and _split_telnet_stream reassembles when given the whole stream
    from baitbox.servers.telnet_server import _split_telnet_stream

    clean, pending = _split_telnet_stream(b"who\xff\xfb")
    assert clean == b"who"
    assert pending == b"\xff\xfb"
    clean2, pending2 = _split_telnet_stream(pending + b"\x00mi\r\n")
    assert clean2 == b"mi\r\n"
    assert pending2 == b""


async def _drive_shell_flow(monkeypatch) -> tuple[bytes, TelnetHoneypot]:
    events: list[dict] = []
    _patch_common(monkeypatch, events)
    from baitbox.sessions import session_manager
    before = set(session_manager.sessions.keys())

    honeypot = TelnetHoneypot()
    transport = FakeTransport()
    honeypot.connection_made(transport)

    honeypot.data_received(b"root\r\n")
    await asyncio.sleep(0)

    honeypot.data_received(b"secret123\r\n")
    await asyncio.sleep(0)
    assert honeypot.state == "shell"

    # Full fake shell: whoami works against the shared engine
    honeypot.data_received(b"whoami\r\n")
    await asyncio.sleep(0)
    assert events[-1]["event_type"] == "command"

    # Pipelines work too
    honeypot.data_received(b"cat /etc/passwd | grep ubuntu | wc -l\r\n")
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    # Sessions are tracked for the dashboard
    tracked = {k for k in session_manager.sessions.keys()}
    assert honeypot.session_id in tracked - before

    # exit closes connection and unregisters
    honeypot.data_received(b"exit\r\n")
    await asyncio.sleep(0)
    return b"".join(transport.written), honeypot


def test_telnet_shell_runs_real_vfs_commands(monkeypatch):
    written, honeypot = asyncio.run(_drive_shell_flow(monkeypatch))
    from baitbox.sessions import session_manager

    assert b"Password:" in written
    assert b"root@" in written  # prompt rendered
    # pipeline result (1 matching line) appears before final prompt
    assert b"1" in written.split(b"whoami")[-1][:80]
    assert honeypot.transport.closed is True
    assert honeypot.session_id not in session_manager.sessions


def test_strip_plain_data_untouched():
    data = b"cat /etc/passwd\r\n"
    assert _strip_telnet_options(data) == data


# ── Shared VFS shell over Telnet ────────────────────────────────────────────

def _patch_common(monkeypatch, events: list[dict]) -> None:
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


def test_telnet_connection_lost_unregisters_session(monkeypatch):
    events: list[dict] = []
    _patch_common(monkeypatch, events)
    from baitbox.sessions import session_manager

    honeypot = TelnetHoneypot()
    honeypot.transport = FakeTransport()
    honeypot._enter_shell()
    assert honeypot.session_id in session_manager.sessions
    honeypot.connection_lost(None)
    assert honeypot.session_id not in session_manager.sessions


def test_telnet_prompt_reflects_cwd_changes(monkeypatch):
    events: list[dict] = []
    _patch_common(monkeypatch, events)
    honeypot = TelnetHoneypot()
    honeypot.username = "root"
    honeypot._enter_shell()
    honeypot.run_command("cd /var/log")
    prompt = honeypot.prompt().decode()
    assert "/var/log" in prompt
