"""Telnet honeypot with a stateful fake shell.

Attackers that connect are greeted by a login prompt, their credentials
are captured, and they are dropped into the same virtual filesystem shell
used by the SSH honeypot.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from ..config import settings
from ..db import log_event
from ..pubsub import pubsub
from ..ratelimit import is_blocked, is_rate_limited, record_connection
from ..sessions import SSHSession, session_manager

logger = logging.getLogger("baitbox.telnet")

HOSTNAME = settings.ssh_banner_hostname

# Telnet protocol constants (RFC 854)
_IAC = 0xFF
_DONT = 0xFE
_DO = 0xFD
_WONT = 0xFC
_WILL = 0xFB
_SB = 0xFA
_SE = 0xF0

_BANNER = (
    f"\r\n"
    f"{HOSTNAME} login: "
).encode()

_MOTD_TEMPLATE = (
    "\r\nWelcome to Ubuntu 22.04.4 LTS ({hostname})\r\n"
    "\r\n * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    "\r\nLast login: Mon Jun 23 07:12:01 2026 from 10.0.0.1\r\n"
)


def _split_telnet_stream(data: bytes) -> tuple[bytes, bytes]:
    """Strip complete Telnet IAC sequences, returning ``(clean, pending_tail)``.

    ``pending_tail`` holds an incomplete trailing sequence so it can be
    prepended to the next received chunk.
    """
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        byte = data[i]
        if byte != _IAC:
            out.append(byte)
            i += 1
            continue
        # IAC at end of chunk — wait for the rest of the sequence
        if i + 1 >= n:
            return bytes(out), data[i:]
        cmd = data[i + 1]
        if cmd == _IAC:  # escaped literal 0xFF
            out.append(_IAC)
            i += 2
            continue
        if cmd in (_WILL, _WONT, _DO, _DONT):
            if i + 2 >= n:
                return bytes(out), data[i:]  # option byte arrives later
            i += 3
            continue
        if cmd == _SB:
            # Skip until IAC SE (or end of chunk)
            j = i + 2
            while j < n:
                if data[j] == _IAC and j + 1 < n and data[j + 1] == _SE:
                    j += 2
                    break
                if data[j] == _IAC and j + 1 >= n:
                    return bytes(out), data[i:]
                j += 1
            else:
                return bytes(out), data[i:]
            i = j
            continue
        # All remaining commands are two bytes
        if i + 2 > n:
            return bytes(out), data[i:]
        i += 2
    return bytes(out), b""


def _strip_telnet_options(data: bytes) -> bytes:
    """Strip Telnet IAC command sequences from received data.

    Handles two-byte commands, WILL/WONT/DO/DONT option negotiation,
    ``IAC IAC`` escapes, and ``SB ... SE`` subnegotiations. Incomplete
    trailing sequences are preserved for the next chunk.
    """
    clean, _tail = _split_telnet_stream(data)
    return clean


async def _publish(event: dict[str, Any]) -> None:
    await pubsub.publish(event)


class _TransportStub:
    """Lightweight close() target so telnet sessions fit SessionManager."""

    def __init__(self, protocol: "TelnetHoneypot") -> None:
        self._protocol = protocol

    def close(self) -> None:
        try:
            if self._protocol.transport is not None:
                self._protocol.transport.close()
        except Exception:
            pass


class TelnetHoneypot(asyncio.Protocol):
    """Asyncio protocol implementing a fake Telnet server with a VFS shell."""

    def __init__(self) -> None:
        self.transport: asyncio.Transport | None = None
        self.peer_ip = "unknown"
        self.peer_port = 0
        self.state = "login"  # login | password | shell
        self.username = ""
        self.session_id = ""
        self._buf = b""
        self._pending_iac = b""
        self.session: SSHSession | None = None

    # ── asyncio.Protocol lifecycle ──────────────────────────────────────────

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        self.transport = transport
        peer = transport.get_extra_info("peername")
        if peer:
            self.peer_ip, self.peer_port = peer[0], peer[1]
        record_connection(self.peer_ip, "Telnet")
        if is_blocked(self.peer_ip) or is_rate_limited(self.peer_ip, "Telnet"):
            transport.close()
            return
        transport.write(_BANNER)

    def data_received(self, data: bytes) -> None:
        stream = self._pending_iac + data
        clean, self._pending_iac = _split_telnet_stream(stream)
        self._buf += clean
        while True:
            for sep in (b"\r\n", b"\n", b"\r"):
                if sep in self._buf:
                    line, self._buf = self._buf.split(sep, 1)
                    asyncio.get_running_loop().create_task(
                        self._handle_line(line.decode("utf-8", errors="replace").strip())
                    )
                    break
            else:
                break

    def connection_lost(self, exc: Exception | None) -> None:
        self._teardown_session()

    # ── State machine ───────────────────────────────────────────────────────

    async def _handle_line(self, line: str) -> None:
        assert self.transport is not None

        if self.state == "login":
            self.username = line[:64] or "root"
            self.transport.write(b"Password: ")
            self.state = "password"

        elif self.state == "password":
            password = line
            event = await log_event(
                self.peer_ip,
                "Telnet",
                "auth_attempt",
                {"username": self.username, "password": password, "method": "telnet"},
            )
            await _publish(event)
            self._enter_shell()
            self.transport.write(_MOTD_TEMPLATE.format(hostname=HOSTNAME).encode())
            self.transport.write(self.prompt())
            self.state = "shell"

        elif self.state == "shell":
            command = line.strip()

            if len(command) > settings.max_command_length:
                self.transport.write(b"bash: command line too long\r\n" + self.prompt())
                return

            if not command:
                self.transport.write(self.prompt())
                return

            event = await log_event(
                self.peer_ip,
                "Telnet",
                "command",
                {"command": command, "username": self.username},
            )
            await _publish(event)

            response, should_close = self.run_command(command)
            self.transport.write(response)
            if should_close or command in {"exit", "logout", "quit"}:
                self.transport.write(b"\r\nlogout\r\n")
                self._teardown_session()
                self.transport.close()
                return
            self.transport.write(self.prompt())

    def _teardown_session(self) -> None:
        """Unregister the tracked session (idempotent)."""
        if self.session_id:
            session_manager.unregister(self.session_id)
            self.session_id = ""

    def _enter_shell(self) -> None:
        """Register this connection as a trackable honeypot session."""
        stub = _TransportStub(self)
        self.session_id = uuid.uuid4().hex
        self.session = SSHSession(
            session_id=self.session_id,
            src_ip=self.peer_ip,
            src_port=self.peer_port,
            username=self.username,
            channel=None,
            transport=stub,
            protocol="Telnet",
        )
        session_manager.register(self.session)

    def run_command(self, command: str) -> tuple[bytes, bool]:
        """Execute a command through the shared fake-shell engine."""
        if self.session is None:
            self._enter_shell()
        assert self.session is not None
        try:
            from .ssh_server import execute_session_command
            return execute_session_command(self.session, command)
        except Exception:
            logger.exception("telnet shell error")
            return b"bash: internal error\r\n", False

    def prompt(self) -> bytes:
        if self.session is None:
            return b"$ "
        cwd = self.session.cwd
        home = "/root" if self.session.username == "root" else f"/home/{self.session.username}"
        if cwd == home:
            cwd = "~"
        char = "#" if self.session.username == "root" else "$"
        return f"{self.session.username}@{HOSTNAME}:{cwd}{char} ".encode()

    def _fake_response(self, command: str) -> bytes:
        """Legacy static responses — kept for compatibility/testing."""
        cmd = command.split()[0] if command.split() else ""
        responses: dict[str, bytes] = {
            "whoami": b"root",
            "id": b"uid=0(root) gid=0(root) groups=0(root)",
            "hostname": HOSTNAME.encode(),
            "uname": b"Linux web-prod-01 5.15.0-94-generic #104-Ubuntu SMP x86_64",
            "ls": b"backups.tar.gz  database.sql  deploy.sh  secrets.txt",
            "pwd": b"/root",
            "ps": b"  PID TTY TIME CMD\r\n 1021 pts/0 00:00:00 sh",
            "cat": b"DB_PASSWORD=REDACTED_BY_BAITBOX\r\nAPI_KEY=sk_live_fake_key_abc123\r\n",
            "wget": b"--2026-06-28 14:01:02--  http://malware.example/payload.sh\r\nConnecting to malware.example... failed: Connection timed out.\r\n",
            "curl": b"curl: (6) Could not resolve host: attacker-c2.example\r\n",
        }
        return responses.get(cmd, f"sh: {cmd}: command not found".encode())


async def start_telnet_server(host: str = "0.0.0.0", port: int = 2323) -> None:
    loop = asyncio.get_running_loop()
    server = await loop.create_server(TelnetHoneypot, host, port)
    logger.info("Telnet honeypot listening on %s:%s", host, port)
    print(f"[Telnet Honeypot] Listening on {host}:{port}")
    async with server:
        await server.serve_forever()
