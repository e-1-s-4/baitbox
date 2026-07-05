"""Simple Telnet honeypot that captures credential and command data."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..config import settings
from ..db import log_event
from ..pubsub import pubsub
from ..ratelimit import is_blocked, is_rate_limited, record_connection

logger = logging.getLogger("baitbox.telnet")

HOSTNAME = settings.ssh_banner_hostname

# Minimal Telnet negotiation bytes — we strip them from received data
_TELNET_IAC = b"\xff"

_BANNER = (
    f"\r\n"
    f"{HOSTNAME} login: "
).encode()

_MOTD = (
    f"\r\nWelcome to Ubuntu 22.04.4 LTS ({HOSTNAME})\r\n"
    f"Last login: Mon Jun 23 07:12:01 2026 from 10.0.0.1\r\n"
    f"\r\n$ "
).encode()


def _strip_telnet_options(data: bytes) -> bytes:
    """Strip Telnet IAC command sequences from received data."""
    result = bytearray()
    i = 0
    while i < len(data):
        if data[i:i+1] == _TELNET_IAC and i + 2 < len(data):
            i += 3  # Skip IAC CMD OPT
        else:
            result.append(data[i])
            i += 1
    return bytes(result)


async def _publish(event: dict[str, Any]) -> None:
    await pubsub.publish(event)


class TelnetHoneypot(asyncio.Protocol):
    """Asyncio protocol implementing a fake Telnet server."""

    def __init__(self) -> None:
        self.transport: asyncio.Transport | None = None
        self.peer_ip = "unknown"
        self.peer_port = 0
        self.state = "login"  # login | password | shell
        self.username = ""
        self._buf = b""

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
        data = _strip_telnet_options(data)
        self._buf += data
        while b"\r\n" in self._buf or b"\n" in self._buf or b"\r" in self._buf:
            for sep in (b"\r\n", b"\n", b"\r"):
                if sep in self._buf:
                    line, self._buf = self._buf.split(sep, 1)
                    asyncio.create_task(self._handle_line(line.decode("utf-8", errors="replace").strip()))
                    break

    async def _handle_line(self, line: str) -> None:
        assert self.transport is not None

        if self.state == "login":
            self.username = line
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
            self.transport.write(_MOTD)
            self.state = "shell"

        elif self.state == "shell":
            command = line.strip()
            
            # Validate command length
            if len(command) > settings.max_command_length:
                self.transport.write(b"sh: command line too long\r\n$ ")
                return
            
            if command:
                event = await log_event(
                    self.peer_ip,
                    "Telnet",
                    "command",
                    {"command": command, "username": self.username},
                )
                await _publish(event)

                if command in {"exit", "logout", "quit"}:
                    self.transport.write(b"\r\nlogout\r\n")
                    self.transport.close()
                    return

                # Simple static responses for common commands
                response = self._fake_response(command)
                self.transport.write(response + b"\r\n$ ")

    def _fake_response(self, command: str) -> bytes:
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

    def connection_lost(self, exc: Exception | None) -> None:
        pass


async def start_telnet_server(host: str = "0.0.0.0", port: int = 2323) -> None:
    loop = asyncio.get_running_loop()
    server = await loop.create_server(TelnetHoneypot, host, port)
    print(f"[Telnet Honeypot] Listening on {host}:{port}")
    async with server:
        await server.serve_forever()
