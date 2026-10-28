"""State management for active SSH/Telnet sessions in BaitBox."""

from __future__ import annotations
import threading
import time
import logging
from collections import deque
from typing import Any, Dict, List

logger = logging.getLogger("baitbox.sessions")


class SSHSession:
    """An interactive honeypot session (SSH or Telnet).

    ``channel``/``transport`` are paramiko objects for SSH sessions; for
    Telnet sessions they are lightweight stubs exposing ``close()``.
    """

    def __init__(
        self,
        session_id: str,
        src_ip: str,
        src_port: int,
        username: str,
        channel: Any = None,
        transport: Any = None,
        protocol: str = "SSH",
    ) -> None:
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.username = username
        self.protocol = protocol
        self.login_time = time.time()
        self.last_seen = time.time()
        self.channel = channel
        self.transport = transport
        self.cwd = "/root"
        self.last_exit_code = 0
        # Bounded command history: attackers scripting loops over hours must
        # not grow memory without bound. Newest entries are always kept.
        from .config import settings
        self.commands: deque[Dict[str, Any]] = deque(maxlen=settings.max_session_commands)

        # Initialize a custom virtual filesystem for this session
        from .vfs import VirtualFilesystem
        self.vfs = VirtualFilesystem()

    def add_command(self, command: str, exit_code: int | None = None) -> None:
        self.last_seen = time.time()
        entry: Dict[str, Any] = {
            "command": command,
            "timestamp": time.time(),
        }
        if exit_code is not None:
            entry["exit_code"] = exit_code
        self.commands.append(entry)

    def command_count(self) -> int:
        """Total commands executed this session (may exceed the stored window)."""
        return getattr(self, "_total_commands", len(self.commands))

    def close(self) -> None:
        for obj in (self.channel, self.transport):
            if obj is None:
                continue
            try:
                obj.close()
            except Exception:
                pass

    def is_stale(self, timeout_seconds: int = 3600) -> bool:
        """Check if session is stale (no activity for timeout_seconds)."""
        return (time.time() - self.last_seen) > timeout_seconds

    def transcript(self) -> Dict[str, Any]:
        """Return a structured transcript of the full stored session history."""
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "username": self.username,
            "protocol": self.protocol,
            "login_time": self.login_time,
            "duration_seconds": round(time.time() - self.login_time, 2),
            "command_count": len(self.commands),
            "commands": [
                {
                    "index": i,
                    "command": c.get("command", ""),
                    "timestamp": c.get("timestamp"),
                    "exit_code": c.get("exit_code"),
                }
                for i, c in enumerate(self.commands)
            ],
        }


class SessionManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, SSHSession] = {}
        self._lock = threading.RLock()
        self._cleanup_task: threading.Thread | None = None

    def register(self, session: SSHSession) -> None:
        with self._lock:
            # Enforce a global concurrent-session cap: floods of short-lived
            # connections must not exhaust memory. Evict the stalest session.
            max_sessions = 1000
            try:
                from .config import settings
                max_sessions = settings.max_sessions
            except Exception:
                pass
            while len(self.sessions) >= max_sessions:
                oldest_id = min(
                    self.sessions,
                    key=lambda sid: self.sessions[sid].last_seen,
                    default=None,
                )
                if oldest_id is None:
                    break
                victim = self.sessions.pop(oldest_id, None)
                if victim:
                    victim.close()
                    logger.warning(
                        "Session cap (%s) reached — evicted stalest session %s from %s",
                        max_sessions, oldest_id, victim.src_ip,
                    )
            self.sessions[session.session_id] = session
            logger.debug(f"Registered session {session.session_id} from {session.src_ip}")

    def unregister(self, session_id: str) -> None:
        with self._lock:
            session = self.sessions.pop(session_id, None)
            if session:
                logger.debug(f"Unregistered session {session_id} from {session.src_ip}")

    def get_session(self, session_id: str) -> SSHSession | None:
        with self._lock:
            return self.sessions.get(session_id)

    def count_for_ip(self, src_ip: str) -> int:
        """Return the number of active sessions originating from an IP."""
        with self._lock:
            return sum(1 for s in self.sessions.values() if s.src_ip == src_ip)

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            sessions = list(self.sessions.values())
        res = []
        for s in sessions:
            res.append({
                "session_id": s.session_id,
                "src_ip": s.src_ip,
                "src_port": s.src_port,
                "username": s.username,
                "protocol": s.protocol,
                "login_time": s.login_time,
                "last_seen": s.last_seen,
                "duration_seconds": round(time.time() - s.login_time, 2),
                "idle_seconds": round(time.time() - s.last_seen, 2),
                "cwd": s.cwd,
                "command_count": len(s.commands),
                "commands": list(s.commands)[-10:]  # last 10 commands
            })
        return res

    def cleanup_stale_sessions(self, timeout_seconds: int = 3600) -> int:
        """Remove stale sessions and return count of cleaned sessions."""
        with self._lock:
            stale_sessions = [
                session_id for session_id, session in self.sessions.items()
                if session.is_stale(timeout_seconds)
            ]
            for session_id in stale_sessions:
                session = self.sessions.pop(session_id, None)
                if session:
                    session.close()
                    logger.info(f"Cleaned up stale session {session_id} from {session.src_ip}")
            return len(stale_sessions)

    def start_cleanup_task(self, interval_seconds: int = 300) -> None:
        """Start background task to periodically clean up stale sessions."""
        if self._cleanup_task is not None:
            return

        def cleanup_loop():
            while True:
                try:
                    time.sleep(interval_seconds)
                    count = self.cleanup_stale_sessions(timeout_seconds=3600)
                    if count > 0:
                        logger.info(f"Session cleanup: removed {count} stale sessions")
                except Exception as e:
                    logger.error(f"Session cleanup error: {e}")

        self._cleanup_task = threading.Thread(target=cleanup_loop, daemon=True)
        self._cleanup_task.start()
        logger.info(f"Started session cleanup task (interval: {interval_seconds}s)")


session_manager = SessionManager()
