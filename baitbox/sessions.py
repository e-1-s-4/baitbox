"""State management for active SSH sessions in BaitBox."""

from __future__ import annotations
import threading
import time
import logging
from typing import Any, Dict, List
import paramiko

logger = logging.getLogger("baitbox.sessions")

class SSHSession:
    def __init__(
        self,
        session_id: str,
        src_ip: str,
        src_port: int,
        username: str,
        channel: paramiko.Channel,
        transport: paramiko.Transport,
    ) -> None:
        self.session_id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.username = username
        self.login_time = time.time()
        self.last_seen = time.time()
        self.channel = channel
        self.transport = transport
        self.cwd = "/root"
        self.commands: List[Dict[str, Any]] = []
        
        # Initialize a custom virtual filesystem for this session
        from .vfs import VirtualFilesystem
        self.vfs = VirtualFilesystem()

    def add_command(self, command: str) -> None:
        self.last_seen = time.time()
        self.commands.append({
            "command": command,
            "timestamp": time.time(),
        })

    def close(self) -> None:
        try:
            self.channel.close()
        except Exception:
            pass
        try:
            self.transport.close()
        except Exception:
            pass

    def is_stale(self, timeout_seconds: int = 3600) -> bool:
        """Check if session is stale (no activity for timeout_seconds)."""
        return (time.time() - self.last_seen) > timeout_seconds


class SessionManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, SSHSession] = {}
        self._lock = threading.RLock()
        self._cleanup_task: threading.Thread | None = None

    def register(self, session: SSHSession) -> None:
        with self._lock:
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
                "login_time": s.login_time,
                "last_seen": s.last_seen,
                "duration_seconds": round(time.time() - s.login_time, 2),
                "idle_seconds": round(time.time() - s.last_seen, 2),
                "cwd": s.cwd,
                "commands": s.commands[-10:]  # last 10 commands
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
