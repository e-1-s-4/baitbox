"""v2.3.0 session management tests: memory caps and transcripts."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from baitbox.sessions import SSHSession, SessionManager, session_manager


def make_session(session_id="s1", username="root"):
    return SSHSession(
        session_id=session_id,
        src_ip="203.0.113.1",
        src_port=44444,
        username=username,
        channel=MagicMock(),
        transport=MagicMock(),
    )


def test_command_history_is_bounded():
    from baitbox.config import settings

    s = make_session()
    cap = settings.max_session_commands
    for i in range(cap + 120):
        s.add_command(f"cmd-{i}")
    assert len(s.commands) == cap
    # Newest entries retained, oldest dropped
    assert s.commands[-1]["command"] == f"cmd-{cap + 119}"
    assert s.commands[0]["command"] == f"cmd-120"


def test_transcript_contains_commands_and_exit_codes():
    s = make_session()
    s.add_command("whoami", exit_code=0)
    s.add_command("cat /etc/shadow", exit_code=1)
    t = s.transcript()
    assert t["session_id"] == "s1"
    assert t["src_ip"] == "203.0.113.1"
    assert t["command_count"] == 2
    assert t["commands"][0]["exit_code"] == 0
    assert t["commands"][1]["exit_code"] == 1
    assert t["commands"][1]["index"] == 1


def test_session_manager_enforces_cap():
    mgr = SessionManager()
    # Artificially fill to the cap
    original = mgr.sessions
    try:
        from baitbox.config import settings
        cap = settings.max_sessions
        for i in range(cap):
            s = make_session(f"id-{i}")
            # id-0 is the stalest (oldest last_seen)
            s.last_seen = time.time() - (cap - i)
            mgr.sessions[s.session_id] = s
        assert len(mgr.sessions) == cap
        # Registering one more evicts the stalest
        fresh = make_session("fresh")
        mgr.register(fresh)
        assert len(mgr.sessions) == cap
        assert "id-0" not in mgr.sessions
        assert "fresh" in mgr.sessions
    finally:
        mgr.sessions = original


def test_count_for_ip():
    mgr = SessionManager()
    original = mgr.sessions
    try:
        mgr.sessions = {}
        a = make_session("a")
        b = make_session("b")
        c = make_session("c")
        b.src_ip = "198.51.100.7"
        for s in (a, b, c):
            mgr.sessions[s.session_id] = s
        assert mgr.count_for_ip("203.0.113.1") == 2
        assert mgr.count_for_ip("198.51.100.7") == 1
        assert mgr.count_for_ip("10.0.0.1") == 0
    finally:
        mgr.sessions = original


def test_list_sessions_reports_command_count():
    s = make_session("list-1")
    s.add_command("ls")
    s.add_command("pwd")
    session_manager.register(s)
    try:
        listed = session_manager.list_sessions()
        entry = next(x for x in listed if x["session_id"] == "list-1")
        assert entry["command_count"] == 2
        assert entry["protocol"] == "SSH"
    finally:
        session_manager.unregister("list-1")
