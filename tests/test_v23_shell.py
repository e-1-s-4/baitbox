"""v2.3.0 shell tests: new commands, exit-code tracking, history control."""

from __future__ import annotations

from unittest.mock import MagicMock

from baitbox.sessions import SSHSession
from baitbox.servers.ssh_server import execute_session_command


def make_session(username: str = "root") -> SSHSession:
    return SSHSession(
        session_id="v23-shell",
        src_ip="203.0.113.9",
        src_port=55555,
        username=username,
        channel=MagicMock(),
        transport=MagicMock(),
    )


# ── Exit-code tracking ($? expansion) ──────────────────────────────────────

def test_exit_code_zero_on_success():
    s = make_session()
    execute_session_command(s, "whoami")
    assert s.last_exit_code == 0
    out, _ = execute_session_command(s, "echo done=$?")
    assert b"done=0" in out


def test_exit_code_127_on_unknown_command():
    s = make_session()
    execute_session_command(s, "definitely-not-a-real-cmd")
    assert s.last_exit_code == 127
    out, _ = execute_session_command(s, "echo code=$?")
    assert b"code=127" in out


def test_exit_code_nonzero_on_missing_file():
    s = make_session()
    execute_session_command(s, "cat /no/such/file")
    assert s.last_exit_code != 0


def test_transcript_rows_carry_exit_codes():
    s = make_session()
    execute_session_command(s, "whoami")
    execute_session_command(s, "no-such-cmd-xyz")
    codes = [c.get("exit_code") for c in s.commands]
    assert codes == [0, 127]


# ── New v2.3.0 commands ────────────────────────────────────────────────────

def test_dig_returns_dns_answer():
    s = make_session()
    out, close = execute_session_command(s, "dig example.com A")
    assert not close
    assert b"ANSWER SECTION" in out
    assert b"example.com" in out
    assert b"IN\tA" in out


def test_nslookup_returns_answer():
    s = make_session()
    out, _ = execute_session_command(s, "nslookup example.com")
    assert b"Non-authoritative answer" in out
    assert b"10.0.0.7" in out


def test_whois_returns_domain_record():
    s = make_session()
    out, _ = execute_session_command(s, "whois example.com")
    assert b"Domain Name: example.com" in out


def test_tree_renders_virtual_filesystem():
    s = make_session()
    out, _ = execute_session_command(s, "tree /etc")
    assert b"etc" in out


def test_tree_missing_path_errors():
    s = make_session()
    out, _ = execute_session_command(s, "tree /definitely/not/here")
    assert b"No such file or directory" in out


def test_dmesg_returns_kernel_log():
    s = make_session()
    out, _ = execute_session_command(s, "dmesg")
    assert b"Linux version" in out


def test_lsusb_and_lspci():
    s = make_session()
    out, _ = execute_session_command(s, "lsusb")
    assert b"root hub" in out
    out, _ = execute_session_command(s, "lspci")
    assert b"Ethernet controller" in out


def test_sha512sum_matches_hashlib():
    import hashlib

    s = make_session()
    content = s.vfs.read_file("/etc/passwd")
    expected = hashlib.sha512(content).hexdigest()
    out, _ = execute_session_command(s, "sha512sum /etc/passwd")
    assert expected.encode() in out


def test_sha224sum_pipeline():
    import hashlib

    s = make_session()
    content = s.vfs.read_file("/etc/passwd")
    expected = hashlib.sha224(content).hexdigest()
    out, _ = execute_session_command(s, "cat /etc/passwd | sha224sum")
    assert expected.encode() in out


def test_history_c_clears_history():
    s = make_session()
    execute_session_command(s, "whoami")
    execute_session_command(s, "ls /etc")
    assert len(s.commands) >= 2
    execute_session_command(s, "history -c")
    assert len(s.commands) == 0


def test_new_commands_tab_complete():
    from baitbox.servers.ssh_server import complete_input

    s = make_session()
    buf, candidates = complete_input(s, "di")
    assert "dig " in candidates
    buf, candidates = complete_input(s, "who")
    assert "whois " in candidates
