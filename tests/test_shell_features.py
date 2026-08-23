"""Tests for shell emulation features: pipelines, chaining, expansion, new commands."""

from __future__ import annotations

from unittest.mock import MagicMock

from baitbox.sessions import SSHSession
from baitbox.servers.ssh_server import (
    ShellHistory,
    complete_input,
    execute_session_command,
    output_indicates_failure,
)


def make_session(username: str = "root", cwd: str = "/root") -> SSHSession:
    session = SSHSession(
        session_id="test-shell-1",
        src_ip="203.0.113.77",
        src_port=54321,
        username=username,
        channel=MagicMock(),
        transport=MagicMock(),
    )
    session.cwd = cwd
    return session


# ── Pipelines ──────────────────────────────────────────────────────────────

def test_pipe_cat_grep():
    out, _ = execute_session_command(make_session(), "cat /etc/passwd | grep ubuntu")
    assert b"ubuntu" in out


def test_pipe_ls_wc_counts_lines():
    out, _ = execute_session_command(make_session(), "ls /etc | wc -l")
    # /etc has multiple entries; piped ls must emit one entry per line
    count = int(out.strip())
    assert count > 3


def test_pipe_head_then_wc():
    out, _ = execute_session_command(make_session(), "cat /etc/passwd | head -n 3 | wc -l")
    assert out.strip() == b"3"


def test_pipe_head_numeric_flag():
    out, _ = execute_session_command(make_session(), "cat /etc/passwd | head -3 | wc -l")
    assert out.strip() == b"3"


def test_pipe_tail_n_flag():
    out, _ = execute_session_command(make_session(), "cat /etc/passwd | tail -2 | wc -l")
    assert out.strip() == b"2"


def test_pipe_ps_aux_grep():
    out, _ = execute_session_command(make_session(), "ps aux | grep mysqld")
    assert b"mysqld" in out


def test_pipe_sort_uniq():
    out, _ = execute_session_command(make_session(), "printf 'b\\na\\nb' | sort")
    assert out == b"a\r\nb\r\nb\r\n"


def test_pipe_cut_delimiter():
    out, _ = execute_session_command(make_session(), "cat /etc/passwd | cut -d : -f 1 | head -1")
    assert out.startswith(b"root")


def test_three_stage_pipeline():
    out, _ = execute_session_command(
        make_session(), "cat /etc/passwd | grep root | wc -l"
    )
    assert int(out.strip()) >= 1


def test_unknown_pipeline_consumer_returns_empty():
    out, close = execute_session_command(make_session(), "cat /etc/hostname | frobnicate")
    assert out == b""
    assert not close


# ── Chaining ───────────────────────────────────────────────────────────────

def test_chain_semicolon_runs_both():
    out, _ = execute_session_command(make_session(), "echo one ; echo two")
    assert b"one" in out and b"two" in out


def test_chain_and_stops_on_failure():
    s = make_session()
    out, _ = execute_session_command(s, "cd /does-not-exist && echo SHOULD_NOT_APPEAR")
    assert b"SHOULD_NOT_APPEAR" not in out
    assert b"No such file or directory" in out


def test_chain_and_continues_on_success():
    s = make_session(cwd="/tmp")
    out, _ = execute_session_command(s, "cd /etc && pwd")
    assert s.cwd == "/etc"
    assert b"/etc" in out


def test_chain_or_runs_fallback_on_failure():
    out, _ = execute_session_command(make_session(), "ls /does-not-exist || echo FALLBACK_OK")
    assert b"FALLBACK_OK" in out


def test_chain_or_skips_fallback_on_success():
    out, _ = execute_session_command(make_session(), "echo FINE || echo NOT_THIS")
    assert b"FINE" in out
    assert b"NOT_THIS" not in out


# ── Environment variable expansion ─────────────────────────────────────────

def test_echo_expands_home_user_hostname():
    out, _ = execute_session_command(make_session(), "echo $USER at $HOME on ${HOSTNAME}")
    assert b"root at /root on web-prod-01" in out


def test_echo_single_quotes_are_literal():
    out, _ = execute_session_command(make_session(), "echo '$HOME'")
    assert out.strip() == b"$HOME"


def test_cd_expands_env_var():
    s = make_session(cwd="/tmp")
    execute_session_command(s, "cd $HOME")
    assert s.cwd == "/root"


# ── New commands ───────────────────────────────────────────────────────────

def test_reboot_terminates_session():
    out, close = execute_session_command(make_session(), "reboot")
    assert close
    assert b"going down" in out


def test_shutdown_terminates_session():
    _, close = execute_session_command(make_session(), "shutdown now")
    assert close


def test_shutdown_cancel_is_safe():
    _, close = execute_session_command(make_session(), "shutdown -c")
    assert not close


def test_w_lists_users():
    out, _ = execute_session_command(make_session(), "w")
    assert b"root" in out
    assert b"load average" in out


def test_docker_ps_table():
    out, _ = execute_session_command(make_session(), "docker ps")
    assert b"CONTAINER ID" in out
    assert b"nginx" in out


def test_docker_images():
    out, _ = execute_session_command(make_session(), "docker images")
    assert b"REPOSITORY" in out


def test_kubectl_get_pods():
    out, _ = execute_session_command(make_session(), "kubectl get pods")
    assert b"Running" in out


def test_ssh_client_internal_host_refused():
    out, _ = execute_session_command(make_session(), "ssh root@10.0.0.10")
    assert b"Connection refused" in out


def test_ssh_client_external_host_times_out():
    out, _ = execute_session_command(make_session(), "ssh root@203.0.113.99")
    assert b"Connection timed out" in out


def test_ll_alias_expands_to_ls_al():
    out, close = execute_session_command(make_session(), "ll /root")
    assert not close
    assert b".bashrc" in out  # -a flag from alias shows hidden files


def test_la_alias_shows_hidden_only_names():
    out, _ = execute_session_command(make_session(), "la /root")
    assert b".bash_history" in out


def test_journalctl_outputs_log_lines():
    out, _ = execute_session_command(make_session(), "journalctl -u ssh")
    assert b"sshd" in out


def test_hostnamectl_static_output():
    out, _ = execute_session_command(make_session(), "hostnamectl")
    assert b"Static hostname" in out


def test_printenv_known_variable():
    out, _ = execute_session_command(make_session(), "printenv HOME")
    assert out.strip() == b"/root"


def test_groups_for_root():
    out, _ = execute_session_command(make_session(), "groups")
    assert b"root" in out


def test_file_detects_script():
    out, _ = execute_session_command(make_session(), "file /root/deploy.sh")
    assert b"shell script" in out


def test_du_reports_size():
    out, _ = execute_session_command(make_session(), "du /var/log")
    assert b"/var/log" in out


def test_iptables_lists_chains():
    out, _ = execute_session_command(make_session(), "iptables -L")
    assert b"Chain INPUT" in out


def test_pip_install_output():
    out, _ = execute_session_command(make_session(), "pip install requests")
    assert b"Successfully installed" in out


def test_apt_install_output():
    out, _ = execute_session_command(make_session(), "apt-get install htop")
    assert b"Reading package lists" in out


def test_xxd_hex_dump():
    out, _ = execute_session_command(make_session(), "xxd /etc/hostname")
    assert b":" in out  # offset column


def test_strings_extracts_text():
    out, _ = execute_session_command(make_session(), "strings /etc/hostname")
    assert b"web-prod-01" in out


def test_scp_connection_refused():
    out, _ = execute_session_command(make_session(), "scp f.txt deploy@10.0.0.5:/tmp/")
    assert b"refused" in out.lower()


# ── Exit status derivation ──────────────────────────────────────────────────

def test_exit_status_helpers():
    from baitbox.servers.ssh_server import _exit_status_for

    assert _exit_status_for(b"") == 0
    assert _exit_status_for(b"id\r\n") == 0
    assert _exit_status_for(b"bash: nope: command not found\r\n") == 127
    assert _exit_status_for(b"cat: x: No such file or directory\r\n") == 1


def test_output_indicates_failure_markers():
    assert output_indicates_failure(b"bash: xyz: command not found\r\n")
    assert output_indicates_failure(b"No such file or directory")
    assert not output_indicates_failure(b"all good\r\n")


# ── History navigation ──────────────────────────────────────────────────────

def test_shell_history_up_and_down_roundtrip():
    history = ShellHistory(["whoami", "ls -la"])
    assert history.up("") == "ls -la"
    assert history.up("ls -la") == "whoami"
    assert history.up("whoami") is None  # already oldest
    assert history.down() == "ls -la"
    assert history.down() == ""  # draft restored
    assert history.down() is None  # nothing newer


def test_shell_history_preserves_draft():
    history = ShellHistory(["cmd-a"])
    assert history.up("my draft") == "cmd-a"
    assert history.down() == "my draft"


# ── Tab completion ──────────────────────────────────────────────────────────

def test_tab_completion_first_word_single_match():
    completed, candidates = complete_input(make_session(), "whoa")
    assert completed == "whoami "
    assert candidates == ["whoami "]


def test_tab_completion_first_word_multi_match_keeps_buffer():
    buffer, candidates = complete_input(make_session(), "wh")
    assert buffer == "wh"
    assert len(candidates) >= 3
    assert all(c.startswith("wh") for c in candidates)


def test_tab_completion_absolute_path():
    completed, candidates = complete_input(make_session(), "cat /ro")
    assert completed == "cat /root/"
    assert candidates == ["/root/"]


def test_tab_completion_relative_path_common_prefix():
    completed, candidates = complete_input(make_session(cwd="/root"), "cat .bas")
    # .bash_history and .bashrc both match; bash extends to the common prefix
    assert completed == "cat .bash"
    assert candidates == []


def test_tab_completion_directory_adds_slash():
    completed, _ = complete_input(make_session(), "cd /et")
    assert completed == "cd /etc/"
