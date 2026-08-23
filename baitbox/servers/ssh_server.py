"""Paramiko-powered SSH honeypot server."""

from __future__ import annotations

import logging
import os
import queue
import re
import shlex
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import paramiko

from ..async_bridge import run_on_main_loop
from ..config import settings
from ..db import log_event
from ..pubsub import pubsub
from ..ratelimit import block_ip, is_blocked, is_rate_limited, record_connection
from ..sessions import SSHSession, session_manager

logger = logging.getLogger("baitbox.ssh")

HOSTNAME = settings.ssh_banner_hostname

WELCOME = (
    f"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-94-generic x86_64)\r\n"
    f"\r\n"
    f" * Documentation:  https://help.ubuntu.com\r\n"
    f" * Management:     https://landscape.canonical.com\r\n"
    f"\r\n"
    f" System information as of {time.strftime('%a %b %d %H:%M:%S %Z %Y')}\r\n"
    f"\r\n"
    f"  System load:  0.08              Processes:          127\r\n"
    f"  Usage of /:   34.2% of 19.52GB  Users logged in:    1\r\n"
    f"  Memory usage: 52%               IPv4 address for eth0: 10.0.0.3\r\n"
    f"\r\n"
    f"Last login: Tue Jun 24 09:14:11 2026 from 203.0.113.24\r\n"
).encode()


def _load_host_key() -> paramiko.PKey:
    """Load a stable host key when configured, otherwise create an ephemeral key."""
    if not settings.ssh_host_key:
        return paramiko.RSAKey.generate(2048)

    key_path = Path(settings.ssh_host_key).expanduser()
    if key_path.exists():
        return paramiko.RSAKey.from_private_key_file(str(key_path))

    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(key_path))
    return key


HOST_KEY = _load_host_key()


class FakeShell(paramiko.ServerInterface):
    """Accepts authentication and records SSH channel requests."""

    def __init__(self, client_addr: tuple[str, int]) -> None:
        self.client_ip = client_addr[0]
        # Channel requests (shell/exec) are queued as they arrive so the
        # acceptor loop can serve multiple sequential sessions, like real sshd.
        self.requests: queue.Queue[tuple[str, paramiko.Channel, str | None]] = queue.Queue()
        self.username = "root"

    def get_allowed_auths(self, username: str) -> str:
        return "password,keyboard-interactive,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        _log_from_thread(self.client_ip, "auth_attempt", {"username": username, "password": password, "method": "password"})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_interactive(self, username: str, submethods: str) -> int:
        self.username = username
        _log_from_thread(self.client_ip, "auth_attempt", {"username": username, "method": "keyboard-interactive"})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        self.username = username
        _log_from_thread(
            self.client_ip,
            "auth_attempt",
            {"username": username, "method": "publickey", "key_type": key.get_name(), "fingerprint": key.fingerprint.hex()},
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.requests.put(("shell", channel, None))
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.requests.put(("exec", channel, command.decode("utf-8", errors="replace")))
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True

    def check_channel_env_request(self, channel: paramiko.Channel, name: bytes, value: bytes) -> bool:
        return True


async def _log_and_publish(src_ip: str, event_type: str, payload: dict[str, Any]) -> None:
    try:
        event = await log_event(src_ip, "SSH", event_type, payload)
        await pubsub.publish(event)
    except Exception:
        # Persistence problems must never tear down an active attacker
        # session — the honeypot keeps engaging even if storage fails.
        logger.exception("failed to persist SSH event %r", event_type)


def _log_from_thread(src_ip: str, event_type: str, payload: dict[str, Any]) -> None:
    try:
        run_on_main_loop(_log_and_publish(src_ip, event_type, payload))
    except Exception:
        logger.exception("failed to schedule SSH event logging")


def make_prompt(cwd: str, username: str = "root") -> bytes:
    p = cwd
    if p == "/root" or p == f"/home/{username}":
        p = "~"
    char = "#" if username == "root" else "$"
    return f"{username}@{HOSTNAME}:{p}{char} ".encode()


# ── Shell emulation helpers ──────────────────────────────────────────────────

_ALIASES: dict[str, str] = {
    "ll": "ls -alF",
    "la": "ls -A",
    "l": "ls -CF",
}

_KNOWN_COMMANDS = frozenset({
    "ls", "dir", "cd", "cat", "less", "more", "grep", "egrep", "fgrep", "find",
    "touch", "mkdir", "rm", "rmdir", "echo", "stat", "cp", "mv", "head", "tail",
    "wget", "curl", "ping", "nmap", "vi", "vim", "nano", "chmod", "chown",
    "useradd", "adduser", "userdel", "deluser", "groupadd", "groupdel", "usermod",
    "passwd", "tar", "gzip", "gunzip", "zip", "unzip", "which", "whereis", "man",
    "dpkg", "apt", "apt-get", "yum", "dnf", "rpm", "apk", "pip", "pip3",
    "kill", "pkill", "killall", "pgrep", "wc", "base64", "md5sum", "sha256sum",
    "sha1sum", "awk", "sed", "nc", "netcat", "ncat", "socat", "service",
    "pwd", "whoami", "id", "hostname", "uname", "uptime", "date", "clear",
    "sudo", "su", "doas", "env", "printenv", "history", "fc", "ps", "netstat",
    "ss", "ifconfig", "ip", "route", "arp", "who", "w", "last", "lastlog",
    "df", "du", "free", "top", "htop", "vmstat", "iostat", "lscpu", "lsblk",
    "mount", "umount", "findmnt", "swapon", "swapoff", "ln", "readlink",
    "realpath", "basename", "dirname", "file", "tty", "stty",
    "crontab", "at", "batch", "python", "python3", "perl", "php", "ruby",
    "node", "npm", "gcc", "g++", "cc", "make", "cmake", "gdb", "strace",
    "ltrace", "objdump", "readelf", "nm", "strings", "xxd", "hexdump",
    "mysql", "mysqldump", "sqlite3", "psql", "redis-cli", "mongo", "git",
    "systemctl", "service", "journalctl", "hostnamectl", "timedatectl",
    "localectl", "reboot", "shutdown", "poweroff", "halt", "init", "exit",
    "logout", "docker", "docker-compose", "podman", "kubectl", "helm",
    "scp", "sftp", "rsync", "ftp", "ssh", "telnet", "tcpdump", "iptables",
    "nft", "ufw", "firewall-cmd", "dd", "sync", "mkfifo", "sort", "uniq",
    "cut", "tr", "tee", "xargs", "seq", "printf", "sleep", "yes", "true",
    "false", "test", "[", "alias", "unalias", "export", "unset", "source",
    "set", "groups", "finger", "logname", "chattr", "lsattr", "getfacl",
    "setfacl", "visudo", "chsh", "chfn", "sh", "bash", "dash", "zsh",
})


class ShellHistory:
    """Arrow-key history navigation state shared with the interactive loop."""

    def __init__(self, entries: list[str]) -> None:
        self.entries = entries
        self.index = len(entries)
        self.draft = ""

    def up(self, current_buffer: str) -> str | None:
        """Move back in history; remembers the live buffer as the draft."""
        if self.index == len(self.entries):
            self.draft = current_buffer
        if self.index <= 0:
            return None
        self.index -= 1
        return self.entries[self.index]

    def down(self) -> str | None:
        """Move forward in history; restores the draft past the newest entry."""
        if self.index >= len(self.entries):
            return None
        self.index += 1
        if self.index == len(self.entries):
            return self.draft
        return self.entries[self.index]


def _split_outside_quotes(text: str, separators: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """Split ``text`` on multi-char operators outside quotes.

    Returns ``(segments, operators)`` where ``operators[i]`` precedes
    ``segments[i + 1]``.
    """
    segments: list[str] = []
    operators: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(text)

    def flush(op: str) -> None:
        nonlocal buf
        segments.append("".join(buf))
        operators.append(op)
        buf = []

    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if quote == "'" and ch == "'":
                quote = None
            elif quote == '"':
                if ch == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    quote = None
            i += 1
            continue
        matched = False
        for sep in separators:
            if text.startswith(sep, i):
                flush(sep)
                i += len(sep)
                matched = True
                break
        if matched:
            continue
        if ch in ("'", '"'):
            quote = ch
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return segments, operators


def _split_chains(command: str) -> tuple[list[str], list[str]]:
    """Split a command line on ``&&``, ``||`` and ``;``."""
    return _split_outside_quotes(command, ("&&", "||", ";"))


def _split_pipeline(segment: str) -> list[str]:
    """Split one chain segment on single ``|`` pipes."""
    stages, _ = _split_outside_quotes(segment, ("|",))
    return [stage.strip() for stage in stages]


_FAILURE_MARKERS = (
    b"command not found",
    b"No such file",
    b"Not a directory",
    b"Permission denied",
    b"missing operand",
    b"missing file operand",
    b"missing pattern operand",
    b"cannot ",
    b"Cannot ",
    b"is a directory",
    b"Is a directory",
    b"invalid option",
    b"failed",
    b"Failed",
)


def output_indicates_failure(out: bytes) -> bool:
    """Heuristic success detection for ``&&``/``||`` chain semantics."""
    return any(marker in out for marker in _FAILURE_MARKERS)


def _home_for(username: str) -> str:
    return "/root" if username == "root" else f"/home/{username}"


def _expand_vars(text: str, session: SSHSession) -> str:
    """Expand common environment variables ($HOME, ${USER}, $?, ...) ."""
    uid = "0" if session.username == "root" else "1000"
    variables = {
        "HOME": _home_for(session.username),
        "USER": session.username,
        "USERNAME": session.username,
        "LOGNAME": session.username,
        "PWD": session.cwd,
        "OLDPWD": session.cwd,
        "HOSTNAME": HOSTNAME,
        "SHELL": "/bin/bash",
        "TERM": "xterm-256color",
        "LANG": "en_US.UTF-8",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "UID": uid,
        "EUID": uid,
        "?": "0",
        "$": "1177",
        "RANDOM": "1337",
    }

    def _sub_braced(match: re.Match[str]) -> str:
        return variables.get(match.group(1), "")

    expanded = re.sub(r"\$\{(\w+)\}", _sub_braced, text)
    for name, value in variables.items():
        expanded = expanded.replace(f"${name}", value)
    return expanded


def _apply_stdin_filter(session: SSHSession, stage: str, stdin_data: bytes) -> bytes:
    """Run the consuming side of a pipeline against upstream output."""
    try:
        parts = shlex.split(stage, posix=True)
    except ValueError:
        parts = stage.split()
    if not parts:
        return stdin_data

    executable = parts[0]
    flags = [a for a in parts[1:] if a.startswith("-") and len(a) > 1]
    operands = [a for a in parts[1:] if not a.startswith("-")]

    def load_operand_file() -> bytes | None:
        if not operands:
            return stdin_data
        path = session.vfs._normalize_path(session.cwd, operands[0])
        content = session.vfs.read_file(path)
        if content is None:
            return f"{executable}: {operands[0]}: No such file or directory\r\n".encode()
        return content

    text = stdin_data.decode("utf-8", errors="replace")
    lines = text.splitlines()

    if executable in {"grep", "egrep", "fgrep"}:
        if not operands:
            return b"grep: missing pattern operand\r\n"
        pattern = operands[0]
        source_lines = lines
        file_operands = operands[1:]
        if file_operands:
            path = session.vfs._normalize_path(session.cwd, file_operands[0])
            content = session.vfs.read_file(path)
            if content is None:
                return f"grep: {file_operands[0]}: No such file or directory\r\n".encode()
            source_lines = content.decode("utf-8", errors="replace").splitlines()
        case_insensitive = "-i" in flags
        invert = "-v" in flags
        needle = pattern.lower() if case_insensitive else pattern
        matched = [
            ln for ln in source_lines
            if (needle in (ln.lower() if case_insensitive else ln)) != invert
        ]
        if "-c" in flags:
            return f"{len(matched)}\r\n".encode()
        if not matched:
            return b""
        prefix = f"{file_operands[0]}:" if len(file_operands) > 1 else ""
        return ("\r\n".join(prefix + ln for ln in matched) + "\r\n").encode()

    if executable == "wc":
        counts_only = "".join(f.lstrip("-") for f in flags)
        if operands:
            loaded = load_operand_file()
            if loaded is None:
                return b""
            src_text = loaded.decode("utf-8", errors="replace").rstrip("\n")
            src_lines = src_text.split("\n") if src_text else []
        else:
            trimmed = text.rstrip("\n")
            src_lines = trimmed.split("\n") if trimmed else []
            src_text = trimmed
        n_lines = len(src_lines)
        n_words = len(src_text.split())
        n_bytes = len(stdin_data)
        label = f" {operands[0]}" if operands else ""
        if counts_only == "l":
            return f"{n_lines}{label}\r\n".encode()
        if counts_only == "w":
            return f"{n_words}{label}\r\n".encode()
        if counts_only == "c":
            return f"{n_bytes}{label}\r\n".encode()
        return f"{n_lines} {n_words} {n_bytes}{label}\r\n".encode()

    if executable == "head":
        count = 10
        for flag_idx, flag in enumerate(parts[1:], start=1):
            if flag == "-n" and flag_idx + 1 < len(parts):
                try:
                    count = int(parts[flag_idx + 1])
                except ValueError:
                    pass
            elif flag.startswith("-n") and len(flag) > 2:
                try:
                    count = int(flag[2:])
                except ValueError:
                    pass
            elif flag.startswith("-c") and len(flag) > 2:
                try:
                    return stdin_data[: int(flag[2:])] + b"\r\n"
                except (ValueError, TypeError):
                    pass
            elif flag.startswith("-") and flag[1:].isdigit():
                count = int(flag[1:])
        selected = lines[:count] if count >= 0 else lines[:max(0, len(lines) + count)]
        return ("\r\n".join(selected) + "\r\n").encode() if selected else b""

    if executable == "tail":
        count = 10
        for flag_idx, flag in enumerate(parts[1:], start=1):
            if flag == "-n" and flag_idx + 1 < len(parts):
                try:
                    count = int(parts[flag_idx + 1])
                except ValueError:
                    pass
            elif flag.startswith("-n") and len(flag) > 2:
                try:
                    count = int(flag[2:])
                except ValueError:
                    pass
            elif flag.startswith("-") and flag[1:].isdigit():
                count = int(flag[1:])
        selected = lines[-count:] if count > 0 else []
        return ("\r\n".join(selected) + "\r\n").encode() if selected else b""

    if executable == "sort":
        reverse = "-r" in flags
        numeric = "-n" in flags or "-g" in flags
        unique = "-u" in flags
        ordered = sorted(set(lines) if unique else lines,
                         key=lambda ln: (float(re.sub(r"[^0-9.]", "", ln) or 0) if numeric else ln),
                         reverse=reverse)
        return ("\r\n".join(ordered) + "\r\n").encode() if ordered else b""

    if executable == "uniq":
        result: list[str] = []
        if "-c" in flags:
            counts: list[tuple[int, str]] = []
            for ln in lines:
                if counts and counts[-1][1] == ln:
                    counts[-1] = (counts[-1][0] + 1, ln)
                else:
                    counts.append((1, ln))
            result = [f"{count:7d} {ln}" for count, ln in counts]
        else:
            for ln in lines:
                if not result or result[-1] != ln:
                    result.append(ln)
        return ("\r\n".join(result) + "\r\n").encode() if result else b""

    if executable == "cut":
        delim = "\t"
        fields = "1"
        for flag_idx, flag in enumerate(parts):
            if flag == "-d" and flag_idx + 1 < len(parts):
                delim = parts[flag_idx + 1]
            elif flag.startswith("-d") and len(flag) > 2:
                delim = flag[2:]
            if flag == "-f" and flag_idx + 1 < len(parts):
                fields = parts[flag_idx + 1]
            elif flag.startswith("-f") and len(flag) > 2:
                fields = flag[2:]
        try:
            indices = [int(piece) for piece in fields.split(",")]
        except ValueError:
            indices = [1]

        def _pick(ln: str) -> str:
            cols = ln.split(delim)
            return delim.join(cols[idx - 1] for idx in indices if 0 < idx <= len(cols))

        picked = [_pick(ln) for ln in lines]
        return ("\r\n".join(picked) + "\r\n").encode() if picked else b""

    if executable == "tr":
        sets = [a for a in parts[1:] if not a.startswith("-")]
        if len(sets) >= 2:
            src, dst = sets[0], sets[1]
            table = str.maketrans(src, dst[: len(src)].ljust(len(src), dst[-1]))
            return text.translate(table).encode()
        if "-d" in flags and sets:
            return text.replace(sets[0], "").encode()
        return stdin_data

    if executable in {"awk", "gawk"}:
        match = re.search(r"\{.*print\s+\$?(\d+)\s*\}", stage)
        column = int(match.group(1)) if match else 0
        picked = [" ".join(ln.split()[column - 1:]) if column == 0
                  else (ln.split()[column - 1] if len(ln.split()) >= column else "")
                  for ln in lines]
        picked = [p for p in picked if p]
        return ("\r\n".join(picked) + "\r\n").encode() if picked else b""

    if executable == "tee":
        if operands:
            path = session.vfs._normalize_path(session.cwd, operands[0])
            session.vfs.write_file(path, stdin_data)
        return stdin_data

    if executable in {"cat", "tac"}:
        if not operands:
            if executable == "tac":
                return ("\r\n".join(reversed(lines)) + "\r\n").encode() if lines else b""
            return stdin_data
        return load_operand_file() or b""

    if executable == "base64":
        import base64 as b64
        if "-d" in flags or "--decode" in flags:
            try:
                return b64.b64decode(text.strip()) + b"\r\n"
            except Exception:
                return b"base64: invalid input\r\n"
        return b64.b64encode(stdin_data) + b"\r\n"

    if executable in {"md5sum", "sha1sum", "sha256sum"}:
        import hashlib
        algo = {"md5sum": hashlib.md5, "sha1sum": hashlib.sha1, "sha256sum": hashlib.sha256}[executable]
        label = operands[0] if operands else "-"
        return f"{algo(stdin_data).hexdigest()}  {label}\r\n".encode()

    if executable == "xargs":
        return stdin_data

    if executable == "true":
        return b""
    if executable == "false":
        return b""

    return b""


def execute_session_command(session: SSHSession, command: str) -> tuple[bytes, bool]:
    """Return a fake shell response and whether the session should close.

    Supports top-level chaining (``cmd1 && cmd2``, ``cmd1 || cmd2``,
    ``cmd1 ; cmd2``) and pipelines (``cat f | grep x | wc -l``).
    """
    command = command.strip()

    # Validate command length to prevent buffer overflow attacks
    if len(command) > settings.max_command_length:
        return b"bash: command line too long\r\n", False

    session.add_command(command)

    segments, operators = _split_chains(command)
    collected = b""
    for idx, segment in enumerate(segments):
        segment = segment.strip()
        if not segment:
            continue
        if idx > 0:
            failed = output_indicates_failure(collected)
            if operators[idx - 1] == "&&" and failed:
                break
            if operators[idx - 1] == "||" and not failed:
                break
        chunk, should_close = _run_pipeline(session, segment)
        collected += chunk
        if should_close:
            return collected, True
    return collected, False


def _run_pipeline(session: SSHSession, segment: str) -> tuple[bytes, bool]:
    stages = [stage for stage in _split_pipeline(segment) if stage]
    if not stages:
        return b"", False
    output, should_close = _dispatch_command(session, stages[0], piped=len(stages) > 1)
    for stage in stages[1:]:
        output = _apply_stdin_filter(session, stage, output)
    return output, should_close


def _dispatch_command(session: SSHSession, command: str, piped: bool = False) -> tuple[bytes, bool]:
    """Execute a single (pipe-free) command against the session VFS."""
    try:
        parts = shlex.split(command, posix=True) if command else []
    except ValueError:
        parts = command.split()

    if not parts:
        return b"", False

    if parts[0] in _ALIASES:
        parts = _ALIASES[parts[0]].split() + parts[1:]

    executable = parts[0]
    args = parts[1:]
    flags = [a for a in args if a.startswith("-") and len(a) > 1]
    operands = [a for a in args if not a.startswith("-")]

    # ── Built-ins ─────────────────────────────────────────────────────────────

    if executable in {"exit", "logout"}:
        return b"logout\r\n", True

    if executable == "pwd":
        return f"{session.cwd}\r\n".encode(), False

    if executable == "whoami":
        return f"{session.username}\r\n".encode(), False

    if executable == "id":
        uid = "0" if session.username == "root" else "1000"
        name = session.username
        return f"uid={uid}({name}) gid={uid}({name}) groups={uid}({name})\r\n".encode(), False

    if executable == "hostname":
        return f"{HOSTNAME}\r\n".encode(), False

    if executable == "uname":
        if "-a" in args or "--all" in args:
            return f"Linux {HOSTNAME} 5.15.0-94-generic #104-Ubuntu SMP Tue Jan 16 23:22:22 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\r\n".encode(), False
        return b"Linux\r\n", False

    if executable == "uptime":
        return b" 14:01:10 up 47 days, 12:34,  1 user,  load average: 0.08, 0.12, 0.10\r\n", False

    if executable == "date":
        return f"{time.strftime('%a %b %d %H:%M:%S %Z %Y')}\r\n".encode(), False

    if executable == "clear":
        return b"\x1b[2J\x1b[H", False

    if executable in {"sudo", "su"}:
        if session.username == "root":
            return b"root is already running as root\r\n", False
        return b"[sudo] password for ubuntu: \r\nSorry, user ubuntu may not run sudo on this host.\r\n", False

    if executable == "env":
        return (
            f"SHELL=/bin/bash\r\n"
            f"USER={session.username}\r\n"
            f"HOME=/{'root' if session.username == 'root' else 'home/' + session.username}\r\n"
            f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
            f"PWD={session.cwd}\r\n"
            f"HOSTNAME={HOSTNAME}\r\n"
            f"TERM=xterm-256color\r\n"
            f"LANG=en_US.UTF-8\r\n"
        ).encode(), False

    if executable == "history":
        lines = [f"  {i}  {c['command']}" for i, c in enumerate(session.commands, 1)]
        return ("\r\n".join(lines) + "\r\n").encode(), False

    if executable == "ps":
        combined_args = "".join(args)
        if "aux" in combined_args or "ax" in combined_args or "e" in combined_args:
            return (
                b"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                b"root         1  0.0  0.1 168640 13228 ?        Ss   Jun01   0:07 /sbin/init\r\n"
                b"root       412  0.0  0.2 236448 19856 ?        Ss   Jun01   0:00 /usr/sbin/sshd -D\r\n"
                b"www-data   987  0.1  0.8 452336 67220 ?        S    Jun01   5:12 nginx: worker process\r\n"
                b"mysql     1023  0.3  5.2 1782440 424088 ?      Sl   Jun01  12:44 /usr/sbin/mysqld\r\n"
                b"root      1177  0.0  0.1  14432  9088 pts/0    Ss   14:01   0:00 -bash\r\n"
                b"root      1244  0.0  0.0  12948  3968 pts/0    R+   14:01   0:00 ps aux\r\n"
            ), False
        return (
            b"  PID TTY          TIME CMD\r\n"
            b" 1177 pts/0    00:00:00 bash\r\n"
            b" 1244 pts/0    00:00:00 ps\r\n"
        ), False

    if executable in {"netstat", "ss"}:
        return (
            b"Active Internet connections (servers and established)\r\n"
            b"Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            b"tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            b"tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            b"tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n"
            b"tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\n"
            b"tcp        0      0 10.0.0.3:22             203.0.113.5:54321       ESTABLISHED\r\n"
        ), False

    if executable in {"ifconfig", "ip"}:
        if executable == "ip" and args and args[0] in ("a", "addr", "address"):
            return (
                b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\r\n"
                b"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
                b"    inet 127.0.0.1/8 scope host lo\r\n"
                b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc mq state UP group default qlen 1000\r\n"
                b"    link/ether 0a:1b:2c:3d:4e:5f brd ff:ff:ff:ff:ff:ff\r\n"
                b"    inet 10.0.0.3/24 brd 10.0.0.255 scope global eth0\r\n"
            ), False
        return (
            b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\r\n"
            b"        inet 10.0.0.3  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
            b"        ether 0a:1b:2c:3d:4e:5f  txqueuelen 1000  (Ethernet)\r\n"
            b"        RX packets 482341  bytes 612483201 (612.4 MB)\r\n"
            b"\r\n"
            b"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            b"        inet 127.0.0.1  netmask 255.0.0.0\r\n"
        ), False

    if executable == "who":
        return f"root     pts/0        2026-06-28 14:01 (203.0.113.5)\r\n".encode(), False

    if executable == "last":
        return (
            b"root     pts/0        203.0.113.5      Sat Jun 28 14:01   still logged in\r\n"
            b"deploy   pts/1        10.0.0.1         Sat Jun 28 11:12 - 11:45  (00:33)\r\n"
            b"ubuntu   pts/0        10.0.0.1         Fri Jun 27 09:00 - 10:22  (01:22)\r\n"
            b"\r\nwtmp begins Mon Jun  1 00:00:01 2026\r\n"
        ), False

    if executable == "df":
        return (
            b"Filesystem      1K-blocks     Used Available Use% Mounted on\r\n"
            b"/dev/xvda1       20480000  7012352  13467648  35% /\r\n"
            b"tmpfs            2013128        0   2013128   0% /dev/shm\r\n"
            b"/dev/xvdb1      51200000 24576000  26624000  48% /data\r\n"
        ), False

    if executable == "free":
        return (
            b"               total        used        free      shared  buff/cache   available\r\n"
            b"Mem:         4026256     1848204      814320       12344     1363732     2159504\r\n"
            b"Swap:        2097148           0     2097148\r\n"
        ), False

    if executable in {"top", "htop"}:
        return (
            b"top - 14:01:10 up 47 days, 12:34,  1 user,  load average: 0.08, 0.12, 0.10\r\n"
            b"Tasks: 127 total,   1 running, 126 sleeping,   0 stopped,   0 zombie\r\n"
            b"%Cpu(s):  1.2 us,  0.3 sy,  0.0 ni, 98.4 id,  0.1 wa,  0.0 hi,  0.0 si\r\n"
            b"MiB Mem :   3932.9 total,    795.2 free,   1804.9 used,   1332.8 buff/cache\r\n\r\n"
            b"  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\r\n"
            b" 1023 mysql     20   0 1.7g 414m  35m S   0.3   5.2  12:44.33 mysqld\r\n"
            b"  987 www-data  20   0  452m  65m  12m S   0.1   0.8   5:12.09 nginx\r\n"
            b" 1177 root      20   0 14432  8.8m  5.6m S   0.0   0.1   0:00.04 bash\r\n"
        ), False

    if executable == "crontab":
        if "-l" in args:
            content = session.vfs.read_file("/etc/crontab")
            if content:
                return content.replace(b"\n", b"\r\n"), False
        return b"no crontab for root\r\n", False

    if executable == "python3" or executable == "python":
        if not args:
            return b"Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0]\r\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n>>> \r\n", False
        if args[0] == "-c" and len(args) > 1:
            code = args[1]
            if "print" in code:
                inner = code.split("print(", 1)[-1].rstrip(")")
                return f"{inner.strip(chr(34)).strip(chr(39))}\r\n".encode(), False
        return b"", False

    if executable == "mysql":
        return b"ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: NO)\r\n", False

    if executable == "git":
        if args and args[0] == "log":
            return (
                b"commit a3f2c1d9e0b8f4a1c7d6e5f3b2a0e9d8c7b6a5f4\r\n"
                b"Author: deploy <deploy@example.com>\r\nDate:   Fri Jun 27 12:00:00 2026 +0000\r\n\r\n    Deploy v2.4.1 - hotfix payment gateway\r\n\r\n"
                b"commit b4e3d2c1f0a9e8d7c6b5a4f3e2d1c0b9a8f7e6d5\r\n"
                b"Author: alice <alice@example.com>\r\nDate:   Thu Jun 26 09:30:00 2026 +0000\r\n\r\n    feat: add Stripe webhook handler\r\n\r\n"
            ), False
        return b"fatal: not a git repository (or any of the parent directories): .git\r\n", False

    if executable == "systemctl":
        if args and args[0] == "status" and len(args) > 1:
            svc = args[1]
            return (
                f"● {svc}.service - {svc.capitalize()} Service\r\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled)\r\n"
                f"     Active: active (running) since Mon 2026-06-01 00:00:00 UTC; 27 days ago\r\n"
                f"   Main PID: 1023 ({svc})\r\n"
            ).encode(), False
        if args and args[0] in ("restart", "start", "stop", "reload"):
            svc = args[1] if len(args) > 1 else "unknown"
            return b"", False  # Silent success
        return b"Failed to connect to bus: No such file or directory\r\n", False

    # ── File System Commands ──────────────────────────────────────────────────

    if executable in {"ls", "dir"}:
        target_dir = session.cwd
        paths = [a for a in args if not a.startswith("-")]
        options = "".join([a[1:] for a in args if a.startswith("-")])
        if paths:
            target_dir = session.vfs._normalize_path(session.cwd, paths[0])

        if not session.vfs.exists(target_dir):
            return f"ls: cannot access '{paths[0]}': No such file or directory\r\n".encode(), False

        if session.vfs.is_file(target_dir):
            return f"{paths[0]}\r\n".encode(), False

        items = session.vfs.list_dir(target_dir)
        if items is None:
            return f"ls: cannot open directory '{target_dir}': Permission denied\r\n".encode(), False

        # Include dotfiles when -a/-A/-la flags given
        show_hidden = "a" in options.lower()
        if not show_hidden:
            items = [i for i in items if not i.startswith(".")]

        if "l" in options:
            lines = []
            for item in items:
                item_path = (target_dir if target_dir.endswith("/") else target_dir + "/") + item
                is_dir = session.vfs.is_dir(item_path)
                perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                size = 4096 if is_dir else len(session.vfs.read_file(item_path) or b"")
                lines.append(f"{perm} 1 root root {size:7d} Jun 28 14:01 {item}")
            return ("\r\n".join(lines) + "\r\n").encode(), False
        elif piped:
            # Real ls emits one entry per line when stdout is not a TTY
            return ("\r\n".join(items) + "\r\n").encode(), False
        else:
            # Color-like output without ANSI (simple)
            return ("  ".join(items) + "\r\n").encode(), False

    if executable == "cd":
        target = _expand_vars(args[0] if args else "~", session) if args else _home_for(session.username)
        if target in ("~", "-"):
            if target == "-" :
                return b"", False
            target = _home_for(session.username)
        target_dir = session.vfs._normalize_path(session.cwd, target)
        if session.vfs.is_dir(target_dir):
            session.cwd = target_dir
            return b"", False
        elif session.vfs.is_file(target_dir):
            return f"bash: cd: {target}: Not a directory\r\n".encode(), False
        else:
            return f"bash: cd: {target}: No such file or directory\r\n".encode(), False

    if executable == "cat":
        if not args:
            return b"", False
        results = []
        for target in args:
            if target.startswith("-"):
                continue
            target_path = session.vfs._normalize_path(session.cwd, target)
            if session.vfs.is_file(target_path):
                content = session.vfs.read_file(target_path)
                if content is not None:
                    results.append(content.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\n", "\r\n"))
            elif session.vfs.is_dir(target_path):
                results.append(f"cat: {target}: Is a directory\r\n")
            else:
                results.append(f"cat: {target}: No such file or directory\r\n")
        return "".join(results).encode(), False

    if executable == "less" or executable == "more":
        if not args:
            return b"", False
        target_path = session.vfs._normalize_path(session.cwd, args[-1])
        content = session.vfs.read_file(target_path)
        if content is None:
            return f"{executable}: {args[-1]}: No such file or directory\r\n".encode(), False
        return content.replace(b"\n", b"\r\n"), False

    if executable == "grep":
        if len(args) < 1:
            return b"grep: missing pattern operand\r\n", False
        flags = [a for a in args if a.startswith("-")]
        non_flags = [a for a in args if not a.startswith("-")]
        if not non_flags:
            return b"grep: missing pattern operand\r\n", False
        pattern = non_flags[0]
        files = non_flags[1:]
        results = []
        for fname in files:
            fpath = session.vfs._normalize_path(session.cwd, fname)
            matches = session.vfs.grep(pattern, fpath)
            if len(files) > 1:
                results.extend([f"{fname}:{line}" for line in matches])
            else:
                results.extend(matches)
        if not results:
            return b"", False
        return ("\r\n".join(results) + "\r\n").encode(), False

    if executable == "find":
        root = args[0] if args and not args[0].startswith("-") else session.cwd
        root = session.vfs._normalize_path(session.cwd, root)
        name = None
        for i, a in enumerate(args):
            if a == "-name" and i + 1 < len(args):
                name = args[i + 1].strip("*").strip("'\"")
        results = session.vfs.find(root, name)
        return ("\r\n".join(results) + "\r\n").encode() if results else b"", False

    if executable == "touch":
        if not args:
            return b"touch: missing file operand\r\n", False
        for target in args:
            if target.startswith("-"):
                continue
            target_path = session.vfs._normalize_path(session.cwd, target)
            session.vfs.write_file(target_path, b"")
        return b"", False

    if executable == "mkdir":
        if not args:
            return b"mkdir: missing operand\r\n", False
        for target in args:
            if target.startswith("-"):
                continue
            target_path = session.vfs._normalize_path(session.cwd, target)
            if not session.vfs.mkdir(target_path):
                return f"mkdir: cannot create directory '{target}': File exists or parent directory missing\r\n".encode(), False
        return b"", False

    if executable == "rm":
        if not args:
            return b"rm: missing operand\r\n", False
        recursive = False
        targets = []
        for target in args:
            if target in {"-r", "-rf", "-f", "-fr"}:
                recursive = True
            else:
                targets.append(target)
        for target in targets:
            target_path = session.vfs._normalize_path(session.cwd, target)
            if session.vfs.is_file(target_path):
                session.vfs.rm(target_path)
            elif session.vfs.is_dir(target_path):
                if recursive:
                    prefix = target_path if target_path.endswith("/") else target_path + "/"
                    keys_to_del = [k for k in list(session.vfs.fs.keys()) if k == target_path or k.startswith(prefix)]
                    for k in keys_to_del:
                        del session.vfs.fs[k]
                else:
                    return f"rm: cannot remove '{target}': Is a directory\r\n".encode(), False
            else:
                return f"rm: cannot remove '{target}': No such file or directory\r\n".encode(), False
        return b"", False

    if executable == "rmdir":
        if not args:
            return b"rmdir: missing operand\r\n", False
        for target in args:
            target_path = session.vfs._normalize_path(session.cwd, target)
            if not session.vfs.rmdir(target_path):
                return f"rmdir: failed to remove '{target}': Directory not empty or does not exist\r\n".encode(), False
        return b"", False

    if executable == "echo":
        raw_cmd = command[5:].strip() if len(command) > 4 else ""
        if ">>" in raw_cmd:
            content_part, file_part = raw_cmd.split(">>", 1)
            append = True
        elif ">" in raw_cmd:
            content_part, file_part = raw_cmd.split(">", 1)
            append = False
        else:
            content_part = raw_cmd
            file_part = ""
            append = False

        content_part = content_part.strip()
        quoted_single = content_part.startswith("'") and content_part.endswith("'") and len(content_part) >= 2
        if (content_part.startswith('"') and content_part.endswith('"')) or quoted_single:
            content_part = content_part[1:-1]
        if not quoted_single:
            content_part = _expand_vars(content_part, session)

        if file_part:
            file_name = _expand_vars(file_part.strip().strip('"').strip("'"), session)
            target_path = session.vfs._normalize_path(session.cwd, file_name)
            existing = b""
            if append and session.vfs.is_file(target_path):
                existing = session.vfs.read_file(target_path) or b""
            new_content = existing + content_part.encode() + b"\n"
            if session.vfs.write_file(target_path, new_content):
                return b"", False
            else:
                return f"bash: {file_name}: No such file or directory or target is a directory\r\n".encode(), False
        else:
            return f"{content_part}\r\n".encode(), False

    if executable == "stat":
        if not args:
            return b"stat: missing operand\r\n", False
        target = args[0]
        target_path = session.vfs._normalize_path(session.cwd, target)
        info = session.vfs.stat(target_path)
        if not info:
            return f"stat: cannot statx '{target}': No such file or directory\r\n".encode(), False
        return (
            f"  File: {info['name']}\r\n"
            f"  Size: {info['size']}\tBlocks: 8          IO Block: 4096   {info['type']}\r\n"
            f"Access: ({info['mode']})  Uid: (    0/    root)   Gid: (    0/    root)\r\n"
        ).encode(), False

    if executable == "cp":
        if len(args) < 2:
            return b"cp: missing file operand\r\n", False
        source = session.vfs._normalize_path(session.cwd, args[-2])
        destination = session.vfs._normalize_path(session.cwd, args[-1])
        if session.vfs.is_dir(destination):
            destination = session.vfs._normalize_path(destination, args[-2].rstrip("/").split("/")[-1])
        if not session.vfs.copy(source, destination):
            return f"cp: cannot stat '{args[-2]}': No such file or directory\r\n".encode(), False
        return b"", False

    if executable == "mv":
        if len(args) < 2:
            return b"mv: missing file operand\r\n", False
        source = session.vfs._normalize_path(session.cwd, args[-2])
        destination = session.vfs._normalize_path(session.cwd, args[-1])
        if session.vfs.is_dir(destination):
            destination = session.vfs._normalize_path(destination, args[-2].rstrip("/").split("/")[-1])
        if not session.vfs.move(source, destination):
            return f"mv: cannot move '{args[-2]}' to '{args[-1]}'\r\n".encode(), False
        return b"", False

    if executable == "head":
        if not args:
            return b"head: missing file operand\r\n", False
        count = 10
        files = []
        i = 0
        while i < len(args):
            if args[i] == "-n" and i + 1 < len(args):
                try:
                    count = max(0, int(args[i + 1]))
                except ValueError:
                    pass
                i += 2
                continue
            if not args[i].startswith("-"):
                files.append(args[i])
            i += 1
        target = files[0] if files else args[-1]
        target_path = session.vfs._normalize_path(session.cwd, target)
        content = session.vfs.read_file(target_path)
        if content is None:
            return f"head: cannot open '{target}' for reading: No such file or directory\r\n".encode(), False
        return ("\r\n".join(content.decode("utf-8", errors="replace").splitlines()[:count]) + "\r\n").encode(), False

    if executable == "tail":
        if not args:
            return b"tail: missing file operand\r\n", False
        target = [a for a in args if not a.startswith("-")][-1]
        target_path = session.vfs._normalize_path(session.cwd, target)
        content = session.vfs.read_file(target_path)
        if content is None:
            return f"tail: cannot open '{target}' for reading: No such file or directory\r\n".encode(), False
        return ("\r\n".join(content.decode("utf-8", errors="replace").splitlines()[-10:]) + "\r\n").encode(), False

    if executable in {"wget", "curl"}:
        url = _expand_vars(next((a for a in args if not a.startswith("-")), "index.html"), session)
        filename = url.split("/")[-1] if "/" in url else "index.html"
        if not filename or filename.startswith("-"):
            filename = "index.html"
        target_path = session.vfs._normalize_path(session.cwd, filename)
        fake_payload = (
            f"#!/bin/bash\n"
            f"# Simulated payload downloaded from {url}\n"
            f"# This script was logged and captured by BaitBox\n"
            f"echo 'Error: system architecture not supported'\n"
        ).encode()
        session.vfs.write_file(target_path, fake_payload)
        if executable == "wget":
            return (
                f"--2026-06-28 14:01:10--  {url}\r\n"
                f"Resolving {url.split('/')[2] if '//' in url else url}... 203.0.113.99\r\n"
                f"Connecting to {url.split('/')[2] if '//' in url else url}:80... connected.\r\n"
                f"HTTP request sent, awaiting response... 200 OK\r\n"
                f"Length: {len(fake_payload)} [text/x-sh]\r\n"
                f"Saving to: '{filename}'\r\n\r\n"
                f"100%[============================>] {len(fake_payload)}  --.-KB/s    in 0s\r\n\r\n"
                f"2026-06-28 14:01:11 (512 KB/s) - '{filename}' saved [{len(fake_payload)}/{len(fake_payload)}]\r\n"
            ).encode(), False
        else:
            return fake_payload, False

    if executable == "ping":
        if not args:
            return b"ping: missing host operand\r\n", False
        host = next((a for a in args if not a.startswith("-")), "")
        if not host:
            return b"ping: missing host operand\r\n", False
        return (
            f"PING {host} ({host}) 56(84) bytes of data.\r\n"
            f"64 bytes from {host}: icmp_seq=1 ttl=64 time=0.032 ms\r\n"
            f"64 bytes from {host}: icmp_seq=2 ttl=64 time=0.045 ms\r\n"
            f"64 bytes from {host}: icmp_seq=3 ttl=64 time=0.029 ms\r\n"
            f"\r\n--- {host} ping statistics ---\r\n"
            f"3 packets transmitted, 3 received, 0% packet loss, time 2004ms\r\n"
            f"rtt min/avg/max/mdev = 0.029/0.035/0.045/0.007 ms\r\n"
        ).encode(), False

    if executable == "nmap":
        host = next((a for a in args if not a.startswith("-")), "localhost")
        return (
            f"Starting Nmap 7.80 ( https://nmap.org ) at 2026-06-28 14:01 UTC\r\n"
            f"Nmap scan report for {host}\r\n"
            f"Host is up (0.00030s latency).\r\n"
            f"Not shown: 996 closed ports\r\n"
            f"PORT     STATE SERVICE\r\n"
            f"22/tcp   open  ssh\r\n"
            f"80/tcp   open  http\r\n"
            f"443/tcp  open  https\r\n"
            f"3306/tcp open  mysql\r\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds\r\n"
        ).encode(), False

    if executable in {"vi", "vim", "nano"}:
        if not args:
            return b"\r\n\r\n~\r\n~\r\n[No Name] [New File]\r\n", False
        fname = next((a for a in args if not a.startswith("-")), "")
        fpath = session.vfs._normalize_path(session.cwd, fname) if fname else ""
        if fpath and session.vfs.is_file(fpath):
            content = session.vfs.read_file(fpath) or b""
            lines = len(content.splitlines())
            return f'"{fname}" {lines}L, {len(content)}C\r\n'.encode(), False
        return f'"{fname}" [New File]\r\n'.encode(), False

    if executable == "chmod":
        if not args:
            return b"chmod: missing operand\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "chown":
        if not args:
            return b"chown: missing operand\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "useradd":
        if not args:
            return b"useradd: missing operand\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "passwd":
        if not args:
            return b"passwd: missing operand\r\n", False
        return b"New password: \r\nRetype new password: \r\npasswd: all authentication tokens updated successfully.\r\n", False

    if executable == "tar":
        if not args:
            return b"tar: You must specify one of the -Acdrtux options\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "gzip":
        if not args:
            return b"gzip: compressed data not written to a terminal\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "zip":
        if not args:
            return b"zip: nothing to do\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "unzip":
        if not args:
            return b"unzip: need at least one file specification\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "which":
        if not args:
            return b"which: missing operand\r\n", False
        cmd = args[0]
        common_paths = {
            "ls": "/bin/ls",
            "cat": "/bin/cat",
            "grep": "/bin/grep",
            "python": "/usr/bin/python",
            "python3": "/usr/bin/python3",
            "wget": "/usr/bin/wget",
            "curl": "/usr/bin/curl",
            "ssh": "/usr/bin/ssh",
            "nc": "/usr/bin/nc",
            "nmap": "/usr/bin/nmap",
        }
        path = common_paths.get(cmd, f"/usr/bin/{cmd}")
        return f"{path}\r\n".encode(), False

    if executable == "whereis":
        if not args:
            return b"whereis: missing operand\r\n", False
        cmd = args[0]
        return f"{cmd}: /usr/bin/{cmd} /usr/share/man/man1/{cmd}.1.gz\r\n".encode(), False

    if executable == "man":
        if not args:
            return b"What manual page do you want?\r\n", False
        return b"No manual entry for {}\r\n".format(args[0]).encode(), False

    if executable == "dpkg":
        if not args:
            return b"dpkg: requires an action option\r\n", False
        return b"", False  # Silent success for honeypot

    if executable in {"kill", "pkill", "killall"}:
        if not args:
            return f"{executable}: usage error\r\n".encode(), False
        return b"", False

    if executable == "wc":
        if not args:
            return b"0 0 0\r\n", False
        lines_only = "-l" in args or "--lines" in args
        target = [a for a in args if not a.startswith("-")][-1] if any(not a.startswith("-") for a in args) else None
        if target:
            fpath = session.vfs._normalize_path(session.cwd, target)
            content = session.vfs.read_file(fpath)
            if content is None:
                return f"wc: {target}: No such file or directory\r\n".encode(), False
            lines = len(content.splitlines())
            words = len(content.split())
            bytes_cnt = len(content)
            if lines_only:
                return f"{lines} {target}\r\n".encode(), False
            return f"{lines} {words} {bytes_cnt} {target}\r\n".encode(), False
        return b"0 0 0\r\n", False

    if executable == "base64":
        import base64 as b64
        decode_mode = "-d" in args or "--decode" in args
        target = [a for a in args if not a.startswith("-")][-1] if any(not a.startswith("-") for a in args) else None
        if target:
            fpath = session.vfs._normalize_path(session.cwd, target)
            content = session.vfs.read_file(fpath)
            if content is None:
                return f"base64: {target}: No such file or directory\r\n".encode(), False
            if decode_mode:
                try:
                    return b64.b64decode(content.strip()) + b"\r\n", False
                except Exception:
                    return b"base64: invalid input\r\n", False
            else:
                return b64.b64encode(content) + b"\r\n", False
        return b"", False

    if executable in {"md5sum", "sha256sum"}:
        import hashlib
        target = [a for a in args if not a.startswith("-")][-1] if any(not a.startswith("-") for a in args) else None
        if target:
            fpath = session.vfs._normalize_path(session.cwd, target)
            content = session.vfs.read_file(fpath)
            if content is None:
                return f"{executable}: {target}: No such file or directory\r\n".encode(), False
            h = hashlib.md5(content).hexdigest() if executable == "md5sum" else hashlib.sha256(content).hexdigest()
            return f"{h}  {target}\r\n".encode(), False
        return b"", False

    if executable in {"awk", "sed"}:
        if not args:
            return f"{executable}: missing script/file operand\r\n".encode(), False
        target = args[-1] if not args[-1].startswith("-") else None
        if target:
            fpath = session.vfs._normalize_path(session.cwd, target)
            content = session.vfs.read_file(fpath)
            if content is not None:
                return content.replace(b"\n", b"\r\n"), False
        return b"", False

    if executable in {"nc", "netcat", "ncat", "socat"}:
        return b"Ncat: Connection refused.\r\n", False

    if executable == "service":
        if len(args) >= 2 and args[1] == "status":
            svc = args[0]
            return f"● {svc}.service - {svc.capitalize()} Service\r\n   Active: active (running)\r\n".encode(), False
        return b"", False

    # ── Session-terminating system commands ─────────────────────────────────

    if executable in {"reboot", "shutdown", "poweroff", "halt", "init"}:
        if executable == "shutdown" and args and args[0] in ("-c", "--cancel"):
            return b"", False
        if executable == "init" and args and args[0] not in ("0", "6"):
            return b"", False
        action = {
            "reboot": "reboot",
            "shutdown": "shutdown",
            "poweroff": "power-off",
            "halt": "halt",
            "init": "reboot",
        }[executable]
        return (
            b"Broadcast message from root@" + HOSTNAME.encode() + b" (pts/0) (" +
            time.strftime("%a %b %d %H:%M:%S %Z %Y").encode() + b"):\r\n\r\n"
            b"The system is going down for " + action.encode() + b" NOW!\r\n"
        ), True

    # ── Additional discovery / recon commands ───────────────────────────────

    if executable == "w":
        return (
            f" {time.strftime('%H:%M:%S')} up 47 days, 12:34,  1 user,  load average: 0.08, 0.12, 0.10\r\n"
            f"USER     TTY      FROM             LOGIN@   IDLE   WHAT\r\n"
            f"root     pts/0    203.0.113.5      14:01    0.00s  w\r\n"
        ).encode(), False

    if executable == "lastlog":
        return (
            b"Username         Port     From             Latest\r\n"
            b"root             pts/0    203.0.113.5      Sat Jun 28 14:01:10 +0000 2026\r\n"
            b"ubuntu           pts/1    10.0.0.1         Fri Jun 27 09:00:22 +0000 2026\r\n"
            b"deploy                                     **Never logged in**\r\n"
        ), False

    if executable == "du":
        target = next((a for a in args if not a.startswith("-")), session.cwd)
        target_path = session.vfs._normalize_path(session.cwd, target)
        total = 0
        prefix = target_path if target_path.endswith("/") else target_path + "/"
        for key in session.vfs.fs:
            if key.startswith(prefix) and session.vfs.is_file(key):
                total += len(session.vfs.read_file(key) or b"")
        return f"{max(4, total // 1024)}\t{target}\r\n".encode(), False

    if executable == "lscpu":
        return (
            b"Architecture:        x86_64\r\n"
            b"CPU(s):              2\r\n"
            b"Model name:          Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\r\n"
            b"Thread(s) per core:  1\r\n"
            b"Core(s) per socket:  2\r\n"
        ), False

    if executable == "lsblk":
        return (
            b"NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\r\n"
            b"xvda   202:0    0   20G  0 disk\r\n"
            b"\xe2\x94\x94\xe2\x94\x80xvda1 202:1    0   20G  0 part /\r\n"
            b"xvdb   202:16   0   50G  0 disk\r\n"
            b"\xe2\x94\x94\xe2\x94\x80xvdb1 202:17   0   50G  0 part /data\r\n"
        ), False

    if executable in {"mount", "findmnt"}:
        return (
            b"/dev/xvda1 on / type ext4 (rw,relatime,discard)\r\n"
            b"tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\r\n"
            b"/dev/xvdb1 on /data type ext4 (rw,relatime)\r\n"
        ), False

    if executable in {"vmstat"}:
        return (
            b"procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\r\n"
            b" r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\r\n"
            b" 1  0      0 814320 128452 1420204    0    0     3    12   18   22  1  0 98  0  0\r\n"
        ), False

    if executable in {"iostat"}:
        return (
            b"Linux 5.15.0-94-generic (web-prod-01)\t06/28/2026\t_x86_64_\t(2 CPU)\r\n\r\n"
            b"avg-cpu:  %user   %nice %system %iowait  %steal   %idle\r\n"
            b"           1.21    0.00    0.34    0.12    0.00   98.33\r\n\r\n"
            b"Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn\r\n"
            b"xvda              1.42         8.12        21.40         0.00     4218920   11123440\r\n"
        ), False

    if executable == "ln":
        if len(args) < 2:
            return b"ln: missing file operand\r\n", False
        source = session.vfs._normalize_path(session.cwd, args[-2])
        destination = session.vfs._normalize_path(session.cwd, args[-1])
        content = session.vfs.read_file(source)
        if content is None:
            return f"ln: failed to access '{args[-2]}': No such file or directory\r\n".encode(), False
        session.vfs.write_file(destination, content)
        return b"", False

    if executable == "file":
        if not operands:
            return b"file: missing operand\r\n", False
        results = []
        for target in operands:
            path = session.vfs._normalize_path(session.cwd, target)
            content = session.vfs.read_file(path)
            if content is None:
                if session.vfs.is_dir(path):
                    results.append(f"{target}: directory")
                else:
                    results.append(f"{target}: cannot open `{target}' (No such file or directory)")
            elif content.startswith(b"\x1f\x8b"):
                results.append(f"{target}: gzip compressed data")
            elif content.startswith(b"#!"):
                results.append(f"{target}: Bourne-Again shell script, ASCII text executable")
            else:
                results.append(f"{target}: ASCII text")
        return ("\r\n".join(results) + "\r\n").encode(), False

    if executable in {"readlink", "realpath"}:
        if not operands:
            return f"{executable}: missing operand\r\n".encode(), False
        return f"{session.vfs._normalize_path(session.cwd, operands[0])}\r\n".encode(), False

    if executable in {"basename", "dirname"}:
        if not operands:
            return f"{executable}: missing operand\r\n".encode(), False
        value = operands[0].rstrip("/")
        if executable == "basename":
            return f"{value.split('/')[-1] or '/'}\r\n".encode(), False
        parent = "/".join(value.split("/")[:-1])
        return f"{parent or '/'}\r\n".encode(), False

    if executable == "tty":
        return b"/dev/pts/0\r\n", False

    if executable == "stty":
        return b"speed 38400 baud; rows 44; columns 160; line = 0;\r\n", False

    # ── Text processing standalone ──────────────────────────────────────────

    if executable in {"sort", "uniq", "cut", "tr", "xargs", "tac"}:
        return _apply_stdin_filter(session, command, b"")

    if executable == "seq":
        try:
            values = [int(a) for a in operands]
        except ValueError:
            return b"seq: invalid integer argument\r\n", False
        if len(values) == 1:
            start, stop = 1, values[0]
        elif len(values) >= 2:
            start, stop = values[0], values[1]
        else:
            return b"seq: missing operand\r\n", False
        numbers = list(range(start, stop + 1))[:1000]
        return ("\r\n".join(str(n) for n in numbers) + "\r\n").encode() if numbers else b"", False

    if executable == "printf":
        raw = command[len(executable):].strip()
        expanded = _expand_vars(raw, session)
        try:
            pieces = shlex.split(expanded)
        except ValueError:
            pieces = [expanded.strip('"\'')]
        fmt = pieces[0] if pieces else ""
        rendered = fmt.replace("\\n", "\n").replace("%s", "{}")
        for value in pieces[1:]:
            rendered = rendered.replace("{}", str(value), 1)
        rendered = re.sub(r"%s|%d", "", rendered).replace("{}", "")
        out = rendered.replace("\n", "\r\n")
        return (out + ("\r\n" if not out.endswith("\n") else "")).encode(), False

    if executable == "sleep":
        return b"", False

    if executable == "yes":
        text = operands[0] if operands else "y"
        return ("\r\n".join([text] * 10) + "\r\n").encode(), False

    if executable in {"test", "["}:
        return b"", False

    if executable in {"true", ":"}:
        return b"", False

    # ── Shell builtins ──────────────────────────────────────────────────────

    if executable == "printenv":
        if operands:
            env_out, _ = _dispatch_command(session, "env")
            for ln in env_out.decode().split("\r\n"):
                if ln.startswith(f"{operands[0]}="):
                    return (ln.split("=", 1)[1] + "\r\n").encode(), False
            return b"", False
        return _dispatch_command(session, "env")

    if executable in {"export", "unset", "set", "source", ".", "unalias", "fc"}:
        return b"", False

    if executable == "alias":
        if not operands:
            aliases = "\r\n".join(f"alias {name}='{value}'" for name, value in _ALIASES.items())
            return (aliases + "\r\n").encode(), False
        return b"", False

    if executable == "groups":
        name = session.username
        groups_list = "root" if name == "root" else f"{name} adm sudo docker"
        return f"{groups_list}\r\n".encode(), False

    if executable == "finger":
        user = operands[0] if operands else session.username
        return (
            f"Login: {user}                             Name: {user.capitalize()}\r\n"
            f"Directory: {_home_for(user):24} Shell: /bin/bash\r\n"
            f"On since Sat Jun 28 14:01 (UTC) from 203.0.113.5\r\n"
        ).encode(), False

    if executable == "logname":
        return f"{session.username}\r\n".encode(), False

    # ── User management ─────────────────────────────────────────────────────

    if executable in {"adduser", "useradd"}:
        if not operands:
            return f"{executable}: missing operand\r\n".encode(), False
        if executable == "adduser":
            return (
                f"Adding user '{operands[0]}' ...\r\n"
                f"Adding new group '{operands[0]}' (1002) ...\r\n"
                f"Adding new user '{operands[0]}' (1002) with group '{operands[0]}' ...\r\n"
                f"Creating home directory '/home/{operands[0]}' ...\r\n"
            ).encode(), False
        return b"", False

    if executable in {"userdel", "deluser"}:
        if not operands:
            return f"{executable}: missing operand\r\n".encode(), False
        return b"", False

    if executable in {"groupadd", "groupdel", "usermod", "chsh", "chfn", "visudo"}:
        return b"", False

    if executable in {"chattr", "setfacl"}:
        if not operands:
            return f"{executable}: missing operand\r\n".encode(), False
        return b"", False

    if executable in {"lsattr"}:
        targets = operands or ["."]
        lines = []
        for target in targets:
            path = session.vfs._normalize_path(session.cwd, target)
            if session.vfs.exists(path):
                lines.append(f"--------------e------- {target}")
            else:
                lines.append(f"lsattr: No such file or directory while trying to stat {target}")
        return ("\r\n".join(lines) + "\r\n").encode(), False

    if executable in {"getfacl"}:
        target = operands[0] if operands else "."
        return f"# file: {target}\n# owner: root\n# group: root\nuser::rw-\ngroup::r--\nother::r--\r\n".replace("\n", "\r\n").encode(), False

    # ── Logs & systemd ──────────────────────────────────────────────────────

    if executable == "journalctl":
        content = session.vfs.read_file("/var/log/auth.log")
        if content is None:
            return b"-- No entries --\r\n", False
        header = b"-- Logs begin at Mon 2026-06-01 00:00:01 UTC. --\r\n"
        return header + content.replace(b"\n", b"\r\n"), False

    if executable in {"hostnamectl", "timedatectl", "localectl"}:
        if executable == "hostnamectl":
            return (
                f"   Static hostname: {HOSTNAME}\r\n"
                "         Icon name: computer-vm\r\n"
                "           Chassis: vm\r\n"
                "        Virtualization: xen\r\n"
                "  Operating System: Ubuntu 22.04.4 LTS\r\n"
                "            Kernel: Linux 5.15.0-94-generic\r\n"
                "      Architecture: x86-64\r\n"
            ).encode(), False
        if executable == "timedatectl":
            return (
                f"               Local time: {time.strftime('%a %Y-%m-%d %H:%M:%S UTC')}\r\n"
                f"           Universal time: {time.strftime('%a %Y-%m-%d %H:%M:%S UTC')}\r\n"
                "                 Time zone: Etc/UTC (UTC, +0000)\r\n"
                "               NTP service: active\r\n"
            ).encode(), False
        return b"System Keymap: us\r\n", False

    # ── Containers & tooling ────────────────────────────────────────────────

    if executable in {"docker", "podman"}:
        sub = args[0] if args else ""
        if sub == "ps" or (sub == "container" and args[1:2] == ["ls"]):
            return (
                b"CONTAINER ID   IMAGE           COMMAND                  CREATED       STATUS       PORTS                    NAMES\r\n"
                b"a1b2c3d4e5f6   nginx:latest    \"/docker-entrypoint.\"   3 weeks ago   Up 27 days   0.0.0.0:80->80/tcp       web\r\n"
                b"f6e5d4c3b2a1   mysql:8.0       \"docker-entrypoint.s\"   3 weeks ago   Up 27 days   3306/tcp                 db\r\n"
            ), False
        if sub in {"images", "image"}:
            return (
                b"REPOSITORY        TAG       IMAGE ID       CREATED       SIZE\r\n"
                b"nginx             latest    a72860cb95fd   5 weeks ago   188MB\r\n"
                b"mysql             8.0       f5da8161d18e   6 weeks ago   574MB\r\n"
            ), False
        if sub in {"--version", "-v", "version"}:
            return b"Docker version 24.0.7, build afdd53b\r\n", False
        if sub in {"exec", "run", "start", "stop", "restart", "kill", "rm", "build", "pull", "push", "login"}:
            return b"", False
        return b"", False

    if executable == "kubectl":
        sub = args[0] if args else ""
        if sub == "get":
            resource = args[1] if len(args) > 1 else ""
            if resource.startswith("pod"):
                return (
                    b"NAME                        READY   STATUS    RESTARTS   AGE\r\n"
                    b"web-7d9f8b6c5-xk2pz         1/1     Running   0          27d\r\n"
                    b"db-mysql-0                  1/1     Running   0          30d\r\n"
                ), False
            if resource.startswith("node"):
                return (
                    b"NAME           STATUS   ROLES    AGE   VERSION\r\n"
                    b"node-master    Ready    master   45d   v1.29.2\r\n"
                    b"node-worker-1  Ready    worker   45d   v1.29.2\r\n"
                ), False
            return b"No resources found in default namespace.\r\n", False
        if sub in {"version", "--version"}:
            return b"Client Version: v1.29.2\r\nKubernetes Version: v1.29.2\r\n", False
        if sub in {"config", "describe", "logs", "apply", "delete", "exec", "port-forward"}:
            return b"", False
        return b"", False

    if executable in {"helm"}:
        return b"", False

    if executable == "docker-compose":
        return b"", False

    # ── Compilers & interpreters ────────────────────────────────────────────

    if executable in {"gcc", "g++", "cc", "make", "cmake"}:
        if any(a in ("-v", "--version") for a in args):
            versions = {
                "gcc": "gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
                "g++": "g++ (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
                "cc": "cc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0",
                "make": "GNU Make 4.3",
                "cmake": "cmake version 3.22.1",
            }
            return f"{versions[executable]}\r\n".encode(), False
        return b"", False

    if executable in {"perl", "php", "ruby", "node", "npm"}:
        if any(a in ("-v", "--version") for a in args):
            versions = {
                "perl": "This is perl 5, version 34, subversion 0 (v5.34.0)",
                "php": "PHP 8.1.2-1ubuntu2.14 (cli)",
                "ruby": "ruby 3.0.2p107 (2021-07-07 revision 0db68f0233) [x86_64-linux-gnu]",
                "node": "v12.22.9",
                "npm": "8.5.1",
            }
            return f"{versions[executable]}\r\n".encode(), False
        return b"", False

    if executable in {"strace", "ltrace", "gdb", "objdump", "readelf", "nm"}:
        if executable in {"strace", "ltrace"} and operands:
            return b"", False
        if executable == "gdb":
            return b"GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1\r\n", False
        if not operands:
            return b"", False
        return f"{executable}: '{operands[0]}': No such file\r\n".encode(), False

    if executable in {"strings"}:
        if not operands:
            return b"strings: missing file operand\r\n", False
        path = session.vfs._normalize_path(session.cwd, operands[0])
        content = session.vfs.read_file(path)
        if content is None:
            return f"strings: '{operands[0]}': No such file\r\n".encode(), False
        printable = []
        current = ""
        for byte in content:
            ch = chr(byte)
            if 32 <= byte < 127:
                current += ch
            else:
                if len(current) >= 4:
                    printable.append(current)
                current = ""
        if len(current) >= 4:
            printable.append(current)
        return ("\r\n".join(printable[:200]) + "\r\n").encode() if printable else b"", False

    if executable in {"xxd", "hexdump", "od"}:
        if not operands:
            return f"{executable}: missing file operand\r\n".encode(), False
        path = session.vfs._normalize_path(session.cwd, operands[0])
        content = session.vfs.read_file(path)
        if content is None:
            return f"{executable}: {operands[0]}: No such file or directory\r\n".encode(), False
        dump_lines = []
        for offset in range(0, min(len(content), 256), 16):
            chunk = content[offset:offset + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(47)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            dump_lines.append(f"{offset:08x}: {hex_part}  {ascii_part}")
        return ("\r\n".join(dump_lines) + "\r\n").encode() if dump_lines else b"", False

    # ── Network pivoting tools ──────────────────────────────────────────────

    if executable == "ssh":
        target = next((a for a in operands if "@" in a or "." in a or a.startswith("10.")), "")
        host = target.split("@", 1)[1] if "@" in target else target
        port_flag = None
        for flag_idx, flag in enumerate(args):
            if flag == "-p" and flag_idx + 1 < len(args):
                port_flag = args[flag_idx + 1]
        port = port_flag or "22"
        if not host:
            return b"usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] destination\r\n", False
        if host.startswith(("10.", "192.168.", "172.")):
            return f"ssh: connect to host {host} port {port}: Connection refused\r\n".encode(), False
        return f"ssh: connect to host {host} port {port}: Connection timed out\r\n".encode(), False

    if executable in {"scp", "sftp", "rsync", "ftp"}:
        return (
            b"ssh: connect to host 10.0.0.5 port 22: Connection refused\r\n"
            b"lost connection\r\n"
        ), False

    if executable in {"telnet"}:
        target = next((a for a in operands if not a.startswith("-")), "")
        return f"telnet: Unable to connect to remote host: Connection refused\r\n".encode(), False

    if executable in {"tcpdump", "dumpcap"}:
        if session.username != "root":
            return b"tcpdump: eth0: You don't have permission to capture on that device\r\n", False
        return (
            b"tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\r\n"
            b"listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\r\n"
            b"^C\r\n0 packets captured\r\n0 packets received by filter\r\n0 packets dropped by kernel\r\n"
        ), False

    if executable in {"iptables", "nft", "ufw", "firewall-cmd"}:
        if executable == "ufw":
            return b"Status: inactive\r\n", False
        if executable in {"iptables", "nft"}:
            return (
                b"Chain INPUT (policy ACCEPT)\r\n"
                b"target     prot opt source               destination\r\n"
                b"ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh\r\n"
                b"ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http\r\n\r\n"
                b"Chain FORWARD (policy DROP)\r\n"
                b"target     prot opt source               destination\r\n\r\n"
                b"Chain OUTPUT (policy ACCEPT)\r\n"
                b"target     prot opt source               destination\r\n"
            ), False
        return b"", False

    if executable in {"route"}:
        return (
            b"Kernel IP routing table\r\n"
            b"Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\r\n"
            b"default         10.0.0.1        0.0.0.0         UG    100    0        0 eth0\r\n"
            b"10.0.0.0        0.0.0.0         255.255.255.0   U     100    0        0 eth0\r\n"
        ), False

    if executable in {"arp"}:
        return (
            b"Address          HWtype  HWaddress           Flags Mask            Iface\r\n"
            b"10.0.0.1         ether   00:11:22:33:44:55   C                     eth0\r\n"
        ), False

    # ── Databases & misc clients ────────────────────────────────────────────

    if executable in {"mysqldump"}:
        return b"mysqldump: Got error: 1045: Access denied for user 'root'@'localhost' (using password: NO) when trying to connect\r\n", False

    if executable in {"sqlite3", "psql", "redis-cli", "mongo"}:
        if executable == "redis-cli":
            return b"Could not connect to Redis at 127.0.0.1:6379: Connection refused\r\n", False
        if executable == "psql":
            return b"psql: error: connection refused\r\n", False
        if executable == "mongo":
            return b"MongoNetworkError: connect ECONNREFUSED 127.0.0.1:27017\r\n", False
        return b"sqlite3: unable to open database file\r\n", False

    if executable in {"pip", "pip3"}:
        if operands and operands[0] in ("install", "download"):
            pkgs = [p for p in operands[1:] if not p.startswith("-")] or ["package"]
            names = ", ".join(f"{p}-1.0.0" for p in pkgs[:3])
            return (
                b"Collecting " + pkgs[0].encode() + b"\r\n"
                b"  Downloading " + pkgs[0].encode() + b"-1.0.0-py3-none-any.whl (52 kB)\r\n"
                b"Installing collected packages: " + ", ".join(pkgs[:3]).encode() + b"\r\n"
                b"Successfully installed " + names.encode() + b"\r\n"
            ), False
        if any(a == "--version" or a == "-V" for a in args):
            return b"pip 22.0.2 from /usr/lib/python3/dist-packages/pip (python 3.10)\r\n", False
        return b"", False

    if executable in {"rpm", "dpkg-query"}:
        return b"", False

    # ── Misc utilities ──────────────────────────────────────────────────────

    if executable == "pgrep":
        return b"1177\r\n1244\r\n", False

    if executable == "dd":
        params = {}
        for arg in operands:
            if "=" in arg:
                key, _, value = arg.partition("=")
                params[key] = value
        src = params.get("if")
        dst = params.get("of")
        if not dst:
            return b"dd: failed to open 'of=' : Invalid argument\r\n", False
        if src:
            src_path = session.vfs._normalize_path(session.cwd, src)
            content = session.vfs.read_file(src_path)
            if content is None:
                return f"dd: failed to open '{src}': No such file or directory\r\n".encode(), False
        else:
            content = b"\x00" * 1024
        dst_path = session.vfs._normalize_path(session.cwd, dst)
        if not session.vfs.write_file(dst_path, content):
            return f"dd: failed to open '{dst}': Permission denied\r\n".encode(), False
        blocks = max(1, len(content) // 512)
        return (
            f"{blocks}+0 records in\r\n{blocks}+0 records out\r\n"
            f"{len(content)} bytes copied, 0.002 s, 51.2 MB/s\r\n"
        ).encode(), False

    if executable in {"sync", "mkfifo", "swapon", "swapoff", "at", "batch", "dash", "zsh"}:
        return b"", False

    if executable == "egrep" or executable == "fgrep":
        return _apply_stdin_filter(session, "grep " + " ".join(args), b"")

    # ── Package managers (verbose success) ──────────────────────────────────

    if executable in {"apt", "apt-get", "yum", "dnf", "apk"}:
        if not operands:
            return f"{executable}: missing command\r\n".encode(), False
        sub = operands[0]
        if sub in {"update"}:
            return (
                b"Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\r\n"
                b"Reading package lists... Done\r\n"
            ), False
        if sub in {"install", "remove", "upgrade", "purge"}:
            pkgs = [p for p in operands[1:] if not p.startswith("-")]
            if not pkgs:
                return b"", False
            pkg = pkgs[0]
            return (
                "Reading package lists... Done\r\n"
                "Building dependency tree... Done\r\n"
                "The following NEW packages will be installed:\r\n"
                f"  {pkg}\r\n"
                "0 upgraded, 1 newly installed, 0 to remove and 12 not upgraded.\r\n"
                f"Setting up {pkg} ...\r\n"
            ).encode(), False
        if sub in {"list", "search", "info", "show"}:
            return b"", False
        return b"", False

    # Script execution
    run_file = ""
    if executable.startswith("./"):
        run_file = executable[2:]
    elif executable in {"sh", "bash"} and args:
        run_file = args[0]

    if run_file:
        file_path = session.vfs._normalize_path(session.cwd, run_file)
        if session.vfs.is_file(file_path):
            content = session.vfs.read_file(file_path) or b""
            if content.startswith(b"#!"):
                lines = content.decode("utf-8", errors="replace").split("\n")
                output_lines = []
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("echo "):
                        echo_str = line[5:].strip().strip('"').strip("'")
                        output_lines.append(echo_str)
                    elif line.startswith("sleep "):
                        pass  # Silently skip
                if output_lines:
                    return ("\r\n".join(output_lines) + "\r\n").encode(), False
                return b"", False

    return f"bash: {executable}: command not found\r\n".encode(), False


def _exit_status_for(output: bytes) -> int:
    """Derive a plausible process exit status from fake command output."""
    if not output:
        return 0
    if b"command not found" in output:
        return 127
    if output_indicates_failure(output):
        return 1
    return 0


def complete_input(session: SSHSession, buffer: str) -> tuple[str, list[str]]:
    """Tab-completion for paths and command names.

    Returns ``(updated_buffer, candidates)``. ``updated_buffer`` equals
    ``buffer`` when nothing could be completed.
    """
    if not buffer or buffer.endswith(" "):
        token = ""
        head = buffer
        completing_first_word = not buffer.strip()
    else:
        pieces = buffer.split()
        token = pieces[-1]
        head = buffer[: len(buffer) - len(token)]
        completing_first_word = len(pieces) == 1

    candidates: list[str] = []

    if completing_first_word:
        base_dir = session.cwd
        for cmd in _KNOWN_COMMANDS:
            if cmd.startswith(token):
                candidates.append(cmd + " ")
        for item in session.vfs.list_dir(base_dir) or []:
            rendered_item = f"./{item}" if token.startswith("./") else item
            if rendered_item.startswith(token):
                suffix = "/" if session.vfs.is_dir(
                    session.vfs._normalize_path(base_dir, item)
                ) else " "
                candidates.append(rendered_item + suffix)
        candidates = sorted(set(candidates))
        if len(candidates) == 1:
            return head + candidates[0], candidates
        return buffer, candidates

    # Path completion for later arguments
    dirname, _, partial = token.rpartition("/")
    if dirname == "":
        if token.startswith("/"):
            base_dir = "/"
            path_prefix = "/"
        else:
            base_dir = session.cwd
            path_prefix = ""
    elif dirname == "/":
        base_dir = "/"
        path_prefix = "/"
    else:
        base_dir = session.vfs._normalize_path(session.cwd, dirname)
        path_prefix = dirname.rstrip("/") + "/"

    matches: list[str] = []
    for item in session.vfs.list_dir(base_dir) or []:
        if item.startswith(partial):
            suffix = "/" if session.vfs.is_dir(
                session.vfs._normalize_path(base_dir, item)
            ) else " "
            matches.append(path_prefix + item + suffix)

    candidates = sorted(matches)
    if not candidates:
        return buffer, []
    if len(candidates) == 1:
        return head + candidates[0], candidates
    common = os.path.commonprefix(candidates)
    if len(common) > len(token):
        return head + common, []
    return buffer, candidates


def _redraw_line(channel: paramiko.Channel, session: SSHSession, buffer: str) -> None:
    """Erase the current line and redraw prompt + buffer."""
    channel.send(b"\r\x1b[K" + make_prompt(session.cwd, session.username) + buffer.encode())


def _run_exec(channel: paramiko.Channel, session: SSHSession, command: str) -> None:
    _log_from_thread(session.src_ip, "command", {"command": command, "mode": "exec", "session_id": session.session_id})
    try:
        response, _ = execute_session_command(session, command)
    except Exception:
        logger.exception("error executing %r", command)
        response, _ = b"bash: internal error\r\n", False
    channel.send(response)
    channel.send_exit_status(_exit_status_for(response))
    try:
        channel.shutdown_write()
    except Exception:
        pass


def handle_ssh_client(client: socket.socket, addr: tuple[str, int]) -> None:
    ip = addr[0]
    record_connection(ip, "SSH")

    if is_blocked(ip) or is_rate_limited(ip, "SSH"):
        client.close()
        return

    transport = paramiko.Transport(client)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7"
    transport.add_server_key(HOST_KEY)
    server = FakeShell(addr)
    session_id = uuid.uuid4().hex
    ssh_session: SSHSession | None = None

    try:
        transport.start_server(server=server)

        # Serve multiple sequential channels (exec commands, then a shell),
        # mirroring real sshd behaviour where one connection carries many
        # sessions that share login state.
        while transport.is_active():
            channel = transport.accept(settings.ssh_channel_timeout)
            if channel is None:
                break
            try:
                kind, req_channel, payload = server.requests.get(timeout=settings.ssh_channel_timeout)
            except queue.Empty:
                channel.close()
                continue

            username = getattr(server, "username", "root")
            if ssh_session is None:
                ssh_session = SSHSession(
                    session_id=session_id,
                    src_ip=ip,
                    src_port=addr[1],
                    username=username,
                    channel=req_channel,
                    transport=transport,
                )
                session_manager.register(ssh_session)
            else:
                # Keep one logical session across channels; update the active
                # channel so dashboard kill actions target the live one.
                ssh_session.channel = req_channel

            if kind == "exec" and payload:
                _run_exec(req_channel, ssh_session, payload)
                continue

            _run_shell(req_channel, ssh_session)
            break
    except (OSError, EOFError, paramiko.SSHException) as exc:
        _log_from_thread(ip, "connection_error", {"error": str(exc)})
    except Exception:
        # Unexpected bugs must not crash the acceptor thread or leak sockets.
        logger.exception("unexpected error handling SSH client from %s", ip)
    finally:
        session_manager.unregister(session_id)
        transport.close()


def _run_shell(channel: paramiko.Channel, session: SSHSession) -> None:
    channel.send(WELCOME)
    channel.send(make_prompt(session.cwd, session.username))
    buffer = ""
    history = ShellHistory([c["command"] for c in session.commands])
    while True:
        char = channel.recv(1)
        if not char:
            break
        if char in {b"\r", b"\n"}:
            command = buffer.strip()
            channel.send(b"\r\n")
            if command:
                _log_from_thread(session.src_ip, "command",
                                 {"command": command, "mode": "shell", "session_id": session.session_id})
                response, should_close = execute_session_command(session, command)
                channel.send(response)
                if should_close:
                    break
            buffer = ""
            history = ShellHistory([c["command"] for c in session.commands])
            channel.send(make_prompt(session.cwd, session.username))
        elif char == b"\x7f":  # Backspace
            if buffer:
                buffer = buffer[:-1]
                channel.send(b"\b \b")
        elif char == b"\x03":  # Ctrl+C
            buffer = ""
            history = ShellHistory([c["command"] for c in session.commands])
            channel.send(b"^C\r\n")
            channel.send(make_prompt(session.cwd, session.username))
        elif char == b"\x04":  # Ctrl+D
            channel.send(b"logout\r\n")
            break
        elif char == b"\t":  # Tab completion
            completed, candidates = complete_input(session, buffer)
            if len(candidates) == 1 or (completed != buffer and not candidates):
                buffer = completed
                _redraw_line(channel, session, buffer)
            elif candidates:
                names = [c.rstrip("/ ") for c in candidates]
                column_block = "  ".join(names[:40])
                channel.send(b"\r\n" + column_block.encode() + b"\r\n")
                _redraw_line(channel, session, buffer)
        elif char == b"\x1b":  # Escape sequence (arrow keys)
            seq = channel.recv(2)
            if seq in (b"[A", b"OA"):  # Up arrow
                prev_cmd = history.up(buffer)
                if prev_cmd is not None:
                    buffer = prev_cmd
                    _redraw_line(channel, session, buffer)
            elif seq in (b"[B", b"OB"):  # Down arrow
                next_cmd = history.down()
                if next_cmd is not None:
                    buffer = next_cmd
                    _redraw_line(channel, session, buffer)
            elif seq[0:1] == b"[" and len(seq) >= 1:
                pass  # Ignore other escape sequences (left/right/home/end)
        else:
            decoded = char.decode("utf-8", errors="ignore")
            if decoded:
                buffer += decoded
                channel.send(char)


def start_ssh_server(host: str = "0.0.0.0", port: int = 2222) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(settings.ssh_backlog)
    print(f"[SSH Honeypot] Listening on {host}:{port}")

    try:
        while True:
            client, addr = sock.accept()
            thread = threading.Thread(target=handle_ssh_client, args=(client, addr), daemon=True)
            thread.start()
    finally:
        sock.close()
