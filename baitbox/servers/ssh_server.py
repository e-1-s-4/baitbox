"""Paramiko-powered SSH honeypot server."""

from __future__ import annotations

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
        self.shell_requested = threading.Event()
        self.exec_command: str | None = None
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
        self.shell_requested.set()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        self.exec_command = command.decode("utf-8", errors="replace")
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
    event = await log_event(src_ip, "SSH", event_type, payload)
    await pubsub.publish(event)


def _log_from_thread(src_ip: str, event_type: str, payload: dict[str, Any]) -> None:
    run_on_main_loop(_log_and_publish(src_ip, event_type, payload))


def make_prompt(cwd: str, username: str = "root") -> bytes:
    p = cwd
    if p == f"/root" or p == f"/home/{username}":
        p = "~"
    char = "#" if username == "root" else "$"
    return f"{username}@{HOSTNAME}:{p}{char} ".encode()


def execute_session_command(session: SSHSession, command: str) -> tuple[bytes, bool]:
    """Return a fake shell response and whether the session should close."""
    command = command.strip()
    
    # Validate command length to prevent buffer overflow attacks
    from ..config import settings
    if len(command) > settings.max_command_length:
        return b"bash: command line too long\r\n", False
    
    session.add_command(command)
    try:
        parts = shlex.split(command, posix=True) if command else []
    except ValueError:
        parts = command.split()

    if not parts:
        return b"", False

    executable = parts[0]
    args = parts[1:]

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

        # Include dotfiles when -a or -la flags given
        show_hidden = "a" in options
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
        else:
            # Color-like output without ANSI (simple)
            return ("  ".join(items) + "\r\n").encode(), False

    if executable == "cd":
        target = args[0] if args else (f"/root" if session.username == "root" else f"/home/{session.username}")
        if target == "~":
            target = f"/root" if session.username == "root" else f"/home/{session.username}"
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
        if (content_part.startswith('"') and content_part.endswith('"')) or (content_part.startswith("'") and content_part.endswith("'")):
            content_part = content_part[1:-1]

        if file_part:
            file_name = file_part.strip().strip('"').strip("'")
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
        url = next((a for a in args if not a.startswith("-")), "index.html")
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

    if executable == "apt":
        if not args:
            return b"apt: missing command\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "apt-get":
        if not args:
            return b"apt-get: missing command\r\n", False
        return b"", False  # Silent success for honeypot

    if executable == "yum":
        if not args:
            return b"yum: missing command\r\n", False
        return b"", False  # Silent success for honeypot

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


def _run_exec(channel: paramiko.Channel, session: SSHSession, command: str) -> None:
    _log_from_thread(session.src_ip, "command", {"command": command, "mode": "exec", "session_id": session.session_id})
    response, _ = execute_session_command(session, command)
    channel.send(response)
    channel.send_exit_status(0)


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

    try:
        transport.start_server(server=server)
        channel = transport.accept(settings.ssh_channel_timeout)
        if channel is None:
            return

        username = getattr(server, "username", "root")
        ssh_session = SSHSession(
            session_id=session_id,
            src_ip=ip,
            src_port=addr[1],
            username=username,
            channel=channel,
            transport=transport,
        )
        session_manager.register(ssh_session)

        wait_step = 0.05
        waited = 0.0
        while not server.shell_requested.is_set() and server.exec_command is None and waited < settings.ssh_channel_timeout:
            if not transport.is_active():
                return
            time.sleep(wait_step)
            waited += wait_step
        if not server.shell_requested.is_set() and server.exec_command is None:
            return

        if server.exec_command is not None:
            _run_exec(channel, ssh_session, server.exec_command)
            return
        _run_shell(channel, ssh_session)
    except (OSError, EOFError, paramiko.SSHException) as exc:
        _log_from_thread(ip, "connection_error", {"error": str(exc)})
    finally:
        session_manager.unregister(session_id)
        transport.close()


def _run_shell(channel: paramiko.Channel, session: SSHSession) -> None:
    channel.send(WELCOME)
    channel.send(make_prompt(session.cwd, session.username))
    buffer = ""
    history_pos = -1
    addr = (session.src_ip, session.src_port)
    while True:
        char = channel.recv(1)
        if not char:
            break
        if char in {b"\r", b"\n"}:
            command = buffer.strip()
            channel.send(b"\r\n")
            if command:
                _log_from_thread(addr[0], "command", {"command": command, "mode": "shell", "session_id": session.session_id})
                response, should_close = execute_session_command(session, command)
                channel.send(response)
                if should_close:
                    break
                history_pos = -1
            buffer = ""
            channel.send(make_prompt(session.cwd, session.username))
        elif char == b"\x7f":  # Backspace
            if buffer:
                buffer = buffer[:-1]
                channel.send(b"\b \b")
        elif char == b"\x03":  # Ctrl+C
            buffer = ""
            channel.send(b"^C\r\n")
            channel.send(make_prompt(session.cwd, session.username))
        elif char == b"\x04":  # Ctrl+D
            channel.send(b"logout\r\n")
            break
        elif char == b"\x1b":  # Escape sequence (arrow keys)
            seq = channel.recv(2)
            if seq == b"[A" and session.commands:  # Up arrow
                idx = max(0, len(session.commands) - 1 - max(history_pos, -1) - 1)
                prev_cmd = session.commands[idx]["command"]
                channel.send(b"\r" + make_prompt(session.cwd, session.username))
                channel.send(b" " * len(buffer))
                channel.send(b"\r" + make_prompt(session.cwd, session.username))
                channel.send(prev_cmd.encode())
                buffer = prev_cmd
                history_pos += 1
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
