"""Tests for the enhanced VFS module."""

from __future__ import annotations
import pytest
from baitbox.vfs import VirtualFilesystem


@pytest.fixture()
def vfs():
    return VirtualFilesystem()


# ── Basic existence ────────────────────────────────────────────────────────

def test_root_exists(vfs):
    assert vfs.exists("/")
    assert vfs.is_dir("/")


def test_etc_passwd_is_file(vfs):
    assert vfs.is_file("/etc/passwd")
    assert not vfs.is_dir("/etc/passwd")


def test_etc_dir(vfs):
    assert vfs.is_dir("/etc")


def test_root_dir(vfs):
    assert vfs.is_dir("/root")


# ── New VFS paths ─────────────────────────────────────────────────────────

def test_bash_history_exists(vfs):
    assert vfs.is_file("/root/.bash_history")
    content = vfs.read_file("/root/.bash_history")
    assert b"mysql" in content


def test_bashrc_contains_env(vfs):
    content = vfs.read_file("/root/.bashrc")
    assert content is not None
    assert b"DB_PASS" in content


def test_ssh_authorized_keys(vfs):
    assert vfs.is_file("/root/.ssh/authorized_keys")
    content = vfs.read_file("/root/.ssh/authorized_keys")
    assert b"ssh-rsa" in content


def test_env_file(vfs):
    assert vfs.is_file("/var/www/html/.env")
    content = vfs.read_file("/var/www/html/.env")
    assert b"DB_PASSWORD" in content


def test_shadow_file(vfs):
    assert vfs.is_file("/etc/shadow")
    content = vfs.read_file("/etc/shadow")
    assert b"root" in content


def test_proc_cpuinfo(vfs):
    assert vfs.is_file("/proc/cpuinfo")
    content = vfs.read_file("/proc/cpuinfo")
    assert b"Intel" in content


def test_nginx_conf(vfs):
    assert vfs.is_file("/etc/nginx/nginx.conf")


def test_var_log_auth(vfs):
    assert vfs.is_file("/var/log/auth.log")
    content = vfs.read_file("/var/log/auth.log")
    assert b"sshd" in content


# ── Path normalisation ────────────────────────────────────────────────────

def test_normalize_relative(vfs):
    assert vfs._normalize_path("/root", "backups.tar.gz") == "/root/backups.tar.gz"


def test_normalize_dotdot(vfs):
    assert vfs._normalize_path("/var/www/html", "../../log") == "/var/log"


def test_normalize_absolute_passthrough(vfs):
    assert vfs._normalize_path("/tmp", "/etc/passwd") == "/etc/passwd"


# ── List directory ────────────────────────────────────────────────────────

def test_list_root(vfs):
    items = vfs.list_dir("/")
    assert "etc" in items
    assert "root" in items
    assert "var" in items
    assert "tmp" in items


def test_list_root_hidden_files(vfs):
    items = vfs.list_dir("/root")
    assert ".bash_history" in items
    assert ".bashrc" in items
    assert "secrets.txt" in items


def test_list_nonexistent_returns_none(vfs):
    assert vfs.list_dir("/nonexistent") is None


# ── Read file ─────────────────────────────────────────────────────────────

def test_read_secrets(vfs):
    content = vfs.read_file("/root/secrets.txt")
    assert content is not None
    assert b"MOCK" in content


def test_read_nonexistent(vfs):
    assert vfs.read_file("/nonexistent/file") is None


def test_read_dir_returns_none(vfs):
    assert vfs.read_file("/etc") is None


# ── Write, mkdir, rm ──────────────────────────────────────────────────────

def test_write_and_read(vfs):
    assert vfs.write_file("/tmp/test.txt", b"hello")
    assert vfs.read_file("/tmp/test.txt") == b"hello"


def test_write_to_missing_parent_fails(vfs):
    assert not vfs.write_file("/nonexistent/dir/file.txt", b"data")


def test_mkdir_and_list(vfs):
    assert vfs.mkdir("/tmp/mydir")
    assert vfs.is_dir("/tmp/mydir")
    assert "mydir" in vfs.list_dir("/tmp")


def test_rm_file(vfs):
    vfs.write_file("/tmp/to_delete.txt", b"bye")
    assert vfs.rm("/tmp/to_delete.txt")
    assert not vfs.exists("/tmp/to_delete.txt")


def test_rm_dir_fails(vfs):
    assert not vfs.rm("/tmp")


def test_rmdir_nonempty_fails(vfs):
    # /root has children
    assert not vfs.rmdir("/root")


def test_rmdir_empty(vfs):
    vfs.mkdir("/tmp/emptydir")
    assert vfs.rmdir("/tmp/emptydir")
    assert not vfs.exists("/tmp/emptydir")


# ── Stat ──────────────────────────────────────────────────────────────────

def test_stat_file(vfs):
    info = vfs.stat("/etc/passwd")
    assert info is not None
    assert info["type"] == "file"
    assert info["size"] > 0


def test_stat_dir(vfs):
    info = vfs.stat("/etc")
    assert info is not None
    assert info["type"] == "directory"
    assert info["mode"].startswith("d")


def test_stat_nonexistent(vfs):
    assert vfs.stat("/does/not/exist") is None


# ── Copy / Move ───────────────────────────────────────────────────────────

def test_copy_file(vfs):
    vfs.write_file("/tmp/original.txt", b"original")
    assert vfs.copy("/tmp/original.txt", "/tmp/copy.txt")
    assert vfs.read_file("/tmp/copy.txt") == b"original"
    assert vfs.read_file("/tmp/original.txt") == b"original"


def test_move_file(vfs):
    vfs.write_file("/tmp/moveme.txt", b"moving")
    assert vfs.move("/tmp/moveme.txt", "/tmp/moved.txt")
    assert vfs.read_file("/tmp/moved.txt") == b"moving"
    assert not vfs.exists("/tmp/moveme.txt")


# ── Grep ─────────────────────────────────────────────────────────────────

def test_grep_found(vfs):
    results = vfs.grep("root", "/etc/passwd")
    assert len(results) >= 1
    assert all("root" in line.lower() for line in results)


def test_grep_not_found(vfs):
    results = vfs.grep("zzznomatch999", "/etc/passwd")
    assert results == []


def test_grep_nonexistent_file(vfs):
    results = vfs.grep("anything", "/nonexistent")
    assert results == []


# ── Find ─────────────────────────────────────────────────────────────────

def test_find_under_root(vfs):
    results = vfs.find("/root")
    assert "/root/secrets.txt" in results
    assert "/root/.bash_history" in results


def test_find_with_name_filter(vfs):
    results = vfs.find("/", "passwd")
    assert any("passwd" in r for r in results)


def test_find_nonexistent_root(vfs):
    results = vfs.find("/nonexistent")
    assert results == []
