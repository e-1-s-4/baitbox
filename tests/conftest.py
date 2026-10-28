"""Shared pytest configuration for the BaitBox test suite.

The SQLite backend keeps a single long-lived ``aiosqlite`` connection.  That
connection is backed by a non-daemon thread, so leaving it open after the last
test both keeps the interpreter alive (the suite appears to hang) and holds a
file lock on the temporary database (``WinError 32`` during cleanup on
Windows).  Closing it after every test keeps the suite deterministic and
portable.

The default database path is also redirected into a per-test temporary
directory so a plain ``pytest`` run never creates or mutates ``baitbox.db`` in
the checkout.
"""

from __future__ import annotations

import asyncio

import pytest

from baitbox import db, db_sqlite


@pytest.fixture(autouse=True)
def _isolate_default_database(tmp_path, monkeypatch):
    """Point the default SQLite path at a throwaway file for every test."""
    test_db = str(tmp_path / "baitbox-test.db")
    monkeypatch.setattr(db, "DB_NAME", test_db)
    monkeypatch.setattr(db_sqlite, "DB_NAME", test_db)
    yield


@pytest.fixture(autouse=True)
def _close_sqlite_connection():
    """Yield the test, then release the shared SQLite connection."""
    yield
    try:
        asyncio.run(db_sqlite.close_connection())
    except Exception:
        pass
