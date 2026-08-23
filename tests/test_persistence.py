"""Tests for event filtering, retention pruning, and blocked-IP persistence."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from baitbox import db
from baitbox import db_sqlite


class _TempDBTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.old_db_name = db.DB_NAME
        self.old_sqlite_db_name = db_sqlite.DB_NAME
        tmp_db = str(Path(self.tmpdir.name) / "events.db")
        db.DB_NAME = tmp_db
        db_sqlite.DB_NAME = tmp_db

    def tearDown(self):
        db.DB_NAME = self.old_db_name
        db_sqlite.DB_NAME = self.old_sqlite_db_name
        asyncio.run(db_sqlite.close_connection())
        self.tmpdir.cleanup()


class EventFilterTests(_TempDBTestCase):
    def _seed(self):
        async def seed():
            await db.init_db()
            await db.log_event("192.0.2.1", "SSH", "auth_attempt", {"username": "root"})
            await db.log_event("192.0.2.1", "SSH", "command", {"command": "id"})
            await db.log_event("198.51.100.7", "HTTP", "request", {"path": "/wp-admin"})
            await db.log_event("198.51.100.9", "Telnet", "auth_attempt", {"username": "admin"})
        asyncio.run(seed())

    def test_filter_by_protocol(self):
        self._seed()

        async def scenario():
            return await db.get_recent_events(50, protocol="SSH")

        events = asyncio.run(scenario())
        assert len(events) == 2
        assert all(e["protocol"] == "SSH" for e in events)

    def test_filter_by_src_ip(self):
        self._seed()

        async def scenario():
            return await db.get_recent_events(50, src_ip="198.51.100.7")

        events = asyncio.run(scenario())
        assert len(events) == 1
        assert events[0]["payload"]["path"] == "/wp-admin"

    def test_filter_by_event_type(self):
        self._seed()

        async def scenario():
            return await db.get_recent_events(50, event_type="auth_attempt")

        events = asyncio.run(scenario())
        assert len(events) == 2

    def test_combined_filters(self):
        self._seed()

        async def scenario():
            return await db.get_recent_events(
                50, protocol="SSH", event_type="command"
            )

        events = asyncio.run(scenario())
        assert len(events) == 1
        assert events[0]["payload"]["command"] == "id"


class RetentionPruneTests(_TempDBTestCase):
    def test_prune_events_removes_only_old_rows(self):
        async def scenario():
            await db.init_db()
            fresh = await db.log_event("192.0.2.5", "SSH", "command", {"command": "whoami"})
            # Insert a stale row directly with an old timestamp
            import aiosqlite
            from baitbox.db_sqlite import _get_db

            conn = await _get_db()
            await conn.execute(
                "INSERT INTO events (timestamp, src_ip, protocol, event_type, payload)"
                " VALUES (?, ?, ?, ?, ?)",
                (
                    "2020-01-01T00:00:00+00:00",
                    "203.0.113.66",
                    "SSH",
                    "command",
                    '{"command": "ancient"}',
                ),
            )
            await conn.commit()

            removed = await db.prune_events(retention_hours=720)
            remaining = await db.get_recent_events(50)
            return removed, remaining, fresh

        removed, remaining, fresh = asyncio.run(scenario())
        self.assertEqual(removed, 1)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["id"], fresh["id"])

    def test_prune_disabled_when_retention_zero(self):
        async def scenario():
            await db.init_db()
            await db.log_event("192.0.2.6", "HTTP", "request", {"path": "/"})
            return await db.prune_events(retention_hours=0)

        self.assertEqual(asyncio.run(scenario()), 0)


class BlockedIPPersistenceTests(_TempDBTestCase):
    def test_block_unblock_round_trip(self):
        async def scenario():
            await db.init_db()
            await db.persist_blocked_ip("203.0.113.10")
            await db.persist_blocked_ip("203.0.113.11")
            blocked = await db.load_blocked_ips()
            await db.persist_unblocked_ip("203.0.113.10")
            after = await db.load_blocked_ips()
            return blocked, after

        blocked, after = asyncio.run(scenario())
        self.assertEqual(blocked, ["203.0.113.10", "203.0.113.11"])
        self.assertEqual(after, ["203.0.113.11"])

    def test_duplicate_block_is_idempotent(self):
        async def scenario():
            await db.init_db()
            await db.persist_blocked_ip("198.51.100.3")
            await db.persist_blocked_ip("198.51.100.3")
            return await db.load_blocked_ips()

        self.assertEqual(asyncio.run(scenario()), ["198.51.100.3"])


if __name__ == "__main__":
    unittest.main()
