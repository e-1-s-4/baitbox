import asyncio
import tempfile
import unittest
from pathlib import Path

from baitbox import db
from baitbox import db_sqlite


class DatabaseTests(unittest.TestCase):
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
        self.tmpdir.cleanup()

    def test_event_round_trip_decodes_payload_and_orders_oldest_first(self):
        async def scenario():
            await db.init_db()
            first = await db.log_event("192.0.2.1", "SSH", "auth_attempt", {"username": "root", "password": "toor"})
            second = await db.log_event("198.51.100.2", "HTTP", "request", {"path": "/wp-admin"})
            await db.log_event("192.0.2.1", "SSH", "command", {"command": "cat /etc/passwd"})
            events = await db.get_recent_events()
            stats = await db.get_stats()
            return first, second, events, stats

        first, second, events, stats = asyncio.run(scenario())

        self.assertEqual([event["id"] for event in events], [first["id"], second["id"], second["id"] + 1])
        self.assertEqual(events[0]["payload"]["password"], "toor")
        self.assertEqual(stats["total_events"], 3)
        self.assertEqual({row["src_ip"] for row in stats["top_ips"]}, {"192.0.2.1", "198.51.100.2"})
        self.assertEqual(stats["top_passwords"][0]["password"], "toor")
        self.assertEqual(stats["recent_commands"][0]["command"], "cat /etc/passwd")
        self.assertIn({"event_type": "command", "count": 1}, stats["by_event_type"])


class GeoIPCacheTests(unittest.TestCase):
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
        self.tmpdir.cleanup()

    def test_geoip_cache_round_trip_and_expiry(self):
        async def scenario():
            await db.init_db()
            data = {"ip": "203.0.113.10", "country": "Example", "threat_score": 40}
            await db.set_geoip_cache("203.0.113.10", data, ttl=60)
            cached = await db.get_geoip_cache("203.0.113.10")
            await db.set_geoip_cache("203.0.113.11", {"ip": "203.0.113.11"}, ttl=-1)
            expired = await db.get_geoip_cache("203.0.113.11")
            return cached, expired

        cached, expired = asyncio.run(scenario())

        self.assertEqual(cached["country"], "Example")
        self.assertEqual(cached["threat_score"], 40)
        self.assertIsNone(expired)


if __name__ == "__main__":
    unittest.main()
