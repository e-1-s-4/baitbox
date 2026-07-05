"""Tests for health and readiness endpoints."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from baitbox import db
from baitbox import db_sqlite
from baitbox.servers.http_server import app


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.old_db_name = db.DB_NAME
        self.old_sqlite_db_name = db_sqlite.DB_NAME
        tmp_db = str(Path(self.tmpdir.name) / "events.db")
        db.DB_NAME = tmp_db
        db_sqlite.DB_NAME = tmp_db
        asyncio.run(db.init_db())
        self.client = TestClient(app)

    def tearDown(self):
        db.DB_NAME = self.old_db_name
        db_sqlite.DB_NAME = self.old_sqlite_db_name
        self.tmpdir.cleanup()

    def test_healthz_is_public(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "baitbox")

    def test_readyz_is_public_and_reports_database(self):
        response = self.client.get("/readyz")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ready")
        self.assertTrue(data["events_accessible"])


if __name__ == "__main__":
    unittest.main()
