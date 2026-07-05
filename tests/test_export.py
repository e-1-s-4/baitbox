"""Tests for event export API."""

from __future__ import annotations

import asyncio
import csv
import io
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from baitbox import db
from baitbox import db_sqlite
from baitbox.servers.http_server import app


def _setup_client():
    tmpdir = tempfile.TemporaryDirectory()
    tmp_db = str(Path(tmpdir.name) / "events.db")
    db.DB_NAME = tmp_db
    db_sqlite.DB_NAME = tmp_db
    asyncio.run(db.init_db())
    asyncio.run(db.log_event("203.0.113.5", "HTTP", "credential_probe", {"path": "/.env", "method": "GET"}))
    client = TestClient(app)
    client.post("/login", data={"username": "admin", "password": "admin"})
    return client, tmpdir


def test_export_json_requires_auth():
    client, tmpdir = _setup_client()
    try:
        unauth = TestClient(app)
        assert unauth.get("/api/events/export?format=json").status_code == 401
        res = client.get("/api/events/export?format=json&limit=10")
        assert res.status_code == 200
        body = res.json()
        assert body["count"] >= 1
        assert body["events"][0]["src_ip"] == "203.0.113.5"
    finally:
        tmpdir.cleanup()


def test_export_csv_format():
    client, tmpdir = _setup_client()
    try:
        res = client.get("/api/events/export?format=csv&limit=10")
        assert res.status_code == 200
        assert "text/csv" in res.headers["content-type"]
        rows = list(csv.DictReader(io.StringIO(res.text)))
        assert rows[0]["src_ip"] == "203.0.113.5"
        assert rows[0]["protocol"] == "HTTP"
    finally:
        tmpdir.cleanup()
