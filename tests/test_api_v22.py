"""API-level tests: event query filters, POST /logout, CSV export columns."""

import asyncio
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from baitbox import db
from baitbox import db_sqlite
from baitbox.servers.http_server import APP_VERSION, app, create_jwt_token


class ApiV22Tests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.old_db_name = db.DB_NAME
        self.old_sqlite_db_name = db_sqlite.DB_NAME
        tmp_db = str(Path(self.tmpdir.name) / "events.db")
        db.DB_NAME = tmp_db
        db_sqlite.DB_NAME = tmp_db

        async def seed():
            await db.init_db()
            await db.log_event("192.0.2.1", "SSH", "auth_attempt", {"username": "root", "password": "x"})
            await db.log_event("198.51.100.7", "HTTP", "request", {"path": "/wp-admin"})
            await db.log_event("198.51.100.9", "Telnet", "auth_attempt", {"username": "admin"})

        asyncio.run(seed())
        self.client = TestClient(app)
        self.token = create_jwt_token("admin")

    def tearDown(self):
        db.DB_NAME = self.old_db_name
        db_sqlite.DB_NAME = self.old_sqlite_db_name
        asyncio.run(db_sqlite.close_connection())
        self.tmpdir.cleanup()

    def _auth_get(self, url):
        return self.client.get(url, cookies={"session_token": self.token})

    def test_events_filter_protocol_param(self):
        response = self._auth_get("/api/events?protocol=HTTP")
        self.assertEqual(response.status_code, 200)
        events = response.json()
        assert len(events) == 1
        self.assertEqual(events[0]["protocol"], "HTTP")

    def test_events_filter_src_ip_param(self):
        response = self._auth_get("/api/events?src_ip=192.0.2.1")
        events = response.json()
        assert len(events) == 1
        self.assertEqual(events[0]["payload"]["username"], "root")

    def test_events_filter_event_type_param(self):
        response = self._auth_get("/api/events?event_type=auth_attempt")
        events = response.json()
        assert len(events) == 2

    def test_post_logout_redirects_and_clears_cookie(self):
        response = self.client.post("/logout", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers.get("location"), "/login")
        set_cookie = response.headers.get("set-cookie", "")
        self.assertIn("session_token=", set_cookie)

    def test_csv_export_includes_threat_columns(self):
        response = self._auth_get("/api/events/export?format=csv&limit=100")
        self.assertEqual(response.status_code, 200)
        header_line = response.text.splitlines()[0]
        self.assertIn("threat_score", header_line)
        self.assertIn("threat_level", header_line)

    def test_app_version_bumped(self):
        self.assertEqual(APP_VERSION, "2.3.0")

    def test_simulate_accepts_non_dict_json(self):
        """A JSON array body must not 500 the authenticated simulate endpoint."""
        response = self.client.post(
            "/api/simulate",
            json=[1, 2, 3],
            cookies={"session_token": self.token},
        )
        self.assertNotEqual(response.status_code, 500)
        self.assertIn(response.status_code, (200, 400, 422))

    def test_simulate_scalar_json(self):
        response = self.client.post(
            "/api/simulate",
            content=b"12345",
            headers={"Content-Type": "application/json"},
            cookies={"session_token": self.token},
        )
        self.assertNotEqual(response.status_code, 500)

    def test_request_payload_non_dict_json_is_coerced(self):
        """_request_payload must always return a dict for logged events."""
        import asyncio
        from starlette.requests import Request
        from baitbox.servers.http_server import _request_payload

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/x",
            "raw_path": b"/x",
            "query_string": b"",
            "root_path": "",
            "headers": [(b"content-type", b"application/json")],
            "client": ("127.0.0.1", 1234),
            "server": ("test", 80),
        }
        body = b"[1, 2, 3]"
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        request = Request(scope, receive)
        payload = asyncio.run(_request_payload(request))
        self.assertIsInstance(payload, dict)
        self.assertIsInstance(payload.get("body"), dict)


if __name__ == "__main__":
    unittest.main()
