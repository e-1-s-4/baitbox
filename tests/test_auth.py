import asyncio
import tempfile
import unittest
from pathlib import Path
import datetime as dt

from fastapi.testclient import TestClient

from baitbox import db
from baitbox import db_sqlite
from baitbox.config import settings
from baitbox.servers.http_server import app, create_jwt_token, verify_jwt_token, verify_user_credentials


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.old_db_name = db.DB_NAME
        self.old_sqlite_db_name = db_sqlite.DB_NAME
        tmp_db = str(Path(self.tmpdir.name) / "events.db")
        db.DB_NAME = tmp_db
        db_sqlite.DB_NAME = tmp_db

        # Initialize test DB with default admin user
        async def init():
            await db.init_db()
        asyncio.run(init())

        # TestClient automatically handles middleware/routes
        self.client = TestClient(app)

    def tearDown(self):
        db.DB_NAME = self.old_db_name
        db_sqlite.DB_NAME = self.old_sqlite_db_name
        self.tmpdir.cleanup()

    def test_verify_jwt_token(self):
        token = create_jwt_token("test-user")
        user = verify_jwt_token(token)
        self.assertEqual(user, "test-user")

        invalid = verify_jwt_token("invalid-token")
        self.assertIsNone(invalid)

    def test_expired_jwt_token_is_rejected(self):
        token = create_jwt_token("test-user", expires_delta=dt.timedelta(seconds=-1))
        self.assertIsNone(verify_jwt_token(token))

    def test_verify_user_credentials(self):
        async def verify():
            # default credentials from config are "admin" / "admin"
            valid = await verify_user_credentials("admin", "admin")
            invalid_pw = await verify_user_credentials("admin", "wrong-password")
            invalid_user = await verify_user_credentials("wrong-user", "admin")
            return valid, invalid_pw, invalid_user

        valid, invalid_pw, invalid_user = asyncio.run(verify())
        self.assertTrue(valid)
        self.assertFalse(invalid_pw)
        self.assertFalse(invalid_user)

    def test_dashboard_redirects_when_unauthenticated(self):
        # We use follow_redirects=False to verify the 307 Redirect header itself
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers.get("location"), "/login")

    def test_api_unauthorized_when_unauthenticated(self):
        response = self.client.get("/api/events")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"detail": "Unauthorized"})

    def test_api_auth_login_alias_sets_cookie(self):
        response = self.client.post("/api/auth/login", data={"username": "admin", "password": "admin"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("session_token", response.cookies)

    def test_login_success_sets_cookie(self):
        # Perform POST /login with correct credentials
        response = self.client.post("/login", data={"username": "admin", "password": "admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})
        self.assertIn("session_token", response.cookies)

        # Access protected endpoint with cookie
        cookie_val = response.cookies["session_token"]
        response2 = self.client.get("/api/events", cookies={"session_token": cookie_val})
        self.assertEqual(response2.status_code, 200)

    def test_login_failure_returns_401(self):
        response = self.client.post("/login", data={"username": "admin", "password": "wrong"})
        self.assertEqual(response.status_code, 401)
        self.assertNotIn("session_token", response.cookies)

    def test_logout_clears_cookie_and_redirects(self):
        response = self.client.get("/logout", follow_redirects=False)
        self.assertEqual(response.status_code, 307)
        self.assertEqual(response.headers.get("location"), "/login")
        # cookie should be deleted (have an empty value or max-age=0/expires in past)
        # We can verify that the response set-cookie header contains max-age=0 or similar
        set_cookie = response.headers.get("set-cookie", "")
        self.assertTrue("session_token=" in set_cookie)
        self.assertTrue("Max-Age=0" in set_cookie or 'expires=' in set_cookie.lower())

    def test_bearer_token_authenticates_api(self):
        token = create_jwt_token("admin")
        response = self.client.get("/api/events", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(response.status_code, 200)

    def test_honeypot_endpoints_not_blocked_by_auth(self):
        # Honeypot paths must not be intercepted by auth
        response = self.client.get("/wp-admin")
        self.assertNotEqual(response.status_code, 401)
        self.assertNotEqual(response.status_code, 307)
        self.assertEqual(response.status_code, 200)  # standard decoy page


if __name__ == "__main__":
    unittest.main()
