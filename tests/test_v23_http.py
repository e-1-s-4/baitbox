"""v2.3.0 HTTP honeypot tests: new decoys and event pagination."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from baitbox.db import init_db, log_event
from baitbox.servers.http_server import (
    _FAKE_PHPINFO,
    _FAKE_ROBOTS,
    _fake_wp_users,
    _is_probe_path,
    app,
)


@pytest.fixture()
def client():
    return TestClient(app)


def test_robots_txt_decoy_lists_hidden_paths():
    assert "Disallow: /admin" in _FAKE_ROBOTS
    assert "Disallow: /backup.sql" in _FAKE_ROBOTS
    assert "Disallow: /.env" in _FAKE_ROBOTS
    assert "User-agent: *" in _FAKE_ROBOTS


def test_wp_json_users_decoy():
    users = _fake_wp_users()
    assert isinstance(users, list)
    assert {u["slug"] for u in users} >= {"admin", "deploy"}


def test_phpinfo_decoy_contains_php_banner():
    rendered = _FAKE_PHPINFO.format(hostname="web-prod-01")
    assert "PHP Version" in rendered
    assert "web-prod-01" in rendered


def test_git_head_is_probe_path():
    assert _is_probe_path("/.git/HEAD")
    assert _is_probe_path("/wp-json/wp/v2/users")


def test_favicon_route_does_not_hit_catch_all(client):
    resp = client.get("/favicon.ico")
    assert resp.status_code == 200
    assert "svg" in resp.headers["content-type"]


def test_healthz_reports_version(client):
    from baitbox import __version__

    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["version"] == __version__


def test_events_endpoint_supports_offset():
    async def _seed():
        await init_db()
        for i in range(6):
            await log_event(
                "203.0.113.80",
                "HTTP",
                "request",
                {"path": f"/offset-check-{i}", "method": "GET"},
            )

    asyncio.run(_seed())
    with TestClient(app) as c:
        from baitbox.servers import http_server

        orig = http_server.verify_jwt_token
        http_server.verify_jwt_token = lambda token: "admin" if token else None
        c.cookies.set("session_token", "fake-token-for-test")
        try:
            first = c.get("/api/events?limit=3").json()
            second = c.get("/api/events?limit=3&offset=3").json()
        finally:
            http_server.verify_jwt_token = orig
        assert len(first) == 3
        assert len(second) == 3
        first_ids = {e["id"] for e in first}
        second_ids = {e["id"] for e in second}
        assert first_ids.isdisjoint(second_ids)


def test_transcript_endpoint_404_for_unknown_session(client):
    from baitbox.servers import http_server

    orig = http_server.verify_jwt_token
    http_server.verify_jwt_token = lambda token: "admin" if token else None
    client.cookies.set("session_token", "fake-token-for-test")
    try:
        resp = client.get("/api/sessions/does-not-exist/transcript")
    finally:
        http_server.verify_jwt_token = orig
    assert resp.status_code == 404
