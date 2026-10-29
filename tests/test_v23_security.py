"""v2.3.0 security tests: JWT logout revocation, auth route additions, metrics auth."""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from baitbox.config import settings
from baitbox.servers.http_server import (
    _revoke_token,
    app,
    create_jwt_token,
    verify_jwt_token,
)


@pytest.fixture()
def client():
    return TestClient(app)


def test_logout_revokes_subsequent_token_use(client):
    token = create_jwt_token("admin")
    assert verify_jwt_token(token) == "admin"

    # Logout with the token presented as a cookie
    client.cookies.set("session_token", token)
    resp = client.get("/logout", follow_redirects=False)
    assert resp.status_code == 307

    # The token is now revoked — API access with it must fail
    resp = client.get("/api/stats")
    assert resp.status_code == 401


def test_logout_revokes_bearer_token(client):
    token = create_jwt_token("admin")
    resp = client.get(
        "/logout",
        headers={"Authorization": f"Bearer {token}"},
        follow_redirects=False,
    )
    assert resp.status_code == 307
    assert verify_jwt_token(token) is None


def test_revoked_token_cannot_reach_websocket_auth():
    token = create_jwt_token("admin")
    _revoke_token(token)
    assert verify_jwt_token(token) is None


def test_websocket_requires_auth():
    """Unauthenticated WebSocket upgrades must be rejected cleanly (no ASGI 500)."""
    from starlette.websockets import WebSocketDisconnect

    c = TestClient(app)
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws/feed"):
            pass  # pragma: no cover - handshake should be refused


def test_websocket_rejects_revoked_token():
    from starlette.websockets import WebSocketDisconnect

    token = create_jwt_token("admin")
    _revoke_token(token)
    c = TestClient(app)
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect(f"/ws/feed?token={token}"):
            pass  # pragma: no cover


def test_unrelated_token_not_affected_by_revocation():
    keep = create_jwt_token("admin")
    burn = create_jwt_token("admin")
    _revoke_token(burn)
    assert verify_jwt_token(keep) == "admin"
    assert verify_jwt_token(burn) is None


def test_token_contains_jti_and_iat():
    token = create_jwt_token("admin")
    payload = pyjwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    assert payload["sub"] == "admin"
    assert payload.get("jti")
    assert payload.get("iat")


def test_metrics_route_requires_auth(client):
    # A browser navigation (Accept: text/html) bounces to /login…
    resp = client.get("/metrics", follow_redirects=False, headers={"Accept": "text/html"})
    assert resp.status_code == 307
    assert resp.headers["location"] == "/login"
    # …while a Prometheus scraper gets a clean 401 rather than a redirect it
    # would not follow (TestClient's default Accept is */*).
    resp2 = client.get("/metrics", follow_redirects=False)
    assert resp2.status_code == 401


def test_ioc_route_requires_auth(client):
    resp = client.get("/api/ioc")
    assert resp.status_code == 401


def test_metrics_route_serves_prometheus_when_authenticated(client, monkeypatch):
    from baitbox.servers import http_server

    monkeypatch.setattr(
        http_server, "verify_jwt_token", lambda token: "admin" if token else None
    )
    client.cookies.set("session_token", "fake-token-for-test")
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "baitbox_events_total" in resp.text
    assert "text/plain" in resp.headers["content-type"]


def test_login_html_has_content_security_policy(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "base-uri 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    # External sources the dashboard legitimately needs must be allow-listed
    assert "https://unpkg.com" in csp
    assert "https://cdn.jsdelivr.net" in csp
    assert "https://fonts.googleapis.com" in csp
    assert "https://fonts.gstatic.com" in csp
    assert "https://server.arcgisonline.com" in csp


def test_dashboard_html_has_content_security_policy(client, monkeypatch):
    from baitbox.servers import http_server

    monkeypatch.setattr(
        http_server, "verify_jwt_token", lambda token: "admin" if token else None
    )
    client.cookies.set("session_token", "fake-token-for-test")
    resp = client.get("/")
    assert resp.status_code == 200
    assert "content-security-policy" in resp.headers


def test_non_html_response_has_no_csp(client):
    resp = client.get("/healthz")
    assert "text/html" not in resp.headers.get("content-type", "")
    assert "content-security-policy" not in resp.headers
