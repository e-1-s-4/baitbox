import asyncio
from types import SimpleNamespace

from baitbox.ratelimit import block_ip, unblock_ip
from baitbox.servers.http_server import honeypot


class FakeRequest:
    method = "GET"
    headers = {"x-forwarded-for": "203.0.113.42"}
    client = SimpleNamespace(host="198.51.100.99")
    url = SimpleNamespace(path="/wp-admin", query="")

    async def body(self):
        return b""


def test_blocked_ip_is_rejected_before_honeypot_response():
    ip = "203.0.113.42"
    block_ip(ip)
    try:
        response = asyncio.run(honeypot(FakeRequest(), "wp-admin"))
    finally:
        unblock_ip(ip)

    assert response.status_code == 403
    assert response.body == b'{"status":"blocked"}'


def test_rate_limited_ip_is_rejected_before_honeypot_response(monkeypatch):
    from baitbox.servers import http_server

    monkeypatch.setattr(http_server, "is_rate_limited", lambda src_ip, protocol: True)
    response = asyncio.run(honeypot(FakeRequest(), "wp-admin"))
    assert response.status_code == 429
    assert response.body == b'{"status":"rate_limited"}'


def test_is_probe_path_detects_common_scanner_targets():
    from baitbox.servers.http_server import _is_probe_path

    assert _is_probe_path("/wp-admin")
    assert _is_probe_path("/backup.sql")
    assert _is_probe_path("/.git/HEAD")
    assert _is_probe_path("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")
    assert not _is_probe_path("/favicon.ico")


def test_payload_is_truncated_before_logging(monkeypatch):
    from baitbox.servers import http_server

    class LargeBodyRequest(FakeRequest):
        method = "POST"
        headers = {"content-type": "text/plain"}
        url = SimpleNamespace(path="/upload", query="")

        async def body(self):
            return b"x" * 20

    monkeypatch.setattr(http_server, "settings", SimpleNamespace(http_max_body_bytes=8))
    payload = asyncio.run(http_server._request_payload(LargeBodyRequest()))

    assert payload["body_truncated"] is True
    assert payload["body"] == {"raw_body": "xxxxxxxx"}


def test_ip_validation_normalizes_ipv4_and_rejects_bad_values():
    from baitbox.servers.http_server import _validate_ip

    assert _validate_ip("203.0.113.42") == "203.0.113.42"

    try:
        _validate_ip("not-an-ip")
    except ValueError as exc:
        assert "Invalid IP address" in str(exc)
    else:
        raise AssertionError("invalid IP was accepted")


def test_client_ip_ignores_malformed_forwarded_for_header():
    from baitbox.servers.http_server import _client_ip

    class BadForwardedRequest(FakeRequest):
        headers = {"x-forwarded-for": "not-an-ip, 203.0.113.10"}

    assert _client_ip(BadForwardedRequest()) == "198.51.100.99"


def test_auth_route_matching_leaves_api_scanner_decoys_public():
    from baitbox.servers.http_server import _is_dashboard_route

    assert _is_dashboard_route("/api/events")
    assert _is_dashboard_route("/api/block/203.0.113.42")
    assert not _is_dashboard_route("/api/v1/users")
    assert not _is_dashboard_route("/api/.env")
