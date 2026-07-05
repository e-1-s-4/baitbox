"""FastAPI dashboard and HTTP honeypot routes."""

from __future__ import annotations

import csv
import io
import json
from http.cookies import SimpleCookie
from ipaddress import ip_address
from urllib.parse import parse_qs
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware

from ..db import get_recent_events, get_stats, log_event
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


def create_jwt_token(username: str, expires_delta: dt.timedelta | None = None) -> str:
    """Create a signed dashboard session token for a username."""
    if expires_delta is None:
        expires_delta = dt.timedelta(hours=settings.jwt_expiry_hours)
    payload = {
        "sub": username,
        "exp": dt.datetime.now(dt.UTC) + expires_delta,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def verify_jwt_token(token: str) -> str | None:
    """Return the authenticated username for a valid token, otherwise ``None``."""
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


async def verify_user_credentials(username: str, password: str) -> bool:
    """Validate dashboard credentials against the configured bcrypt hash."""
    password_hash = await get_user_password_hash(username)
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
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
                    await self._send_http_error(send, 403, "Forbidden")
                    return
                elif path.startswith("/api/"):
                    await self._send_http_error(send, 401, "Unauthorized")
                    return
                else:
                    await self._send_redirect(send, "/login")
                    return

        await self.app(scope, receive, send)

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
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"geolocation=(), microphone=(), camera=()"),
                ]
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
    version="2.1.0",
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuthMiddleware)
# Note: CORS is permissive for honeypot purposes to capture all traffic
# In production, consider restricting to specific origins if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_DASHBOARD_API_EXACT_PATHS = {
    "/api/events",
    "/api/events/export",
    "/api/stats",
    "/api/sessions",
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
    "/admin/", "/wp-content/", "/wp-includes/", "/node_modules/",
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


def _client_ip(request: Request) -> str:
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
    except Exception:
        pass
    return event


async def _request_payload(request: Request) -> dict[str, Any]:
    """Safely extract and truncate request payload for logging."""
    try:
        body = await request.body()
    except Exception:
        body = b""
    
    truncated = len(body) > settings.http_max_body_bytes
    if truncated:
        body = body[: settings.http_max_body_bytes]

    form_data: dict[str, Any] = {}
    if body:
        content_type = request.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                try:
                    form_data = json.loads(body.decode("utf-8", errors="replace"))
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
    return LOGIN_HTML.read_text(encoding="utf-8")


@app.post("/login")
@app.post("/api/auth/login")
async def login(username: str = Form(...), password: str = Form(...)) -> Response:
    if await verify_user_credentials(username, password):
        token = create_jwt_token(username)
        response = JSONResponse({"status": "ok"})
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=24 * 60 * 60,
            secure=settings.session_cookie_secure,
        )
        return response
    return JSONResponse(
        {"detail": "Invalid username or password"},
        status_code=401
    )


@app.get("/logout")
async def logout() -> Response:
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
async def api_events(limit: int = 100) -> list[dict[str, Any]]:
    events = await get_recent_events(limit=_limit_value(limit))
    return [_enrich_event(ev) for ev in events]


@app.get("/api/events/export")
async def api_events_export(limit: int = 500, format: str = "json") -> Response:
    """Export recent events as JSON or CSV for incident review."""
    events = await get_recent_events(limit=_limit_value(limit, maximum=5000))
    if format.lower() == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["id", "timestamp", "src_ip", "protocol", "event_type", "payload"],
        )
        writer.writeheader()
        for event in events:
            writer.writerow({**event, "payload": json.dumps(event.get("payload", {}), sort_keys=True)})
        return Response(
            output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=baitbox-events.csv"},
        )

    return JSONResponse({"events": events, "count": len(events)})


@app.get("/api/stats")
async def api_stats() -> dict[str, Any]:
    stats = await get_stats()
    # Append rate-limit data
    stats["top_connections"] = get_connection_counts()[:10]
    stats["blocked_ips"] = get_blocked_ips()
    return stats


@app.get("/api/sessions")
async def api_sessions() -> list[dict[str, Any]]:
    from ..sessions import session_manager
    sessions = session_manager.list_sessions()
    return [_enrich_event(s) for s in sessions]



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
    # Also terminate any active SSH sessions from this IP
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

    # .env file decoy - return fake env to entice credential harvesting bots
    if request.url.path in ("/.env", "/env", "/.env.local"):
        return Response(_FAKE_ENV, media_type="text/plain", status_code=200)

    # .git/config decoy
    if "/.git" in request.url.path:
        return Response(
            "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://github.com/example/production.git\n",
            media_type="text/plain", status_code=200,
        )

    if request.url.path in _DECOY_PATHS or _is_probe_path(request.url.path):
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
