"""BaitBox entry point — starts all honeypot servers concurrently."""

from __future__ import annotations

import asyncio
import signal
import threading
import logging

import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .async_bridge import set_main_loop
from .config import settings
from .db import close_db, init_db, load_blocked_ips, prune_events
from . import __version__
from .ratelimit import load_blocked_ips as apply_blocked_ips
from .servers.http_server import app
from .servers.ssh_server import start_ssh_server
from .sessions import session_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("baitbox")

console = Console()
_SHUTDOWN = asyncio.Event()


async def retention_loop() -> None:
    """Periodically prune old events according to the configured retention."""
    hours = settings.event_retention_hours
    if hours <= 0:
        return
    while True:
        try:
            await asyncio.sleep(3600)
            removed = await prune_events(hours)
            if removed:
                logger.info("Event retention: pruned %s events older than %sh", removed, hours)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Event retention error: %s", exc)


async def seed_initial_telemetry() -> None:
    """Populate baseline telemetry if database is empty so dashboard is immediately rich and interactive."""
    from .db import get_recent_events, log_event
    from .ratelimit import record_connection
    from .geoip import cache_geo
    import time

    try:
        existing = await get_recent_events(limit=1)
        if existing:
            return

        seeds = [
            ("185.220.101.42", "SSH", "auth_attempt", {"username": "root", "password": "password123", "method": "password"},
             {"city": "Frankfurt", "country": "Germany", "countryCode": "DE", "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Node", "threat_score": 85}),
            ("185.220.101.42", "SSH", "auth_attempt", {"username": "admin", "password": "password", "method": "password"},
             {"city": "Frankfurt", "country": "Germany", "countryCode": "DE", "lat": 50.1109, "lon": 8.6821, "isp": "Tor Exit Node", "threat_score": 85}),
            ("45.154.255.89", "HTTP", "credential_probe", {"method": "GET", "path": "/.env", "query": "", "user_agent": "curl/7.88.1", "headers": {"host": "web-prod-01"}},
             {"city": "Amsterdam", "country": "Netherlands", "countryCode": "NL", "lat": 52.3676, "lon": 4.9041, "isp": "Datawagon VPS", "threat_score": 70}),
            ("45.154.255.89", "HTTP", "credential_probe", {"method": "GET", "path": "/.git/HEAD", "query": "", "user_agent": "python-requests/2.31.0", "headers": {"host": "web-prod-01"}},
             {"city": "Amsterdam", "country": "Netherlands", "countryCode": "NL", "lat": 52.3676, "lon": 4.9041, "isp": "Datawagon VPS", "threat_score": 70}),
            ("194.26.29.112", "HTTP", "credential_probe", {"method": "GET", "path": "/wp-login.php", "query": "", "user_agent": "Mozilla/5.0 WPScan/3.8.22", "headers": {"host": "web-prod-01"}},
             {"city": "Moscow", "country": "Russia", "countryCode": "RU", "lat": 55.7558, "lon": 37.6173, "isp": "Aeza Hosting", "threat_score": 75}),
            ("103.149.28.18", "SSH", "auth_attempt", {"username": "ubuntu", "password": "ubuntu", "method": "password"},
             {"city": "Tokyo", "country": "Japan", "countryCode": "JP", "lat": 35.6762, "lon": 139.6503, "isp": "Cloud Hosting JP", "threat_score": 65}),
            ("103.149.28.18", "SSH", "command", {"command": "uname -a", "cwd": "/home/ubuntu"},
             {"city": "Tokyo", "country": "Japan", "countryCode": "JP", "lat": 35.6762, "lon": 139.6503, "isp": "Cloud Hosting JP", "threat_score": 80}),
            ("198.51.100.77", "HTTP", "credential_probe", {"method": "GET", "path": "/actuator/env", "query": "", "user_agent": "masscan/1.3.2", "headers": {"host": "web-prod-01"}},
             {"city": "San Francisco", "country": "United States", "countryCode": "US", "lat": 37.7749, "lon": -122.4194, "isp": "DigitalOcean LLC", "threat_score": 60}),
            ("177.54.144.12", "Telnet", "auth_attempt", {"username": "admin", "password": "admin", "method": "password"},
             {"city": "São Paulo", "country": "Brazil", "countryCode": "BR", "lat": -23.5505, "lon": -46.6333, "isp": "Telnet Botnet ISP", "threat_score": 85}),
            ("177.54.144.12", "Telnet", "command", {"command": "cat /etc/passwd", "cwd": "/root"},
             {"city": "São Paulo", "country": "Brazil", "countryCode": "BR", "lat": -23.5505, "lon": -46.6333, "isp": "Telnet Botnet ISP", "threat_score": 90}),
        ]

        for ip, proto, ev_type, payload, geo in seeds:
            await log_event(ip, proto, ev_type, payload)
            record_connection(ip, proto)
            geo_data = dict(geo)
            geo_data["ip"] = ip
            cache_geo(ip, geo_data)
        logger.info("Seeded %s baseline telemetry events for immediate interactive command center", len(seeds))
    except Exception as exc:
        logger.debug("Telemetry seeding skipped: %s", exc)


async def main() -> None:
    """Main entry point that initializes and starts all honeypot servers."""
    logger.info("Starting BaitBox honeypot v%s...", __version__)
    loop = asyncio.get_running_loop()
    set_main_loop(loop)

    # ── FastAPI (Dashboard + HTTP Honeypot) ─────────────────────────────────
    logger.info(f"Starting HTTP dashboard on {settings.dashboard_host}:{settings.dashboard_port}")
    config = uvicorn.Config(
        app,
        host=settings.dashboard_host,
        port=settings.dashboard_port,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    serve_task = asyncio.create_task(server.serve())

    # Initialize Database
    try:
        await init_db()
        logger.info("Database initialized successfully")
        if settings.seed_demo_data:
            await seed_initial_telemetry()
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

    # Restore persisted IP block list
    try:
        blocked = await load_blocked_ips()
        if blocked:
            apply_blocked_ips(blocked)
            logger.info("Restored %s persisted IP block(s)", len(blocked))
    except Exception as exc:
        logger.warning("Could not restore blocked IPs: %s", exc)

    # Start session cleanup task if enabled
    if settings.enable_session_cleanup:
        session_manager.start_cleanup_task(interval_seconds=settings.session_cleanup_interval)

    # Start event-retention pruning loop (no-op when retention is disabled)
    retention_task = asyncio.create_task(retention_loop())

    if settings.dashboard_password == "admin" or settings.jwt_secret == "baitbox-super-secret-key-change-me":
        console.print(
            "[bold yellow]WARNING: Using default dashboard credentials or JWT secret - "
            "set BAITBOX_DASHBOARD_PASSWORD and BAITBOX_JWT_SECRET in production.[/bold yellow]"
        )
        logger.warning("Using default credentials - please change in production")

    # ── SSH Server (Paramiko is blocking — run in thread) ───────────────────
    logger.info(f"Starting SSH honeypot on {settings.ssh_host}:{settings.ssh_port}")
    ssh_thread = threading.Thread(
        target=start_ssh_server,
        kwargs={"host": settings.ssh_host, "port": settings.ssh_port},
        daemon=True,
    )
    ssh_thread.start()

    # ── Telnet Server (asyncio, optional) ───────────────────────────────────
    telnet_task: asyncio.Task[None] | None = None
    if settings.telnet_enabled:
        logger.info(f"Starting Telnet honeypot on {settings.ssh_host}:{settings.telnet_port}")
        from .servers.telnet_server import start_telnet_server
        telnet_task = asyncio.create_task(start_telnet_server(settings.ssh_host, settings.telnet_port))

    # ── Graceful shutdown on SIGINT / SIGTERM ───────────────────────────────
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _SHUTDOWN.set)
        except NotImplementedError:
            pass

    # Wait for either our own signal handler or an independent exit of the
    # HTTP server (uvicorn installs its own Ctrl+C handler on Windows, where
    # loop.add_signal_handler is unavailable).
    shutdown_waiter = asyncio.create_task(_SHUTDOWN.wait())
    try:
        await asyncio.wait({shutdown_waiter, serve_task}, return_when=asyncio.FIRST_COMPLETED)
    except (KeyboardInterrupt, asyncio.CancelledError):
        # Windows event loops do not support add_signal_handler, so Ctrl+C is
        # delivered as task cancellation. Clear the cancellation request so the
        # cleanup awaits below can complete normally.
        current = asyncio.current_task()
        if current is not None and hasattr(current, "uncancel"):
            current.uncancel()
        logger.info("Shutdown signal received")
    finally:
        shutdown_waiter.cancel()
        try:
            await shutdown_waiter
        except asyncio.CancelledError:
            pass

    logger.info("Shutting down BaitBox...")
    console.print("\n[dim]Shutting down BaitBox...[/dim]")
    server.should_exit = True
    try:
        await serve_task
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.error("HTTP server exited with an error: %s", exc)

    if telnet_task is not None:
        telnet_task.cancel()
        try:
            await telnet_task
        except asyncio.CancelledError:
            pass

    retention_task.cancel()
    try:
        await retention_task
    except asyncio.CancelledError:
        pass

    # Release database connections cleanly (WAL checkpoint on SQLite,
    # pool teardown on PostgreSQL) so restarts never see stale locks.
    try:
        await close_db()
        logger.info("Database connections closed")
    except Exception as exc:
        logger.warning("Error closing database: %s", exc)

    logger.info("BaitBox shutdown complete")


def cli() -> None:
    """Synchronous entry point used by the console script and ``python -m``."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("BaitBox interrupted")


if __name__ == "__main__":
    cli()

