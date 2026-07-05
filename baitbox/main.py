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
from .db import init_db
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


async def main() -> None:
    """Main entry point that initializes and starts all honeypot servers."""
    logger.info("Starting BaitBox honeypot...")
    
    # Initialize Database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

    loop = asyncio.get_running_loop()
    set_main_loop(loop)

    # Start session cleanup task if enabled
    if settings.enable_session_cleanup:
        session_manager.start_cleanup_task(interval_seconds=settings.session_cleanup_interval)

    if settings.dashboard_password == "admin" or settings.jwt_secret == "baitbox-super-secret-key-change-me":
        console.print(
            "[bold yellow]⚠  Using default dashboard credentials or JWT secret — "
            "set BAITBOX_DASHBOARD_PASSWORD and BAITBOX_JWT_SECRET in production.[/bold yellow]"
        )
        logger.warning("Using default credentials - please change in production")

    # ── Boot Banner ─────────────────────────────────────────────────────────
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim")
    table.add_column(style="bright_white")
    table.add_row("🪤  SSH Honeypot", f"{settings.ssh_host}:{settings.ssh_port}")
    table.add_row("🌐  HTTP Decoys", f"http://localhost:{settings.dashboard_port}")
    table.add_row("📺  Dashboard", f"http://localhost:{settings.dashboard_port}")
    table.add_row("🗃️  Database", f"{settings.database_type} ({settings.database_path})")
    if settings.telnet_enabled:
        table.add_row("📡  Telnet Honeypot", f"{settings.ssh_host}:{settings.telnet_port}")
    if settings.webhook_url:
        table.add_row("🔔  Webhooks", f"{settings.webhook_type.upper()} → {settings.webhook_url[:40]}...")
    if settings.geoip_enabled:
        table.add_row("🗺️  GeoIP", "Server-side (ip-api.com, cached 1h)")

    console.print(Panel(
        table,
        title="[bold green]🪤  BaitBox Honeypot v2.1[/bold green]",
        subtitle="[dim]Trap attackers. Capture intel. Stay safe.[/dim]",
        border_style="green",
        expand=False,
    ))

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
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _SHUTDOWN.set)
        except NotImplementedError:
            # Windows does not support add_signal_handler for all signals
            pass

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

    await _SHUTDOWN.wait()
    logger.info("Shutting down BaitBox...")
    console.print("\n[dim]Shutting down BaitBox…[/dim]")
    server.should_exit = True
    await serve_task

    if telnet_task is not None:
        telnet_task.cancel()
        try:
            await telnet_task
        except asyncio.CancelledError:
            pass
    
    logger.info("BaitBox shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())
