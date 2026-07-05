"""Database Abstraction Layer for BaitBox persistence."""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from .config import settings
from .db_sqlite import SQLiteDB
from .db_postgres import PostgresDB

DB_NAME = settings.database_path

# Select the active backend instance based on configuration
if settings.database_type.lower() in ("postgres", "postgresql"):
    db_instance = PostgresDB()
else:
    db_instance = SQLiteDB()


async def init_db() -> None:
    """Initialize database tables and seed configuration data."""
    await db_instance.init_db()


async def get_geoip_cache(ip: str) -> Optional[Dict[str, Any]]:
    """Retrieve GeoIP cache entry from the database."""
    return await db_instance.get_geoip_cache(ip)


async def set_geoip_cache(ip: str, data: Dict[str, Any], ttl: int = 3600) -> None:
    """Cache GeoIP results to avoid repeated lookups."""
    await db_instance.set_geoip_cache(ip, data, ttl)


async def log_event(src_ip: str, protocol: str, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Persist a honeypot event to the active database backend."""
    return await db_instance.log_event(src_ip, protocol, event_type, payload)


async def get_recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve the most recent logged events."""
    return await db_instance.get_recent_events(limit)


async def get_stats() -> Dict[str, Any]:
    """Retrieve telemetry metrics for the dashboards."""
    return await db_instance.get_stats()


async def get_user_password_hash(username: str) -> Optional[str]:
    """Retrieve the password hash for a dashboard user."""
    return await db_instance.get_user_password_hash(username)
