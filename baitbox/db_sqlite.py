"""SQLite persistence implementation for BaitBox."""

from __future__ import annotations
import datetime as dt
import json
import time
from typing import Any, Dict, List, Optional
import aiosqlite

from .config import settings

DB_NAME = settings.database_path


class SQLiteDB:
    async def init_db(self) -> None:
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol_type ON events(protocol, event_type)")

            # GeoIP cache table
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS geoip_cache (
                    ip TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            await db.execute("CREATE INDEX IF NOT EXISTS idx_geoip_cache_expires ON geoip_cache(expires_at)")

            # Users table for dashboard auth
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
                """
            )
            await db.commit()

            # Ensure the configured user exists and is up to date
            import bcrypt
            hashed = bcrypt.hashpw(settings.dashboard_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            await db.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
                """,
                (settings.dashboard_username, hashed),
            )
            await db.commit()

    async def get_geoip_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        async with aiosqlite.connect(DB_NAME) as db:
            db.row_factory = aiosqlite.Row
            row = await (
                await db.execute(
                    "SELECT data, expires_at FROM geoip_cache WHERE ip = ?",
                    (ip,),
                )
            ).fetchone()

        if not row or float(row["expires_at"]) <= time.time():
            return None

        try:
            return json.loads(row["data"])
        except json.JSONDecodeError:
            return None

    async def set_geoip_cache(self, ip: str, data: Dict[str, Any], ttl: int = 3600) -> None:
        expires_at = time.time() + ttl
        async with aiosqlite.connect(DB_NAME) as db:
            await db.execute(
                """
                INSERT INTO geoip_cache (ip, data, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
                """,
                (ip, json.dumps(data, sort_keys=True), expires_at),
            )
            await db.execute("DELETE FROM geoip_cache WHERE expires_at <= ?", (time.time(),))
            await db.commit()

    async def log_event(self, src_ip: str, protocol: str, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = dt.datetime.now(dt.UTC).isoformat()
        payload_str = json.dumps(payload, sort_keys=True)

        async with aiosqlite.connect(DB_NAME) as db:
            cursor = await db.execute(
                "INSERT INTO events (timestamp, src_ip, protocol, event_type, payload) VALUES (?, ?, ?, ?, ?)",
                (timestamp, src_ip, protocol, event_type, payload_str),
            )
            await db.commit()
            event_id = cursor.lastrowid

        event = {
            "id": event_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "protocol": protocol,
            "event_type": event_type,
            "payload": payload,
        }

        try:
            from .anomaly import analyze_event
            threat_info = analyze_event(event)
            event["threat_score"] = threat_info["threat_score"]
            event["threat_level"] = threat_info["threat_level"]
            event["threat_reasons"] = threat_info["reasons"]
        except Exception:
            pass

        try:
            from .webhooks import send_webhook_notification
            send_webhook_notification(event)
        except Exception:
            pass

        return event

    def _decode_row(self, row: aiosqlite.Row) -> Dict[str, Any]:
        event = dict(row)
        try:
            event["payload"] = json.loads(event.get("payload") or "{}")
        except json.JSONDecodeError:
            event["payload"] = {"raw": event.get("payload", "")}
        return event

    async def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(DB_NAME) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
            rows = await cursor.fetchall()
            return [self._decode_row(row) for row in reversed(rows)]

    async def get_stats(self) -> Dict[str, Any]:
        async with aiosqlite.connect(DB_NAME) as db:
            db.row_factory = aiosqlite.Row
            total = (await (await db.execute("SELECT COUNT(*) AS count FROM events")).fetchone())["count"]
            by_protocol = await (await db.execute(
                "SELECT protocol, COUNT(*) AS count FROM events GROUP BY protocol ORDER BY count DESC"
            )).fetchall()
            by_event_type = await (await db.execute(
                "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type ORDER BY count DESC"
            )).fetchall()
            top_ips = await (await db.execute(
                "SELECT src_ip, COUNT(*) AS count FROM events GROUP BY src_ip ORDER BY count DESC LIMIT 10"
            )).fetchall()
            recent_commands = await (await db.execute(
                """
                SELECT timestamp, src_ip, json_extract(payload, '$.command') AS command
                FROM events
                WHERE protocol = 'SSH' AND event_type = 'command'
                ORDER BY id DESC
                LIMIT 20
                """
            )).fetchall()
            top_passwords = await (await db.execute(
                """
                SELECT json_extract(payload, '$.password') AS password, COUNT(*) AS count
                FROM events
                WHERE event_type = 'auth_attempt' AND json_extract(payload, '$.password') IS NOT NULL
                GROUP BY password
                ORDER BY count DESC
                LIMIT 10
                """
            )).fetchall()
            top_usernames = await (await db.execute(
                """
                SELECT json_extract(payload, '$.username') AS username, COUNT(*) AS count
                FROM events
                WHERE event_type = 'auth_attempt' AND json_extract(payload, '$.username') IS NOT NULL
                GROUP BY username
                ORDER BY count DESC
                LIMIT 10
                """
            )).fetchall()
            hourly = await (await db.execute(
                """
                SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) AS hour, COUNT(*) AS count
                FROM events
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour
                ORDER BY hour
                """
            )).fetchall()
            top_paths = await (await db.execute(
                """
                SELECT json_extract(payload, '$.path') AS path, COUNT(*) AS count
                FROM events
                WHERE protocol = 'HTTP'
                GROUP BY path
                ORDER BY count DESC
                LIMIT 10
                """
            )).fetchall()

        return {
            "total_events": total,
            "by_protocol": [dict(row) for row in by_protocol],
            "by_event_type": [dict(row) for row in by_event_type],
            "top_ips": [dict(row) for row in top_ips],
            "top_passwords": [dict(row) for row in top_passwords],
            "top_usernames": [dict(row) for row in top_usernames],
            "recent_commands": [dict(row) for row in recent_commands],
            "hourly_events": [dict(row) for row in hourly],
            "top_http_paths": [dict(row) for row in top_paths],
        }

    async def get_user_password_hash(self, username: str) -> Optional[str]:
        async with aiosqlite.connect(DB_NAME) as db:
            db.row_factory = aiosqlite.Row
            row = await (
                await db.execute(
                    "SELECT password_hash FROM users WHERE username = ?",
                    (username,),
                )
            ).fetchone()
        return row["password_hash"] if row else None
