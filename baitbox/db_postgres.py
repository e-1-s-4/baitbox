"""PostgreSQL persistence implementation for BaitBox."""

from __future__ import annotations
import datetime as dt
import json
import time
from typing import Any, Dict, List, Optional
import asyncpg

from .config import settings


class PostgresDB:
    def __init__(self) -> None:
        self._pool: asyncpg.Pool | None = None

    async def _get_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                settings.database_url,
                min_size=2,
                max_size=10,
                command_timeout=30,
            )
        return self._pool

    async def init_db(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            # Events Table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload JSONB NOT NULL
                )
                """
            )
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_protocol_type ON events(protocol, event_type)")

            # GeoIP cache table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS geoip_cache (
                    ip TEXT PRIMARY KEY,
                    data JSONB NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_geoip_cache_expires ON geoip_cache(expires_at)")

            # Users table
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL
                )
                """
            )

            # Persisted IP block list (survives restarts)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )

            # Ensure the configured user exists and is up to date
            import bcrypt
            hashed = bcrypt.hashpw(settings.dashboard_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            await conn.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES ($1, $2)
                ON CONFLICT(username) DO UPDATE SET password_hash = EXCLUDED.password_hash
                """,
                settings.dashboard_username, hashed,
            )

    async def get_geoip_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT data, expires_at FROM geoip_cache WHERE ip = $1",
                ip,
            )

        if not row or float(row["expires_at"]) <= time.time():
            return None

        # asyncpg auto-decodes JSONB columns into Python dict/lists
        data = row["data"]
        if isinstance(data, str):
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                return None
        return data

    async def set_geoip_cache(self, ip: str, data: Dict[str, Any], ttl: int = 3600) -> None:
        expires_at = time.time() + ttl
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO geoip_cache (ip, data, expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT(ip) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at
                """,
                ip, json.dumps(data, sort_keys=True), expires_at,
            )
            await conn.execute("DELETE FROM geoip_cache WHERE expires_at <= $1", time.time())

    async def log_event(self, src_ip: str, protocol: str, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = dt.datetime.now(dt.UTC)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            event_id = await conn.fetchval(
                """
                INSERT INTO events (timestamp, src_ip, protocol, event_type, payload)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
                """,
                timestamp, src_ip, protocol, event_type, json.dumps(payload, sort_keys=True),
            )

        event = {
            "id": event_id,
            "timestamp": timestamp.isoformat(),
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

    def _decode_row(self, row: asyncpg.Record) -> Dict[str, Any]:
        event = dict(row)
        if isinstance(event.get("timestamp"), dt.datetime):
            event["timestamp"] = event["timestamp"].isoformat()
        
        payload = event.get("payload")
        if isinstance(payload, str):
            try:
                event["payload"] = json.loads(payload)
            except json.JSONDecodeError:
                event["payload"] = {"raw": payload}
        return event

    async def get_recent_events(
        self,
        limit: int = 50,
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if protocol:
            params.append(protocol)
            clauses.append(f"protocol = ${len(params)}")
        if src_ip:
            params.append(src_ip)
            clauses.append(f"src_ip = ${len(params)}")
        if event_type:
            params.append(event_type)
            clauses.append(f"event_type = ${len(params)}")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ${len(params)}",
                *params,
            )
            return [self._decode_row(row) for row in reversed(rows)]

    async def get_stats(self) -> Dict[str, Any]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM events") or 0
            
            by_protocol_rows = await conn.fetch(
                "SELECT protocol, COUNT(*) AS count FROM events GROUP BY protocol ORDER BY count DESC"
            )
            by_protocol = [dict(r) for r in by_protocol_rows]

            by_event_type_rows = await conn.fetch(
                "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type ORDER BY count DESC"
            )
            by_event_type = [dict(r) for r in by_event_type_rows]

            top_ips_rows = await conn.fetch(
                "SELECT src_ip, COUNT(*) AS count FROM events GROUP BY src_ip ORDER BY count DESC LIMIT 10"
            )
            top_ips = [dict(r) for r in top_ips_rows]

            recent_commands_rows = await conn.fetch(
                """
                SELECT timestamp, src_ip, payload->>'command' AS command
                FROM events
                WHERE protocol IN ('SSH', 'Telnet') AND event_type = 'command'
                ORDER BY id DESC
                LIMIT 20
                """
            )
            recent_commands = []
            for r in recent_commands_rows:
                ts = r["timestamp"]
                if isinstance(ts, dt.datetime):
                    ts = ts.isoformat()
                recent_commands.append({
                    "timestamp": ts,
                    "src_ip": r["src_ip"],
                    "command": r["command"]
                })

            top_passwords_rows = await conn.fetch(
                """
                SELECT payload->>'password' AS password, COUNT(*) AS count
                FROM events
                WHERE event_type = 'auth_attempt' AND payload->>'password' IS NOT NULL
                GROUP BY password
                ORDER BY count DESC
                LIMIT 10
                """
            )
            top_passwords = [dict(r) for r in top_passwords_rows]

            top_usernames_rows = await conn.fetch(
                """
                SELECT payload->>'username' AS username, COUNT(*) AS count
                FROM events
                WHERE event_type = 'auth_attempt' AND payload->>'username' IS NOT NULL
                GROUP BY username
                ORDER BY count DESC
                LIMIT 10
                """
            )
            top_usernames = [dict(r) for r in top_usernames_rows]

            hourly_rows = await conn.fetch(
                """
                SELECT to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:00:00') AS hour, COUNT(*) AS count
                FROM events
                WHERE timestamp >= NOW() - INTERVAL '24 hours'
                GROUP BY hour
                ORDER BY hour
                """
            )
            hourly = [dict(r) for r in hourly_rows]

            top_paths_rows = await conn.fetch(
                """
                SELECT payload->>'path' AS path, COUNT(*) AS count
                FROM events
                WHERE protocol = 'HTTP' AND payload->>'path' IS NOT NULL
                GROUP BY path
                ORDER BY count DESC
                LIMIT 10
                """
            )
            top_paths = [dict(r) for r in top_paths_rows]

        return {
            "total_events": total,
            "by_protocol": by_protocol,
            "by_event_type": by_event_type,
            "top_ips": top_ips,
            "top_passwords": top_passwords,
            "top_usernames": top_usernames,
            "recent_commands": recent_commands,
            "hourly_events": hourly,
            "top_http_paths": top_paths,
        }

    async def prune_events(self, retention_hours: int) -> int:
        """Delete events older than the retention window. Returns rows removed."""
        if retention_hours <= 0:
            return 0
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            deleted = await conn.fetchval(
                """
                WITH removed AS (
                    DELETE FROM events
                    WHERE timestamp < NOW() - ($1 || ' hours')::INTERVAL
                    RETURNING 1
                )
                SELECT COUNT(*) FROM removed
                """,
                str(retention_hours),
            )
            await conn.execute("DELETE FROM geoip_cache WHERE expires_at <= $1", time.time())
            return int(deleted or 0)

    async def block_ip(self, ip: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO blocked_ips (ip, created_at)
                VALUES ($1, NOW())
                ON CONFLICT(ip) DO NOTHING
                """,
                ip,
            )

    async def unblock_ip(self, ip: str) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM blocked_ips WHERE ip = $1", ip)

    async def get_blocked_ips(self) -> List[str]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT ip FROM blocked_ips ORDER BY ip")
        return [row["ip"] for row in rows]

    async def get_user_password_hash(self, username: str) -> Optional[str]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT password_hash FROM users WHERE username = $1",
                username,
            )
        return row["password_hash"] if row else None
