"""Tests for the PostgreSQL backend (``baitbox/db_postgres.py``).

A live PostgreSQL server is not required: the asyncpg pool/connection objects
are replaced with in-memory fakes so the SQL building, parameter binding,
row decoding and cross-backend interface conformance can all be verified in CI.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import time

from baitbox.db_postgres import PostgresDB
from baitbox.db_sqlite import SQLiteDB


# ── Fakes ───────────────────────────────────────────────────────────────────


class _FakeConn:
    """Captures queries and returns canned result sets keyed by SQL substring."""

    def __init__(self, fetch_map=None, fetchval_map=None, fetchrow_map=None):
        self._fetch_map = fetch_map or {}
        self._fetchval_map = fetchval_map or {}
        self._fetchrow_map = fetchrow_map or {}
        self.queries: list[tuple[str, str, tuple]] = []

    @staticmethod
    def _match(mapping, query, default):
        for needle, value in mapping.items():
            if needle.lower() in query.lower():
                return value
        return default

    async def fetch(self, query, *args):
        self.queries.append(("fetch", query, args))
        return self._match(self._fetch_map, query, [])

    async def fetchval(self, query, *args):
        self.queries.append(("fetchval", query, args))
        return self._match(self._fetchval_map, query, None)

    async def fetchrow(self, query, *args):
        self.queries.append(("fetchrow", query, args))
        return self._match(self._fetchrow_map, query, None)

    async def execute(self, query, *args):
        self.queries.append(("execute", query, args))
        return "OK"

    def sql_with(self, needle: str) -> list[tuple]:
        return [q for q in self.queries if needle.lower() in q[1].lower()]


class _FakeAcquire:
    def __init__(self, conn):
        self._conn = conn

    async def __aenter__(self):
        return self._conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self, conn):
        self._conn = conn
        self.closed = False

    def acquire(self):
        return _FakeAcquire(self._conn)

    async def close(self):
        self.closed = True


def _make_backend(conn: _FakeConn) -> PostgresDB:
    backend = PostgresDB()
    pool = _FakePool(conn)

    async def _get_pool():
        return pool

    backend._get_pool = _get_pool  # type: ignore[method-assign]
    return backend


# ── Row decoding ────────────────────────────────────────────────────────────


def test_decode_row_converts_datetime_and_json_payload():
    db = PostgresDB()
    decoded = db._decode_row({
        "id": 1,
        "timestamp": dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.UTC),
        "src_ip": "203.0.113.9",
        "payload": '{"username": "root"}',
    })
    assert decoded["timestamp"].startswith("2026-01-02T03:04:05")
    assert decoded["payload"] == {"username": "root"}


def test_decode_row_passes_through_native_jsonb_and_bad_json():
    db = PostgresDB()
    # asyncpg decodes JSONB into Python objects already
    native = db._decode_row({"payload": {"a": 1}, "timestamp": "2026-01-01T00:00:00"})
    assert native["payload"] == {"a": 1}
    assert native["timestamp"] == "2026-01-01T00:00:00"
    # malformed JSON text is wrapped rather than raising
    broken = db._decode_row({"payload": "{not json", "timestamp": "x"})
    assert broken["payload"] == {"raw": "{not json"}


# ── Queries ─────────────────────────────────────────────────────────────────


def test_get_recent_events_binds_filters_and_reverses_order():
    conn = _FakeConn(fetch_map={"FROM events": [
        {"id": 1, "payload": "{}"},
        {"id": 2, "payload": "{}"},
    ]})
    db = _make_backend(conn)
    rows = asyncio.run(db.get_recent_events(
        limit=50, protocol="SSH", src_ip="1.2.3.4", event_type="command", offset=10,
    ))

    (_, sql, params), = [q for q in conn.queries if q[0] == "fetch"]
    assert "protocol = $1" in sql
    assert "src_ip = $2" in sql
    assert "event_type = $3" in sql
    assert "LIMIT $4 OFFSET $5" in sql
    assert params == ("SSH", "1.2.3.4", "command", 50, 10)
    # rows are returned oldest-first
    assert [r["id"] for r in rows] == [2, 1]


def test_get_stats_aggregates_every_section():
    conn = _FakeConn(
        fetch_map={
            "GROUP BY protocol": [{"protocol": "SSH", "count": 5}],
            "GROUP BY event_type": [{"event_type": "command", "count": 3}],
            "GROUP BY src_ip": [{"src_ip": "1.2.3.4", "count": 2}],
            "payload->>'command'": [{"timestamp": dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
                                     "src_ip": "1.2.3.4", "command": "id"}],
            "payload->>'password'": [{"password": "toor", "count": 4}],
            "payload->>'username'": [{"username": "root", "count": 6}],
            "to_char(timestamp": [{"hour": "2026-01-01T00:00:00", "count": 1}],
            "payload->>'path'": [{"path": "/admin", "count": 9}],
        },
        fetchval_map={"COUNT(*) FROM events": 42},
    )
    db = _make_backend(conn)
    stats = asyncio.run(db.get_stats())

    assert stats["total_events"] == 42
    assert stats["by_protocol"] == [{"protocol": "SSH", "count": 5}]
    assert stats["by_event_type"] == [{"event_type": "command", "count": 3}]
    assert stats["top_ips"] == [{"src_ip": "1.2.3.4", "count": 2}]
    assert stats["top_passwords"] == [{"password": "toor", "count": 4}]
    assert stats["top_usernames"] == [{"username": "root", "count": 6}]
    assert stats["top_http_paths"] == [{"path": "/admin", "count": 9}]
    # datetime in recent_commands is serialised to ISO text
    assert stats["recent_commands"][0]["timestamp"].startswith("2026-01-01")
    assert stats["recent_commands"][0]["command"] == "id"
    assert stats["hourly_events"][0]["hour"] == "2026-01-01T00:00:00"


def test_block_unblock_and_list_ips():
    conn = _FakeConn(fetch_map={"FROM blocked_ips": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}]})
    db = _make_backend(conn)

    asyncio.run(db.block_ip("1.2.3.4"))
    assert any("INSERT INTO blocked_ips" in q[1] for q in conn.queries)

    asyncio.run(db.unblock_ip("1.2.3.4"))
    dels = conn.sql_with("DELETE FROM blocked_ips")
    assert dels and dels[-1][2] == ("1.2.3.4",)

    assert asyncio.run(db.get_blocked_ips()) == ["1.2.3.4", "5.6.7.8"]


def test_geoip_cache_roundtrip_and_expiry():
    fresh = _FakeConn(fetchrow_map={"FROM geoip_cache": {
        "data": {"city": "Nowhere"}, "expires_at": time.time() + 600,
    }})
    assert asyncio.run(_make_backend(fresh).get_geoip_cache("1.2.3.4")) == {"city": "Nowhere"}

    # JSON string payloads (non-asyncpg sources) are decoded
    text = _FakeConn(fetchrow_map={"FROM geoip_cache": {
        "data": '{"city": "Elsewhere"}', "expires_at": time.time() + 600,
    }})
    assert asyncio.run(_make_backend(text).get_geoip_cache("1.2.3.4")) == {"city": "Elsewhere"}

    # expired or malformed entries yield None
    expired = _FakeConn(fetchrow_map={"FROM geoip_cache": {
        "data": {"city": "Old"}, "expires_at": time.time() - 1,
    }})
    assert asyncio.run(_make_backend(expired).get_geoip_cache("1.2.3.4")) is None

    bad = _FakeConn(fetchrow_map={"FROM geoip_cache": {
        "data": "not-json", "expires_at": time.time() + 600,
    }})
    assert asyncio.run(_make_backend(bad).get_geoip_cache("1.2.3.4")) is None

    # set writes and prunes expired rows
    writes = _FakeConn()
    asyncio.run(_make_backend(writes).set_geoip_cache("9.9.9.9", {"city": "X"}, ttl=60))
    assert writes.sql_with("INSERT INTO geoip_cache")
    assert writes.sql_with("DELETE FROM geoip_cache")


def test_prune_events():
    conn = _FakeConn(fetchval_map={"FROM removed": 7})
    db = _make_backend(conn)
    assert asyncio.run(db.prune_events(24)) == 7
    # non-positive retention is a no-op and must not touch the database
    conn.queries.clear()
    assert asyncio.run(db.prune_events(0)) == 0
    assert conn.queries == []


def test_log_event_returns_enriched_event():
    conn = _FakeConn(fetchval_map={"RETURNING id": 99})
    db = _make_backend(conn)
    event = asyncio.run(db.log_event("203.0.113.5", "SSH", "auth_attempt", {"username": "root"}))
    assert event["id"] == 99
    assert event["src_ip"] == "203.0.113.5"
    assert event["protocol"] == "SSH"
    assert event["payload"] == {"username": "root"}
    dt.datetime.fromisoformat(event["timestamp"])
    assert conn.sql_with("INSERT INTO events")


def test_init_db_creates_schema_and_seeds_user():
    conn = _FakeConn()
    db = _make_backend(conn)
    asyncio.run(db.init_db())

    executed = " \n".join(q[1] for q in conn.queries if q[0] == "execute")
    for table in ("events", "geoip_cache", "users", "blocked_ips"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in executed
    assert "ON CONFLICT(username) DO UPDATE" in executed
    # the seeded password hash is a bcrypt digest
    hash_params = [p for q in conn.queries if "INSERT INTO users" in q[1] for p in q[2]]
    assert any(str(p).startswith("$2") for p in hash_params)


def test_close_releases_pool():
    conn = _FakeConn()
    pool = _FakePool(conn)
    db = PostgresDB()
    db._pool = pool
    asyncio.run(db.close())
    assert pool.closed is True
    assert db._pool is None


# ── Interface conformance with the SQLite backend ───────────────────────────


def test_postgres_backend_matches_sqlite_interface():
    """The DB layer calls these by name, so both backends must expose them."""
    required = {
        "init_db",
        "get_geoip_cache",
        "set_geoip_cache",
        "log_event",
        "get_recent_events",
        "get_stats",
        "prune_events",
        "block_ip",
        "unblock_ip",
        "get_blocked_ips",
        "get_user_password_hash",
        "close",
    }
    for name in required:
        assert callable(getattr(PostgresDB, name, None)), f"PostgresDB missing {name}"
        assert callable(getattr(SQLiteDB, name, None)), f"SQLiteDB missing {name}"
