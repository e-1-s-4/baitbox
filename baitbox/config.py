"""Runtime configuration for BaitBox."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _safe_int(env_var: str, default: int) -> int:
    """Safely convert environment variable to int with fallback."""
    try:
        return int(os.getenv(env_var, str(default)))
    except (ValueError, TypeError):
        return default


@dataclass(frozen=True)
class Settings:
    """Application settings loaded from environment variables."""

    ssh_host: str = os.getenv("BAITBOX_SSH_HOST", "0.0.0.0")
    ssh_port: int = _safe_int("BAITBOX_SSH_PORT", 2222)
    dashboard_host: str = os.getenv("BAITBOX_DASHBOARD_HOST", "0.0.0.0")
    dashboard_port: int = _safe_int("BAITBOX_DASHBOARD_PORT", _safe_int("PORT", 8000))
    database_path: str = os.getenv("BAITBOX_DB", "baitbox.db")
    max_events: int = _safe_int("BAITBOX_MAX_EVENTS", 100)
    ssh_host_key: str = os.getenv("BAITBOX_SSH_HOST_KEY", "")
    ssh_backlog: int = _safe_int("BAITBOX_SSH_BACKLOG", 100)
    ssh_channel_timeout: int = _safe_int("BAITBOX_SSH_CHANNEL_TIMEOUT", 20)
    webhook_url: str = os.getenv("BAITBOX_WEBHOOK_URL", "")
    webhook_type: str = os.getenv("BAITBOX_WEBHOOK_TYPE", "discord")
    # Server-side GeoIP: set to "0" to disable (reduces external lookups)
    geoip_enabled: bool = os.getenv("BAITBOX_GEOIP_ENABLED", "1") not in ("0", "false", "no")
    # Telnet honeypot
    telnet_port: int = _safe_int("BAITBOX_TELNET_PORT", 2323)
    telnet_enabled: bool = os.getenv("BAITBOX_TELNET_ENABLED", "1") not in ("0", "false", "no")
    # Banner customisation
    ssh_banner_hostname: str = os.getenv("BAITBOX_SSH_HOSTNAME", "web-prod-01")

    # Dashboard Authentication
    dashboard_username: str = os.getenv("BAITBOX_DASHBOARD_USER", "admin")
    # Database selection
    database_type: str = os.getenv("BAITBOX_DB_TYPE", "sqlite")
    database_url: str = os.getenv("BAITBOX_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/baitbox")
    dashboard_password: str = os.getenv("BAITBOX_DASHBOARD_PASSWORD", "admin")
    jwt_secret: str = os.getenv("BAITBOX_JWT_SECRET", "baitbox-super-secret-key-change-me")
    jwt_expiry_hours: int = _safe_int("BAITBOX_JWT_EXPIRY_HOURS", 24)
    session_cookie_secure: bool = os.getenv("BAITBOX_SESSION_COOKIE_SECURE", "0").lower() in ("1", "true", "yes")
    http_max_body_bytes: int = _safe_int("BAITBOX_HTTP_MAX_BODY_BYTES", 65536)
    # Rate limiting (connections per 60-second window)
    rate_limit_ssh: int = _safe_int("BAITBOX_RATE_LIMIT_SSH", 20)
    rate_limit_http: int = _safe_int("BAITBOX_RATE_LIMIT_HTTP", 100)
    rate_limit_telnet: int = _safe_int("BAITBOX_RATE_LIMIT_TELNET", 30)
    # Security enhancements
    enable_request_logging: bool = os.getenv("BAITBOX_ENABLE_REQUEST_LOGGING", "1") not in ("0", "false", "no")
    max_command_length: int = _safe_int("BAITBOX_MAX_COMMAND_LENGTH", 4096)
    enable_session_cleanup: bool = os.getenv("BAITBOX_ENABLE_SESSION_CLEANUP", "1") not in ("0", "false", "no")
    session_cleanup_interval: int = _safe_int("BAITBOX_SESSION_CLEANUP_INTERVAL", 300)  # 5 minutes

    # Dashboard login brute-force protection (failed attempts per window per IP)
    login_rate_limit: int = _safe_int("BAITBOX_LOGIN_RATE_LIMIT", 10)
    login_rate_window_secs: int = _safe_int("BAITBOX_LOGIN_RATE_WINDOW_SECS", 300)

    # Event retention: prune events older than N hours (0 disables pruning)
    event_retention_hours: int = _safe_int("BAITBOX_EVENT_RETENTION_HOURS", 720)

    # Webhook filtering: only notify for events at/above this threat level
    webhook_min_threat_level: str = os.getenv("BAITBOX_WEBHOOK_MIN_THREAT_LEVEL", "LOW").upper()

    # ── v2.3.0 additions ────────────────────────────────────────────────────
    # Trust X-Forwarded-For / X-Real-IP headers when deriving the client IP.
    # Leave disabled (default) unless BaitBox sits behind a trusted reverse
    # proxy — otherwise attackers can spoof their source IP and evade the
    # block list and rate limiter.
    trust_proxy: bool = os.getenv("BAITBOX_TRUST_PROXY", "0").lower() in ("1", "true", "yes")

    # Prometheus /metrics endpoint (protected by dashboard auth)
    metrics_enabled: bool = os.getenv("BAITBOX_METRICS_ENABLED", "1").lower() not in ("0", "false", "no")

    # Add Strict-Transport-Security header (enable when served over HTTPS)
    hsts_enabled: bool = os.getenv("BAITBOX_HSTS_ENABLED", "0").lower() in ("1", "true", "yes")
    hsts_max_age: int = _safe_int("BAITBOX_HSTS_MAX_AGE", 31536000)

    # Memory bounds for interactive sessions
    max_session_commands: int = _safe_int("BAITBOX_MAX_SESSION_COMMANDS", 500)
    max_sessions: int = _safe_int("BAITBOX_MAX_SESSIONS", 1000)

    # Webhook delivery: bounded queue + single worker (prevents thread
    # explosion during credential-stuffing floods)
    webhook_queue_size: int = _safe_int("BAITBOX_WEBHOOK_QUEUE_SIZE", 500)

    # Insert a handful of realistic demo events on first start when the
    # database is empty. Off by default so production telemetry is never
    # polluted with fabricated attackers.
    seed_demo_data: bool = os.getenv("BAITBOX_SEED_DEMO_DATA", "0").lower() in ("1", "true", "yes")


settings = Settings()
