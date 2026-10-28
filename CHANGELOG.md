# Changelog

All notable changes to BaitBox are documented here.

## [2.3.0] — 2026-10-18

### Added
- **Prometheus metrics endpoint** (`GET /metrics`, auth-protected): events, protocol/type counters, active sessions, blocked IPs, tracked threats, attack telemetry, and MITRE ATT&CK technique gauges — zero extra dependencies (`baitbox/metrics.py`).
- **IOC threat-feed export** (`GET /api/ioc`): aggregated malicious-IP feed with threat scores, MITRE techniques, first/last seen, captured credentials, and probed paths. Formats: JSON, CSV, and plain IP-per-line blocklist (`baitbox/ioc.py`).
- **Session transcripts**: bounded per-command history with exit codes, exposed via `GET /api/sessions/{id}/transcript` and a dashboard modal (📜 TRANSCRIPT).
- **New fake shell commands**: `dig`, `nslookup`, `host`, `whois`, `tree` (renders the live VFS), `dmesg`, `lsusb`, `lspci`, `sha224sum`, `sha384sum`, `sha512sum` (+ pipeline variants), and `history -c`.
- **Real exit-code tracking**: `$?` expansion now reflects the previous command's status; transcripts record it per command.
- **New HTTP decoys**: fake `robots.txt` advertising hidden paths, WordPress REST user enumeration (`/wp-json/wp/v2/users`), fake `phpinfo()`, and `.git/HEAD`.
- **Event pagination**: `offset` parameter on `GET /api/events`.
- **JWT logout revocation**: tokens carry a `jti` and are revoked on logout so stolen/leftover tokens die immediately.
- **GitHub Actions CI**: pytest matrix (3.11/3.12) plus Docker build & container health smoke test.
- **`.env.example`** full configuration reference and **CHANGELOG.md**.
- **Emoji favicon** route (stops browser noise hitting the catch-all honeypot).

### Security
- **Spoof-resistant source attribution**: `X-Forwarded-For` is only honoured when `BAITBOX_TRUST_PROXY=1` (default off), preventing block-list/rate-limit evasion by header rotation.
- **Non-root Docker image** with dedicated `honeypot` user, persistent SSH host key under `/data`, and a trimmed `.dockerignore`.
- **HSTS support** (`BAITBOX_HSTS_ENABLED`) for HTTPS deployments.
- **Bounded memory everywhere**: per-session command-history cap (`BAITBOX_MAX_SESSION_COMMANDS`), concurrent-session cap with stalest eviction (`BAITBOX_MAX_SESSIONS`), GeoIP cache eviction, per-IP anomaly indicator cap, and hard telnet input-buffer ceiling.
- **Bounded webhook delivery**: single worker + bounded queue replaces thread-per-event (prevents thread explosion during credential-stuffing floods).
- Telnet **flood hardening**: line processing in bounded batches (max 64/batch) with self-rescheduling drain; oversized buffers disconnect the peer.
- Removed committed runtime artifacts (`baitbox.db-shm`, `baitbox.db-wal`) and extended `.gitignore`.

### Fixed
- Pipeline checksum filters (`cat f | sha256sum`) now hash the same bytes as direct file hashing (CRLF display normalization) — matches real shell fidelity.
- `/metrics` remains scrape-able (in-memory gauges only) when the database is temporarily unavailable.
- Database connections are now released cleanly on graceful shutdown (WAL checkpoint / pool teardown).
- Version single-sourced in `baitbox/__init__.py` (was duplicated across modules).

## [2.2.0]

- Shell pipes/chaining, Telnet VFS shell, event export (CEF/ECS), anomaly enhancements, GeoIP caching, performance and security fixes.

## [2.1.0]

- Telnet honeypot, VFS enhancements, dashboard upgrades, webhooks.

## [2.0.0]

- Initial multi-protocol honeypot with SSH/HTTP servers and real-time dashboard.
