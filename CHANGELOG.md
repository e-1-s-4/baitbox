# Changelog

All notable changes to BaitBox are documented here.

## [Unreleased]

### Fixed
- **Docker build**: the unprivileged `honeypot` user is created before the code is copied, so `COPY --chown` no longer fails; the image also pins `BAITBOX_DASHBOARD_PORT=8000`.
- **Default dashboard port** is now consistently `8000` (config previously defaulted to `3000` while Docker, compose, docs and the dashboard all used `8000`).
- **Test suite** is fully isolated and exits cleanly: every test gets its own SQLite file, the shared `aiosqlite` connection is closed after each test (no more Windows `WinError 32` or hanging non-daemon threads), and no `baitbox.db` is left in the checkout.
- **HTTP body capture** now streams and caps reads at `BAITBOX_HTTP_MAX_BODY_BYTES` instead of buffering oversized uploads in memory.
- **GeoIP lookups** are throttled and bounded in flight, failures are no longer cached for a full hour, and demo/simulation seeding uses a public cache helper.
- **SIEM/IOC exports**: event exports now carry MITRE techniques and attack categories, the CSV includes a `mitre_techniques` column, and STIX output uses valid indicator types plus IPv6 patterns.
- **Shell fidelity**: `rm -rf` removes directory trees under the VFS lock (metadata included), `tail -n <N>` honours the requested count, and `ls -l` reports real mode/owner/group/mtime and symlink targets from the VFS.
- **SQLite hourly stats** compare against a matching ISO-8601 cutoff (previous query mixed `T` and space-separated formats).
- **Session counts** now report the true total commands executed, even after the bounded history window rolls over.
- **Windows shutdown** completes gracefully when `loop.add_signal_handler` is unavailable; the process releases the database instead of hanging.
- **Bounded memory**: login-failure tracking and the connection log are capped (idle entries evicted, then oldest), and the dashboard demo-credential hint only appears while the shipped defaults are still active.
- **SSH host keys** are now 2048-bit RSA and a corrupt/truncated persisted key is regenerated instead of crashing startup; keyboard-interactive response handling was added.
- **Demo telemetry seeding is opt-in** (`BAITBOX_SEED_DEMO_DATA=1`) so fabricated attackers never pollute production data.
- API documentation routes (`/docs`, `/redoc`, `/openapi.json`) are disabled so honeypot visitors cannot enumerate the real API surface.

### Added
- `.env.example`, `.dockerignore`, and the GitHub Actions CI workflow (pytest 3.11/3.12 + Docker build).
- `python -m baitbox` entry point and a `baitbox` console script; `pyproject.toml` now declares runtime dependencies and package data.
- STIX 2.1 output for the IOC feed (`/api/ioc?format=stix`).

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
