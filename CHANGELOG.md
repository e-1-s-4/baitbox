# Changelog

All notable changes to BaitBox are documented here.

## [Unreleased]

### Fixed
- **Fake-shell crash on `man <cmd>`**: the handler called `.format()` on a
  `bytes` literal, raising `AttributeError` and tearing down the SSH/telnet
  shell. It now returns a proper `No manual entry for <cmd>` line.
- **`$USERNAME` / `$LOGNAME` expansion**: environment variables are now
  substituted longest-name-first, so `echo $USERNAME` no longer yields
  `rootNAME` (the earlier `$USER` replacement clobbered it).
- **Standalone text filters** (`sort`, `uniq`, `cut`, `tr`, `tac`, `xargs`,
  `egrep`, `fgrep`) returned a bare `bytes` object instead of an
  `(output, should_close)` tuple — crashing the caller — and read nothing when
  given a file operand (e.g. `sort /etc/passwd`). They now return a tuple and
  read their file operands from the VFS.
- **`tr` ranges and character classes**: `tr a-z A-Z` (and `[:upper:]`,
  `[:lower:]`, `[:digit:]`, …) now expand correctly instead of being treated as
  three literal characters by `str.maketrans`.
- **`awk`/`gawk` file operands**: `awk '{print $N}' file` now actually applies
  the program instead of echoing the whole file back untouched.
- **`sed`** now applies the common expression forms — `s/RE/REPL/[gi]`,
  `Np`/`N,Mp` (with `-n`), `Nd`/`N,Md` and `/RE/d` — instead of returning the
  file verbatim.
- **`tac <file>`** now reverses the file's lines (it previously behaved like
  `cat`), and **`xargs`** defaults to `echo` / runs an explicit command with the
  piped tokens appended instead of passing stdin straight through.
- **Tab completion crash**: `complete_input` raised `IndexError` for
  whitespace-only/control-character buffers (e.g. a lone `\r`); it now handles
  them, and the SSH shell loop guards the call.
- **Unauthenticated WebSocket upgrades** now return a clean rejection
  (`websocket.close` → HTTP 403) instead of emitting an HTTP-scoped ASGI message
  that made uvicorn raise a `RuntimeError`/500 and log a stack trace.
- **`POST /api/simulate` 500**: a JSON body that was not an object (array,
  string, number) raised `AttributeError`; non-dict bodies are now ignored.
- **HTTP body logging** (`_request_payload`) coerces a non-object JSON body
  into a `raw_body` wrapper so downstream `.get()` calls never see a list/scalar.
- **GeoIP** ignores non-object responses from the upstream API instead of
  raising.
- **`/metrics`** tolerates `None`/malformed stats, non-dict aggregate rows and
  non-numeric counts, keeping the scrape endpoint live.
- **`/api/ioc`** tolerates mixed-type timestamps and unhashable
  protocol/event-type values so one malformed event cannot break the feed.
- **Login page overflow**: `body { overflow: hidden }` clipped the login card
  on short viewports with no way to scroll; it now allows vertical scrolling
  and uses `100dvh`.
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

### Security
- **Dashboard stored-XSS hardening**: attacker-controlled fields (`src_ip`,
  which can come from `X-Forwarded-For` when `BAITBOX_TRUST_PROXY=1`,
  `protocol`, `event_type`, and GeoIP city/country) are now HTML-escaped
  everywhere they are rendered, and IP values injected into inline handler
  attributes are constrained to an IP-shaped allowlist (`safeIp`). Covers the
  event feed, session cards, Top-IPs leaderboard and the Leaflet map popups.
- **Content-Security-Policy** on dashboard/login HTML responses: external
  sources are restricted to the specific CDNs, font hosts and map-tile host the
  UI needs, with `object-src 'none'`, `base-uri 'self'` and
  `frame-ancestors 'none'` as extra XSS/clickjacking backstops. Inline assets
  stay allowed because the dashboard is built on them.
- **`/metrics` negotiation**: unauthenticated machine scrapers now receive a
  JSON `401` (Prometheus does not follow redirects) while browser navigations
  still bounce to `/login`.

### Added
- Regression tests covering every fix above (fake-shell robustness, `tr`
  ranges, `/api/simulate` non-dict bodies, metrics/IOC malformed input,
  dashboard escaping helpers).
- **PostgreSQL backend test coverage** using in-memory asyncpg fakes (SQL
  building/parameter binding, row decoding, GeoIP/blocklist/prune roundtrips,
  schema init and cross-backend interface conformance) — no live DB required.
- **Static Docker validation tests** for `Dockerfile`/`docker-compose.yml`
  invariants (unprivileged user before `COPY --chown`, internal port, health
  probes, published ports and the Postgres wiring).
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
