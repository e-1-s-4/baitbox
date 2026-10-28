
# 🪤 BaitBox

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://img.shields.io/badge/CI-github--actions-green)](#)
[![Tests](https://img.shields.io/badge/tests-310%20passing-brightgreen)](#)
[![Version](https://img.shields.io/badge/version-2.3.0-purple)](#)

> **BaitBox** is a zero-config, multi-protocol honeypot for homelabbers and security researchers. Drop attackers into a stateful fake filesystem, watch them try to pivot, and get real-time alerts — all from a beautiful cyber command-center dashboard.

<img width="1280" height="720" alt="y" src="https://github.com/user-attachments/assets/6ef378cd-ddf3-40c8-808e-423c1ccb95fd" />

## 🚀 Features

- **🛡️ Multi-Protocol Honeypot:** Simultaneously traps SSH, HTTP, and Telnet attackers.
- **🎭 Stateful POSIX Virtual Filesystem (VFS):** Thread-safe virtual Linux filesystem complete with POSIX ownership, permissions (`chmod`, `chown`), symbolic links (`symlink`, `readlink`), file modifications (`touch`, `truncate`, `append_file`), cryptographic checksums (`sha256`, `md5`), unified diffs, tree views, disk usage quotas, and path traversal jail protection. SSH and Telnet attackers are dropped into an authentic environment featuring: `~/.bash_history`, `~/.bashrc` (with fake DB credentials), `~/.ssh/authorized_keys`, `/var/www/html/.env`, `/etc/shadow`, `/etc/crontab`, Nginx configs, MySQL dumps, auth logs, and virtual hardware statistics.
- **💻 140+ Fake Shell Commands:** Full interactive shell with `ls -la` (hidden files), `cd ~`, `cat`, `grep`, `find`, `ps aux`, `netstat`, `ifconfig`/`ip`, `who`/`w`, `last`, `df`, `free`, `top`, `crontab -l`, `python3 -c`, `mysql`, `git log`, `systemctl status`, `journalctl`, `nmap`, `wget`/`curl`, `ping`, `vi`/`nano`, `chmod`, `chown`, `useradd`, `passwd`, `tar`, `gzip`, `zip`, `unzip`, `which`, `whereis`, `man`, `dpkg`, `apt`, `yum`, `echo` with redirection, shell script execution, plus attacker favourites: `docker ps`, `docker images`, `kubectl get pods`, `ssh`/`scp` pivoting, `reboot`/`shutdown`, `iptables -L`, `tcpdump`, `xxd`, `strings`, and more. **New in v2.3:** `dig`, `nslookup`, `host`, `whois`, `tree` (renders the live VFS), `dmesg`, `lsusb`, `lspci`, and the full `sha1sum`–`sha512sum` checksum family.
- **🔗 Shell Pipes & Chaining:** Realistic pipelines (`cat /etc/passwd | grep root | wc -l`) with working `grep`/`wc`/`head`/`tail`/`sort`/`uniq`/`cut`/`tr`/`awk`/`base64`/`shaNNNsum` filters, command chaining with `&&`, `||`, and `;`, environment-variable expansion (`$HOME`, `${HOSTNAME}`, `$?` — now reflecting the **real previous exit code**), aliases (`ll`, `la`), **tab-completion** for paths and commands, and full ↑/↓ arrow-key history navigation. `history -c` works too.
- **📡 Telnet Honeypot:** An asyncio-powered Telnet server on port 2323 that captures credentials and drops attackers into the same stateful fake shell as SSH (with proper RFC 854 option negotiation handling). Telnet sessions appear in the dashboard's Active Intruders panel. **New in v2.3:** bounded line-processing batches and a hard input-buffer ceiling neutralise pipelined-flood DoS attempts.
- **🛡️ Advanced Attack & Exploit Detection:** Real-time signature detection and classification for:
  - **Cryptominers:** Detection of XMRig, CPUMiner, Stratum mining pool URIs (`stratum+tcp://`), Monero (XMR) wallet addresses, and mining pool domains.
  - **Reverse Shells:** Detection of Bash `/dev/tcp`, Netcat executable shells (`nc -e`), named pipes (`mkfifo`), Python/Perl/Ruby socket spawns, and Socat tunnels.
  - **Web Exploits:** Signatures for Log4Shell (CVE-2021-44228 `${jndi:...}`), Spring4Shell (CVE-2022-22965), Shellshock (CVE-2014-6271), SSRF (`169.254.169.254`), SQL Injection, XSS, and directory path traversals.
- **🎯 MITRE ATT&CK Mapping:** Automatic per-event classification mapped directly to standard MITRE ATT&CK tactics and technique IDs (e.g. `T1059.004` Unix Shell, `T1078` Valid Accounts, `T1496` Resource Hijacking, `T1190` Exploit Public-Facing Application, `T1548.003` Sudo, `T1552.001` Credentials in Files, `T1105` Ingress Tool Transfer) — **now surfaced live on the dashboard's MITRE ATT&CK panel**.
- **📊 Prometheus Metrics (new in v2.3):** Auth-protected `/metrics` endpoint exposing events, protocols, event types, active sessions, blocked IPs, tracked threats, and MITRE technique counts in the standard text exposition format — zero extra dependencies.
- **🧬 IOC Threat-Feed Export (new in v2.3):** `/api/ioc` aggregates observed malicious IPs (with threat scores, MITRE techniques, first/last seen), top credential pairs, and probed paths. Formats: structured **JSON**, flat **CSV**, or a plain **IP-per-line** blocklist ready for ipset/nginx deny/CrowdSec.
- **📜 Session Transcripts (new in v2.3):** Every SSH/Telnet session records a bounded, per-command transcript with exit codes — reviewable in the dashboard (📜 TRANSCRIPT button) or via `/api/sessions/{id}/transcript`.
- **🪤 Enriched HTTP Decoys (new in v2.3):** Fake `robots.txt` that advertises "hidden" juicy paths, WordPress REST user-enumeration responses (`/wp-json/wp/v2/users`), a fake `phpinfo()` page, and a `.git/HEAD` decoy — on top of the existing `.env`, `.aws/credentials`, `.docker/config.json`, and admin-login traps.
- **🛰️ Enterprise SIEM Telemetry & Export:** Native export endpoints for SIEM pipelines supporting **ArcSight Common Event Format (CEF)** via `/api/events/export?format=cef`, **Elastic Common Schema (ECS v8.11)** via `/api/events/export?format=ecs`, standard JSON, CSV, and structured single-line JSON log formatting — all one click away from the dashboard's EXPORT menu.
- **📊 Premium Dashboard:** A stunning, pure-vanilla-CSS cyber command center with:
  - **Live GeoIP Attack Map** (server-side resolution, cached, no API key needed)
  - **Threat Score Indicators** (🔴 HIGH / 🟡 MED / 🟢 LOW per attacker)
  - **24-Hour Event Timeline** chart
  - **Protocol Split** donut chart
  - **Real-time event stream** with pause/resume **and threat-level filter chips** (new in v2.3)
  - **MITRE ATT&CK technique panel** with live attack-category counters (new in v2.3)
  - **Export menu** — CSV / JSON / CEF / ECS / IOC feed (new in v2.3)
  - **Session transcript modal** with per-command exit codes (new in v2.3)
  - **IP Block/Unblock controls** — one click blocks an IP and terminates their sessions; blocks persist across restarts
  - **Top Offending IPs, Top Passwords, Top HTTP Paths** leaderboards
  - **Active Intruder Controller** — live session view with BOOT/BLOCK/MAP buttons
- **🔐 Dashboard Authentication:** Login-protected dashboard with bcrypt-hashed credentials, constant-time credential verification, JWT session tokens with `jti`-based **logout revocation** (new in v2.3 — stolen or leftover tokens die immediately), and brute-force protection on failed logins.
- **🛡️ Spoof-Resistant Source Attribution (new in v2.3):** `X-Forwarded-For` is ignored unless `BAITBOX_TRUST_PROXY=1`, so direct attackers can no longer rotate the header to evade IP blocks and rate limits.
- **🔔 Webhook Notifications:** Discord and Slack alerts for auth attempts, commands, and decoy hits — filterable by minimum threat level and safely truncated to platform limits. **New in v2.3:** a bounded delivery queue with a single worker replaces thread-per-event, so credential-stuffing floods can no longer explode thread counts.
- **📈 Anomaly Detection:** Real-time per-IP threat scoring with pattern analysis for rapid auth attempts, high-risk commands, privilege escalation, and sensitive file access.
- **🚫 IP Rate Limiting & Persistent Block List:** Automatic connection tracking; manual blocks survive restarts via the database.
- **🐘 PostgreSQL Support:** Optional PostgreSQL backend for production-grade persistence via Docker Compose.
- **🐳 Hardened Docker:** Non-root container user, persistent host key, `.dockerignore`-trimmed image, CI-built and smoke-tested.
- **🧹 Automatic Cleanup:** Background tasks for stale session cleanup and configurable event-retention pruning.
- **🧠 Bounded Memory Everywhere (new in v2.3):** per-session command history cap, concurrent-session cap (stalest evicted), GeoIP cache eviction, per-IP indicator caps, and bounded telnet input buffers — long-running deployments stay lean under scanner floods.
- **📝 Structured Logging:** Comprehensive logging with timestamps and log levels for debugging and monitoring.
- **⚡ Performance Optimizations:** Persistent WAL-mode SQLite connection, PostgreSQL connection pooling, non-blocking GeoIP lookups, and bounded in-memory tracking tables.

## ⚡ Quickstart

### Docker (Recommended — SQLite, zero-config)

```bash
docker run -d \
  --name baitbox \
  -p 2222:2222 \
  -p 2323:2323 \
  -p 8000:8000 \
  ghcr.io/e-1-s-4/baitbox:latest
```

Open **http://localhost:8000** to see the dashboard.  
Login with **admin / admin** (change via env vars in production!).

### Docker Compose (PostgreSQL backend)

```bash
git clone https://github.com/e-1-s-4/baitbox.git
cd baitbox
docker compose up -d
```

This starts BaitBox with a PostgreSQL database for production workloads. See `docker-compose.yml` for configuration.

### Python (local dev)

```bash
git clone https://github.com/e-1-s-4/baitbox.git
cd baitbox
pip install -r requirements.txt
python -m baitbox.main
```

(login: admin / admin)

## 🧪 Test It

**SSH Honeypot:**
```bash
ssh root@localhost -p 2222
# Enter any password (e.g. admin123)
# Try: ls -la, cat /root/secrets.txt, cat /var/www/html/.env, grep DB_PASS /root/.bashrc
# Try pipes and chaining: cat /etc/passwd | grep ubuntu | wc -l
# Try tab-completion (cat /et<TAB>), history with ↑/↓, and `reboot`
```

**Telnet Honeypot:**
```bash
telnet localhost 2323
# Enter any username/password, then explore the same fake filesystem
```

**HTTP Decoys:**
```bash
curl http://localhost:8000/wp-admin
curl http://localhost:8000/.env
curl http://localhost:8000/.git/config
```

Then open **http://localhost:8000** and watch your actions appear on the dashboard in real-time.

## 🔐 Dashboard Authentication

The dashboard requires authentication. Default credentials:

| Variable | Default | Description |
|---|---|---|
| `BAITBOX_DASHBOARD_USER` | `admin` | Dashboard login username |
| `BAITBOX_DASHBOARD_PASSWORD` | `admin` | Dashboard login password |
| `BAITBOX_JWT_SECRET` | _(auto)_ | JWT signing secret — **change this in production** |

All `/api/*` endpoints and the `/ws/feed` WebSocket require a valid JWT session cookie or bearer token. Unauthenticated API requests return **401 Unauthorized**, unauthenticated WebSocket handshakes are rejected with **403 Forbidden**, and unauthenticated dashboard visits are redirected to `/login`. Failed dashboard logins are rate-limited per IP (default: 10 attempts per 5 minutes → HTTP 429).

## ⚙️ Configuration

All settings are via environment variables:

| Variable | Default | Description |
|---|---|---|
| `BAITBOX_SSH_HOST` | `0.0.0.0` | SSH honeypot bind address |
| `BAITBOX_SSH_PORT` | `2222` | SSH honeypot port |
| `BAITBOX_DASHBOARD_HOST` | `0.0.0.0` | Dashboard bind address |
| `BAITBOX_DASHBOARD_PORT` | `8000` | Dashboard port |
| `BAITBOX_TELNET_PORT` | `2323` | Telnet honeypot port |
| `BAITBOX_TELNET_ENABLED` | `1` | Set to `0` to disable Telnet |
| `BAITBOX_DB` | `baitbox.db` | SQLite database path |
| `BAITBOX_DB_TYPE` | `sqlite` | Database backend: `sqlite` or `postgresql` |
| `BAITBOX_DATABASE_URL` | _(see below)_ | PostgreSQL connection URL (only used when `BAITBOX_DB_TYPE=postgresql`) |
| `BAITBOX_MAX_EVENTS` | `100` | Max events kept client-side |
| `BAITBOX_SSH_HOST_KEY` | _(empty)_ | Path to RSA host key (auto-generated if empty) |
| `BAITBOX_SSH_BACKLOG` | `100` | TCP listen backlog |
| `BAITBOX_SSH_CHANNEL_TIMEOUT` | `20` | SSH channel idle timeout (seconds) |
| `BAITBOX_SSH_HOSTNAME` | `web-prod-01` | Fake hostname shown in SSH banner/prompt |
| `BAITBOX_GEOIP_ENABLED` | `1` | Set to `0` to disable server-side GeoIP lookups |
| `BAITBOX_WEBHOOK_URL` | _(empty)_ | Discord/Slack webhook URL |
| `BAITBOX_WEBHOOK_TYPE` | `discord` | Webhook format: `discord`, `slack`, or `generic` |
| `BAITBOX_DASHBOARD_USER` | `admin` | Dashboard login username |
| `BAITBOX_DASHBOARD_PASSWORD` | `admin` | Dashboard login password |
| `BAITBOX_JWT_SECRET` | _(auto)_ | JWT signing secret |
| `BAITBOX_JWT_EXPIRY_HOURS` | `24` | JWT token expiry time in hours |
| `BAITBOX_SESSION_COOKIE_SECURE` | `0` | Set to `1` when the dashboard is served over HTTPS |
| `BAITBOX_HTTP_MAX_BODY_BYTES` | `65536` | Max captured HTTP request body bytes per event |
| `BAITBOX_RATE_LIMIT_SSH` | `20` | Max SSH connections per IP per 60-second window |
| `BAITBOX_RATE_LIMIT_HTTP` | `100` | Max HTTP requests per IP per 60-second window |
| `BAITBOX_RATE_LIMIT_TELNET` | `30` | Max Telnet connections per IP per 60-second window |
| `BAITBOX_ENABLE_REQUEST_LOGGING` | `1` | Set to `0` to disable HTTP request logging |
| `BAITBOX_MAX_COMMAND_LENGTH` | `4096` | Maximum command length for SSH/Telnet commands |
| `BAITBOX_ENABLE_SESSION_CLEANUP` | `1` | Set to `0` to disable automatic session cleanup |
| `BAITBOX_SESSION_CLEANUP_INTERVAL` | `300` | Session cleanup interval in seconds (default: 5 minutes) |
| `BAITBOX_EVENT_RETENTION_HOURS` | `720` | Prune events older than this many hours (`0` disables pruning) |
| `BAITBOX_LOGIN_RATE_LIMIT` | `10` | Failed dashboard logins allowed per IP per window |
| `BAITBOX_LOGIN_RATE_WINDOW_SECS` | `300` | Login rate-limit window in seconds |
| `BAITBOX_WEBHOOK_MIN_THREAT_LEVEL` | `LOW` | Only send webhooks for events at/above this level (`LOW`/`MEDIUM`/`CRITICAL`) |
| `BAITBOX_TRUST_PROXY` | `0` | v2.3: honour `X-Forwarded-For` (enable ONLY behind a trusted reverse proxy) |
| `BAITBOX_METRICS_ENABLED` | `1` | v2.3: expose the auth-protected Prometheus `/metrics` endpoint |
| `BAITBOX_HSTS_ENABLED` | `0` | v2.3: add Strict-Transport-Security header (enable when serving HTTPS) |
| `BAITBOX_HSTS_MAX_AGE` | `31536000` | v2.3: HSTS max-age in seconds |
| `BAITBOX_MAX_SESSION_COMMANDS` | `500` | v2.3: per-session command-history cap (memory bound) |
| `BAITBOX_MAX_SESSIONS` | `1000` | v2.3: concurrent-session cap (stalest evicted) |
| `BAITBOX_WEBHOOK_QUEUE_SIZE` | `500` | v2.3: bounded webhook delivery queue size |

## 📈 Prometheus Metrics

When enabled (default), BaitBox exposes an auth-protected `/metrics` endpoint in the Prometheus text exposition format:

```text
baitbox_events_total 1234
baitbox_events_protocol_total{protocol="SSH"} 890
baitbox_events_type_total{event_type="auth_attempt"} 412
baitbox_active_sessions 2
baitbox_blocked_ips 7
baitbox_tracked_ips 34
baitbox_active_threats 5
baitbox_attack_reverse_shells 3
baitbox_mitre_technique_ips{technique_id="T1059.004"} 12
```

Scrape it with any Prometheus-compatible collector:

```yaml
scrape_configs:
  - job_name: baitbox
    metrics_path: /metrics
    authorization:
      credentials: <your-dashboard-JWT-or-basic-flow>
    static_configs:
      - targets: ["honeypot-host:8000"]
```

For long-lived scraping, mint a bearer token once via `POST /api/auth/login` and pass it as an `Authorization: Bearer <token>` header.

## 🧬 IOC Threat-Feed Export

`GET /api/ioc` turns recent honeypot activity into a machine-consumable indicator feed. Only genuinely suspicious sources are included: manually blocked IPs, or IPs whose live anomaly score is MEDIUM+.

| Format | Call | Consumer |
|---|---|---|
| JSON (full feed) | `GET /api/ioc?format=json` | Threat-intel dashboards, SIEM |
| CSV (flat table) | `GET /api/ioc?format=csv` | Spreadsheets, incident reports |
| TXT (IP per line) | `GET /api/ioc?format=txt` | ipset / nginx deny / CrowdSec blocklists |

The JSON feed includes per-IP threat scores, MITRE ATT&CK techniques, first/last seen timestamps, captured usernames, sample commands, and probed HTTP paths — plus top credential pairs observed across all attackers.

## 📜 Session Transcripts

Every SSH and Telnet session keeps a bounded, per-command transcript with timestamps and exit codes:

- **Dashboard:** open ACTIVE INTRUDERS → 📜 TRANSCRIPT for a live session.
- **API:** `GET /api/sessions/{session_id}/transcript` returns the structured history (including exit codes — `127` means the attacker ran a command our fake shell didn't know, often a great IOC candidate).

History is capped at `BAITBOX_MAX_SESSION_COMMANDS` (newest retained) so multi-hour automated sessions can't exhaust memory.

## 📈 Anomaly Detection

BaitBox includes a real-time anomaly detection engine that scores each attacker IP based on behavioral patterns:

| Pattern | Score | Description |
|---|---|---|
| Multiple failed logins | +15 | ≥5 auth attempts from a single IP |
| Rapid auth attempts | +30 | ≥3 auth attempts within 10 seconds |
| High-risk commands | +30 | `wget`, `curl`, `chmod`, `chown`, `nc`, `ncat`, `useradd`, `systemctl`, `crontab`, destructive deletes, etc. |
| Privilege escalation | +25 | `root` login or `sudo`/`su` commands |
| Sensitive file access | +20 | Access to `/etc/shadow`, `/etc/passwd`, `.env`, `.git`, SSH keys, `/proc`, and similar discovery targets |
| Rapid command execution | +35 | ≥5 commands within 10 seconds |

**Threat levels:** 🟢 LOW (0–29) · 🟡 MEDIUM (30–69) · 🔴 CRITICAL (70–100)

Scores are displayed per-session on the dashboard and included in webhook notifications.

## 🌐 API Endpoints

| Endpoint | Auth | Description |
|---|---|---|
| `POST /login` | No | Authenticate and receive JWT session cookie (rate-limited) |
| `POST /api/auth/login` | No | API alias for dashboard authentication |
| `GET /logout` · `POST /logout` | No | Revoke the presented JWT (v2.3), clear session cookie, redirect to `/login` |
| `GET /api/events?limit=100&offset=0` | Yes | Recent events (oldest-to-newest) with GeoIP enrichment; supports `protocol`, `src_ip`, `event_type` filters and `offset` pagination (v2.3) |
| `GET /api/events/export?format=json\|csv\|cef\|ecs&limit=500` | Yes | Export recent events with threat scores for offline incident review |
| `GET /api/ioc?format=json\|csv\|txt` | Yes | v2.3: Indicator-of-Compromise feed (malicious IPs, credentials, probed paths) |
| `GET /metrics` | Yes | v2.3: Prometheus metrics scrape endpoint |
| `GET /api/stats` | Yes | Aggregate stats: totals, protocol splits, top IPs, passwords, HTTP paths, hourly timeline, blocked IPs |
| `GET /api/sessions` | Yes | Active SSH/Telnet sessions with GeoIP data |
| `GET /api/sessions/{id}/transcript` | Yes | v2.3: full per-command session transcript with exit codes |
| `POST /api/sessions/{id}/kill` | Yes | Terminate an SSH session |
| `POST /api/block/{ip}` | Yes | Block an IP (persisted across restarts) and terminate all its sessions |
| `POST /api/unblock/{ip}` | Yes | Unblock an IP |
| `GET /api/geoip/{ip}` | Yes | Server-side GeoIP lookup with threat scoring (cached 1h, non-blocking) |
| `GET /api/threat/{ip}` | Yes | Real-time anomaly/threat score for an IP |
| `GET /api/attack-summary` | Yes | Aggregated attack-vector stats + top MITRE ATT&CK techniques |
| `WS /ws/feed` | Yes | Real-time event WebSocket feed with GeoIP enrichment |
| `GET /healthz` | No | Container/orchestrator liveness probe |
| `GET /readyz` | No | Readiness probe with database connectivity check |

## 🏗️ Project Structure

```text
baitbox/
├── baitbox/
│   ├── anomaly.py         # Real-time anomaly detection engine (bounded memory)
│   ├── async_bridge.py    # Thread → asyncio event-loop bridge
│   ├── config.py          # Settings from environment variables
│   ├── db.py              # Database abstraction layer (SQLite/PostgreSQL)
│   ├── db_sqlite.py       # SQLite persistence backend (WAL, single connection)
│   ├── db_postgres.py     # PostgreSQL persistence backend
│   ├── geoip.py           # Server-side GeoIP with threat scoring (non-blocking, evicting cache)
│   ├── ioc.py             # v2.3: Indicator-of-Compromise feed builder (json/csv/txt)
│   ├── main.py            # Entry point (starts all servers + retention task)
│   ├── metrics.py         # v2.3: Prometheus text-exposition metrics builder
│   ├── pubsub.py          # Asyncio pub/sub for WebSocket broadcasting
│   ├── ratelimit.py       # IP rate limiting and persistent block list
│   ├── sessions.py        # Active SSH/Telnet session manager (caps + transcripts)
│   ├── telemetry.py       # SIEM export formatting (CEF, ECS) and input validation
│   ├── vfs.py             # Virtual filesystem for the fake shell
│   ├── webhooks.py        # Discord/Slack/generic webhooks (bounded delivery queue)
│   ├── servers/
│   │   ├── http_server.py # FastAPI dashboard + HTTP honeypot + auth + /metrics + /api/ioc
│   │   ├── ssh_server.py  # Paramiko SSH honeypot (140+ commands, pipes, tab-completion)
│   │   └── telnet_server.py # Asyncio Telnet honeypot (full VFS shell, flood-hardened)
│   └── static/
│       ├── index.html     # Premium single-page dashboard (MITRE panel, filters, transcripts)
│       └── login.html     # Login page
├── tests/
│   ├── test_anomaly.py      # Anomaly detection tests
│   ├── test_anomaly_enhanced.py # Extended anomaly/scoring tests
│   ├── test_api_v22.py      # Event filters / logout / export API tests
│   ├── test_auth.py         # Dashboard authentication tests
│   ├── test_db.py           # Database round-trip tests
│   ├── test_export.py       # Event export tests
│   ├── test_geoip.py        # GeoIP tests
│   ├── test_health.py       # Health/readiness probe tests
│   ├── test_http_server.py  # HTTP honeypot tests
│   ├── test_ioc.py          # v2.3: IOC feed tests
│   ├── test_metrics.py      # v2.3: Prometheus metrics tests
│   ├── test_persistence.py  # Filters, retention pruning, block persistence
│   ├── test_pubsub.py       # Pub/sub tests
│   ├── test_ratelimit.py    # Rate limiter tests
│   ├── test_shell_features.py # Pipes, chaining, expansion, history, completion
│   ├── test_ssh_server.py   # 45+ SSH command tests
│   ├── test_telnet.py       # Telnet protocol tests
│   ├── test_telnet_vfs.py   # Telnet shared-shell & IAC parsing tests
│   ├── test_telemetry.py    # CEF/ECS export + validation tests
│   ├── test_v22_features.py # Webhook filtering, login limits, pruning
│   ├── test_v23_anomaly.py  # v2.3: indicator caps, MITRE mapping
│   ├── test_v23_http.py     # v2.3: new decoys, pagination, transcripts
│   ├── test_v23_security.py # v2.3: JWT revocation, proxy trust, metrics auth
│   ├── test_v23_sessions.py # v2.3: memory caps, session manager, transcripts
│   ├── test_v23_shell.py    # v2.3: new commands, exit codes, history -c
│   ├── test_vfs.py          # 50+ VFS tests
│   ├── test_vfs_enhanced.py # Extended VFS tests
│   └── test_webhooks.py     # Webhook formatting/queue delivery tests
├── .env.example           # Full configuration reference
├── .github/workflows/ci.yml  # CI: pytest matrix + Docker smoke test
├── docker-compose.yml     # PostgreSQL + BaitBox stack
├── Dockerfile             # Non-root hardened image
├── requirements.txt
└── README.md
```

## ⚠️ Disclaimer

BaitBox is intended for **educational and research purposes only**. Deploy only on isolated machines or behind a strict firewall. The maintainers are not responsible for any misuse or damage. Ensure you comply with all applicable laws in your jurisdiction.

## 📄 License

MIT — see `LICENSE` for details.
