
# 🪤 BaitBox

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#)

> **BaitBox** is a zero-config, multi-protocol honeypot for homelabbers and security researchers. Drop attackers into a stateful fake filesystem, watch them try to pivot, and get real-time alerts — all from a beautiful cyber command-center dashboard.

<img width="1280" height="720" alt="y" src="https://github.com/user-attachments/assets/6ef378cd-ddf3-40c8-808e-423c1ccb95fd" />

## 🚀 Features

- **🛡️ Multi-Protocol Honeypot:** Simultaneously traps SSH, HTTP, and Telnet attackers.
- **🎭 Stateful Fake Filesystem (VFS):** SSH attackers are dropped into a convincing virtual Linux machine with realistic files: `~/.bash_history`, `~/.bashrc` (with fake DB passwords), `~/.ssh/authorized_keys`, `/var/www/html/.env`, `/etc/shadow`, `/etc/crontab`, Nginx config, MySQL dumps, auth logs, and more.
- **💻 70+ Fake Shell Commands:** Full interactive shell with `ls -la` (hidden files), `cd ~`, `cat`, `grep`, `find`, `ps aux`, `netstat`, `ifconfig`/`ip`, `who`, `last`, `df`, `free`, `top`, `crontab -l`, `python3 -c`, `mysql`, `git log`, `systemctl status`, `nmap`, `wget`/`curl`, `ping`, `vi`/`nano`, `chmod`, `chown`, `useradd`, `passwd`, `tar`, `gzip`, `zip`, `unzip`, `which`, `whereis`, `man`, `dpkg`, `apt`, `yum`, `echo` with redirection, shell script execution, history navigation (↑ arrow), Ctrl+C, Ctrl+D.
- **📡 Telnet Honeypot:** An asyncio-powered Telnet server on port 2323 that captures credentials and commands.
- **📊 Premium Dashboard:** A stunning, pure-vanilla-CSS cyber command center with:
  - **Live GeoIP Attack Map** (server-side resolution, cached, no API key needed)
  - **Threat Score Indicators** (🔴 HIGH / 🟡 MED / 🟢 LOW per attacker)
  - **24-Hour Event Timeline** chart
  - **Protocol Split** donut chart
  - **Real-time event stream** with pause/resume
  - **IP Block/Unblock** controls — one click blocks an IP and terminates their sessions
  - **Top Offending IPs, Top Passwords, Top HTTP Paths** leaderboards
  - **Active Intruder Controller** — live session view with BOOT/BLOCK/MAP buttons
- **🔐 Dashboard Authentication:** Login-protected dashboard with bcrypt-hashed credentials and JWT session tokens.
- **🔔 Webhook Notifications:** Discord and Slack alerts for auth attempts, commands, and decoy hits.
- **📈 Anomaly Detection:** Real-time per-IP threat scoring with pattern analysis for rapid auth attempts, high-risk commands, privilege escalation, and sensitive file access.
- **🚫 IP Rate Limiting & Block List:** Automatic connection tracking; manually block IPs from the dashboard.
- **🐘 PostgreSQL Support:** Optional PostgreSQL backend for production-grade persistence via Docker Compose.
- **🐳 Zero-Config Docker:** Full honeypot + dashboard in 5 seconds.
- **🔒 Enhanced Security:** Input validation, command length limits, CORS support, and secure configuration defaults.
- **🧹 Automatic Session Cleanup:** Background task to clean up stale SSH sessions (configurable).
- **📝 Structured Logging:** Comprehensive logging with timestamps and log levels for debugging and monitoring.
- **⚡ Performance Optimizations:** PostgreSQL connection pooling, enhanced caching, and optimized database queries.

## ⚡ Quickstart

### Docker (Recommended — SQLite, zero-config)

```bash
docker run -d \
  --name baitbox \
  -p 2222:2222 \
  -p 2323:2323 \
  -p 8000:8000 \
  ghcr.io/qylen/baitbox:latest
```

Open **http://localhost:8000** to see the dashboard.  
Login with **admin / admin** (change via env vars in production!).

### Docker Compose (PostgreSQL backend)

```bash
git clone https://github.com/qylen/baitbox.git
cd baitbox
docker compose up -d
```

This starts BaitBox with a PostgreSQL database for production workloads. See `docker-compose.yml` for configuration.

### Python (local dev)

```bash
git clone https://github.com/qylen/baitbox.git
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
```

**Telnet Honeypot:**
```bash
telnet localhost 2323
# Enter any username/password
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

All `/api/*` endpoints and the `/ws/feed` WebSocket require a valid JWT session cookie or bearer token. Unauthenticated API requests return **401 Unauthorized**, unauthenticated WebSocket handshakes are rejected with **403 Forbidden**, and unauthenticated dashboard visits are redirected to `/login`.

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
| `POST /login` | No | Authenticate and receive JWT session cookie |
| `POST /api/auth/login` | No | API alias for dashboard authentication |
| `POST /logout` | Yes | Clear session cookie |
| `GET /api/events?limit=100` | Yes | Recent events (oldest-to-newest) with GeoIP enrichment |
| `GET /api/events/export?format=json|csv&limit=500` | Yes | Export recent events for offline incident review |
| `GET /api/stats` | Yes | Aggregate stats: totals, protocol splits, top IPs, passwords, HTTP paths, hourly timeline, blocked IPs |
| `GET /api/sessions` | Yes | Active SSH sessions with GeoIP data |
| `POST /api/sessions/{id}/kill` | Yes | Terminate an SSH session |
| `POST /api/block/{ip}` | Yes | Block an IP and terminate all its sessions |
| `POST /api/unblock/{ip}` | Yes | Unblock an IP |
| `GET /api/geoip/{ip}` | Yes | Server-side GeoIP lookup with threat scoring (cached 1h) |
| `GET /api/threat/{ip}` | Yes | Real-time anomaly/threat score for an IP |
| `WS /ws/feed` | Yes | Real-time event WebSocket feed with GeoIP enrichment |
| `GET /healthz` | No | Container/orchestrator liveness probe |
| `GET /readyz` | No | Readiness probe with database connectivity check |

## 🏗️ Project Structure

```text
baitbox/
├── baitbox/
│   ├── anomaly.py         # Real-time anomaly detection engine
│   ├── config.py          # Settings from environment variables
│   ├── db.py              # Database abstraction layer (SQLite/PostgreSQL)
│   ├── db_sqlite.py       # SQLite persistence backend
│   ├── db_postgres.py     # PostgreSQL persistence backend
│   ├── geoip.py           # Server-side GeoIP with threat scoring
│   ├── main.py            # Entry point (starts all servers)
│   ├── pubsub.py          # Asyncio pub/sub for WebSocket broadcasting
│   ├── ratelimit.py       # IP rate limiting and block list
│   ├── sessions.py        # Active SSH session manager
│   ├── vfs.py             # Virtual filesystem for SSH honeypot
│   ├── webhooks.py        # Discord/Slack/generic webhook notifications
│   ├── servers/
│   │   ├── http_server.py # FastAPI dashboard + HTTP honeypot + auth
│   │   ├── ssh_server.py  # Paramiko SSH honeypot (50+ commands)
│   │   └── telnet_server.py # Asyncio Telnet honeypot
│   └── static/
│       └── index.html     # Premium single-page dashboard with login
├── tests/
│   ├── test_anomaly.py    # Anomaly detection tests
│   ├── test_auth.py       # Dashboard authentication tests
│   ├── test_db.py         # Database round-trip tests
│   ├── test_http_server.py # HTTP honeypot tests
│   ├── test_ratelimit.py  # Rate limiter tests
│   ├── test_ssh_server.py # 40+ SSH command tests
│   └── test_vfs.py        # 50+ VFS tests
├── docker-compose.yml     # PostgreSQL + BaitBox stack
├── Dockerfile
├── requirements.txt
└── README.md
```

## ⚠️ Disclaimer

BaitBox is intended for **educational and research purposes only**. Deploy only on isolated machines or behind a strict firewall. The maintainers are not responsible for any misuse or damage. Ensure you comply with all applicable laws in your jurisdiction.

## 📄 License

MIT — see `LICENSE` for details.
