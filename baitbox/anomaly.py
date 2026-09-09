"""Anomaly detection, signature matching, and MITRE ATT&CK mapping for BaitBox honeypot."""

from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

# In-memory store for IP metrics
# {ip: {"auth_attempts": [timestamps], "commands": [timestamps], ...}}
_ip_metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "auth_attempts": [],
    "commands": [],
    "high_risk_detected": False,
    "priv_esc_detected": False,
    "file_access_detected": False,
    "cryptominer_detected": False,
    "reverse_shell_detected": False,
    "exploit_detected": False,
    "recon_detected": False,
    "matched_indicators": [],
    "mitre_techniques": set(),
})

# Global attack statistics for telemetry dashboards
_attack_stats: Dict[str, int] = defaultdict(int)

# Pruning controls: cap memory usage for scans from many unique IPs.
_MAX_TRACKED_IPS = 5000
_IDLE_SECONDS = 3600.0
_last_activity: Dict[str, float] = {}
_events_since_prune = 0


# ── MITRE ATT&CK Technique Definitions ──────────────────────────────────────

MITRE_TECHNIQUES = {
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "tactic": "Execution",
        "description": "Adversary executing commands through interactive or scripted Unix shell.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation",
        "description": "Adversary authenticating with default or stolen credentials (e.g. root/admin).",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversary scanning ports, endpoints, or network services (nmap, masscan, netstat).",
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": "Adversary hijacking system resources for cryptomining (e.g. XMRig, Monero).",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversary exploiting software vulnerabilities (Log4Shell, Spring4Shell, Shellshock, SQLi).",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversary modifying crontab or cron files for task persistence.",
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "description": "Adversary searching for secrets in configuration files, .env, .aws, or shadow.",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "description": "Adversary attempting sudo or privilege escalation commands.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversary transferring tools from external systems (wget, curl, tftp).",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "description": "Adversary communicating over standard HTTP/S or probing decoys.",
    },
    "T1070.004": {
        "name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "description": "Adversary deleting files or logs to erase forensic evidence.",
    },
}


# ── Signature Matchers ──────────────────────────────────────────────────────

# Cryptominer indicators
_CRYPTOMINER_PATTERNS = [
    (r"\b(xmrig|minerd|cryptonight|cpuminer|ccminer)\b", "Known cryptominer binary name"),
    (r"stratum\+(?:tcp|ssl)://", "Stratum mining pool connection URI"),
    (r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", "Monero (XMR) wallet address pattern"),
    (r"(?:supportxmr\.com|minergate\.com|moneroocean\.stream|nanopool\.org|hashvault\.pro|minexmr\.com)", "Known cryptocurrency mining pool hostname"),
    (r"(?:-o\s+stratum|-u\s+[a-zA-Z0-9\.]+\s+-p\s+x)", "Cryptominer command-line flags"),
]

# Reverse shell indicators
_REVERSE_SHELL_PATTERNS = [
    (r"bash\s+-i\s+>&?\s*/dev/tcp/\S+/\d+", "Bash /dev/tcp interactive reverse shell"),
    (r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", "Bash /dev/tcp socket redirection"),
    (r"\b(?:nc|ncat|netcat)\b.*?-e\s+/(?:bin|usr)/[a-z]*sh", "Netcat executable reverse shell (-e)"),
    (r"\bmkfifo\s+\S+;\s*(?:cat|sh|bash)", "FIFO named-pipe reverse shell"),
    (r"python(?:\d)?\s+-c\s+['\"].*?(?:socket|pty\.spawn).*?['\"]", "Python socket/pty reverse shell"),
    (r"perl\s+-e\s+['\"].*?use\s+Socket.*?['\"]", "Perl socket reverse shell"),
    (r"socat\s+exec:.*?,pty.*?tcp:", "Socat interactive reverse shell"),
]

# Web exploit indicators
_WEB_EXPLOIT_PATTERNS = [
    (r"\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|http)://", "Log4j / Log4Shell (CVE-2021-44228) JNDI lookup"),
    (r"class\.module\.classLoader", "Spring4Shell (CVE-2022-22965) classLoader injection"),
    (r"\(\)\s*\{\s*:\s*;\s*\}\s*;", "Shellshock (CVE-2014-6271) function definition injection"),
    (r"169\.254\.169\.254|metadata\.google\.internal", "SSRF cloud metadata instance endpoint access"),
    (r"(?:union\s+select|select\s+.*from|' OR '1'='1|waitfor\s+delay|benchmark\(\d+,|sleep\(\d+\))", "SQL injection pattern"),
    (r"(?:<script\b|javascript:|onerror=|onload=)", "Cross-site scripting (XSS) payload"),
    (r"(?:\.\./\.\./|\.\.\\\.\.\\|%2e%2e/|%252e%252e)", "Directory path traversal probe"),
    (r"(?:c99\.php|r57\.php|wso\.php|alfa\.php|eval\(base64_decode)", "Known PHP webshell or backdoor probe"),
]


def _clean_old_timestamps(lst: List[float], now: float, window: float = 60.0) -> List[float]:
    """Remove timestamps older than the specified window."""
    return [t for t in lst if now - t <= window]


def prune_metrics(max_ips: int = _MAX_TRACKED_IPS, idle_seconds: float = _IDLE_SECONDS) -> int:
    """Drop idle IP entries when the tracking table grows too large."""
    now = time.time()
    if len(_ip_metrics) <= max_ips:
        return 0
    stale = [
        ip for ip, last in _last_activity.items()
        if now - last > idle_seconds
    ]
    for ip in stale:
        _ip_metrics.pop(ip, None)
        _last_activity.pop(ip, None)

    # Still too large? Evict the least recently active half.
    if len(_ip_metrics) > max_ips:
        ordered = sorted(_last_activity.items(), key=lambda kv: kv[1])
        for ip, _ in ordered[: len(ordered) // 2]:
            _ip_metrics.pop(ip, None)
            _last_activity.pop(ip, None)
    return len(stale)


def reset_metrics(ip: str | None = None) -> None:
    """Clear in-memory anomaly metrics (used by tests)."""
    if ip is None:
        _ip_metrics.clear()
        _last_activity.clear()
        _attack_stats.clear()
    else:
        _ip_metrics.pop(ip, None)
        _last_activity.pop(ip, None)


def detect_cryptominer(text: str) -> List[Dict[str, Any]]:
    """Check text for cryptomining signatures."""
    matches = []
    # Limit length to avoid excessive regex work
    sample = text[:4096]
    for pat, desc in _CRYPTOMINER_PATTERNS:
        if re.search(pat, sample, re.IGNORECASE):
            matches.append({
                "rule": "CRYPTOMINER",
                "description": desc,
                "mitre_id": "T1496",
                "severity": "HIGH",
            })
    return matches


def detect_reverse_shell(text: str) -> List[Dict[str, Any]]:
    """Check text for reverse shell signatures."""
    matches = []
    sample = text[:4096]
    for pat, desc in _REVERSE_SHELL_PATTERNS:
        if re.search(pat, sample, re.IGNORECASE):
            matches.append({
                "rule": "REVERSE_SHELL",
                "description": desc,
                "mitre_id": "T1059.004",
                "severity": "CRITICAL",
            })
    return matches


def detect_web_exploit(path: str, query: str = "", body: str = "") -> List[Dict[str, Any]]:
    """Check HTTP request parameters for web exploit signatures."""
    matches = []
    full_req = f"{path}?{query} {body}"[:4096]
    for pat, desc in _WEB_EXPLOIT_PATTERNS:
        if re.search(pat, full_req, re.IGNORECASE):
            matches.append({
                "rule": "WEB_EXPLOIT",
                "description": desc,
                "mitre_id": "T1190",
                "severity": "HIGH",
            })
    return matches


def get_mitre_attack_tags(command_or_path: str, protocol: str = "SSH") -> List[Dict[str, str]]:
    """Return mapped MITRE ATT&CK technique details for a command, path, or activity."""
    sample = command_or_path[:4096]
    tags: List[Dict[str, str]] = []
    added = set()

    def _add(tech_id: str):
        if tech_id not in added and tech_id in MITRE_TECHNIQUES:
            added.add(tech_id)
            info = MITRE_TECHNIQUES[tech_id]
            tags.append({
                "technique_id": tech_id,
                "technique_name": info["name"],
                "tactic": info["tactic"],
            })

    if protocol in ("SSH", "Telnet"):
        _add("T1059.004")  # Unix shell execution
        if re.search(r"\b(sudo|su|pkexec|doas)\b", sample):
            _add("T1548.003")
        if re.search(r"\b(wget|curl|tftp|scp)\b", sample):
            _add("T1105")
        if re.search(r"(/etc/passwd|/etc/shadow|\.env|id_rsa|authorized_keys|secrets\.txt)", sample):
            _add("T1552.001")
        if re.search(r"\b(crontab|/etc/cron)\b", sample):
            _add("T1053.003")
        if re.search(r"\b(nmap|ping|masscan|netstat|arp|ifconfig|ip\s+a)\b", sample):
            _add("T1046")
        if re.search(r"\b(rm\s+-rf|shred|history\s+-c)\b", sample):
            _add("T1070.004")
        if detect_cryptominer(sample):
            _add("T1496")

    elif protocol == "HTTP":
        _add("T1071.001")  # Web protocols
        if detect_web_exploit(sample):
            _add("T1190")
        if re.search(r"(\.env|\.git|\.aws|shadow|passwd)", sample):
            _add("T1552.001")

    return tags


def get_threat_score(ip: str) -> Dict[str, Any]:
    """
    Calculate the cumulative threat score and level for a given IP address.
    Returns a dict with threat_score, threat_level, reasons, indicators, and MITRE techniques.
    """
    metrics = _ip_metrics[ip]
    now = time.time()

    # Clean up old timestamps
    metrics["auth_attempts"] = _clean_old_timestamps(metrics["auth_attempts"], now)
    metrics["commands"] = _clean_old_timestamps(metrics["commands"], now)

    score = 0
    reasons: List[str] = []

    # 1. Auth attempt frequency (bot-like password guessing)
    attempts_10s = len([t for t in metrics["auth_attempts"] if now - t <= 10.0])
    if attempts_10s > 3:
        score += 30
        reasons.append(f"High frequency of login attempts ({attempts_10s} in last 10s)")
    elif len(metrics["auth_attempts"]) > 5:
        score += 15
        reasons.append("Multiple failed login attempts")

    # 2. Command execution frequency (rapid command execution)
    cmds_5s = len([t for t in metrics["commands"] if now - t <= 5.0])
    if cmds_5s > 4:
        score += 35
        reasons.append(f"Rapid command execution ({cmds_5s} in last 5s)")

    # 3. High risk command patterns
    if metrics["high_risk_detected"]:
        score += 30
        reasons.append("Flagged high-risk commands (e.g. wget, curl, chmod)")

    # 4. Privilege escalation attempts
    if metrics["priv_esc_detected"]:
        score += 25
        reasons.append("Privilege escalation attempts (e.g. su, sudo, or root login)")

    # 5. Sensitive file access patterns
    if metrics["file_access_detected"]:
        score += 20
        reasons.append("Suspicious file/directory access patterns (e.g. /etc/passwd, .env)")

    # Cap score at 100
    score = min(score, 100)

    # Risk level classification
    if score >= 70:
        level = "CRITICAL"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Compile attack categories
    categories = []
    if metrics.get("cryptominer_detected"):
        categories.append("CRYPTOMINING")
    if metrics.get("reverse_shell_detected"):
        categories.append("REVERSE_SHELL")
    if metrics.get("exploit_detected"):
        categories.append("EXPLOIT")
    if metrics.get("priv_esc_detected"):
        categories.append("PRIVILEGE_ESCALATION")
    if metrics.get("file_access_detected"):
        categories.append("CREDENTIAL_ACCESS")

    return {
        "threat_score": score,
        "threat_level": level,
        "reasons": reasons,
        "indicators": metrics.get("matched_indicators", []),
        "mitre_techniques": sorted(list(metrics.get("mitre_techniques", set()))),
        "attack_categories": categories,
    }


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a new honeypot event, update IP metrics, and return threat information.
    Modifies in-memory metrics for the event's source IP.
    """
    global _events_since_prune
    src_ip = event.get("src_ip", "unknown")
    event_type = event.get("event_type", "")
    payload = event.get("payload", {})
    protocol = event.get("protocol", "")

    now = time.time()
    metrics = _ip_metrics[src_ip]
    _last_activity[src_ip] = now
    _events_since_prune += 1
    if _events_since_prune >= 500:
        _events_since_prune = 0
        prune_metrics()

    # Update in-memory state
    if event_type == "auth_attempt":
        metrics["auth_attempts"].append(now)
        _attack_stats["auth_attempts"] += 1
        # Root logins are counted as privilege escalation attempts
        if payload.get("username") == "root":
            metrics["priv_esc_detected"] = True
            metrics["mitre_techniques"].add("T1078")
            _attack_stats["root_logins"] += 1

    elif event_type == "command" or (protocol in ("SSH", "Telnet") and "command" in payload):
        command = str(payload.get("command", ""))[:4096]
        metrics["commands"].append(now)
        _attack_stats["commands"] += 1

        # Match high risk commands (downloads, network tools, execution, reverse shell patterns)
        if re.search(r"\b(wget|curl|chmod\s+(?:777|\+x)|chown|useradd|groupadd|tftp|netcat|ncat|nc|socat|iptables|systemctl|crontab|rm\s+-rf|nohup|pkill|killall)\b", command) or re.search(r"(bash\s+-i|pty\.spawn|/dev/tcp/|exec\s+5<>|socket\.socket)", command):
            metrics["high_risk_detected"] = True
            metrics["mitre_techniques"].add("T1059.004")

        # Match privilege escalation commands
        if re.search(r"\b(sudo|su|pkexec|doas)\b", command):
            metrics["priv_esc_detected"] = True
            metrics["mitre_techniques"].add("T1548.003")
            _attack_stats["privilege_escalations"] += 1

        # Match suspicious file access patterns
        if re.search(r"(/etc/passwd|/etc/shadow|/etc/sudoers|/etc/hosts|authorized_keys|id_rsa|\.env|\.git|\.aws|\.docker|\.kube|/proc/|/dev/null)", command):
            metrics["file_access_detected"] = True
            metrics["mitre_techniques"].add("T1552.001")
            _attack_stats["credential_access"] += 1

        # Detect cryptominers
        crypto_hits = detect_cryptominer(command)
        if crypto_hits:
            metrics["cryptominer_detected"] = True
            metrics["high_risk_detected"] = True
            metrics["mitre_techniques"].add("T1496")
            metrics["matched_indicators"].extend(crypto_hits)
            _attack_stats["cryptomining_probes"] += 1

        # Detect reverse shells
        rev_hits = detect_reverse_shell(command)
        if rev_hits:
            metrics["reverse_shell_detected"] = True
            metrics["high_risk_detected"] = True
            metrics["mitre_techniques"].add("T1059.004")
            metrics["matched_indicators"].extend(rev_hits)
            _attack_stats["reverse_shells"] += 1

        # Add general MITRE tags
        for tag in get_mitre_attack_tags(command, protocol):
            metrics["mitre_techniques"].add(tag["technique_id"])

    elif protocol == "HTTP":
        path = str(payload.get("path", ""))[:1024]
        query = str(payload.get("query", ""))[:1024]
        body_str = str(payload.get("body", ""))[:2048]
        full_req = f"{path}?{query} {body_str}"
        _attack_stats["http_requests"] += 1

        # Match sensitive path probes
        if re.search(r"(\.env|\.git|\.aws|\.docker|\.kube|/admin|/wp-admin|/wp-login|/etc/passwd|/etc/shadow|/actuator|/console)", path):
            metrics["file_access_detected"] = True
            metrics["mitre_techniques"].add("T1552.001")
            _attack_stats["credential_probes"] += 1

        # Match web attack patterns (SQLi, XSS, Path Traversal, Command Injection)
        if re.search(r"(union\s+select|select\s+.*from|' OR '1'='1|<script>|\.\./\.\./|;\s*cat\s+|;\s*wget|;\s*curl)", full_req, re.IGNORECASE):
            metrics["high_risk_detected"] = True
            metrics["mitre_techniques"].add("T1190")
            _attack_stats["web_exploits"] += 1

        # Additional rich exploit detection
        exploit_hits = detect_web_exploit(path, query, body_str)
        if exploit_hits:
            metrics["exploit_detected"] = True
            metrics["high_risk_detected"] = True
            metrics["mitre_techniques"].add("T1190")
            metrics["matched_indicators"].extend(exploit_hits)
            _attack_stats["web_exploits"] += 1

        for tag in get_mitre_attack_tags(full_req, "HTTP"):
            metrics["mitre_techniques"].add(tag["technique_id"])

    # Calculate and return updated threat stats
    return get_threat_score(src_ip)


def get_attack_summary() -> Dict[str, Any]:
    """Return aggregated telemetry across all detected attack vectors."""
    now = time.time()
    active_threats = sum(1 for m in _ip_metrics.values() if m["high_risk_detected"] or m["priv_esc_detected"])
    total_ips = len(_ip_metrics)

    # Collect technique frequency
    technique_counts: Dict[str, int] = defaultdict(int)
    for m in _ip_metrics.values():
        for tech in m.get("mitre_techniques", set()):
            technique_counts[tech] += 1

    top_techniques = [
        {
            "technique_id": tech_id,
            "name": MITRE_TECHNIQUES.get(tech_id, {}).get("name", "Unknown"),
            "tactic": MITRE_TECHNIQUES.get(tech_id, {}).get("tactic", "Unknown"),
            "count": count,
        }
        for tech_id, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    return {
        "active_threats": active_threats,
        "total_tracked_ips": total_ips,
        "stats": dict(_attack_stats),
        "top_mitre_techniques": top_techniques,
    }
