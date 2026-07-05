"""Anomaly detection and pattern matching for BaitBox honeypot."""

from __future__ import annotations
import re
import time
from collections import defaultdict
from typing import Any, Dict, List

# In-memory store for IP metrics
# {ip: {"auth_attempts": [timestamps], "commands": [timestamps], "high_risk_detected": bool, "priv_esc_detected": bool, "file_access_detected": bool}}
_ip_metrics: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
    "auth_attempts": [],
    "commands": [],
    "high_risk_detected": False,
    "priv_esc_detected": False,
    "file_access_detected": False,
})


def _clean_old_timestamps(lst: List[float], now: float, window: float = 60.0) -> List[float]:
    """Remove timestamps older than the specified window."""
    return [t for t in lst if now - t <= window]


def reset_metrics(ip: str | None = None) -> None:
    """Clear in-memory anomaly metrics (used by tests)."""
    if ip is None:
        _ip_metrics.clear()
    else:
        _ip_metrics.pop(ip, None)


def get_threat_score(ip: str) -> Dict[str, Any]:
    """
    Calculate the cumulative threat score and level for a given IP address.
    Returns a dict with threat_score, threat_level, and reasons.
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

    return {
        "threat_score": score,
        "threat_level": level,
        "reasons": reasons,
    }


def analyze_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze a new honeypot event, update IP metrics, and return threat information.
    Modifies in-memory metrics for the event's source IP.
    """
    src_ip = event.get("src_ip", "unknown")
    event_type = event.get("event_type", "")
    payload = event.get("payload", {})
    protocol = event.get("protocol", "")

    now = time.time()
    metrics = _ip_metrics[src_ip]

    # Update in-memory state
    if event_type == "auth_attempt":
        metrics["auth_attempts"].append(now)
        # Root logins are counted as privilege escalation attempts
        if payload.get("username") == "root":
            metrics["priv_esc_detected"] = True

    elif event_type == "command" or (protocol in ("SSH", "Telnet") and "command" in payload):
        command = payload.get("command", "")
        metrics["commands"].append(now)

        # Match high risk commands
        if re.search(r"\b(wget|curl|chmod\s+(?:777|\+x)|chown|useradd|groupadd|tftp|netcat|ncat|nc|iptables|systemctl|crontab|rm\s+-rf)\b", command):
            metrics["high_risk_detected"] = True

        # Match privilege escalation commands
        if re.search(r"\b(sudo|su)\b", command):
            metrics["priv_esc_detected"] = True

        # Match suspicious file access patterns
        if re.search(r"(/etc/passwd|/etc/shadow|/etc/hosts|authorized_keys|id_rsa|\.env|\.git|/proc/|/dev/null)", command):
            metrics["file_access_detected"] = True

    elif protocol == "HTTP":
        path = payload.get("path", "")
        if re.search(r"(\.env|\.git|/admin|/wp-admin|/wp-login|/etc/passwd|/etc/shadow)", path):
            metrics["file_access_detected"] = True

    # Calculate and return updated threat stats
    return get_threat_score(src_ip)
