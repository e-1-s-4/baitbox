"""Indicator-of-Compromise (IOC) feed generation for BaitBox.

Aggregates recent honeypot activity into a machine-consumable IOC feed:
malicious source IPs with threat scores, captured credential pairs, probed
HTTP paths, and associated MITRE ATT&CK techniques. Consumers include
firewalls, CrowdSec/fail2ban-style blocklist tools, and threat-intel
dashboards.

Output formats:
  * ``json`` — full structured feed (default)
  * ``csv``  — flat tabular compromise list
  * ``txt``  — one malicious IP per line (ready for ipset / nginx deny)
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from .anomaly import get_threat_score
from .telemetry import validate_ip_address

_THREAT_ORDER = {"CRITICAL": 0, "MEDIUM": 1, "LOW": 2}


def build_ioc_feed(events: list[dict[str, Any]], blocked_ips: list[str] | None = None) -> dict[str, Any]:
    """Aggregate raw events into a structured IOC feed.

    ``events`` must be chronological oldest-to-newest (the shape returned by
    ``get_recent_events``). Only events from IPs that look malicious are
    included: blocked IPs, or IPs whose live threat score is MEDIUM+.
    """
    blocked = set(blocked_ips or [])
    per_ip: dict[str, dict[str, Any]] = {}

    for ev in events:
        src_ip = str(ev.get("src_ip", "")).strip()
        if not src_ip:
            continue
        try:
            src_ip = validate_ip_address(src_ip)
        except ValueError:
            continue

        entry = per_ip.setdefault(src_ip, {
            "ip": src_ip,
            "event_count": 0,
            "protocols": set(),
            "event_types": set(),
            "first_seen": ev.get("timestamp"),
            "last_seen": ev.get("timestamp"),
            "usernames": set(),
            "commands": [],
            "probed_paths": [],
        })
        entry["event_count"] += 1
        if ev.get("protocol"):
            entry["protocols"].add(ev["protocol"])
        if ev.get("event_type"):
            entry["event_types"].add(ev["event_type"])
        ts = ev.get("timestamp")
        if ts:
            if entry["first_seen"] is None or ts < entry["first_seen"]:
                entry["first_seen"] = ts
            if entry["last_seen"] is None or ts > entry["last_seen"]:
                entry["last_seen"] = ts

        payload = ev.get("payload") or {}
        if isinstance(payload, dict):
            if payload.get("username"):
                entry["usernames"].add(str(payload["username"])[:64])
            cmd = payload.get("command")
            if cmd and len(entry["commands"]) < 10:
                entry["commands"].append(str(cmd)[:256])
            path = payload.get("path")
            if path and len(entry["probed_paths"]) < 10:
                entry["probed_paths"].append(str(path)[:256])

    malicious: list[dict[str, Any]] = []
    for ip, entry in per_ip.items():
        threat = get_threat_score(ip)
        is_blocked = ip in blocked
        if not is_blocked and threat["threat_level"] == "LOW":
            continue  # benign-looking scanner noise stays out of the feed
        malicious.append({
            "ip": ip,
            "event_count": entry["event_count"],
            "protocols": sorted(entry["protocols"]),
            "event_types": sorted(entry["event_types"]),
            "first_seen": entry["first_seen"],
            "last_seen": entry["last_seen"],
            "usernames": sorted(entry["usernames"])[:10],
            "commands": entry["commands"],
            "probed_paths": entry["probed_paths"],
            "threat_score": threat["threat_score"],
            "threat_level": threat["threat_level"],
            "mitre_techniques": threat.get("mitre_techniques", []),
            "blocked": is_blocked,
        })

    malicious.sort(key=lambda m: (
        _THREAT_ORDER.get(m["threat_level"], 3),
        -m["event_count"],
        m["ip"],
    ))

    # Credential intelligence: most-reused username/password pairs
    cred_counts: dict[tuple[str, str], int] = {}
    path_counts: dict[str, int] = {}
    technique_counts: dict[str, int] = {}
    for ev in events:
        payload = ev.get("payload") or {}
        if ev.get("event_type") == "auth_attempt" and isinstance(payload, dict):
            user = str(payload.get("username", ""))[:64]
            pwd = str(payload.get("password", ""))[:64]
            if user or pwd:
                key = (user or "(empty)", pwd or "(empty)")
                cred_counts[key] = cred_counts.get(key, 0) + 1
        if ev.get("protocol") == "HTTP" and isinstance(payload, dict):
            path = payload.get("path")
            if path:
                path_counts[str(path)[:256]] = path_counts.get(str(path)[:256], 0) + 1
        for tech in ev.get("mitre_techniques", []) or []:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1

    top_credentials = [
        {"username": u, "password": p, "count": c}
        for (u, p), c in sorted(cred_counts.items(), key=lambda kv: -kv[1])[:20]
    ]
    top_paths = [
        {"path": p, "count": c}
        for p, c in sorted(path_counts.items(), key=lambda kv: -kv[1])[:20]
    ]
    top_techniques = [
        {"technique_id": t, "count": c}
        for t, c in sorted(technique_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
    ]

    return {
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "feed": "baitbox-ioc",
        "malicious_ips": malicious,
        "top_credentials": top_credentials,
        "top_probed_paths": top_paths,
        "mitre_techniques": top_techniques,
    }


def ioc_feed_to_csv(feed: dict[str, Any]) -> str:
    """Flatten the malicious-IP section of the feed into CSV."""
    import csv as _csv
    import io as _io

    out = _io.StringIO()
    writer = _csv.writer(out)
    writer.writerow([
        "ip", "threat_score", "threat_level", "event_count",
        "first_seen", "last_seen", "protocols", "blocked",
    ])
    for m in feed.get("malicious_ips", []):
        writer.writerow([
            m.get("ip", ""),
            m.get("threat_score", 0),
            m.get("threat_level", ""),
            m.get("event_count", 0),
            m.get("first_seen", ""),
            m.get("last_seen", ""),
            ";".join(m.get("protocols", [])),
            "1" if m.get("blocked") else "0",
        ])
    return out.getvalue()


def ioc_feed_to_ip_list(feed: dict[str, Any]) -> str:
    """One malicious IP per line — consumable by ipset, nginx deny, CrowdSec."""
    return "\n".join(m.get("ip", "") for m in feed.get("malicious_ips", []) if m.get("ip")) + (
        "\n" if feed.get("malicious_ips") else ""
    )
