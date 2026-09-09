"""Telemetry, SIEM export formatting (CEF, ECS, JSON), and input validation utilities."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("baitbox.telemetry")


# ── Structured JSON Logging Formatter ───────────────────────────────────────

class JSONLogFormatter(logging.Formatter):
    """Format Python log records as single-line JSON strings for SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": dt.datetime.fromtimestamp(record.created, tz=dt.timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "thread": record.threadName,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


# ── Input Validation and Sanitization ───────────────────────────────────────

def validate_ip_address(value: str) -> str:
    """
    Validate and canonicalize an IPv4 or IPv6 address.
    Raises ValueError on malformed addresses.
    """
    if not value or not isinstance(value, str):
        raise ValueError("IP address must be a non-empty string.")
    clean = value.strip()
    try:
        obj = ipaddress.ip_address(clean)
        # Canonical string representation (e.g. compressed IPv6)
        return str(obj)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address format: '{clean}'") from exc


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is in a private RFC1918/RFC4193 range."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def is_loopback_ip(ip_str: str) -> bool:
    """Return True if the IP address is a loopback address."""
    try:
        return ipaddress.ip_address(ip_str).is_loopback
    except ValueError:
        return False


def sanitize_input(text: str, max_length: int = 4096) -> str:
    """Trim whitespace and enforce a strict upper length bound to prevent ReDoS/DoS."""
    if not isinstance(text, str):
        return ""
    return text[:max_length].strip()


def clamp_limit(
    limit: Any,
    default: int = 100,
    minimum: int = 1,
    maximum: int = 1000,
) -> int:
    """Safely clamp user pagination/query limit values within defined boundaries."""
    try:
        val = int(limit)
    except (ValueError, TypeError):
        return default
    return max(minimum, min(val, maximum))


# ── SIEM Export: Common Event Format (CEF) ──────────────────────────────────

def _cef_escape(val: Any) -> str:
    """Escape special characters per the ArcSight CEF standard."""
    s = str(val) if val is not None else ""
    return s.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def export_cef_event(event: Dict[str, Any]) -> str:
    """
    Convert a BaitBox event dict to an ArcSight Common Event Format (CEF) string.
    Header: CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
    """
    version = "0"
    vendor = "BaitBox"
    product = "Honeypot"
    dev_version = "2.2.0"
    event_type = event.get("event_type", "activity")
    name = f"{event.get('protocol', 'UNKNOWN')} {event_type.replace('_', ' ').title()}"

    threat_score = event.get("threat_score", 0)
    # CEF severity is an integer from 0 to 10
    severity = max(0, min(int(round(threat_score / 10)), 10))

    src_ip = event.get("src_ip", "")
    protocol = event.get("protocol", "")
    ts = event.get("timestamp", "")
    payload = event.get("payload", {})

    extensions = [
        f"src={_cef_escape(src_ip)}",
        f"proto={_cef_escape(protocol)}",
        f"cat={_cef_escape(event_type)}",
        f"act={_cef_escape(event_type)}",
        f"cn1={threat_score}",
        "cn1Label=threatScore",
    ]

    if ts:
        extensions.append(f"rt={_cef_escape(ts)}")

    if isinstance(payload, dict):
        if "username" in payload:
            extensions.append(f"suser={_cef_escape(payload['username'])}")
        if "command" in payload:
            extensions.append(f"msg={_cef_escape(payload['command'])}")
        elif "path" in payload:
            extensions.append(f"request={_cef_escape(payload['path'])}")
            if "method" in payload:
                extensions.append(f"requestMethod={_cef_escape(payload['method'])}")

    mitre_techs = event.get("mitre_techniques")
    if mitre_techs and isinstance(mitre_techs, list):
        extensions.append(f"cs1={_cef_escape(','.join(mitre_techs))}")
        extensions.append("cs1Label=mitreTechniques")

    return f"CEF:{version}|{vendor}|{product}|{dev_version}|{event_type}|{name}|{severity}|{' '.join(extensions)}"


# ── SIEM Export: Elastic Common Schema (ECS) ────────────────────────────────

def export_ecs_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a BaitBox event dict to Elastic Common Schema (ECS) specification format.
    Compatible with Elasticsearch, Logstash, Filebeat, and Kibana SIEM.
    """
    ts = event.get("timestamp")
    if not ts:
        ts = dt.datetime.now(dt.timezone.utc).isoformat()

    protocol = str(event.get("protocol", "generic")).lower()
    event_type = str(event.get("event_type", "event"))
    src_ip = event.get("src_ip", "")
    payload = event.get("payload", {})
    threat_score = event.get("threat_score", 0)
    threat_level = event.get("threat_level", "LOW")

    ecs: Dict[str, Any] = {
        "@timestamp": ts,
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "alert" if threat_level in ("MEDIUM", "CRITICAL") else "event",
            "category": ["intrusion_detection", "threat"],
            "type": ["info"],
            "action": event_type,
            "dataset": f"baitbox.{protocol}",
            "risk_score": float(threat_score),
            "severity": 3 if threat_level == "CRITICAL" else (2 if threat_level == "MEDIUM" else 1),
        },
        "observer": {
            "vendor": "BaitBox",
            "product": "Honeypot",
            "type": "honeypot",
            "version": "2.2.0",
        },
        "source": {
            "ip": src_ip,
        },
        "network": {
            "protocol": protocol,
        },
    }

    # Populate protocol-specific details
    if protocol in ("ssh", "telnet"):
        if event_type == "auth_attempt" and isinstance(payload, dict):
            ecs["user"] = {"name": payload.get("username", "")}
            ecs["event"]["type"] = ["authentication"]
        elif event_type == "command" and isinstance(payload, dict):
            ecs["process"] = {
                "command_line": payload.get("command", ""),
            }
    elif protocol == "http" and isinstance(payload, dict):
        ecs["http"] = {
            "request": {
                "method": payload.get("method", "GET"),
                "body": {"bytes": len(str(payload.get("body", "")))},
            },
        }
        ecs["url"] = {
            "path": payload.get("path", ""),
            "query": payload.get("query", ""),
        }
        if payload.get("user_agent"):
            ecs["user_agent"] = {"original": payload.get("user_agent")}

    if "geo" in event and isinstance(event["geo"], dict):
        geo = event["geo"]
        ecs["source"]["geo"] = {
            "country_name": geo.get("country"),
            "country_iso_code": geo.get("countryCode"),
            "city_name": geo.get("city"),
            "region_name": geo.get("regionName"),
        }

    mitre_techs = event.get("mitre_techniques")
    if mitre_techs and isinstance(mitre_techs, list):
        ecs["threat"] = {
            "framework": "MITRE ATT&CK",
            "technique": [{"id": tech} for tech in mitre_techs],
        }

    return ecs
