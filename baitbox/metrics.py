"""Prometheus metrics exposition for BaitBox (text/plain; version=0.0.4).

Builds a scrape-ready payload from the anomaly engine, session manager,
rate limiter and database stats without requiring any external client
library — keeps the dependency footprint zero.
"""

from __future__ import annotations

from typing import Any

from .anomaly import get_attack_summary, get_threat_score


def _escape_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _num(value: Any) -> str:
    """Coerce a stat value to a Prometheus-safe numeric string."""
    try:
        return str(int(value))
    except (TypeError, ValueError):
        try:
            return str(float(value))
        except (TypeError, ValueError):
            return "0"


def _dict_rows(rows: Any) -> list[dict[str, Any]]:
    """Keep only dict rows so a single malformed aggregate cannot break scraping."""
    if not isinstance(rows, (list, tuple)):
        return []
    return [row for row in rows if isinstance(row, dict)]


def build_prometheus_metrics(stats: dict[str, Any], blocked_count: int, session_count: int) -> str:
    """Render the Prometheus text exposition payload.

    ``stats`` is the dict returned by the database ``get_stats()`` helper.
    """
    if not isinstance(stats, dict):
        stats = {}
    lines: list[str] = []

    def _metric(name: str, m_type: str, help_text: str) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {m_type}")

    total = stats.get("total_events", 0)
    _metric("baitbox_events_total", "counter", "Total honeypot events recorded.")
    lines.append(f"baitbox_events_total {_num(total)}")

    _metric("baitbox_events_protocol_total", "counter", "Events recorded per protocol.")
    for row in _dict_rows(stats.get("by_protocol")):
        proto = _escape_label(row.get("protocol", "unknown"))
        lines.append(f'baitbox_events_protocol_total{{protocol="{proto}"}} {_num(row.get("count", 0))}')

    _metric("baitbox_events_type_total", "counter", "Events recorded per event type.")
    for row in _dict_rows(stats.get("by_event_type")):
        etype = _escape_label(row.get("event_type", "unknown"))
        lines.append(f'baitbox_events_type_total{{event_type="{etype}"}} {_num(row.get("count", 0))}')

    _metric("baitbox_active_sessions", "gauge", "Currently active attacker sessions.")
    lines.append(f"baitbox_active_sessions {_num(session_count)}")

    _metric("baitbox_blocked_ips", "gauge", "Manually blocked attacker IPs.")
    lines.append(f"baitbox_blocked_ips {_num(blocked_count)}")

    # Threat-level distribution from the live anomaly engine
    summary = get_attack_summary()
    if not isinstance(summary, dict):
        summary = {}
    _metric("baitbox_tracked_ips", "gauge", "Attacker IPs currently tracked by the anomaly engine.")
    lines.append(f"baitbox_tracked_ips {_num(summary.get('total_tracked_ips', 0))}")

    _metric("baitbox_active_threats", "gauge", "Tracked IPs flagged for high-risk behaviour.")
    lines.append(f"baitbox_active_threats {_num(summary.get('active_threats', 0))}")

    attack_stats = summary.get("stats", {})
    if isinstance(attack_stats, dict):
        for stat_name, value in sorted(attack_stats.items()):
            safe = _escape_label(stat_name)
            lines.append(f"# TYPE baitbox_attack_{safe} counter")
            lines.append(f"# HELP baitbox_attack_{safe} Attack telemetry counter: {safe}.")
            lines.append(f"baitbox_attack_{safe} {_num(value)}")

    _metric("baitbox_auth_attempts_total", "counter", "Total authentication attempts observed (24h-independent).")
    auth_rows = {row.get("event_type"): row.get("count", 0) for row in _dict_rows(stats.get("by_event_type"))}
    lines.append(f"baitbox_auth_attempts_total {_num(auth_rows.get('auth_attempt', 0))}")

    _metric("baitbox_mitre_technique_ips", "gauge", "Tracked IPs associated with each MITRE ATT&CK technique.")
    for row in _dict_rows(summary.get("top_mitre_techniques")):
        tech = _escape_label(row.get("technique_id", "unknown"))
        lines.append(f'baitbox_mitre_technique_ips{{technique_id="{tech}"}} {_num(row.get("count", 0))}')

    lines.append("")
    return "\n".join(lines)
