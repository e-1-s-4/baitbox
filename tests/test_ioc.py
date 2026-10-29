"""Tests for the IOC (Indicator of Compromise) feed builder (v2.3.0)."""

from __future__ import annotations

import csv
import io

from baitbox.ioc import build_ioc_feed, ioc_feed_to_csv, ioc_feed_to_ip_list
from baitbox.anomaly import analyze_event, reset_metrics


def _events():
    return [
        {
            "id": 1,
            "timestamp": "2026-06-01T10:00:00+00:00",
            "src_ip": "203.0.113.50",
            "protocol": "SSH",
            "event_type": "auth_attempt",
            "payload": {"username": "root", "password": "123456", "method": "password"},
        },
        {
            "id": 2,
            "timestamp": "2026-06-01T10:00:05+00:00",
            "src_ip": "203.0.113.50",
            "protocol": "SSH",
            "event_type": "command",
            "payload": {"command": "cat /etc/shadow"},
        },
        {
            "id": 3,
            "timestamp": "2026-06-01T10:01:00+00:00",
            "src_ip": "203.0.113.50",
            "protocol": "HTTP",
            "event_type": "credential_probe",
            "payload": {"method": "GET", "path": "/.env"},
        },
    ]


def test_feed_contains_malicious_ip_with_threat_data():
    reset_metrics()
    # root auth (+25 priv-esc) + /etc/shadow access (+20) → 45 → MEDIUM
    analyze_event(_events()[0])
    analyze_event(_events()[1])
    feed = build_ioc_feed(_events(), blocked_ips=[])
    assert feed["feed"] == "baitbox-ioc"
    ips = [m["ip"] for m in feed["malicious_ips"]]
    assert "203.0.113.50" in ips
    entry = next(m for m in feed["malicious_ips"] if m["ip"] == "203.0.113.50")
    assert entry["event_count"] == 3
    assert set(entry["protocols"]) == {"SSH", "HTTP"}
    assert entry["first_seen"] <= entry["last_seen"]
    assert "root" in entry["usernames"]
    reset_metrics()


def test_feed_excludes_benign_low_threat_ips():
    reset_metrics()
    feed = build_ioc_feed(_events(), blocked_ips=[])
    # With no anomaly analysis the single IP stays LOW threat → excluded
    assert not feed["malicious_ips"]
    reset_metrics()


def test_blocked_ip_always_included_even_if_low_threat():
    reset_metrics()
    feed = build_ioc_feed(_events(), blocked_ips=["203.0.113.50"])
    assert any(m["ip"] == "203.0.113.50" for m in feed["malicious_ips"])
    assert feed["malicious_ips"][0]["blocked"] is True
    reset_metrics()


def test_feed_includes_credential_intelligence():
    reset_metrics()
    feed = build_ioc_feed(_events(), blocked_ips=["203.0.113.50"])
    assert feed["top_credentials"]
    top = feed["top_credentials"][0]
    assert top["username"] == "root"
    assert top["password"] == "123456"
    assert feed["top_probed_paths"][0]["path"] == "/.env"
    reset_metrics()


def test_csv_output_is_parseable():
    reset_metrics()
    feed = build_ioc_feed(_events(), blocked_ips=["203.0.113.50"])
    csv_text = ioc_feed_to_csv(feed)
    rows = list(csv.reader(io.StringIO(csv_text)))
    assert rows[0][0] == "ip"
    assert any(row and row[0] == "203.0.113.50" for row in rows[1:])
    reset_metrics()


def test_txt_output_is_ip_blocklist():
    reset_metrics()
    feed = build_ioc_feed(_events(), blocked_ips=["203.0.113.50"])
    txt = ioc_feed_to_ip_list(feed)
    assert txt.strip() == "203.0.113.50"
    reset_metrics()


def test_malformed_ips_are_skipped():
    reset_metrics()
    events = [
        {"src_ip": "not-an-ip", "protocol": "HTTP", "event_type": "request",
         "payload": {}, "timestamp": "2026-06-01T10:00:00+00:00"},
    ]
    feed = build_ioc_feed(events, blocked_ips=[])
    assert not feed["malicious_ips"]
    reset_metrics()


def test_ioc_tolerates_malformed_fields():
    """Mixed-type timestamps and unhashable protocols/types must not crash."""
    reset_metrics()
    events = [
        {"src_ip": "203.0.113.60", "protocol": ["SSH"], "event_type": {"a": 1},
         "payload": {"username": ["root"]}, "timestamp": {"bad": "type"}},
        {"src_ip": "203.0.113.60", "protocol": "SSH", "event_type": "auth_attempt",
         "payload": {"username": "root", "password": "pw"}, "timestamp": 1234567890},
        {"src_ip": "203.0.113.60", "protocol": "SSH", "event_type": "command",
         "payload": {"command": "id"}, "timestamp": None},
    ]
    feed = build_ioc_feed(events, blocked_ips=["203.0.113.60"])
    entry = next(e for e in feed["malicious_ips"] if e["ip"] == "203.0.113.60")
    assert entry["event_count"] == 3
    assert entry["blocked"] is True
    reset_metrics()
