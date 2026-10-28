"""Tests for enhanced features: attack simulation, STIX 2.1 threat intel export, and new decoys."""

from __future__ import annotations

import asyncio
import pytest
from fastapi.testclient import TestClient

from baitbox.db import init_db
from baitbox.servers.http_server import app
from baitbox.ioc import build_ioc_feed, ioc_feed_to_stix


@pytest.fixture(autouse=True)
def setup_db():
    asyncio.run(init_db())


@pytest.fixture()
def client():
    return TestClient(app)


def test_stix_ioc_conversion():
    feed = {
        "malicious_ips": [
            {
                "ip": "185.220.101.42",
                "threat_score": 85,
                "threat_level": "CRITICAL",
                "protocols": ["SSH"],
                "first_seen": "2026-10-28T12:00:00Z",
                "mitre_techniques": ["T1110.001"],
                "blocked": False,
            }
        ]
    }
    stix = ioc_feed_to_stix(feed)
    assert stix["type"] == "bundle"
    assert len(stix["objects"]) == 1
    obj = stix["objects"][0]
    assert obj["type"] == "indicator"
    assert "185.220.101.42" in obj["pattern"]
    assert obj["confidence"] == 85


def test_stix_export_endpoint(client, monkeypatch):
    from baitbox.servers import http_server

    monkeypatch.setattr(
        http_server, "verify_jwt_token", lambda token: "admin" if token else None
    )
    client.cookies.set("session_token", "fake-token-for-test")
    resp = client.get("/api/ioc?format=stix")
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "bundle"
    assert "objects" in data


def test_simulate_attack_endpoint(client, monkeypatch):
    from baitbox.servers import http_server

    monkeypatch.setattr(
        http_server, "verify_jwt_token", lambda token: "admin" if token else None
    )
    client.cookies.set("session_token", "fake-token-for-test")

    # Test ssh_bruteforce simulation
    resp = client.post("/api/simulate", json={"scenario": "ssh_bruteforce"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["events_generated"] >= 3

    # Test web_recon simulation
    resp = client.post("/api/simulate", json={"scenario": "web_recon"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["events_generated"] >= 1

    # Test shell_intrusion simulation
    resp = client.post("/api/simulate", json={"scenario": "shell_intrusion"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_etc_passwd_decoy(client):
    resp = client.get("/etc/passwd")
    assert resp.status_code == 200
    assert "root:x:0:0" in resp.text
    assert "deploy:x:1000:1000" in resp.text


def test_actuator_decoy(client):
    resp = client.get("/actuator/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "UP"
