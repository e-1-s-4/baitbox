"""Tests for GeoIP helpers."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from baitbox import geoip


def _geo_settings(**kwargs):
    defaults = {"geoip_enabled": True}
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_private_ip_returns_local_metadata():
    data = asyncio.run(geoip.lookup_ip("127.0.0.1"))
    assert data["country"] == "Private Network"
    assert data["threat_score"] == 0


def test_get_cached_returns_none_for_unknown_ip():
    geoip._CACHE.clear()
    assert geoip.get_cached("203.0.113.99") is None


def test_schedule_lookup_skips_private_ips(monkeypatch):
    called = {"count": 0}

    async def fake_lookup(ip):
        called["count"] += 1

    monkeypatch.setattr(geoip, "lookup_ip", fake_lookup)
    monkeypatch.setattr(geoip, "settings", _geo_settings(geoip_enabled=True))
    geoip.schedule_lookup("10.0.0.5")
    assert called["count"] == 0


def test_threat_score_flags_hosting_asn():
    score = geoip._threat_score({"isp": "DigitalOcean LLC", "countryCode": "US"})
    assert score >= 40


def test_lookup_disabled_returns_reason(monkeypatch):
    monkeypatch.setattr(geoip, "settings", _geo_settings(geoip_enabled=False))
    data = asyncio.run(geoip.lookup_ip("8.8.8.8"))
    assert data["reason"] == "disabled"
