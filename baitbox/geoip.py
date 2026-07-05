"""Server-side GeoIP resolution with in-memory caching and threat scoring."""

from __future__ import annotations

import ipaddress
import logging
import time
import urllib.request
import json
from typing import Any

from .config import settings

logger = logging.getLogger("baitbox.geoip")

# In-memory cache: ip -> {data, expires}
_CACHE: dict[str, dict[str, Any]] = {}
_TTL = 3600  # 1 hour

# Known Tor exit node ranges / suspicious ASN keywords (heuristic)
_SUSPICIOUS_ASN_KEYWORDS = {
    "digitalocean", "linode", "vultr", "ovh", "hetzner", "leaseweb",
    "serverius", "choopa", "frantech", "aeza", "m247", "zenlayer",
    "serverstack", "datacamp", "host europe", "datawagon", "combahton",
}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _threat_score(data: dict[str, Any]) -> int:
    """Heuristic 0-100 threat score based on GeoIP data."""
    score = 0
    if not data:
        return score
    # VPN/Hosting ASN
    asn_name = (data.get("isp") or data.get("org") or "").lower()
    if any(kw in asn_name for kw in _SUSPICIOUS_ASN_KEYWORDS):
        score += 40
    # Non-US/EU hosting countries with high bot traffic
    high_risk_countries = {"CN", "RU", "BR", "IN", "KP", "IR", "VN", "UA"}
    if data.get("countryCode") in high_risk_countries:
        score += 30
    # Proxy/VPN flag
    if data.get("proxy") or data.get("hosting"):
        score += 30
    return min(score, 100)


async def lookup_ip(ip: str) -> dict[str, Any]:
    """Return GeoIP info dict for an IP. Uses memory and SQLite caches to avoid rate-limiting."""
    if not settings.geoip_enabled:
        return _unknown_geoip(ip, reason="disabled")

    if _is_private(ip):
        return {
            "ip": ip,
            "city": "Local Host",
            "country": "Private Network",
            "countryCode": "XX",
            "lat": 37.7749,
            "lon": -122.4194,
            "isp": "Loopback",
            "org": "Private",
            "threat_score": 0,
        }

    now = time.time()
    cached = _CACHE.get(ip)
    if cached and cached["expires"] > now:
        return cached["data"]

    try:
        from .db import get_geoip_cache
        cached_data = await get_geoip_cache(ip)
        if cached_data:
            _CACHE[ip] = {"data": cached_data, "expires": now + _TTL}
            return cached_data
    except Exception as exc:
        logger.debug("GeoIP SQLite cache read failed for %s: %s", ip, exc)

    data: dict[str, Any] = _unknown_geoip(ip)

    try:
        # ip-api.com free tier: 45 req/min, no API key needed
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,proxy,hosting"
        req = urllib.request.Request(url, headers={"User-Agent": "BaitBox/2.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            raw = json.loads(resp.read().decode())
        if raw.get("status") == "success":
            data.update({
                "city": raw.get("city", "Unknown"),
                "country": raw.get("country", "Unknown"),
                "countryCode": raw.get("countryCode", "XX"),
                "lat": raw.get("lat", 0.0),
                "lon": raw.get("lon", 0.0),
                "isp": raw.get("isp", "Unknown"),
                "org": raw.get("org", "Unknown"),
                "threat_score": _threat_score(raw),
            })
    except Exception as exc:
        logger.debug("GeoIP lookup failed for %s: %s", ip, exc)

    _CACHE[ip] = {"data": data, "expires": now + _TTL}
    try:
        from .db import set_geoip_cache
        await set_geoip_cache(ip, data, ttl=_TTL)
    except Exception as exc:
        logger.debug("GeoIP SQLite cache write failed for %s: %s", ip, exc)
    return data


def _unknown_geoip(ip: str, reason: str = "unknown") -> dict[str, Any]:
    """Return a stable placeholder shape for unavailable GeoIP data."""
    return {
        "ip": ip,
        "city": "Unknown",
        "country": "Unknown",
        "countryCode": "XX",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown",
        "org": "Unknown",
        "threat_score": 0,
        "reason": reason,
    }


def get_cached(ip: str) -> dict[str, Any] | None:
    """Return cached GeoIP data without performing a fresh lookup."""
    entry = _CACHE.get(ip)
    if entry and entry["expires"] > time.time():
        return entry["data"]
    return None


def schedule_lookup(ip: str) -> None:
    """Queue a background GeoIP lookup when data is not already cached."""
    if not settings.geoip_enabled or _is_private(ip) or get_cached(ip) is not None:
        return

    from .async_bridge import fire_and_forget

    fire_and_forget(lookup_ip(ip))
