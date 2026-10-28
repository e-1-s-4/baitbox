"""Discord, Slack, and generic webhook integration for BaitBox telemetry.

v2.3.0: delivery moved from one-thread-per-event to a single bounded worker
queue. Credential-stuffing floods previously spawned unbounded numbers of
short-lived threads; now overflow events are dropped (with a warning) instead.
"""

from __future__ import annotations
import json
import logging
import queue
import threading
import urllib.request
from typing import Any

from .config import settings

logger = logging.getLogger("baitbox.webhooks")

# Discord hard limits (embeds): description <= 4096, field value <= 1024
_DISCORD_DESCRIPTION_LIMIT = 3900
_DISCORD_FIELD_VALUE_LIMIT = 1000
_SLACK_TEXT_LIMIT = 3500
_GENERIC_PAYLOAD_LIMIT = 60000

_THREAT_RANK = {"LOW": 0, "MEDIUM": 1, "CRITICAL": 2}

_delivery_queue: "queue.Queue[dict[str, Any] | None]" = queue.Queue(
    maxsize=max(1, settings.webhook_queue_size)
)
_worker_started = False
_worker_lock = threading.Lock()
_dropped_count = 0


def _threat_rank(level: str | None) -> int:
    return _THREAT_RANK.get((level or "LOW").upper(), 0)


def _ensure_worker() -> None:
    """Start the singleton delivery worker thread (lazily, once)."""
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        thread = threading.Thread(target=_worker_loop, name="baitbox-webhooks", daemon=True)
        thread.start()
        _worker_started = True


def _worker_loop() -> None:
    """Drain the delivery queue; ``None`` is a poison pill for shutdown."""
    while True:
        item = _delivery_queue.get()
        if item is None:
            break
        try:
            _send_webhook_sync(item)
        except Exception as exc:  # never let delivery kill the worker
            logger.error("Webhook delivery error: %s", exc)
        finally:
            _delivery_queue.task_done()


def send_webhook_notification(event: dict[str, Any]) -> None:
    if not settings.webhook_url:
        return

    # Respect the configured minimum threat level (default: notify for all)
    minimum = settings.webhook_min_threat_level.upper()
    event_level = str(event.get("threat_level") or "LOW").upper()
    if _threat_rank(event_level) < _threat_rank(minimum):
        return

    global _dropped_count
    _ensure_worker()
    try:
        _delivery_queue.put_nowait(event)
    except queue.Full:
        _dropped_count += 1
        if _dropped_count == 1 or _dropped_count % 100 == 0:
            logger.warning(
                "Webhook queue full — dropped %s notification(s) total", _dropped_count
            )


def flush_webhooks(timeout: float = 10.0) -> bool:
    """Block until all queued webhook deliveries completed (used by tests)."""
    try:
        _delivery_queue.join()
        return True
    except Exception:
        return False


_TRUNCATION_SUFFIX = "\n…[truncated by BaitBox]"


def _truncate(text: Any, limit: int) -> str:
    rendered = text if isinstance(text, str) else json.dumps(text, indent=2, default=str)
    if len(rendered) <= limit:
        return rendered
    return rendered[: max(0, limit - len(_TRUNCATION_SUFFIX))] + _TRUNCATION_SUFFIX


def _send_webhook_sync(event: dict[str, Any]) -> None:
    url = settings.webhook_url
    w_type = settings.webhook_type.lower()
    
    src_ip = event.get("src_ip", "Unknown")
    protocol = event.get("protocol", "Unknown")
    event_type = event.get("event_type", "Unknown")
    payload = event.get("payload", {})
    
    data: dict[str, Any] = {}
    
    if w_type == "discord":
        threat_level = event.get("threat_level", "LOW")
        color = 3447003
        if threat_level == "CRITICAL":
            color = 15548997
        elif threat_level == "MEDIUM":
            color = 16753920

        embed = {
            "title": _truncate(f"🚨 BaitBox Honeypot Alert ({protocol})", 250),
            "color": color,
            "fields": [
                {"name": "Attacker IP", "value": f"`{src_ip}`", "inline": True},
                {"name": "Protocol", "value": f"`{protocol}`", "inline": True},
                {"name": "Event Type", "value": f"`{event_type}`", "inline": True},
            ],
            "footer": {"text": "BaitBox Honeypot Telemetry"}
        }

        # Add threat details to fields
        threat_score = event.get("threat_score", 0)
        reasons = event.get("threat_reasons", [])
        threat_emoji = "🔴" if threat_level == "CRITICAL" else "🟡" if threat_level == "MEDIUM" else "🟢"
        embed["fields"].append({"name": "Threat Level", "value": _truncate(f"{threat_emoji} `{threat_level}` ({threat_score}%)", _DISCORD_FIELD_VALUE_LIMIT), "inline": True})
        if reasons:
            reason_text = "\n".join(f"• {r}" for r in reasons)
            embed["fields"].append({"name": "Threat Indicators", "value": _truncate(reason_text, _DISCORD_FIELD_VALUE_LIMIT), "inline": False})

        if event_type == "auth_attempt":
            user = payload.get("username", "unknown")
            pwd = payload.get("password", "unknown")
            method = payload.get("method", "unknown")
            if protocol == "Telnet":
                description = f"**Telnet Login Attempt**\n• Username: `{user}`\n• Password: `{pwd}`"
            else:
                description = f"**SSH Login Attempt**\n• Username: `{user}`\n• Password: `{pwd}`\n• Method: `{method}`"
        elif event_type == "command":
            cmd = payload.get("command", "")
            mode = payload.get("mode", "shell")
            description = f"**SSH Command Run ({mode})**\n```bash\n$ {cmd}\n```"
        elif event_type == "credential_probe":
            path = payload.get("path", "")
            req_method = payload.get("method", "GET")
            body = payload.get("body", {})
            body_str = json.dumps(body, indent=2) if body else "None"
            description = f"**HTTP Decoy Path Accessed**\n• Path: `{req_method} {path}`\n• Submitted Payload:\n```json\n{body_str}\n```"
        else:
            payload_str = json.dumps(payload, indent=2, default=str)
            description = f"**Telemetry Raw Payload**\n```json\n{payload_str}\n```"

        embed["description"] = _truncate(description, _DISCORD_DESCRIPTION_LIMIT)
        data = {"embeds": [embed]}
        
    elif w_type == "slack":
        threat_level = event.get("threat_level", "LOW")
        threat_score = event.get("threat_score", 0)
        reasons = event.get("threat_reasons", [])
        threat_emoji = "🔴" if threat_level == "CRITICAL" else "🟡" if threat_level == "MEDIUM" else "🟢"

        text = f"🚨 *BaitBox Honeypot Alert ({protocol})*\n"
        text += f"*Threat Level:* {threat_emoji} `{threat_level}` ({threat_score}%)\n"
        text += f"*Attacker IP:* `{src_ip}`\n*Event:* `{event_type}`\n"
        if reasons:
            text += "*Threat Indicators:*\n" + "\n".join(f"• {r}" for r in reasons) + "\n"

        if event_type == "auth_attempt":
            text += f"• Username: `{payload.get('username')}`\n• Password: `{payload.get('password')}`"
        elif event_type == "command":
            text += f"• Command: `{payload.get('command')}`"
        elif event_type == "credential_probe":
            text += f"• Path: `{payload.get('method')} {payload.get('path')}`"
        else:
            text += f"• Payload: `{json.dumps(payload, default=str)}`"

        data = {"text": _truncate(text, _SLACK_TEXT_LIMIT)}

    else:  # generic JSON payload
        data = {"event": event}
        encoded = json.dumps(data, default=str)
        if len(encoded) > _GENERIC_PAYLOAD_LIMIT:
            data = {"event": {k: event.get(k) for k in ("id", "timestamp", "src_ip", "protocol", "event_type", "threat_score", "threat_level")}}


    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "BaitBox-Honeypot/1.0"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            response.read()
    except Exception as e:
        logger.error(f"Failed to send webhook notification: {e}")
