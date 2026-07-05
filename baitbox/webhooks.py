"""Discord, Slack, and generic webhook integration for BaitBox telemetry."""

from __future__ import annotations
import json
import logging
import urllib.request
import threading
from typing import Any

from .config import settings

logger = logging.getLogger("baitbox.webhooks")


def send_webhook_notification(event: dict[str, Any]) -> None:
    if not settings.webhook_url:
        return

    # Run in a background thread to avoid blocking main execution flow
    thread = threading.Thread(target=_send_webhook_sync, args=(event,), daemon=True)
    thread.start()


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
            "title": f"🚨 BaitBox Honeypot Alert ({protocol})",
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
        embed["fields"].append({"name": "Threat Level", "value": f"{threat_emoji} `{threat_level}` ({threat_score}%)", "inline": True})
        if reasons:
            embed["fields"].append({"name": "Threat Indicators", "value": "\n".join(f"• {r}" for r in reasons), "inline": False})
        
        if event_type == "auth_attempt":
            user = payload.get("username", "unknown")
            pwd = payload.get("password", "unknown")
            method = payload.get("method", "unknown")
            if protocol == "Telnet":
                embed["description"] = f"**Telnet Login Attempt**\n• Username: `{user}`\n• Password: `{pwd}`"
            else:
                embed["description"] = f"**SSH Login Attempt**\n• Username: `{user}`\n• Password: `{pwd}`\n• Method: `{method}`"
        elif event_type == "command":
            cmd = payload.get("command", "")
            mode = payload.get("mode", "shell")
            embed["description"] = f"**SSH Command Run ({mode})**\n```bash\n$ {cmd}\n```"
        elif event_type == "credential_probe":
            path = payload.get("path", "")
            method = payload.get("method", "GET")
            body = payload.get("body", {})
            body_str = json.dumps(body, indent=2) if body else "None"
            embed["description"] = f"**HTTP Decoy Path Accessed**\n• Path: `{method} {path}`\n• Submitted Payload:\n```json\n{body_str}\n```"
        else:
            payload_str = json.dumps(payload, indent=2)
            embed["description"] = f"**Telemetry Raw Payload**\n```json\n{payload_str}\n```"
            
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
            if protocol == "Telnet":
                text += f"• Username: `{payload.get('username')}`\n• Password: `{payload.get('password')}`"
            else:
                text += f"• Username: `{payload.get('username')}`\n• Password: `{payload.get('password')}`"
        elif event_type == "command":
            text += f"• Command: `{payload.get('command')}`"
        elif event_type == "credential_probe":
            text += f"• Path: `{payload.get('method')} {payload.get('path')}`"
        else:
            text += f"• Payload: `{json.dumps(payload)}`"
            
        data = {"text": text}
        
    else:  # generic JSON payload
        data = event


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
