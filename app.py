"""BaitBox Application Entry Point.

Starts the multi-protocol honeypot (SSH on :2222, Telnet on :2323,
HTTP decoys and Cyber Command Center dashboard on :3000).
"""

from __future__ import annotations

import asyncio
import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baitbox.servers.http_server import app
from baitbox.main import main

if __name__ == "__main__":
    asyncio.run(main())
