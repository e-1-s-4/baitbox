"""BaitBox Application Entry Point.

Starts the multi-protocol honeypot (SSH on :2222, Telnet on :2323,
HTTP decoys and the command-center dashboard on :8000).

Prefer ``python -m baitbox`` or the ``baitbox`` console script; this module is
kept as a convenience for running the checkout directly.
"""

from __future__ import annotations

import asyncio
import os
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from baitbox.main import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
