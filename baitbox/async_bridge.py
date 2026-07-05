"""Bridge blocking threads (SSH) to the main asyncio event loop."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any, TypeVar

T = TypeVar("T")

_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Register the running application event loop for cross-thread scheduling."""
    global _main_loop
    _main_loop = loop


def run_on_main_loop(coro: Coroutine[Any, Any, T], *, timeout: float = 10.0) -> T:
    """Run a coroutine on the main loop from a worker thread, or locally as fallback."""
    if _main_loop is not None and _main_loop.is_running():
        future = asyncio.run_coroutine_threadsafe(coro, _main_loop)
        return future.result(timeout=timeout)
    return asyncio.run(coro)


def fire_and_forget(coro: Coroutine[Any, Any, Any]) -> None:
    """Schedule a coroutine on the main loop without blocking the caller."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        loop.create_task(coro)
        return

    if _main_loop is not None and _main_loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, _main_loop)
        return

    asyncio.run(coro)
