"""Small cross-thread pub/sub helper used by the dashboard feed."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class _Subscriber:
    queue: asyncio.Queue[dict[str, Any]]
    loop: asyncio.AbstractEventLoop


class PubSub:
    def __init__(self) -> None:
        self._subscribers: set[_Subscriber] = set()

    def _enqueue(self, queue: asyncio.Queue[dict[str, Any]], message: dict[str, Any]) -> None:
        """Enqueue an event, dropping the oldest item when the queue is full."""
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                pass

    async def publish(self, message: dict[str, Any]) -> None:
        stale: list[_Subscriber] = []
        for subscriber in tuple(self._subscribers):
            if subscriber.loop.is_closed():
                stale.append(subscriber)
                continue
            subscriber.loop.call_soon_threadsafe(self._enqueue, subscriber.queue, message)
        for subscriber in stale:
            self._subscribers.discard(subscriber)

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=1000)
        self._subscribers.add(_Subscriber(queue=queue, loop=asyncio.get_running_loop()))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers = {subscriber for subscriber in self._subscribers if subscriber.queue is not queue}


pubsub = PubSub()
