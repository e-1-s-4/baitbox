"""Tests for the dashboard pub/sub feed."""

from __future__ import annotations

import asyncio

from baitbox.pubsub import PubSub, _Subscriber


async def _collect_one(queue: asyncio.Queue, pubsub: PubSub) -> dict:
    await pubsub.publish({"src_ip": "203.0.113.1", "protocol": "HTTP"})
    return await asyncio.wait_for(queue.get(), timeout=1)


def test_publish_delivers_to_subscriber():
    pubsub = PubSub()

    async def run():
        queue = await pubsub.subscribe()
        event = await _collect_one(queue, pubsub)
        pubsub.unsubscribe(queue)
        return event

    event = asyncio.run(run())
    assert event["src_ip"] == "203.0.113.1"


def test_publish_drops_oldest_when_queue_full():
    pubsub = PubSub()

    async def run():
        queue: asyncio.Queue = asyncio.Queue(maxsize=2)
        loop = asyncio.get_running_loop()
        pubsub._subscribers.add(_Subscriber(queue=queue, loop=loop))
        await pubsub.publish({"id": 1})
        await pubsub.publish({"id": 2})
        await pubsub.publish({"id": 3})
        first = await queue.get()
        second = await queue.get()
        return first, second

    first, second = asyncio.run(run())
    assert first["id"] == 2
    assert second["id"] == 3
