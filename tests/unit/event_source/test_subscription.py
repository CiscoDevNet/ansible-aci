from unittest.mock import patch
from typing import Any, List
from asyncmock import AsyncMock
from extensions.eda.plugins.event_source.subscription import main as subscription_main
import pytest
import json
import asyncio


# Refresh mock method
def refresh_patch(hostname: str, token: str, rf_timeout: int, sub_urls: List[str]) -> None:
    pass


# Login mock method
def login_patch(hostname: str, username: str, password: str) -> str:
    return f"{hostname}{username}{password}"


# Subscribe mock method
def subscribe_patch(hostname, token, rf_timeout, sub_urls) -> List[str]:
    return [f"{hostname}{token}{rf_timeout}{url}" for url in sub_urls]


# Mock iterator
class AsyncIterator:
    def __init__(self) -> None:
        self.count = 0

    async def __anext__(self) -> str:
        if self.count < 2:
            self.count += 1
            return json.dumps({"eventid": f"00{self.count}"})
        else:
            raise StopAsyncIteration


# Mock Async Websocket
class MockWebSocket(AsyncMock):  # type: ignore[misc]
    def __aiter__(self) -> AsyncIterator:
        return AsyncIterator()

    async def close(self) -> None:
        pass


# Mock AsyncQueue
class MockQueue(asyncio.Queue[Any]):
    def __init__(self) -> None:
        self.queue: list[Any] = []

    async def put(self, item: Any) -> None:
        self.queue.append(item)


def test_websocket_subscription() -> None:

    with patch(
        "websockets.connect",
        return_value=MockWebSocket(),
    ), patch("unit.event_source.tmp_subscription.login", return_value=login_patch), patch(
        "unit.event_source.tmp_subscription.subscribe", return_value=subscribe_patch
    ), patch("unit.event_source.tmp_subscription.refresh", return_value=refresh_patch):

        my_queue = MockQueue()
        asyncio.run(
            subscription_main(
                my_queue,
                {
                    "hostname": "my-apic.com",
                    "username": "admin",
                    "password": "admin",
                    "subscriptions": ['/api/node/class/faultInst.json?query-target-filter=and(eq(faultInst.code,"F1386"))'],
                },
            )
        )

        assert my_queue.queue[0] == {"eventid": "001"}
        assert len(my_queue.queue) == 2
