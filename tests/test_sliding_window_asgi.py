"""ASGI HTTP and websocket use the same Redis engine and timings."""

import fakeredis
import fakeredis.aioredis
import pytest

from tests.redis_helpers import close_async_redis
from django.test import override_settings

from ratelimit_middleware.middleware import ASGIRateLimitMiddleware


async def http_app(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


@pytest.mark.asyncio
async def test_asgi_http_headers_and_limited_response_are_coherent():
    with override_settings(RATELIMIT_RATE=1, RATELIMIT_WINDOW=30):
        middleware = ASGIRateLimitMiddleware(http_app)
        middleware._storage._async_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        scope = {"type": "http", "path": "/ok", "client": ("192.0.2.12", 8888), "headers": []}
        try:

            async def request():
                messages = []

                async def send(message):
                    messages.append(message)

                async def receive():
                    return {"type": "http.request", "body": b"", "more_body": False}

                await middleware(scope, receive, send)
                return messages

            admitted = await request()
            denied = await request()
            assert admitted[0]["status"] == 200
            assert denied[0]["status"] == 429
            admitted_headers = dict(admitted[0]["headers"])
            denied_headers = dict(denied[0]["headers"])
            assert admitted_headers[b"x-ratelimit-remaining"] == b"0"
            assert denied_headers[b"x-ratelimit-remaining"] == b"0"
            assert denied_headers[b"retry-after"] == denied_headers[b"x-ratelimit-reset"]
            assert 1 <= int(denied_headers[b"retry-after"]) <= 30
            assert await middleware._storage._async_client.zcard("ratelimit:http:192.0.2.12") == 1
        finally:
            await close_async_redis(middleware._storage._async_client)


@pytest.mark.asyncio
async def test_websocket_message_limits_use_bounded_engine():
    # The same shared Lua check is used for WebSocket handshakes and messages;
    # verify separate suffix buckets cannot interfere with one another.
    with override_settings(RATELIMIT_RATE=1, RATELIMIT_WINDOW=30):
        middleware = ASGIRateLimitMiddleware(http_app)
        middleware._storage._async_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        try:
            handshake = await middleware._check("test:ws:handshake", 1, 30)
            message = await middleware._check("test:ws:msg", 1, 30)
            denied_message = await middleware._check("test:ws:msg", 1, 30)
            assert not handshake.limited
            assert not message.limited
            assert denied_message.limited
            assert await middleware._storage._async_client.zcard("test:ws:msg") == 1
        finally:
            await close_async_redis(middleware._storage._async_client)
