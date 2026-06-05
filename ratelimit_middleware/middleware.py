from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Awaitable, Callable, Optional, Union

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from redis import Redis
from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import RedisError

from .conf import get_ratelimit_settings

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when a request exceeds the configured rate limit."""


class BaseRateLimit:
    def __init__(self) -> None:
        self.cfg = get_ratelimit_settings()

    def _client_ip_from_meta(self, request: HttpRequest) -> str:
        if self.cfg.trust_x_forwarded_for:
            xff = request.META.get("HTTP_X_FORWARDED_FOR")
            if xff:
                return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "") or ""

    def is_exempt_request(self, request: HttpRequest) -> bool:
        path = request.path_info.lstrip("/")
        return any(path.startswith(p.lstrip("/")) for p in self.cfg.exempt_paths) or self._client_ip_from_meta(request) in self.cfg.exempt_ips

    def key_for_request(self, request: HttpRequest, suffix: str = "http") -> str:
        parts = ["ratelimit", suffix, self._client_ip_from_meta(request)]
        if self.cfg.include_user_agent:
            parts.append(request.META.get("HTTP_USER_AGENT", "") or "")
        return ":".join(parts)

    def add_headers(self, response: HttpResponseBase, count: int, limit: Optional[int] = None, window: Optional[int] = None) -> None:
        if not self.cfg.enable_headers:
            return
        limit = self.cfg.rate if limit is None else limit
        window = self.cfg.window if window is None else window
        response["X-RateLimit-Limit"] = str(limit)
        response["X-RateLimit-Remaining"] = str(max(0, limit - count))
        response["X-RateLimit-Reset"] = str(window)

    def build_429(self, count: int, limit: Optional[int] = None, window: Optional[int] = None) -> HttpResponse:
        limit = self.cfg.rate if limit is None else limit
        window = self.cfg.window if window is None else window
        response = HttpResponse(
            json.dumps({"error": "Rate limit exceeded", "detail": f"Please try again in {window} seconds"}),
            status=429,
            content_type="application/json",
        )
        response["Retry-After"] = str(window)
        self.add_headers(response, count, limit, window)
        return response


class RateLimitMiddleware(BaseRateLimit):
    """Django WSGI/ASGI middleware using Redis sliding-window rate limiting."""

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Callable[[HttpRequest], Union[HttpResponseBase, Awaitable[HttpResponseBase]]]) -> None:
        super().__init__()
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(get_response)
        if self.async_mode:
            markcoroutinefunction(self)
        self._redis_sync: Optional[Redis] = None
        self._redis_async: Optional[AsyncRedis] = None

    def _get_sync_redis(self) -> Redis:
        if self._redis_sync is None:
            self._redis_sync = Redis.from_url(
                self.cfg.redis_url,
                socket_timeout=self.cfg.redis_timeout,
                socket_connect_timeout=self.cfg.redis_timeout,
                decode_responses=True,
            )
        return self._redis_sync

    def _get_async_redis(self) -> AsyncRedis:
        if self._redis_async is None:
            self._redis_async = AsyncRedis.from_url(
                self.cfg.redis_url,
                socket_timeout=self.cfg.redis_timeout,
                socket_connect_timeout=self.cfg.redis_timeout,
                decode_responses=True,
            )
        return self._redis_async

    def _member(self) -> str:
        return f"{time.time()}:{uuid.uuid4().hex}"

    def should_limit_sync(self, request: HttpRequest) -> tuple[bool, int]:
        if self.is_exempt_request(request):
            return False, 0
        key = self.key_for_request(request)
        now = time.time()
        try:
            pipe = self._get_sync_redis().pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, now - self.cfg.window)
            pipe.zadd(key, {self._member(): now})
            pipe.zcard(key)
            pipe.expire(key, self.cfg.window)
            _, _, count, _ = pipe.execute()
            count = int(count)
            return count > self.cfg.rate, count
        except RedisError:
            logger.exception("Redis error during sync rate limit check")
            if self.cfg.fail_open:
                return False, 0
            return True, self.cfg.rate + 1

    async def should_limit_async(self, request: HttpRequest) -> tuple[bool, int]:
        if self.is_exempt_request(request):
            return False, 0
        key = self.key_for_request(request)
        now = time.time()
        try:
            pipe = self._get_async_redis().pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, now - self.cfg.window)
            pipe.zadd(key, {self._member(): now})
            pipe.zcard(key)
            pipe.expire(key, self.cfg.window)
            _, _, count, _ = await pipe.execute()
            count = int(count)
            return count > self.cfg.rate, count
        except RedisError:
            logger.exception("Redis error during async rate limit check")
            if self.cfg.fail_open:
                return False, 0
            return True, self.cfg.rate + 1

    def __call__(self, request: HttpRequest) -> Union[HttpResponseBase, Awaitable[HttpResponseBase]]:
        if self.async_mode:
            return self.__acall__(request)
        return self.__sync_call__(request)

    def __sync_call__(self, request: HttpRequest) -> HttpResponseBase:
        limited, count = self.should_limit_sync(request)
        if limited:
            return self.build_429(count)
        response = self.get_response(request)
        self.add_headers(response, count)
        return response

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        limited, count = await self.should_limit_async(request)
        if limited:
            return self.build_429(count)
        response = await self.get_response(request)
        self.add_headers(response, count)
        return response


class ASGIRateLimitMiddleware(BaseRateLimit):
    """ASGI boundary middleware for HTTP and WebSocket rate limiting."""

    def __init__(self, app: Callable) -> None:
        super().__init__()
        self.app = app
        self._redis: Optional[AsyncRedis] = None

    def _get_header(self, scope, name: bytes) -> str:
        for key, value in scope.get("headers", []):
            if key.lower() == name:
                return value.decode("utf-8", errors="ignore")
        return ""

    def _get_client_ip(self, scope) -> str:
        if self.cfg.trust_x_forwarded_for:
            xff = self._get_header(scope, b"x-forwarded-for")
            if xff:
                return xff.split(",")[0].strip()
        client = scope.get("client")
        return client[0] if client else ""

    def _is_exempt(self, scope) -> bool:
        path = (scope.get("path") or "").lstrip("/")
        return any(path.startswith(p.lstrip("/")) for p in self.cfg.exempt_paths) or self._get_client_ip(scope) in self.cfg.exempt_ips

    def _key(self, scope, suffix: str) -> str:
        parts = ["ratelimit", suffix, self._get_client_ip(scope)]
        if self.cfg.include_user_agent:
            parts.append(self._get_header(scope, b"user-agent"))
        return ":".join(parts)

    async def _get_redis(self) -> AsyncRedis:
        if self._redis is None:
            self._redis = AsyncRedis.from_url(
                self.cfg.redis_url,
                socket_timeout=self.cfg.redis_timeout,
                socket_connect_timeout=self.cfg.redis_timeout,
                decode_responses=True,
            )
        return self._redis

    async def _should_limit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.time()
        try:
            pipe = (await self._get_redis()).pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zadd(key, {f"{now}:{uuid.uuid4().hex}": now})
            pipe.zcard(key)
            pipe.expire(key, window)
            _, _, count, _ = await pipe.execute()
            count = int(count)
            return count > limit, count
        except RedisError:
            logger.exception("Redis error during ASGI rate limit check")
            if self.cfg.fail_open:
                return False, 0
            return True, limit + 1

    def _headers(self, count: int, limit: int, window: int) -> list[tuple[bytes, bytes]]:
        if not self.cfg.enable_headers:
            return []
        return [
            (b"x-ratelimit-limit", str(limit).encode()),
            (b"x-ratelimit-remaining", str(max(0, limit - count)).encode()),
            (b"x-ratelimit-reset", str(window).encode()),
        ]

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"} or self._is_exempt(scope):
            return await self.app(scope, receive, send)

        if scope_type == "http":
            limited, count = await self._should_limit(self._key(scope, "http"), self.cfg.rate, self.cfg.window)
            if limited:
                body = json.dumps({"error": "Rate limit exceeded", "detail": f"Please try again in {self.cfg.window} seconds"}).encode()
                headers = [(b"content-type", b"application/json"), (b"retry-after", str(self.cfg.window).encode())]
                headers += self._headers(count, self.cfg.rate, self.cfg.window)
                await send({"type": "http.response.start", "status": 429, "headers": headers})
                await send({"type": "http.response.body", "body": body})
                return

            headers_to_add = self._headers(count, self.cfg.rate, self.cfg.window)

            async def send_wrapper(message):
                if message["type"] == "http.response.start" and headers_to_add:
                    message.setdefault("headers", [])
                    message["headers"].extend(headers_to_add)
                await send(message)

            return await self.app(scope, receive, send_wrapper)

        if self.cfg.ws_handshake:
            limited, _ = await self._should_limit(self._key(scope, "ws:handshake"), self.cfg.rate, self.cfg.window)
            if limited:
                await send({"type": "websocket.close", "code": 4408})
                return

        if self.cfg.ws_msg_rate <= 0:
            return await self.app(scope, receive, send)

        msg_key = self._key(scope, "ws:msg")

        async def receive_wrapper():
            event = await receive()
            if event["type"] == "websocket.receive":
                limited, _ = await self._should_limit(msg_key, self.cfg.ws_msg_rate, self.cfg.ws_msg_window)
                if limited:
                    await send({"type": "websocket.close", "code": 4408})
                    return {"type": "websocket.disconnect", "code": 4408}
            return event

        return await self.app(scope, receive_wrapper, send)
