from __future__ import annotations

import json
import logging
import time
from typing import Awaitable, Callable, Optional, Union, Tuple

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseBase

from redis import Redis
from redis.asyncio import Redis as AsyncRedis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class RateLimitMiddleware:
    """
    Works in BOTH:
    - sync stack (WSGI / sync views)
    - async stack (ASGI + Daphne/Uvicorn / async views)

    Put it in settings.MIDDLEWARE like normal.
    """

    sync_capable = True
    async_capable = True

    def __init__(
        self,
        get_response: Callable[[HttpRequest], Union[HttpResponseBase, Awaitable[HttpResponseBase]]],
    ) -> None:
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(self.get_response)
        if self.async_mode:
            markcoroutinefunction(self)

        # Settings
        self.rate_limit = getattr(settings, "RATELIMIT_RATE", 60)
        self.time_window = getattr(settings, "RATELIMIT_WINDOW", 60)
        self.exempt_paths = getattr(settings, "RATELIMIT_EXEMPT_PATHS", [])
        self.exempt_ips = getattr(settings, "RATELIMIT_EXEMPT_IPS", [])
        self.include_user_agent = getattr(settings, "RATELIMIT_INCLUDE_USER_AGENT", False)
        self.enable_headers = getattr(settings, "RATELIMIT_ENABLE_HEADERS", True)

        # Redis config
        self.redis_host = getattr(settings, "RATELIMIT_REDIS_HOST", "localhost")
        self.redis_port = getattr(settings, "RATELIMIT_REDIS_PORT", 6379)
        self.redis_db = getattr(settings, "RATELIMIT_REDIS_DB", 0)
        self.redis_password = getattr(settings, "RATELIMIT_REDIS_PASSWORD", None)
        self.redis_timeout = getattr(settings, "RATELIMIT_REDIS_TIMEOUT", 1)

        # Create clients (lazy-ish but safe)
        self._redis_sync: Optional[Redis] = None
        self._redis_async: Optional[AsyncRedis] = None

        # Optional fallback if Redis is down
        self.fallback_rate = getattr(settings, "RATELIMIT_FALLBACK_RATE", 1000)
        self.fallback_window = getattr(settings, "RATELIMIT_FALLBACK_WINDOW", 60)

    # -------------------------
    # Common helpers
    # -------------------------
    def get_client_ip(self, request: HttpRequest) -> str:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "") or ""

    def get_rate_limit_key(self, request: HttpRequest) -> str:
        parts = ["ratelimit", self.get_client_ip(request)]
        if self.include_user_agent:
            parts.append(request.META.get("HTTP_USER_AGENT", "") or "")
        return ":".join(parts)

    def is_exempt(self, request: HttpRequest) -> bool:
        path = request.path_info.lstrip("/")
        if any(path.startswith(exempt) for exempt in self.exempt_paths):
            return True
        if self.get_client_ip(request) in self.exempt_ips:
            return True
        return False

    def add_rate_limit_headers(self, response: HttpResponseBase, request_count: int) -> None:
        if not self.enable_headers:
            return
        response["X-RateLimit-Limit"] = str(self.rate_limit)
        response["X-RateLimit-Remaining"] = str(max(0, self.rate_limit - request_count))
        response["X-RateLimit-Reset"] = str(self.time_window)

    def build_429(self, request_count: int) -> HttpResponse:
        resp = HttpResponse(
            json.dumps(
                {
                    "error": "Rate limit exceeded",
                    "detail": f"Please try again in {self.time_window} seconds",
                }
            ),
            content_type="application/json",
            status=429,
        )
        resp["Retry-After"] = str(self.time_window)
        self.add_rate_limit_headers(resp, request_count)
        return resp

    # -------------------------
    # Redis clients
    # -------------------------
    def _get_sync_redis(self) -> Redis:
        if self._redis_sync is None:
            self._redis_sync = Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                socket_timeout=self.redis_timeout,
                decode_responses=True,
            )
        return self._redis_sync

    def _get_async_redis(self) -> AsyncRedis:
        if self._redis_async is None:
            self._redis_async = AsyncRedis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                socket_timeout=self.redis_timeout,
                decode_responses=True,
            )
        return self._redis_async

    # -------------------------
    # Rate limit checks
    # -------------------------
    def should_be_limited_sync(self, request: HttpRequest) -> Tuple[bool, int]:
        if self.is_exempt(request):
            return False, 0

        key = self.get_rate_limit_key(request)
        now = time.time()

        try:
            r = self._get_sync_redis()
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, now - self.time_window)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, self.time_window)
            _, count, *_ = pipe.execute()
            count = int(count)
            return count > self.rate_limit, count
        except RedisError as e:
            logger.error("Redis error (sync rate limit): %s", e)
            # permissive fallback
            self.rate_limit = self.fallback_rate
            self.time_window = self.fallback_window
            return False, 0

    async def should_be_limited_async(self, request: HttpRequest) -> Tuple[bool, int]:
        if self.is_exempt(request):
            return False, 0

        key = self.get_rate_limit_key(request)
        now = time.time()

        try:
            r = self._get_async_redis()
            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, now - self.time_window)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, self.time_window)
            _, count, *_ = await pipe.execute()
            count = int(count)
            return count > self.rate_limit, count
        except RedisError as e:
            logger.error("Redis error (async rate limit): %s", e)
            # permissive fallback
            self.rate_limit = self.fallback_rate
            self.time_window = self.fallback_window
            return False, 0

    # -------------------------
    # Django middleware entry
    # -------------------------
    def __call__(self, request: HttpRequest) -> Union[HttpResponseBase, Awaitable[HttpResponseBase]]:
        if self.async_mode:
            return self.__acall__(request)
        return self.__sync_call__(request)

    def __sync_call__(self, request: HttpRequest) -> HttpResponseBase:
        try:
            limited, count = self.should_be_limited_sync(request)
            if limited:
                return self.build_429(count)

            response = self.get_response(request)
            self.add_rate_limit_headers(response, count)
            return response
        except Exception as e:
            logger.exception("Error in RateLimitMiddleware(sync): %s", e)
            return self.get_response(request)

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        try:
            limited, count = await self.should_be_limited_async(request)
            if limited:
                return self.build_429(count)

            response = await self.get_response(request)
            self.add_rate_limit_headers(response, count)
            return response
        except Exception as e:
            logger.exception("Error in RateLimitMiddleware(async): %s", e)
            return await self.get_response(request)



class ASGIRateLimitMiddleware:
    """
    ASGI middleware to rate-limit HTTP + WebSocket at the server boundary.

    - HTTP: returns 429 JSON response
    - WebSocket: rejects the handshake with close code 4408 (policy violation style)
      (You can choose another code if you prefer.)
    """

    def __init__(self, app: Callable) -> None:
        self.app = app

        self.rate_limit = getattr(settings, "RATELIMIT_RATE", 60)
        self.time_window = getattr(settings, "RATELIMIT_WINDOW", 60)

        self.exempt_paths = getattr(settings, "RATELIMIT_EXEMPT_PATHS", [])
        self.exempt_ips = getattr(settings, "RATELIMIT_EXEMPT_IPS", [])

        self.include_user_agent = getattr(settings, "RATELIMIT_INCLUDE_USER_AGENT", False)
        self.enable_headers = getattr(settings, "RATELIMIT_ENABLE_HEADERS", True)

        # WS-specific knobs
        self.ws_limit_handshake = getattr(settings, "RATELIMIT_WS_HANDSHAKE", True)
        self.ws_message_rate = getattr(settings, "RATELIMIT_WS_MSG_RATE", 0)  # 0 = disabled
        self.ws_message_window = getattr(settings, "RATELIMIT_WS_MSG_WINDOW", 60)

        self._redis: Optional[Redis] = None

    async def _get_redis(self) -> Redis:
        if self._redis is not None:
            return self._redis

        self._redis = Redis(
            host=getattr(settings, "RATELIMIT_REDIS_HOST", "localhost"),
            port=getattr(settings, "RATELIMIT_REDIS_PORT", 6379),
            db=getattr(settings, "RATELIMIT_REDIS_DB", 0),
            password=getattr(settings, "RATELIMIT_REDIS_PASSWORD", None),
            socket_timeout=getattr(settings, "RATELIMIT_REDIS_TIMEOUT", 1),
            decode_responses=True,
        )

        try:
            await self._redis.ping()
        except RedisError as e:
            logger.error("Failed to connect to Redis (ASGI): %s", e)
            # Keep object but middleware becomes permissive.
        return self._redis

    def _get_header(self, scope, name: bytes) -> str:
        for k, v in scope.get("headers", []):
            if k.lower() == name:
                try:
                    return v.decode("utf-8")
                except Exception:
                    return ""
        return ""

    def _get_client_ip(self, scope) -> str:
        """
        ASGI-friendly client IP extraction.
        Prefer X-Forwarded-For if you trust your proxy, else fallback to scope['client'].
        """
        xff = self._get_header(scope, b"x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()

        client = scope.get("client")
        if client and len(client) >= 1:
            return client[0] or ""
        return ""

    def _is_exempt(self, scope) -> bool:
        path = (scope.get("path") or "").lstrip("/")
        if any(path.startswith(exempt) for exempt in self.exempt_paths):
            return True

        ip = self._get_client_ip(scope)
        if ip in self.exempt_ips:
            return True

        return False

    def _key(self, scope, suffix: str = "http") -> str:
        parts = ["ratelimit", suffix, self._get_client_ip(scope)]
        if self.include_user_agent:
            ua = self._get_header(scope, b"user-agent")
            if ua:
                parts.append(ua)
        return ":".join(parts)

    async def _should_limit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """
        Redis sorted-set sliding window.
        Returns (should_limit, current_count).
        """
        try:
            r = await self._get_redis()
            now = time.time()

            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, window)
            _, count, *_ = await pipe.execute()

            return count > limit, int(count)
        except RedisError as e:
            logger.error("Redis error in ASGI rate limiting: %s", e)
            return False, 0

    def _http_headers(self, count: int) -> list[tuple[bytes, bytes]]:
        if not self.enable_headers:
            return []
        remaining = max(0, self.rate_limit - count)
        return [
            (b"x-ratelimit-limit", str(self.rate_limit).encode()),
            (b"x-ratelimit-remaining", str(remaining).encode()),
            (b"x-ratelimit-reset", str(self.time_window).encode()),
        ]

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        if self._is_exempt(scope):
            return await self.app(scope, receive, send)

        # -------------------------
        # HTTP limiting
        # -------------------------
        if scope_type == "http":
            key = self._key(scope, "http")
            limited, count = await self._should_limit(key, self.rate_limit, self.time_window)

            if limited:
                body = json.dumps(
                    {
                        "error": "Rate limit exceeded",
                        "detail": f"Please try again in {self.time_window} seconds",
                    }
                ).encode("utf-8")

                headers = [(b"content-type", b"application/json"), (b"retry-after", str(self.time_window).encode())]
                headers += self._http_headers(count)

                await send(
                    {
                        "type": "http.response.start",
                        "status": 429,
                        "headers": headers,
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return

            # Add headers on successful responses by wrapping send
            headers_to_add = self._http_headers(count)

            async def send_wrapper(message):
                if message["type"] == "http.response.start" and headers_to_add:
                    message.setdefault("headers", [])
                    message["headers"].extend(headers_to_add)
                await send(message)

            return await self.app(scope, receive, send_wrapper)

        # -------------------------
        # WebSocket limiting
        # -------------------------
        if scope_type == "websocket":
            # 1) Limit handshake (connection attempts)
            if self.ws_limit_handshake:
                key = self._key(scope, "ws:handshake")
                limited, _ = await self._should_limit(key, self.rate_limit, self.time_window)
                if limited:
                    # Reject handshake
                    # 4408 is commonly used as "policy violation / rate limited" in some stacks
                    await send({"type": "websocket.close", "code": 4408})
                    return

            # 2) Optional: limit messages (if enabled)
            if not self.ws_message_rate or self.ws_message_rate <= 0:
                return await self.app(scope, receive, send)

            msg_key = self._key(scope, "ws:msg")

            async def receive_wrapper():
                event = await receive()
                if event["type"] == "websocket.receive":
                    limited, _ = await self._should_limit(msg_key, self.ws_message_rate, self.ws_message_window)
                    if limited:
                        await send({"type": "websocket.close", "code": 4408})
                        return {"type": "websocket.disconnect", "code": 4408}
                return event

            return await self.app(scope, receive_wrapper, send)