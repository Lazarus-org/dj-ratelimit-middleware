"""Backend selection and portable cache-admission regression tests."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from django.core.checks import run_checks
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from ratelimit_middleware.conf import get_ratelimit_settings
from ratelimit_middleware.middleware import ASGIRateLimitMiddleware, RateLimitMiddleware
from ratelimit_middleware.storage import DjangoCacheStorage, RedisStorage


CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "limit-tests",
    },
    "ratelimit": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "limit-test-extra",
    },
    "unused": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"},
    "redis": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "rediss://localhost:6380/9",
    },
    "complex": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://localhost:6379/0",
        "OPTIONS": {"db": 12},
    },
}


def cache_settings(alias="ratelimit"):
    return override_settings(
        CACHES=CACHES,
        RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": alias},
        RATELIMIT_RATE=2,
        RATELIMIT_WINDOW=60,
    )


def test_cache_sync_middleware_enforces_quota_without_redis():
    with cache_settings():
        middleware = RateLimitMiddleware(lambda request: HttpResponse("OK"))
        assert isinstance(middleware._storage, DjangoCacheStorage)
        request = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.8")
        assert middleware(request).status_code == 200
        assert middleware(request).status_code == 200
        response = middleware(request)
        assert response.status_code == 429
        assert response["Retry-After"] == "60"  # conservative cache upper bound


@pytest.mark.asyncio
async def test_cache_async_django_middleware_enforces_quota():
    async def downstream(request):
        return HttpResponse("OK")

    with cache_settings():
        middleware = RateLimitMiddleware(downstream)
        request = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.9")
        assert (await middleware(request)).status_code == 200
        assert (await middleware(request)).status_code == 200
        assert (await middleware(request)).status_code == 429


@pytest.mark.asyncio
async def test_cache_asgi_http_and_websocket_enforce_quota():
    messages = []

    async def downstream(scope, receive, send):
        if scope["type"] == "http":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
        else:
            await send({"type": "websocket.accept"})

    async def receive():
        return {"type": "http.request"}

    async def send(message):
        messages.append(message)

    with cache_settings():
        middleware = ASGIRateLimitMiddleware(downstream)
        scope = {"type": "http", "client": ("192.0.2.12", 321), "path": "/ok", "headers": []}
        await middleware(scope, receive, send)
        await middleware(scope, receive, send)
        await middleware(scope, receive, send)
        assert [m["status"] for m in messages if m["type"] == "http.response.start"] == [
            200,
            200,
            429,
        ]

        # Separate WebSocket handshake identity does not share the HTTP counter.
        with override_settings(RATELIMIT_WS_HANDSHAKE=True):
            ws_scope = {**scope, "type": "websocket"}
            await middleware(ws_scope, receive, send)
            await middleware(ws_scope, receive, send)
            await middleware(ws_scope, receive, send)
            assert messages[-1] == {"type": "websocket.close", "code": 4408}


def test_cache_window_does_not_extend_on_denial():
    from django.core.cache import caches

    with override_settings(
        CACHES=CACHES,
        RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": "ratelimit"},
    ):
        backend = DjangoCacheStorage("ratelimit")
        assert not backend.check_sync("ttl-key", 1, 1).limited
        assert backend.check_sync("ttl-key", 1, 1).limited
        time.sleep(1.1)
        assert not backend.check_sync("ttl-key", 1, 1).limited
        caches["ratelimit"].delete("ttl-key")


def test_cache_selects_requested_alias_not_default():
    from django.core.cache import caches

    with cache_settings():
        middleware = RateLimitMiddleware(lambda request: HttpResponse("ok"))
        request = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.15")
        middleware(request)
        key = "ratelimit:http:192.0.2.15"
        assert caches["ratelimit"].get(key) == 1
        assert caches["default"].get(key) is None


def test_redis_is_default_backend():
    with override_settings(RATELIMIT_STORAGE=None):
        cfg = get_ratelimit_settings()
        assert cfg.storage_backend == "redis"
        assert isinstance(
            RateLimitMiddleware(lambda req: HttpResponse("ok"))._storage, RedisStorage
        )


@pytest.mark.parametrize(
    "storage",
    [
        {"BACKEND": "something"},
        {"BACKEND": "cache", "URL": "redis://localhost"},
        {"BACKEND": "cache", "CACHE_ALIAS": "missing"},
        {"BACKEND": "cache", "CACHE_ALIAS": "unused"},
        {"BACKEND": "redis", "CACHE_ALIAS": "default"},
        {"BACKEND": "redis", "CACHE_ALIAS": "complex"},
        {"BACKEND": "redis", "CACHE_ALIAS": "redis", "URL": "redis://localhost"},
        {"BACKEND": "redis", "URL": "http://localhost"},
        {"BACKEND": "redis", "URL": 123},
        {"BACKEND": "redis", "unknown": 3},
    ],
)
def test_invalid_storage_configuration_rejected(storage):
    with override_settings(CACHES=CACHES, RATELIMIT_STORAGE=storage):
        with pytest.raises(ImproperlyConfigured):
            get_ratelimit_settings()


def test_redis_cache_alias_uses_public_location_with_native_adapter():
    with override_settings(
        CACHES=CACHES, RATELIMIT_STORAGE={"BACKEND": "redis", "CACHE_ALIAS": "redis"}
    ):
        middleware = RateLimitMiddleware(lambda r: HttpResponse("ok"))
        assert isinstance(middleware._storage, RedisStorage)
        assert middleware._storage.url == "rediss://localhost:6380/9"


def test_cache_backend_warns_about_guarantees():
    with cache_settings():
        warning_codes = {w.id for w in run_checks()}
    assert {"ratelimit.W004", "ratelimit.W005"} <= warning_codes


def test_cache_storage_failure_respects_fail_closed():
    with cache_settings():
        middleware = RateLimitMiddleware(lambda request: HttpResponse("ok"))
        with patch.object(
            middleware._storage, "check_sync", side_effect=RuntimeError("unexpected")
        ):
            with pytest.raises(RuntimeError):
                middleware(RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.21"))


def test_cache_storage_explicit_failure_respects_fail_closed():
    from ratelimit_middleware.storage import StorageError

    with cache_settings():
        middleware = RateLimitMiddleware(lambda request: HttpResponse("ok"))
        with patch.object(
            middleware._storage, "check_sync", side_effect=StorageError("cache down")
        ):
            assert (
                middleware(RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.22")).status_code
                == 429
            )


def test_cache_storage_explicit_failure_can_fail_open():
    from ratelimit_middleware.storage import StorageError

    with cache_settings():
        with override_settings(RATELIMIT_FAIL_OPEN=True):
            middleware = RateLimitMiddleware(lambda request: HttpResponse("ok"))
            with patch.object(
                middleware._storage, "check_sync", side_effect=StorageError("cache down")
            ):
                assert (
                    middleware(RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.23")).status_code
                    == 200
                )
