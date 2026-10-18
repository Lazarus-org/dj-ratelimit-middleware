"""Adversarial regressions found during the stabilization audit."""

from unittest.mock import AsyncMock, patch

import pytest

from tests.redis_helpers import close_async_redis
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from ratelimit_middleware.checks import ratelimit_settings_check
from ratelimit_middleware.middleware import ASGIRateLimitMiddleware, RateLimitMiddleware
from ratelimit_middleware.storage import DjangoCacheStorage


@pytest.mark.parametrize(
    "extra,code",
    [
        ({"RATELIMIT_REDIS_TIMEOUT": 10**1000}, "ratelimit.E009"),
        (
            {"RATELIMIT_ALGORITHM": "token_bucket", "RATELIMIT_WS_MSG_RATE": 10**10},
            "ratelimit.E017",
        ),
        (
            {"RATELIMIT_ALGORITHM": "token_bucket", "RATELIMIT_WS_MSG_WINDOW": 10**10},
            "ratelimit.E017",
        ),
        ({"RATELIMIT_REDIS_URL": "redis://localhost/0?socket_timeout=bad"}, "ratelimit.E003"),
        ({"RATELIMIT_REDIS_URL": "redis://localhost/0?socket_timeout=nan"}, "ratelimit.E003"),
        ({"RATELIMIT_REDIS_URL": "redis://localhost/0?max_connections=0"}, "ratelimit.E003"),
        (
            {"RATELIMIT_IDENTITY": "custom", "RATELIMIT_IDENTITY_RESOLVER": ".bad.resolver"},
            "ratelimit.E015",
        ),
        (
            {
                "RATELIMIT_STORAGE": {"BACKEND": "cache"},
                "CACHES": {
                    "default": {
                        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                        "KEY_FUNCTION": "missing.module.function",
                    }
                },
            },
            "ratelimit.E013",
        ),
    ],
)
def test_bad_configuration_is_blocking_for_all_entry_points(extra, code):
    with override_settings(RATELIMIT_FAIL_OPEN=True, **extra):
        assert code in {issue.id for issue in ratelimit_settings_check(None)}
        with pytest.raises(ImproperlyConfigured, match=code):
            RateLimitMiddleware(lambda request: HttpResponse("ok"))
        with pytest.raises(ImproperlyConfigured, match=code):
            ASGIRateLimitMiddleware(AsyncMock())


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_cache_configuration_errors_are_never_storage_failures(async_mode):
    storage = DjangoCacheStorage("default")
    with patch("ratelimit_middleware.storage.caches") as caches:
        caches.__getitem__.side_effect = ImproperlyConfigured("bad backend configuration")
        with pytest.raises(ImproperlyConfigured):
            if async_mode:
                await storage.check_async("key", 1, 60)
            else:
                storage.check_sync("key", 1, 60)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_backend_credentials_never_reach_django_logs(async_mode, caplog):
    from redis.exceptions import AuthenticationError

    async def downstream_async(request):
        return HttpResponse("ok")

    middleware = RateLimitMiddleware(
        downstream_async if async_mode else lambda r: HttpResponse("ok")
    )
    request = RequestFactory().get("/private", REMOTE_ADDR="192.0.2.200")
    method = "_get_async_redis" if async_mode else "_get_sync_redis"
    with patch.object(
        middleware._storage, method, side_effect=AuthenticationError("credential-secret")
    ):
        response = await middleware(request) if async_mode else middleware(request)
    assert response.status_code == 429
    assert "credential-secret" not in caplog.text
    assert "Storage error" in caplog.text


def test_ambiguous_leading_slashes_never_exempt():
    from ratelimit_middleware.identity import is_exempt_path

    assert not is_exempt_path("//health", ("/health",))


def test_fractional_token_denial_is_not_lost_to_header_rounding():
    import fakeredis
    from ratelimit_middleware.token_bucket import bucket_key, check_sync

    client = fakeredis.FakeRedis(decode_responses=True)
    seconds, micros = client.time()
    # A server clock correction must not let display-count rounding override
    # the Lua admission decision when capacity is just below one token.
    client.hset(
        bucket_key("fraction"),
        mapping={
            "tokens": "0.9999999995",
            "at": (seconds + 10) * 1000000 + micros,
        },
    )
    assert check_sync(client, "fraction", 1, 60).limited


@pytest.mark.parametrize(
    "name",
    ["RATELIMIT_RATE", "RATELIMIT_WINDOW", "RATELIMIT_WS_MSG_RATE", "RATELIMIT_WS_MSG_WINDOW"],
)
def test_sliding_window_numeric_limits_fit_redis_lua(name):
    with override_settings(**{name: 10**1000}):
        with pytest.raises(ImproperlyConfigured):
            RateLimitMiddleware(lambda request: HttpResponse())


def test_policy_sliding_window_numeric_limits_fit_redis_lua():
    with override_settings(
        RATELIMIT_POLICIES=[
            {
                "NAME": "huge",
                "PATH": "/",
                "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 10**1000}],
            }
        ]
    ):
        with pytest.raises(ImproperlyConfigured):
            RateLimitMiddleware(lambda request: HttpResponse())


def test_invalid_cache_backend_path_does_not_echo_credentials():
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "cache"},
        CACHES={
            "default": {
                "BACKEND": "redis://:credential-secret@localhost/0",
            }
        },
    ):
        issues = ratelimit_settings_check(None)
        assert any(issue.id == "ratelimit.E013" for issue in issues)
        assert "credential-secret" not in " ".join(issue.msg for issue in issues)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_cross_slot_groups_are_configuration_errors_even_when_fail_open(async_mode):
    from redis.exceptions import ClusterCrossSlotError
    from ratelimit_middleware.policies import WindowQuota
    from ratelimit_middleware.storage import RedisStorage

    with override_settings(RATELIMIT_FAIL_OPEN=True):
        storage = RedisStorage("redis://localhost/0", 1)
        quotas = (WindowQuota("ip", 1, 60), WindowQuota("user", 1, 60))
        method = "_get_async_redis" if async_mode else "_get_sync_redis"
        with patch.object(storage, method, side_effect=ClusterCrossSlotError("cross-slot")):
            with pytest.raises(ImproperlyConfigured, match="Cluster"):
                if async_mode:
                    await storage.check_many_async(quotas)
                else:
                    storage.check_many_sync(quotas)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_native_clients_work_with_redis5_without_protocol_url_override(async_mode):
    import os
    from uuid import uuid4
    from redis import Redis
    from ratelimit_middleware.storage import RedisStorage
    from ratelimit_middleware.token_bucket import bucket_key

    url = os.environ.get("RATELIMIT_TEST_REDIS5_URL")
    if not url:
        pytest.skip("Set RATELIMIT_TEST_REDIS5_URL to a disposable Redis 5 server")
    cleanup = Redis.from_url(url, protocol=2)
    assert cleanup.info("server")["redis_version"].startswith("5.")
    for algorithm in ("sliding_window", "token_bucket"):
        key = f"validation:redis5:{uuid4().hex}"
        storage = RedisStorage(url, 2, algorithm)
        try:
            if async_mode:
                assert not (await storage.check_async(key, 1, 60)).limited
                assert (await storage.check_async(key, 1, 60)).limited
            else:
                assert not storage.check_sync(key, 1, 60).limited
                assert storage.check_sync(key, 1, 60).limited
        finally:
            cleanup.delete(key, bucket_key(key))
            if storage._sync_client is not None:
                storage._sync_client.close()
            if storage._async_client is not None:
                await close_async_redis(storage._async_client)
    cleanup.close()


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("grouped", [False, True])
@pytest.mark.parametrize("error_name", ["MovedError", "AskError"])
@pytest.mark.asyncio
async def test_unsupported_cluster_redirects_cannot_fail_open(async_mode, grouped, error_name):
    from redis import exceptions
    from ratelimit_middleware.policies import WindowQuota
    from ratelimit_middleware.storage import RedisStorage

    storage = RedisStorage("redis://localhost/0", 1)
    quotas = (WindowQuota("ip", 1, 60), WindowQuota("user", 1, 60))
    error = getattr(exceptions, error_name)("123 127.0.0.1:6379")
    with patch.object(
        storage, "_get_async_redis" if async_mode else "_get_sync_redis", side_effect=error
    ):
        with pytest.raises(ImproperlyConfigured, match="Cluster"):
            if async_mode:
                if grouped:
                    await storage.check_many_async(quotas)
                else:
                    await storage.check_async("key", 1, 60)
            elif grouped:
                storage.check_many_sync(quotas)
            else:
                storage.check_sync("key", 1, 60)


@pytest.mark.parametrize("query", ["unknown_option=1", "protocol=9"])
def test_redis_connection_options_fail_before_first_request(query):
    with override_settings(RATELIMIT_REDIS_URL=f"redis://localhost/0?{query}"):
        assert "ratelimit.E003" in {issue.id for issue in ratelimit_settings_check(None)}
        with pytest.raises(ImproperlyConfigured, match="ratelimit.E003"):
            RateLimitMiddleware(lambda request: HttpResponse())
        with pytest.raises(ImproperlyConfigured, match="ratelimit.E003"):
            ASGIRateLimitMiddleware(AsyncMock())


def test_connection_option_validation_never_connects():
    from ratelimit_middleware.conf import _valid_redis_url

    with patch("redis.connection.Connection.connect", side_effect=AssertionError("network access")):
        assert _valid_redis_url("redis://localhost/0?socket_timeout=1&max_connections=2")


@pytest.mark.asyncio
async def test_asgi_accepts_tuple_headers_without_mutating_application_messages():
    from ratelimit_middleware.sliding_window import SlidingWindowResult

    start = {
        "type": "http.response.start",
        "status": 200,
        "headers": ((b"content-type", b"text/plain"),),
    }
    sent = []

    async def app(scope, receive, send):
        await send(start)
        await send({"type": "http.response.body", "body": b"ok"})

    async def send(message):
        sent.append(message)

    middleware = ASGIRateLimitMiddleware(app)
    middleware._storage.check_async = AsyncMock(
        side_effect=[SlidingWindowResult(False, 1, 60), SlidingWindowResult(False, 2, 60)]
    )
    scope = {
        "type": "http",
        "path": "/headers",
        "method": "GET",
        "headers": [],
        "http_version": "1.1",
        "scheme": "http",
        "query_string": b"",
        "asgi": {"version": "3.0"},
        "server": ("127.0.0.1", 80),
        "client": ("192.0.2.246", 42),
    }
    await middleware(scope, AsyncMock(), send)
    await middleware(scope, AsyncMock(), send)
    assert start["headers"] == ((b"content-type", b"text/plain"),)
    responses = [message for message in sent if message["type"] == "http.response.start"]
    assert [dict(message["headers"])[b"x-ratelimit-remaining"] for message in responses] == [
        b"1",
        b"0",
    ]
    assert all(
        sum(name == b"x-ratelimit-limit" for name, _ in message["headers"]) == 1
        for message in responses
    )
