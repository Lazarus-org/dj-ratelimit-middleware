"""Opt-in integration tests. URLs must identify disposable local test services."""

import asyncio
import os
import platform
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from tests.redis_helpers import close_async_redis
from django.core.cache import caches
from django.test import override_settings
from redis import Redis
from redis.asyncio import Redis as AsyncRedis

from ratelimit_middleware import sliding_window, token_bucket
from ratelimit_middleware.policies import WindowQuota
from ratelimit_middleware.storage import DjangoCacheStorage, RedisStorage, StorageError


@pytest.fixture
def live_redis():
    url = os.environ.get("RATELIMIT_TEST_REDIS_URL")
    if not url:
        pytest.skip("Set RATELIMIT_TEST_REDIS_URL to a disposable Redis instance")
    client = Redis.from_url(url, decode_responses=True, socket_timeout=2)
    base = f"ratelimit:validation:{uuid4().hex}"
    keys = [base + suffix for suffix in (":a", ":b", ":c")]
    try:
        assert client.ping()
        yield client, keys, url
    finally:
        client.delete(*keys, *(token_bucket.bucket_key(key) for key in keys))
        client.close()


@pytest.mark.parametrize("engine", [sliding_window, token_bucket])
def test_real_server_admission_expiry_and_rejection_state(live_redis, engine):
    client, keys, _ = live_redis
    key = keys[0]
    actual = token_bucket.bucket_key(key) if engine is token_bucket else key
    for _ in range(3):
        assert not engine.check_sync(client, key, 3, 60).limited
    state = client.dump(actual)
    ttl = client.pttl(actual)
    denied = engine.check_sync(client, key, 3, 60)
    assert denied.limited and 1 <= denied.reset_after <= 60
    assert client.dump(actual) == state
    assert 0 < client.pttl(actual) <= ttl
    assert (client.hlen(actual) if engine is token_bucket else client.zcard(actual)) == (
        2 if engine is token_bucket else 3
    )
    assert not engine.check_sync(client, keys[1], 3, 60).limited
    # Check natural expiration in an independent short-lived bucket. Keeping
    # the rejection bucket's refill slow avoids assuming subsecond scheduling.
    expiry_key = keys[2]
    expiry_actual = token_bucket.bucket_key(expiry_key) if engine is token_bucket else expiry_key
    assert not engine.check_sync(client, expiry_key, 1, 1).limited
    assert 0 < client.pttl(expiry_actual) <= 1000
    time.sleep(1.1)
    assert not client.exists(expiry_actual)
    assert not engine.check_sync(client, expiry_key, 1, 1).limited


@pytest.mark.parametrize(
    "engine,algorithm", [(sliding_window, "sliding_window"), (token_bucket, "token_bucket")]
)
def test_real_group_concurrency_and_rollback(live_redis, engine, algorithm):
    client, keys, _ = live_redis
    quotas = (WindowQuota(keys[0], 10, 600, algorithm), WindowQuota(keys[1], 100, 600, algorithm))
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(lambda _: engine.check_many_sync(client, quotas), range(100)))
    assert sum(not any(item.limited for item in group) for group in results) == 10
    fresh = (quotas[0], WindowQuota(keys[2], 100, 600, algorithm))
    assert engine.check_many_sync(client, fresh)[0].limited
    actual = token_bucket.bucket_key(keys[2]) if engine is token_bucket else keys[2]
    assert not client.exists(actual)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "engine,algorithm", [(sliding_window, "sliding_window"), (token_bucket, "token_bucket")]
)
async def test_real_async_parallel_group_admission(live_redis, engine, algorithm):
    _, keys, url = live_redis
    client = AsyncRedis.from_url(url, decode_responses=True, socket_timeout=2)
    try:
        quotas = (
            WindowQuota(keys[0], 10, 600, algorithm),
            WindowQuota(keys[1], 20, 600, algorithm),
        )
        results = await asyncio.gather(
            *(engine.check_many_async(client, quotas) for _ in range(100))
        )
        assert sum(not any(item.limited for item in group) for group in results) == 10
    finally:
        await close_async_redis(client)


def test_real_sliding_server_time_and_exact_cutoff(live_redis):
    client, keys, _ = live_redis
    seconds, micros = client.time()
    now = seconds + micros / 1e6
    client.zadd(keys[0], {"expired": now - 60, "recent": now - 1})
    result = sliding_window.check_sync(client, keys[0], 1, 60)
    assert result.limited and result.count == 1
    assert 58 <= result.reset_after <= 59
    assert client.zrange(keys[0], 0, -1) == ["recent"]


def test_real_fractional_refill_and_clock_correction_denial(live_redis):
    client, keys, _ = live_redis
    seconds, micros = client.time()
    now = seconds * 1000000 + micros
    key = token_bucket.bucket_key(keys[0])
    # Half a token plus 0.6 seconds of refill at one token/second admits once.
    client.hset(key, mapping={"tokens": "0.5", "at": now - 600000})
    assert not token_bucket.check_sync(client, keys[0], 2, 2).limited
    assert token_bucket.check_sync(client, keys[0], 2, 2).limited
    client.hset(key, mapping={"tokens": "0.9999999995", "at": now + 10000000})
    assert token_bucket.check_sync(client, keys[0], 1, 60).limited


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_real_cache_admission_and_eviction(live_redis, async_mode):
    _, keys, url = live_redis
    config = {
        "default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": url}
    }
    with override_settings(CACHES=config):
        storage = DjangoCacheStorage("default")

        async def check():
            return (
                await storage.check_async(keys[0], 1, 1)
                if async_mode
                else storage.check_sync(keys[0], 1, 1)
            )

        try:
            assert not (await check()).limited
            assert (await check()).limited
            await caches["default"].adelete(keys[0])
            assert not (await check()).limited  # Eviction resets a generic-cache quota.
            await asyncio.sleep(1.1)
            assert not (await check()).limited
        finally:
            await caches["default"].adelete(keys[0])


def test_memcached_counter_concurrency_and_expiry():
    location = os.environ.get("RATELIMIT_TEST_MEMCACHED_URL")
    if not location:
        pytest.skip("Set RATELIMIT_TEST_MEMCACHED_URL to disposable Memcached")
    config = {
        "default": {
            "BACKEND": "django.core.cache.backends.memcached.PyMemcacheCache",
            "LOCATION": location,
            "OPTIONS": {"use_pooling": True, "connect_timeout": 2, "timeout": 2, "no_delay": True},
        }
    }
    key = f"validation:{uuid4().hex}"
    # pymemcache calls platform.system() while creating each connection. On
    # Windows, initialize CPython's WMI-backed platform cache on the main thread
    # before starting concurrent clients (avoids upstream COM/WMI races).
    platform.uname()
    with override_settings(CACHES=config):
        storage = DjangoCacheStorage("default")
        try:
            with ThreadPoolExecutor(max_workers=20) as executor:
                results = list(executor.map(lambda _: storage.check_sync(key, 10, 10), range(100)))
            assert sum(not item.limited for item in results) == 10
            assert caches["default"].get(key) == 100  # Cache denials consume counters.
            caches["default"].delete(key)
            assert not storage.check_sync(key, 1, 1).limited
            time.sleep(1.1)
            assert not storage.check_sync(key, 1, 1).limited
        finally:
            caches["default"].delete(key)


@pytest.mark.asyncio
async def test_connection_refused_is_storage_error_for_both_paths():
    # Port 1 on loopback is intentionally unavailable; no external network use.
    storage = RedisStorage("redis://127.0.0.1:1/0", 0.05)
    with pytest.raises(StorageError):
        storage.check_sync("unused", 1, 60)
    with pytest.raises(StorageError):
        await storage.check_async("unused", 1, 60)
    storage._sync_client.close()
    await close_async_redis(storage._async_client)


@pytest.mark.parametrize("algorithm", ["sliding_window", "token_bucket"])
@pytest.mark.asyncio
async def test_real_storage_adapter_single_and_group_paths(live_redis, algorithm):
    _, keys, url = live_redis
    storage = RedisStorage(url, 2, algorithm)
    quotas = tuple(WindowQuota(key, 1, 60, algorithm) for key in keys[1:])
    try:
        assert not storage.check_sync(keys[0], 1, 60).limited
        assert (await storage.check_async(keys[0], 1, 60)).limited
        assert all(not item.limited for item in storage.check_many_sync(quotas))
        assert all(item.limited for item in await storage.check_many_async(quotas))
        assert storage._get_sync_redis() is storage._sync_client
        assert storage._get_async_redis() is storage._async_client
    finally:
        storage._sync_client.close()
        await close_async_redis(storage._async_client)
