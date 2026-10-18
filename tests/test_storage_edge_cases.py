"""Deterministic backend failures and cache expiry races, without network I/O."""

import builtins
from unittest.mock import AsyncMock, Mock, call, patch

import pytest
from django.core.exceptions import ImproperlyConfigured

from ratelimit_middleware.policies import WindowQuota
from ratelimit_middleware.sliding_window import SlidingWindowResult
from ratelimit_middleware.storage import DjangoCacheStorage, RedisStorage, StorageError


@pytest.mark.parametrize(
    "operation,module",
    [
        ("construct", "redis.connection"),
        ("_get_sync_redis", "redis"),
        ("_get_async_redis", "redis.asyncio"),
        ("check_sync", "redis.exceptions"),
        ("check_async", "redis.exceptions"),
        ("check_many_sync", "redis.exceptions"),
        ("check_many_async", "redis.exceptions"),
    ],
)
@pytest.mark.asyncio
async def test_missing_redis_extra_is_a_configuration_error(monkeypatch, operation, module):
    storage = RedisStorage("redis://localhost/15", 1)
    original_import = builtins.__import__

    def missing_extra(name, *args, **kwargs):
        if name == module:
            raise ImportError("redis extra is not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_extra)
    with pytest.raises(ImproperlyConfigured, match="redis") as caught:
        if operation == "construct":
            RedisStorage("redis://localhost/15", 1)
        elif operation.startswith("_get"):
            getattr(storage, operation)()
        else:
            args = ([WindowQuota("a", 1, 60), WindowQuota("b", 2, 60)],)
            if "many" not in operation:
                args = ("a", 1, 60)
            if operation.endswith("async"):
                await getattr(storage, operation)(*args)
            else:
                getattr(storage, operation)(*args)
    assert isinstance(caught.value.__cause__, ImportError)


def test_native_storage_rejects_invalid_client_options_without_connecting():
    with pytest.raises(ImproperlyConfigured, match="invalid connection options"):
        RedisStorage("redis://localhost/15?socket_timeout=invalid", 1)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("retry_wins", [False, True])
@pytest.mark.asyncio
async def test_cache_expiry_between_add_and_increment_retries_once(async_mode, retry_wins):
    cache = Mock()
    mock_class = AsyncMock if async_mode else Mock
    add = mock_class(side_effect=[False, retry_wins])
    incr = mock_class(side_effect=[ValueError("expired"), 3])
    cache.aadd, cache.aincr = (add, incr) if async_mode else (None, None)
    cache.add, cache.incr = (add, incr) if not async_mode else (None, None)
    storage = DjangoCacheStorage("selected")
    with patch("ratelimit_middleware.storage.caches", {"selected": cache}):
        result = (
            await storage.check_async("bucket", 2, 60)
            if async_mode
            else storage.check_sync("bucket", 2, 60)
        )
    assert result == SlidingWindowResult(not retry_wins, 1 if retry_wins else 3, 60)
    assert add.call_args_list == [call("bucket", 1, timeout=60)] * 2
    assert incr.call_args_list == [call("bucket")] * (1 if retry_wins else 2)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_cache_second_expiry_fails_instead_of_admitting_and_recovers(async_mode):
    cache = Mock()
    mock_class = AsyncMock if async_mode else Mock
    add = mock_class(side_effect=[False, False, True])
    incr = mock_class(side_effect=ValueError("evicted again"))
    if async_mode:
        cache.aadd, cache.aincr = add, incr
    else:
        cache.add, cache.incr = add, incr
    storage = DjangoCacheStorage("selected")
    with patch("ratelimit_middleware.storage.caches", {"selected": cache}):
        with pytest.raises(StorageError) as caught:
            if async_mode:
                await storage.check_async("bucket", 2, 60)
            else:
                storage.check_sync("bucket", 2, 60)
        assert isinstance(caught.value.__cause__, ValueError)
        result = (
            await storage.check_async("bucket", 2, 60)
            if async_mode
            else storage.check_sync("bucket", 2, 60)
        )
    assert result == SlidingWindowResult(False, 1, 60)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("denied_index", [None, 0, 1])
@pytest.mark.asyncio
async def test_cache_groups_stop_charging_after_first_denial(async_mode, denied_index):
    storage = DjangoCacheStorage("unused")
    quotas = tuple(WindowQuota(f"quota:{i}", i + 1, 60) for i in range(3))
    results = tuple(SlidingWindowResult(i == denied_index, i + 1, 60) for i in range(3))
    method = "check_async" if async_mode else "check_sync"
    with patch.object(storage, method, side_effect=results) as check:
        actual = (
            await storage.check_many_async(quotas)
            if async_mode
            else storage.check_many_sync(quotas)
        )
    count = 3 if denied_index is None else denied_index + 1
    assert actual == results[:count]
    assert check.call_args_list == [call(q.key, q.rate, q.window) for q in quotas[:count]]
