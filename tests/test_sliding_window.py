"""Atomic admission contract tests (requires fakeredis[lua])."""

from concurrent.futures import ThreadPoolExecutor
from time import sleep

import fakeredis
import fakeredis.aioredis
import pytest

from tests.redis_helpers import close_async_redis

from ratelimit_middleware.sliding_window import (
    SLIDING_WINDOW_SCRIPT,
    SlidingWindowResult,
    check_async,
    check_sync,
)


def test_admitted_events_are_bounded_under_rejection_flood():
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:bounded"
    results = [check_sync(redis, key, limit=3, window=60) for _ in range(200)]
    assert [result.limited for result in results] == [False] * 3 + [True] * 197
    assert {result.count for result in results[2:]} == {3}
    assert redis.zcard(key) == 3
    assert 0 < redis.pttl(key) <= 60_000
    assert all(1 <= result.reset_after <= 60 for result in results)


def test_denied_requests_do_not_refresh_ttl():
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:ttl"
    check_sync(redis, key, limit=1, window=10)
    before = redis.pttl(key)
    for _ in range(40):
        assert check_sync(redis, key, limit=1, window=10).limited
    assert redis.pttl(key) <= before
    assert redis.zcard(key) == 1


def test_rate_window_expires_to_allow_requests_again():
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:expiry"
    assert not check_sync(redis, key, limit=1, window=1).limited
    assert check_sync(redis, key, limit=1, window=1).limited
    sleep(1.15)
    result = check_sync(redis, key, limit=1, window=1)
    assert not result.limited
    assert result.count == 1
    assert redis.zcard(key) == 1


def test_actual_wait_is_rounded_up_to_seconds():
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:retry"
    check_sync(redis, key, limit=1, window=2)
    sleep(1.1)
    result = check_sync(redis, key, limit=1, window=2)
    assert result == SlidingWindowResult(limited=True, count=1, reset_after=1)


def test_simultaneous_requests_never_exceed_quota():
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:concurrent"

    def request(_):
        return check_sync(redis, key, limit=10, window=30)

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(request, range(100)))
    assert sum(not result.limited for result in results) == 10
    assert redis.zcard(key) == 10
    assert max(result.count for result in results) == 10


@pytest.mark.asyncio
async def test_async_uses_the_same_atomic_admission_script():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    key = "test:async"
    try:
        first = await check_async(redis, key, limit=1, window=30)
        second = await check_async(redis, key, limit=1, window=30)
        assert not first.limited
        assert second.limited
        assert second.count == 1
        assert await redis.zcard(key) == 1
    finally:
        await close_async_redis(redis)


def test_lua_source_only_addresses_the_supplied_key():
    # Keep key names as KEYS, not embedded in the script or derived from ARGV.
    assert "KEYS[1]" in SLIDING_WINDOW_SCRIPT
    assert "redis.call('TIME')" in SLIDING_WINDOW_SCRIPT
    assert "if count < limit then" in SLIDING_WINDOW_SCRIPT
    assert "redis.call('PEXPIRE', key, window_ms)" in SLIDING_WINDOW_SCRIPT


def test_eval_arguments_use_constant_script_single_key_and_unique_members():
    class RecordingRedis:
        def __init__(self):
            self.calls = []

        def eval(self, *args):
            self.calls.append(args)
            return [1, 1, 4250]

    redis = RecordingRedis()
    first = check_sync(redis, "bucket:1", limit=2, window=5)
    second = check_sync(redis, "bucket:1", limit=2, window=5)
    assert first == second == SlidingWindowResult(limited=False, count=1, reset_after=5)
    assert all(call[:5] == (SLIDING_WINDOW_SCRIPT, 1, "bucket:1", 2, 5000) for call in redis.calls)
    assert len(redis.calls[0][5]) == 32
    assert redis.calls[0][5] != redis.calls[1][5]


@pytest.mark.asyncio
async def test_async_eval_arguments_and_result_parsing():
    class RecordingAsyncRedis:
        async def eval(self, *args):
            assert args[1:5] == (1, "bucket:async", 1, 30_000)
            return [0, 1, 1]

    result = await check_async(RecordingAsyncRedis(), "bucket:async", limit=1, window=30)
    assert result == SlidingWindowResult(limited=True, count=1, reset_after=1)


def test_real_redis_concurrency_when_integration_url_is_set():
    """Optional true multi-client check against an isolated Redis database."""
    import os
    import uuid

    from redis import Redis

    url = os.environ.get("RATELIMIT_TEST_REDIS_URL")
    if not url:
        pytest.skip("Set RATELIMIT_TEST_REDIS_URL for a real Redis integration run")
    redis = Redis.from_url(url, decode_responses=True)
    key = f"ratelimit:test:concurrent:{uuid.uuid4().hex}"
    try:

        def request(_):
            return check_sync(redis, key, limit=10, window=30)

        with ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(request, range(100)))
        assert sum(not result.limited for result in results) == 10
        assert redis.zcard(key) == 10
    finally:
        redis.delete(key)
        redis.close()


def test_second_based_event_scores_are_counted_within_window():
    """A recently admitted event must count toward the active window."""
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:score"
    seconds, microseconds = redis.time()
    redis.zadd(key, {"recent-event": seconds + microseconds / 1_000_000 - 2})
    redis.expire(key, 60)
    result = check_sync(redis, key, limit=1, window=60)
    assert result.limited
    assert result.count == 1
    assert redis.zcard(key) == 1
    assert 57 <= result.reset_after <= 59
