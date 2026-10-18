"""Redis-backed token-bucket regression suite; requires fakeredis[lua]."""

from concurrent.futures import ThreadPoolExecutor
from time import sleep

import pytest

from tests.redis_helpers import close_async_redis

import fakeredis
import fakeredis.aioredis
from ratelimit_middleware.policies import WindowQuota
from ratelimit_middleware.sliding_window import check_sync as sliding_check
from ratelimit_middleware.token_bucket import (
    TOKEN_BUCKET_SCRIPT,
    bucket_key,
    check_async,
    check_many_async,
    check_many_sync,
    check_sync,
)


def test_constant_space_under_rejected_request_flood():
    redis = fakeredis.FakeRedis(decode_responses=True)
    results = [check_sync(redis, "test:token", 3, 60) for _ in range(1000)]
    assert sum(not result.limited for result in results) == 3
    assert redis.hlen(bucket_key("test:token")) == 2
    assert redis.zcard("test:token") == 0
    assert results[-1].reset_after >= 1


def test_denied_requests_do_not_extend_ttl():
    redis = fakeredis.FakeRedis(decode_responses=True)
    check_sync(redis, "test:ttl", 1, 10)
    before = redis.pttl(bucket_key("test:ttl"))
    for _ in range(50):
        assert check_sync(redis, "test:ttl", 1, 10).limited
    assert 0 < redis.pttl(bucket_key("test:ttl")) <= before


def test_refill_and_burst_capacity():
    redis = fakeredis.FakeRedis(decode_responses=True)
    key = "test:refill"
    assert not check_sync(redis, key, 2, 2).limited
    assert not check_sync(redis, key, 2, 2).limited
    assert check_sync(redis, key, 2, 2).limited
    sleep(1.15)
    assert not check_sync(redis, key, 2, 2).limited


def test_multi_quotas_are_all_or_nothing():
    redis = fakeredis.FakeRedis(decode_responses=True)
    qs = (
        WindowQuota("test:ip", 2, 60, "token_bucket"),
        WindowQuota("test:user", 10, 60, "token_bucket"),
    )
    for _ in range(2):
        assert all(not r.limited for r in check_many_sync(redis, qs))
    results = check_many_sync(redis, qs)
    assert results[0].limited
    assert not results[1].limited
    assert 1 <= results[0].reset_after <= 60
    assert float(redis.hget(bucket_key("test:user"), "tokens")) > 7.9


def test_concurrent_burst_has_exact_admission_count():
    redis = fakeredis.FakeRedis(decode_responses=True)
    with ThreadPoolExecutor(max_workers=16) as executor:
        decisions = list(
            executor.map(lambda _: check_sync(redis, "test:parallel", 10, 60), range(100))
        )
    assert sum(not r.limited for r in decisions) == 10
    assert redis.hlen(bucket_key("test:parallel")) == 2


@pytest.mark.asyncio
async def test_async_single_and_group_match_sync_contract():
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    try:
        assert not (await check_async(redis, "test:async", 1, 60)).limited
        assert (await check_async(redis, "test:async", 1, 60)).limited
        quotas = (
            WindowQuota("test:async:a", 1, 60, "token_bucket"),
            WindowQuota("test:async:b", 1, 60, "token_bucket"),
        )
        assert not any(r.limited for r in await check_many_async(redis, quotas))
        assert all(r.limited for r in await check_many_async(redis, quotas))
    finally:
        await close_async_redis(redis)


def test_sliding_window_and_bucket_have_separate_key_types():
    redis = fakeredis.FakeRedis(decode_responses=True)
    assert not sliding_check(redis, "test:shared", 1, 60).limited
    assert not check_sync(redis, "test:shared", 1, 60).limited
    assert redis.type("test:shared") == "zset"
    assert redis.type(bucket_key("test:shared")) == "hash"


def test_script_reads_all_buckets_before_any_write():
    assert "local amounts = {}" in TOKEN_BUCKET_SCRIPT
    assert "if not blocked then" in TOKEN_BUCKET_SCRIPT
    assert "redis.call('PEXPIRE'" in TOKEN_BUCKET_SCRIPT
    assert "redis.call('TIME')" in TOKEN_BUCKET_SCRIPT


def test_adapter_eval_uses_one_server_call_and_constant_script():
    class RecordingRedis:
        def __init__(self):
            self.calls = []

        def eval(self, *args):
            self.calls.append(args)
            return [1, 1, 4000]

    redis = RecordingRedis()
    assert not check_sync(redis, "test:record", 10, 60).limited
    assert len(redis.calls) == 1
    assert redis.calls[0] == (TOKEN_BUCKET_SCRIPT, 1, bucket_key("test:record"), 10, 60000)


def test_real_redis_parallel_when_isolated_url_is_set():
    """Opt-in multi-client test; never run against a production Redis instance."""
    import os
    from uuid import uuid4
    from redis import Redis

    url = os.environ.get("RATELIMIT_TEST_REDIS_URL")
    if not url:
        pytest.skip("Set RATELIMIT_TEST_REDIS_URL to an isolated Redis instance")
    redis = Redis.from_url(url, decode_responses=True)
    base = f"test:token:real:{uuid4().hex}"
    qs = (
        WindowQuota(base + ":ip", 10, 60, "token_bucket"),
        WindowQuota(base + ":user", 20, 60, "token_bucket"),
    )
    try:
        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(lambda _: check_many_sync(redis, qs), range(100)))
        assert sum(not any(r.limited for r in group) for group in results) == 10
        assert all(redis.hlen(bucket_key(q.key)) == 2 for q in qs)
    finally:
        redis.delete(*(bucket_key(q.key) for q in qs))
        redis.close()
