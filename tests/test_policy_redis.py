"""Redis Lua group admission: atomicity, memory bounds, retry timing."""

from concurrent.futures import ThreadPoolExecutor

import pytest

import fakeredis
from ratelimit_middleware.policies import WindowQuota
from ratelimit_middleware.sliding_window import check_many_async, check_many_sync


def test_group_denial_does_not_consume_other_quota():
    client = fakeredis.FakeRedis(decode_responses=True)
    quotas = (WindowQuota("cp5:ip", 2, 60), WindowQuota("cp5:user", 10, 60))
    for _ in range(2):
        assert all(not result.limited for result in check_many_sync(client, quotas))
    assert check_many_sync(client, quotas)[0].limited
    assert client.zcard("cp5:ip") == 2
    assert client.zcard("cp5:user") == 2


def test_two_identity_quota_isolation_and_concurrent_atomicity():
    client = fakeredis.FakeRedis(decode_responses=True)
    quotas = (WindowQuota("cp5:a", 7, 60), WindowQuota("cp5:b", 13, 60))
    with ThreadPoolExecutor(max_workers=16) as pool:
        allowed = list(
            pool.map(
                lambda _: not any(r.limited for r in check_many_sync(client, quotas)), range(60)
            )
        )
    assert sum(allowed) == 7
    assert client.zcard("cp5:a") == 7
    assert client.zcard("cp5:b") == 7


@pytest.mark.asyncio
async def test_async_group_uses_one_server_side_operation():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    quotas = (WindowQuota("cp5:async-a", 1, 60), WindowQuota("cp5:async-b", 1, 60))
    assert not any(r.limited for r in await check_many_async(client, quotas))
    results = await check_many_async(client, quotas)
    assert all(r.limited for r in results)
    assert all(r.reset_after >= 1 for r in results)
