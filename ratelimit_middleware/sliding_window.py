"""Atomic Redis sliding-window admission shared by Django and ASGI.

The clock is obtained *inside Redis*, not from individual app workers. Rejected
requests never allocate a member or extend a bucket's expiration. The script
uses one Redis key and works with the Redis 5+ effects-replication default.
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass
from typing import Any

# Keep the Lua source constant to avoid unbounded Redis script-cache growth.
# A ZSET holds one timestamped member for each admitted request only.
SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local window_seconds = window_ms / 1000
local member = ARGV[3]

local clock = redis.call('TIME')
-- Store event timestamps in Unix seconds with sub-second precision.
local now_seconds = tonumber(clock[1]) + tonumber(clock[2]) / 1000000

-- An event exactly one window old no longer counts.
redis.call('ZREMRANGEBYSCORE', key, '-inf', now_seconds - window_seconds)
local count = redis.call('ZCARD', key)
local allowed = 0
if count < limit then
    redis.call('ZADD', key, now_seconds, member)
    redis.call('PEXPIRE', key, window_ms)
    count = count + 1
    allowed = 1
end

-- TTL is refreshed only for successful admissions. Denied requests cannot
-- pin their bucket in memory or increase its cardinality.
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset_ms = window_ms
if #oldest == 2 then
    reset_ms = math.max(0, math.ceil((window_seconds - (now_seconds - tonumber(oldest[2]))) * 1000))
end
return {allowed, count, reset_ms}
"""


@dataclass(frozen=True)
class SlidingWindowResult:
    """Current admission decision and seconds until the next slot frees."""

    limited: bool
    count: int
    reset_after: int


def _read_result(raw: Any) -> SlidingWindowResult:
    """Convert Redis's integer response to HTTP-safe rounded-up seconds."""
    allowed, count, reset_ms = (int(value) for value in raw)
    # At millisecond precision a positive wait under a second needs Retry-After=1.
    return SlidingWindowResult(
        limited=not bool(allowed),
        count=count,
        reset_after=max(1, math.ceil(max(0, reset_ms) / 1000)),
    )


def check_sync(redis: Any, key: str, limit: int, window: int) -> SlidingWindowResult:
    """Admit or reject one event with one server-side atomic operation."""
    raw = redis.eval(SLIDING_WINDOW_SCRIPT, 1, key, limit, window * 1000, uuid.uuid4().hex)
    return _read_result(raw)


async def check_async(redis: Any, key: str, limit: int, window: int) -> SlidingWindowResult:
    """Async equivalent, using the same script and server clock."""
    raw = await redis.eval(SLIDING_WINDOW_SCRIPT, 1, key, limit, window * 1000, uuid.uuid4().hex)
    return _read_result(raw)


# Multiple quotas are applied all-or-nothing on standalone Redis. Every
# quota's key is evaluated inside one script, using one server clock sample.
# Redis Cluster requires every KEYS argument to be in the same hash slot;
# different user/IP keys normally are not. Do not silently force all rate
# limits into one shared cluster hash slot (which becomes a hot shard).
MULTI_SLIDING_WINDOW_SCRIPT = """
local n = #KEYS
local clock = redis.call('TIME')
local now = tonumber(clock[1]) + tonumber(clock[2]) / 1000000
local counts = {}
local wait = {}
local blocked = false
for i = 1, n do
    local a = (i - 1) * 3
    local limit = tonumber(ARGV[a + 1])
    local window_ms = tonumber(ARGV[a + 2])
    local seconds = window_ms / 1000
    redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now - seconds)
    counts[i] = redis.call('ZCARD', KEYS[i])
    if counts[i] >= limit then blocked = true end
    local oldest = redis.call('ZRANGE', KEYS[i], 0, 0, 'WITHSCORES')
    if #oldest == 2 then
        wait[i] = math.max(0, math.ceil((seconds - (now - tonumber(oldest[2]))) * 1000))
    else
        wait[i] = window_ms
    end
end
local result = {blocked and 0 or 1}
for i = 1, n do
    local a = (i - 1) * 3
    if not blocked then
        redis.call('ZADD', KEYS[i], now, ARGV[a + 3])
        redis.call('PEXPIRE', KEYS[i], tonumber(ARGV[a + 2]))
        counts[i] = counts[i] + 1
        if counts[i] == 1 then wait[i] = tonumber(ARGV[a + 2]) end
    end
    table.insert(result, counts[i])
    table.insert(result, wait[i])
end
return result
"""


def _read_multi(raw: Any, quotas: Any) -> tuple[SlidingWindowResult, ...]:
    """Parse one atomic group decision into an individual result per limit."""
    if len(raw) != 1 + len(quotas) * 2:
        raise ValueError("Unexpected Redis group admission result")
    allowed = bool(int(raw[0]))
    results = []
    for i, quota in enumerate(quotas):
        count = int(raw[1 + i * 2])
        reset_ms = int(raw[2 + i * 2])
        results.append(
            SlidingWindowResult(
                limited=not allowed and count >= quota.rate,
                count=count,
                reset_after=max(1, math.ceil(max(0, reset_ms) / 1000)),
            )
        )
    return tuple(results)


def check_many_sync(redis: Any, quotas: Any) -> tuple[SlidingWindowResult, ...]:
    if len(quotas) < 2:
        raise ValueError("Multi-quota Redis admission requires at least two quotas")
    request_id = uuid.uuid4().hex
    args = [
        item
        for i, q in enumerate(quotas)
        for item in (q.rate, q.window * 1000, f"{request_id}:{i}")
    ]
    raw = redis.eval(MULTI_SLIDING_WINDOW_SCRIPT, len(quotas), *(q.key for q in quotas), *args)
    return _read_multi(raw, quotas)


async def check_many_async(redis: Any, quotas: Any) -> tuple[SlidingWindowResult, ...]:
    if len(quotas) < 2:
        raise ValueError("Multi-quota Redis admission requires at least two quotas")
    request_id = uuid.uuid4().hex
    args = [
        item
        for i, q in enumerate(quotas)
        for item in (q.rate, q.window * 1000, f"{request_id}:{i}")
    ]
    raw = await redis.eval(
        MULTI_SLIDING_WINDOW_SCRIPT, len(quotas), *(q.key for q in quotas), *args
    )
    return _read_multi(raw, quotas)
