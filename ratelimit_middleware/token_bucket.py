"""Atomic, constant-space Redis token-bucket admission.

The script accepts one or more keys, obtaining Redis server time once and
reading every bucket before committing any admission. Rejections do not write
state or refresh expiration. A key stores exactly two hash fields; bucket keys
are separated from sliding-window sorted sets by the storage adapter.

Token-bucket semantics: RATE is both capacity and refill tokens per WINDOW
seconds, with a burst of RATE admitted from an initially full bucket.
"""

from __future__ import annotations

import math
from typing import Any

from .sliding_window import SlidingWindowResult

# Lua runs atomically on standalone Redis. As with grouped sliding-window
# scripts, Redis Cluster multi-key calls require every key in one hash slot.
TOKEN_BUCKET_SCRIPT = """
local n = #KEYS
local clock = redis.call('TIME')
local now_us = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local amounts = {}
local blocked = false

for i = 1, n do
    local rate = tonumber(ARGV[2 * i - 1])
    local window_us = tonumber(ARGV[2 * i]) * 1000
    local state = redis.call('HMGET', KEYS[i], 'tokens', 'at')
    local tokens = rate
    if state[1] and state[2] then
        local elapsed = math.max(0, now_us - tonumber(state[2]))
        tokens = math.min(rate, tonumber(state[1]) + elapsed * rate / window_us)
    end
    amounts[i] = tokens
    if tokens < 1 then blocked = true end
end

local out = {blocked and 0 or 1}
for i = 1, n do
    local rate = tonumber(ARGV[2 * i - 1])
    local window_ms = tonumber(ARGV[2 * i])
    local tokens = amounts[i]
    if not blocked then
        tokens = tokens - 1
        redis.call('HSET', KEYS[i], 'tokens', string.format('%.17g', tokens), 'at', string.format('%.0f', now_us))
        -- After this interval the bucket is completely full without state.
        local expiry = math.max(1, math.ceil((rate - tokens) * window_ms / rate))
        redis.call('PEXPIRE', KEYS[i], expiry)
    end
    -- The count is an approximate number of spent tokens (for header display).
    local spent = math.min(rate, math.max(0, math.ceil(rate - tokens - 0.000000001)))
    -- Header rounding must never erase a quota's actual denial.
    if amounts[i] < 1 then spent = rate end
    local wait_ms
    if blocked and amounts[i] < 1 then
        wait_ms = math.max(1, math.ceil((1 - amounts[i]) * window_ms / rate))
    else
        wait_ms = math.max(1, math.ceil((rate - tokens) * window_ms / rate))
    end
    table.insert(out, spent)
    table.insert(out, wait_ms)
end
return out
"""  # nosec B105


def _parse(raw: Any, rates: tuple[int, ...]) -> tuple[SlidingWindowResult, ...]:
    if len(raw) != 1 + 2 * len(rates):
        raise ValueError("Unexpected Redis token-bucket admission result")
    admitted = bool(int(raw[0]))
    return tuple(
        SlidingWindowResult(
            limited=not admitted and int(raw[1 + 2 * i]) >= rate,
            count=int(raw[1 + 2 * i]),
            reset_after=max(1, math.ceil(max(0, int(raw[2 + 2 * i])) / 1000)),
        )
        for i, rate in enumerate(rates)
    )


def bucket_key(key: str) -> str:
    """Keep token-bucket hashes disjoint from existing sliding-window ZSETs."""
    return f"ratelimit:tb:{key}"


def _args(quotas):
    if not 1 <= len(quotas) <= 8:
        raise ValueError("Token-bucket admission requires between one and eight quotas")
    return (
        len(quotas),
        *(bucket_key(q.key) for q in quotas),
        *(value for q in quotas for value in (q.rate, q.window * 1000)),
    )


def check_sync(redis: Any, key: str, limit: int, window: int) -> SlidingWindowResult:
    quota = _Quota(key, limit, window)
    return _parse(redis.eval(TOKEN_BUCKET_SCRIPT, *_args((quota,))), (limit,))[0]


async def check_async(redis: Any, key: str, limit: int, window: int) -> SlidingWindowResult:
    quota = _Quota(key, limit, window)
    return _parse(await redis.eval(TOKEN_BUCKET_SCRIPT, *_args((quota,))), (limit,))[0]


def check_many_sync(redis: Any, quotas) -> tuple[SlidingWindowResult, ...]:
    return _parse(redis.eval(TOKEN_BUCKET_SCRIPT, *_args(quotas)), tuple(q.rate for q in quotas))


async def check_many_async(redis: Any, quotas) -> tuple[SlidingWindowResult, ...]:
    return _parse(
        await redis.eval(TOKEN_BUCKET_SCRIPT, *_args(quotas)), tuple(q.rate for q in quotas)
    )


class _Quota:
    __slots__ = ("key", "rate", "window")

    def __init__(self, key: str, rate: int, window: int):
        self.key, self.rate, self.window = key, rate, window
