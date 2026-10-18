"""Explicit, isolated Redis smoke/benchmark for the admission engines.

Do NOT run against Lifeguard or another shared/production Redis. Every run
uses a unique key prefix and deletes only the keys it created.

Example:
  uv run python scripts/benchmark_ratelimit.py \
    --redis-url redis://127.0.0.1:6379/15 --confirm-test-redis

The results are observations, not a performance promise. Collect server CPU,
latency and memory separately under representative production workloads.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from statistics import mean
from time import perf_counter_ns
from uuid import uuid4


@dataclass(frozen=True)
class Quota:
    key: str
    rate: int
    window: int
    algorithm: str


def percentile(values: list[float], pct: float) -> float:
    values = sorted(values)
    if not values:
        return 0.0
    index = max(0, math.ceil(len(values) * pct / 100) - 1)
    return values[index]


def aggregate(samples: list[tuple[float, bool]], elapsed: float, memory_bytes: int | None):
    delays = [latency for latency, _ in samples]
    return {
        "requests": len(samples),
        "admitted": sum(allowed for _, allowed in samples),
        "rejected": sum(not allowed for _, allowed in samples),
        "wall_seconds": round(elapsed, 3),
        "requests_per_second": round(len(samples) / elapsed, 1),
        "latency_ms": {
            "mean": round(mean(delays), 3),
            "p50": round(percentile(delays, 50), 3),
            "p95": round(percentile(delays, 95), 3),
            "p99": round(percentile(delays, 99), 3),
        },
        "redis_key_memory_bytes": memory_bytes,
    }


def run_sync(redis_url, *, requests, workers, identities, group_size, algorithm, rate, window):
    from redis import Redis
    from ratelimit_middleware.sliding_window import check_many_sync as slide_many
    from ratelimit_middleware.sliding_window import check_sync as slide_single
    from ratelimit_middleware.token_bucket import check_many_sync as bucket_many
    from ratelimit_middleware.token_bucket import check_sync as bucket_single
    from ratelimit_middleware.token_bucket import bucket_key

    prefix = f"ratelimit:bench:{uuid4().hex}"
    keys = [f"{prefix}:{i}:{j}" for i in range(identities) for j in range(group_size)]
    actual = [bucket_key(key) if algorithm == "token_bucket" else key for key in keys]
    client = Redis.from_url(redis_url, decode_responses=True, socket_timeout=2)

    def request(i):
        identity = i % identities
        qs = [
            Quota(keys[identity * group_size + j], rate, window, algorithm)
            for j in range(group_size)
        ]
        start = perf_counter_ns()
        if group_size == 1:
            result = (bucket_single if algorithm == "token_bucket" else slide_single)(
                client, qs[0].key, rate, window
            )
            allowed = not result.limited
        else:
            result = (bucket_many if algorithm == "token_bucket" else slide_many)(client, tuple(qs))
            allowed = not any(item.limited for item in result)
        return (perf_counter_ns() - start) / 1e6, allowed

    try:
        beginning = perf_counter_ns()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            samples = list(pool.map(request, range(requests)))
        elapsed = (perf_counter_ns() - beginning) / 1e9
        sizes = [client.memory_usage(key) or 0 for key in actual]
        return aggregate(samples, elapsed, sum(sizes))
    finally:
        # Never use FLUSHDB or a keyspace scan. Delete only this run's exact keys.
        for start in range(0, len(actual), 500):
            client.delete(*actual[start : start + 500])
        client.close()


async def run_async(
    redis_url, *, requests, workers, identities, group_size, algorithm, rate, window
):
    from redis.asyncio import Redis
    from ratelimit_middleware.sliding_window import check_many_async as slide_many
    from ratelimit_middleware.sliding_window import check_async as slide_single
    from ratelimit_middleware.token_bucket import check_many_async as bucket_many
    from ratelimit_middleware.token_bucket import check_async as bucket_single
    from ratelimit_middleware.token_bucket import bucket_key

    prefix = f"ratelimit:bench:{uuid4().hex}"
    keys = [f"{prefix}:{i}:{j}" for i in range(identities) for j in range(group_size)]
    actual = [bucket_key(key) if algorithm == "token_bucket" else key for key in keys]
    client = Redis.from_url(redis_url, decode_responses=True, socket_timeout=2)
    gate = asyncio.Semaphore(workers)

    async def request(i):
        async with gate:
            identity = i % identities
            qs = [
                Quota(keys[identity * group_size + j], rate, window, algorithm)
                for j in range(group_size)
            ]
            start = perf_counter_ns()
            if group_size == 1:
                result = await (bucket_single if algorithm == "token_bucket" else slide_single)(
                    client, qs[0].key, rate, window
                )
                allowed = not result.limited
            else:
                result = await (bucket_many if algorithm == "token_bucket" else slide_many)(
                    client, tuple(qs)
                )
                allowed = not any(item.limited for item in result)
            return (perf_counter_ns() - start) / 1e6, allowed

    try:
        beginning = perf_counter_ns()
        samples = await asyncio.gather(*(request(i) for i in range(requests)))
        elapsed = (perf_counter_ns() - beginning) / 1e9
        sizes = [await client.memory_usage(key) or 0 for key in actual]
        return aggregate(samples, elapsed, sum(sizes))
    finally:
        for start in range(0, len(actual), 500):
            await client.delete(*actual[start : start + 500])
        closer = getattr(client, "aclose", None) or client.close
        await closer()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--redis-url", required=True, help="Isolated test Redis URL")
    parser.add_argument(
        "--confirm-test-redis", action="store_true", help="Explicitly confirm test-only Redis"
    )
    parser.add_argument("--mode", choices=("sync", "async"), default="sync")
    parser.add_argument(
        "--algorithm", choices=("sliding_window", "token_bucket"), default="token_bucket"
    )
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--identities", type=int, default=100)
    parser.add_argument("--group-size", type=int, choices=(1, 2), default=1)
    parser.add_argument("--rate", type=int, default=100)
    parser.add_argument("--window", type=int, default=60)
    args = parser.parse_args()
    if not args.confirm_test_redis:
        parser.error("Do not run without explicitly confirming an isolated test Redis")
    if min(args.requests, args.workers, args.identities, args.rate, args.window) <= 0:
        parser.error("Request count, concurrency, identities, rate, window must be positive")
    if args.algorithm == "token_bucket" and (args.rate > 1_000_000_000 or args.window > 31_536_000):
        parser.error("Token bucket RATE/WINDOW exceed safe numeric bounds")
    if args.requests > 200_000 or args.identities > 20_000 or args.workers > 500:
        parser.error("Requested load exceeds the benchmark's safety bounds")
    kwargs = vars(args).copy()
    for name in ("mode", "confirm_test_redis", "redis_url"):
        kwargs.pop(name)
    if args.mode == "sync":
        result = run_sync(args.redis_url, **kwargs)
    else:
        result = asyncio.run(run_async(args.redis_url, **kwargs))
    print(json.dumps({"mode": args.mode, "algorithm": args.algorithm, **result}, indent=2))


if __name__ == "__main__":
    main()
