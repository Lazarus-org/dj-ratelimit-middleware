"""Storage adapters for rate-limit admission.

Redis provides an exact atomic sliding window. The portable Django-cache
adapter uses an approximate, first-request-anchored counter window: backends
may differ in atomicity, eviction, and async implementation. Do not describe
cache admission as an atomic security boundary.
"""

from __future__ import annotations

from typing import Protocol

from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured

from .constants import ALGORITHM_SLIDING_WINDOW, ALGORITHM_TOKEN_BUCKET, STORAGE_CACHE
from . import token_bucket
from .sliding_window import (
    SlidingWindowResult,
    check_async,
    check_sync,
    check_many_sync as redis_many_sync,
    check_many_async as redis_many_async,
)


class StorageError(Exception):
    """An operation against the configured storage backend failed."""


class RateLimitStorage(Protocol):
    """Small admission interface independent of Django/ASGI request objects."""

    def check_sync(self, key: str, limit: int, window: int) -> SlidingWindowResult: ...

    async def check_async(self, key: str, limit: int, window: int) -> SlidingWindowResult: ...

    def check_many_sync(self, quotas) -> tuple[SlidingWindowResult, ...]: ...

    async def check_many_async(self, quotas) -> tuple[SlidingWindowResult, ...]: ...


class RedisStorage:
    """One Redis Lua call per admission, with lazily reused client pools."""

    def __init__(self, url: str, timeout: float, algorithm: str = ALGORITHM_SLIDING_WINDOW):
        try:
            from redis.connection import parse_url
        except ImportError as exc:
            raise ImproperlyConfigured(
                "Native Redis storage requires dj-ratelimit-middleware[redis]."
            ) from exc
        try:
            parse_url(url)
        except (ValueError, TypeError):
            raise ImproperlyConfigured("Native Redis URL has invalid connection options.") from None
        self.algorithm = algorithm
        self.url = url
        self.timeout = timeout
        self._sync_client = None
        self._async_client = None

    def _get_sync_redis(self):
        if self._sync_client is None:
            try:
                from redis import Redis
            except ImportError as exc:
                raise ImproperlyConfigured(
                    "Native Redis storage requires dj-ratelimit-middleware[redis]."
                ) from exc
            self._sync_client = Redis.from_url(
                self.url,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True,
                protocol=2,  # Keep Redis 5 compatibility when newer clients default to RESP3.
            )
        return self._sync_client

    def _get_async_redis(self):
        if self._async_client is None:
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise ImproperlyConfigured(
                    "Native Redis storage requires dj-ratelimit-middleware[redis]."
                ) from exc
            self._async_client = Redis.from_url(
                self.url,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True,
                protocol=2,  # Keep Redis 5 compatibility when newer clients default to RESP3.
            )
        return self._async_client

    def check_sync(
        self, key: str, limit: int, window: int, *, algorithm: str | None = None
    ) -> SlidingWindowResult:
        try:
            from redis.exceptions import AskError, RedisError
        except ImportError as exc:
            raise ImproperlyConfigured(
                "Native Redis storage requires dj-ratelimit-middleware[redis]."
            ) from exc
        try:
            return (
                token_bucket.check_sync
                if (algorithm or self.algorithm) == ALGORITHM_TOKEN_BUCKET
                else check_sync
            )(self._get_sync_redis(), key, limit, window)
        except AskError:
            raise ImproperlyConfigured(
                "Native Redis cannot route Redis Cluster redirections."
            ) from None
        except RedisError as exc:
            raise StorageError("Native Redis rate-limit operation failed") from exc

    async def check_async(
        self, key: str, limit: int, window: int, *, algorithm: str | None = None
    ) -> SlidingWindowResult:
        try:
            from redis.exceptions import AskError, RedisError
        except ImportError as exc:
            raise ImproperlyConfigured(
                "Native Redis storage requires dj-ratelimit-middleware[redis]."
            ) from exc
        try:
            return await (
                token_bucket.check_async
                if (algorithm or self.algorithm) == ALGORITHM_TOKEN_BUCKET
                else check_async
            )(self._get_async_redis(), key, limit, window)
        except AskError:
            raise ImproperlyConfigured(
                "Native Redis cannot route Redis Cluster redirections."
            ) from None
        except RedisError as exc:
            raise StorageError("Native Redis rate-limit operation failed") from exc

    def check_many_sync(self, quotas) -> tuple[SlidingWindowResult, ...]:
        """Atomic multi-key admission on standalone Redis; Cluster slots must match."""
        try:
            from redis.exceptions import AskError, ClusterCrossSlotError, RedisError
        except ImportError as exc:
            raise ImproperlyConfigured("Native Redis storage requires the redis extra") from exc
        try:
            return (
                token_bucket.check_many_sync
                if quotas[0].algorithm == ALGORITHM_TOKEN_BUCKET
                else redis_many_sync
            )(self._get_sync_redis(), quotas)
        except (AskError, ClusterCrossSlotError):
            raise ImproperlyConfigured(
                "Native Redis does not support Cluster redirections or cross-slot quota groups."
            ) from None
        except RedisError as exc:
            raise StorageError("Native Redis grouped rate-limit operation failed") from exc

    async def check_many_async(self, quotas) -> tuple[SlidingWindowResult, ...]:
        try:
            from redis.exceptions import AskError, ClusterCrossSlotError, RedisError
        except ImportError as exc:
            raise ImproperlyConfigured("Native Redis storage requires the redis extra") from exc
        try:
            return await (
                token_bucket.check_many_async
                if quotas[0].algorithm == ALGORITHM_TOKEN_BUCKET
                else redis_many_async
            )(self._get_async_redis(), quotas)
        except (AskError, ClusterCrossSlotError):
            raise ImproperlyConfigured(
                "Native Redis does not support Cluster redirections or cross-slot quota groups."
            ) from None
        except RedisError as exc:
            raise StorageError("Native Redis grouped rate-limit operation failed") from exc


class DjangoCacheStorage:
    """Portable counter-based window, not an exact atomic sliding window.

    The first admission anchors a fixed TTL. Rejects can increase the counter
    but never extend that TTL. Redis and Memcached backends generally support
    atomic increments; other backends may not. Expired/evicted entries may
    restart a window. Reset times are only upper-bound estimates because the
    cache API does not provide portable TTL inspection.
    """

    def __init__(self, alias: str):
        self.alias = alias

    def check_sync(self, key: str, limit: int, window: int) -> SlidingWindowResult:
        try:
            # Django caches are thread-local; don't retain a cache instance
            # captured in the middleware initialization thread.
            cache = caches[self.alias]
            if cache.add(key, 1, timeout=window):
                count = 1
            else:
                try:
                    count = cache.incr(key)
                except ValueError:
                    # Expiry between add() and incr(): retry once. An eviction
                    # during this sequence must never silently allow a miss.
                    if cache.add(key, 1, timeout=window):
                        count = 1
                    else:
                        count = cache.incr(key)
            return SlidingWindowResult(limited=count > limit, count=int(count), reset_after=window)
        except ImproperlyConfigured:
            raise
        except Exception as exc:
            raise StorageError("Django cache rate-limit operation failed") from exc

    async def check_async(self, key: str, limit: int, window: int) -> SlidingWindowResult:
        try:
            cache = caches[self.alias]
            if await cache.aadd(key, 1, timeout=window):
                count = 1
            else:
                try:
                    count = await cache.aincr(key)
                except ValueError:
                    if await cache.aadd(key, 1, timeout=window):
                        count = 1
                    else:
                        count = await cache.aincr(key)
            return SlidingWindowResult(limited=count > limit, count=int(count), reset_after=window)
        except ImproperlyConfigured:
            raise
        except Exception as exc:
            raise StorageError("Django cache rate-limit operation failed") from exc

    def check_many_sync(self, quotas) -> tuple[SlidingWindowResult, ...]:
        """Non-atomic cache fallback: earlier quotas can be charged on denial."""
        results = []
        for q in quotas:
            result = self.check_sync(q.key, q.rate, q.window)
            results.append(result)
            if result.limited:
                break
        return tuple(results)

    async def check_many_async(self, quotas) -> tuple[SlidingWindowResult, ...]:
        results = []
        for q in quotas:
            result = await self.check_async(q.key, q.rate, q.window)
            results.append(result)
            if result.limited:
                break
        return tuple(results)


def make_storage(cfg) -> RateLimitStorage:
    """Create the configured adapter once per middleware instance."""
    if cfg.storage_backend == STORAGE_CACHE:
        return DjangoCacheStorage(cfg.cache_alias)
    return RedisStorage(
        cfg.redis_url, cfg.redis_timeout, getattr(cfg, "algorithm", ALGORITHM_SLIDING_WINDOW)
    )
