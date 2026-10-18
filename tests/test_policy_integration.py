"""Django, ASGI, DRF, and cache multi-quota integration regressions."""

from types import SimpleNamespace

import pytest
from django.core.cache import caches
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from ratelimit_middleware.middleware import ASGIRateLimitMiddleware, RateLimitMiddleware
from ratelimit_middleware.sliding_window import SlidingWindowResult
from ratelimit_middleware.storage import DjangoCacheStorage


RULES = [
    {
        "NAME": "auth",
        "PATH": "/api/login/",
        "METHODS": ["POST"],
        "LIMITS": [
            {"IDENTITY": "ip", "RATE": 2, "WINDOW": 60},
            {"IDENTITY": "user", "RATE": 3, "WINDOW": 60},
        ],
    },
]


class FakeStorage:
    def __init__(self):
        self.counters = {}
        self.group_calls = 0

    def check_sync(self, key, limit, window):
        count = self.counters.get(key, 0)
        if count < limit:
            self.counters[key] = count + 1
            return SlidingWindowResult(False, count + 1, window)
        return SlidingWindowResult(True, count, window)

    async def check_async(self, key, limit, window):
        return self.check_sync(key, limit, window)

    def check_many_sync(self, quotas):
        self.group_calls += 1
        blocked = any(self.counters.get(q.key, 0) >= q.rate for q in quotas)
        results = []
        for q in quotas:
            count = self.counters.get(q.key, 0)
            if not blocked:
                count += 1
                self.counters[q.key] = count
            results.append(SlidingWindowResult(blocked and count >= q.rate, count, q.window))
        return tuple(results)

    async def check_many_async(self, quotas):
        return self.check_many_sync(quotas)


def request(path="/api/login/", method="post", user_id=1):
    req = getattr(RequestFactory(), method)(path, REMOTE_ADDR="192.0.2.42")
    req.user = SimpleNamespace(pk=user_id, is_authenticated=True)
    return req


def test_django_combined_quotas_and_global_default():
    with override_settings(RATELIMIT_POLICIES=RULES, RATELIMIT_RATE=1):
        middleware = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        storage = middleware._storage = FakeStorage()
        req = request()
        assert middleware(req).status_code == 200
        assert middleware(req).status_code == 200
        response = middleware(req)
        assert response.status_code == 429
        assert response["X-RateLimit-Limit"] == "2"
        assert storage.group_calls == 3
        # GET on the same URL does not match the POST policy.
        assert middleware(request(method="get")).status_code == 200
        assert middleware(request(method="get")).status_code == 429


def test_group_denial_does_not_spend_available_user_quota():
    with override_settings(RATELIMIT_POLICIES=RULES):
        middleware = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        storage = middleware._storage = FakeStorage()
        user_a, user_b = request(user_id=1), request(user_id=2)
        middleware(user_a)
        middleware(user_a)
        before = dict(storage.counters)
        assert middleware(user_b).status_code == 429  # IP quota exhausted
        assert before == storage.counters


@pytest.mark.asyncio
async def test_async_django_policy_combined_limits():
    async def downstream(req):
        return HttpResponse("ok")

    with override_settings(RATELIMIT_POLICIES=RULES):
        middleware = RateLimitMiddleware(downstream)
        storage = middleware._storage = FakeStorage()
        req = request()
        assert (await middleware(req)).status_code == 200
        assert (await middleware(req)).status_code == 200
        assert (await middleware(req)).status_code == 429
        assert storage.group_calls == 3


@pytest.mark.asyncio
async def test_asgi_policy_uses_one_group_admission():
    sent = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(msg):
        sent.append(msg)

    with override_settings(RATELIMIT_POLICIES=RULES):
        middleware = ASGIRateLimitMiddleware(app)
        middleware._storage = FakeStorage()
        scope = {
            "type": "http",
            "path": "/api/login/",
            "method": "POST",
            "client": ("192.0.2.42", 1234),
            "headers": [],
            "user": SimpleNamespace(pk=11, is_authenticated=True),
        }
        for _ in range(3):
            await middleware(scope, receive, send)
        assert [m["status"] for m in sent if m["type"] == "http.response.start"] == [200, 200, 429]
        assert middleware._storage.group_calls == 3


def test_drf_adapter_selects_http_policy_after_authentication():
    pytest.importorskip("rest_framework")
    from ratelimit_middleware.drf import RateLimitThrottle

    with override_settings(RATELIMIT_POLICIES=RULES):
        throttle = RateLimitThrottle()
        storage = throttle._storage = FakeStorage()
        req = request()
        assert throttle.allow_request(req, object())
        assert throttle.allow_request(req, object())
        assert not throttle.allow_request(req, object())
        assert storage.group_calls == 3


def test_cache_group_warns_and_preserves_non_atomic_behavior():
    settings = {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
        "ratelimit": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "cp5-ratelimit",
        },
    }
    from django.core.checks import run_checks

    with override_settings(
        CACHES=settings,
        RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": "ratelimit"},
        RATELIMIT_POLICIES=RULES,
    ):
        assert "ratelimit.W007" in {w.id for w in run_checks()}
        backend = DjangoCacheStorage("ratelimit")
        result = backend.check_many_sync(
            (
                SimpleNamespace(key="cache-quota-1", rate=10, window=60),
                SimpleNamespace(key="cache-quota-2", rate=1, window=60),
            )
        )
        assert len(result) == 2 and all(not x.limited for x in result)
        assert backend.check_many_sync(
            (
                SimpleNamespace(key="cache-quota-1", rate=10, window=60),
                SimpleNamespace(key="cache-quota-2", rate=1, window=60),
            )
        )[-1].limited
        # The first cache quota is charged despite rejection by the second.
        assert caches["ratelimit"].get("cache-quota-1") == 2
