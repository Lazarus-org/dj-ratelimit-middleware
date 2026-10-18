"""Django, ASGI and config checks for opt-in principal modes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from django.core.checks import run_checks
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.utils.functional import SimpleLazyObject
from django.test import RequestFactory, override_settings

from ratelimit_middleware.conf import get_ratelimit_settings
from ratelimit_middleware.middleware import ASGIRateLimitMiddleware, RateLimitMiddleware
from ratelimit_middleware.principals import principal_key
from ratelimit_middleware.sliding_window import SlidingWindowResult


class CountingStorage:
    def __init__(self):
        self.counts = {}

    def check_sync(self, key, limit, window):
        self.counts[key] = self.counts.get(key, 0) + 1
        return SlidingWindowResult(self.counts[key] > limit, self.counts[key], window)

    async def check_async(self, key, limit, window):
        return self.check_sync(key, limit, window)


def user(pk, authenticated=True):
    return SimpleNamespace(pk=pk, is_authenticated=authenticated)


def test_django_users_sharing_ip_get_separate_buckets():
    with override_settings(RATELIMIT_IDENTITY="user", RATELIMIT_RATE=1):
        mw = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        mw._storage = CountingStorage()
        a = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.1")
        b = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.1")
        a.user, b.user = user(101), user(102)
        assert mw(a).status_code == 200
        assert mw(b).status_code == 200
        assert mw(a).status_code == 429
        assert set(mw._storage.counts) == {
            principal_key("http", "192.0.2.1", ("user", "101")),
            principal_key("http", "192.0.2.1", ("user", "102")),
        }


def test_django_anonymous_falls_back_to_ip_and_is_limited():
    with override_settings(RATELIMIT_IDENTITY="user", RATELIMIT_RATE=1):
        mw = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        mw._storage = CountingStorage()
        req = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.10")
        req.user = user(None, False)
        assert mw(req).status_code == 200
        assert mw(req).status_code == 429
        assert list(mw._storage.counts) == ["ratelimit:http:192.0.2.10"]


def test_default_ip_mode_never_accesses_lazy_user():
    with override_settings(RATELIMIT_IDENTITY="ip"):
        mw = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        mw._storage = CountingStorage()
        req = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.11")

        class LazyExplosive:
            @property
            def is_authenticated(self):
                raise AssertionError("Unexpected lazy authentication")

        req.user = LazyExplosive()
        assert mw(req).status_code == 200


@pytest.mark.asyncio
async def test_django_async_uses_async_auth_not_sync_lazy_user():
    async def downstream(req):
        return HttpResponse("ok")

    with override_settings(RATELIMIT_IDENTITY="user", RATELIMIT_RATE=1):
        mw = RateLimitMiddleware(downstream)
        mw._storage = CountingStorage()
        req = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.13")

        def raise_if_evaluated():
            raise AssertionError("Accessed sync lazy auth from async path")

        req.user = SimpleLazyObject(raise_if_evaluated)

        async def auser():
            return user(22)

        req.auser = auser
        assert (await mw(req)).status_code == 200
        assert (await mw(req)).status_code == 429


@pytest.mark.asyncio
async def test_asgi_authenticated_and_anonymous_ip_fallback():
    messages = []

    async def downstream(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request"}

    async def send(message):
        messages.append(message)

    with override_settings(RATELIMIT_IDENTITY="user", RATELIMIT_RATE=1):
        mw = ASGIRateLimitMiddleware(downstream)
        mw._storage = CountingStorage()
        scope = {"type": "http", "path": "/", "client": ("192.0.2.16", 500), "headers": []}
        await mw({**scope, "user": user(1)}, receive, send)
        await mw({**scope, "user": user(2)}, receive, send)
        await mw({**scope, "user": user(1)}, receive, send)
        await mw(scope, receive, send)
        await mw(scope, receive, send)
        assert [m["status"] for m in messages if m["type"] == "http.response.start"] == [
            200,
            200,
            429,
            200,
            429,
        ]


def custom_resolver(context):
    return ("tenant", context.tenant_id) if getattr(context, "tenant_id", None) else None


def test_django_custom_mode_uses_verified_principal_and_ip_fallback():
    with override_settings(
        RATELIMIT_IDENTITY="custom",
        RATELIMIT_IDENTITY_RESOLVER="tests.test_identity_integration.custom_resolver",
        RATELIMIT_RATE=1,
    ):
        mw = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        mw._storage = CountingStorage()
        req = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.17")
        req.tenant_id = "tenant-a"
        assert mw(req).status_code == 200
        assert mw(req).status_code == 429
        req.tenant_id = None
        assert mw(req).status_code == 200


@pytest.mark.parametrize(
    "kwargs",
    [
        {"RATELIMIT_IDENTITY": "account"},
        {"RATELIMIT_IDENTITY": "custom"},
        {
            "RATELIMIT_IDENTITY": "ip",
            "RATELIMIT_IDENTITY_RESOLVER": "tests.test_identity_integration.custom_resolver",
        },
        {"RATELIMIT_IDENTITY": "custom", "RATELIMIT_IDENTITY_RESOLVER": "nonexistent.module.fn"},
    ],
)
def test_identity_misconfigurations_rejected(kwargs):
    with override_settings(**kwargs):
        with pytest.raises(ImproperlyConfigured):
            get_ratelimit_settings()


def test_missing_session_auth_warns_in_user_mode():
    with override_settings(RATELIMIT_IDENTITY="user"):
        assert "ratelimit.W006" in {item.id for item in run_checks()}


def test_ip_mode_uses_consistent_ip_keys():
    with override_settings(RATELIMIT_IDENTITY="ip"):
        mw = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        req = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.18")
        assert mw.key_for_request(req) == "ratelimit:http:192.0.2.18"


@pytest.mark.asyncio
async def test_async_django_prefers_verified_upstream_user_over_session_user():
    async def downstream(req):
        return HttpResponse("ok")

    with override_settings(RATELIMIT_IDENTITY="user", RATELIMIT_RATE=1):
        mw = RateLimitMiddleware(downstream)
        mw._storage = CountingStorage()
        req = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.27")
        req.user = user(91)

        async def invalid_session_lookup():
            raise AssertionError("Should not run Django session authentication again")

        req.auser = invalid_session_lookup
        assert (await mw(req)).status_code == 200
        assert (await mw(req)).status_code == 429
