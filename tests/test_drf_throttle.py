"""Optional DRF throttle consumes verified DRF request.user after authentication."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("rest_framework")

from django.test import override_settings
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory, force_authenticate

from ratelimit_middleware.drf import RateLimitThrottle, _shared_storage
from ratelimit_middleware.principals import principal_key
from ratelimit_middleware.sliding_window import SlidingWindowResult


class CountingStorage:
    def __init__(self):
        self.counts = {}

    def check_sync(self, key, limit, window):
        self.counts[key] = self.counts.get(key, 0) + 1
        return SlidingWindowResult(self.counts[key] > limit, self.counts[key], window)


def make_request(principal=None):
    raw = APIRequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.21")
    if principal is not None:
        force_authenticate(raw, user=principal)
    return Request(raw)


def test_drf_authenticated_users_share_ip_but_not_quota():
    storage = CountingStorage()
    with override_settings(RATELIMIT_RATE=1):
        _shared_storage.cache_clear()
        with patch("ratelimit_middleware.drf.make_storage", return_value=storage) as factory:
            throttle = RateLimitThrottle()
            throttle2 = RateLimitThrottle()
            assert factory.call_count == 1  # don't allocate Redis pools per DRF request
            user_a = SimpleNamespace(pk="alice", is_authenticated=True)
            user_b = SimpleNamespace(pk="bob", is_authenticated=True)
            assert throttle.allow_request(make_request(user_a), None)
            assert throttle2.allow_request(make_request(user_b), None)
            assert not RateLimitThrottle().allow_request(make_request(user_a), None)
            assert principal_key("drf", "192.0.2.21", ("user", "alice")) in storage.counts
        _shared_storage.cache_clear()


def test_drf_anonymous_falls_back_to_ip():
    storage = CountingStorage()
    with override_settings(RATELIMIT_RATE=1):
        _shared_storage.cache_clear()
        with patch("ratelimit_middleware.drf.make_storage", return_value=storage):
            throttle = RateLimitThrottle()
            assert throttle.allow_request(make_request(), None)
            assert not throttle.allow_request(make_request(), None)
            assert throttle.wait() == 60
            assert list(storage.counts) == ["ratelimit:drf:192.0.2.21"]
        _shared_storage.cache_clear()


def test_drf_custom_principal_can_be_configured_without_changing_middleware_mode():
    storage = CountingStorage()

    class TenantThrottle(RateLimitThrottle):
        identity_mode = "custom"
        identity_resolver = "tests.test_drf_throttle.tenant_resolver"

    with override_settings(RATELIMIT_IDENTITY="ip", RATELIMIT_RATE=1):
        _shared_storage.cache_clear()
        with patch("ratelimit_middleware.drf.make_storage", return_value=storage):
            raw = APIRequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.21")
            request = Request(raw)
            request.verified_tenant_id = "tenant-a"
            throttle = TenantThrottle()
            assert throttle.allow_request(request, None)
            assert not throttle.allow_request(request, None)
            assert principal_key("drf", "192.0.2.21", ("tenant", "tenant-a")) in storage.counts
        _shared_storage.cache_clear()


def tenant_resolver(request):
    return ("tenant", request.verified_tenant_id)
