"""Configuration, storage selection and Django middleware token-bucket tests."""

import pytest

pytest.importorskip("django")
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from ratelimit_middleware.conf import config_errors, get_ratelimit_settings
from ratelimit_middleware.middleware import RateLimitMiddleware
from ratelimit_middleware.sliding_window import SlidingWindowResult
from ratelimit_middleware.storage import RedisStorage


def test_cache_backend_rejects_global_and_policy_token_bucket():
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "cache"}, RATELIMIT_ALGORITHM="token_bucket"
    ):
        assert "ratelimit.E018" in {code for code, _ in config_errors()}
        with pytest.raises(ImproperlyConfigured):
            get_ratelimit_settings()
    rules = [
        {
            "NAME": "api",
            "PATH": "/api/",
            "ALGORITHM": "token_bucket",
            "LIMITS": [
                {"IDENTITY": "ip", "RATE": 10, "WINDOW": 60},
            ],
        }
    ]
    with override_settings(RATELIMIT_STORAGE={"BACKEND": "cache"}, RATELIMIT_POLICIES=rules):
        assert "ratelimit.E018" in {code for code, _ in config_errors()}


def test_global_token_bucket_selects_redis_storage_algorithm():
    with override_settings(RATELIMIT_ALGORITHM="token_bucket"):
        middleware = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        assert isinstance(middleware._storage, RedisStorage)
        assert middleware._storage.algorithm == "token_bucket"


def test_token_policy_selects_redis_override_and_default_remains_sliding():
    rules = [
        {
            "NAME": "api",
            "PATH": "/api/",
            "ALGORITHM": "token_bucket",
            "LIMITS": [
                {"IDENTITY": "ip", "RATE": 10, "WINDOW": 60},
            ],
        }
    ]
    with override_settings(RATELIMIT_POLICIES=rules):
        middleware = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        calls = []

        class Storage:
            algorithm = "sliding_window"

            def check_sync(self, key, rate, window, *, algorithm=None):
                calls.append(algorithm)
                return SlidingWindowResult(False, 1, window)

        middleware._storage = Storage()
        assert middleware(RequestFactory().get("/api/")).status_code == 200
        assert middleware(RequestFactory().get("/else/")).status_code == 200
        assert calls == ["token_bucket", None]


def test_explicit_policy_overrides_global_token_bucket():
    rules = [
        {
            "NAME": "strict",
            "PATH": "/strict/",
            "LIMITS": [
                {"IDENTITY": "ip", "RATE": 10, "WINDOW": 60},
            ],
        }
    ]
    with override_settings(RATELIMIT_ALGORITHM="token_bucket", RATELIMIT_POLICIES=rules):
        middleware = RateLimitMiddleware(lambda req: HttpResponse("ok"))
        calls = []

        class Storage:
            algorithm = "token_bucket"

            def check_sync(self, key, rate, window, *, algorithm=None):
                calls.append(algorithm)
                return SlidingWindowResult(False, 1, window)

        middleware._storage = Storage()
        assert middleware(RequestFactory().get("/strict/")).status_code == 200
        assert calls == ["sliding_window"]
