"""Regression coverage for system checks and startup configuration validation."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.core.checks import Error, Warning, run_checks
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import override_settings

from ratelimit_middleware.checks import ratelimit_settings_check
from ratelimit_middleware.conf import _valid_redis_url, get_ratelimit_settings
from ratelimit_middleware.middleware import RateLimitMiddleware


CACHE_BACKENDS = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    "dummy": {"BACKEND": "django.core.cache.backends.dummy.DummyCache"},
    "missing": {"BACKEND": "missing.module.CacheBackend"},
    "not_cache": {"BACKEND": "builtins.dict"},
    "invalid": {"BACKEND": 42},
    "bad_options": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "OPTIONS": "not-a-mapping",
    },
}


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        ({"RATELIMIT_ALGORITHM": "unknown"}, "ratelimit.E017"),
        ({"RATELIMIT_RATE": -1}, "ratelimit.E001"),
        ({"RATELIMIT_RATE": 0}, "ratelimit.E001"),
        ({"RATELIMIT_RATE": True}, "ratelimit.E001"),
        ({"RATELIMIT_WINDOW": -60}, "ratelimit.E002"),
        ({"RATELIMIT_WINDOW": "60"}, "ratelimit.E002"),
        ({"RATELIMIT_ALGORITM": "token_bucket"}, "ratelimit.E019"),
        ({"MIDDLEWARE": ["ratelimit_middleware.middleware.RatelimitMiddleware"]}, "ratelimit.E020"),
        ({"RATELIMIT_ALGORITHM": ["sliding_window"]}, "ratelimit.E017"),
        ({"RATELIMIT_ALGORITHM": None}, "ratelimit.E017"),
        ({"RATELIMIT_STORAGE": {"BACKEND": "unknown"}}, "ratelimit.E012"),
        ({"RATELIMIT_STORAGE": {"BACKEND": ["cache"]}}, "ratelimit.E012"),
        ({"RATELIMIT_STORAGE": {}}, "ratelimit.E012"),
        ({"RATELIMIT_STORAGE": "redis"}, "ratelimit.E012"),
        ({"RATELIMIT_STORAGE": {"BACKEND": "cache", "CACHE_ALIAS": "absent"}}, "ratelimit.E013"),
        ({"RATELIMIT_STORAGE": {"BACKEND": "cache", "CACHE_ALIAS": "dummy"}}, "ratelimit.E013"),
        ({"RATELIMIT_STORAGE": {"BACKEND": "cache", "CACHE_ALIAS": "missing"}}, "ratelimit.E013"),
        ({"RATELIMIT_STORAGE": {"BACKEND": "cache", "CACHE_ALIAS": "not_cache"}}, "ratelimit.E013"),
        ({"RATELIMIT_STORAGE": {"BACKEND": "cache", "CACHE_ALIAS": "invalid"}}, "ratelimit.E013"),
        (
            {"RATELIMIT_STORAGE": {"BACKEND": "cache", "CACHE_ALIAS": "bad_options"}},
            "ratelimit.E013",
        ),
        (
            {"RATELIMIT_STORAGE": {"BACKEND": "redis", "URL": "redis://localhost:bad"}},
            "ratelimit.E003",
        ),
        ({"RATELIMIT_STORAGE": {"BACKEND": "redis", "URL": "redis://"}}, "ratelimit.E003"),
        (
            {"RATELIMIT_STORAGE": {"BACKEND": "redis", "URL": "redis://localhost:0/0"}},
            "ratelimit.E003",
        ),
        (
            {"RATELIMIT_STORAGE": {"BACKEND": "redis", "URL": "redis://localhost/not-a-db"}},
            "ratelimit.E003",
        ),
        (
            {"RATELIMIT_STORAGE": {"BACKEND": "redis", "URL": "redis://localhost/0#bad"}},
            "ratelimit.E003",
        ),
        ({"RATELIMIT_REDIS_URL": "bad://localhost"}, "ratelimit.E003"),
        ({"RATELIMIT_EXEMPT_PATHS": ["health/"]}, "ratelimit.E006"),
        ({"RATELIMIT_EXEMPT_IPS": ["invalid-ip"]}, "ratelimit.E007"),
        ({"RATELIMIT_REDIS_TIMEOUT": float("nan")}, "ratelimit.E009"),
        ({"RATELIMIT_WS_MSG_RATE": True}, "ratelimit.E010"),
        ({"RATELIMIT_WS_MSG_WINDOW": 0}, "ratelimit.E010"),
        ({"RATELIMIT_ENABLE_HEADERS": "false"}, "ratelimit.E011"),
        ({"RATELIMIT_FAIL_OPEN": None}, "ratelimit.E011"),
        ({"RATELIMIT_WS_HANDSHAKE": 1}, "ratelimit.E011"),
        ({"RATELIMIT_IDENTITY": ["user"]}, "ratelimit.E014"),
        ({"RATELIMIT_IDENTITY": "wrong"}, "ratelimit.E014"),
        (
            {"RATELIMIT_IDENTITY": "custom", "RATELIMIT_IDENTITY_RESOLVER": "missing.resolver"},
            "ratelimit.E015",
        ),
        (
            {
                "RATELIMIT_POLICIES": [
                    {
                        "NAME": "bad",
                        "PATH": "/x",
                        "ALGORITHM": "missing",
                        "LIMITS": [
                            {"IDENTITY": "ip", "RATE": 2, "WINDOW": 60},
                        ],
                    },
                ]
            },
            "ratelimit.E016",
        ),
        (
            {"RATELIMIT_ALGORITHM": "token_bucket", "RATELIMIT_STORAGE": {"BACKEND": "cache"}},
            "ratelimit.E018",
        ),
    ],
)
def test_invalid_settings_report_django_checks_and_fail_at_startup(extra, expected):
    with override_settings(CACHES=CACHE_BACKENDS, **extra):
        findings = ratelimit_settings_check(None)
        assert expected in {finding.id for finding in findings if isinstance(finding, Error)}
        with pytest.raises(ImproperlyConfigured, match=expected):
            get_ratelimit_settings()
        # Misconfiguration must not be hidden behind a fail-open limiter.
        with pytest.raises(ImproperlyConfigured, match=expected):
            RateLimitMiddleware(lambda request: HttpResponse("ok"))


def test_reports_more_than_one_invalid_setting_in_single_pass():
    with override_settings(RATELIMIT_RATE=0, RATELIMIT_ALGORITHM="wrong"):
        ids = {issue.id for issue in ratelimit_settings_check(None)}
        assert {"ratelimit.E001", "ratelimit.E017"} <= ids


def test_valid_cache_backend_does_not_require_native_redis_connection():
    with override_settings(
        CACHES=CACHE_BACKENDS,
        RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": "default"},
    ):
        assert not [
            e
            for e in ratelimit_settings_check(None)
            if isinstance(e, Error) and e.id.startswith("ratelimit.E")
        ]
        assert get_ratelimit_settings().storage_backend == "cache"


def test_valid_native_redis_url_is_checked_without_connecting():
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "redis", "URL": "rediss://localhost:6380/9"}
    ):
        assert get_ratelimit_settings().storage_backend == "redis"


@pytest.mark.parametrize(
    "url",
    [
        "redis://localhost:6379/0",
        "rediss://:secret@redis.example.test:6380/15?socket_timeout=1",
        "redis://[::1]:6379/0?db=1",
        "unix:///var/run/redis/redis.sock?db=0",
    ],
)
def test_valid_redis_url_syntax(url):
    assert _valid_redis_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "redis://",
        "redis://localhost:0/0",
        "redis://localhost:65536",
        "redis://localhost/foo",
        "redis://localhost/-1",
        "redis://localhost/0#frag",
        "redis://localhost/0?db=wrong",
        "redis://localhost/0?db=1&db=2",
        "redis://localhost/0?db",
        "redis://localhost/0\n",
        "unix://",
        "unix:///",
        "unix://localhost/tmp/redis.sock",
        "ftp://localhost/0",
        "redis://localhost/0 ",
        "redis://localhost:/0",
        "redis://local host/0",
        "redis://[invalid-ipv6]/0",
    ],
)
def test_invalid_redis_url_syntax(url):
    assert not _valid_redis_url(url)


@pytest.mark.parametrize(
    "middleware",
    [
        ["ratelimit_middleware.middleware.RateLimitMiddleware"],
        [
            "ratelimit_middleware.middleware.RateLimitMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ],
    ],
)
def test_missing_session_auth_middleware_has_advisory_warning(middleware):
    with override_settings(
        RATELIMIT_IDENTITY="user",
        MIDDLEWARE=middleware,
        RATELIMIT_STORAGE={"BACKEND": "cache"},
        CACHES=CACHE_BACKENDS,
    ):
        findings = ratelimit_settings_check(None)
        assert "ratelimit.W006" in {
            finding.id for finding in findings if isinstance(finding, Warning)
        }
        # A custom upstream middleware may provide a trusted request.user.
        assert "ratelimit.E021" not in {
            finding.id for finding in findings if isinstance(finding, Error)
        }


def test_valid_user_auth_middleware_order_has_no_auth_warning():
    with override_settings(
        RATELIMIT_IDENTITY="user",
        MIDDLEWARE=[
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "ratelimit_middleware.middleware.RateLimitMiddleware",
        ],
        RATELIMIT_STORAGE={"BACKEND": "cache"},
        CACHES=CACHE_BACKENDS,
    ):
        assert "ratelimit.W006" not in {finding.id for finding in ratelimit_settings_check(None)}


def test_cache_accuracy_limitations_remain_warnings():
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "cache"},
        CACHES=CACHE_BACKENDS,
    ):
        findings = ratelimit_settings_check(None)
        warnings = {finding.id for finding in findings if isinstance(finding, Warning)}
        errors = {finding.id for finding in findings if isinstance(finding, Error)}
        assert {"ratelimit.W004", "ratelimit.W005"} <= warnings
        assert not any(code.startswith("ratelimit.E") for code in errors)


def test_invalid_config_cannot_be_bypassed_by_fail_open():
    with override_settings(
        RATELIMIT_FAIL_OPEN=True,
        RATELIMIT_RATE=-1,
        RATELIMIT_WINDOW=-60,
        RATELIMIT_IDENTITY="not-supported",
    ):
        error_ids = {
            finding.id for finding in ratelimit_settings_check(None) if isinstance(finding, Error)
        }
        assert {"ratelimit.E001", "ratelimit.E002", "ratelimit.E014"} <= error_ids
        with pytest.raises(ImproperlyConfigured) as exc_info:
            RateLimitMiddleware(lambda request: HttpResponse("ok"))
        for code in ("ratelimit.E001", "ratelimit.E002", "ratelimit.E014"):
            assert code in str(exc_info.value)


def test_invalid_settings_return_only_blocking_errors_not_advisory_warnings():
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": "dummy"},
        CACHES=CACHE_BACKENDS,
        RATELIMIT_RATE=-10,
    ):
        findings = [
            finding
            for finding in ratelimit_settings_check(None)
            if finding.id.startswith("ratelimit.")
        ]
        assert {"ratelimit.E001", "ratelimit.E013"} <= {finding.id for finding in findings}
        assert all(isinstance(finding, Error) for finding in findings)


def test_cache_import_exception_becomes_configuration_error():
    with override_settings(
        CACHES=CACHE_BACKENDS,
        RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": "missing"},
    ):
        with patch(
            "ratelimit_middleware.conf.import_string", side_effect=RuntimeError("invalid import")
        ):
            findings = ratelimit_settings_check(None)
            assert "ratelimit.E013" in {
                finding.id for finding in findings if isinstance(finding, Error)
            }
            with pytest.raises(ImproperlyConfigured, match="ratelimit.E013"):
                get_ratelimit_settings()


def test_limiter_check_is_registered_with_django():
    with override_settings(RATELIMIT_RATE=0):
        assert "ratelimit.E001" in {issue.id for issue in run_checks()}
