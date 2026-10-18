"""Boundary values and valid alternatives for startup configuration."""

import builtins
from unittest.mock import patch

import pytest
from django.core.cache.backends.base import BaseCache, default_key_func
from django.test import override_settings

from ratelimit_middleware import conf
from ratelimit_middleware.checks import ratelimit_settings_check
from ratelimit_middleware.constants import (
    DJANGO_MIDDLEWARE_PATH,
    DJANGO_REDIS_CACHE_BACKEND,
    MAX_TOKEN_BUCKET_RATE,
    MAX_TOKEN_BUCKET_WINDOW,
)


def test_url_structure_validation_works_without_optional_redis(monkeypatch):
    original_import = builtins.__import__

    def missing_extra(name, *args, **kwargs):
        if name == "redis.connection":
            raise ImportError("not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_extra)
    assert conf._valid_redis_url("redis://localhost/15?db=1")
    assert not conf._valid_redis_url("redis://localhost/15?db=-1")


@pytest.mark.parametrize(
    "key_function,valid",
    [
        (default_key_func, True),
        ("django.core.cache.backends.base.default_key_func", True),
        (42, False),
        ("tests.settings.SECRET_KEY", False),
    ],
)
def test_cache_key_functions_must_resolve_to_callables(key_function, valid):
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "cache"},
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "KEY_FUNCTION": key_function,
            }
        },
    ):
        errors = conf.config_errors()
    assert (not errors) == valid
    if not valid:
        assert any(code == "ratelimit.E013" and "KEY_FUNCTION" in msg for code, msg in errors)


@pytest.mark.parametrize("alias", [None, "", " default "])
def test_cache_alias_must_be_a_nonempty_unpadded_string(alias):
    with override_settings(RATELIMIT_STORAGE={"BACKEND": "cache", "CACHE_ALIAS": alias}):
        assert any(code == "ratelimit.E012" for code, _ in conf.config_errors())


@pytest.mark.parametrize(
    "storage",
    [
        {"BACKEND": "cache", "URL": "redis://localhost/0"},
        {"BACKEND": "cache", "CACHE_ALIAS": "missing"},
        {"BACKEND": "redis", "CACHE_ALIAS": "missing"},
    ],
)
def test_invalid_cache_storage_source_is_blocking(storage):
    with override_settings(RATELIMIT_STORAGE=storage):
        assert conf.config_errors()


@pytest.mark.parametrize("ignore", [False, True])
def test_django_redis_global_exception_suppression_is_checked(ignore):
    original_import = conf.import_string

    def backend_import(path):
        return BaseCache if path == DJANGO_REDIS_CACHE_BACKEND else original_import(path)

    with (
        override_settings(
            RATELIMIT_STORAGE={"BACKEND": "cache"},
            CACHES={"default": {"BACKEND": DJANGO_REDIS_CACHE_BACKEND}},
            DJANGO_REDIS_IGNORE_EXCEPTIONS=ignore,
        ),
        patch.object(conf, "import_string", side_effect=backend_import),
    ):
        errors = conf.config_errors()
    assert bool(errors) == ignore
    if ignore:
        assert any("must not suppress" in msg for _, msg in errors)


@pytest.mark.parametrize(
    "setting,value",
    [
        ("RATELIMIT_RATE", MAX_TOKEN_BUCKET_RATE + 1),
        ("RATELIMIT_WINDOW", MAX_TOKEN_BUCKET_WINDOW + 1),
    ],
)
def test_global_token_bucket_numeric_bounds(setting, value):
    with override_settings(RATELIMIT_ALGORITHM="token_bucket", **{setting: value}):
        assert ("ratelimit.E017", "Token bucket RATE/WINDOW exceed safe numeric bounds.") in (
            conf.config_errors()
        )


async def async_resolver(context):
    return ("tenant", "verified")


class AsyncResolver:
    async def __call__(self, context):
        return ("tenant", "verified")


async_callable = AsyncResolver()


@pytest.mark.parametrize("name", ["async_resolver", "async_callable", "AsyncResolver", "conf"])
def test_custom_resolver_must_be_a_synchronous_function_or_callable(name):
    # Classes are callable, but this class constructs an async callable. The
    # configured resolver itself must not advertise an async __call__ method.
    with override_settings(
        RATELIMIT_IDENTITY="custom",
        RATELIMIT_IDENTITY_RESOLVER=f"{__name__}.{name}",
    ):
        assert any(code == "ratelimit.E015" for code, _ in conf.config_errors())


def test_unused_proxy_configuration_and_uninstalled_middleware_are_advisory():
    with override_settings(
        RATELIMIT_TRUSTED_PROXIES=("192.0.2.1",),
        MIDDLEWARE=["django.middleware.common.CommonMiddleware"],
    ):
        assert {issue.id for issue in ratelimit_settings_check(None)} == {
            "ratelimit.W002",
            "ratelimit.W003",
        }


def test_shared_cache_has_approximation_warning_without_process_local_warning():
    with override_settings(
        RATELIMIT_STORAGE={"BACKEND": "cache"},
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.redis.RedisCache",
                "LOCATION": "redis://localhost/15",
            }
        },
    ):
        assert {issue.id for issue in ratelimit_settings_check(None)} == {"ratelimit.W005"}


def test_native_multi_quota_policy_warns_about_cluster_slots():
    with override_settings(
        RATELIMIT_POLICIES=[
            {
                "NAME": "group",
                "PATH": "/api/",
                "LIMITS": [{"IDENTITY": "ip", "RATE": 2, "WINDOW": 60}] * 2,
            }
        ]
    ):
        assert {issue.id for issue in ratelimit_settings_check(None)} == {"ratelimit.W008"}


def test_user_middleware_without_authentication_warns():
    with override_settings(RATELIMIT_IDENTITY="user", MIDDLEWARE=[DJANGO_MIDDLEWARE_PATH]):
        assert {issue.id for issue in ratelimit_settings_check(None)} == {"ratelimit.W006"}


def test_nonsequence_middleware_setting_does_not_crash_package_checks():
    with override_settings(MIDDLEWARE=None):
        assert ratelimit_settings_check(None) == []


def test_invalid_policies_return_blocking_errors_before_advisory_checks():
    with (
        override_settings(RATELIMIT_POLICIES=[{"NAME": "missing-limits"}]),
        patch("ratelimit_middleware.checks.compile_policies") as advisory_compile,
    ):
        assert {issue.id for issue in ratelimit_settings_check(None)} == {"ratelimit.E016"}
        advisory_compile.assert_not_called()
