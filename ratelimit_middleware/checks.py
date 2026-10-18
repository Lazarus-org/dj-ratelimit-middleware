"""Django system checks for rate-limiting configuration."""

from __future__ import annotations

from collections.abc import Mapping

from django.conf import settings
from django.core.checks import Error, Warning, register

from .constants import (
    DJANGO_AUTH_MIDDLEWARE_PATH,
    DJANGO_MIDDLEWARE_PATH,
    IDENTITY_IP,
    IDENTITY_USER,
    NON_DISTRIBUTED_CACHE_BACKENDS,
    STORAGE_CACHE,
    STORAGE_REDIS,
)
from .conf import config_errors
from .policies import PolicyConfigurationError, compile_policies


@register()
def ratelimit_settings_check(app_configs, **kwargs):
    errors = config_errors()
    findings = [Error(message, id=code) for code, message in errors]
    # Advisory warnings only make sense for a valid configuration. An invalid
    # configuration must produce a clear blocking check, not mixed signals.
    if errors:
        return findings

    storage = getattr(settings, "RATELIMIT_STORAGE", None)
    backend = storage.get("BACKEND") if isinstance(storage, Mapping) else STORAGE_REDIS
    if getattr(settings, "RATELIMIT_TRUSTED_PROXIES", ()) and not getattr(
        settings, "RATELIMIT_TRUST_X_FORWARDED_FOR", False
    ):
        findings.append(
            Warning(
                "RATELIMIT_TRUSTED_PROXIES has no effect unless RATELIMIT_TRUST_X_FORWARDED_FOR is True.",
                id="ratelimit.W002",
            )
        )

    if backend == STORAGE_CACHE:
        alias = storage.get("CACHE_ALIAS", "default")
        configured_caches = getattr(settings, "CACHES", {})
        details = (
            configured_caches.get(alias, {})
            if isinstance(configured_caches, Mapping) and isinstance(alias, str)
            else {}
        )
        cache_backend = details.get("BACKEND") if isinstance(details, Mapping) else None
        if isinstance(cache_backend, str) and cache_backend in NON_DISTRIBUTED_CACHE_BACKENDS:
            findings.append(
                Warning(
                    "Django Cache rate limiting with this backend is not a distributed, atomic security boundary.",
                    id="ratelimit.W004",
                )
            )
        findings.append(
            Warning(
                "Django Cache uses approximate counter windows, not Redis exact sliding windows; validate backend atomicity and eviction policies.",
                id="ratelimit.W005",
            )
        )

    raw_policies = getattr(settings, "RATELIMIT_POLICIES", ())
    try:
        policies = compile_policies(
            raw_policies,
            has_custom_resolver=bool(getattr(settings, "RATELIMIT_IDENTITY_RESOLVER", None)),
        )
    except PolicyConfigurationError:
        policies = ()  # An E016 error is already returned by config_errors().
    if backend == STORAGE_CACHE and any(len(rule.limits) > 1 for rule in policies):
        findings.append(
            Warning(
                "Django Cache policy groups are not atomic; rejected requests can consume "
                "earlier quotas. Use native Redis for all-or-nothing admission.",
                id="ratelimit.W007",
            )
        )

    if backend == STORAGE_REDIS and any(len(rule.limits) > 1 for rule in policies):
        findings.append(
            Warning(
                "Atomic multi-key Redis policies require one Redis server or keys in the "
                "same Redis Cluster hash slot. Cross-slot Redis Cluster requests are unsupported.",
                id="ratelimit.W008",
            )
        )

    configured_middleware = getattr(settings, "MIDDLEWARE", [])
    middleware = (
        list(configured_middleware) if isinstance(configured_middleware, (list, tuple)) else []
    )
    path = DJANGO_MIDDLEWARE_PATH
    if middleware and path not in middleware:
        findings.append(
            Warning(
                f"{path} is not in MIDDLEWARE (ignore if using the standalone ASGI middleware).",
                id="ratelimit.W003",
            )
        )

    if (
        getattr(settings, "RATELIMIT_IDENTITY", IDENTITY_IP) == IDENTITY_USER
        or any(limit.identity == IDENTITY_USER for rule in policies for limit in rule.limits)
    ) and path in middleware:
        auth_path = DJANGO_AUTH_MIDDLEWARE_PATH
        if auth_path not in middleware or middleware.index(auth_path) > middleware.index(path):
            findings.append(
                Warning(
                    "User identity mode requires a verified request.user; place the limiter after "
                    "AuthenticationMiddleware for session users. DRF token/JWT authentication "
                    "occurs later and requires the optional DRF throttle integration.",
                    id="ratelimit.W006",
                )
            )

    return findings
