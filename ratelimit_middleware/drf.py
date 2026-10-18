"""Optional DRF integration: runs after DRF has authenticated the request.

Add ``ratelimit_middleware.drf.RateLimitThrottle`` to DRF throttle_classes
(or subclass it). No dependency on DRF is imported from the core package.
If Django middleware is also active, these are intentionally separate buckets.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from inspect import iscoroutinefunction

from django.utils.module_loading import import_string
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from rest_framework.throttling import BaseThrottle

from .constants import IDENTITY_CUSTOM, IDENTITY_USER
from .conf import get_ratelimit_settings
from .identity import client_ip
from .principals import choose_identity, principal_key
from .policies import match_policy
from .policy_admission import admit_sync
from .storage import StorageError, make_storage

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _shared_config():
    """Parse and validate settings once, not on every incoming DRF request."""
    return get_ratelimit_settings()


@lru_cache(maxsize=16)
def _shared_storage(cfg):
    """Reuse connection pools across DRF's per-request throttle instances."""
    return make_storage(cfg)


@lru_cache(maxsize=32)
def _shared_resolver(path):
    return import_string(path)


def _invalidate_on_settings_change(sender, setting, **kwargs):
    if setting.startswith("RATELIMIT_") or setting in {"CACHES", "DJANGO_REDIS_IGNORE_EXCEPTIONS"}:
        _shared_config.cache_clear()
        _shared_storage.cache_clear()
        _shared_resolver.cache_clear()


setting_changed.connect(_invalidate_on_settings_change, weak=False)


class RateLimitThrottle(BaseThrottle):
    """Authenticated DRF user quota with anonymous IP fallback by default.

    This adapter intentionally uses the same configured rate/window, but a
    distinct ``drf`` namespace from the Django middleware. Subclasses can
    override ``identity_mode`` to "ip" or "custom". The latter uses the
    configured RATELIMIT_IDENTITY_RESOLVER dotted path.
    """

    identity_mode = IDENTITY_USER
    identity_resolver = None  # Override in a subclass for DRF-only custom principals.

    def __init__(self):
        self.cfg = _shared_config()
        self._storage = _shared_storage(self.cfg)
        self._reset_after = None
        resolver_path = self.identity_resolver or self.cfg.identity_resolver
        if self.identity_mode == IDENTITY_CUSTOM:
            if not resolver_path:
                raise ImproperlyConfigured("Custom DRF identity requires identity_resolver.")
            self._resolver = _shared_resolver(resolver_path)
            if (
                not callable(self._resolver)
                or iscoroutinefunction(self._resolver)
                or iscoroutinefunction(getattr(self._resolver, "__call__", None))
            ):
                raise ImproperlyConfigured(
                    "Custom DRF identity resolver must be a synchronous callable."
                )
        else:
            self._resolver = None
        self._policy_resolver = self._resolver or (
            _shared_resolver(self.cfg.identity_resolver) if self.cfg.identity_resolver else None
        )

    def allow_request(self, request, view):
        ip = client_ip(
            request.META.get("REMOTE_ADDR"),
            request.META.get("HTTP_X_FORWARDED_FOR"),
            trust_forwarded=self.cfg.trust_x_forwarded_for,
            trusted_proxies=self.cfg.trusted_proxies,
        )
        # DRF authentication precedes throttling; never parse raw JWT/API keys.
        policy = match_policy(self.cfg.policies, request.path_info, request.method)
        try:
            if policy is not None:
                user = (
                    request.user
                    if any(limit.identity == IDENTITY_USER for limit in policy.limits)
                    else None
                )
                decision = admit_sync(
                    self._storage,
                    policy,
                    "drf",
                    request,
                    ip,
                    user=user,
                    resolver=self._policy_resolver,
                )
                self._reset_after = decision.result.reset_after
                return not decision.result.limited
            user = request.user if self.identity_mode == IDENTITY_USER else None
            identity = choose_identity(
                self.identity_mode, request, user=user, resolver=self._resolver
            )
            key = principal_key("drf", ip, identity)
            result = self._storage.check_sync(key, self.cfg.rate, self.cfg.window)
        except StorageError:
            logger.error("Rate-limit storage error during DRF throttling")
            self._reset_after = self.cfg.window
            return self.cfg.fail_open
        self._reset_after = result.reset_after
        return not result.limited

    def wait(self):
        return self._reset_after
