from __future__ import annotations

from django.conf import settings
from django.core.checks import Error, Warning, register


def _is_positive_int(value) -> bool:
    return isinstance(value, int) and value > 0


@register()
def ratelimit_settings_check(app_configs, **kwargs):
    errors = []

    rate = getattr(settings, "RATELIMIT_RATE", 60)
    window = getattr(settings, "RATELIMIT_WINDOW", 60)
    redis_url = getattr(settings, "RATELIMIT_REDIS_URL", None)
    redis_host = getattr(settings, "RATELIMIT_REDIS_HOST", None)
    trust_xff = getattr(settings, "RATELIMIT_TRUST_X_FORWARDED_FOR", False)

    if not _is_positive_int(rate):
        errors.append(Error("RATELIMIT_RATE must be a positive integer.", id="ratelimit.E001"))

    if not _is_positive_int(window):
        errors.append(Error("RATELIMIT_WINDOW must be a positive integer in seconds.", id="ratelimit.E002"))

    if redis_url is not None and not str(redis_url).startswith(("redis://", "rediss://", "unix://")):
        errors.append(Error("RATELIMIT_REDIS_URL must start with redis://, rediss://, or unix://.", id="ratelimit.E003"))

    if redis_url is None and redis_host is None:
        errors.append(Warning("No RATELIMIT_REDIS_URL configured; defaulting to redis://localhost:6379/0.", id="ratelimit.W001"))

    if trust_xff and not getattr(settings, "SECURE_PROXY_SSL_HEADER", None):
        errors.append(Warning("RATELIMIT_TRUST_X_FORWARDED_FOR=True should only be used behind a trusted proxy.", id="ratelimit.W002"))

    middleware = list(getattr(settings, "MIDDLEWARE", []))
    path = "ratelimit_middleware.middleware.RateLimitMiddleware"
    if middleware and path not in middleware:
        errors.append(Warning(f"{path} is not in MIDDLEWARE.", id="ratelimit.W003"))

    return errors
