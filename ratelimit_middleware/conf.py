from __future__ import annotations

from dataclasses import dataclass
from django.conf import settings


@dataclass(frozen=True)
class RateLimitSettings:
    rate: int
    window: int
    exempt_paths: tuple[str, ...]
    exempt_ips: tuple[str, ...]
    include_user_agent: bool
    enable_headers: bool
    redis_url: str
    redis_timeout: float
    fail_open: bool
    trust_x_forwarded_for: bool
    ws_handshake: bool
    ws_msg_rate: int
    ws_msg_window: int


def get_ratelimit_settings() -> RateLimitSettings:
    redis_url = getattr(settings, "RATELIMIT_REDIS_URL", None)
    if not redis_url:
        host = getattr(settings, "RATELIMIT_REDIS_HOST", "localhost")
        port = getattr(settings, "RATELIMIT_REDIS_PORT", 6379)
        db = getattr(settings, "RATELIMIT_REDIS_DB", 0)
        password = getattr(settings, "RATELIMIT_REDIS_PASSWORD", None)
        auth = f":{password}@" if password else ""
        redis_url = f"redis://{auth}{host}:{port}/{db}"

    return RateLimitSettings(
        rate=int(getattr(settings, "RATELIMIT_RATE", 60)),
        window=int(getattr(settings, "RATELIMIT_WINDOW", 60)),
        exempt_paths=tuple(getattr(settings, "RATELIMIT_EXEMPT_PATHS", ())),
        exempt_ips=tuple(getattr(settings, "RATELIMIT_EXEMPT_IPS", ())),
        include_user_agent=bool(getattr(settings, "RATELIMIT_INCLUDE_USER_AGENT", False)),
        enable_headers=bool(getattr(settings, "RATELIMIT_ENABLE_HEADERS", True)),
        redis_url=str(redis_url),
        redis_timeout=float(getattr(settings, "RATELIMIT_REDIS_TIMEOUT", 1)),
        fail_open=bool(getattr(settings, "RATELIMIT_FAIL_OPEN", True)),
        trust_x_forwarded_for=bool(getattr(settings, "RATELIMIT_TRUST_X_FORWARDED_FOR", False)),
        ws_handshake=bool(getattr(settings, "RATELIMIT_WS_HANDSHAKE", True)),
        ws_msg_rate=int(getattr(settings, "RATELIMIT_WS_MSG_RATE", 0)),
        ws_msg_window=int(getattr(settings, "RATELIMIT_WS_MSG_WINDOW", 60)),
    )
