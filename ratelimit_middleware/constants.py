"""Canonical, framework-independent rate-limiting choices and limits.

Keep algorithm, storage and identity identifiers in one place so settings
validation, policy compilation and request adapters cannot silently diverge.
"""

STORAGE_CACHE = "cache"
STORAGE_REDIS = "redis"
STORAGE_BACKENDS = frozenset({STORAGE_CACHE, STORAGE_REDIS})

ALGORITHM_SLIDING_WINDOW = "sliding_window"
# Algorithm identifier, not a credential.
ALGORITHM_TOKEN_BUCKET = "token_bucket"  # nosec B105
ALGORITHMS = frozenset({ALGORITHM_SLIDING_WINDOW, ALGORITHM_TOKEN_BUCKET})

IDENTITY_IP = "ip"
IDENTITY_USER = "user"
IDENTITY_CUSTOM = "custom"
IDENTITY_MODES = frozenset({IDENTITY_IP, IDENTITY_USER, IDENTITY_CUSTOM})

# Redis Lua uses doubles; keep counters and millisecond TTLs exactly representable.
MAX_RATE = (1 << 53) - 1
MAX_WINDOW = MAX_RATE // 1000

MAX_TOKEN_BUCKET_RATE = 1_000_000_000
MAX_TOKEN_BUCKET_WINDOW = 31_536_000
MAX_POLICIES = 64
MAX_LIMITS_PER_POLICY = 8

REDIS_URL_SCHEMES = ("redis://", "rediss://", "unix://")
DJANGO_REDIS_CACHE_BACKEND = "django_redis.cache.RedisCache"
DJANGO_REDIS_CACHE_BACKENDS = frozenset(
    {
        "django.core.cache.backends.redis.RedisCache",
        DJANGO_REDIS_CACHE_BACKEND,
    }
)
NON_DISTRIBUTED_CACHE_BACKENDS = frozenset(
    {
        "django.core.cache.backends.locmem.LocMemCache",
        "django.core.cache.backends.filebased.FileBasedCache",
        "django.core.cache.backends.db.DatabaseCache",
    }
)
DJANGO_MIDDLEWARE_PATH = "ratelimit_middleware.middleware.RateLimitMiddleware"
DJANGO_AUTH_MIDDLEWARE_PATH = "django.contrib.auth.middleware.AuthenticationMiddleware"

# These names belong to the public Django settings namespace. Detect typos at
# startup instead of silently applying defaults for unrecognized settings.
SETTING_NAMES = frozenset(
    {
        "RATELIMIT_ALGORITHM",
        "RATELIMIT_ENABLE_HEADERS",
        "RATELIMIT_EXEMPT_IPS",
        "RATELIMIT_EXEMPT_PATHS",
        "RATELIMIT_FAIL_OPEN",
        "RATELIMIT_IDENTITY",
        "RATELIMIT_IDENTITY_RESOLVER",
        "RATELIMIT_POLICIES",
        "RATELIMIT_RATE",
        "RATELIMIT_REDIS_TIMEOUT",
        "RATELIMIT_REDIS_URL",
        "RATELIMIT_STORAGE",
        "RATELIMIT_TRUSTED_PROXIES",
        "RATELIMIT_TRUST_X_FORWARDED_FOR",
        "RATELIMIT_WINDOW",
        "RATELIMIT_WS_HANDSHAKE",
        "RATELIMIT_WS_MSG_RATE",
        "RATELIMIT_WS_MSG_WINDOW",
    }
)
