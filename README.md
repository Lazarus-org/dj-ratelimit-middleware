# dj-ratelimit-middleware

[![PyPI](https://img.shields.io/pypi/v/dj-ratelimit-middleware?logo=pypi&logoColor=white)](https://pypi.org/project/dj-ratelimit-middleware/)
[![Python Versions](https://img.shields.io/pypi/pyversions/dj-ratelimit-middleware?logo=python&logoColor=white)](https://pypi.org/project/dj-ratelimit-middleware/)
[![Django Versions](https://img.shields.io/pypi/djversions/dj-ratelimit-middleware)](https://pypi.org/project/dj-ratelimit-middleware/)
[![CI](https://github.com/lazarus-org/dj-ratelimit-middleware/actions/workflows/ci.yml/badge.svg)](https://github.com/lazarus-org/dj-ratelimit-middleware/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/lazarus-org/dj-ratelimit-middleware)](https://github.com/lazarus-org/dj-ratelimit-middleware/blob/main/LICENSE)
[![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://pre-commit.com/)
[![Open Issues](https://img.shields.io/github/issues/lazarus-org/dj-ratelimit-middleware)](https://github.com/lazarus-org/dj-ratelimit-middleware/issues)
[![Last Commit](https://img.shields.io/github/last-commit/lazarus-org/dj-ratelimit-middleware)](https://github.com/lazarus-org/dj-ratelimit-middleware/commits/main)
[![Language](https://img.shields.io/github/languages/top/lazarus-org/dj-ratelimit-middleware)](https://github.com/lazarus-org/dj-ratelimit-middleware)
[![Coverage](https://codecov.io/gh/lazarus-org/dj-ratelimit-middleware/branch/main/graph/badge.svg)](https://codecov.io/gh/lazarus-org/dj-ratelimit-middleware)

**Flexible rate limiting for Django, Django REST Framework, and ASGI.**

`dj-ratelimit-middleware` provides Redis-backed atomic rate limiting or portable Django Cache limits, HTTP policies, authenticated-user and IP identities, and optional WebSocket enforcement. Choose exact sliding windows or constant-memory token buckets according to your workload.

## Features

- **Two native Redis algorithms:** exact sliding-window log and constant-space token bucket, each enforced by atomic Lua operations.
- **Alternative Django Cache backend:** uses Django's configured cache alias, without requiring the optional `redis` Python dependency.
- **Configurable identities:** client IP (default), authenticated user ID (with anonymous-IP fallback), or a trusted custom principal.
- **HTTP policies:** path, path prefix, methods, priority, algorithm, and up to eight quotas per matching policy.
- **Grouped Redis admission:** all-or-nothing admission for multiple quotas in one Redis operation on supported standalone servers.
- **Framework integration:** synchronous/asynchronous Django middleware, an optional DRF throttle, and standalone ASGI HTTP/WebSocket middleware.
- **Security-oriented configuration:** trusted-proxy networks, bounded forwarded headers, explicit exemptions, strict Django checks, and blocking startup validation.
- **Operational controls:** configurable fail-open/fail-closed behavior, 429 responses, `Retry-After`, and optional rate-limit headers.

## Contents

- [Requirements and installation](#requirements-and-installation)
- [Quick start](#quick-start)
- [Storage backends and algorithms](#storage-backends-and-algorithms)
- [Identity and authentication](#identity-and-authentication)
- [Endpoint policies](#endpoint-policies)
- [Django REST Framework](#django-rest-framework)
- [ASGI and WebSockets](#asgi-and-websockets)
- [Responses and headers](#responses-and-headers)
- [Configuration reference](#configuration-reference)
- [Security and deployment considerations](#security-and-deployment-considerations)
- [Performance and testing](#performance-and-testing)
- [Development](#development)

## Requirements and installation

- Python **3.10–3.14**.
- Django **5.2** on Python 3.10–3.14, or Django **6.0/6.1** on Python 3.12–3.14.
- Optional Django REST Framework **3.18.3 or newer**, using the `drf` extra.
- Optional `redis-py >=5.0`, using the `redis` extra for native Redis storage. Native Redis requires a reachable compatible Redis server.

```bash
# Django Cache only (no redis-py required)
pip install dj-ratelimit-middleware

# Native Redis engine
pip install 'dj-ratelimit-middleware[redis]'

# Native Redis plus DRF throttling
pip install 'dj-ratelimit-middleware[redis,drf]'
```

With [uv](https://docs.astral.sh/uv/):

```bash
uv add dj-ratelimit-middleware
uv add 'dj-ratelimit-middleware[redis,drf]'
```

The **PyPI distribution name** is `dj-ratelimit-middleware`; the **Python import and Django app name** is `ratelimit_middleware`. DRF is optional. The package defines no database models or URL routes.

## Quick start

Choose **one** storage configuration. The examples below use the normal Django middleware entry point.

### Option A — Django Cache

Django Cache is an accessible starting point where approximate counter-based limits are sufficient. This minimal example uses Django's built-in, **process-local** memory cache, so it is intended for **development only**. In a multi-worker deployment, configure a shared backend such as Redis or Memcached and install whichever client driver that backend requires.

```python
# settings.py
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
    "ratelimit": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    },
}

INSTALLED_APPS = [
    # ...
    "ratelimit_middleware",  # Enables Django system checks
]

MIDDLEWARE = [
    # ... other middleware
    "ratelimit_middleware.middleware.RateLimitMiddleware",
]

RATELIMIT_STORAGE = {"BACKEND": "cache", "CACHE_ALIAS": "ratelimit"}
RATELIMIT_RATE = 60
RATELIMIT_WINDOW = 60  # seconds
```

This uses the standard Django Cache API, **not** the native Redis Lua engine. To deploy a shared cache instead, change `CACHES["ratelimit"]` to a supported Redis- or Memcached-backed Django cache and install its backend-specific Python driver. The package itself does not require the `redis` extra for generic cache mode, but **Django's Redis cache backend still requires redis-py**. See the [storage comparison](#storage-backends-and-algorithms).

### Option B — Native Redis (stronger admission guarantees)

Use the `redis` extra and supply a connection URL explicitly:

```python
# settings.py
import os

INSTALLED_APPS = [
    # ...
    "ratelimit_middleware",
]

MIDDLEWARE = [
    # ...
    "ratelimit_middleware.middleware.RateLimitMiddleware",
]

RATELIMIT_STORAGE = {
    "BACKEND": "redis",
    "URL": os.environ["RATELIMIT_REDIS_URL"],
}
RATELIMIT_RATE = 60
RATELIMIT_WINDOW = 60
RATELIMIT_FAIL_OPEN = False  # Consider for critical protected endpoints
```

The default algorithm is an **exact sliding window**. To enable the constant-space token bucket instead:

```python
RATELIMIT_ALGORITHM = "token_bucket"
```

An alternative native Redis configuration can reference a supported **simple** Django Redis cache alias:

```python
RATELIMIT_STORAGE = {"BACKEND": "redis", "CACHE_ALIAS": "ratelimit"}
```

For this alias form, the cache backend must be Django's built-in `RedisCache` or a supported simple `django-redis` configuration with a single valid URL. Advanced options (e.g., Sentinel, multi-location configurations, custom client options) are not automatically translated into the native Redis client; use an explicit URL when appropriate. The native adapter creates its **own client/pool**, rather than borrowing the cache backend's private connection internals.

The shorthand `RATELIMIT_REDIS_URL = "redis://..."` also selects native Redis if `RATELIMIT_STORAGE` is omitted. Omitting both a valid Redis configuration and an explicit cache backend is an **error**; a native Redis server URL is not assumed.

### Validate the configuration

```bash
python manage.py check
```

Unknown `RATELIMIT_*` names, invalid algorithm/identity/backend options, nonpositive rate/window values, malformed policies, and unsupported combinations produce blocking check errors and fail middleware initialization. The `ratelimit_middleware` app must be installed for Django's registered checks; initialization validates settings independently.

## Storage backends and algorithms

| Capability | Native Redis | Django Cache |
|---|---|---|
| Algorithm | Exact sliding window **or** token bucket | First-request-anchored counter window |
| Concurrency | Atomic server-side Lua admission | Depends on underlying cache; no portable atomic admission guarantee |
| Multiple quotas | Atomic group on supported standalone Redis | Sequential; an earlier quota can be consumed before a later denial |
| Memory per identity | Sliding window: O(admitted events); token bucket: O(1) | O(1) counter per quota |
| Reset estimate | Calculated from Redis state | Conservative whole-window estimate |
| Async | Native async Redis client | Django's async cache API |
| Eviction | Redis state loss resets quota | Cache eviction can reset quota |

### Sliding window

`RATELIMIT_RATE = 60` and `RATELIMIT_WINDOW = 60` mean **at most 60 admitted requests in any rolling 60-second interval**, per rate-limit key on native Redis. Only successful admissions add an event; rejected requests do not grow the event log or refresh its TTL.

Use this when exact rolling-window enforcement matters. Memory scales with the number of admitted events still in the window.

### Token bucket

```python
RATELIMIT_ALGORITHM = "token_bucket"
RATELIMIT_RATE = 120
RATELIMIT_WINDOW = 60
```

The bucket starts full with capacity **120**, refills at **120 tokens per 60 seconds**, and spends one token per admitted request. This supports bursts up to current capacity and uses constant-size Redis state per identity. It is **not** equivalent to a strict rolling-window maximum.

Token bucket requires `RATELIMIT_STORAGE` to use native Redis (or an equivalent valid native Redis URL configuration). The generic Django Cache adapter rejects this algorithm at startup.

For grouped limits, a policy selects **one algorithm for its entire group**. Mixed-algorithm groups are not supported. Different policies can select different algorithms.

## Identity and authentication

### IP identity (default)

```python
RATELIMIT_IDENTITY = "ip"
```

Requests share a quota by resolved client IP. The package normalizes IPv4/IPv6 and can use `X-Forwarded-For` only when the immediate network peer belongs to explicitly trusted proxies. See [trusted proxies](#trusted-proxies).

### Authenticated Django users

```python
RATELIMIT_IDENTITY = "user"

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "ratelimit_middleware.middleware.RateLimitMiddleware",
    # ... other middleware
]
```

An already authenticated user's stable primary key is used as the identity; anonymous requests fall back to IP. Authenticated identities are **namespaced and SHA-256 hashed** before being used in rate-limit keys. Resolving Django's lazy session principal can involve the usual session/authentication lookup; IP mode avoids it.

**DRF token/JWT authentication happens later than Django middleware.** For those requests, use the [optional DRF throttle](#django-rest-framework) if you need quotas on the verified DRF user identity. The library does not decode JWTs or authenticate credentials itself.

### Trusted custom identities

Custom resolvers are supported for identities the application has **already authenticated or verified** (e.g., an API-key principal or tenant). Define a synchronous, nonblocking callable:

```python
# myproject/ratelimit.py
def resolve_principal(context):
    principal = (
        context.get("verified_principal")
        if isinstance(context, dict)  # ASGI scope
        else getattr(context, "verified_principal", None)  # Django/DRF request
    )
    if principal is None:
        return None  # Use the resolved client IP instead
    return ("service", principal.pk)
```

```python
# settings.py
RATELIMIT_IDENTITY = "custom"
RATELIMIT_IDENTITY_RESOLVER = "myproject.ratelimit.resolve_principal"
```

The callable receives the framework's request object or ASGI scope. It must return `None` or a `(namespace, identifier)` tuple using bounded, supported values. **Never** use an arbitrary `X-User-ID`, bearer token, or unverified JWT claim as a principal. Do not perform database or network I/O in this resolver.

## Endpoint policies

`RATELIMIT_POLICIES` is an ordered list of policy dictionaries. The **first matching policy** after priority sorting replaces the global/default quota for that HTTP request. If nothing matches, the global rate/identity/algorithm applies. Exemptions bypass admission before policy selection.

```python
RATELIMIT_POLICIES = [
    {
        "NAME": "login",
        "PATH": "/api/auth/login/",
        "METHODS": ["POST"],
        "PRIORITY": 100,
        "ALGORITHM": "sliding_window",
        "LIMITS": [
            {"IDENTITY": "ip", "RATE": 10, "WINDOW": 60},
        ],
    },
    {
        "NAME": "management",
        "PATH_PREFIX": "/api/management/",
        "METHODS": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "PRIORITY": 10,
        "ALGORITHM": "token_bucket",  # Native Redis only
        "LIMITS": [
            {"IDENTITY": "user", "RATE": 120, "WINDOW": 60},
            {"IDENTITY": "ip", "RATE": 600, "WINDOW": 60},
        ],
    },
]
```

A policy has the following fields:

| Field | Required | Description |
|---|---|---|
| `NAME` | Yes | Unique lowercase identifier, at most 32 characters |
| `PATH` / `PATH_PREFIX` | Exactly one | Literal exact path or path-segment-aware subtree prefix |
| `METHODS` | No | List/tuple of uppercase HTTP methods; omitted matches any method |
| `PRIORITY` | No | Integer from -1000 to 1000; higher value wins; declaration order breaks ties |
| `ALGORITHM` | No | `sliding_window` (default) or `token_bucket` (native Redis only) |
| `LIMITS` | Yes | 1–8 quotas, each containing exactly `IDENTITY`, `RATE`, and `WINDOW` |

A policy may include IP and authenticated-user quotas simultaneously. With native Redis on a supported standalone server, the group is checked **atomically**: if one quota denies, no quota in that group is charged. With Django Cache, checks are sequential and **can partially consume** earlier quotas before a denial. Policy counts and integer values are bounded at configuration time (at most 64 policies).

`PATH_PREFIX = "/api/manage/"` matches `/api/manage` and its subtree, but not `/api/management`. HTTP policies currently apply to **HTTP**, not WebSocket message limits.

## Django REST Framework

Install the `drf` extra and add the throttle to DRF's configuration or a specific view:

```python
REST_FRAMEWORK = {
    "DEFAULT_THROTTLE_CLASSES": [
        "ratelimit_middleware.drf.RateLimitThrottle",
    ],
}
```

This adapter runs **after DRF authentication** and uses a verified user identity by default, falling back to IP for anonymous requests. Its configuration follows the global rate/window and HTTP policies, but the throttle uses **separate `drf` quota keys** from the Django middleware's `http` keys.

If both adapters are active, **both enforce their own quotas**; this can be desirable for defense in depth, but may also lead to redundant checks and additional backend work. DRF throttles use DRF's 429 and wait/`Retry-After` handling, whereas the Django middleware produces its own JSON 429 and optional `X-RateLimit-*` headers. Django middleware exemptions are not a separate automatic exemption mechanism for DRF throttles.

Subclass `RateLimitThrottle` to change its `identity_mode` to `"ip"` or `"custom"`; custom mode uses `identity_resolver` or the configured dotted-path resolver. The DRF package is imported only when this integration is used.

## ASGI and WebSockets

For a standalone ASGI entry point:

```python
# asgi.py
from django.core.asgi import get_asgi_application
from ratelimit_middleware.middleware import ASGIRateLimitMiddleware

application = ASGIRateLimitMiddleware(get_asgi_application())
```

This example wraps Django's ASGI application and rate-limits **at the outer boundary**. If Django's ordinary `RateLimitMiddleware` is already installed, requests may be limited **twice**. Choose an entry point intentionally. For authenticated `scope["user"]` identities (e.g., when using Channels), place the ASGI rate limiter **inside** trusted authentication middleware so the verified principal already exists in the scope.

The standalone adapter supports:

- HTTP admission, policies, 429 JSON responses, and optional rate-limit headers.
- WebSocket handshake limits when `RATELIMIT_WS_HANDSHAKE = True` (default): uses the global rate/window and a dedicated bucket.
- WebSocket inbound-message limits when `RATELIMIT_WS_MSG_RATE > 0` (disabled by default): uses `RATELIMIT_WS_MSG_WINDOW`.
- WebSocket rejection via `websocket.close` with application-defined code `4408`.

WebSocket handshake and message quotas are **separate from HTTP endpoint policies**. Neither Channels nor an ASGI server is a mandatory package dependency.

## Responses and headers

When the Django/ASGI middleware rejects a request, it returns HTTP **429** with a JSON body like:

```json
{
  "error": "Rate limit exceeded",
  "detail": "Please try again in 12 seconds"
}
```

The retry time varies by algorithm and current state; the example is illustrative. The middleware sets `Retry-After` and, by default, rate metadata:

| Header | Meaning |
|---|---|
| `Retry-After` | Estimated seconds before the limiting quota permits another request; on 429 |
| `X-RateLimit-Limit` | Rate of the selected quota |
| `X-RateLimit-Remaining` | Estimated remaining capacity for that quota |
| `X-RateLimit-Reset` | Estimated seconds until quota availability/reset; not an epoch timestamp |

For multiple quotas, headers describe a **selected limiting/most-restrictive quota**, not every configured quota. Cache-based values are approximate. Header emission can be disabled with `RATELIMIT_ENABLE_HEADERS = False`; `Retry-After` on middleware-generated 429 responses remains present.

## Configuration reference

All settings are configured as top-level variables in Django's `settings.py`.

| Setting | Default | Purpose / constraints |
|---|---|---|
| `RATELIMIT_RATE` | `60` | Positive integer global capacity/request limit |
| `RATELIMIT_WINDOW` | `60` | Positive integer seconds for global quota |
| `RATELIMIT_ALGORITHM` | `"sliding_window"` | Native Redis `"sliding_window"` or `"token_bucket"` |
| `RATELIMIT_STORAGE` | `None` (native Redis) | `{"BACKEND": "redis"/"cache", ...}`; see storage examples |
| `RATELIMIT_REDIS_URL` | `None` | Redis URL used when native Redis is selected without an explicit `URL`/alias |
| `RATELIMIT_REDIS_TIMEOUT` | `1` | Positive finite number of seconds for Redis network timeouts |
| `RATELIMIT_FAIL_OPEN` | `True` | Allow a request on **runtime storage failure** when true, otherwise reject |
| `RATELIMIT_ENABLE_HEADERS` | `True` | Add middleware `X-RateLimit-*` headers |
| `RATELIMIT_IDENTITY` | `"ip"` | `"ip"`, `"user"`, or `"custom"` |
| `RATELIMIT_IDENTITY_RESOLVER` | `None` | Dotted path to a synchronous callable when custom identities are used |
| `RATELIMIT_POLICIES` | `()` | Up to 64 compiled HTTP policies; higher priority first |
| `RATELIMIT_EXEMPT_PATHS` | `()` | Literal exact paths or slash-terminated subtrees |
| `RATELIMIT_EXEMPT_IPS` | `()` | Client IPs exempt from middleware/ASGI admission |
| `RATELIMIT_TRUST_X_FORWARDED_FOR` | `False` | Enable explicit trusted-proxy XFF parsing |
| `RATELIMIT_TRUSTED_PROXIES` | `()` | Explicit IP addresses/CIDRs for trusted immediate proxy hops |
| `RATELIMIT_WS_HANDSHAKE` | `True` | Enforce a global quota for WebSocket connection handshakes |
| `RATELIMIT_WS_MSG_RATE` | `0` | Inbound WebSocket message limit; `0` disables |
| `RATELIMIT_WS_MSG_WINDOW` | `60` | Positive integer seconds for inbound WebSocket quota |

**Storage schema:** `RATELIMIT_STORAGE` accepts `BACKEND`, `CACHE_ALIAS`, and `URL` only, with backend-specific restrictions. Cache storage cannot have a URL; native Redis cannot use both `URL` and `CACHE_ALIAS`. If using a cache alias, the alias must exist and resolve to a valid Django backend. `DummyCache` is rejected.

**Validation bounds:** Rates and windows must be valid integers and within safe Redis numeric limits. Token bucket additionally restricts capacity and window to bounded values (see `ratelimit_middleware/constants.py`). Booleans, negative/zero windows, unsupported algorithms/identities, misspelled `RATELIMIT_*` settings, malformed policies, and inconsistent backend options are blocking configuration errors, not warnings.

### Exempt paths and IP addresses

```python
RATELIMIT_EXEMPT_PATHS = (
    "/health",      # Only /health
    "/static/",     # Subtree; not /static-evil
)
RATELIMIT_EXEMPT_IPS = ("192.0.2.10",)
```

Set exemptions narrowly. The package rejects ambiguous path declarations and applies client-IP exemptions to the **resolved** IP. Remember that an exemption is a bypass of this limiter and must not substitute for authorization or network access controls.

## Security and deployment considerations

### Trusted proxies

`X-Forwarded-For` is **not trusted by default**. If the app is behind Nginx or another reverse proxy and client-IP quotas are required:

```python
RATELIMIT_TRUST_X_FORWARDED_FOR = True
RATELIMIT_TRUSTED_PROXIES = (
    "10.0.0.0/24",  # Example only: replace with the real proxy peer/network
)
```

The library checks that the immediate socket peer is trusted, then walks the forwarded chain **right-to-left** to find the first untrusted hop. Malformed/oversized headers use a conservative fallback. Never configure a trust-all network; configure the proxy to normalize/overwrite forwarded headers and prevent direct access to bypass the proxy. Keep trusted ranges as narrow as possible.

### Failure policy

**`RATELIMIT_FAIL_OPEN = True` is the default.** A temporary storage failure can therefore allow requests without enforcement. Choose `False` if denial during an outage is preferable to unthrottled traffic; that decision can affect application availability. Fail-open is a **global setting**, not a per-policy override. Invalid configuration and unsupported Redis Cluster topology are not treated as transient storage failures and should still raise errors.

For security-sensitive endpoints, also apply appropriate controls at the reverse proxy, authentication layer, and network perimeter. Rate limiting does not replace authorization, fraud prevention, or infrastructure-level denial-of-service protection.

### Redis Cluster and shared caches

Native Redis grouped admission depends on a single atomic Lua operation across the relevant keys. **Redis Cluster multi-key operations spanning different hash slots are unsupported**; the library rejects cross-slot/unsupported redirects rather than treating them as ordinary recoverable failures. It does **not** provide a general Redis Cluster routing/failover adapter.

Django Cache may operate across shared Redis/Memcached instances, but its counter-based algorithm is **not an exact sliding window**, and eviction or concurrency semantics depend on the actual cache backend. Cache multi-quota decisions are not transactional; they may consume an earlier quota even when a later quota rejects the request.

### Authentication boundaries

Authenticated-user limiting must receive a **verified** `request.user` or `scope["user"]` before identity evaluation. Session-authenticated Django requests should place the middleware after `AuthenticationMiddleware`; DRF JWT/token authentication requires the DRF throttle for verified DRF principals. Custom resolvers are application code and must not accept untrusted identities, block the event loop, or perform expensive lookups per request.

### Operational observability

The middleware logs fixed storage-error messages without serializing backend exception details, to avoid leaking credentials. Monitor 429 rates, storage connectivity, and server-side latency at the application/infrastructure layer. No built-in Prometheus metrics exporter is provided by this package.

## Performance and testing

The native Redis backend evaluates admission with Lua scripts, avoiding a separate check-and-update round trip. The sliding-window log stores admitted events; token buckets store constant-size state per identity. Actual throughput depends on your Redis deployment, concurrency, and network latency.

Benchmark using a dedicated test Redis instance and choose limits based on production traffic measurements.

For a **disposable, isolated** Redis instance only:

```bash
uv run python scripts/benchmark_ratelimit.py \
    --redis-url redis://127.0.0.1:6379/15 \
    --confirm-test-redis \
    --algorithm token_bucket \
    --mode sync \
    --requests 10000 \
    --workers 32 \
    --identities 100
```

Never run tests or benchmarks against production or other shared Redis instances.

## Development

```bash
# Install development and optional integration dependencies
uv sync --locked --group dev --extra redis --extra drf

# Unit/integration tests; real backend tests require isolated services and
# RATELIMIT_TEST_REDIS_URL / RATELIMIT_TEST_REDIS5_URL /
# RATELIMIT_TEST_MEMCACHED_URL when applicable.
uv run --no-sync pytest -q

# Django checks
uv run --no-sync python -m django check --settings=tests.settings

# Local developer pre-commit and CI-only validation
uv run --no-sync pre-commit run --all-files
uv run --no-sync pre-commit run --all-files --config .pre-commit-config-ci.yaml

# Compatibility matrix (requires corresponding Python interpreters)
uvx tox

# Build and inspect distribution artifacts
uv build --force-pep517
uv run --no-sync python scripts/check_wheel.py dist/
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), and [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Maintained by the [Lazarus organization](https://github.com/Lazarus-org).
