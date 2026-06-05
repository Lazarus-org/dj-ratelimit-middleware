# Django Ratelimit Middleware

A production-ready Redis-backed rate limiting middleware for Django.

It supports both normal Django HTTP requests and ASGI traffic, including WebSocket connections. It is useful for protecting APIs, login endpoints, OTP endpoints, public pages, and high-traffic services from abuse.

---

## Features

* Redis-backed request counting
* Works with Django middleware
* Supports ASGI HTTP and WebSocket traffic
* Per-IP rate limiting
* Optional `X-Forwarded-For` support behind trusted proxies
* Configurable request limit and time window
* Exempt paths and IP addresses
* Optional rate limit headers
* Fail-open or fail-closed behavior when Redis is unavailable
* Django system checks using `python manage.py check`
* Fully tested with `pytest`

---

## Installation

```bash
pip install django-ratelimit-middleware
```

For local development:

```bash
pip install -e ".[test]"
```

---

## Django Setup

Add the app:

```python
INSTALLED_APPS = [
    ...
    "ratelimit_middleware",
]
```

Add the middleware:

```python
MIDDLEWARE = [
    "ratelimit_middleware.middleware.RateLimitMiddleware",
    ...
]
```

Recommended: place it near the top of `MIDDLEWARE` so requests are blocked before reaching expensive application logic.

---

## Basic Configuration

```python
RATELIMIT_RATE = 60
RATELIMIT_WINDOW = 60
RATELIMIT_REDIS_URL = "redis://localhost:6379/0"
RATELIMIT_FAIL_OPEN = True
RATELIMIT_TRUST_X_FORWARDED_FOR = False
```

This allows each client IP to make `60` requests per `60` seconds.

---

## Settings Reference

| Setting                           |                      Default | Description                                   |
| --------------------------------- | ---------------------------: | --------------------------------------------- |
| `RATELIMIT_RATE`                  |                         `60` | Maximum requests allowed per window           |
| `RATELIMIT_WINDOW`                |                         `60` | Time window in seconds                        |
| `RATELIMIT_REDIS_URL`             | `"redis://localhost:6379/0"` | Redis connection URL                          |
| `RATELIMIT_FAIL_OPEN`             |                       `True` | Allow requests if Redis is unavailable        |
| `RATELIMIT_TRUST_X_FORWARDED_FOR` |                      `False` | Use `X-Forwarded-For` for client IP detection |
| `RATELIMIT_EXEMPT_PATHS`          |                         `[]` | Paths that should not be rate limited         |
| `RATELIMIT_EXEMPT_IPS`            |                         `[]` | IP addresses that should not be rate limited  |
| `RATELIMIT_ENABLE_HEADERS`        |                       `True` | Add rate limit headers to responses           |

---

## Example Production Settings

```python
RATELIMIT_RATE = 120
RATELIMIT_WINDOW = 60
RATELIMIT_REDIS_URL = "redis://redis:6379/0"
RATELIMIT_FAIL_OPEN = True
RATELIMIT_TRUST_X_FORWARDED_FOR = False
RATELIMIT_EXEMPT_PATHS = [
    "/health/",
    "/metrics/",
]
RATELIMIT_EXEMPT_IPS = [
    "127.0.0.1",
]
RATELIMIT_ENABLE_HEADERS = True
```

---

## Important Proxy Warning

Only enable this setting when your Django app is behind a trusted proxy such as Nginx:

```python
RATELIMIT_TRUST_X_FORWARDED_FOR = True
```

Do **not** enable it for public direct traffic, because clients can spoof the `X-Forwarded-For` header.

Example Nginx config:

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header Host $host;
```

---

## Response Headers

When headers are enabled, responses include:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 59
X-RateLimit-Reset: 60
```

When the client exceeds the limit:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

---

## Example 429 Response

```json
{
  "detail": "Rate limit exceeded. Try again later."
}
```

---

## Running Django Checks

This package includes Django system checks to validate your rate limit settings.

```bash
python manage.py check
```

Example problems it can detect:

* invalid `RATELIMIT_RATE`
* invalid `RATELIMIT_WINDOW`
* invalid Redis URL
* unsafe or incorrect setting types

---

## Running Tests

Install test dependencies:

```bash
pip install -e ".[test]"
```

Run tests:

```bash
pytest
```

Run with verbose output:

```bash
pytest -v
```

---

## Example Test

```python
from unittest.mock import patch

import fakeredis
from django.test import Client


def redis_factory(*args, **kwargs):
    return fakeredis.FakeRedis(decode_responses=True)


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_allows_until_limit_then_429(mock_redis):
    client = Client(REMOTE_ADDR="1.2.3.4")

    assert client.get("/ok/").status_code == 200
    assert client.get("/ok/").status_code == 200

    response = client.get("/ok/")

    assert response.status_code == 429
    assert response["Retry-After"] == "60"
```

---

## Recommended Use Cases

Use this middleware for:

* OTP endpoints
* login endpoints
* registration endpoints
* password reset endpoints
* public APIs
* expensive search endpoints
* WebSocket connection protection

Example stricter OTP configuration:

```python
RATELIMIT_RATE = 5
RATELIMIT_WINDOW = 60
```

---

## Redis Requirement

Redis must be running for production use.

Local Redis:

```bash
redis-server
```

Docker Compose example:

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

---

## Fail-Open vs Fail-Closed

By default:

```python
RATELIMIT_FAIL_OPEN = True
```

This means if Redis is down, requests are allowed.

For stricter security:

```python
RATELIMIT_FAIL_OPEN = False
```

This means if Redis is down, requests are blocked.

Recommended:

* Public website: `True`
* Critical auth/OTP API: depends on your security policy
* Internal admin API: `False` can be safer

---

## Development Workflow

```bash
git clone <your-repo-url>
cd django-ratelimit-middleware

python -m venv .venv
source .venv/bin/activate

pip install -e ".[test]"
pytest
python tests/testproject/manage.py check
```

On Windows:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[test]"
pytest
```

---

## License

MIT License
