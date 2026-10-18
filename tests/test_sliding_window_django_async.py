"""Django async middleware must propagate the Redis clock result."""

from unittest.mock import patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from ratelimit_middleware.middleware import RateLimitMiddleware
from ratelimit_middleware.sliding_window import SlidingWindowResult


@pytest.mark.asyncio
async def test_async_django_retry_after_and_headers():
    async def downstream(request):
        return HttpResponse("ok")

    with override_settings(RATELIMIT_RATE=1, RATELIMIT_WINDOW=60):
        middleware = RateLimitMiddleware(downstream)
        assert middleware.async_mode
        request = RequestFactory().get("/ok/", REMOTE_ADDR="192.0.2.30")

        async def denied(*args, **kwargs):
            return SlidingWindowResult(limited=True, count=1, reset_after=4)

        with patch("ratelimit_middleware.storage.check_async", side_effect=denied):
            response = await middleware(request)
        assert response.status_code == 429
        assert response["Retry-After"] == "4"
        assert response["X-RateLimit-Reset"] == "4"

        async def admitted(*args, **kwargs):
            return SlidingWindowResult(limited=False, count=1, reset_after=12)

        with patch("ratelimit_middleware.storage.check_async", side_effect=admitted):
            response = await middleware(request)
        assert response.status_code == 200
        assert response["X-RateLimit-Remaining"] == "0"
        assert response["X-RateLimit-Reset"] == "12"
