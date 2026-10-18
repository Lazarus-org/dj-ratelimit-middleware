"""Framework adapter bypasses, async authentication, and failure responses."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.utils.functional import SimpleLazyObject

from ratelimit_middleware.drf import RateLimitThrottle
from ratelimit_middleware.middleware import ASGIRateLimitMiddleware, RateLimitMiddleware
from ratelimit_middleware.sliding_window import SlidingWindowResult
from ratelimit_middleware.storage import StorageError


@pytest.mark.parametrize("policy_mode", [False, True])
@pytest.mark.parametrize("lazy_user", [False, True])
@pytest.mark.parametrize("auser_available", [False, True])
@pytest.mark.asyncio
async def test_async_user_resolution_requires_a_verified_user_or_async_authentication(
    policy_mode, lazy_user, auser_available
):
    options = {"RATELIMIT_IDENTITY": "user"}
    if policy_mode:
        options = {
            "RATELIMIT_POLICIES": [
                {
                    "NAME": "users",
                    "PATH": "/private",
                    "LIMITS": [{"IDENTITY": "user", "RATE": 3, "WINDOW": 30}],
                }
            ]
        }
    user = SimpleNamespace(is_authenticated=True, pk="verified")
    request = RequestFactory().get("/private", REMOTE_ADDR="192.0.2.31")

    def sync_authentication():
        pytest.fail("Async limiting must not evaluate the lazy session user synchronously")

    if lazy_user:
        request.user = SimpleLazyObject(sync_authentication)
    request.auser = AsyncMock(return_value=user) if auser_available else None
    downstream = AsyncMock(return_value=HttpResponse("ok"))
    with override_settings(**options):
        middleware = RateLimitMiddleware(downstream)
        with patch.object(
            middleware._storage, "check_async", return_value=SlidingWindowResult(False, 1, 30)
        ) as check:
            if auser_available:
                response = await middleware(request)
                assert response.status_code == 200
                request.auser.assert_awaited_once_with()
                assert ":user:" in check.call_args.args[0]
                assert "verified" not in check.call_args.args[0]
                downstream.assert_awaited_once_with(request)
            else:
                with pytest.raises(ImproperlyConfigured, match="request.auser"):
                    await middleware(request)
                check.assert_not_called()
                downstream.assert_not_called()


@pytest.mark.asyncio
async def test_async_django_path_exemption_bypasses_storage():
    request = RequestFactory().get("/health")
    with override_settings(RATELIMIT_EXEMPT_PATHS=("/health",)):
        middleware = RateLimitMiddleware(AsyncMock(return_value=HttpResponse("healthy")))
        with patch.object(middleware._storage, "check_async") as check:
            response = await middleware(request)
        assert response.status_code == 200 and response.content == b"healthy"
        check.assert_not_called()


@pytest.mark.parametrize(
    "scope",
    [
        {"type": "lifespan"},
        {"type": "http", "path": "/health"},
        {"type": "websocket", "path": "/health"},
    ],
)
@pytest.mark.asyncio
async def test_asgi_exemptions_and_nonrequest_scopes_pass_through(scope):
    with override_settings(RATELIMIT_EXEMPT_PATHS=("/health",)):
        app, receive, send = AsyncMock(return_value="passed"), AsyncMock(), AsyncMock()
        middleware = ASGIRateLimitMiddleware(app)
        with patch.object(middleware._storage, "check_async") as check:
            assert await middleware(scope, receive, send) == "passed"
        app.assert_awaited_once_with(scope, receive, send)
        check.assert_not_called()


def test_invalid_utf8_forwarded_header_falls_back_to_socket_peer():
    with override_settings(
        RATELIMIT_TRUST_X_FORWARDED_FOR=True, RATELIMIT_TRUSTED_PROXIES=("192.0.2.31",)
    ):
        middleware = ASGIRateLimitMiddleware(AsyncMock())
        scope = {
            "client": ("192.0.2.31", 8000),
            "headers": [(b"x-forwarded-for", b"198.51.100.1\xff")],
        }
        assert middleware._get_client_ip(scope) == "192.0.2.31"


@pytest.mark.parametrize("limited", [False, True])
@pytest.mark.asyncio
async def test_asgi_headers_can_be_disabled_without_losing_retry_after(limited):
    messages = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    with override_settings(RATELIMIT_ENABLE_HEADERS=False):
        middleware = ASGIRateLimitMiddleware(app)
        with patch.object(
            middleware._storage, "check_async", return_value=SlidingWindowResult(limited, 2, 7)
        ):
            await middleware(
                {"type": "http", "path": "/api"},
                AsyncMock(),
                AsyncMock(side_effect=messages.append),
            )
    assert messages[0]["status"] == (429 if limited else 200)
    headers = dict(messages[0]["headers"])
    assert not any(key.startswith(b"x-ratelimit-") for key in headers)
    assert headers.get(b"retry-after") == (b"7" if limited else None)


@pytest.mark.parametrize("fail_open", [False, True])
@pytest.mark.asyncio
async def test_asgi_policy_storage_failure_uses_policy_quota_and_failure_setting(fail_open, caplog):
    messages = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200})
        await send({"type": "http.response.body", "body": b"ok"})

    with override_settings(
        RATELIMIT_FAIL_OPEN=fail_open,
        RATELIMIT_POLICIES=[
            {"NAME": "api", "PATH": "/api", "LIMITS": [{"IDENTITY": "ip", "RATE": 5, "WINDOW": 13}]}
        ],
    ):
        middleware = ASGIRateLimitMiddleware(app)
        with patch.object(middleware._storage, "check_async", side_effect=StorageError("secret")):
            await middleware(
                {"type": "http", "path": "/api"},
                AsyncMock(),
                AsyncMock(side_effect=messages.append),
            )
    assert messages[0]["status"] == (200 if fail_open else 429)
    headers = dict(messages[0]["headers"])
    assert headers[b"x-ratelimit-limit"] == b"5"
    assert headers[b"x-ratelimit-reset"] == b"13"
    assert headers[b"x-ratelimit-remaining"] == (b"5" if fail_open else b"0")
    if not fail_open:
        assert headers[b"retry-after"] == b"13"
    assert "ASGI policy check" in caplog.text and "secret" not in caplog.text


@pytest.mark.asyncio
async def test_websocket_handshake_and_message_limiting_can_both_be_disabled():
    app, receive, send = AsyncMock(), AsyncMock(), AsyncMock()
    scope = {"type": "websocket", "path": "/socket"}
    with override_settings(RATELIMIT_WS_HANDSHAKE=False, RATELIMIT_WS_MSG_RATE=0):
        middleware = ASGIRateLimitMiddleware(app)
        with patch.object(middleware._storage, "check_async") as check:
            await middleware(scope, receive, send)
        check.assert_not_called()
        app.assert_awaited_once_with(scope, receive, send)


@pytest.mark.parametrize(
    "resolver",
    [
        None,
        "tests.test_configuration_edges.conf",
        "tests.test_configuration_edges.async_resolver",
        "tests.test_configuration_edges.async_callable",
    ],
)
def test_drf_custom_identity_resolver_must_be_present_and_synchronous(resolver):
    class CustomThrottle(RateLimitThrottle):
        identity_mode = "custom"
        identity_resolver = resolver

    with pytest.raises(ImproperlyConfigured, match="identity|resolver"):
        CustomThrottle()
