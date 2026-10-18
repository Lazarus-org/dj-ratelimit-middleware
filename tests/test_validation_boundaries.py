"""Configuration boundaries and real framework lifecycle validation."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from django.core.checks import Error
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import Client, RequestFactory, override_settings
from redis.exceptions import AuthenticationError, ConnectionError, MaxConnectionsError, TimeoutError
from rest_framework.authentication import BaseAuthentication, SessionAuthentication
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

from ratelimit_middleware.checks import ratelimit_settings_check
from ratelimit_middleware.conf import get_ratelimit_settings
from ratelimit_middleware.drf import RateLimitThrottle
from ratelimit_middleware.middleware import ASGIRateLimitMiddleware, RateLimitMiddleware
from ratelimit_middleware.sliding_window import SlidingWindowResult
from ratelimit_middleware.storage import StorageError


INVALID = {
    "RATELIMIT_RATE": [None, False, 0, -1, 1.5, "1", [], {}],
    "RATELIMIT_WINDOW": [None, True, 0, -1, 1.5, "1", [], {}],
    "RATELIMIT_ALGORITHM": [None, True, 1, [], {}, "unknown"],
    "RATELIMIT_IDENTITY": [None, True, 1, [], {}, "unknown"],
    "RATELIMIT_STORAGE": [False, 1, [], "cache", {}, {"BACKEND": "cache", "TYPO": 1}],
    "RATELIMIT_POLICIES": [None, True, 1, "rule", {}, [None], [{"NAME": "bad"}]],
    "RATELIMIT_EXEMPT_PATHS": [None, True, "/", {}, [1], ["/a//b"], ["/../b"]],
    "RATELIMIT_EXEMPT_IPS": [None, True, "127.0.0.1", {}, [1], ["bad"]],
    "RATELIMIT_TRUSTED_PROXIES": [None, True, "127.0.0.1", {}, [1], ["::/0"]],
    "RATELIMIT_REDIS_URL": [False, 1, [], {}, "http://secret@host"],
    "RATELIMIT_REDIS_TIMEOUT": [None, False, 0, -1, "1", [], {}, float("inf")],
    "RATELIMIT_WS_MSG_RATE": [None, True, -1, 1.5, "1", [], {}],
    "RATELIMIT_WS_MSG_WINDOW": [None, True, 0, -1, "1", [], {}],
    **{
        name: [None, 0, 1, "false", [], {}]
        for name in (
            "RATELIMIT_FAIL_OPEN",
            "RATELIMIT_ENABLE_HEADERS",
            "RATELIMIT_WS_HANDSHAKE",
            "RATELIMIT_TRUST_X_FORWARDED_FOR",
        )
    },
    "RATELIMIT_IDENTITY_RESOLVER": [False, 1, [], {}, "missing.resolver"],
}


@pytest.mark.parametrize(
    "name,value", [(name, value) for name, values in INVALID.items() for value in values]
)
def test_invalid_types_and_boundaries_block_all_adapters(name, value):
    with override_settings(**{name: value}):
        issues = ratelimit_settings_check(None)
        assert issues and all(isinstance(issue, Error) for issue in issues)
        for factory in (
            lambda: RateLimitMiddleware(lambda r: HttpResponse()),
            lambda: ASGIRateLimitMiddleware(AsyncMock()),
            RateLimitThrottle,
        ):
            with pytest.raises(ImproperlyConfigured):
                factory()


@pytest.mark.parametrize(
    "exception", [ConnectionError, TimeoutError, AuthenticationError, MaxConnectionsError]
)
@pytest.mark.parametrize("fail_open", [True, False])
@pytest.mark.asyncio
async def test_storage_failure_taxonomy_sync_async_and_recovery(exception, fail_open):
    request = RequestFactory().get("/private", REMOTE_ADDR="192.0.2.201")

    async def app(request):
        return HttpResponse("ok")

    with override_settings(RATELIMIT_FAIL_OPEN=fail_open):
        for async_mode in (False, True):
            middleware = RateLimitMiddleware(app if async_mode else lambda r: HttpResponse("ok"))
            method = "_get_async_redis" if async_mode else "_get_sync_redis"
            with patch.object(middleware._storage, method, side_effect=exception("temporary")):
                response = await middleware(request) if async_mode else middleware(request)
            assert response.status_code == (200 if fail_open else 429)
            with patch.object(
                middleware._storage,
                "check_async" if async_mode else "check_sync",
                return_value=SlidingWindowResult(False, 1, 60),
            ):
                response = await middleware(request) if async_mode else middleware(request)
            assert response.status_code == 200


@pytest.mark.asyncio
async def test_websocket_protocol_connect_messages_and_disconnect():
    events = iter(
        [
            {"type": "websocket.connect"},
            {"type": "websocket.receive", "text": "one"},
            {"type": "websocket.receive", "text": "two"},
        ]
    )
    sent = []

    async def app(scope, receive, send):
        assert await receive() == {"type": "websocket.connect"}
        await send({"type": "websocket.accept"})
        assert (await receive())["text"] == "one"
        assert await receive() == {"type": "websocket.disconnect", "code": 4408}

    async def receive():
        return next(events)

    async def send(event):
        sent.append(event)

    with override_settings(RATELIMIT_WS_MSG_RATE=1, RATELIMIT_STORAGE={"BACKEND": "cache"}):
        middleware = ASGIRateLimitMiddleware(app)
        await middleware(
            {"type": "websocket", "path": "/ws", "client": ("192.0.2.210", 12)}, receive, send
        )
    assert sent == [{"type": "websocket.accept"}, {"type": "websocket.close", "code": 4408}]


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_open", [True, False])
async def test_asgi_failure_and_disconnect_paths(fail_open, caplog):
    sent = []
    app = AsyncMock()
    with override_settings(RATELIMIT_FAIL_OPEN=fail_open):
        middleware = ASGIRateLimitMiddleware(app)
        middleware._storage.check_async = AsyncMock(side_effect=StorageError("credential-secret"))
        await middleware(
            {"type": "http", "path": "/private", "client": ("192.0.2.211", 12)},
            AsyncMock(),
            AsyncMock(side_effect=lambda event: sent.append(event)),
        )
        assert app.await_count == int(fail_open)
        if not fail_open:
            assert sent[0]["status"] == 429
    assert "credential-secret" not in caplog.text


@pytest.mark.django_db
def test_real_django_session_identity_and_drf_session_authentication(django_user_model):
    user = django_user_model.objects.create_user(username="limiter-validation")
    middleware = [
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "ratelimit_middleware.middleware.RateLimitMiddleware",
    ]
    with override_settings(
        MIDDLEWARE=middleware,
        RATELIMIT_IDENTITY="user",
        RATELIMIT_RATE=1,
        RATELIMIT_STORAGE={"BACKEND": "cache"},
    ):
        client = Client()
        client.force_login(user)
        assert client.get("/ok/").status_code == 200
        assert client.get("/ok/").status_code == 429

        class View(APIView):
            authentication_classes = [SessionAuthentication]
            throttle_classes = [RateLimitThrottle]

            def get(self, request):
                return Response({"id": request.user.pk})

        raw = APIRequestFactory().get("/session")
        raw.user = user
        assert View.as_view()(raw).status_code == 200
        response = View.as_view()(raw)
        assert response.status_code == 429 and response["Retry-After"].isdigit()


def test_custom_drf_authentication_runs_once_and_does_not_query_database():
    calls = []

    class VerifiedAuthentication(BaseAuthentication):
        def authenticate(self, request):
            calls.append(request)
            return SimpleNamespace(pk="verified-token-id", is_authenticated=True), "opaque-token"

    class View(APIView):
        authentication_classes = [VerifiedAuthentication]
        throttle_classes = [RateLimitThrottle]

        def get(self, request):
            return Response({"ok": True})

    with override_settings(RATELIMIT_STORAGE={"BACKEND": "cache"}, RATELIMIT_RATE=1):
        view = View.as_view()
        factory = APIRequestFactory()
        assert view(factory.get("/token")).status_code == 200
        assert view(factory.get("/token")).status_code == 429
        assert len(calls) == 2


def test_downstream_exceptions_propagate_and_do_not_refund_quota():
    with override_settings(RATELIMIT_STORAGE={"BACKEND": "cache"}, RATELIMIT_RATE=1):
        middleware = RateLimitMiddleware(
            lambda request: (_ for _ in ()).throw(ValueError("view failed"))
        )
        request = RequestFactory().get("/private", REMOTE_ADDR="192.0.2.221")
        with pytest.raises(ValueError, match="view failed"):
            middleware(request)
        assert middleware(request).status_code == 429


def test_valid_minimum_and_disabled_websocket_message_limit():
    with override_settings(
        RATELIMIT_RATE=1, RATELIMIT_WINDOW=1, RATELIMIT_WS_MSG_RATE=0, RATELIMIT_WS_MSG_WINDOW=1
    ):
        cfg = get_ratelimit_settings()
        assert (cfg.rate, cfg.window, cfg.ws_msg_rate) == (1, 1, 0)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize(
    "failure", [ConnectionError, TimeoutError, AuthenticationError, MaxConnectionsError]
)
@pytest.mark.asyncio
async def test_group_storage_failures_are_normalized(async_mode, failure):
    from ratelimit_middleware.policies import WindowQuota
    from ratelimit_middleware.storage import RedisStorage

    storage = RedisStorage("redis://127.0.0.1:16379/0", 1)
    quotas = (WindowQuota("one", 1, 60), WindowQuota("two", 2, 60))
    with patch.object(
        storage,
        "_get_async_redis" if async_mode else "_get_sync_redis",
        side_effect=failure("secret"),
    ):
        with pytest.raises(StorageError):
            if async_mode:
                await storage.check_many_async(quotas)
            else:
                storage.check_many_sync(quotas)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.asyncio
async def test_cache_eviction_race_retries_without_silently_admitting(async_mode):
    from unittest.mock import MagicMock
    from ratelimit_middleware.storage import DjangoCacheStorage

    backend = MagicMock()
    backend.add.side_effect = [False, False]
    backend.incr.side_effect = [ValueError("evicted"), 3]
    backend.aadd = AsyncMock(side_effect=[False, False])
    backend.aincr = AsyncMock(side_effect=[ValueError("evicted"), 3])
    with patch("ratelimit_middleware.storage.caches", {"default": backend}):
        storage = DjangoCacheStorage("default")
        result = (
            await storage.check_async("race", 2, 60)
            if async_mode
            else storage.check_sync("race", 2, 60)
        )
        assert result.limited and result.count == 3


@pytest.mark.parametrize("fail_open", [True, False])
def test_drf_storage_failure_is_redacted_and_respects_policy(fail_open, caplog):
    with override_settings(RATELIMIT_FAIL_OPEN=fail_open):
        throttle = RateLimitThrottle()
        with patch.object(
            throttle._storage, "check_sync", side_effect=StorageError("credential-secret")
        ):
            request = APIRequestFactory().get("/private")
            request.user = None
            assert throttle.allow_request(request, None) is fail_open
            assert throttle.wait() == 60
    assert "credential-secret" not in caplog.text
