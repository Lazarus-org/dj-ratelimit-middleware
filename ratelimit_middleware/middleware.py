from __future__ import annotations

import json
import logging
from typing import Awaitable, Callable, Optional, Union

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.http import HttpRequest, HttpResponse, HttpResponseBase
from django.core.exceptions import ImproperlyConfigured
from django.utils.functional import SimpleLazyObject
from django.utils.translation import gettext_lazy as _

from .constants import IDENTITY_USER
from .conf import get_ratelimit_settings
from .identity import client_ip, is_exempt_path
from .principals import choose_identity, principal_key
from .policies import PolicyDecision, match_policy
from .policy_admission import admit_sync, admit_async
from django.utils.module_loading import import_string
from .sliding_window import SlidingWindowResult
from .storage import StorageError, make_storage

logger = logging.getLogger(__name__)


class BaseRateLimit:
    """Shared helpers for Django and ASGI rate limit middleware.

    This base class contains only framework-independent behavior: settings
    loading, client identity detection, exemption checks, cache-key generation,
    and HTTP 429 response building.
    """

    def __init__(self) -> None:
        """Load rate-limit settings once when the middleware is instantiated."""
        self.cfg = get_ratelimit_settings()
        self._storage = make_storage(self.cfg)
        self._identity_resolver = (
            import_string(self.cfg.identity_resolver) if self.cfg.identity_resolver else None
        )

    def _client_ip_from_meta(self, request: HttpRequest) -> str:
        """Resolve the client from the socket peer and configured trusted chain."""
        return client_ip(
            request.META.get("REMOTE_ADDR"),
            request.META.get("HTTP_X_FORWARDED_FOR"),
            trust_forwarded=self.cfg.trust_x_forwarded_for,
            trusted_proxies=self.cfg.trusted_proxies,
        )

    def is_exempt_request(self, request: HttpRequest) -> bool:
        """Only exact paths or explicit subtrees and canonical IPs are exempt."""
        return is_exempt_path(request.path_info, self.cfg.exempt_paths) or (
            bool(self.cfg.exempt_ips) and self._client_ip_from_meta(request) in self.cfg.exempt_ips
        )

    def key_for_request(self, request: HttpRequest, suffix: str = "http") -> str:
        """Resolve an opt-in principal; IP remains the no-authentication default."""
        user = (
            getattr(request, IDENTITY_USER, None)
            if self.cfg.identity_mode == IDENTITY_USER
            else None
        )
        identity = choose_identity(
            self.cfg.identity_mode, request, user=user, resolver=self._identity_resolver
        )
        return principal_key(suffix, self._client_ip_from_meta(request), identity)

    async def async_key_for_request(self, request: HttpRequest, suffix: str = "http") -> str:
        """Obtain Django session principals using its async API when available."""
        user = None
        if self.cfg.identity_mode == IDENTITY_USER:
            # Prefer an already-verified principal supplied by upstream custom
            # authentication. This avoids fetching the session user again.
            candidate = getattr(request, IDENTITY_USER, None)
            if candidate is not None and type(candidate) is not SimpleLazyObject:
                user = candidate
            else:
                auser = getattr(request, "auser", None)
                if not callable(auser):
                    raise ImproperlyConfigured(
                        "Async user limiting needs a resolved request.user or request.auser()."
                    )
                user = await auser()
        identity = choose_identity(
            self.cfg.identity_mode, request, user=user, resolver=self._identity_resolver
        )
        return principal_key(suffix, self._client_ip_from_meta(request), identity)

    def add_headers(
        self,
        response: HttpResponseBase,
        count: int,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        *,
        reset_after: Optional[int] = None,
    ) -> None:
        """Attach optional rate-limit headers to an HTTP response."""
        if not self.cfg.enable_headers:
            return

        limit = self.cfg.rate if limit is None else limit
        window = self.cfg.window if window is None else window
        response["X-RateLimit-Limit"] = str(limit)
        response["X-RateLimit-Remaining"] = str(max(0, limit - count))
        response["X-RateLimit-Reset"] = str(window if reset_after is None else reset_after)

    def build_429(
        self,
        count: int,
        limit: Optional[int] = None,
        window: Optional[int] = None,
        *,
        reset_after: Optional[int] = None,
    ) -> HttpResponse:
        """Build a translated JSON ``429 Too Many Requests`` response."""
        limit = self.cfg.rate if limit is None else limit
        window = self.cfg.window if window is None else window
        retry_after = window if reset_after is None else reset_after

        # Keep user-facing strings lazy so Django can translate them at render
        # time according to the active language.
        payload = {
            "error": str(_("Rate limit exceeded")),
            "detail": str(_("Please try again in %(seconds)s seconds") % {"seconds": retry_after}),
        }
        response = HttpResponse(
            json.dumps(payload),
            status=429,
            content_type="application/json",
        )
        response["Retry-After"] = str(retry_after)
        self.add_headers(response, count, limit, window, reset_after=retry_after)
        return response


class RateLimitMiddleware(BaseRateLimit):
    """Django middleware for WSGI and ASGI with pluggable rate-limit storage."""

    sync_capable = True
    async_capable = True

    def __init__(
        self,
        get_response: Callable[[HttpRequest], Union[HttpResponseBase, Awaitable[HttpResponseBase]]],
    ) -> None:
        """Initialize middleware and detect whether Django is running async."""
        super().__init__()
        self.get_response = get_response
        self.async_mode = iscoroutinefunction(get_response)
        if self.async_mode:
            markcoroutinefunction(self)

    def _selected_policy(self, request: HttpRequest):
        return match_policy(self.cfg.policies, request.path_info, request.method)

    async def _policy_async_user(self, request: HttpRequest):
        """Resolve an authenticated Django user only when the policy needs it."""
        candidate = getattr(request, IDENTITY_USER, None)
        if candidate is not None and type(candidate) is not SimpleLazyObject:
            return candidate
        auser = getattr(request, "auser", None)
        if not callable(auser):
            raise ImproperlyConfigured(
                "Async user limiting needs a resolved request.user or request.auser()."
            )
        return await auser()

    def _failed(self, limit: int, window: int) -> PolicyDecision:
        return PolicyDecision(
            SlidingWindowResult(
                limited=not self.cfg.fail_open,
                count=0 if self.cfg.fail_open else limit + 1,
                reset_after=window,
            ),
            limit,
            window,
        )

    def _admit_sync(self, request: HttpRequest) -> PolicyDecision:
        """Admit the first matching policy, or the global default quota."""
        if self.is_exempt_request(request):
            return PolicyDecision(
                SlidingWindowResult(False, 0, self.cfg.window), self.cfg.rate, self.cfg.window
            )
        policy = self._selected_policy(request)
        try:
            if policy is not None:
                user = (
                    getattr(request, IDENTITY_USER, None)
                    if any(limit.identity == IDENTITY_USER for limit in policy.limits)
                    else None
                )
                return admit_sync(
                    self._storage,
                    policy,
                    "http",
                    request,
                    self._client_ip_from_meta(request),
                    user=user,
                    resolver=self._identity_resolver,
                )
            result = self._storage.check_sync(
                self.key_for_request(request), self.cfg.rate, self.cfg.window
            )
            return PolicyDecision(result, self.cfg.rate, self.cfg.window)
        except StorageError:
            logger.error("Storage error during sync rate limit check")
            return self._failed(
                policy.limits[0].rate if policy else self.cfg.rate,
                policy.limits[0].window if policy else self.cfg.window,
            )

    async def _admit_async(self, request: HttpRequest) -> PolicyDecision:
        if self.is_exempt_request(request):
            return PolicyDecision(
                SlidingWindowResult(False, 0, self.cfg.window), self.cfg.rate, self.cfg.window
            )
        policy = self._selected_policy(request)
        try:
            if policy is not None:
                user = (
                    await self._policy_async_user(request)
                    if any(limit.identity == IDENTITY_USER for limit in policy.limits)
                    else None
                )
                return await admit_async(
                    self._storage,
                    policy,
                    "http",
                    request,
                    self._client_ip_from_meta(request),
                    user=user,
                    resolver=self._identity_resolver,
                )
            result = await self._storage.check_async(
                await self.async_key_for_request(request), self.cfg.rate, self.cfg.window
            )
            return PolicyDecision(result, self.cfg.rate, self.cfg.window)
        except StorageError:
            logger.error("Storage error during async rate limit check")
            return self._failed(
                policy.limits[0].rate if policy else self.cfg.rate,
                policy.limits[0].window if policy else self.cfg.window,
            )

    def __call__(
        self, request: HttpRequest
    ) -> Union[HttpResponseBase, Awaitable[HttpResponseBase]]:
        """Route the request through the sync or async middleware path."""
        if self.async_mode:
            return self.__acall__(request)
        return self.__sync_call__(request)

    def __sync_call__(self, request: HttpRequest) -> HttpResponseBase:
        """Handle a synchronous request and add rate-limit headers."""
        decision = self._admit_sync(request)
        result = decision.result
        if result.limited:
            return self.build_429(
                result.count, decision.limit, decision.window, reset_after=result.reset_after
            )

        response = self.get_response(request)
        self.add_headers(
            response, result.count, decision.limit, decision.window, reset_after=result.reset_after
        )
        return response

    async def __acall__(self, request: HttpRequest) -> HttpResponseBase:
        """Handle an asynchronous request and add rate-limit headers."""
        decision = await self._admit_async(request)
        result = decision.result
        if result.limited:
            return self.build_429(
                result.count, decision.limit, decision.window, reset_after=result.reset_after
            )

        response = await self.get_response(request)
        self.add_headers(
            response, result.count, decision.limit, decision.window, reset_after=result.reset_after
        )
        return response


class ASGIRateLimitMiddleware(BaseRateLimit):
    """ASGI boundary middleware for HTTP requests and WebSocket traffic.

    Use this class when you want to protect an entire ASGI application before
    traffic reaches Django Channels, Starlette, or another ASGI app.
    """

    def __init__(self, app: Callable) -> None:
        """Store the wrapped ASGI application and configured storage adapter."""
        super().__init__()
        self.app = app

    def _get_header(self, scope, name: bytes) -> str:
        """Read only a single, well-formed header (reject ambiguous duplicates)."""
        matches = [value for key, value in scope.get("headers", []) if key.lower() == name]
        if len(matches) != 1:
            return ""
        try:
            return matches[0].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return ""

    def _get_client_ip(self, scope) -> str:
        """Use the same proxy-chain trust boundary as Django middleware."""
        peer = scope.get("client")
        return client_ip(
            peer[0] if peer else None,
            self._get_header(scope, b"x-forwarded-for"),
            trust_forwarded=self.cfg.trust_x_forwarded_for,
            trusted_proxies=self.cfg.trusted_proxies,
        )

    def _is_exempt(self, scope) -> bool:
        """Apply the shared exact/subtree matcher and canonical IP exemption."""
        return is_exempt_path(scope.get("path") or "/", self.cfg.exempt_paths) or (
            bool(self.cfg.exempt_ips) and self._get_client_ip(scope) in self.cfg.exempt_ips
        )

    def _key(self, scope, suffix: str) -> str:
        """Build a bucket from an ASGI-authenticated principal or peer IP."""
        user = scope.get(IDENTITY_USER) if self.cfg.identity_mode == IDENTITY_USER else None
        identity = choose_identity(
            self.cfg.identity_mode, scope, user=user, resolver=self._identity_resolver
        )
        return principal_key(suffix, self._get_client_ip(scope), identity)

    async def _check(self, key: str, limit: int, window: int) -> SlidingWindowResult:
        """Apply the chosen storage backend without blocking the event loop."""
        try:
            return await self._storage.check_async(key, limit, window)
        except StorageError:
            logger.error("Storage error during ASGI rate limit check")
            return SlidingWindowResult(
                limited=not self.cfg.fail_open,
                count=0 if self.cfg.fail_open else limit + 1,
                reset_after=window,
            )

    def _headers(
        self, count: int, limit: int, window: int, *, reset_after: Optional[int] = None
    ) -> list[tuple[bytes, bytes]]:
        """Return ASGI byte headers for rate-limit metadata."""
        if not self.cfg.enable_headers:
            return []
        return [
            (b"x-ratelimit-limit", str(limit).encode()),
            (b"x-ratelimit-remaining", str(max(0, limit - count)).encode()),
            (b"x-ratelimit-reset", str(window if reset_after is None else reset_after).encode()),
        ]

    def _too_many_requests_body(self, window: int) -> bytes:
        """Return translated JSON body for ASGI ``429`` responses."""
        payload = {
            "error": str(_("Rate limit exceeded")),
            "detail": str(_("Please try again in %(seconds)s seconds") % {"seconds": window}),
        }
        return json.dumps(payload).encode()

    async def __call__(self, scope, receive, send):
        """Rate-limit ASGI HTTP requests and WebSocket connections/messages."""
        scope_type = scope.get("type")
        if scope_type not in {"http", "websocket"} or self._is_exempt(scope):
            return await self.app(scope, receive, send)

        if scope_type == "http":
            policy = match_policy(
                self.cfg.policies, scope.get("path") or "/", scope.get("method") or "GET"
            )
            limit, window = self.cfg.rate, self.cfg.window
            if policy is not None:
                try:
                    decision = await admit_async(
                        self._storage,
                        policy,
                        "http",
                        scope,
                        self._get_client_ip(scope),
                        user=scope.get(IDENTITY_USER)
                        if any(limit.identity == IDENTITY_USER for limit in policy.limits)
                        else None,
                        resolver=self._identity_resolver,
                    )
                    result, limit, window = decision.result, decision.limit, decision.window
                except StorageError:
                    logger.error("Storage error during ASGI policy check")
                    limit, window = policy.limits[0].rate, policy.limits[0].window
                    result = SlidingWindowResult(
                        not self.cfg.fail_open, limit + 1 if not self.cfg.fail_open else 0, window
                    )
            else:
                result = await self._check(self._key(scope, "http"), limit, window)
            if result.limited:
                headers = [
                    (b"content-type", b"application/json"),
                    (b"retry-after", str(result.reset_after).encode()),
                ]
                headers += self._headers(
                    result.count, limit, window, reset_after=result.reset_after
                )
                await send({"type": "http.response.start", "status": 429, "headers": headers})
                await send(
                    {
                        "type": "http.response.body",
                        "body": self._too_many_requests_body(result.reset_after),
                    }
                )
                return

            headers_to_add = self._headers(
                result.count, limit, window, reset_after=result.reset_after
            )

            async def send_wrapper(message):
                if message["type"] == "http.response.start" and headers_to_add:
                    message = {
                        **message,
                        "headers": [*message.get("headers", ()), *headers_to_add],
                    }
                await send(message)

            return await self.app(scope, receive, send_wrapper)

        if self.cfg.ws_handshake:
            decision = await self._check(
                self._key(scope, "ws:handshake"),
                self.cfg.rate,
                self.cfg.window,
            )
            if decision.limited:
                # 4408 is commonly used by ASGI apps to mean policy/rate-limit
                # violation, while still being an application-defined code.
                await send({"type": "websocket.close", "code": 4408})
                return

        if self.cfg.ws_msg_rate <= 0:
            return await self.app(scope, receive, send)

        msg_key = self._key(scope, "ws:msg")

        async def receive_wrapper():
            """Rate-limit individual WebSocket receive events."""
            event = await receive()
            if event["type"] == "websocket.receive":
                decision = await self._check(
                    msg_key,
                    self.cfg.ws_msg_rate,
                    self.cfg.ws_msg_window,
                )
                if decision.limited:
                    await send({"type": "websocket.close", "code": 4408})
                    return {"type": "websocket.disconnect", "code": 4408}
            return event

        return await self.app(scope, receive_wrapper, send)
