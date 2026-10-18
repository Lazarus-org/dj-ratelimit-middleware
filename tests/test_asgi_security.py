"""ASGI must use the same trusted-proxy identity and exclusions as Django."""

from django.test import override_settings

from ratelimit_middleware.middleware import ASGIRateLimitMiddleware


async def _app(scope, receive, send):
    return None


def test_asgi_rightmost_untrusted_identity_and_same_path_behavior():
    with override_settings(
        RATELIMIT_TRUST_X_FORWARDED_FOR=True,
        RATELIMIT_TRUSTED_PROXIES=["10.0.0.0/8"],
        RATELIMIT_EXEMPT_PATHS=["/metrics"],
        RATELIMIT_EXEMPT_IPS=["2001:db8::1"],
    ):
        middleware = ASGIRateLimitMiddleware(_app)
        scope = {
            "type": "http",
            "path": "/metrics-leak",
            "client": ("10.0.0.5", 8080),
            "headers": [(b"x-forwarded-for", b"spoofed, 198.51.100.10")],
        }
        assert middleware._get_client_ip(scope) == "198.51.100.10"
        assert not middleware._is_exempt(scope)
        assert middleware._key(scope, "http") == "ratelimit:http:198.51.100.10"
        assert middleware._is_exempt({**scope, "path": "/metrics"})
        assert middleware._is_exempt({**scope, "client": ("2001:0db8::1", 8080), "headers": []})


def test_asgi_duplicate_forwarding_headers_cannot_select_attacker_value():
    with override_settings(
        RATELIMIT_TRUST_X_FORWARDED_FOR=True,
        RATELIMIT_TRUSTED_PROXIES=["10.0.0.0/8"],
    ):
        middleware = ASGIRateLimitMiddleware(_app)
        scope = {
            "type": "http",
            "path": "/foo",
            "client": ("10.0.0.5", 8080),
            "headers": [
                (b"x-forwarded-for", b"1.1.1.1"),
                (b"x-forwarded-for", b"2.2.2.2"),
            ],
        }
        assert middleware._get_client_ip(scope) == "10.0.0.5"
