"""Pure identity tests: no Django/Redis imports or external services needed."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from ratelimit_middleware.principals import (
    InvalidPrincipal,
    authenticated_identity,
    choose_identity,
    principal_key,
)


def test_ip_key_unchanged_for_existing_buckets():
    assert principal_key("http", "198.51.100.4", None) == "ratelimit:http:198.51.100.4"


def test_authenticated_user_identity_and_namespace():
    user = SimpleNamespace(is_authenticated=True, pk=123)
    assert authenticated_identity(user) == ("user", "123")
    key = principal_key("http", "198.51.100.4", authenticated_identity(user))
    assert key.startswith("ratelimit:http:user:")
    assert "123" not in key
    assert "198.51.100.4" not in key
    assert len(key) < 100


def test_uuid_identity_stable():
    identifier = uuid4()
    assert principal_key("http", "x", ("user", identifier)) == principal_key(
        "http", "x", ("user", str(identifier))
    )


def test_namespace_prevents_cross_principal_collisions():
    assert principal_key("http", "x", ("user", 12)) != principal_key("http", "x", ("apikey", 12))
    assert principal_key("http", "x", ("user", 12)) != principal_key(
        "ws:handshake", "x", ("user", 12)
    )


def test_anonymous_user_falls_back_to_ip():
    user = SimpleNamespace(is_authenticated=False, pk=None)
    assert choose_identity("user", object(), user=user) is None
    assert principal_key("http", "192.0.2.5", choose_identity("user", object(), user=user)) == (
        "ratelimit:http:192.0.2.5"
    )


def test_ip_mode_does_not_access_authentication():
    class Explosive:
        @property
        def is_authenticated(self):
            raise AssertionError("IP mode must not evaluate lazy Django request.user")

    assert choose_identity("ip", object(), user=Explosive()) is None


def test_custom_resolver_with_verified_principal():
    context = {"verified_api_key_id": "key:secret-metadata"}
    identity = choose_identity(
        "custom", context, resolver=lambda c: ("apikey", c["verified_api_key_id"])
    )
    key = principal_key("http", "192.0.2.1", identity)
    assert "secret-metadata" not in key
    assert key.startswith("ratelimit:http:apikey:")


def test_custom_none_explicitly_falls_back_to_ip():
    assert choose_identity("custom", object(), resolver=lambda context: None) is None


@pytest.mark.parametrize(
    "identity",
    [
        ("evil:key", "123"),
        ("", "123"),
        ("CAPS", "123"),
        ("user", ""),
        ("user", "x" * 513),
        ("user", True),
        ("user", 1.23),
        ("user", "new\nline"),
        "unstructured",
        ("user", "x", "y"),
    ],
)
def test_rejects_invalid_identity_and_prevents_key_injection(identity):
    with pytest.raises(InvalidPrincipal):
        principal_key("http", "192.0.2.1", identity)


def test_authenticated_user_must_have_stable_pk():
    with pytest.raises(InvalidPrincipal):
        authenticated_identity(SimpleNamespace(is_authenticated=True, pk=None))


def test_invalid_custom_resolver_cannot_silently_fallback():
    with pytest.raises(InvalidPrincipal):
        choose_identity("custom", object(), resolver=lambda _: ("user", ""))


def test_custom_missing_resolver_is_error():
    with pytest.raises(InvalidPrincipal):
        choose_identity("custom", object())
