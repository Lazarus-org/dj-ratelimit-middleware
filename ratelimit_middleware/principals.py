"""Trusted request-principal identification; never interpret authentication headers.

Identity creation is storage-independent and uses no I/O. Django/DRF/ASGI
adapters are responsible for supplying an already authenticated principal.
"""

from __future__ import annotations

from .constants import IDENTITY_CUSTOM, IDENTITY_IP, IDENTITY_USER

import hashlib
import re
from collections.abc import Callable
from uuid import UUID


_MAX_IDENTIFIER_LENGTH = 512
_NAMESPACE_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")


class InvalidPrincipal(ValueError):
    """A configured identity resolver returned an invalid/untrusted identity."""


def authenticated_identity(user: object) -> tuple[str, str] | None:
    """Return a stable identity for an authenticated principal, or None.

    Accessing a Django lazy ``request.user`` can evaluate session auth; callers
    must only do so when user-mode limiting has been explicitly selected.
    """
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    pk = getattr(user, "pk", None)
    if pk is None or isinstance(pk, bool) or not isinstance(pk, (str, int, UUID)):
        raise InvalidPrincipal("Authenticated user must have a stable string, integer, or UUID pk")
    return IDENTITY_USER, _validate_identifier(pk)


def _validate_identifier(identifier: object) -> str:
    if isinstance(identifier, bool) or not isinstance(identifier, (str, int, UUID)):
        raise InvalidPrincipal("Identity value must be a string, integer, or UUID")
    value = str(identifier)
    if not value or len(value) > _MAX_IDENTIFIER_LENGTH or any(ord(c) < 32 for c in value):
        raise InvalidPrincipal(
            "Identity value must be nonempty, bounded, and free of control characters"
        )
    return value


def principal_key(suffix: str, ip: str, identity: tuple[str, object] | None) -> str:
    """Produce a stable, bounded key without exposing user identifiers."""
    if identity is None:
        return f"ratelimit:{suffix}:{ip}"
    if not isinstance(identity, tuple) or len(identity) != 2:
        raise InvalidPrincipal("Custom identity must be a (namespace, identifier) tuple")
    namespace, value = identity
    if not isinstance(namespace, str) or not _NAMESPACE_PATTERN.fullmatch(namespace):
        raise InvalidPrincipal("Identity namespace must be 1-32 lowercase safe characters")
    identifier = _validate_identifier(value)
    digest = hashlib.sha256(f"{namespace}\x00{identifier}".encode("utf-8")).hexdigest()
    return f"ratelimit:{suffix}:{namespace}:{digest}"


def choose_identity(
    mode: str,
    context: object,
    *,
    user: object = None,
    resolver: Callable[[object], tuple[str, object] | None] | None = None,
) -> tuple[str, object] | None:
    """Use a trusted user or explicitly configured resolver; None means IP fallback.

    Custom resolvers MUST return verified principal identifiers, not arbitrary
    raw authorization headers, and MUST be synchronous/nonblocking.
    """
    if mode == IDENTITY_IP:
        return None
    if mode == IDENTITY_USER:
        return authenticated_identity(user)
    if mode == IDENTITY_CUSTOM:
        if resolver is None:
            raise InvalidPrincipal("Custom identity resolver is not configured")
        identity = resolver(context)
        if identity is not None:
            if not isinstance(identity, tuple) or len(identity) != 2:
                raise InvalidPrincipal("Custom identity must be a (namespace, identifier) tuple")
            # Validate eagerly, before any storage access or fallback decision.
            principal_key("validation", "unused", identity)
        return identity
    raise InvalidPrincipal("Unsupported rate-limit identity mode")
