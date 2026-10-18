"""Django settings and validation for the rate-limit middleware."""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from inspect import iscoroutinefunction
from ipaddress import ip_network
from urllib.parse import parse_qsl, urlsplit

from django.conf import settings
from django.core.cache.backends.base import BaseCache
from django.core.cache.backends.dummy import DummyCache
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from .constants import (
    ALGORITHM_SLIDING_WINDOW,
    ALGORITHM_TOKEN_BUCKET,
    ALGORITHMS,
    DJANGO_MIDDLEWARE_PATH,
    DJANGO_REDIS_CACHE_BACKEND,
    DJANGO_REDIS_CACHE_BACKENDS,
    IDENTITY_CUSTOM,
    IDENTITY_IP,
    IDENTITY_MODES,
    MAX_RATE,
    MAX_WINDOW,
    MAX_TOKEN_BUCKET_RATE,
    MAX_TOKEN_BUCKET_WINDOW,
    REDIS_URL_SCHEMES,
    SETTING_NAMES,
    STORAGE_BACKENDS,
    STORAGE_CACHE,
    STORAGE_REDIS,
)
from .identity import Network, parse_address
from .policies import PolicyConfigurationError, RateLimitPolicy, compile_policies


@dataclass(frozen=True)
class RateLimitSettings:
    rate: int
    window: int
    exempt_paths: tuple[str, ...]
    exempt_ips: tuple[str, ...]
    enable_headers: bool
    redis_url: str
    storage_backend: str
    cache_alias: str
    redis_timeout: float
    fail_open: bool
    trust_x_forwarded_for: bool
    trusted_proxies: tuple[Network, ...]
    ws_handshake: bool
    ws_msg_rate: int
    ws_msg_window: int
    identity_mode: str
    identity_resolver: str | None
    policies: tuple[RateLimitPolicy, ...]
    algorithm: str = ALGORITHM_SLIDING_WINDOW


def _positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def _positive_finite(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and value > 0
    except OverflowError:
        return False


def _valid_redis_url(url: object) -> bool:
    """Check supported Redis URL structure without connecting or leaking secrets.

    Redis-py supports additional connection query options; their backend-specific
    semantics remain Redis-py's responsibility. The database index, however,
    must not be silently interpreted as a different database.
    """
    if (
        not isinstance(url, str)
        or not url.startswith(REDIS_URL_SCHEMES)
        or not url
        or url != url.strip()
        or any(ord(char) <= 32 or ord(char) == 127 for char in url)
    ):
        return False
    try:
        parsed = urlsplit(url)
        if parsed.fragment or parsed.scheme not in {"redis", "rediss", "unix"}:
            return False
        if parsed.scheme == "unix":
            if parsed.netloc or not parsed.path.startswith("/") or parsed.path == "/":
                return False
        else:
            if not parsed.hostname or parsed.netloc.endswith(":"):
                return False
            if parsed.port is not None and not (1 <= parsed.port <= 65535):
                return False
            if parsed.path not in ("", "/") and not _valid_redis_db(parsed.path[1:]):
                return False
        # Python 3.10 rejects an empty query with strict_parsing=True.
        query = (
            parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            if parsed.query
            else []
        )
        for key, value in query:
            if key in {"socket_timeout", "socket_connect_timeout", "timeout"}:
                if not _positive_finite(float(value)):
                    return False
            elif key in {"max_connections", "socket_read_size"}:
                if int(value) <= 0:
                    return False
        # Use the installed client's public URL parser for its version-specific
        # typed options. Parsing performs no connection or credential logging.
        try:
            from redis.connection import Connection, parse_url
        except ImportError:
            pass  # The redis extra is checked when creating native storage.
        else:
            options = parse_url(url)
            connection_class = options.pop("connection_class", Connection)
            options.pop("max_connections", None)  # A pool option, not a connection argument.
            try:
                # Construction validates supported kwargs/protocol without
                # opening a socket; connect() remains lazy in redis-py.
                connection_class(**options)
            except Exception:
                return False
        database_options = [value for key, value in query if key == "db"]
        return len(database_options) <= 1 and all(_valid_redis_db(db) for db in database_options)
    except (ValueError, TypeError, OverflowError):  # malformed URL/query arguments
        return False


def _valid_redis_db(value: str) -> bool:
    # Redis database numbers are nonnegative decimal indices; bound their
    # representation so pathological inputs fail during configuration checks.
    return (
        bool(value)
        and len(value) <= 10
        and value.isascii()
        and value.isdecimal()
        and int(value) <= 2_147_483_647
    )


def _selected_cache_info(alias: str, issues: list[tuple[str, str]]) -> Mapping | None:
    """Validate a selected Django cache backend without connecting to its server."""
    caches_setting = getattr(settings, "CACHES", None)
    cache_info = caches_setting.get(alias) if isinstance(caches_setting, Mapping) else None
    if not isinstance(cache_info, Mapping):
        issues.append(("ratelimit.E013", f"Unknown Django cache alias: {alias}."))
        return None
    backend_path = cache_info.get("BACKEND")
    if not isinstance(backend_path, str) or not backend_path.strip():
        issues.append(
            (
                "ratelimit.E013",
                f"CACHES[{alias!r}].BACKEND must be a Django cache backend import path.",
            )
        )
        return None
    try:
        backend_class = import_string(backend_path)
        if not isinstance(backend_class, type) or not issubclass(backend_class, BaseCache):
            raise TypeError("not a Django BaseCache subclass")
    except Exception as exc:
        issues.append(
            (
                "ratelimit.E013",
                f"CACHES[{alias!r}].BACKEND is not a valid Django cache backend ({type(exc).__name__}).",
            )
        )
        return None
    if issubclass(backend_class, DummyCache):
        issues.append(("ratelimit.E013", "DummyCache cannot enforce rate limits."))
    if not isinstance(cache_info.get("OPTIONS", {}), Mapping):
        issues.append(("ratelimit.E013", f"CACHES[{alias!r}].OPTIONS must be a mapping."))
    key_function = cache_info.get("KEY_FUNCTION")
    if key_function is not None:
        try:
            if isinstance(key_function, str):
                key_function = import_string(key_function)
            if not callable(key_function):
                raise TypeError("not callable")
        except Exception:
            issues.append(
                ("ratelimit.E013", f"CACHES[{alias!r}].KEY_FUNCTION must import a callable.")
            )
    return cache_info


def storage_configuration() -> tuple[str, str, str | None, list[tuple[str, str]]]:
    """Validate storage settings and resolve explicitly supported Redis aliases.

    Django cache backends are checked using their public class import path;
    no cache connection or network I/O occurs during validation.
    """
    issues: list[tuple[str, str]] = []
    value = getattr(settings, "RATELIMIT_STORAGE", None)
    if value is None:
        url = getattr(settings, "RATELIMIT_REDIS_URL", None)
        if url is not None and not _valid_redis_url(url):
            issues.append(("ratelimit.E003", "RATELIMIT_REDIS_URL must be a valid Redis URL."))
        return STORAGE_REDIS, "default", url, issues
    if not isinstance(value, Mapping):
        return (
            STORAGE_REDIS,
            "default",
            None,
            [("ratelimit.E012", "RATELIMIT_STORAGE must be a mapping.")],
        )

    backend = value.get("BACKEND")
    if not isinstance(backend, str) or backend not in STORAGE_BACKENDS:
        issues.append(("ratelimit.E012", "RATELIMIT_STORAGE.BACKEND must be 'cache' or 'redis'."))
        return STORAGE_REDIS, "default", None, issues
    if any(key not in {"BACKEND", "CACHE_ALIAS", "URL"} for key in value):
        issues.append(("ratelimit.E012", "RATELIMIT_STORAGE contains unsupported keys."))
    alias = value.get("CACHE_ALIAS", "default")
    if not isinstance(alias, str) or not alias.strip() or alias != alias.strip():
        issues.append(
            ("ratelimit.E012", "RATELIMIT_STORAGE.CACHE_ALIAS must be a nonempty cache alias.")
        )
        alias = "default"

    if backend == STORAGE_CACHE:
        if "URL" in value:
            issues.append(("ratelimit.E012", "Cache storage must not specify URL."))
        cache_info = _selected_cache_info(alias, issues)
        if cache_info is not None:
            options = cache_info.get("OPTIONS", {})
            if isinstance(options, Mapping) and (
                options.get("ignore_exc") is True
                or options.get("IGNORE_EXCEPTIONS") is True
                or (
                    cache_info.get("BACKEND") == DJANGO_REDIS_CACHE_BACKEND
                    and getattr(settings, "DJANGO_REDIS_IGNORE_EXCEPTIONS", False) is True
                )
            ):
                issues.append(
                    (
                        "ratelimit.E013",
                        "Cache backend must not suppress errors during rate limiting.",
                    )
                )
        return backend, alias, None, issues

    if "URL" in value and "CACHE_ALIAS" in value:
        issues.append(
            ("ratelimit.E012", "Redis storage must use either URL or CACHE_ALIAS, not both.")
        )
    if "URL" in value:
        url = value["URL"]
    elif "CACHE_ALIAS" in value:
        cache_info = _selected_cache_info(alias, issues)
        if cache_info is None:
            return backend, alias, None, issues
        if cache_info.get("BACKEND") not in DJANGO_REDIS_CACHE_BACKENDS:
            issues.append(
                (
                    "ratelimit.E013",
                    "Native Redis cache alias requires a supported Redis cache backend.",
                )
            )
        options = cache_info.get("OPTIONS", {})
        allowed = {"CLIENT_CLASS": "django_redis.client.DefaultClient"}
        if not isinstance(options, Mapping) or any(
            key not in allowed or option != allowed[key] for key, option in options.items()
        ):
            issues.append(
                (
                    "ratelimit.E013",
                    "Redis cache alias has unsupported connection options; supply an explicit URL.",
                )
            )
        url = cache_info.get("LOCATION")
        if not _valid_redis_url(url):
            issues.append(
                ("ratelimit.E013", "Redis cache alias requires one valid Redis URL LOCATION.")
            )
    else:
        url = getattr(settings, "RATELIMIT_REDIS_URL", None)
    if url is not None and not _valid_redis_url(url):
        issues.append(
            (
                "ratelimit.E003",
                "Native Redis URL must be a valid redis://, rediss://, or unix:// URL.",
            )
        )
    return backend, alias, url, issues


def config_errors() -> list[tuple[str, str]]:
    """Return deterministic configuration errors for Django checks and startup."""
    errors: list[tuple[str, str]] = []

    for name in dir(settings):
        if name.startswith("RATELIMIT_") and name not in SETTING_NAMES:
            errors.append(("ratelimit.E019", f"Unsupported rate-limit setting: {name}."))

    middleware = getattr(settings, "MIDDLEWARE", ())
    if isinstance(middleware, (list, tuple)):
        for path in middleware:
            if (
                isinstance(path, str)
                and path.startswith("ratelimit_middleware.middleware.")
                and path != DJANGO_MIDDLEWARE_PATH
            ):
                errors.append(
                    (
                        "ratelimit.E020",
                        f"Invalid rate-limit middleware path: {path!r}; use {DJANGO_MIDDLEWARE_PATH}.",
                    )
                )

    if not _positive_int(getattr(settings, "RATELIMIT_RATE", 60)):
        errors.append(("ratelimit.E001", "RATELIMIT_RATE must be a positive integer."))
    if not _positive_int(getattr(settings, "RATELIMIT_WINDOW", 60)):
        errors.append(("ratelimit.E002", "RATELIMIT_WINDOW must be a positive integer in seconds."))

    for setting_name, default, maximum in (
        ("RATELIMIT_RATE", 60, MAX_RATE),
        ("RATELIMIT_WINDOW", 60, MAX_WINDOW),
        ("RATELIMIT_WS_MSG_RATE", 0, MAX_RATE),
        ("RATELIMIT_WS_MSG_WINDOW", 60, MAX_WINDOW),
    ):
        value = getattr(settings, setting_name, default)
        if type(value) is int and value > maximum:
            errors.append(("ratelimit.E017", f"{setting_name} exceeds safe Redis numeric bounds."))

    explicit_redis_url = getattr(settings, "RATELIMIT_REDIS_URL", None)
    if explicit_redis_url is not None and not _valid_redis_url(explicit_redis_url):
        errors.append(("ratelimit.E003", "RATELIMIT_REDIS_URL must be a valid Redis URL."))

    backend, _, url, storage_errors = storage_configuration()
    errors.extend(storage_errors)
    if (
        backend == STORAGE_REDIS
        and not url
        and not any(code in {"ratelimit.E003", "ratelimit.E013"} for code, _ in errors)
    ):
        errors.append(
            (
                "ratelimit.E003",
                "Native Redis storage requires RATELIMIT_STORAGE.URL, a supported CACHE_ALIAS, "
                "or RATELIMIT_REDIS_URL.",
            )
        )

    flag = getattr(settings, "RATELIMIT_TRUST_X_FORWARDED_FOR", False)
    proxies = getattr(settings, "RATELIMIT_TRUSTED_PROXIES", ())
    valid_proxies = isinstance(proxies, (list, tuple)) and bool(proxies)
    if valid_proxies:
        for item in proxies:
            try:
                if not isinstance(item, str):
                    raise ValueError("expected a string")
                network = ip_network(item, strict=False)
                if network.prefixlen == 0:
                    raise ValueError("trust-all networks are unsafe")
            except ValueError:
                valid_proxies = False
                break
    if not isinstance(proxies, (list, tuple)) or (proxies and not valid_proxies):
        errors.append(
            (
                "ratelimit.E005",
                "RATELIMIT_TRUSTED_PROXIES must contain valid non-global IP/CIDR networks.",
            )
        )
    if flag is True and not valid_proxies:
        errors.append(
            (
                "ratelimit.E004",
                "RATELIMIT_TRUST_X_FORWARDED_FOR requires explicit RATELIMIT_TRUSTED_PROXIES.",
            )
        )

    paths = getattr(settings, "RATELIMIT_EXEMPT_PATHS", ())
    if not isinstance(paths, (list, tuple)) or any(
        not isinstance(p, str)
        or (not p.strip("/") and p != "/")
        or not p.startswith("/")
        or any(token in p for token in ("?", "#", "\\", "//", "\x00"))
        or any(segment in {".", ".."} for segment in p.split("/"))
        or p != p.strip()
        for p in paths
    ):
        errors.append(
            ("ratelimit.E006", "RATELIMIT_EXEMPT_PATHS must contain valid literal paths.")
        )

    ips = getattr(settings, "RATELIMIT_EXEMPT_IPS", ())
    if not isinstance(ips, (list, tuple)) or any(parse_address(ip) is None for ip in ips):
        errors.append(("ratelimit.E007", "RATELIMIT_EXEMPT_IPS must contain valid IP addresses."))

    timeout = getattr(settings, "RATELIMIT_REDIS_TIMEOUT", 1)
    if not _positive_finite(timeout):
        errors.append(
            ("ratelimit.E009", "RATELIMIT_REDIS_TIMEOUT must be a positive finite number.")
        )

    msg_rate = getattr(settings, "RATELIMIT_WS_MSG_RATE", 0)
    if (
        type(msg_rate) is not int
        or msg_rate < 0
        or not _positive_int(getattr(settings, "RATELIMIT_WS_MSG_WINDOW", 60))
    ):
        errors.append(
            (
                "ratelimit.E010",
                "RATELIMIT_WS_MSG_RATE must be a nonnegative integer and RATELIMIT_WS_MSG_WINDOW a positive integer.",
            )
        )

    for name, default in (
        ("RATELIMIT_TRUST_X_FORWARDED_FOR", False),
        ("RATELIMIT_ENABLE_HEADERS", True),
        ("RATELIMIT_FAIL_OPEN", True),
        ("RATELIMIT_WS_HANDSHAKE", True),
    ):
        if type(getattr(settings, name, default)) is not bool:
            errors.append(("ratelimit.E011", f"{name} must be a boolean."))

    algorithm = getattr(settings, "RATELIMIT_ALGORITHM", ALGORITHM_SLIDING_WINDOW)
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        errors.append(
            ("ratelimit.E017", "RATELIMIT_ALGORITHM must be 'sliding_window' or 'token_bucket'.")
        )

    if algorithm == ALGORITHM_TOKEN_BUCKET and (
        (
            type(getattr(settings, "RATELIMIT_RATE", 60)) is int
            and getattr(settings, "RATELIMIT_RATE", 60) > MAX_TOKEN_BUCKET_RATE
        )
        or (
            type(getattr(settings, "RATELIMIT_WINDOW", 60)) is int
            and getattr(settings, "RATELIMIT_WINDOW", 60) > MAX_TOKEN_BUCKET_WINDOW
        )
    ):
        errors.append(("ratelimit.E017", "Token bucket RATE/WINDOW exceed safe numeric bounds."))

    if algorithm == ALGORITHM_TOKEN_BUCKET and (
        (type(msg_rate) is int and msg_rate > MAX_TOKEN_BUCKET_RATE)
        or (
            type(getattr(settings, "RATELIMIT_WS_MSG_WINDOW", 60)) is int
            and getattr(settings, "RATELIMIT_WS_MSG_WINDOW", 60) > MAX_TOKEN_BUCKET_WINDOW
        )
    ):
        errors.append(
            (
                "ratelimit.E017",
                "Token bucket RATELIMIT_WS_MSG_RATE/WINDOW exceed safe numeric bounds.",
            )
        )

    identity_mode = getattr(settings, "RATELIMIT_IDENTITY", IDENTITY_IP)
    raw_policies = getattr(settings, "RATELIMIT_POLICIES", ())
    try:
        policies = compile_policies(
            raw_policies,
            has_custom_resolver=bool(getattr(settings, "RATELIMIT_IDENTITY_RESOLVER", None)),
        )
    except PolicyConfigurationError as exc:
        errors.append(("ratelimit.E016", str(exc)))
        policies = ()
    if backend == STORAGE_CACHE and (
        algorithm == ALGORITHM_TOKEN_BUCKET
        or any(policy.algorithm == ALGORITHM_TOKEN_BUCKET for policy in policies)
    ):
        errors.append(
            ("ratelimit.E018", "Token bucket requires native Redis storage, not Django Cache.")
        )

    resolver_path = getattr(settings, "RATELIMIT_IDENTITY_RESOLVER", None)
    if not isinstance(identity_mode, str) or identity_mode not in IDENTITY_MODES:
        errors.append(("ratelimit.E014", "RATELIMIT_IDENTITY must be 'ip', 'user', or 'custom'."))
    if identity_mode == IDENTITY_CUSTOM or any(
        limit.identity == IDENTITY_CUSTOM for policy in policies for limit in policy.limits
    ):
        if not isinstance(resolver_path, str) or not resolver_path.strip():
            errors.append(
                (
                    "ratelimit.E015",
                    "Custom identity requires RATELIMIT_IDENTITY_RESOLVER dotted path.",
                )
            )
        else:
            try:
                resolver = import_string(resolver_path)
                if (
                    not callable(resolver)
                    or iscoroutinefunction(resolver)
                    or iscoroutinefunction(getattr(resolver, "__call__", None))
                ):
                    raise ValueError("resolver must be a synchronous callable")
            except Exception:
                errors.append(
                    ("ratelimit.E015", "Identity resolver path must import a synchronous callable.")
                )
    elif resolver_path is not None:
        errors.append(
            ("ratelimit.E015", "RATELIMIT_IDENTITY_RESOLVER is only used with custom identity.")
        )

    return list(dict.fromkeys(errors))


def get_ratelimit_settings() -> RateLimitSettings:
    errors = config_errors()
    if errors:
        raise ImproperlyConfigured("; ".join(f"{code}: {message}" for code, message in errors))

    backend, alias, redis_url, _ = storage_configuration()
    return RateLimitSettings(
        rate=getattr(settings, "RATELIMIT_RATE", 60),
        window=getattr(settings, "RATELIMIT_WINDOW", 60),
        exempt_paths=tuple(getattr(settings, "RATELIMIT_EXEMPT_PATHS", ())),
        exempt_ips=tuple(
            str(parse_address(ip)) for ip in getattr(settings, "RATELIMIT_EXEMPT_IPS", ())
        ),
        enable_headers=getattr(settings, "RATELIMIT_ENABLE_HEADERS", True),
        redis_url=redis_url or "",
        storage_backend=backend,
        cache_alias=alias,
        redis_timeout=float(getattr(settings, "RATELIMIT_REDIS_TIMEOUT", 1)),
        fail_open=getattr(settings, "RATELIMIT_FAIL_OPEN", True),
        trust_x_forwarded_for=getattr(settings, "RATELIMIT_TRUST_X_FORWARDED_FOR", False),
        trusted_proxies=tuple(
            ip_network(item, strict=False)
            for item in getattr(settings, "RATELIMIT_TRUSTED_PROXIES", ())
        ),
        ws_handshake=getattr(settings, "RATELIMIT_WS_HANDSHAKE", True),
        ws_msg_rate=getattr(settings, "RATELIMIT_WS_MSG_RATE", 0),
        ws_msg_window=getattr(settings, "RATELIMIT_WS_MSG_WINDOW", 60),
        identity_mode=getattr(settings, "RATELIMIT_IDENTITY", IDENTITY_IP),
        identity_resolver=getattr(settings, "RATELIMIT_IDENTITY_RESOLVER", None),
        policies=compile_policies(
            getattr(settings, "RATELIMIT_POLICIES", ()),
            has_custom_resolver=bool(getattr(settings, "RATELIMIT_IDENTITY_RESOLVER", None)),
        ),
        algorithm=getattr(settings, "RATELIMIT_ALGORITHM", ALGORITHM_SLIDING_WINDOW),
    )
