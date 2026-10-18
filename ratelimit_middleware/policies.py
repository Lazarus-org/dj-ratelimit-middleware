"""Bounded, precompiled HTTP policy matching and quota decision selection.

Policy routing is framework independent. No configuration parsing, database
access, or remote calls occur while matching a request.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping, Sequence

from .constants import (
    ALGORITHM_SLIDING_WINDOW,
    ALGORITHM_TOKEN_BUCKET,
    ALGORITHMS,
    IDENTITY_CUSTOM,
    IDENTITY_MODES,
    MAX_LIMITS_PER_POLICY,
    MAX_POLICIES,
    MAX_RATE,
    MAX_WINDOW,
    MAX_TOKEN_BUCKET_RATE,
    MAX_TOKEN_BUCKET_WINDOW,
)
from .principals import choose_identity, principal_key
from .sliding_window import SlidingWindowResult


class PolicyConfigurationError(ValueError):
    """A rate-limit policy has an invalid or ambiguous declaration."""


@dataclass(frozen=True)
class PolicyLimit:
    identity: str
    rate: int
    window: int


@dataclass(frozen=True)
class RateLimitPolicy:
    name: str
    path: str | None
    path_prefix: str | None
    methods: frozenset[str]
    priority: int
    limits: tuple[PolicyLimit, ...]
    algorithm: str = ALGORITHM_SLIDING_WINDOW

    def matches(self, path: str, method: str) -> bool:
        if self.methods and method.upper() not in self.methods:
            return False
        if self.path is not None:
            return path == self.path
        if self.path_prefix is None:
            return False
        if self.path_prefix == "/":
            return path.startswith("/")
        prefix = self.path_prefix.rstrip("/")
        return path == prefix or path.startswith(prefix + "/")


@dataclass(frozen=True)
class WindowQuota:
    key: str
    rate: int
    window: int
    algorithm: str = ALGORITHM_SLIDING_WINDOW


@dataclass(frozen=True)
class PolicyDecision:
    result: SlidingWindowResult
    limit: int
    window: int


def _path(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("/")
        and not value.endswith("//")
        and "//" not in value
        and not any(c in value for c in ("?", "#", "\\", "\x00"))
        and not any(segment in (".", "..") for segment in value.split("/"))
    )


def compile_policies(raw: object, *, has_custom_resolver: bool) -> tuple[RateLimitPolicy, ...]:
    """Validate policy declarations at startup and sort by priority, then order.

    A policy selects one group of quotas. The first matched policy wins;
    overlapping policies are not independently applied. A rule contains at most
    eight limits to bound per-request backend and identity-resolution work.
    """
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_POLICIES:
        raise PolicyConfigurationError(
            f"RATELIMIT_POLICIES must be a list of at most {MAX_POLICIES} policies"
        )
    compiled = []
    names: set[str] = set()
    for rule in raw:
        if not isinstance(rule, Mapping) or any(
            k not in {"NAME", "PATH", "PATH_PREFIX", "METHODS", "PRIORITY", "LIMITS", "ALGORITHM"}
            for k in rule
        ):
            raise PolicyConfigurationError("Policy must be a mapping with supported fields")
        name = rule.get("NAME")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 32
            or not all(c.isascii() and (c.islower() or c.isdigit() or c in "_-") for c in name)
            or not name[0].isalpha()
        ):
            raise PolicyConfigurationError(
                "Policy NAME must be a lowercase identifier (max 32 characters)"
            )
        if name in names:
            raise PolicyConfigurationError(f"Duplicate rate-limit policy: {name}")
        names.add(name)
        path, prefix = rule.get("PATH"), rule.get("PATH_PREFIX")
        if (path is None) == (prefix is None) or not _path(path if path is not None else prefix):
            raise PolicyConfigurationError(
                f"Policy {name} requires exactly one valid PATH or PATH_PREFIX"
            )
        methods = rule.get("METHODS", ())
        if (
            not isinstance(methods, (tuple, list))
            or len(methods) > 16
            or any(
                not isinstance(m, str)
                or not m
                or len(m) > 20
                or not m.isascii()
                or not m.isalpha()
                or m != m.upper()
                for m in methods
            )
        ):
            raise PolicyConfigurationError(
                f"Policy {name} METHODS must contain uppercase HTTP verbs"
            )
        priority = rule.get("PRIORITY", 0)
        if type(priority) is not int or abs(priority) > 1000:
            raise PolicyConfigurationError(
                f"Policy {name} PRIORITY must be an integer from -1000 to 1000"
            )
        raw_limits = rule.get("LIMITS")
        if (
            not isinstance(raw_limits, (tuple, list))
            or not 1 <= len(raw_limits) <= MAX_LIMITS_PER_POLICY
        ):
            raise PolicyConfigurationError(
                f"Policy {name} must declare between 1 and {MAX_LIMITS_PER_POLICY} limits"
            )
        algorithm = rule.get("ALGORITHM", ALGORITHM_SLIDING_WINDOW)
        if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
            raise PolicyConfigurationError(f"Policy {name} has unsupported ALGORITHM")
        limits: list[PolicyLimit] = []
        for entry in raw_limits:
            if not isinstance(entry, Mapping) or set(entry) != {"IDENTITY", "RATE", "WINDOW"}:
                raise PolicyConfigurationError(
                    f"Policy {name} limit requires IDENTITY, RATE and WINDOW"
                )
            identity, rate, window = entry["IDENTITY"], entry["RATE"], entry["WINDOW"]
            if not isinstance(identity, str) or identity not in IDENTITY_MODES:
                raise PolicyConfigurationError(f"Policy {name} has unsupported identity")
            if identity == IDENTITY_CUSTOM and not has_custom_resolver:
                raise PolicyConfigurationError(f"Policy {name} needs RATELIMIT_IDENTITY_RESOLVER")
            if type(rate) is not int or rate <= 0 or type(window) is not int or window <= 0:
                raise PolicyConfigurationError(
                    f"Policy {name} limits need positive integer rates/windows"
                )
            if rate > MAX_RATE or window > MAX_WINDOW:
                raise PolicyConfigurationError(
                    f"Policy {name} RATE/WINDOW exceed safe Redis numeric bounds"
                )
            if algorithm == ALGORITHM_TOKEN_BUCKET and (
                rate > MAX_TOKEN_BUCKET_RATE or window > MAX_TOKEN_BUCKET_WINDOW
            ):
                raise PolicyConfigurationError(
                    f"Policy {name} token bucket RATE/WINDOW exceed safe numeric bounds"
                )
            limits.append(PolicyLimit(identity, rate, window))
        compiled.append(
            RateLimitPolicy(
                name, path, prefix, frozenset(methods), priority, tuple(limits), algorithm
            )
        )
    return tuple(sorted(compiled, key=lambda p: -p.priority))


def match_policy(
    policies: Sequence[RateLimitPolicy], path: str, method: str
) -> RateLimitPolicy | None:
    """Match in precompiled priority/order sequence, returning no-policy fallback."""
    for policy in policies:
        if policy.matches(path, method):
            return policy
    return None


def policy_quotas(
    policy: RateLimitPolicy,
    suffix: str,
    context: object,
    ip: str,
    *,
    user: object = None,
    resolver=None,
) -> tuple[WindowQuota, ...]:
    """Derive bounded, collision-resistant policy keys without I/O."""
    quotas = []
    for index, limit in enumerate(policy.limits):
        identity = choose_identity(limit.identity, context, user=user, resolver=resolver)
        key = principal_key(f"policy:{policy.name}:{index}:{suffix}", ip, identity)
        quotas.append(WindowQuota(key, limit.rate, limit.window, policy.algorithm))
    return tuple(quotas)


def choose_decision(
    quotas: Sequence[WindowQuota], results: Sequence[SlidingWindowResult]
) -> PolicyDecision:
    """Return the most restrictive quota for HTTP headers and denial timing."""
    if not results or len(results) > len(quotas):
        raise ValueError("Storage returned invalid quota result count")
    if len(results) < len(quotas) and not any(result.limited for result in results):
        raise ValueError("Incomplete non-denied quota group result")
    joined = tuple(zip(quotas, results))
    denied = [(q, r) for q, r in joined if r.limited]
    if denied:
        quota, result = max(denied, key=lambda qr: qr[1].reset_after)
    else:
        quota, result = min(joined, key=lambda qr: (qr[0].rate - qr[1].count) / qr[0].rate)
    return PolicyDecision(result, quota.rate, quota.window)
