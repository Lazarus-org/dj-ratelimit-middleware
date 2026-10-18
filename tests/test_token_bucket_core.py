"""Framework-free token-bucket policy and Redis wire contract tests."""

from dataclasses import dataclass

import pytest

from ratelimit_middleware.policies import PolicyConfigurationError, compile_policies, policy_quotas
from ratelimit_middleware.token_bucket import _parse, _args, TOKEN_BUCKET_SCRIPT, bucket_key
from ratelimit_middleware.sliding_window import SlidingWindowResult


@dataclass(frozen=True)
class Quota:
    key: str
    rate: int
    window: int


def test_lua_args_are_bounded_and_use_distinct_key_types():
    assert _args((Quota("old", 2, 60),)) == (1, bucket_key("old"), 2, 60_000)
    with pytest.raises(ValueError):
        _args(())
    with pytest.raises(ValueError):
        _args((Quota("x", 1, 1),) * 9)
    assert "KEYS[i]" in TOKEN_BUCKET_SCRIPT


def test_parse_grouped_decisions_and_wait_rounding():
    assert _parse([1, 1, 1001, 2, 900], (2, 5)) == (
        SlidingWindowResult(False, 1, 2),
        SlidingWindowResult(False, 2, 1),
    )
    assert _parse([0, 2, 2010, 1, 5000], (2, 5)) == (
        SlidingWindowResult(True, 2, 3),
        SlidingWindowResult(False, 1, 5),
    )
    with pytest.raises(ValueError):
        _parse([1, 1], (3,))


def test_policy_opt_in_and_global_default():
    policies = compile_policies(
        (
            {
                "NAME": "api",
                "PATH_PREFIX": "/api/",
                "ALGORITHM": "token_bucket",
                "LIMITS": [{"IDENTITY": "ip", "RATE": 100, "WINDOW": 60}],
            },
            {
                "NAME": "strict",
                "PATH_PREFIX": "/strict/",
                "LIMITS": [{"IDENTITY": "ip", "RATE": 10, "WINDOW": 60}],
            },
        ),
        has_custom_resolver=False,
    )
    assert [p.algorithm for p in policies] == ["token_bucket", "sliding_window"]
    quota = policy_quotas(policies[0], "http", {}, "192.0.2.1")[0]
    assert quota.algorithm == "token_bucket"


@pytest.mark.parametrize("algorithm", ["broken", None, 1, "TOKEN_BUCKET"])
def test_unknown_policy_algorithm_rejected(algorithm):
    with pytest.raises(PolicyConfigurationError):
        compile_policies(
            (
                {
                    "NAME": "api",
                    "PATH": "/",
                    "ALGORITHM": algorithm,
                    "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 60}],
                },
            ),
            has_custom_resolver=False,
        )


def test_excessive_numeric_capacity_rejected():
    with pytest.raises(PolicyConfigurationError):
        compile_policies(
            (
                {
                    "NAME": "api",
                    "PATH": "/",
                    "ALGORITHM": "token_bucket",
                    "LIMITS": [{"IDENTITY": "ip", "RATE": 2_000_000_000, "WINDOW": 60}],
                },
            ),
            has_custom_resolver=False,
        )
