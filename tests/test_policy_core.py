"""Policy engine tests runnable without Django or a Redis service."""

from types import SimpleNamespace

import pytest

from ratelimit_middleware.policies import (
    PolicyConfigurationError,
    WindowQuota,
    choose_decision,
    compile_policies,
    match_policy,
    policy_quotas,
)
from ratelimit_middleware.sliding_window import SlidingWindowResult, _read_multi


def _rule(name, path="/api/login/", **kwargs):
    return {
        "NAME": name,
        "PATH": path,
        "METHODS": ["POST"],
        "LIMITS": [{"IDENTITY": "ip", "RATE": 2, "WINDOW": 60}],
        **kwargs,
    }


def test_matching_method_and_priority():
    policies = compile_policies(
        (
            {
                "NAME": "general",
                "PATH_PREFIX": "/api",
                "LIMITS": [{"IDENTITY": "ip", "RATE": 8, "WINDOW": 30}],
            },
            _rule("login", PRIORITY=20),
        ),
        has_custom_resolver=False,
    )
    assert match_policy(policies, "/api/login/", "POST").name == "login"
    assert match_policy(policies, "/api/login/", "GET").name == "general"
    assert match_policy(policies, "/apiary", "POST") is None


@pytest.mark.parametrize(
    "rule",
    [
        _rule("UPPER"),
        _rule("bad", path="/api/../bad"),
        _rule("bad", LIMITS=[]),
        _rule("bad", LIMITS=[{"IDENTITY": "ip", "RATE": True, "WINDOW": 60}]),
        _rule("bad", LIMITS=[{"IDENTITY": "custom", "RATE": 10, "WINDOW": 60}]),
        _rule("bad", METHODS=["post"]),
        _rule("bad", LIMITS=[{"IDENTITY": "ip", "RATE": 10, "WINDOW": 60}] * 9),
    ],
)
def test_validation_rejects_unsafe_rules(rule):
    with pytest.raises(PolicyConfigurationError):
        compile_policies((rule,), has_custom_resolver=False)


def test_duplicate_policy_rejected():
    with pytest.raises(PolicyConfigurationError):
        compile_policies((_rule("login"), _rule("login")), has_custom_resolver=False)


def test_quota_identity_keys_and_rule_separation():
    policies = compile_policies(
        (
            _rule(
                "login",
                LIMITS=[
                    {"IDENTITY": "ip", "RATE": 5, "WINDOW": 60},
                    {"IDENTITY": "user", "RATE": 10, "WINDOW": 60},
                ],
            ),
            _rule("other"),
        ),
        has_custom_resolver=False,
    )
    user = SimpleNamespace(is_authenticated=True, pk=123)
    a = policy_quotas(policies[0], "http", None, "192.0.2.1", user=user)
    b = policy_quotas(policies[1], "http", None, "192.0.2.1")
    assert len({a[0].key, a[1].key, b[0].key}) == 3
    assert "123" not in a[1].key
    assert a[1].key == policy_quotas(policies[0], "http", None, "192.0.2.2", user=user)[1].key


def test_redis_multi_response_denial_does_not_mark_available_quota_blocked():
    quotas = (WindowQuota("ip", 2, 60), WindowQuota("user", 5, 60))
    results = _read_multi([0, 2, 51000, 1, 80000], quotas)
    assert results[0].limited and not results[1].limited
    assert choose_decision(quotas, results).limit == 2


def test_incomplete_results_must_contain_denial():
    quotas = (WindowQuota("ip", 2, 60), WindowQuota("user", 5, 60))
    with pytest.raises(ValueError):
        choose_decision(quotas, (SlidingWindowResult(False, 1, 20),))
