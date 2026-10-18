"""Pure policy semantics and bounded configuration regressions."""

from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from django.core.checks import run_checks

from ratelimit_middleware.conf import get_ratelimit_settings
from ratelimit_middleware.policies import (
    PolicyConfigurationError,
    WindowQuota,
    choose_decision,
    compile_policies,
    match_policy,
    policy_quotas,
)
from ratelimit_middleware.sliding_window import SlidingWindowResult


def rule(name="login", **kwargs):
    return {
        "NAME": name,
        "PATH": "/api/login/",
        "METHODS": ["POST"],
        "LIMITS": [{"IDENTITY": "ip", "RATE": 2, "WINDOW": 60}],
        **kwargs,
    }


def compile_rules(*items, resolver=False):
    return compile_policies(items, has_custom_resolver=resolver)


def test_first_match_is_priority_ordered_with_stable_ties():
    policies = compile_rules(
        {
            "NAME": "general",
            "PATH_PREFIX": "/api",
            "LIMITS": [{"IDENTITY": "ip", "RATE": 30, "WINDOW": 60}],
        },
        rule("exact", PRIORITY=4),
    )
    assert match_policy(policies, "/api/login/", "POST").name == "exact"
    assert match_policy(policies, "/api/login/", "GET").name == "general"
    assert match_policy(policies, "/api/other", "GET").name == "general"
    assert match_policy(policies, "/apiary", "GET") is None
    assert match_policy(policies, "/other", "GET") is None


def test_tie_breaks_in_declaration_order():
    a = {
        "NAME": "first",
        "PATH_PREFIX": "/",
        "LIMITS": [{"IDENTITY": "ip", "RATE": 20, "WINDOW": 60}],
    }
    b = {
        "NAME": "second",
        "PATH_PREFIX": "/",
        "LIMITS": [{"IDENTITY": "ip", "RATE": 10, "WINDOW": 60}],
    }
    assert match_policy(compile_rules(a, b), "/x", "GET").name == "first"


@pytest.mark.parametrize(
    "bad",
    [
        {"NAME": "UPPER", "PATH": "/x", "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 1}]},
        {
            "NAME": "ok",
            "PATH": "/x",
            "PATH_PREFIX": "/",
            "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 1}],
        },
        {"NAME": "ok", "PATH": "x", "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 1}]},
        {"NAME": "ok", "PATH": "/x/../z", "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 1}]},
        {
            "NAME": "ok",
            "PATH": "/x",
            "METHODS": ["post"],
            "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 1}],
        },
        {"NAME": "ok", "PATH": "/x", "LIMITS": [{"IDENTITY": "ip", "RATE": True, "WINDOW": 1}]},
        {"NAME": "ok", "PATH": "/x", "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 0}]},
        {"NAME": "ok", "PATH": "/x", "LIMITS": []},
        {"NAME": "ok", "PATH": "/x", "LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": 1}] * 9},
        {"NAME": "ok", "PATH": "/x", "LIMITS": [{"IDENTITY": "custom", "RATE": 1, "WINDOW": 1}]},
    ],
)
def test_bad_policy_rejected(bad):
    with pytest.raises(PolicyConfigurationError):
        compile_rules(bad)


def test_duplicate_names_are_rejected():
    with pytest.raises(PolicyConfigurationError):
        compile_rules(rule(), rule())


def test_policy_keys_are_isolated_by_rule_and_index():
    policies = compile_rules(
        rule(
            "a",
            LIMITS=[
                {"IDENTITY": "ip", "RATE": 2, "WINDOW": 60},
                {"IDENTITY": "user", "RATE": 10, "WINDOW": 60},
            ],
        ),
        rule("b"),
    )
    context = SimpleNamespace()
    user = SimpleNamespace(pk=123, is_authenticated=True)
    first = policy_quotas(policies[0], "http", context, "192.0.2.1", user=user)
    second = policy_quotas(policies[1], "http", context, "192.0.2.1")
    assert len(set(q.key for q in first + second)) == 3
    assert first[0].key.startswith("ratelimit:policy:a:0:http:")
    assert "123" not in first[1].key
    assert (
        first[1].key == policy_quotas(policies[0], "http", context, "192.0.2.2", user=user)[1].key
    )


def test_policy_decision_selects_blocked_quota_and_maximum_retry():
    quotas = (WindowQuota("a", 10, 60), WindowQuota("b", 20, 120))
    denied = choose_decision(
        quotas,
        (
            SlidingWindowResult(True, 10, 12),
            SlidingWindowResult(True, 20, 40),
        ),
    )
    assert denied.result.limited and denied.limit == 20 and denied.result.reset_after == 40
    allowed = choose_decision(
        quotas,
        (
            SlidingWindowResult(False, 9, 20),
            SlidingWindowResult(False, 2, 50),
        ),
    )
    assert not allowed.result.limited and allowed.limit == 10


def test_default_configuration_limits_unmatched_requests():
    with override_settings(RATELIMIT_POLICIES=[]):
        assert get_ratelimit_settings().policies == ()


def test_custom_identity_policy_accepted_with_valid_resolver_path():
    with override_settings(
        RATELIMIT_IDENTITY="ip",
        RATELIMIT_IDENTITY_RESOLVER="tests.test_identity_integration.custom_resolver",
        RATELIMIT_POLICIES=[rule(LIMITS=[{"IDENTITY": "custom", "RATE": 2, "WINDOW": 60}])],
    ):
        # Use the same import path validation as the regular middleware.
        assert get_ratelimit_settings().policies[0].limits[0].identity == "custom"


def test_bad_policy_configuration_has_django_check_error():
    with override_settings(RATELIMIT_POLICIES=[{"NAME": "bad"}]):
        with pytest.raises(ImproperlyConfigured):
            get_ratelimit_settings()
        assert "ratelimit.E016" in {issue.id for issue in run_checks()}
