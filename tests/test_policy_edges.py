"""Policy contract failures and sync/async single-quota algorithm selection."""

from unittest.mock import AsyncMock, Mock, call

import pytest

from ratelimit_middleware.constants import MAX_RATE, MAX_WINDOW
from ratelimit_middleware.policies import (
    PolicyConfigurationError,
    RateLimitPolicy,
    WindowQuota,
    choose_decision,
    compile_policies,
)
from ratelimit_middleware.policy_admission import admit_async, admit_sync
from ratelimit_middleware.principals import InvalidPrincipal, choose_identity
from ratelimit_middleware import sliding_window
from ratelimit_middleware.sliding_window import SlidingWindowResult


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"ALGORITHM": "unknown"}, "ALGORITHM"),
        ({"PRIORITY": 1001}, "PRIORITY"),
        ({"PRIORITY": True}, "PRIORITY"),
        ({"LIMITS": [None]}, "requires IDENTITY"),
        ({"LIMITS": [{"IDENTITY": "ip", "RATE": 1}]}, "requires IDENTITY"),
        ({"LIMITS": [{"IDENTITY": "unknown", "RATE": 1, "WINDOW": 60}]}, "identity"),
        ({"LIMITS": [{"IDENTITY": "ip", "RATE": MAX_RATE + 1, "WINDOW": 60}]}, "bounds"),
        ({"LIMITS": [{"IDENTITY": "ip", "RATE": 1, "WINDOW": MAX_WINDOW + 1}]}, "bounds"),
    ],
)
def test_policy_validation_reports_specific_contract_errors(changes, message):
    rule = {
        "NAME": "api",
        "PATH": "/api/",
        "LIMITS": [{"IDENTITY": "ip", "RATE": 2, "WINDOW": 60}],
        **changes,
    }
    with pytest.raises(PolicyConfigurationError, match=message):
        compile_policies([rule], has_custom_resolver=False)


def test_manually_constructed_policy_without_a_path_matches_nothing():
    policy = RateLimitPolicy("invalid", None, None, frozenset(), 0, ())
    assert not policy.matches("/api/", "GET")


@pytest.mark.parametrize("results", [(), (SlidingWindowResult(False, 1, 60),) * 2])
def test_decisions_reject_empty_or_excess_results(results):
    with pytest.raises(ValueError, match="invalid quota result count"):
        choose_decision([WindowQuota("a", 2, 60)], results)


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("algorithm", ["sliding_window", "token_bucket"])
@pytest.mark.asyncio
async def test_single_policy_quota_selects_algorithm_without_changing_default(
    async_mode, algorithm
):
    policy = compile_policies(
        [
            {
                "NAME": "api",
                "PATH": "/api/",
                "ALGORITHM": algorithm,
                "LIMITS": [{"IDENTITY": "ip", "RATE": 2, "WINDOW": 30}],
            }
        ],
        has_custom_resolver=False,
    )[0]
    storage = Mock(algorithm="sliding_window")
    result = SlidingWindowResult(False, 1, 17)
    storage.check_sync = Mock(return_value=result)
    storage.check_async = AsyncMock(return_value=result)
    args = (storage, policy, "http", None, "192.0.2.10")
    decision = await admit_async(*args) if async_mode else admit_sync(*args)
    method = storage.check_async if async_mode else storage.check_sync
    kwargs = {"algorithm": algorithm} if algorithm != storage.algorithm else {}
    assert method.call_args == call("ratelimit:policy:api:0:http:192.0.2.10", 2, 30, **kwargs)
    assert decision.result == result and decision.limit == 2 and decision.window == 30
    assert storage.algorithm == "sliding_window"
    storage.check_many_sync.assert_not_called()
    storage.check_many_async.assert_not_called()


def test_custom_identity_none_uses_ip_fallback():
    context = object()
    resolver = Mock(return_value=None)
    assert choose_identity("custom", context, resolver=resolver) is None
    resolver.assert_called_once_with(context)


@pytest.mark.parametrize(
    "mode,resolver,message",
    [
        ("custom", lambda context: "untrusted", "namespace, identifier"),
        ("unsupported", None, "Unsupported"),
    ],
)
def test_invalid_identity_contracts_are_rejected(mode, resolver, message):
    with pytest.raises(InvalidPrincipal, match=message):
        choose_identity(mode, None, resolver=resolver)


def test_malformed_redis_group_response_is_rejected():
    with pytest.raises(ValueError, match="Unexpected Redis group"):
        sliding_window._read_multi([1, 0], [WindowQuota("a", 2, 60)])


@pytest.mark.parametrize("async_mode", [False, True])
@pytest.mark.parametrize("quotas", [(), (WindowQuota("a", 2, 60),)])
@pytest.mark.asyncio
async def test_redis_multi_admission_requires_multiple_quotas_before_any_io(async_mode, quotas):
    client = Mock()
    client.eval = AsyncMock() if async_mode else Mock()
    with pytest.raises(ValueError, match="at least two quotas"):
        if async_mode:
            await sliding_window.check_many_async(client, quotas)
        else:
            sliding_window.check_many_sync(client, quotas)
    client.eval.assert_not_called()
