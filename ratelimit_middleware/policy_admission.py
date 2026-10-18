"""Framework-neutral policy admission using the configured storage adapter."""

from __future__ import annotations

from .constants import ALGORITHM_SLIDING_WINDOW
from .policies import PolicyDecision, RateLimitPolicy, choose_decision, policy_quotas


def admit_sync(
    storage, policy: RateLimitPolicy, suffix: str, context, ip, *, user=None, resolver=None
) -> PolicyDecision:
    quotas = policy_quotas(policy, suffix, context, ip, user=user, resolver=resolver)
    if len(quotas) == 1:
        quota = quotas[0]
        if quota.algorithm != getattr(storage, "algorithm", ALGORITHM_SLIDING_WINDOW):
            results = (
                storage.check_sync(quota.key, quota.rate, quota.window, algorithm=quota.algorithm),
            )
        else:
            results = (storage.check_sync(quota.key, quota.rate, quota.window),)
    else:
        results = storage.check_many_sync(quotas)
    return choose_decision(quotas, results)


async def admit_async(
    storage, policy: RateLimitPolicy, suffix: str, context, ip, *, user=None, resolver=None
) -> PolicyDecision:
    quotas = policy_quotas(policy, suffix, context, ip, user=user, resolver=resolver)
    if len(quotas) == 1:
        quota = quotas[0]
        if quota.algorithm != getattr(storage, "algorithm", ALGORITHM_SLIDING_WINDOW):
            results = (
                await storage.check_async(
                    quota.key, quota.rate, quota.window, algorithm=quota.algorithm
                ),
            )
        else:
            results = (await storage.check_async(quota.key, quota.rate, quota.window),)
    else:
        results = await storage.check_many_async(quotas)
    return choose_decision(quotas, results)
