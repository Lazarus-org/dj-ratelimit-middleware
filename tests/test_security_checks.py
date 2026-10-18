"""System checks and runtime configuration must reject unsafe settings."""

import pytest
from django.core.checks import run_checks
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings

from ratelimit_middleware.conf import get_ratelimit_settings


@pytest.mark.parametrize(
    ("config", "expected_id"),
    [
        ({"RATELIMIT_TRUST_X_FORWARDED_FOR": True}, "ratelimit.E004"),
        ({"RATELIMIT_TRUSTED_PROXIES": ["0.0.0.0/0"]}, "ratelimit.E005"),
        ({"RATELIMIT_TRUSTED_PROXIES": ["invalid network"]}, "ratelimit.E005"),
        ({"RATELIMIT_EXEMPT_PATHS": ["/a?query=yes"]}, "ratelimit.E006"),
        ({"RATELIMIT_EXEMPT_PATHS": ["/static/../private/"]}, "ratelimit.E006"),
        ({"RATELIMIT_EXEMPT_IPS": ["not an ip"]}, "ratelimit.E007"),
        ({"RATELIMIT_REDIS_TIMEOUT": 0}, "ratelimit.E009"),
        ({"RATELIMIT_WS_MSG_RATE": -1}, "ratelimit.E010"),
        ({"RATELIMIT_TRUST_X_FORWARDED_FOR": "False"}, "ratelimit.E011"),
        ({"RATELIMIT_RATE": True}, "ratelimit.E001"),
        ({"RATELIMIT_WINDOW": "60"}, "ratelimit.E002"),
    ],
)
def test_django_checks_and_runtime_reject_invalid_config(config, expected_id):
    with override_settings(**config):
        assert expected_id in {finding.id for finding in run_checks()}
        with pytest.raises(ImproperlyConfigured):
            get_ratelimit_settings()


def test_trusted_proxy_config_accepted():
    with override_settings(
        RATELIMIT_TRUST_X_FORWARDED_FOR=True,
        RATELIMIT_TRUSTED_PROXIES=["10.10.10.0/24", "2001:db8::/32"],
    ):
        config = get_ratelimit_settings()
        assert len(config.trusted_proxies) == 2
        assert not [f for f in run_checks() if f.id.startswith("ratelimit.E")]


def test_native_redis_requires_an_explicit_connection():
    with override_settings(RATELIMIT_REDIS_URL=None, RATELIMIT_STORAGE=None):
        with pytest.raises(ImproperlyConfigured, match="requires RATELIMIT_STORAGE.URL"):
            get_ratelimit_settings()
