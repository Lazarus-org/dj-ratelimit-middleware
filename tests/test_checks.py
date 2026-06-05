from django.core.checks import run_checks
from django.test import override_settings


def test_invalid_rate_check():
    with override_settings(RATELIMIT_RATE=0):
        errors = run_checks()
    assert any(e.id == "ratelimit.E001" for e in errors)


def test_invalid_window_check():
    with override_settings(RATELIMIT_WINDOW=-1):
        errors = run_checks()
    assert any(e.id == "ratelimit.E002" for e in errors)
