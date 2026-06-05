from unittest.mock import patch

import fakeredis
from django.test import Client, override_settings
from redis.exceptions import RedisError


def redis_factory(*args, **kwargs):
    return fakeredis.FakeRedis(decode_responses=True)


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_allows_until_limit_then_429(mock_redis):
    client = Client(REMOTE_ADDR="1.2.3.4")
    assert client.get("/ok/").status_code == 200
    assert client.get("/ok/").status_code == 200
    response = client.get("/ok/")
    assert response.status_code == 429
    assert response["Retry-After"] == "60"


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_exempt_path_not_limited(mock_redis):
    with override_settings(RATELIMIT_EXEMPT_PATHS=["ok/"]):
        client = Client(REMOTE_ADDR="1.2.3.5")
        for _ in range(5):
            assert client.get("/ok/").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_headers_added(mock_redis):
    client = Client(REMOTE_ADDR="1.2.3.6")
    response = client.get("/ok/")
    assert response["X-RateLimit-Limit"] == "2"
    assert response["X-RateLimit-Remaining"] == "1"
    assert response["X-RateLimit-Reset"] == "60"


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_different_ips_have_separate_limits(mock_redis):
    client_a = Client(REMOTE_ADDR="10.0.0.1")
    client_b = Client(REMOTE_ADDR="10.0.0.2")

    assert client_a.get("/ok/").status_code == 200
    assert client_a.get("/ok/").status_code == 200

    # Client A is now over the limit.
    assert client_a.get("/ok/").status_code == 429

    # Client B has a different IP, so it still has its own quota.
    assert client_b.get("/ok/").status_code == 200
    assert client_b.get("/ok/").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_exempt_ip_not_limited(mock_redis):
    with override_settings(RATELIMIT_EXEMPT_IPS=["8.8.8.8"]):
        client = Client(REMOTE_ADDR="8.8.8.8")
        for _ in range(10):
            assert client.get("/ok/").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_exempt_path_accepts_leading_slash(mock_redis):
    with override_settings(RATELIMIT_EXEMPT_PATHS=["/ok/"]):
        client = Client(REMOTE_ADDR="1.2.3.7")
        for _ in range(5):
            assert client.get("/ok/").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_x_forwarded_for_is_ignored_by_default(mock_redis):
    client = Client(REMOTE_ADDR="9.9.9.9")

    assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1").status_code == 200
    assert client.get("/ok/", HTTP_X_FORWARDED_FOR="2.2.2.2").status_code == 200

    # Because X-Forwarded-For is not trusted by default, both requests counted
    # against REMOTE_ADDR=9.9.9.9.
    assert client.get("/ok/", HTTP_X_FORWARDED_FOR="3.3.3.3").status_code == 429


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_x_forwarded_for_can_be_trusted_when_enabled(mock_redis):
    with override_settings(RATELIMIT_TRUST_X_FORWARDED_FOR=True):
        client = Client(REMOTE_ADDR="9.9.9.9")

        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1").status_code == 200
        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1").status_code == 200
        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1").status_code == 429

        # A different forwarded client IP gets a separate quota.
        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="2.2.2.2").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_x_forwarded_for_uses_first_ip_when_trusted(mock_redis):
    with override_settings(RATELIMIT_TRUST_X_FORWARDED_FOR=True):
        client = Client(REMOTE_ADDR="9.9.9.9")

        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1, 10.0.0.1").status_code == 200
        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1, 10.0.0.2").status_code == 200
        assert client.get("/ok/", HTTP_X_FORWARDED_FOR="1.1.1.1, 10.0.0.3").status_code == 429


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_user_agent_is_ignored_by_default(mock_redis):
    client = Client(REMOTE_ADDR="5.5.5.5")

    assert client.get("/ok/", HTTP_USER_AGENT="agent-a").status_code == 200
    assert client.get("/ok/", HTTP_USER_AGENT="agent-b").status_code == 200
    assert client.get("/ok/", HTTP_USER_AGENT="agent-c").status_code == 429


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_user_agent_can_be_part_of_key_when_enabled(mock_redis):
    with override_settings(RATELIMIT_INCLUDE_USER_AGENT=True):
        client = Client(REMOTE_ADDR="5.5.5.6")

        assert client.get("/ok/", HTTP_USER_AGENT="agent-a").status_code == 200
        assert client.get("/ok/", HTTP_USER_AGENT="agent-a").status_code == 200
        assert client.get("/ok/", HTTP_USER_AGENT="agent-a").status_code == 429

        # Same IP but different user-agent has a different key.
        assert client.get("/ok/", HTTP_USER_AGENT="agent-b").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_headers_can_be_disabled(mock_redis):
    with override_settings(RATELIMIT_ENABLE_HEADERS=False):
        client = Client(REMOTE_ADDR="6.6.6.6")
        response = client.get("/ok/")

        assert response.status_code == 200
        assert "X-RateLimit-Limit" not in response
        assert "X-RateLimit-Remaining" not in response
        assert "X-RateLimit-Reset" not in response


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=RedisError("redis down"))
def test_redis_error_fail_closed_returns_429(mock_redis):
    with override_settings(RATELIMIT_FAIL_OPEN=False):
        client = Client(REMOTE_ADDR="7.7.7.7")
        response = client.get("/ok/")

        assert response.status_code == 429
        assert response["Retry-After"] == "60"


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=RedisError("redis down"))
def test_redis_error_fail_open_allows_request(mock_redis):
    with override_settings(RATELIMIT_FAIL_OPEN=True):
        client = Client(REMOTE_ADDR="7.7.7.8")
        response = client.get("/ok/")

        assert response.status_code == 200
        assert response["X-RateLimit-Remaining"] == "2"


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_custom_rate_and_window_are_used(mock_redis):
    with override_settings(RATELIMIT_RATE=1, RATELIMIT_WINDOW=10):
        client = Client(REMOTE_ADDR="11.11.11.11")

        assert client.get("/ok/").status_code == 200
        response = client.get("/ok/")

        assert response.status_code == 429
        assert response["Retry-After"] == "10"
        assert response["X-RateLimit-Limit"] == "1"
        assert response["X-RateLimit-Reset"] == "10"


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_post_requests_are_limited_too(mock_redis):
    client = Client(REMOTE_ADDR="12.12.12.12")

    assert client.post("/ok/").status_code == 200
    assert client.post("/ok/").status_code == 200
    assert client.post("/ok/").status_code == 429


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_rate_limit_window_expires_old_requests(mock_redis):
    current_time = 1_000.0

    def fake_time():
        return current_time

    with override_settings(RATELIMIT_RATE=2, RATELIMIT_WINDOW=60):
        with patch("ratelimit_middleware.middleware.time.time", side_effect=fake_time):
            client = Client(REMOTE_ADDR="13.13.13.13")

            assert client.get("/ok/").status_code == 200
            assert client.get("/ok/").status_code == 200
            assert client.get("/ok/").status_code == 429

            # Move time outside the configured window. Old sorted-set entries
            # should be removed by zremrangebyscore, so the client is allowed again.
            current_time = 1_061.0
            assert client.get("/ok/").status_code == 200


@patch("ratelimit_middleware.middleware.Redis.from_url", side_effect=redis_factory)
def test_response_body_for_429_is_json(mock_redis):
    client = Client(REMOTE_ADDR="14.14.14.14")

    client.get("/ok/")
    client.get("/ok/")
    response = client.get("/ok/")

    assert response.status_code == 429
    assert response["Content-Type"] == "application/json"
    assert response.json()["error"] == "Rate limit exceeded"
    assert "Please try again" in response.json()["detail"]
