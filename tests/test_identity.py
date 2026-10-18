"""Security regression tests for framework-independent request identity."""

from ipaddress import ip_network

import pytest

from ratelimit_middleware.identity import canonical_ip, client_ip, is_exempt_path


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("::ffff:192.0.2.1", "192.0.2.1"),
        (" 192.0.2.1 ", "192.0.2.1"),
        ("example.com", "unknown"),
        ("1.2.3.4:80", "unknown"),
        ("", "unknown"),
        ("untrusted\nvalue", "unknown"),
    ],
)
def test_canonical_ip(raw, expected):
    assert canonical_ip(raw) == expected


@pytest.fixture
def networks():
    return (ip_network("10.0.0.0/8"), ip_network("192.168.0.0/16"))


def resolve(peer, xff, networks, enabled=True):
    return client_ip(peer, xff, trust_forwarded=enabled, trusted_proxies=networks)


def test_rightmost_untrusted_hop_prevents_header_spoofing(networks):
    assert resolve("10.0.0.2", "fake-a, 198.51.100.3", networks) == "198.51.100.3"
    assert resolve("10.0.0.2", "fake-b, 198.51.100.3", networks) == "198.51.100.3"


def test_proxy_chain_walks_only_configured_trusted_hops(networks):
    assert resolve("10.0.0.2", "203.0.113.5, 192.168.2.2", networks) == "203.0.113.5"
    assert resolve("10.0.0.2", "spoofed, 198.51.100.4, 192.168.2.2", networks) == "198.51.100.4"


def test_untrusted_immediate_peer_is_the_identity(networks):
    assert resolve("198.51.100.4", "203.0.113.5", networks) == "198.51.100.4"


def test_trust_flag_disabled_ignores_header(networks):
    assert resolve("10.0.0.2", "203.0.113.5", networks, enabled=False) == "10.0.0.2"


def test_malformed_rightmost_hop_falls_back_to_socket_peer(networks):
    assert resolve("10.0.0.2", "203.0.113.5, nope", networks) == "10.0.0.2"
    assert resolve("10.0.0.2", "203.0.113.5:443", networks) == "10.0.0.2"


def test_enormous_header_falls_back_to_socket_peer(networks):
    assert resolve("10.0.0.2", "1" * 4097, networks) == "10.0.0.2"
    assert resolve("10.0.0.2", ",".join("1.1.1.1" for _ in range(33)), networks) == "10.0.0.2"


def test_no_peer_address_never_trusts_xff(networks):
    assert resolve(None, "1.1.1.1", networks) == "unknown"


def test_all_trusted_chain_falls_back_to_socket_peer(networks):
    assert resolve("10.0.0.2", "10.0.0.4, 192.168.2.2", networks) == "10.0.0.2"


@pytest.mark.parametrize(
    ("path", "patterns", "expected"),
    [
        ("/health", ("/health",), True),
        ("/healthcheck", ("/health",), False),
        ("/health/", ("/health",), False),
        ("/static/file.js", ("/static/",), True),
        ("/static-hijack/file.js", ("/static/",), False),
        ("/", ("/",), True),
        ("/admin", ("/",), False),
        ("/ok/", ("ok/",), True),
        ("/ok/foo", ("ok/",), True),
        ("/okay/", ("ok/",), False),
        ("/static/../secure", ("/static/",), False),
        ("/static//secure", ("/static/",), False),
    ],
)
def test_path_exemptions(path, patterns, expected):
    assert is_exempt_path(path, patterns) is expected
