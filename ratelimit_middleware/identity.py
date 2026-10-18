"""Security-critical request identity and path matching shared by Django and ASGI."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

Address = IPv4Address | IPv6Address
Network = IPv4Network | IPv6Network

# Malformed/unavailable peer addresses must not create attacker-controlled buckets.
UNKNOWN_CLIENT = "unknown"
MAX_FORWARDED_HEADER_LENGTH = 4096
MAX_FORWARDED_HOPS = 32


def parse_address(value: object) -> Address | None:
    """Parse a bare IP (never a hostname, port, or untrusted text fragment)."""
    if not isinstance(value, str):
        return None
    try:
        address = ip_address(value.strip())
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def canonical_ip(value: object) -> str:
    """Normalize a peer address or use one shared unidentified bucket."""
    address = parse_address(value)
    return str(address) if address is not None else UNKNOWN_CLIENT


def _is_trusted(address: Address, networks: tuple[Network, ...]) -> bool:
    return any(address in network for network in networks)


def client_ip(
    peer: object,
    forwarded_for: object,
    *,
    trust_forwarded: bool,
    trusted_proxies: tuple[Network, ...],
) -> str:
    """Choose the first untrusted hop from the right of a trusted XFF chain.

    A configured trust flag alone must never authorize a caller-supplied header.
    The immediate socket peer must also belong to an explicitly trusted network.
    """
    peer_address = parse_address(peer)
    if peer_address is None:
        return UNKNOWN_CLIENT
    fallback = str(peer_address)
    if not trust_forwarded or not _is_trusted(peer_address, trusted_proxies):
        return fallback
    if not isinstance(forwarded_for, str) or not forwarded_for:
        return fallback
    if len(forwarded_for) > MAX_FORWARDED_HEADER_LENGTH:
        return fallback

    chain = forwarded_for.split(",")
    if len(chain) > MAX_FORWARDED_HOPS:
        return fallback
    for hop in reversed(chain):
        address = parse_address(hop)
        if address is None:
            # Do not derive cache keys from malformed header fragments.
            return fallback
        if not _is_trusted(address, trusted_proxies):
            return str(address)
    # No untrusted hop: do not derive an identity from a potentially spoofed
    # leftmost value; conservatively use the immediate peer instead.
    return fallback


def is_exempt_path(path: str, exemptions: tuple[str, ...]) -> bool:
    """Match an exact path or an explicitly configured slash-terminated subtree.

    '/health' matches only '/health'; '/assets/' matches that subtree, but
    never '/assets-evil'. The root path '/' always means root only.
    """
    if "//" in path:
        return False
    normalized_path = "/" + path.lstrip("/")
    if "//" in normalized_path or any(
        segment in {".", ".."} for segment in normalized_path.split("/")
    ):
        # Never exempt paths with ambiguous normalization across proxies.
        return False
    for item in exemptions:
        pattern = "/" + item.lstrip("/")
        if pattern == "/":
            if normalized_path == "/":
                return True
        elif pattern.endswith("/"):
            if normalized_path.startswith(pattern):
                return True
        elif normalized_path == pattern:
            return True
    return False
