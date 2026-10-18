# Security Policy

Security is important to `dj-ratelimit-middleware`: the package is designed to enforce rate limits in Django, Django REST Framework (DRF), and ASGI applications. We welcome responsible reports of vulnerabilities affecting the package.

## Supported versions

Security fixes are provided for the current `1.0.x` release series. Older release series are not supported unless explicitly stated in a GitHub security advisory or release note.

| Version | Security support |
| --- | --- |
| `1.0.x` | Supported |

Please verify an issue against the latest available patch release before reporting, when practical.

## Reporting a vulnerability

**Please do not disclose an unpatched vulnerability in a public GitHub issue, discussion, or pull request.**

1. Open the repository's [Security tab](https://github.com/lazarus-org/dj-ratelimit-middleware/security).
2. Select **Report a vulnerability** if GitHub private vulnerability reporting is enabled.
3. If private reporting is unavailable, contact the Lazarus maintainers using a private contact channel listed on the [organization profile](https://github.com/lazarus-org). If no private channel is listed, open a public issue *only to request a secure contact method*, without describing the vulnerability or providing reproduction details.

A helpful private report includes the affected package version, relevant Django/Python/backend versions, the security impact, a minimal reproduction, and any proposed mitigation. Please redact credentials, tokens, personal information, and production data.

## How reports are handled

Maintainers will review reports privately, attempt to reproduce and assess the impact, and prioritize a fix and regression tests where appropriate. We aim to coordinate disclosure with the reporter after a fix or suitable mitigation is available. Confirmed issues may be communicated through GitHub Security Advisories and release notes, with reporter credit when requested and appropriate.

Response and resolution times depend on severity and maintainer availability; we do not promise a fixed service-level agreement. Please avoid public disclosure while a report is being investigated and coordinated.

## Deployment security considerations

`dj-ratelimit-middleware` provides application-level rate limiting, not a complete denial-of-service defense. Its security guarantees depend on the configured backend, authentication context, and deployment topology.

- **Backend failure policy:** `RATELIMIT_FAIL_OPEN` defaults to `True`. With this setting, recoverable storage failures can allow requests without enforcing a quota. Evaluate `False` for security-sensitive endpoints, accounting for its availability impact.
- **Storage guarantees:** Native Redis supports atomic admission for the implemented algorithms and supported quota groups. Generic Django Cache behavior depends on the cache backend; eviction may reset quotas, and multi-quota admission is not guaranteed to be atomic.
- **Proxy trust:** Only enable `X-Forwarded-For` processing with explicitly configured trusted proxies. Ensure clients cannot bypass the trusted proxy and connect directly to an unprotected application listener.
- **Authenticated identities:** Use identities supplied by verified authentication. For DRF token/JWT authentication, use the DRF integration after authentication; do not derive identities from unverified headers or token claims.
- **Redis topology:** Multi-key atomic Lua operations require compatible Redis key placement. Full Redis Cluster routing and failover are not provided; unsupported cross-slot/topology errors are treated as configuration failures.
- **Defense in depth:** Apply network, reverse-proxy, authentication, and infrastructure-level protections appropriate to the application. Test the limiter's configured failure behavior before relying on it for critical traffic.

See the [README](README.md) for supported settings and integration examples.
