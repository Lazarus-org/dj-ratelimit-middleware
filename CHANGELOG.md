# Changelog

All notable changes to `dj-ratelimit-middleware` are documented here.

## [1.0.0]

### Added

- Pluggable rate-limit storage with Django Cache and native Redis backends.
- Atomic Redis sliding-window and constant-memory token-bucket algorithms.
- Configurable HTTP policies with exact paths, prefixes, HTTP methods, priorities, and multiple quotas.
- IP-based, authenticated-user, and verified custom-principal identity strategies.
- Trusted proxy chain resolution and safe path/IP exemptions.
- Synchronous and asynchronous Django middleware, optional Django REST Framework throttle, and standalone ASGI/WebSocket support.
- Configurable storage failure policy, HTTP 429 responses, retry information, and rate-limit response headers.
- Strict Django system checks and startup validation for settings and backend configurations.
- uv packaging, compatibility testing through tox, pre-commit hooks, security checks, and Redis benchmarks.

### Security and correctness

- Enforce bounded atomic Redis admission and prevent rejected requests from growing Redis sliding-window state.
- Correct token-bucket fractional-token denial handling.
- Reject unsupported Redis Cluster key operations and invalid cache configurations independently of fail-open behavior.
- Redact sensitive storage-error details from logs and configuration errors.
- Validate forwarding chains, exemption paths, numeric limits, and Redis connection settings.
- Preserve caller-owned ASGI header objects and support iterable response headers.
- Support Redis 5 connections with compatible RESP2 defaults.
