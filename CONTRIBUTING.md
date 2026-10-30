# Contributing to dj-ratelimit-middleware

Thanks for contributing to Lazarus's Django rate-limiting package. Security,
concurrency correctness, clear public contracts, and predictable operation under
storage failures matter more than expanding feature count.

## Local setup

Install Git, [uv](https://docs.astral.sh/uv/), and a supported Python interpreter
(3.10–3.14). Clone the repository and install its development dependencies:

```bash
git clone https://github.com/Lazarus-org/dj-ratelimit-middleware.git
cd dj-ratelimit-middleware
uv sync --locked --group dev --extra redis --extra drf
uv run --no-sync pre-commit install
uv run --no-sync pre-commit install --hook-type commit-msg
```

The committed `uv.lock` is the development lockfile. Source distributions and
wheels use the runtime and optional dependencies from `pyproject.toml`.

## Local checks

```bash
uv run --no-sync pytest -q
uv run --no-sync python -m django check --settings=tests.settings
uv run --no-sync pre-commit run --all-files
uv run --no-sync pre-commit run --all-files --config .pre-commit-config-ci.yaml
uv run --no-sync bandit -c pyproject.toml -r ratelimit_middleware
uv build --force-pep517
uv run --no-sync python scripts/check_wheel.py dist/
```

The local pre-commit configuration may format or fix files. The CI configuration
validates the formatted state without applying automated fixes. Both configurations
operate on the `ratelimit_middleware`, `tests`, and `scripts` source trees.

### Integration tests

Tests requiring live Redis/Memcached use **isolated, disposable test services**.
The test suite reads the following environment variables when those services
are available:

- `RATELIMIT_TEST_REDIS_URL`
- `RATELIMIT_TEST_REDIS5_URL`
- `RATELIMIT_TEST_MEMCACHED_URL`

Never point tests or benchmarks at production, shared, or externally managed
services. Some tests exercise expiry, denial floods, malformed inputs, and
connection failures. Use `uvx tox` to run the compatibility environments,
provided the required Python interpreters and test services are available.

## Pull requests

- Keep PRs focused and explain motivation, security implications, and expected
  behavior. Add a regression test for every bug fix.
- Test sync Django, async Django, ASGI, and DRF paths where a change affects
  their shared contract. Consider concurrent multi-worker behavior.
- Do not weaken or skip failing tests to achieve a passing build.
- Avoid logging credentials, tokens, private user identifiers, or production data.
- Use Conventional Commits, e.g. `fix(redis): reject unsupported cluster slots`.
- Update `CHANGELOG.md` when a change affects user-facing behavior or guarantees.

This project is preparing its **first public release**; internal development
checkpoints are not released compatibility baselines. Once releases exist,
public API changes require deliberate versioning and upgrade notes.

## Reporting vulnerabilities and releases

Read [SECURITY.md](SECURITY.md) for private reporting guidance. The release
workflow builds and validates a wheel and source distribution, checks version
consistency, and runs the full CI workflow. Manual runs on branches validate
artifacts without publishing. Tags must exactly match `v<project.version>`;
tag runs publish the validated distributions to PyPI after all checks pass.

Configure a PyPI Trusted Publisher for this repository's `release.yml` workflow
and the `pypi` GitHub environment. Set required reviewers on that environment
to require maintainer approval before publishing. No publish-enable repository
variable is required. Use Commitizen to keep the project and package versions
in sync when preparing releases.
