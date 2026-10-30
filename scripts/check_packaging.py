"""Validate release metadata without importing the package. CLI requires Python 3.11+."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

EXPECTED_NAME = "dj-ratelimit-middleware"


def validate_metadata(metadata: dict, root: Path, tag: str | None = None) -> str:
    project = metadata.get("project", {})
    if project.get("name") != EXPECTED_NAME:
        raise ValueError(f"Project name must be {EXPECTED_NAME!r}")
    version = project.get("version")
    if not isinstance(version, str) or not version or version != version.strip():
        raise ValueError("Project version must be a nonempty, unpadded string")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"Release tag {tag!r} does not match package version v{version}")

    readme = project.get("readme")
    readme_path = readme.get("file") if isinstance(readme, dict) else readme
    if not isinstance(readme_path, str) or not (root / readme_path).is_file():
        raise ValueError("Project readme must reference an existing file")

    init_path = root / "ratelimit_middleware" / "__init__.py"
    module = ast.parse(init_path.read_text(encoding="utf-8"), filename=str(init_path))
    versions = [
        ast.literal_eval(node.value)
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        )
    ]
    if versions != [version]:
        raise ValueError("Package __version__ must match project.version")
    if metadata.get("tool", {}).get("commitizen", {}).get("version") != version:
        raise ValueError("Commitizen version must match project.version")
    return version


def main(argv=None) -> None:
    import tomllib

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Release tag, exactly v<project.version>")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    try:
        with (root / "pyproject.toml").open("rb") as source:
            version = validate_metadata(tomllib.load(source), root, args.tag)
    except (OSError, ValueError, SyntaxError) as exc:
        parser.exit(1, f"Packaging validation failed: {exc}\n")
    print(f"Validated {EXPECTED_NAME} {version}" + (f" for {args.tag}" if args.tag else ""))


if __name__ == "__main__":
    main()
