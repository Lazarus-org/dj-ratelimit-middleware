"""Verify that the built distribution contains only the intended library."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from zipfile import ZipFile

EXPECTED_NAME = "dj-ratelimit-middleware"


def verify(path: Path) -> None:
    with ZipFile(path) as archive:
        files = set(archive.namelist())
        metadata_paths = [name for name in files if name.endswith(".dist-info/METADATA")]
        if len(metadata_paths) != 1:
            raise AssertionError("Expected exactly one wheel METADATA file")
        metadata = archive.read(metadata_paths[0]).decode("utf-8")
        if not re.search(r"(?m)^Name: dj-ratelimit-middleware$", metadata):
            raise AssertionError("Wheel distribution name does not match Lazarus package")
        if "ratelimit_middleware/__init__.py" not in files:
            raise AssertionError("Rate-limiting library is missing from wheel")
        forbidden = [
            name
            for name in files
            if name.startswith(("kernel/", "tests/", "scripts/"))
            or name in {"manage.py", "uv.lock"}
        ]
        if forbidden:
            raise AssertionError(f"Unexpected non-library files in wheel: {forbidden}")
    print(f"Verified {path.name}: metadata, package inclusion, and isolation")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/check_wheel.py dist/")
    target = Path(sys.argv[1])
    wheels = sorted(target.glob("*.whl")) if target.is_dir() else [target]
    if len(wheels) != 1 or not wheels[0].is_file():
        raise SystemExit("Expected exactly one built wheel")
    verify(wheels[0])
