"""Release metadata and tag checks must reject inconsistent distributions."""

from copy import deepcopy

import pytest

from scripts.check_packaging import validate_metadata


@pytest.fixture
def release_project(tmp_path):
    package = tmp_path / "ratelimit_middleware"
    package.mkdir()
    (package / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    (tmp_path / "README.md").write_text("# Package\n", encoding="utf-8")
    metadata = {
        "project": {"name": "dj-ratelimit-middleware", "version": "1.0.0", "readme": "README.md"},
        "tool": {"commitizen": {"version": "1.0.0"}},
    }
    return tmp_path, metadata


@pytest.mark.parametrize("tag", [None, "v1.0.0"])
@pytest.mark.parametrize("readme", ["README.md", {"file": "README.md"}])
def test_consistent_release_metadata_passes(release_project, tag, readme):
    root, metadata = release_project
    metadata["project"]["readme"] = readme
    assert validate_metadata(metadata, root, tag) == "1.0.0"


@pytest.mark.parametrize("tag", ["v0.1.0", "1.0.0", "v1.0.0-extra", ""])
def test_release_tag_must_match_exactly(release_project, tag):
    root, metadata = release_project
    with pytest.raises(ValueError, match="Release tag"):
        validate_metadata(metadata, root, tag)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("name", "other-package", "Project name"),
        ("version", "", "Project version"),
        ("version", " 1.0.0", "Project version"),
        ("version", 1, "Project version"),
        ("readme", "missing.md", "readme"),
        ("readme", {"text": "inline"}, "readme"),
    ],
)
def test_invalid_release_metadata_fails(release_project, field, value, message):
    root, metadata = release_project
    metadata = deepcopy(metadata)
    metadata["project"][field] = value
    with pytest.raises(ValueError, match=message):
        validate_metadata(metadata, root)


@pytest.mark.parametrize(
    "source", ['__version__ = "0.1.0"', "", '__version__ = "1.0.0"\n__version__ = "1.0.0"']
)
def test_stale_missing_or_duplicate_runtime_version_fails(release_project, source):
    root, metadata = release_project
    (root / "ratelimit_middleware" / "__init__.py").write_text(source, encoding="utf-8")
    with pytest.raises(ValueError, match="__version__"):
        validate_metadata(metadata, root)


def test_stale_commitizen_version_fails(release_project):
    root, metadata = release_project
    metadata["tool"]["commitizen"]["version"] = "0.1.0"
    with pytest.raises(ValueError, match="Commitizen"):
        validate_metadata(metadata, root)
