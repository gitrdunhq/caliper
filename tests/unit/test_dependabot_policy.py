# tested-by: tests/unit/test_dependabot_policy.py
"""Dependabot policy guards for intentionally vulnerable scanner fixtures."""

from __future__ import annotations

import tomllib
from fnmatch import fnmatch
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_VULN_FIXTURE = "tests/e2e/fixtures/vuln-repo"
_VULN_FIXTURE_GLOB = f"{_VULN_FIXTURE}/**"
_CLEAN_FIXTURE = "tests/e2e/fixtures/clean-repo"


def _is_excluded(fixture_path: str, excluded: set[str]) -> bool:
    """Return True if a sample file under fixture_path matches any excluded glob."""
    sample = f"{fixture_path}/requirements.txt"
    return any(fnmatch(sample, pattern) for pattern in excluded)


def _load_dependabot_config() -> dict[object, object]:
    path = _ROOT / ".github" / "dependabot.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), ".github/dependabot.yml must parse to a YAML mapping"
    return data


def _dependabot_updates() -> list[dict[object, object]]:
    updates = _load_dependabot_config().get("updates")
    assert isinstance(updates, list), "dependabot.yml must define an updates list"
    return [update for update in updates if isinstance(update, dict)]


def _root_python_updates() -> list[dict[object, object]]:
    """Root Python update blocks, regardless of pip/uv ecosystem naming."""
    return [
        update
        for update in _dependabot_updates()
        if update.get("package-ecosystem") in {"uv", "pip"} and update.get("directory") == "/"
    ]


def test_dependabot_root_python_uses_uv_ecosystem() -> None:
    """Root Python updates must use the uv ecosystem, not pip.

    The pip ecosystem edits pyproject.toml without regenerating uv.lock, which
    produces un-mergeable lockfile drift. uv updates both atomically.
    """
    root = _root_python_updates()
    assert root, "Dependabot must have a root Python update block"
    assert all(
        update.get("package-ecosystem") == "uv" for update in root
    ), "Root Python updates must use package-ecosystem 'uv' to keep pyproject.toml and uv.lock in sync"


def test_dependabot_excludes_intentional_vulnerability_fixture() -> None:
    python_updates = _root_python_updates()
    assert python_updates, "Dependabot must have a root Python update block"

    excluded = {
        item
        for update in python_updates
        for item in update.get("exclude-paths", [])
        if isinstance(item, str)
    }
    assert _is_excluded(_VULN_FIXTURE, excluded), (
        "Dependabot must not update the intentionally vulnerable e2e fixture; "
        "scanner coverage depends on those pinned vulnerable manifests."
    )
    assert _is_excluded(_CLEAN_FIXTURE, excluded), (
        "Dependabot must not update the clean e2e fixture; "
        "its pinned deps are intentional test inputs."
    )


def test_dependabot_version_updates_have_minimum_package_age() -> None:
    python_update = next(iter(_root_python_updates()))
    cooldown = python_update.get("cooldown")
    assert isinstance(cooldown, dict), "Root Python updates must define a cooldown"
    assert cooldown.get("default-days") == 14


def test_vuln_fixture_keeps_known_vulnerable_dependency_pins() -> None:
    requirements = (_ROOT / _VULN_FIXTURE / "requirements.txt").read_text(encoding="utf-8")
    with (_ROOT / _VULN_FIXTURE / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)

    dependencies = pyproject["project"]["dependencies"]
    assert "requests==2.25.1" in requirements
    assert "requests==2.25.1" in dependencies
    assert "cryptography==3.4.8" in requirements
