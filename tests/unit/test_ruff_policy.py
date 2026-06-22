# tested-by: tests/unit/test_ruff_policy.py
"""Ruff configuration sanity guards."""

from __future__ import annotations

import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _pyproject() -> dict[str, object]:
    with (_ROOT / "pyproject.toml").open("rb") as file:
        data = tomllib.load(file)
    assert isinstance(data, dict), "pyproject.toml must parse to a TOML mapping"
    return data


def _as_mapping(value: object) -> dict[object, object]:
    return value if isinstance(value, dict) else {}


def test_ruff_lint_preferences_stay_conservative() -> None:
    tool = _as_mapping(_pyproject().get("tool"))
    ruff = _as_mapping(tool.get("ruff"))
    lint = _as_mapping(ruff.get("lint"))

    assert ruff.get("target-version") == "py312"
    assert ruff.get("line-length") == 100
    assert ruff.get("preview") is not True
    assert lint.get("preview") is not True

    selected = lint.get("select")
    assert isinstance(selected, list), "Ruff lint rules must use an explicit select list"
    assert "ALL" not in selected, "Do not enable every Ruff rule family at once"
    assert set(selected) == {"E", "F", "W", "I", "N", "UP", "B", "SIM"}

    pfi = _as_mapping(lint.get("per-file-ignores"))
    allowed_patterns = {"tests/**", "src/caliper/detectors/**/*.py"}
    assert (
        set(pfi.keys()) <= allowed_patterns
    ), f"per-file-ignores should only scope to {allowed_patterns}"
