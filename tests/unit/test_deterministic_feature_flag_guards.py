# tested-by: tests/unit/test_deterministic_feature_flag_guards.py
"""Deterministic detector for feature flags without kill switches (issue #168).

Issue #168: Feature flags don't have emergency kill switches.
A kill switch is an emergency mechanism to disable a feature without
redeploying code — typically via environment variable or config override.

This test uses AST analysis to detect feature flag patterns that lack
corresponding kill switch mechanisms.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files that must have kill switches for their feature flags
_FEATURE_FLAG_FILES: tuple[Path, ...] = (
    _SRC / "core" / "config.py",
    _SRC / "core" / "repo_config.py",
    _SRC / "core" / "telemetry.py",
    _SRC / "core" / "taskfit.py",
)

# Feature flag field name patterns (boolean fields indicating features)
_FEATURE_FLAG_PATTERNS: tuple[str, ...] = (
    "enabled",
    "llm_enabled",
    "telemetry_enabled",
)

# Kill switch patterns to look for
_KILL_SWITCH_PATTERNS: tuple[str, ...] = (
    "kill_switch",
    "emergency_disable",
    "circuit_breaker",
    "CALIPER_DISABLE_",
    "_DISABLE_",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _get_class_bases(node: ast.ClassDef) -> list[str]:
    """Extract base class names from a class definition."""
    bases: list[str] = []
    for base in node.bases:
        if isinstance(base, ast.Name):
            bases.append(base.id)
        elif isinstance(base, ast.Attribute):
            bases.append(base.attr)
    return bases


def _is_pydantic_model(node: ast.ClassDef) -> bool:
    """Check if a class is a Pydantic model (BaseModel or BaseSettings)."""
    bases = _get_class_bases(node)
    return any(b in ("BaseModel", "BaseSettings") for b in bases)


def _is_boolean_field(node: ast.AnnAssign | ast.Assign) -> bool:
    """Check if a field annotation is bool type."""
    if isinstance(node, ast.AnnAssign):
        # Check annotation is 'bool' or 'bool = default'
        if isinstance(node.annotation, ast.Name):
            return node.annotation.id == "bool"
    return False


def _get_field_name(node: ast.AnnAssign | ast.Assign) -> str | None:
    """Extract field name from assignment."""
    if isinstance(node, ast.AnnAssign):
        if isinstance(node.target, ast.Name):
            return node.target.id
    elif isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                return target.id
    return None


def _looks_like_feature_flag(name: str) -> bool:
    """Check if field name looks like a feature flag."""
    return any(
        name == pattern or name.endswith(f"_{pattern}") for pattern in _FEATURE_FLAG_PATTERNS
    )


def _find_feature_flags(tree: ast.Module) -> list[tuple[str, int]]:
    """Find all boolean fields that look like feature flags.

    Returns list of (field_name, lineno) tuples.
    """
    flags: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue

        # Only look at Pydantic models (config/telemetry classes)
        if not _is_pydantic_model(node):
            continue

        for item in node.body:
            if isinstance(item, ast.AnnAssign):
                if _is_boolean_field(item):
                    name = _get_field_name(item)
                    if name and _looks_like_feature_flag(name):
                        flags.append((name, item.lineno or 0))

    return flags


def _has_kill_switch_in_file(tree: ast.Module) -> tuple[bool, list[str]]:
    """Check if the file has any kill switch patterns.

    Returns (has_kill_switch, found_patterns).
    """
    found_patterns: list[str] = []
    source = ast.unparse(tree)

    for pattern in _KILL_SWITCH_PATTERNS:
        if pattern in source:
            found_patterns.append(pattern)

    return len(found_patterns) > 0, found_patterns


def _check_feature_flag_usage(tree: ast.Module, flag_name: str) -> dict[str, Any]:
    """Check how a feature flag is used — look for kill switch patterns."""
    result = {
        "has_env_override": False,
        "has_kill_switch_check": False,
        "usage_locations": [],
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == flag_name:
            result["usage_locations"].append(getattr(node, "lineno", 0))

        # Check for environment variable override patterns
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node.func)
            if call_name and any(x in str(call_name).lower() for x in ("environ", "getenv", "env")):
                result["has_env_override"] = True

    return result


def _get_call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #168 - Feature flags don't have kill switches",
    strict=False,
)
def test_168_feature_flags_have_kill_switches() -> None:
    """Detect feature flags without emergency kill switch mechanisms.

    Issue #168: Feature flags (boolean config fields like `enabled`, `llm_enabled`)
    should have emergency kill switches — mechanisms to disable the feature
    without code changes (e.g., environment variable override, circuit breaker).

    Violations:
        - Boolean feature flag field without corresponding kill switch
        - No environment variable override for the feature
        - No circuit breaker or emergency disable mechanism

    Acceptance criteria for fix:
        - Each feature flag has a corresponding kill_switch or emergency_disable field
        - OR features check for CALIPER_DISABLE_* environment variables
        - OR features have circuit breaker pattern implementation
    """
    violations: list[str] = []

    for path in _FEATURE_FLAG_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        # Find feature flags
        feature_flags = _find_feature_flags(tree)

        if not feature_flags:
            continue

        # Check for kill switch patterns in the file
        has_kill_switch, found_patterns = _has_kill_switch_in_file(tree)

        # Check each feature flag
        for flag_name, lineno in feature_flags:
            # Check if this specific flag has kill switch in its name (it's the kill switch)
            if "kill" in flag_name.lower() or "disable" in flag_name.lower():
                continue

            # Check usage patterns
            usage = _check_feature_flag_usage(tree, flag_name)

            # If no kill switch patterns exist at all in the file, report violation
            if not has_kill_switch and not usage["has_env_override"]:
                violations.append(
                    f"{_rel(path)}:{lineno}: '{flag_name}' has no kill switch mechanism "
                    f"(no env override, no circuit breaker found)"
                )

    assert violations == [], (
        "Feature flags must have emergency kill switches:\n"
        "- Add kill_switch field paired with enabled field\n"
        "- OR check CALIPER_DISABLE_* environment variables\n"
        "- OR implement circuit breaker pattern\n\n" + "\n".join(violations)
    )
