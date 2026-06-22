# tested-by: tests/unit/test_deterministic_metrics_guards.py
"""Deterministic guards for metrics collection and high-cardinality label sampling.

These tests encode bug #166 as a RED rule: metrics collection must sample
high-cardinality labels to prevent cardinality explosion in telemetry systems.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector — fix the source code, then this test goes green",
    strict=False,
)

_ROOT = Path(__file__).resolve().parents[2]

# High-cardinality field patterns in telemetry that require sampling
_HIGH_CARDINALITY_FIELDS = {
    "finding_counts": "dict[str, int] — category names are user-controlled",
    "ecosystem_distribution": "dict[str, int] — ecosystem names derived from files",
    "plugin_results": "list[PluginTelemetry] — per-plugin results with dynamic names",
    "error_codes": "list[str] — error codes can grow unbounded",
}

# Sampling-related function names/patterns
_SAMPLING_PATTERNS = {
    "sample",
    "throttle",
    "rate_limit",
    "cardinality_limit",
    "_sample_",
    "_limit_",
    "max_",
    "top_n",
}

# Functions that indicate data is being aggregated/sanitized before metrics
_AGGREGATION_PATTERNS = {
    "_aggregate",
    "_bucket",
    "_sanitize",
    "_normalize",
    "Counter",
    "defaultdict",
}


def _parse_source(path: Path) -> ast.Module:
    """Parse Python source file into AST."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _find_telemetry_event_fields(module: ast.Module) -> dict[str, ast.AnnAssign]:
    """Find all annotated field assignments in TelemetryEvent-like classes."""
    fields: dict[str, ast.AnnAssign] = {}

    for node in ast.walk(module):
        if isinstance(node, ast.ClassDef):
            # Look for TelemetryEvent or similar metrics event classes
            if "Event" in node.name or "Telemetry" in node.name or "Metrics" in node.name:
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        fields[item.target.id] = item
    return fields


def _is_high_cardinality_type(annotation: ast.AST) -> bool:
    """Check if an annotation represents a high-cardinality type (dict[str, ...] or list[...])."""
    if isinstance(annotation, ast.Subscript):
        # Check for dict[...] or list[...]
        if isinstance(annotation.value, ast.Name):
            if annotation.value.id in ("dict", "Dict", "list", "List"):
                return True
        # Check for typing.Dict or typing.List
        if isinstance(annotation.value, ast.Attribute):
            if annotation.value.attr in ("Dict", "List", "dict", "list"):
                return True
    return False


def _get_annotation_str(annotation: ast.AST) -> str:
    """Convert annotation AST to string representation."""
    if isinstance(annotation, ast.Name):
        return annotation.id
    if isinstance(annotation, ast.Attribute):
        return annotation.attr
    if isinstance(annotation, ast.Subscript):
        value_str = _get_annotation_str(annotation.value)
        slice_str = _get_annotation_str(annotation.slice) if hasattr(annotation, "slice") else "..."
        return f"{value_str}[{slice_str}]"
    return str(annotation)


def _find_telemetry_event_constructors(module: ast.Module) -> list[ast.Call]:
    """Find all TelemetryEvent constructor calls in the module."""
    constructors: list[ast.Call] = []

    for node in ast.walk(module):
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node.func)
            if func_name and ("TelemetryEvent" in func_name or "Event" in func_name):
                constructors.append(node)
    return constructors


def _get_call_name(func: ast.AST) -> str | None:
    """Extract the name of a function call."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return f"{_get_call_name(func.value)}.{func.attr}" if func.value else func.attr
    return None


def _find_function_body_sampling(module: ast.Module, func_name: str) -> set[str]:
    """Check if a function body contains sampling patterns."""
    found_patterns: set[str] = set()

    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            # Walk the function body looking for sampling patterns
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = _get_call_name(child.func)
                    if call_name:
                        for pattern in _SAMPLING_PATTERNS:
                            if pattern in call_name.lower():
                                found_patterns.add(pattern)
                if isinstance(child, ast.Name):
                    for pattern in _SAMPLING_PATTERNS:
                        if pattern in child.id.lower():
                            found_patterns.add(pattern)
    return found_patterns


def _find_high_cardinality_usages(module: ast.Module) -> list[dict[str, Any]]:
    """Find usages of high-cardinality telemetry fields without sampling."""
    violations: list[dict[str, Any]] = []

    for node in ast.walk(module):
        # Look for assignments to high-cardinality fields
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript):
                    if isinstance(target.value, ast.Name):
                        field_name = target.value.id
                        if field_name in _HIGH_CARDINALITY_FIELDS:
                            # Check if the assigned value has sampling
                            if not _has_sampling_protection(node.value):
                                violations.append(
                                    {
                                        "field": field_name,
                                        "line": getattr(node, "lineno", 0),
                                        "type": "assignment",
                                    }
                                )

        # Look for dict updates (e.g., finding_counts[key] = value)
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node.func)
            if call_name in ("update", "setdefault"):
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        field_name = node.func.value.id
                        if field_name in _HIGH_CARDINALITY_FIELDS:
                            if not _has_sampling_protection_in_parent(node):
                                violations.append(
                                    {
                                        "field": field_name,
                                        "line": getattr(node, "lineno", 0),
                                        "type": "update",
                                    }
                                )

    return violations


def _has_sampling_protection(node: ast.AST) -> bool:
    """Check if an AST node indicates sampling is applied."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            call_name = _get_call_name(child.func)
            if call_name:
                for pattern in _SAMPLING_PATTERNS:
                    if pattern in call_name.lower():
                        return True
        if isinstance(child, ast.Name):
            for pattern in _SAMPLING_PATTERNS:
                if pattern in child.id.lower():
                    return True
    return False


def _has_sampling_protection_in_parent(node: ast.AST) -> bool:
    """Check for sampling patterns in parent context (simplified)."""
    # This is a simplified check - in practice we'd need full context analysis
    return False


def _find_telemetry_assembly_points(module: ast.Module) -> list[dict[str, Any]]:
    """Find where telemetry events are assembled with high-cardinality data."""
    assembly_points: list[dict[str, Any]] = []

    for node in ast.walk(module):
        # Look for TelemetryEvent instantiation
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node.func)
            if func_name and ("TelemetryEvent" in func_name or "Event" in func_name):
                # Check keyword arguments for high-cardinality fields
                for kw in node.keywords:
                    if kw.arg in _HIGH_CARDINALITY_FIELDS:
                        # Check if the value has sampling protection
                        if not _has_sampling_protection(kw.value):
                            assembly_points.append(
                                {
                                    "field": kw.arg,
                                    "line": getattr(node, "lineno", 0),
                                    "constructor": func_name,
                                }
                            )

    return assembly_points


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_telemetry_event_high_cardinality_fields_have_sampling() -> None:
    """#166: Metrics collection must sample high-cardinality labels.

    Parent bug: #166 — Metrics collection doesn't sample high-cardinality labels.
    This test detects when TelemetryEvent fields with unbounded string keys
    (finding_counts, ecosystem_distribution) are populated without:
    - Cardinality limiting
    - Sampling/throttling
    - Key bucketing/normalization
    """
    telemetry_path = _ROOT / "src" / "caliper" / "core" / "telemetry.py"
    if not telemetry_path.exists():
        pytest.skip("telemetry.py not found")

    module = _parse_source(telemetry_path)

    # Find high-cardinality field definitions
    high_card_fields: list[tuple[str, str]] = []
    fields = _find_telemetry_event_fields(module)

    for field_name, field_node in fields.items():
        if _is_high_cardinality_type(field_node.annotation):
            annotation_str = _get_annotation_str(field_node.annotation)
            if field_name in _HIGH_CARDINALITY_FIELDS:
                high_card_fields.append((field_name, annotation_str))

    # Check if any high-cardinality fields lack sampling guards
    missing_sampling: list[str] = []

    # Look for direct population of high-cardinality fields
    violations = _find_high_cardinality_usages(module)
    for v in violations:
        missing_sampling.append(
            f"telemetry.py:{v['line']} — {v['field']} ({v['type']}) lacks sampling"
        )

    # Check assembly points in the telemetry module itself
    assembly_points = _find_telemetry_assembly_points(module)
    for point in assembly_points:
        missing_sampling.append(
            f"telemetry.py:{point['line']} — {point['field']} in {point['constructor']} "
            "lacks sampling protection"
        )

    # Check if there are any sampling functions defined
    has_sampling_functions = False
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name_lower = node.name.lower()
            for pattern in _SAMPLING_PATTERNS:
                if pattern in func_name_lower:
                    has_sampling_functions = True
                    break

    # Report findings
    assert not high_card_fields or has_sampling_functions or not missing_sampling, (
        f"Bug #166: High-cardinality telemetry fields lack sampling protection.\n"
        f"High-cardinality fields detected: {high_card_fields}\n"
        f"Missing sampling at:\n" + "\n".join(missing_sampling) + "\n\n"
        "Remediation:\n"
        "1. Add cardinality limiting (e.g., top-N categories only)\n"
        "2. Implement key bucketing (e.g., 'other' for rare keys)\n"
        "3. Add sampling/throttling for high-volume events\n"
        "4. Document the sampling strategy in telemetry.py"
    )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_metrics_collection_limits_cardinality_before_emission() -> None:
    """#166: Metrics must apply cardinality limits before emitting telemetry.

    This test scans the codebase for patterns where high-cardinality data
    (file paths, package names, unique IDs) flows into metrics without
    prior aggregation or sampling.
    """
    source_root = _ROOT / "src" / "caliper"
    if not source_root.exists():
        pytest.skip("source directory not found")

    violations: list[str] = []

    # Patterns that indicate high-cardinality data sources
    high_cardinality_sources = {
        "file_path",
        "filepath",
        "path",
        "package_name",
        "cve_id",
        "finding_id",
        "rule_id",
        "sha",
        "hash",
        "uuid",
        "timestamp",
    }

    # Find telemetry event construction across the codebase
    for py_file in sorted(source_root.rglob("*.py")):
        if "test" in py_file.name:
            continue

        try:
            module = _parse_source(py_file)
        except SyntaxError:
            continue

        # Find TelemetryEvent or send_telemetry calls
        for node in ast.walk(module):
            if isinstance(node, ast.Call):
                func_name = _get_call_name(node.func)
                if func_name and ("send_telemetry" in func_name or "TelemetryEvent" in func_name):
                    # Check for high-cardinality values in arguments
                    for kw in node.keywords:
                        if kw.arg in ("finding_counts", "ecosystem_distribution"):
                            # Check if value is a dict comprehension or literal
                            if isinstance(kw.value, ast.Dict):
                                # Check keys for high-cardinality patterns
                                for key in kw.value.keys:
                                    if isinstance(key, ast.Name):
                                        if key.id in high_cardinality_sources:
                                            violations.append(
                                                f"{py_file.relative_to(_ROOT)}:{node.lineno} — "
                                                f"{kw.arg} uses high-cardinality key '{key.id}'"
                                            )

    assert (
        violations == []
    ), "Bug #166: High-cardinality data flows into telemetry without sampling:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(reason="deterministic bug detector", strict=False)
def test_telemetry_event_schema_enforces_cardinality_bounds() -> None:
    """#166: TelemetryEvent schema should enforce cardinality bounds at type level.

    High-cardinality fields should use bounded types like Literal[...]
    or have explicit MaxLength validators rather than unbounded dict[str, ...].
    """
    telemetry_path = _ROOT / "src" / "caliper" / "core" / "telemetry.py"
    if not telemetry_path.exists():
        pytest.skip("telemetry.py not found")

    module = _parse_source(telemetry_path)

    unbounded_fields: list[tuple[str, str]] = []

    for node in ast.walk(module):
        if isinstance(node, ast.ClassDef) and "Telemetry" in node.name:
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id
                    if field_name in _HIGH_CARDINALITY_FIELDS:
                        annotation_str = _get_annotation_str(item.annotation)

                        # Check if it's an unbounded dict or list
                        if "dict[" in annotation_str.lower() or "list[" in annotation_str.lower():
                            # Check for validators (field_validator, validator)
                            has_validator = False
                            # Check decorators on the class for validators on this field
                            for class_item in node.body:
                                if isinstance(class_item, ast.FunctionDef):
                                    for decorator in class_item.decorator_list:
                                        decorator_name = _get_call_name(decorator)
                                        if decorator_name and "validator" in decorator_name.lower():
                                            # Check if this validator is for our field
                                            for stmt in ast.walk(class_item):
                                                if (
                                                    isinstance(stmt, ast.Name)
                                                    and stmt.id == field_name
                                                ):
                                                    has_validator = True
                                                    break

                            if not has_validator:
                                unbounded_fields.append((field_name, annotation_str))

    assert unbounded_fields == [], (
        "Bug #166: TelemetryEvent fields lack cardinality bounds:\n"
        + "\n".join(
            f"  - {name}: {annotation} — no validator enforcing bounds"
            for name, annotation in unbounded_fields
        )
        + "\n\nAdd field_validator with cardinality limits or use bounded types."
    )
