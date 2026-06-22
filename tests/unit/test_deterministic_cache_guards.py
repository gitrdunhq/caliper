"""Deterministic cache TTL guards — tests that detect cache ignores TTL.

# tested-by: tests/unit/test_deterministic_cache_guards.py

These tests use AST analysis to detect when PackageCatalog.lookup() results
are used without checking TTL freshness, causing stale cache entries to be
served (Bug #211).
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

# =============================================================================
# Issue #211: Plugin Result Cache TTL Rule
# =============================================================================


def _get_catalog_source_info():
    """Get source info for catalog.py to parse AST."""
    from caliper.data import catalog

    source_path = Path(inspect.getfile(catalog))
    source = source_path.read_text()
    return ast.parse(source), source_path, source


def _find_lookup_callers():
    """Find all Python files that call PackageCatalog.lookup().

    Returns list of (file_path, source_text) tuples.
    """
    repo_root = Path(__file__).parent.parent.parent
    callers = []

    for py_file in repo_root.rglob("*.py"):
        # Skip tests and cache directories
        if "test_" in py_file.name or "__pycache__" in str(py_file):
            continue
        if py_file.name.startswith("test"):
            continue

        try:
            source = py_file.read_text()
            if "PackageCatalog" in source and ".lookup(" in source:
                callers.append((py_file, source))
        except (OSError, UnicodeDecodeError):
            continue

    return callers


@pytest.mark.xfail(
    reason="deterministic bug detector #211: cache lookup without TTL check",
    strict=False,
)
def test_cache_lookup_without_freshness_check():
    """Detect that PackageCatalog.lookup() results are used without TTL checks.

    Bug #211: When code calls PackageCatalog.lookup() and uses the returned
    CatalogEntry without checking is_vuln_fresh(), is_license_fresh(), or
    is_sbom_fresh(), stale cache entries are served.

    The pattern that indicates this bug:
        entry = catalog.lookup(...)  # Returns potentially stale entry
        # ... use entry without freshness check ...

    Correct pattern should be:
        entry = catalog.lookup(...)
        if entry and not entry.is_vuln_fresh():
            # Trigger re-scan or skip cache

    Target: Any code using lookup() without freshness validation.
    Fix #211: Always check freshness before using cached results.
    """
    lookup_callers = _find_lookup_callers()
    violations = []

    for file_path, source in lookup_callers:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue

        # Look for patterns where lookup result is used without freshness check
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue

            # Check if this is a lookup() call
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue

                var_name = target.id

                # Check if value is a lookup() call
                if isinstance(node.value, ast.Call):
                    call = node.value
                    if isinstance(call.func, ast.Attribute):
                        if call.func.attr == "lookup":
                            # Found: var_name = X.lookup(...)
                            # Now check if var_name is used without freshness check
                            if _is_used_without_freshness_check(tree, var_name):
                                violations.append(
                                    f"{file_path}: variable '{var_name}' from lookup() "
                                    f"used without freshness check (is_*_fresh or needs_scan)"
                                )

    if violations:
        pytest.fail(
            f"BUG DETECTED: Cache lookup results used without TTL validation.\n"
            f"Found {len(violations)} violation(s):\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\n\nBug #211: Stale cache entries served without freshness check.\n"
            "Fix: Always call is_vuln_fresh(), is_license_fresh(), or needs_scan() "
            "before using cached CatalogEntry results."
        )


def _is_used_without_freshness_check(tree: ast.AST, var_name: str) -> bool:
    """Check if a variable is used in the AST without freshness checks.

    Returns True if the variable is used without calling is_*_fresh() or needs_scan().
    """
    freshness_methods = ("is_vuln_fresh", "is_license_fresh", "is_sbom_fresh", "needs_scan")

    for node in ast.walk(tree):
        # Check for attribute access on the variable (e.g., entry.xxx)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == var_name:
                # This is var_name.xxx - check if it's a freshness method
                if node.attr in freshness_methods:
                    # Found freshness check - not a violation
                    return False

        # Check if variable is passed to functions that might validate
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name) and kw.value.id == var_name:
                    # Variable passed as keyword arg - might be validated
                    if kw.arg in ("entry", "catalog_entry", "cached"):
                        return False
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id == var_name:
                    # Variable passed as positional arg
                    if isinstance(node.func, ast.Name):
                        if any(
                            fresh in node.func.id.lower()
                            for fresh in ("fresh", "validate", "check")
                        ):
                            return False

    # If we get here and the variable is actually used somewhere, it's a violation
    return any(isinstance(node, ast.Name) and node.id == var_name for node in ast.walk(tree))


@pytest.mark.xfail(
    reason="deterministic bug detector #211: CatalogEntry lookup lacks freshness guard",
    strict=False,
)
def test_catalog_lookup_source_lacks_ttl_validation():
    """Detect that catalog.py doesn't enforce TTL at lookup time.

    Bug #211: PackageCatalog.lookup() returns entries regardless of freshness.
    The method should either:
    1. Accept a freshness parameter and filter stale entries, or
    2. Document that callers MUST check freshness

    Current implementation (catalog.py:92-134):
        def lookup(self, ecosystem, package_name, version) -> CatalogEntry | None:
            # ... fetch from DB ...
            return CatalogEntry(**dict(zip(cols, row, strict=True)))
            # No freshness check before returning!

    The vulnerability: Callers receive potentially stale data without any
    indication that freshness validation is required.

    Fix #211: Either add freshness parameter to lookup() or add type-level
    indication that returned entries may be stale.
    """
    tree, source_path, source_text = _get_catalog_source_info()

    # Find the lookup method
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "PackageCatalog":
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "lookup":
                    method_source = ast.unparse(item)

                    # Check if lookup has any TTL/freshness parameters or validation
                    has_freshness_param = any(
                        param.arg in ("max_age", "ttl", "fresh_only", "require_fresh")
                        for param in item.args.args + item.args.kwonlyargs
                    )

                    has_freshness_check = any(
                        fresh in method_source
                        for fresh in ("is_vuln_fresh", "is_license_fresh", "needs_scan")
                    )

                    if not has_freshness_param and not has_freshness_check:
                        # Verify this is the problematic pattern
                        if "CatalogEntry" in method_source and "return" in method_source:
                            pytest.fail(
                                f"BUG DETECTED: PackageCatalog.lookup() lacks TTL validation.\n"
                                f"Location: {source_path}, lookup() method\n"
                                f"Issue: Returns CatalogEntry without freshness check.\n"
                                f"Risk: Stale cache entries served to callers.\n"
                                f"Bug #211: Add freshness validation or TTL parameter.\n"
                                f"\nCurrent method returns entry directly from DB without\n"
                                f"checking vuln_scanned_at, license_scanned_at, or sbom_scanned_at."
                            )


@pytest.mark.xfail(
    reason="deterministic bug detector #211: no cache freshness enforcement pattern",
    strict=False,
)
def test_no_centralized_cache_freshness_enforcement():
    """Detect that there's no centralized freshness enforcement for cache lookups.

    Bug #211: The codebase lacks a standardized pattern for ensuring cached
    results are fresh before use. Each caller must remember to check freshness,
    which is error-prone.

    Expected pattern (missing):
        - A decorator or wrapper that validates freshness
        - A lookup_fresh() method that only returns fresh entries
        - A type that cannot be used without freshness check

    Current state: Manual freshness checks required everywhere.
    Fix #211: Implement lookup_fresh() or FreshnessValidatingCatalog wrapper.
    """
    tree, source_path, source_text = _get_catalog_source_info()

    # Check for freshness-enforcing patterns
    freshness_patterns = [
        "lookup_fresh",  # Method that only returns fresh entries
        "FreshnessValidating",  # Wrapper class
        "require_fresh",  # Parameter to enforce freshness
        "@freshness_required",  # Decorator
    ]

    found_pattern = any(pattern in source_text for pattern in freshness_patterns)

    if not found_pattern:
        # Verify the basic lookup exists (confirming the bug context)
        if "def lookup(" in source_text:
            pytest.fail(
                f"BUG DETECTED: No centralized cache freshness enforcement.\n"
                f"Location: {source_path}\n"
                f"Issue: Only basic lookup() exists, no freshness-validating variant.\n"
                f"Bug #211: Cache entries can be stale without detection.\n"
                f"\nMissing patterns: {', '.join(freshness_patterns)}\n"
                f"\nFix: Add lookup_fresh() that returns None for stale entries,\n"
                f"or a decorator that validates freshness before returning."
            )
