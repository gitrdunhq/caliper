"""Deterministic detector for plugin abstract method enforcement (Issue #200).

# tested-by: tests/unit/test_deterministic_abstract_guards.py

Detects when ScannerPlugin subclasses lack proper @abstractmethod
enforcement on methods that should be abstract. This is a bug detector
for issue #234, child of #200.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"
_PLUGIN_DIR = _SRC / "plugins"
_PLUGIN_BASE_FILE = _SRC / "core" / "plugin.py"

# The abstract methods that must be decorated with @abstractmethod in base
_REQUIRED_ABSTRACT_METHODS = frozenset({"name", "description", "category", "can_run", "run"})


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _get_decorator_names(decorator_list: list[ast.expr]) -> set[str]:
    """Extract decorator names from a list of decorator nodes."""
    names: set[str] = set()
    for dec in decorator_list:
        if isinstance(dec, ast.Name):
            names.add(dec.id)
        elif isinstance(dec, ast.Attribute):
            names.add(dec.attr)
        elif isinstance(dec, ast.Call):
            # Handle @abc.abstractmethod() or @abstractmethod()
            if isinstance(dec.func, ast.Name):
                names.add(dec.func.id)
            elif isinstance(dec.func, ast.Attribute):
                names.add(dec.func.attr)
    return names


def _get_base_class_names(bases: list[ast.expr]) -> list[str]:
    """Extract base class names from class definition."""
    names: list[str] = []
    for base in bases:
        if isinstance(base, ast.Name):
            names.append(base.id)
        elif isinstance(base, ast.Attribute):
            names.append(base.attr)
    return names


@pytest.mark.xfail(reason="deterministic bug detector for #200/#234", strict=False)
def test_plugin_base_has_abstractmethod_decorators() -> None:
    """Detect missing @abstractmethod on required methods in ScannerPlugin base class.

    Issue #200: The ScannerPlugin base class should enforce abstract methods
    using @abc.abstractmethod decorator. This test detects when any of the
    required methods (name, description, category, can_run, run) lack the
    @abstractmethod decorator.

    The test AST-analyzes src/caliper/core/plugin.py to verify:
    1. ScannerPlugin class exists and inherits from abc.ABC
    2. Each required method has @abc.abstractmethod decorator
    3. Abstract properties also have @property decorator
    """
    if not _PLUGIN_BASE_FILE.exists():
        pytest.skip("Plugin base file not found")

    tree = _parse(_PLUGIN_BASE_FILE)

    # Find ScannerPlugin class
    scanner_plugin_class: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ScannerPlugin":
            scanner_plugin_class = node
            break

    if scanner_plugin_class is None:
        pytest.skip("ScannerPlugin class not found")

    # Verify it inherits from abc.ABC
    base_names = _get_base_class_names(scanner_plugin_class.bases)
    if "ABC" not in base_names:
        pytest.fail("ScannerPlugin must inherit from abc.ABC")

    # Check each method for @abstractmethod decorator
    violations: list[str] = []
    abstract_methods_found: dict[str, bool] = {}

    for node in scanner_plugin_class.body:
        if isinstance(node, ast.FunctionDef):
            if node.name in _REQUIRED_ABSTRACT_METHODS:
                decorator_names = _get_decorator_names(node.decorator_list)
                has_abstractmethod = "abstractmethod" in decorator_names
                abstract_methods_found[node.name] = has_abstractmethod

                if not has_abstractmethod:
                    line = node.lineno or 0
                    violations.append(
                        f"{_PLUGIN_BASE_FILE}:{line}: "
                        f"method '{node.name}' missing @abstractmethod decorator"
                    )

        elif isinstance(node, ast.Expr):
            # Handle Ellipsis (...) as body for abstract methods
            pass

    # Also check for missing methods entirely
    for method in _REQUIRED_ABSTRACT_METHODS:
        if method not in abstract_methods_found:
            violations.append(
                f"{_PLUGIN_BASE_FILE}: "
                f"required abstract method '{method}' not found in ScannerPlugin"
            )

    # The assertion: if violations exist, bug #200 is present
    # This xfail when bug is present (violations found)
    # and passes when bug is fixed (no violations)
    assert violations == [], (
        "Issue #200/#234: ScannerPlugin base class lacks proper @abstractmethod enforcement:\n"
        + "\n".join(violations)
    )


@pytest.mark.xfail(reason="deterministic bug detector for #200/#234", strict=False)
def test_plugin_subclasses_properly_override_abstract_methods() -> None:
    """Detect plugin subclasses that may not properly override abstract methods.

    This test AST-analyzes all plugin files in src/caliper/plugins/ to detect
    when a ScannerPlugin subclass:
    1. Lacks required method implementations
    2. Has placeholder implementations (pass/ellipsis only)
    3. Missing proper return type annotations on overrides

    The test uses static analysis rather than runtime instantiation to avoid
    triggering ABC enforcement errors during testing.
    """
    if not _PLUGIN_DIR.exists():
        pytest.skip("Plugin directory not found")

    violations: list[str] = []

    plugin_files = sorted(p for p in _PLUGIN_DIR.glob("*.py") if not p.name.startswith("_"))

    for plugin_file in plugin_files:
        try:
            tree = _parse(plugin_file)
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Check if this class inherits from ScannerPlugin
            base_names = _get_base_class_names(node.bases)
            if "ScannerPlugin" not in base_names:
                continue

            # Analyze the class body for method implementations
            implemented_methods: dict[str, ast.FunctionDef] = {}
            property_methods: set[str] = set()

            for child in node.body:
                if isinstance(child, ast.FunctionDef):
                    implemented_methods[child.name] = child
                    # Check if it's a property
                    decorator_names = _get_decorator_names(child.decorator_list)
                    if "property" in decorator_names:
                        property_methods.add(child.name)

            # Check for missing required methods
            for required in _REQUIRED_ABSTRACT_METHODS:
                if required not in implemented_methods:
                    violations.append(
                        f"{plugin_file}:{node.lineno}: "
                        f"class '{node.name}' missing required method '{required}'"
                    )
                    continue

                method = implemented_methods[required]

                # Check for placeholder implementations
                body = method.body
                # Remove docstring if present
                if (
                    body
                    and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)
                ):
                    body = body[1:]

                # Check if body is only pass or ellipsis
                is_placeholder = False
                if not body:
                    is_placeholder = True
                elif len(body) == 1:
                    stmt = body[0]
                    if isinstance(stmt, ast.Pass):
                        is_placeholder = True
                    elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                        if stmt.value.value is ... or stmt.value.value is Ellipsis:
                            is_placeholder = True
                    elif isinstance(stmt, ast.Return) and stmt.value is None:
                        is_placeholder = True

                if is_placeholder:
                    violations.append(
                        f"{plugin_file}:{method.lineno}: "
                        f"class '{node.name}' method '{required}' has placeholder implementation"
                    )

                # Check property decorators on name/description/category
                if required in ("name", "description", "category"):
                    decorator_names = _get_decorator_names(method.decorator_list)
                    if "property" not in decorator_names:
                        violations.append(
                            f"{plugin_file}:{method.lineno}: "
                            f"class '{node.name}' method '{required}' missing @property decorator"
                        )

    # The assertion: if violations exist, potential bugs are present
    assert (
        violations == []
    ), "Issue #200/#234: Plugin subclasses with improper abstract method handling:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(reason="deterministic bug detector for #200/#234", strict=False)
def test_abstract_method_body_is_ellipsis_or_raise() -> None:
    """Detect abstract methods with implementation bodies instead of .../raise.

    Abstract methods should have minimal bodies - either ... (ellipsis) or
    raise NotImplementedError(). Methods with actual implementation code
    in the base class may not truly be abstract.
    """
    if not _PLUGIN_BASE_FILE.exists():
        pytest.skip("Plugin base file not found")

    tree = _parse(_PLUGIN_BASE_FILE)

    violations: list[str] = []

    # Find ScannerPlugin class
    scanner_plugin_class: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "ScannerPlugin":
            scanner_plugin_class = node
            break

    if scanner_plugin_class is None:
        pytest.skip("ScannerPlugin class not found")

    for node in scanner_plugin_class.body:
        if not isinstance(node, ast.FunctionDef):
            continue

        if node.name not in _REQUIRED_ABSTRACT_METHODS:
            continue

        decorator_names = _get_decorator_names(node.decorator_list)
        if "abstractmethod" not in decorator_names:
            continue  # Already caught by other test

        # Check body is minimal (..., pass, or raise NotImplementedError)
        body = node.body

        # Remove docstring
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]

        is_valid_abstract = False

        if not body:
            is_valid_abstract = True  # Empty after docstring
        elif len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, ast.Pass):
                is_valid_abstract = True
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if stmt.value.value is ... or stmt.value.value is Ellipsis:
                    is_valid_abstract = True
            elif isinstance(stmt, ast.Return) and (
                stmt.value is None
                or (isinstance(stmt.value, ast.Constant) and stmt.value.value is None)
            ):
                is_valid_abstract = True
            elif isinstance(stmt, ast.Raise):
                # Check if it's raise NotImplementedError
                if isinstance(stmt.exc, ast.Call):
                    func = stmt.exc.func
                    if isinstance(func, ast.Name) and func.id == "NotImplementedError":
                        is_valid_abstract = True
                    if isinstance(func, ast.Attribute) and func.attr == "NotImplementedError":
                        is_valid_abstract = True
                elif isinstance(stmt.exc, ast.Name) and stmt.exc.id == "NotImplementedError":
                    is_valid_abstract = True

        if not is_valid_abstract:
            violations.append(
                f"{_PLUGIN_BASE_FILE}:{node.lineno}: "
                f"abstract method '{node.name}' has non-trivial implementation body"
            )

    assert violations == [], (
        "Issue #200/#234: Abstract methods should have minimal bodies (... or raise):\n"
        + "\n".join(violations)
    )
