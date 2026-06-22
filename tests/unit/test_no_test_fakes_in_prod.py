# tested-by: tests/unit/test_no_test_fakes_in_prod.py
"""Guard: production code must not contain test fakes, mocks, or test helpers.

Catches the pattern where agents wire bootstrap_test() or _Fake* classes
into production code paths. Test infrastructure belongs in tests/ only.

Two intentional exceptions (see ``_ALLOWED_FILES``):
  - ``bootstrap.py`` — the composition root, which holds the test wiring.
  - ``fake.py`` — the per-area, self-registering ``Fake*`` adapter that the
    ports-&-adapters convention (#404) places beside each port's real
    adapters so the registry can resolve a deterministic stand-in. Nothing
    in a production path resolves it unless asked for by key.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_SRC = Path(__file__).parent.parent.parent / "src" / "eedom"

_FAKE_PATTERNS = [
    r"\bbootstrap_test\b",
    r"\b_Fake\w+\b",
    r"\bFake\w+\b",
    r"\bMock\w+\b",
    r"\bDummy\w+\b",
]

_ALLOWED_FILES = {
    "bootstrap.py",
    "fake.py",
}

_FAKE_RE = re.compile("|".join(_FAKE_PATTERNS))


def _scan_file(path: Path) -> list[str]:
    """Return list of fake/test references found in a production file."""
    try:
        source = path.read_text()
    except Exception:
        return []

    hits = []
    for i, line in enumerate(source.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if _FAKE_RE.search(line):
            hits.append(f"{path.relative_to(_SRC)}:{i}: {line.strip()}")
    return hits


def test_no_fake_classes_in_production_code() -> None:
    """No _Fake*, Fake*, Mock*, Dummy* classes in src/eedom/ (except bootstrap.py)."""
    violations = []
    for py_file in _SRC.rglob("*.py"):
        if py_file.name in _ALLOWED_FILES:
            continue
        if "__pycache__" in str(py_file):
            continue
        try:
            tree = ast.parse(py_file.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if re.match(r"^(_?Fake|Mock|Dummy)", node.name):
                    violations.append(
                        f"{py_file.relative_to(_SRC)}:{node.lineno}: class {node.name}"
                    )
    assert violations == [], "Test fakes found in production code:\n" + "\n".join(violations)


def test_no_bootstrap_test_calls_in_production_code() -> None:
    """No calls to bootstrap_test() in src/eedom/ except bootstrap.py itself."""
    violations = []
    for py_file in _SRC.rglob("*.py"):
        if py_file.name in _ALLOWED_FILES:
            continue
        if "__pycache__" in str(py_file):
            continue
        try:
            tree = ast.parse(py_file.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "bootstrap_test"
            ):
                violations.append(f"{py_file.relative_to(_SRC)}:{node.lineno}: bootstrap_test()")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "bootstrap_test"
            ):
                violations.append(f"{py_file.relative_to(_SRC)}:{node.lineno}: *.bootstrap_test()")
    assert violations == [], "bootstrap_test() called in production code:\n" + "\n".join(violations)


def test_no_null_adapters_in_bootstrap_production_path() -> None:
    """bootstrap() must not wire NullDecisionStore/NullAuditSink for production."""
    bootstrap_file = _SRC / "composition" / "bootstrap.py"
    source = bootstrap_file.read_text()
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "bootstrap":
            func_source = ast.get_source_segment(source, node)
            if func_source:
                null_refs = re.findall(r"\bNull\w+\(\)", func_source)
                assert null_refs == [], (
                    f"bootstrap() wires Null adapters in production: {null_refs}. "
                    "Wire real adapters or accept explicit config for null fallback."
                )
