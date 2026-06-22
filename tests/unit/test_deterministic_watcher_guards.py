"""Deterministic bug detector for config file watcher polling (#203).

This test detects when the file watcher uses polling-based watching
instead of native OS events (inotify on Linux, FSEvents on macOS,
ReadDirectoryChangesW on Windows).

Bug #203: Config file watcher uses polling instead of native OS events.
Parent issue about inefficient file watching that drains battery and
misses rapid changes due to polling intervals.

Acceptance criteria:
- Must use native Observer (not PollingObserver)
- Must not force polling via force_polling=True
- Must use watchdog's native platform-specific emitters

Epic: #146
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #203",
    strict=False,
)


def _find_watchdog_imports_and_usage(source_code: str, filename: str) -> dict:
    """Parse source and find watchdog Observer usage patterns.

    Returns dict with:
    - uses_polling_observer: bool - imports PollingObserver
    - has_force_polling_true: bool - Observer(force_polling=True)
    - uses_base_observer: bool - imports base Observer
    - line_numbers: list[int] - lines where suspicious patterns found
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return {
            "uses_polling_observer": False,
            "has_force_polling_true": False,
            "uses_base_observer": False,
            "line_numbers": [],
        }

    result = {
        "uses_polling_observer": False,
        "has_force_polling_true": False,
        "uses_base_observer": False,
        "line_numbers": [],
    }

    polling_observer_aliases: set[str] = set()
    observer_aliases: set[str] = {"Observer"}

    for node in ast.walk(tree):
        # Check for imports
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if "watchdog" in module:
                for alias in node.names:
                    name = alias.name
                    asname = alias.asname or name

                    if name == "PollingObserver":
                        polling_observer_aliases.add(asname)
                        result["uses_polling_observer"] = True
                        result["line_numbers"].append(node.lineno)

                    if name == "Observer":
                        observer_aliases.add(asname)
                        result["uses_base_observer"] = True

        # Check for Observer(force_polling=True) calls
        if isinstance(node, ast.Call):
            # Check if the call is to an Observer class
            func = node.func
            is_observer_call = False

            if (
                isinstance(func, ast.Name)
                and func.id in observer_aliases
                or isinstance(func, ast.Attribute)
                and func.attr == "Observer"
            ):
                is_observer_call = True

            if is_observer_call:
                # Check for force_polling=True keyword argument
                for keyword in node.keywords:
                    if keyword.arg == "force_polling":
                        value = keyword.value
                        if isinstance(value, ast.Constant) and value.value is True:
                            result["has_force_polling_true"] = True
                            result["line_numbers"].append(node.lineno)

    return result


def _get_source_files(repo_root: Path) -> list[tuple[Path, str]]:
    """Get all Python source files from src/caliper."""
    src_dir = repo_root / "src" / "caliper"
    files: list[tuple[Path, str]] = []

    if not src_dir.exists():
        return files

    for py_file in src_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            files.append((py_file, content))
        except (OSError, UnicodeDecodeError):
            continue

    return files


@pytest.mark.xfail(reason="deterministic bug detector for #203", strict=False)
def test_203_no_polling_observer_usage():
    """Detect PollingObserver import/usage which indicates polling-based watching.

    PollingObserver uses CPU-intensive polling instead of native OS events.
    This drains battery on laptops and can miss rapid file changes.
    """
    repo_root = Path(__file__).resolve().parents[2]
    source_files = _get_source_files(repo_root)

    violations: list[tuple[Path, int]] = []

    for file_path, content in source_files:
        result = _find_watchdog_imports_and_usage(content, str(file_path))

        if result["uses_polling_observer"]:
            for lineno in result["line_numbers"]:
                violations.append((file_path.relative_to(repo_root), lineno))

    if violations:
        violation_str = "\n".join(f"  - {path}:{line}" for path, line in violations)
        pytest.fail(
            f"PollingObserver detected (bug #203). Use native Observer instead:\n"
            f"{violation_str}\n\n"
            f"PollingObserver uses inefficient polling instead of native OS events:\n"
            f"  - Linux: inotify\n"
            f"  - macOS: FSEvents\n"
            f"  - Windows: ReadDirectoryChangesW\n\n"
            f"Replace 'from watchdog.observers import PollingObserver' with\n"
            f"        'from watchdog.observers import Observer'"
        )


@pytest.mark.xfail(reason="deterministic bug detector for #203", strict=False)
def test_203_no_force_polling_true():
    """Detect Observer(force_polling=True) which forces polling mode.

        Even the base Observer can be forced into polling mode, defeating
    the purpose of using native OS events.
    """
    repo_root = Path(__file__).resolve().parents[2]
    source_files = _get_source_files(repo_root)

    violations: list[tuple[Path, int]] = []

    for file_path, content in source_files:
        result = _find_watchdog_imports_and_usage(content, str(file_path))

        if result["has_force_polling_true"]:
            # Line numbers already collected
            for lineno in result["line_numbers"]:
                violations.append((file_path.relative_to(repo_root), lineno))

    if violations:
        violation_str = "\n".join(f"  - {path}:{line}" for path, line in violations)
        pytest.fail(
            f"force_polling=True detected (bug #203). Remove to use native OS events:\n"
            f"{violation_str}\n\n"
            f"Observer(force_polling=True) disables native events and uses polling.\n"
            f"Remove the force_polling parameter to let watchdog auto-select\n"
            f"the appropriate native observer for the platform."
        )


@pytest.mark.xfail(reason="deterministic bug detector for #203", strict=False)
def test_203_watchdog_uses_native_observer():
    """Verify watchdog Observer is used correctly for native events.

    This is a positive test: it confirms the code uses Observer (not
    PollingObserver) and doesn't force polling mode.
    """
    repo_root = Path(__file__).resolve().parents[2]
    watch_py = repo_root / "src" / "caliper" / "cli" / "watch.py"

    if not watch_py.exists():
        pytest.skip("watch.py not found - no file watcher to validate")

    content = watch_py.read_text(encoding="utf-8")
    result = _find_watchdog_imports_and_usage(content, str(watch_py))

    # Must use base Observer
    assert result["uses_base_observer"], (
        "watch.py should import Observer from watchdog.observers for native events. "
        "This ensures the code uses inotify/FSEvents/ReadDirectoryChangesW "
        "instead of polling."
    )

    # Must NOT use PollingObserver
    assert not result["uses_polling_observer"], (
        "watch.py uses PollingObserver which is inefficient. "
        "Use 'from watchdog.observers import Observer' instead."
    )

    # Must NOT force polling
    assert not result["has_force_polling_true"], (
        "watch.py uses force_polling=True which disables native events. "
        "Remove force_polling=True to use native OS events."
    )
