"""Load and evaluate .eedomignore patterns for file-path filtering.

Usage::

    patterns = load_ignore_patterns(repo_path)
    if should_ignore("vendor/lib.py", patterns):
        skip()
"""

# tested-by: tests/unit/test_ignore.py

from __future__ import annotations

import fnmatch
from pathlib import Path

_GLOB_CHARS = frozenset("*?[")

# ---------------------------------------------------------------------------
# Built-in defaults — always applied even without a .eedomignore file.
# These mirror the hard-coded exclusion sets already present in cli/main.py.
# ---------------------------------------------------------------------------
DEFAULT_PATTERNS: list[str] = [
    ".git/",
    "__pycache__/",
    "node_modules/",
    ".venv/",
    "venv/",
    ".claude/",
    ".wfc/",
    ".eedom/",
    ".dogfood/",
    "cdk.out/",
    "build/",
    ".build/",
    "DerivedData/",
    "dist/",
    "*.egg-info/",
    ".temp/",
    ".tox/",
    ".idea/",
    ".vscode/",
    "htmlcov/",
]


def load_ignore_patterns(repo_path: Path) -> list[str]:
    """Return the combined list of default + user-defined ignore patterns.

    Reads ``.eedomignore`` from *repo_path* if it exists.  Lines that are
    empty (after stripping) or start with ``#`` are skipped.  All other lines
    are appended verbatim (after stripping leading/trailing whitespace) to the
    default pattern list.

    Args:
        repo_path: Absolute path to the repository root.

    Returns:
        List of fnmatch-compatible pattern strings.  Directory patterns end
        with ``/``; glob patterns do not.
    """
    patterns: list[str] = list(DEFAULT_PATTERNS)

    root = repo_path.resolve()
    ignore_file = (repo_path / ".eedomignore").resolve()
    if not ignore_file.is_relative_to(root):
        return patterns
    if not ignore_file.exists():
        return patterns

    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)

    return patterns


def should_ignore(file_path: str, patterns: list[str]) -> bool:
    """Return ``True`` if *file_path* matches any pattern in *patterns*.

    Two matching strategies are applied for each pattern:

    * **Directory patterns** (pattern ends with ``/``): the stripped pattern
      name is matched against every component of *file_path* using
      ``fnmatch.fnmatch``.  This catches ``vendor/foo.py``, ``a/vendor/b.py``,
      and ``/abs/vendor/x.py`` all with the single pattern ``vendor/``.

    * **Glob patterns** (no trailing ``/``): matched against the full
      *file_path* string **and** against the basename (``Path.name``) so that
      ``*.pyc`` catches ``src/foo.pyc`` without requiring a leading ``**/``.

    Args:
        file_path: Path to evaluate (relative or absolute, any separator).
        patterns: List produced by :func:`load_ignore_patterns`.

    Returns:
        ``True`` if the path should be excluded from scanning.
    """
    path = Path(file_path)

    # Normalise to forward slashes and anchor with a leading "/" so that
    # "tests/fixtures/" cannot spuriously match inside "notests/fixtures/…".
    normalized = file_path.replace("\\", "/")
    anchored = "/" + normalized

    for pattern in patterns:
        if pattern.endswith("/"):
            dir_pat = pattern[:-1]
            if _GLOB_CHARS & set(dir_pat):
                if any(fnmatch.fnmatch(part, dir_pat) for part in anchored.split("/")):
                    return True
            else:
                if ("/" + pattern) in anchored:
                    return True
        else:
            if fnmatch.fnmatch(file_path, pattern):
                return True
            if fnmatch.fnmatch(path.name, pattern):
                return True

    return False
