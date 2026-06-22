# tested-by: tests/unit/test_source_tree_guard.py
"""Guard: src/caliper/ is the only application package under src/."""

from __future__ import annotations

from pathlib import Path

_SRC = Path(__file__).parent.parent.parent / "src"
_ALLOWED = {"caliper", "caliper.egg-info"}


def test_no_mirror_packages_under_src() -> None:
    """Fail if any package directory exists under src/ outside src/caliper/."""
    dirs = {d.name for d in _SRC.iterdir() if d.is_dir() and not d.name.startswith((".", "__"))}
    mirrors = dirs - _ALLOWED
    assert mirrors == set(), (
        f"Stale mirror packages under src/: {mirrors}. "
        f"Only src/caliper/ should contain application code."
    )
