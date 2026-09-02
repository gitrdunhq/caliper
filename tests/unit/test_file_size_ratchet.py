# tested-by: tests/unit/test_file_size_ratchet.py
"""File-size ratchet: caps `src/caliper` files at 500 lines.

A hard-coded allowlist tracks the files that were already over the cap when
this guard was added. The ratchet only tightens: a file not on the allowlist
must stay under the cap, and an allowlisted file must not grow past the line
count recorded here (so shrinking a file to fix it forward is free, but
regressing back up is caught). A *new* file exceeding the cap fails
immediately — the allowlist never grows.
"""

from __future__ import annotations

from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

_LINE_CAP = 500

# path -> line count recorded when the ratchet was added (or last tightened).
# Shrinking a file below its recorded count is fine; growing past it is not.
_ALLOWLIST = {
    "plugins/_runners/graph_builder.py": 775,
    "detectors/ast_utils.py": 722,
    "core/models.py": 450,
    "adapters/grounding.py": 649,
    "composition/bootstrap.py": 599,
    "core/repo_config.py": 476,
    "core/pipeline.py": 506,
}


def _python_files() -> list[Path]:
    return sorted(p for p in _SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _line_count(path: Path) -> int:
    return sum(1 for _ in path.open(encoding="utf-8"))


def test_no_new_files_exceed_the_cap() -> None:
    unlisted_violations = []
    for path in _python_files():
        rel = path.relative_to(_SRC).as_posix()
        if rel in _ALLOWLIST:
            continue
        lines = _line_count(path)
        if lines > _LINE_CAP:
            unlisted_violations.append(f"{rel}: {lines} lines")
    assert not unlisted_violations, (
        f"Files over the {_LINE_CAP}-line cap not on the allowlist "
        f"(split them, or add a justified allowlist entry): {unlisted_violations}"
    )


def test_allowlisted_files_do_not_grow() -> None:
    regressions = []
    for rel, recorded in _ALLOWLIST.items():
        path = _SRC / rel
        if not path.exists():
            continue  # file moved/removed; test_allowlist_paths_exist reports it
        lines = _line_count(path)
        if lines > recorded:
            regressions.append(f"{rel}: {lines} lines (recorded {recorded})")
    assert not regressions, f"Allowlisted files grew past their recorded size: {regressions}"


def test_allowlist_paths_exist() -> None:
    missing = [rel for rel in _ALLOWLIST if not (_SRC / rel).exists()]
    assert not missing, (
        f"Allowlist entries point at files that no longer exist "
        f"(update the path, e.g. after a tier move): {missing}"
    )
