#!/usr/bin/env python3
"""Standalone tier-boundary reporter for the caliper ports-and-adapters guard.

Read-only static analysis. Reuses the exact resolution logic the enforced
guard test imports (``caliper.core.tier_map``), so a clean run here is a
reliable predictor of ``tests/unit/test_deterministic_architecture_guards.py``
passing -- but it is NOT a substitute for that test in CI. Run it any time you
want a fast, no-container sanity check while editing imports, or a
per-directory inventory of what each tier currently imports.

Usage (from repo root):
    uv run python .claude/skills/caliper-architecture-contract/scripts/check_tier_boundaries.py
    uv run python .claude/skills/caliper-architecture-contract/scripts/check_tier_boundaries.py --summary

Exit code 0 = no violations found. Exit code 1 = violations found (printed).
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
SRC = REPO_ROOT / "src" / "caliper"

sys.path.insert(0, str(REPO_ROOT / "src"))

from caliper.core.tier_map import (  # noqa: E402
    DEFAULT_ALLOWED,
    DEFAULT_SKIP_DIRS,
    DEFAULT_TIER_BY_DIR,
    imported_caliper_modules,
    kernel_modules,
    source_tier,
    target_tier,
)


def python_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print an import-count-by-tier-pair table instead of a violation list.",
    )
    args = parser.parse_args()

    kernel_mods = kernel_modules(SRC)
    violations: list[str] = []
    tier_pair_counts: Counter[tuple[str, str]] = Counter()
    files_by_tier: Counter[str] = Counter()

    for path in python_files():
        src_tier = source_tier(path, SRC, DEFAULT_TIER_BY_DIR, DEFAULT_SKIP_DIRS)
        if src_tier is None:
            continue
        files_by_tier[src_tier] += 1
        allowed = DEFAULT_ALLOWED[src_tier]
        tree = ast.parse(path.read_text(), filename=str(path))
        for module, lineno in imported_caliper_modules(tree, path, SRC):
            tgt_tier = target_tier(module, DEFAULT_TIER_BY_DIR, kernel_mods, DEFAULT_SKIP_DIRS)
            tier_pair_counts[(src_tier, tgt_tier)] += 1
            if tgt_tier not in allowed:
                rel = path.relative_to(REPO_ROOT).as_posix()
                violations.append(f"{rel}:{lineno}: {src_tier} -> {tgt_tier} (import {module})")

    if args.summary:
        print(f"Tiered files: {sum(files_by_tier.values())}")
        for tier, count in sorted(files_by_tier.items()):
            print(f"  {tier:<12} {count} files")
        print()
        print("Import edges observed (source_tier -> target_tier: count):")
        for (s, t), count in sorted(tier_pair_counts.items()):
            marker = "" if t in DEFAULT_ALLOWED[s] else "  *** NOT ALLOWED ***"
            print(f"  {s:<12} -> {t:<12} : {count}{marker}")

    if violations:
        print(f"\n{len(violations)} tier boundary violation(s):")
        for v in violations:
            print(f"  {v}")
        return 1

    print("\nNo tier boundary violations found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
