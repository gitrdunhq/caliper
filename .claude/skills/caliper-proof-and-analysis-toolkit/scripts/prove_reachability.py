#!/usr/bin/env python3
"""Prove reachability scribe behavior on a throwaway synthetic mini-repo.

Recipe companion for caliper-proof-and-analysis-toolkit. Builds two tiny
fixture repos in a tempdir -- one that imports a vulnerable package, one
that declares it but never imports it -- and runs the exact same code path
ADR-009 describes (core/import_resolution.resolve_import_name +
CodeGraph.imports_module) so you can see reachable=True/False/None with
your own eyes instead of trusting the docstring.

Usage (from repo root):
    uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/prove_reachability.py

No repo files are modified -- everything happens under a tempfile.TemporaryDirectory.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from caliper.core.import_resolution import resolve_import_name
from caliper.plugins._runners.graph_builder import CodeGraph


def _check(package: str, repo_source: str, label: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(repo_source)

        import_name = resolve_import_name(package)
        graph = CodeGraph(db_path=":memory:", repo_root=root)
        graph.index_directory(root)
        reachable = graph.imports_module(import_name) if import_name else None

        print(f"--- {label} ---")
        print(f"  declared package : {package!r}")
        print(f"  resolved import  : {import_name!r}")
        print(f"  imports_module() : {reachable}")
        print()


if __name__ == "__main__":
    # Case 1: PyYAML is declared AND imported -> reachable=True path.
    _check("PyYAML", "import yaml\n\ndef load(s):\n    return yaml.safe_load(s)\n", "imported")

    # Case 2: PyYAML is declared but the repo never imports it -> reachable=False path.
    _check("PyYAML", "def load(s):\n    return s.upper()\n", "declared-but-unimported")

    # Case 3: a package name that resolves to no valid identifier -> reachable=None path.
    _check("123-not-an-identifier", "def f():\n    return 1\n", "unresolvable-name")
