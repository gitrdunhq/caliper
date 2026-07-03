#!/usr/bin/env python3
"""Run all 12 built-in code-graph SQL checks against real files in THIS repo.

Read-only: builds an in-memory graph (":memory:"), never touches
.caliper/graph.db. Use this to see what the Blast Radius plugin (#16 in
README.md's plugin table) actually finds on a given file, without running
the full `caliper review` pipeline.

Usage (from repo root):
    uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/run_code_graph_checks.py <file1> [file2 ...]

Example:
    uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/run_code_graph_checks.py \\
        src/caliper/plugins/_runners/graph_builder.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from caliper.plugins._runners.graph_builder import CodeGraph

if __name__ == "__main__":
    targets = sys.argv[1:] or ["src/caliper/plugins/_runners/graph_builder.py"]
    root = Path.cwd()

    graph = CodeGraph(db_path=":memory:", repo_root=root)
    indexed = graph.index_directory(
        root
    )  # whole repo, so cross-file checks (imports, calls) see real edges
    print(f"indexed {indexed} files under {root}")
    print(f"stats: {graph.stats()}")
    print()

    findings = graph.run_checks(targets)
    print(f"{len(findings)} findings across {len(targets)} target file(s): {targets}")
    for f in findings:
        print(f"  [{f['severity']:>8}] {f['check']:<28} {f['message']}")
