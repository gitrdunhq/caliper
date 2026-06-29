"""Tests for the per-part review view — ``core.inspect_view``.

# tested-by: tests/unit/test_inspect_view.py
"""

from __future__ import annotations

from caliper.core.inspect_view import parse_unified_diff

_DIFF = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,0 +2,2 @@
+added line two
+added line three
@@ -10,1 +12,1 @@
-old ten
+new twelve
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -5,1 +5,0 @@
-removed only
"""


def test_parses_new_side_changed_lines() -> None:
    parsed = parse_unified_diff(_DIFF)
    # a.py: lines 2,3 (first hunk) and 12 (second hunk)
    assert [n for n, _ in parsed["a.py"]] == [2, 3, 12]
    assert parsed["a.py"][0][1] == "added line two"
    # b.py: a pure deletion consumes no new-side line number
    assert parsed["b.py"] == []


def test_handles_empty_diff() -> None:
    assert parse_unified_diff("") == {}
