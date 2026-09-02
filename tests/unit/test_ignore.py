"""Tests for caliper.core.ignore — .caliperignore loading and path filtering.

Property domains (DPS-12):
  Determinism   INVARIANT     same (path, patterns) always returns the same bool
  Boundedness   PERFORMANCE   path-traversal-shaped input (``../../etc/passwd``)
                               is handled in bounded time — no infinite loop —
                               and never raises
"""

# tested-by: tests/unit/test_ignore.py

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.ignore import (
    DEFAULT_PATTERNS,
    TEST_PATTERNS,
    load_ignore_patterns,
    should_ignore,
)
from caliper.core.models import Finding
from tests.unit._strategies import (
    any_path_like_text,
    path_traversal_shaped,
    plausible_relative_path,
)

# ---------------------------------------------------------------------------
# load_ignore_patterns
# ---------------------------------------------------------------------------


class TestLoadIgnorePatterns:
    """Tests for load_ignore_patterns()."""

    def test_no_file_returns_defaults_only(self, tmp_path: Path) -> None:
        """When .caliperignore does not exist, only default patterns are returned."""
        patterns = load_ignore_patterns(tmp_path)
        assert patterns == DEFAULT_PATTERNS + TEST_PATTERNS

    def test_loads_patterns_from_file(self, tmp_path: Path) -> None:
        """Patterns listed in .caliperignore are appended after defaults."""
        (tmp_path / ".caliperignore").write_text("vendor/\ntests/fixtures/\n")
        patterns = load_ignore_patterns(tmp_path)
        assert "vendor/" in patterns
        assert "tests/fixtures/" in patterns

    def test_comments_are_ignored(self, tmp_path: Path) -> None:
        """Lines starting with # are treated as comments and excluded."""
        (tmp_path / ".caliperignore").write_text("# This is a comment\nvendor/\n")
        patterns = load_ignore_patterns(tmp_path)
        assert "# This is a comment" not in patterns
        assert "vendor/" in patterns

    def test_inline_comments_not_stripped(self, tmp_path: Path) -> None:
        """A line that does NOT start with # is kept verbatim (inline # is not stripped)."""
        (tmp_path / ".caliperignore").write_text("vendor/  # keep this\n")
        patterns = load_ignore_patterns(tmp_path)
        # The line is kept as-is after stripping leading/trailing whitespace.
        assert "vendor/  # keep this" in patterns

    def test_empty_lines_are_ignored(self, tmp_path: Path) -> None:
        """Blank lines are skipped and do not appear in the returned list."""
        (tmp_path / ".caliperignore").write_text("\n\nvendor/\n\n")
        patterns = load_ignore_patterns(tmp_path)
        assert "" not in patterns
        assert "vendor/" in patterns

    def test_whitespace_only_lines_are_ignored(self, tmp_path: Path) -> None:
        """Lines containing only whitespace are skipped."""
        (tmp_path / ".caliperignore").write_text("   \n  \t  \nvendor/\n")
        patterns = load_ignore_patterns(tmp_path)
        assert "   " not in patterns
        assert "vendor/" in patterns

    def test_defaults_always_present_when_file_exists(self, tmp_path: Path) -> None:
        """Default patterns are included even when .caliperignore is present."""
        (tmp_path / ".caliperignore").write_text("vendor/\n")
        patterns = load_ignore_patterns(tmp_path)
        for default in DEFAULT_PATTERNS:
            assert default in patterns

    def test_returns_list(self, tmp_path: Path) -> None:
        """Return type is a plain list."""
        result = load_ignore_patterns(tmp_path)
        assert isinstance(result, list)

    def test_file_with_only_comments_returns_defaults(self, tmp_path: Path) -> None:
        """A .caliperignore with only comment lines is equivalent to no user patterns."""
        (tmp_path / ".caliperignore").write_text("# ignore everything\n# nope\n")
        patterns = load_ignore_patterns(tmp_path)
        assert patterns == DEFAULT_PATTERNS + TEST_PATTERNS


# ---------------------------------------------------------------------------
# should_ignore — directory patterns
# ---------------------------------------------------------------------------


class TestShouldIgnoreDirectoryPattern:
    """Tests for should_ignore() with trailing-slash (directory) patterns."""

    def test_direct_child_of_vendor(self) -> None:
        assert should_ignore("vendor/foo.py", ["vendor/"]) is True

    def test_nested_under_vendor(self) -> None:
        assert should_ignore("vendor/bar/baz.py", ["vendor/"]) is True

    def test_deeply_nested_under_vendor(self) -> None:
        assert should_ignore("a/b/vendor/c/d.py", ["vendor/"]) is True

    def test_unrelated_file_not_ignored(self) -> None:
        assert should_ignore("src/foo.py", ["vendor/"]) is False

    def test_basename_containing_dir_name_not_ignored(self) -> None:
        """A file named 'vendor.py' at root should NOT be ignored by 'vendor/'."""
        assert should_ignore("vendor.py", ["vendor/"]) is False

    def test_multiple_dir_patterns(self) -> None:
        assert should_ignore("tests/fixtures/bad.json", ["vendor/", "tests/fixtures/"]) is True

    def test_dotgit_excluded_by_default(self) -> None:
        assert should_ignore(".git/config", DEFAULT_PATTERNS) is True

    def test_pycache_excluded_by_default(self) -> None:
        assert should_ignore("src/__pycache__/module.pyc", DEFAULT_PATTERNS) is True

    def test_node_modules_excluded_by_default(self) -> None:
        assert should_ignore("node_modules/lodash/index.js", DEFAULT_PATTERNS) is True


# ---------------------------------------------------------------------------
# should_ignore — glob patterns (no trailing slash)
# ---------------------------------------------------------------------------


class TestShouldIgnoreGlobPattern:
    """Tests for should_ignore() with fnmatch glob patterns."""

    def test_star_extension_matches_basename(self) -> None:
        assert should_ignore("src/foo.pyc", ["*.pyc"]) is True

    def test_star_extension_matches_nested(self) -> None:
        assert should_ignore("a/b/c/foo.pyc", ["*.pyc"]) is True

    def test_star_extension_no_match(self) -> None:
        assert should_ignore("src/foo.py", ["*.pyc"]) is False

    def test_exact_filename_match(self) -> None:
        assert should_ignore("some/path/secret.key", ["secret.key"]) is True

    def test_full_path_pattern(self) -> None:
        assert should_ignore("docs/internal/draft.md", ["docs/internal/draft.md"]) is True


# ---------------------------------------------------------------------------
# should_ignore — edge cases
# ---------------------------------------------------------------------------


class TestShouldIgnoreEdgeCases:
    """Edge-case tests for should_ignore()."""

    def test_empty_patterns_never_ignores(self) -> None:
        assert should_ignore("vendor/foo.py", []) is False

    def test_empty_patterns_never_ignores_git(self) -> None:
        assert should_ignore(".git/HEAD", []) is False

    def test_absolute_path_with_dir_pattern(self) -> None:
        """Absolute paths with a matching component are still ignored."""
        assert should_ignore("/home/user/project/vendor/lib.py", ["vendor/"]) is True

    def test_absolute_path_no_match(self) -> None:
        assert should_ignore("/home/user/project/src/main.py", ["vendor/"]) is False

    @pytest.mark.parametrize(
        "path",
        [
            ".git/COMMIT_EDITMSG",
            "__pycache__/mod.cpython-312.pyc",
            "src/__pycache__/x.pyc",
            "node_modules/@types/foo.d.ts",
            ".venv/lib/python3.12/site.py",
        ],
    )
    def test_default_patterns_cover_common_noise(self, path: str) -> None:
        """Default patterns should exclude all common non-source noise paths."""
        assert should_ignore(path, DEFAULT_PATTERNS) is True

    @pytest.mark.parametrize(
        "path",
        [
            "src/main.py",
            "tests/unit/test_foo.py",
            "pyproject.toml",
            "Dockerfile",
            "README.md",
        ],
    )
    def test_default_patterns_do_not_exclude_source_files(self, path: str) -> None:
        """Default patterns must not exclude ordinary source files."""
        assert should_ignore(path, DEFAULT_PATTERNS) is False


# ---------------------------------------------------------------------------
# cdk.out exclusion — issue #81
# ---------------------------------------------------------------------------


class TestCdkOutExclusion:
    """cdk.out/ must be excluded by DEFAULT_PATTERNS to prevent double-scanning."""

    def test_cdk_out_in_default_patterns(self) -> None:
        assert "cdk.out/" in DEFAULT_PATTERNS

    def test_cdk_out_template_excluded(self) -> None:
        assert should_ignore("cdk.out/MyStack.template.json", DEFAULT_PATTERNS) is True

    def test_cdk_out_nested_excluded(self) -> None:
        assert (
            should_ignore("cdk.out/assembly-Prod/MyStack.template.json", DEFAULT_PATTERNS) is True
        )

    def test_cdk_out_manifest_excluded(self) -> None:
        assert should_ignore("cdk.out/manifest.json", DEFAULT_PATTERNS) is True


# ---------------------------------------------------------------------------
# Expanded default ignore patterns — issue #85
# ---------------------------------------------------------------------------


class TestExpandedDefaultPatterns:
    """DEFAULT_PATTERNS must exclude build artifacts, agent state, and IDE dirs."""

    @pytest.mark.parametrize(
        "path",
        [
            "build/lib/module.py",
            "dist/package.tar.gz",
            "my_pkg.egg-info/PKG-INFO",
            ".dogfood/fleet-state.json",
            ".temp/scratch.txt",
            ".idea/workspace.xml",
            ".vscode/settings.json",
            "htmlcov/index.html",
            "venv/lib/python3.12/site.py",
            ".tox/py312/lib/x.py",
        ],
    )
    def test_generated_paths_excluded(self, path: str) -> None:
        assert should_ignore(path, DEFAULT_PATTERNS) is True

    @pytest.mark.parametrize(
        "pattern",
        [
            "build/",
            "dist/",
            "*.egg-info/",
            ".dogfood/",
            ".temp/",
            ".idea/",
            ".vscode/",
            "htmlcov/",
            "venv/",
            ".tox/",
        ],
    )
    def test_pattern_in_defaults(self, pattern: str) -> None:
        assert pattern in DEFAULT_PATTERNS


# ---------------------------------------------------------------------------
# Property-based tests (DPS-12)
# ---------------------------------------------------------------------------


class TestProperties:
    """Hypothesis coverage for the path-filtering boundary."""

    @given(
        path=st.one_of(plausible_relative_path(), path_traversal_shaped(), any_path_like_text()),
        patterns=st.lists(st.text(max_size=20), max_size=8),
    )
    @settings(max_examples=300)
    def test_should_ignore_never_raises(self, path: str, patterns: list[str]) -> None:
        """should_ignore must handle any (path, patterns) pair without exception."""
        result = should_ignore(path, patterns)
        assert isinstance(result, bool)

    @given(
        path=st.one_of(plausible_relative_path(), path_traversal_shaped(), any_path_like_text()),
        patterns=st.lists(st.text(max_size=20), max_size=8),
    )
    @settings(max_examples=300)
    def test_should_ignore_determinism(self, path: str, patterns: list[str]) -> None:
        """Same (path, patterns) pair always returns the same bool."""
        first = should_ignore(path, patterns)
        second = should_ignore(path, patterns)
        assert first == second

    @given(path=path_traversal_shaped())
    @settings(max_examples=300)
    def test_path_traversal_shaped_input_is_bounded_and_safe(self, path: str) -> None:
        """``../../etc/passwd``-style traversal input never loops or raises.

        Against DEFAULT_PATTERNS and an empty pattern list — neither should
        ever take a pathological amount of time or blow up on backslash /
        leading-slash / repeated-traversal variants.
        """
        assert isinstance(should_ignore(path, []), bool)
        assert isinstance(should_ignore(path, DEFAULT_PATTERNS), bool)

    @given(depth=st.integers(min_value=0, max_value=500))
    @settings(max_examples=50)
    def test_deep_traversal_depth_is_bounded(self, depth: int) -> None:
        """An absurdly deep ``../../../…`` chain still resolves in bounded time."""
        path = "/".join([".."] * depth) + "/etc/passwd"
        assert isinstance(should_ignore(path, DEFAULT_PATTERNS), bool)


# ---------------------------------------------------------------------------
# task-005: .caliperignore per-path rule-id scoping syntax -> typed RuleScope
#
# Contract this RED suite pins down (implementation TBD in GREEN):
#   - caliper.core.ignore.RuleScope: a typed value with `.glob` and
#     `.rule_prefix` fields.
#   - caliper.core.ignore.load_rule_scopes(repo_path: Path) -> list[RuleScope]
#     reads `.caliperignore` and parses any line of the form
#     "<glob> !<rule_prefix>" into a RuleScope. Lines without the
#     " !" scoping marker are ordinary ignore patterns and are not returned.
#   - A line containing " !" but with no glob before it, or no prefix text
#     after it, is malformed and load_rule_scopes() raises ValueError whose
#     message includes the 1-indexed line number of the offending line.
#   - caliper.core.normalizer.normalize_findings() accepts an optional
#     `rule_scopes: list[RuleScope]` keyword argument. Any Finding whose
#     `file_path` matches a RuleScope's glob AND whose `source_tool` starts
#     with that RuleScope's `rule_prefix` is dropped before it reaches the
#     returned (findings, summary) result.
# ---------------------------------------------------------------------------


class TestRuleScopeParsing:
    """AC1/AC2/AC3: load_rule_scopes() parses per-path rule-id scoping lines."""

    def test_parses_compatibility_tests_ds_prefix_scope(self, tmp_path: Path) -> None:
        """'compatibility-tests/** !DS-' parses into RuleScope(glob=..., rule_prefix='DS-')."""
        from caliper.core.ignore import load_rule_scopes

        (tmp_path / ".caliperignore").write_text("compatibility-tests/** !DS-\n")
        scopes = load_rule_scopes(tmp_path)
        assert len(scopes) == 1
        assert scopes[0].glob == "compatibility-tests/**"
        assert scopes[0].rule_prefix == "DS-"

    def test_parses_tools_docs_cal_002_scope(self, tmp_path: Path) -> None:
        """'tools/docs/** !CAL-002' parses into RuleScope(glob='tools/docs/**', rule_prefix='CAL-002')."""
        from caliper.core.ignore import load_rule_scopes

        (tmp_path / ".caliperignore").write_text("tools/docs/** !CAL-002\n")
        scopes = load_rule_scopes(tmp_path)
        assert len(scopes) == 1
        assert scopes[0].glob == "tools/docs/**"
        assert scopes[0].rule_prefix == "CAL-002"

    def test_multiple_rule_scope_lines_all_parsed(self, tmp_path: Path) -> None:
        """Multiple rule-scope lines in one file each produce their own RuleScope."""
        from caliper.core.ignore import load_rule_scopes

        (tmp_path / ".caliperignore").write_text(
            "compatibility-tests/** !DS-\ntools/docs/** !CAL-002\n"
        )
        scopes = load_rule_scopes(tmp_path)
        globs = {s.glob: s.rule_prefix for s in scopes}
        assert globs == {
            "compatibility-tests/**": "DS-",
            "tools/docs/**": "CAL-002",
        }

    def test_missing_glob_before_bang_raises_value_error_with_line_number(
        self, tmp_path: Path
    ) -> None:
        """A line like '!DS-' with no glob before the '!' is malformed; the
        ValueError message must include the 1-indexed offending line number."""
        from caliper.core.ignore import load_rule_scopes

        (tmp_path / ".caliperignore").write_text("vendor/\n!DS-\n")
        with pytest.raises(ValueError, match="2"):
            load_rule_scopes(tmp_path)

    def test_bang_with_no_following_prefix_raises_value_error_with_line_number(
        self, tmp_path: Path
    ) -> None:
        """A line like 'tools/docs/** !' with a '!' but no prefix text after it
        is malformed; the ValueError message must include the line number."""
        from caliper.core.ignore import load_rule_scopes

        (tmp_path / ".caliperignore").write_text("vendor/\ncomments/\ntools/docs/** !\n")
        with pytest.raises(ValueError, match="3"):
            load_rule_scopes(tmp_path)


class TestNormalizerDropsRuleScopedFindings:
    """AC4: normalizer drops findings matched by a RuleScope's glob + rule prefix."""

    def _finding(self, *, file_path: str, source_tool: str) -> Finding:
        from caliper.core.models import Finding, FindingCategory, FindingSeverity

        return Finding(
            severity=FindingSeverity.high,
            category=FindingCategory.behavioral,
            description="a finding",
            source_tool=source_tool,
            package_name="caliper",
            version="",
            file_path=file_path,
        )

    def test_matching_glob_and_rule_prefix_is_dropped(self) -> None:
        """A Finding whose file matches the scope glob and whose rule id
        starts with the scope's rule_prefix is dropped from the result."""
        from caliper.core.ignore import RuleScope
        from caliper.core.models import ScanResult, ScanResultStatus
        from caliper.core.normalizer import normalize_findings

        scoped = self._finding(file_path="compatibility-tests/legacy/foo.py", source_tool="DS-042")
        result = ScanResult(
            tool_name="detector",
            status=ScanResultStatus.success,
            findings=[scoped],
            duration_seconds=0.1,
        )
        scopes = [RuleScope(glob="compatibility-tests/**", rule_prefix="DS-")]

        merged, _summary = normalize_findings([result], rule_scopes=scopes)

        assert merged == []

    def test_non_matching_rule_id_survives(self) -> None:
        """A Finding under the scoped glob but whose rule id does NOT start
        with the scope's rule_prefix is NOT dropped."""
        from caliper.core.ignore import RuleScope
        from caliper.core.models import ScanResult, ScanResultStatus
        from caliper.core.normalizer import normalize_findings

        survivor = self._finding(
            file_path="compatibility-tests/legacy/foo.py", source_tool="CAL-999"
        )
        result = ScanResult(
            tool_name="detector",
            status=ScanResultStatus.success,
            findings=[survivor],
            duration_seconds=0.1,
        )
        scopes = [RuleScope(glob="compatibility-tests/**", rule_prefix="DS-")]

        merged, _summary = normalize_findings([result], rule_scopes=scopes)

        assert len(merged) == 1
        assert merged[0].source_tool == "CAL-999"

    def test_non_matching_glob_survives(self) -> None:
        """A Finding whose rule id matches the prefix but whose file is
        OUTSIDE the scope's glob is NOT dropped."""
        from caliper.core.ignore import RuleScope
        from caliper.core.models import ScanResult, ScanResultStatus
        from caliper.core.normalizer import normalize_findings

        survivor = self._finding(file_path="src/caliper/core/foo.py", source_tool="DS-042")
        result = ScanResult(
            tool_name="detector",
            status=ScanResultStatus.success,
            findings=[survivor],
            duration_seconds=0.1,
        )
        scopes = [RuleScope(glob="compatibility-tests/**", rule_prefix="DS-")]

        merged, _summary = normalize_findings([result], rule_scopes=scopes)

        assert len(merged) == 1
        assert merged[0].file_path == "src/caliper/core/foo.py"
