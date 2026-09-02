"""Test code is excluded from scans by default; ``--include-tests`` opts back in.
# tested-by: tests/unit/test_ignore_tests_default.py

Findings in test code are noise for a CI gate (fixtures with pinned-old deps,
intentionally bad samples, mock secrets). The exclusion layer drops test
directories and test-named files unless the reviewer asks for them, via
``CALIPER_INCLUDE_TESTS=1`` or ``caliper review --include-tests``.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from caliper.core.config import CaliperSettings
from caliper.core.ignore import DEFAULT_PATTERNS, TEST_PATTERNS, load_ignore_patterns, should_ignore

_TEST_PATHS = [
    "tests/unit/test_x.py",
    "src/pkg/tests/helpers.py",
    "test/foo.go",
    "web/src/__tests__/app.tsx",
    "internal/testdata/golden.json",
    "src/pkg/test_thing.py",
    "src/pkg/thing_test.py",
    "src/pkg/conftest.py",
    "pkg/handler_test.go",
    "web/src/app.test.ts",
    "web/src/app.spec.tsx",
    "web/src/util.test.js",
    "src/main/java/FooTest.java",
    "src/main/java/FooTests.java",
    "Sources/App/FooTests.swift",
    "lib/foo_spec.rb",
    "lib/foo_test.rb",
]

_NOT_TEST_PATHS = [
    "src/pkg/testing_utils.py",  # not a test file, "testing" != "tests"
    "src/pkg/contest.py",
    "src/attest/handler.py",
    "src/pkg/latest.ts",
    "docs/spec/openapi.yaml",  # spec/ is NOT a test dir (OpenAPI specs live there)
    "src/fixtures_loader.py",
]


@pytest.mark.parametrize("path", _TEST_PATHS)
def test_test_code_is_ignored_by_default(path: str, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CALIPER_INCLUDE_TESTS", raising=False)
    assert should_ignore(path, load_ignore_patterns(tmp_path))


@pytest.mark.parametrize("path", _NOT_TEST_PATHS)
def test_look_alike_paths_are_not_ignored(path: str, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("CALIPER_INCLUDE_TESTS", raising=False)
    assert not should_ignore(path, load_ignore_patterns(tmp_path))


def test_include_tests_kwarg_keeps_test_code(tmp_path: Path) -> None:
    patterns = load_ignore_patterns(tmp_path, include_tests=True)
    assert patterns == DEFAULT_PATTERNS
    assert not should_ignore("tests/unit/test_x.py", patterns)


def test_default_patterns_are_test_patterns_plus_build_defaults(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.delenv("CALIPER_INCLUDE_TESTS", raising=False)
    assert load_ignore_patterns(tmp_path) == DEFAULT_PATTERNS + TEST_PATTERNS
    assert not (set(DEFAULT_PATTERNS) & set(TEST_PATTERNS))


def test_env_var_opts_in(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CALIPER_INCLUDE_TESTS", "1")
    assert CaliperSettings().include_tests is True
    assert not should_ignore("tests/unit/test_x.py", load_ignore_patterns(tmp_path))


def test_caliperignore_user_patterns_still_apply_with_tests_included(tmp_path: Path) -> None:
    (tmp_path / ".caliperignore").write_text("vendor/\n")
    patterns = load_ignore_patterns(tmp_path, include_tests=True)
    assert should_ignore("vendor/x.py", patterns)
    assert not should_ignore("tests/x.py", patterns)


class TestReviewFlag:
    def test_review_help_lists_include_tests(self) -> None:
        from caliper.cli.main import cli

        result = CliRunner().invoke(cli, ["review", "--help"])
        assert result.exit_code == 0
        assert "--include-tests" in result.output

    def test_flag_sets_the_setting_for_the_run(self, monkeypatch) -> None:
        from caliper.cli.review_cmd import apply_include_tests

        monkeypatch.delenv("CALIPER_INCLUDE_TESTS", raising=False)
        apply_include_tests(True)
        assert CaliperSettings().include_tests is True
        apply_include_tests(False)
        assert CaliperSettings().include_tests is False


class TestExtendedTestDirComponentPatterns:
    """task-004: TEST_PATTERNS should match *-tests/*_tests/*-test/*_test directory
    components (compatibility-tests/, unit_tests/, e2e-test/), while continuing to
    leave spec/ and fixtures/ alone and not falsely matching look-alike words that
    merely contain "test" as a substring (attest, latest, contest).
    """

    def test_ac1_dash_tests_directory_component_is_ignored(self) -> None:
        assert should_ignore("compatibility-tests/foo.py", TEST_PATTERNS) is True

    def test_ac2_underscore_tests_directory_component_is_ignored(self) -> None:
        assert should_ignore("pkg/unit_tests/bar.py", TEST_PATTERNS) is True

    def test_ac3_dash_test_directory_component_is_ignored(self) -> None:
        assert should_ignore("pkg/e2e-test/baz.py", TEST_PATTERNS) is True

    def test_ac4_spec_directory_is_still_not_ignored(self) -> None:
        assert should_ignore("spec/foo.py", TEST_PATTERNS) is False

    def test_ac5_fixtures_directory_is_still_not_ignored(self) -> None:
        assert should_ignore("fixtures/foo.py", TEST_PATTERNS) is False

    def test_ac6_lookalike_substrings_are_not_falsely_matched(self) -> None:
        assert should_ignore("attest/foo.py", TEST_PATTERNS) is False
        assert should_ignore("src/latest.ts", TEST_PATTERNS) is False
        assert should_ignore("src/contest.py", TEST_PATTERNS) is False
