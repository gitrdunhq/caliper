"""Tests for caliper.core.diff — dependency diff detection.

Property domains (DPS-12):
  Determinism   INVARIANT   same requirement/pyproject/package.json line/content
                             always parses to the same result
  (fail-open)   SAFETY      malformed/truncated input never raises — the diff
                             pipeline must degrade to "no dependency change found"
                             rather than crash the whole review
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from caliper.core.diff import (
    DependencyDiffDetector,
    _parse_package_json_deps,
    _parse_pyproject_deps,
    _parse_requirement_line,
)
from caliper.core.models import OperatingMode, RequestType
from tests.unit._strategies import (
    garbage_text,
    malformed_requirement_line,
    valid_requirement_line,
    whitespace_and_control_text,
)

# ---------------------------------------------------------------------------
# Fixtures: sample diff texts
# ---------------------------------------------------------------------------

DIFF_WITH_REQUIREMENTS = """\
diff --git a/requirements.txt b/requirements.txt
index abc1234..def5678 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,4 @@
 flask==2.3.0
+requests==2.31.0
 click>=8.0
"""

DIFF_WITH_PYPROJECT = """\
diff --git a/pyproject.toml b/pyproject.toml
index 111..222 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -5,6 +5,7 @@
 dependencies = [
     "flask>=2.3",
+    "httpx>=0.27",
 ]
"""

DIFF_WITH_PIPFILE = """\
diff --git a/Pipfile b/Pipfile
index aaa..bbb 100644
--- a/Pipfile
+++ b/Pipfile
@@ -1,2 +1,3 @@
 [packages]
+requests = "==2.31.0"
"""

DIFF_NO_DEPENDENCY_FILES = """\
diff --git a/src/app.py b/src/app.py
index 000..111 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1 +1,2 @@
+print("hello")
"""

DIFF_MULTIPLE_FILES = """\
diff --git a/requirements.txt b/requirements.txt
index abc..def 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1,2 @@
+new-pkg==1.0
diff --git a/setup.py b/setup.py
index 111..222 100644
--- a/setup.py
+++ b/setup.py
@@ -1 +1,2 @@
+# change
diff --git a/src/main.py b/src/main.py
index 333..444 100644
--- a/src/main.py
+++ b/src/main.py
@@ -1 +1,2 @@
+pass
"""


# ---------------------------------------------------------------------------
# detect_changed_files
# ---------------------------------------------------------------------------


class TestDetectChangedFiles:
    """Tests for DependencyDiffDetector.detect_changed_files."""

    def test_finds_requirements_txt(self) -> None:

        detector = DependencyDiffDetector()
        result = detector.detect_changed_files(DIFF_WITH_REQUIREMENTS)

        assert "requirements.txt" in result

    def test_finds_pyproject_toml(self) -> None:

        detector = DependencyDiffDetector()
        result = detector.detect_changed_files(DIFF_WITH_PYPROJECT)

        assert "pyproject.toml" in result

    def test_finds_pipfile(self) -> None:

        detector = DependencyDiffDetector()
        result = detector.detect_changed_files(DIFF_WITH_PIPFILE)

        assert "Pipfile" in result

    def test_returns_empty_for_non_dependency_files(self) -> None:

        detector = DependencyDiffDetector()
        result = detector.detect_changed_files(DIFF_NO_DEPENDENCY_FILES)

        assert result == []

    def test_returns_only_dependency_files_from_mixed_diff(self) -> None:

        detector = DependencyDiffDetector()
        result = detector.detect_changed_files(DIFF_MULTIPLE_FILES)

        assert "requirements.txt" in result
        assert "setup.py" in result
        assert "src/main.py" not in result


# ---------------------------------------------------------------------------
# parse_requirements_diff
# ---------------------------------------------------------------------------


class TestParseRequirementsDiff:
    """Tests for DependencyDiffDetector.parse_requirements_diff."""

    def test_new_package_added(self) -> None:

        detector = DependencyDiffDetector()
        before = "flask==2.3.0\nclick>=8.0\n"
        after = "flask==2.3.0\nclick>=8.0\nrequests==2.31.0\n"

        changes = detector.parse_requirements_diff(before, after)

        added = [c for c in changes if c["action"] == "added"]
        assert len(added) == 1
        assert added[0]["package"] == "requests"
        assert added[0]["new_version"] == "2.31.0"
        assert added[0]["old_version"] is None

    def test_package_upgraded(self) -> None:

        detector = DependencyDiffDetector()
        before = "requests==2.28.0\n"
        after = "requests==2.31.0\n"

        changes = detector.parse_requirements_diff(before, after)

        upgraded = [c for c in changes if c["action"] == "upgraded"]
        assert len(upgraded) == 1
        assert upgraded[0]["package"] == "requests"
        assert upgraded[0]["old_version"] == "2.28.0"
        assert upgraded[0]["new_version"] == "2.31.0"

    def test_package_downgraded(self) -> None:

        detector = DependencyDiffDetector()
        before = "requests==2.31.0\n"
        after = "requests==2.28.0\n"

        changes = detector.parse_requirements_diff(before, after)

        downgraded = [c for c in changes if c["action"] == "downgraded"]
        assert len(downgraded) == 1
        assert downgraded[0]["old_version"] == "2.31.0"
        assert downgraded[0]["new_version"] == "2.28.0"

    def test_package_removed(self) -> None:

        detector = DependencyDiffDetector()
        before = "flask==2.3.0\nrequests==2.31.0\n"
        after = "flask==2.3.0\n"

        changes = detector.parse_requirements_diff(before, after)

        removed = [c for c in changes if c["action"] == "removed"]
        assert len(removed) == 1
        assert removed[0]["package"] == "requests"
        assert removed[0]["old_version"] == "2.31.0"
        assert removed[0]["new_version"] is None

    def test_comment_only_change_ignored(self) -> None:

        detector = DependencyDiffDetector()
        before = "# old comment\nflask==2.3.0\n"
        after = "# new comment\nflask==2.3.0\n"

        changes = detector.parse_requirements_diff(before, after)

        assert changes == []

    def test_whitespace_only_change_ignored(self) -> None:

        detector = DependencyDiffDetector()
        before = "flask==2.3.0\n\n"
        after = "flask==2.3.0\n"

        changes = detector.parse_requirements_diff(before, after)

        assert changes == []

    def test_extras_handled(self) -> None:

        detector = DependencyDiffDetector()
        before = ""
        after = "requests[security]==2.31.0\n"

        changes = detector.parse_requirements_diff(before, after)

        added = [c for c in changes if c["action"] == "added"]
        assert len(added) == 1
        assert added[0]["package"] == "requests"

    def test_range_specifier(self) -> None:

        detector = DependencyDiffDetector()
        before = ""
        after = "flask>=2.3.0\n"

        changes = detector.parse_requirements_diff(before, after)

        added = [c for c in changes if c["action"] == "added"]
        assert len(added) == 1
        assert added[0]["package"] == "flask"
        assert added[0]["new_version"] == "2.3.0"


# ---------------------------------------------------------------------------
# parse_pyproject_diff
# ---------------------------------------------------------------------------


class TestParsePyprojectDiff:
    """Tests for DependencyDiffDetector.parse_pyproject_diff."""

    def test_dependency_added(self) -> None:

        detector = DependencyDiffDetector()
        deps_one = '[project]\nname = "myapp"\ndependencies = [\n    "flask>=2.3",\n]\n'
        deps_two = (
            '[project]\nname = "myapp"\ndependencies'
            ' = [\n    "flask>=2.3",\n    "httpx>=0.27",\n]\n'
        )
        before = deps_one
        after = deps_two

        changes = detector.parse_pyproject_diff(before, after)

        added = [c for c in changes if c["action"] == "added"]
        assert len(added) == 1
        assert added[0]["package"] == "httpx"
        assert added[0]["new_version"] == "0.27"

    def test_dependency_removed(self) -> None:

        detector = DependencyDiffDetector()
        deps_one = '[project]\nname = "myapp"\ndependencies = [\n    "flask>=2.3",\n]\n'
        deps_two = (
            '[project]\nname = "myapp"\ndependencies'
            ' = [\n    "flask>=2.3",\n    "httpx>=0.27",\n]\n'
        )
        before = deps_two
        after = deps_one

        changes = detector.parse_pyproject_diff(before, after)

        removed = [c for c in changes if c["action"] == "removed"]
        assert len(removed) == 1
        assert removed[0]["package"] == "httpx"

    def test_dependency_upgraded(self) -> None:

        detector = DependencyDiffDetector()
        before = '[project]\nname = "myapp"\ndependencies = [\n    "flask>=2.3",\n]\n'
        after = '[project]\nname = "myapp"\ndependencies = [\n    "flask>=3.0",\n]\n'

        changes = detector.parse_pyproject_diff(before, after)

        upgraded = [c for c in changes if c["action"] == "upgraded"]
        assert len(upgraded) == 1
        assert upgraded[0]["package"] == "flask"
        assert upgraded[0]["old_version"] == "2.3"
        assert upgraded[0]["new_version"] == "3.0"


# ---------------------------------------------------------------------------
# create_requests
# ---------------------------------------------------------------------------


class TestCreateRequests:
    """Tests for DependencyDiffDetector.create_requests."""

    def test_added_creates_new_package_request(self) -> None:

        detector = DependencyDiffDetector()
        changes = [
            {
                "action": "added",
                "package": "requests",
                "old_version": None,
                "new_version": "2.31.0",
            },
        ]

        requests = detector.create_requests(
            changes,
            ecosystem="pypi",
            team="platform",
            pr_url=None,
            operating_mode=OperatingMode.monitor,
        )

        assert len(requests) == 1
        assert requests[0].request_type == RequestType.new_package
        assert requests[0].package_name == "requests"
        assert requests[0].target_version == "2.31.0"
        assert requests[0].current_version is None

    def test_upgraded_creates_upgrade_request_with_current_version(self) -> None:

        detector = DependencyDiffDetector()
        changes = [
            {
                "action": "upgraded",
                "package": "flask",
                "old_version": "2.3.0",
                "new_version": "3.0.0",
            },
        ]

        requests = detector.create_requests(
            changes,
            ecosystem="pypi",
            team="platform",
            pr_url="https://github.com/org/repo/pull/42",
            operating_mode=OperatingMode.advise,
        )

        assert len(requests) == 1
        assert requests[0].request_type == RequestType.upgrade
        assert requests[0].current_version == "2.3.0"
        assert requests[0].target_version == "3.0.0"
        assert requests[0].pr_url == "https://github.com/org/repo/pull/42"
        assert requests[0].operating_mode == OperatingMode.advise

    def test_downgraded_creates_upgrade_request(self) -> None:

        detector = DependencyDiffDetector()
        changes = [
            {
                "action": "downgraded",
                "package": "flask",
                "old_version": "3.0.0",
                "new_version": "2.3.0",
            },
        ]

        requests = detector.create_requests(
            changes,
            ecosystem="pypi",
            team="platform",
            pr_url=None,
            operating_mode=OperatingMode.monitor,
        )

        assert len(requests) == 1
        assert requests[0].request_type == RequestType.upgrade
        assert requests[0].current_version == "3.0.0"

    def test_removed_generates_no_request(self) -> None:

        detector = DependencyDiffDetector()
        changes = [
            {
                "action": "removed",
                "package": "old-lib",
                "old_version": "1.0.0",
                "new_version": None,
            },
        ]

        requests = detector.create_requests(
            changes,
            ecosystem="pypi",
            team="platform",
            pr_url=None,
            operating_mode=OperatingMode.monitor,
        )

        assert len(requests) == 0

    def test_mixed_changes_filter_removals(self) -> None:

        detector = DependencyDiffDetector()
        changes = [
            {"action": "added", "package": "new-pkg", "old_version": None, "new_version": "1.0"},
            {"action": "removed", "package": "old-pkg", "old_version": "2.0", "new_version": None},
            {
                "action": "upgraded",
                "package": "mid-pkg",
                "old_version": "1.0",
                "new_version": "2.0",
            },
        ]

        requests = detector.create_requests(
            changes,
            ecosystem="pypi",
            team="security",
            pr_url=None,
            operating_mode=OperatingMode.monitor,
        )

        assert len(requests) == 2
        types = {r.request_type for r in requests}
        assert RequestType.new_package in types
        assert RequestType.upgrade in types


# ---------------------------------------------------------------------------
# Property-based tests (DPS-12)
# ---------------------------------------------------------------------------


class TestProperties:
    """Hypothesis coverage for the diff line/content parsing boundary."""

    @given(line=valid_requirement_line())
    @settings(max_examples=200)
    def test_valid_requirement_line_determinism(self, line: str) -> None:
        """Same well-formed requirement line always parses identically."""
        first = _parse_requirement_line(line)
        second = _parse_requirement_line(line)
        assert first == second

    @given(
        line=st.one_of(garbage_text(), malformed_requirement_line(), whitespace_and_control_text())
    )
    @settings(max_examples=300)
    def test_requirement_line_never_raises(self, line: str) -> None:
        """Malformed/garbage requirement-line text never raises — it parses or is None."""
        result = _parse_requirement_line(line)
        assert result is None or isinstance(result, tuple)

    @given(
        line=st.one_of(garbage_text(), malformed_requirement_line(), whitespace_and_control_text())
    )
    @settings(max_examples=300)
    def test_requirement_line_parsing_is_deterministic(self, line: str) -> None:
        """Determinism holds even for the malformed/garbage cases, not just valid ones."""
        assert _parse_requirement_line(line) == _parse_requirement_line(line)

    @given(content=st.one_of(garbage_text(max_size=500), whitespace_and_control_text(max_size=200)))
    @settings(max_examples=200)
    def test_pyproject_parsing_never_raises(self, content: str) -> None:
        """Arbitrary text as pyproject.toml content must degrade to {} , never raise."""
        result = _parse_pyproject_deps(content)
        assert isinstance(result, dict)

    @given(content=st.one_of(garbage_text(max_size=500), whitespace_and_control_text(max_size=200)))
    @settings(max_examples=200)
    def test_package_json_parsing_never_raises(self, content: str) -> None:
        """Arbitrary text as package.json content must degrade to {}, never raise.

        Regression coverage for a real bug: valid-JSON-but-non-object content
        (e.g. a bare number like "6") used to reach ``data.get(...)`` on a
        non-dict and crash with AttributeError instead of falling back to the
        fragment scan.
        """
        result = _parse_package_json_deps(content)
        assert isinstance(result, dict)

    @given(
        content=st.one_of(
            st.integers().map(str),
            st.floats(allow_nan=False, allow_infinity=False).map(str),
            st.booleans().map(lambda b: "true" if b else "false"),
            st.just("null"),
            st.lists(st.integers(), max_size=5).map(str),
        )
    )
    @settings(max_examples=200)
    def test_package_json_non_object_json_never_raises(self, content: str) -> None:
        """Valid JSON scalars/arrays (not objects) must not crash ``.get()`` lookups."""
        result = _parse_package_json_deps(content)
        assert result == {}

    @given(before=garbage_text(max_size=200), after=garbage_text(max_size=200))
    @settings(max_examples=100)
    def test_full_diff_pipeline_never_raises_on_garbage(self, before: str, after: str) -> None:
        """The whole DependencyDiffDetector surface must fail open on garbage content."""
        detector = DependencyDiffDetector()
        assert isinstance(detector.parse_requirements_diff(before, after), list)
        assert isinstance(detector.parse_pyproject_diff(before, after), list)
        assert isinstance(detector.parse_package_json_diff(before, after), list)
