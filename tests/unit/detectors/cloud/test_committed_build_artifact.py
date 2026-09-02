"""Tests for the committed-build-artifact-beside-source detector (CAL-027, #499).
# tested-by: tests/unit/detectors/cloud/test_committed_build_artifact.py

CAL-027 is not AST-based: it inspects the target file's name and its
directory siblings only. It never reads the file's content to decide, so
binary or unreadable artifacts must still be classified correctly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.cloud.committed_build_artifact import (
    CommittedBuildArtifactDetector,
)

DETECTOR_ID = "CAL-027"
DETECTOR_NAME = "Committed Build Artifact Beside Source"


def _touch(directory: Path, *names: str) -> Path:
    """Create empty files ``names`` under ``directory``; return the first one."""
    directory.mkdir(parents=True, exist_ok=True)
    created = []
    for name in names:
        target = directory / name
        target.write_text("")
        created.append(target)
    return created[0]


@pytest.fixture
def detector() -> CommittedBuildArtifactDetector:
    return CommittedBuildArtifactDetector()


class TestMetadata:
    """Identity contract for CAL-027."""

    def test_detector_id(self, detector):
        assert detector.detector_id == DETECTOR_ID

    def test_name(self, detector):
        assert detector.name == DETECTOR_NAME

    def test_category_is_process(self, detector):
        assert detector.category == DetectorCategory.process

    def test_severity_is_low(self, detector):
        assert detector.severity == FindingSeverity.low

    @pytest.mark.parametrize("pattern", ["*.js", "*.d.ts", "*.js.map", "output.json"])
    def test_target_files_contain_artifact_patterns(self, detector, pattern):
        assert pattern in detector.target_files


class TestIsApplicable:
    """Only compiled-artifact names are applicable; sources are not."""

    @pytest.mark.parametrize("name", ["a.js", "a.d.ts", "a.js.map", "output.json"])
    def test_artifact_names_are_applicable(self, detector, name):
        assert detector.is_applicable(Path(name)) is True

    @pytest.mark.parametrize("name", ["a.ts", "a.py"])
    def test_source_names_are_not_applicable(self, detector, name):
        assert detector.is_applicable(Path(name)) is False


class TestPositives:
    """An artifact whose source sibling exists fires exactly once at line 1."""

    @pytest.mark.parametrize(
        ("artifact", "source"),
        [
            ("x.js", "x.ts"),
            ("x.js", "x.tsx"),
            ("x.d.ts", "x.ts"),
            ("x.js.map", "x.ts"),
        ],
    )
    def test_compiled_artifact_beside_source_fires_once(self, detector, tmp_path, artifact, source):
        path = _touch(tmp_path / "src", artifact, source)

        findings = detector.detect(path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == DETECTOR_ID
        assert finding.detector_name == DETECTOR_NAME
        assert finding.category == DetectorCategory.process
        assert finding.severity == FindingSeverity.low
        assert finding.file_path == str(path)
        assert finding.line_number == 1
        assert finding.issue_reference == "#499"

    def test_message_names_artifact_and_source_and_says_not_tracked(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.js", "x.ts")

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message
        assert "x.js" in message
        assert "x.ts" in message
        assert "should not be tracked" in message

    def test_tsx_source_is_named_in_message(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.js", "x.tsx")

        findings = detector.detect(path)

        assert len(findings) == 1
        assert "x.tsx" in findings[0].message

    def test_fix_hint_mentions_gitignore(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.js", "x.ts")

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].fix_hint is not None
        assert ".gitignore" in findings[0].fix_hint

    def test_output_json_beside_cdk_json_fires_once(self, detector, tmp_path):
        path = _touch(tmp_path / "infra", "output.json", "cdk.json")

        findings = detector.detect(path)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.detector_id == DETECTOR_ID
        assert finding.file_path == str(path)
        assert finding.line_number == 1
        assert finding.issue_reference == "#499"
        assert finding.fix_hint is not None
        assert ".gitignore" in finding.fix_hint

    def test_output_json_message_mentions_cdk_and_lambda_invoke(self, detector, tmp_path):
        path = _touch(tmp_path / "infra", "output.json", "cdk.json")

        findings = detector.detect(path)

        assert len(findings) == 1
        message = findings[0].message.lower()
        assert "output.json" in message
        assert "cdk" in message
        assert "lambda invoke" in message
        assert "should not be tracked" in message

    def test_output_json_fires_at_any_depth(self, detector, tmp_path):
        path = _touch(tmp_path / "a" / "b" / "c", "output.json", "cdk.json")

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 1

    def test_binary_js_with_source_sibling_still_fires(self, detector, tmp_path):
        """No content read: undecodable bytes in the artifact do not matter."""
        directory = tmp_path / "src"
        directory.mkdir()
        (directory / "x.ts").write_text("export const x = 1;\n")
        path = directory / "x.js"
        path.write_bytes(b"\x00\xff\xfe\x00 not utf-8 \x80\x81")

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 1


class TestNegatives:
    """No source sibling, excluded path components, or inapplicable file."""

    def test_js_without_ts_or_tsx_sibling(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.js", "y.ts", "x.py")

        assert detector.detect(path) == []

    def test_d_ts_without_ts_sibling(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.d.ts")

        assert detector.detect(path) == []

    def test_js_map_without_ts_sibling(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.js.map")

        assert detector.detect(path) == []

    def test_output_json_without_cdk_json_sibling(self, detector, tmp_path):
        path = _touch(tmp_path / "infra", "output.json", "package.json")

        assert detector.detect(path) == []

    def test_cdk_json_in_parent_does_not_count_for_output_json(self, detector, tmp_path):
        _touch(tmp_path / "infra", "cdk.json")
        path = _touch(tmp_path / "infra" / "sub", "output.json")

        assert detector.detect(path) == []

    def test_ts_source_in_parent_does_not_count_for_js(self, detector, tmp_path):
        _touch(tmp_path / "src", "x.ts")
        path = _touch(tmp_path / "src" / "lib", "x.js")

        assert detector.detect(path) == []

    @pytest.mark.parametrize("component", ["node_modules", "dist", "cdk.out"])
    @pytest.mark.parametrize(
        ("artifact", "source"),
        [
            ("x.js", "x.ts"),
            ("x.d.ts", "x.ts"),
            ("x.js.map", "x.ts"),
            ("output.json", "cdk.json"),
        ],
    )
    def test_excluded_path_component_is_skipped(
        self, detector, tmp_path, component, artifact, source
    ):
        path = _touch(tmp_path / component / "pkg", artifact, source)

        assert detector.detect(path) == []

    @pytest.mark.parametrize("component", ["node_modules", "dist", "cdk.out"])
    def test_excluded_component_as_immediate_parent_is_skipped(self, detector, tmp_path, component):
        path = _touch(tmp_path / component, "x.js", "x.ts")

        assert detector.detect(path) == []

    def test_excluded_name_as_prefix_of_component_is_not_excluded(self, detector, tmp_path):
        """Exclusion matches whole path components, not substrings."""
        path = _touch(tmp_path / "distribution", "x.js", "x.ts")

        findings = detector.detect(path)

        assert len(findings) == 1

    def test_ts_source_file_is_not_applicable_via_detect_safe(self, detector, tmp_path):
        path = _touch(tmp_path / "src", "x.ts", "x.js")

        assert detector.detect_safe(path) == []

    def test_missing_file_returns_empty(self, detector, tmp_path):
        assert detector.detect(tmp_path / "src" / "ghost.js") == []

    def test_missing_file_with_existing_source_sibling_returns_empty(self, detector, tmp_path):
        """The artifact itself must exist; a phantom path is not a finding."""
        _touch(tmp_path / "src", "x.ts")

        assert detector.detect(tmp_path / "src" / "x.js") == []


class TestNoqaSuppression:
    """The framework reads line 1 of the artifact for a ``# noqa`` marker.

    The framework's ``_NOQA_PATTERN`` requires a ``#``, so a JavaScript-style
    ``// noqa`` cannot suppress; only ``# noqa`` forms are asserted here.
    """

    def test_noqa_with_detector_code_on_line_1_suppresses(self, detector, tmp_path):
        directory = tmp_path / "src"
        _touch(directory, "x.ts")
        path = directory / "x.js"
        path.write_text("# noqa: CAL-027\nmodule.exports = {};\n")

        assert detector.detect(path) == []

    def test_bare_noqa_on_line_1_suppresses(self, detector, tmp_path):
        directory = tmp_path / "src"
        _touch(directory, "x.ts")
        path = directory / "x.js"
        path.write_text("# noqa\nmodule.exports = {};\n")

        assert detector.detect(path) == []

    def test_noqa_for_other_detector_does_not_suppress(self, detector, tmp_path):
        directory = tmp_path / "src"
        _touch(directory, "x.ts")
        path = directory / "x.js"
        path.write_text("# noqa: CAL-012\nmodule.exports = {};\n")

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 1

    def test_noqa_on_a_later_line_does_not_suppress(self, detector, tmp_path):
        directory = tmp_path / "src"
        _touch(directory, "x.ts")
        path = directory / "x.js"
        path.write_text("module.exports = {};\n# noqa: CAL-027\n")

        findings = detector.detect(path)

        assert len(findings) == 1
        assert findings[0].line_number == 1


class TestProperties:
    """Formal properties (DPS-12)."""

    def test_determinism_same_file_same_findings(self, detector, tmp_path):
        """Determinism / INVARIANT: same input -> identical findings on repeat."""
        path = _touch(tmp_path / "src", "x.js", "x.ts", "x.tsx")

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 1
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_determinism_output_json_same_findings(self, detector, tmp_path):
        """Determinism / INVARIANT: the output.json branch is repeatable too."""
        path = _touch(tmp_path / "infra", "output.json", "cdk.json")

        first = detector.detect(path)
        second = detector.detect(path)

        assert len(first) == 1
        assert [f.model_dump() for f in first] == [f.model_dump() for f in second]

    def test_fail_open_on_directory_passed_as_file(self, detector, tmp_path):
        """Availability / LIVENESS: a directory named like an artifact never raises."""
        directory = tmp_path / "src" / "x.js"
        directory.mkdir(parents=True)
        _touch(tmp_path / "src", "x.ts")

        assert detector.detect(directory) == []

    def test_fail_open_on_missing_file(self, detector, tmp_path):
        """Availability / LIVENESS: a nonexistent path never raises, returns []."""
        assert detector.detect(tmp_path / "does_not_exist.js") == []

    def test_fail_open_on_missing_output_json(self, detector, tmp_path):
        """Availability / LIVENESS: missing output.json beside cdk.json returns []."""
        _touch(tmp_path / "infra", "cdk.json")

        assert detector.detect(tmp_path / "infra" / "output.json") == []
