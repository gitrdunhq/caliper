"""Tests for ReleaseGateBypassDetector.
# tested-by: tests/unit/detectors/security/test_release_gate.py
"""

from __future__ import annotations

import pytest

from caliper.detectors.security.release_gate import ReleaseGateBypassDetector

BUGGY_YAML = """\
jobs:
  verify-key:
    runs-on: ubuntu-latest
    steps:
      - name: Verify release key
        run: |
          SHA=$(git rev-parse HEAD)
          STORED=$(gh api repos/owner/repo/commits/"$SHA"/status \\
            --jq '[.statuses[] | select(.context == "ci/release-key")] | first | .description')
          if [ -z "$STORED" ] || [ "$STORED" = "null" ]; then
            echo "WARNING: No ci/release-key status found" >&2
            exit 0
          fi
          echo "VERIFIED"
"""

FIXED_YAML = """\
jobs:
  verify-key:
    runs-on: ubuntu-latest
    steps:
      - name: Verify release key
        run: |
          SHA=$(git rev-parse HEAD)
          STORED=$(gh api repos/owner/repo/commits/"$SHA"/status \\
            --jq '[.statuses[] | select(.context == "ci/release-key")] | first | .description')
          if [ -z "$STORED" ] || [ "$STORED" = "null" ]; then
            echo "ERROR: No ci/release-key status found — blocking publication" >&2
            exit 1
          fi
          echo "VERIFIED"
"""

UNRELATED_EXIT_ZERO_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Optional lint
        run: |
          ruff check . || exit 0
"""

NULL_CHECK_BUGGY_YAML = """\
jobs:
  verify:
    steps:
      - name: Check token
        run: |
          TOKEN=$(fetch_token)
          if [ "$TOKEN" = "null" ]; then
            echo "No token" >&2
            exit 0
          fi
"""


class TestReleaseGateBypassDetector:
    """Tests for ReleaseGateBypassDetector (CAL-016)."""

    @pytest.fixture
    def detector(self):
        return ReleaseGateBypassDetector()

    def test_detects_exit_zero_on_empty_check(self, detector, tmp_path):
        """Flags a step that exits 0 when the required status is absent."""
        f = tmp_path / "release.yml"
        f.write_text(BUGGY_YAML)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-016"
        assert "exit 1" in findings[0].fix_hint
        assert findings[0].severity.value == "high"

    def test_no_finding_on_exit_one(self, detector, tmp_path):
        """No finding when empty-check correctly exits 1."""
        f = tmp_path / "release.yml"
        f.write_text(FIXED_YAML)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_detects_null_string_check_with_exit_zero(self, detector, tmp_path):
        """Flags exit 0 when checking for the literal null string."""
        f = tmp_path / "verify.yml"
        f.write_text(NULL_CHECK_BUGGY_YAML)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-016"

    def test_no_finding_for_unrelated_exit_zero(self, detector, tmp_path):
        """No finding when exit 0 is not inside an empty/null check block."""
        f = tmp_path / "build.yml"
        f.write_text(UNRELATED_EXIT_ZERO_YAML)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_no_finding_for_python_file(self, detector, tmp_path):
        """Detector ignores non-YAML files."""
        f = tmp_path / "script.py"
        f.write_text("if not stored:\n    sys.exit(0)\n")

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_no_finding_for_missing_file(self, detector, tmp_path):
        """Detector returns empty list for missing files."""
        findings = detector.detect(tmp_path / "nonexistent.yml")
        assert findings == []

    def test_issue_reference_points_to_parent_bug(self, detector, tmp_path):
        """Finding references parent bug #215."""
        f = tmp_path / "release.yml"
        f.write_text(BUGGY_YAML)

        findings = detector.detect(f)

        assert findings[0].issue_reference == "#215"

    def test_finding_reports_line_number_of_exit_zero(self, detector, tmp_path):
        """Finding line_number points to the exit 0 line."""
        f = tmp_path / "release.yml"
        f.write_text(BUGGY_YAML)

        findings = detector.detect(f)

        lines = BUGGY_YAML.splitlines()
        exit_zero_line = next(i + 1 for i, ln in enumerate(lines) if "exit 0" in ln)
        assert findings[0].line_number == exit_zero_line
