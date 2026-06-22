"""Tests for FixedOutputDelimiterDetector.
# tested-by: tests/unit/detectors/security/test_fixed_output_delimiter.py
"""

from __future__ import annotations

import pytest

from caliper.detectors.security.fixed_output_delimiter import FixedOutputDelimiterDetector

# Buggy: classic MEMO_EOF delimiter writing to GITHUB_OUTPUT
BUGGY_MEMO_EOF_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Set memo output
        run: |
          MEMO="some scanner output that could contain delimiters"
          cat >> "$GITHUB_OUTPUT" << 'MEMO_EOF'
          key=$MEMO
          MEMO_EOF
"""

# Buggy: bare EOF (unquoted) writing to GITHUB_OUTPUT
BUGGY_BARE_EOF_YAML = """\
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Write output
        run: |
          VALUE=$(compute_value)
          cat >> "$GITHUB_OUTPUT" << EOF
          result=$VALUE
          EOF
"""

# Buggy: fixed delimiter writing to GITHUB_ENV
BUGGY_GITHUB_ENV_YAML = """\
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - name: Export env var
        run: |
          cat >> "$GITHUB_ENV" << 'DELIMITER'
          MY_VAR=hello
          DELIMITER
"""

# Clean: simple echo-based write — no heredoc
CLEAN_ECHO_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Write output
        run: |
          echo "key=value" >> "$GITHUB_OUTPUT"
          echo "other=result" >> "$GITHUB_OUTPUT"
"""

# Clean: heredoc present but no GITHUB_OUTPUT/GITHUB_ENV reference
CLEAN_NO_OUTPUT_REF_YAML = """\
jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - name: Write a file
        run: |
          cat > report.txt << 'EOF'
          Some content here
          EOF
"""

# Clean: lowercase heredoc word — not flagged (pattern targets ALL_CAPS)
CLEAN_LOWERCASE_DELIMITER_YAML = """\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Debug
        run: |
          echo "data" >> "$GITHUB_OUTPUT"
          cat << 'end_of_block'
          some shell heredoc not targeting GITHUB_OUTPUT
          end_of_block
"""


class TestFixedOutputDelimiterDetector:
    """Tests for FixedOutputDelimiterDetector (CAL-020)."""

    @pytest.fixture
    def detector(self):
        return FixedOutputDelimiterDetector()

    def test_detects_memo_eof_delimiter(self, detector, tmp_path):
        """Flags YAML using fixed MEMO_EOF delimiter with GITHUB_OUTPUT."""
        f = tmp_path / "action.yml"
        f.write_text(BUGGY_MEMO_EOF_YAML)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-020"
        assert findings[0].severity.value == "low"

    def test_detects_bare_eof_delimiter(self, detector, tmp_path):
        """Flags YAML using bare unquoted EOF delimiter with GITHUB_OUTPUT."""
        f = tmp_path / "release.yml"
        f.write_text(BUGGY_BARE_EOF_YAML)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-020"

    def test_detects_delimiter_with_github_env(self, detector, tmp_path):
        """Flags YAML using fixed delimiter with GITHUB_ENV (not just GITHUB_OUTPUT)."""
        f = tmp_path / "setup.yml"
        f.write_text(BUGGY_GITHUB_ENV_YAML)

        findings = detector.detect(f)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-020"

    def test_no_finding_for_echo_based_write(self, detector, tmp_path):
        """No finding when using simple echo >> without a heredoc."""
        f = tmp_path / "build.yml"
        f.write_text(CLEAN_ECHO_YAML)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_no_finding_when_no_github_output_reference(self, detector, tmp_path):
        """No finding for heredoc that does not target GITHUB_OUTPUT or GITHUB_ENV."""
        f = tmp_path / "generate.yml"
        f.write_text(CLEAN_NO_OUTPUT_REF_YAML)

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_no_finding_for_python_file(self, detector, tmp_path):
        """Detector ignores non-YAML files."""
        f = tmp_path / "script.py"
        f.write_text('import os\nos.environ["GITHUB_OUTPUT"] = "value"\n')

        findings = detector.detect(f)

        assert len(findings) == 0

    def test_no_finding_for_missing_file(self, detector, tmp_path):
        """Detector returns empty list for missing files."""
        findings = detector.detect(tmp_path / "nonexistent.yml")
        assert findings == []

    def test_finding_has_issue_reference(self, detector, tmp_path):
        """Finding references issue #233."""
        f = tmp_path / "action.yml"
        f.write_text(BUGGY_MEMO_EOF_YAML)

        findings = detector.detect(f)

        assert findings[0].issue_reference == "#233"

    def test_finding_message_mentions_randomized_delimiter(self, detector, tmp_path):
        """Finding message advises using a randomized delimiter."""
        f = tmp_path / "action.yml"
        f.write_text(BUGGY_MEMO_EOF_YAML)

        findings = detector.detect(f)

        assert (
            "randomized" in findings[0].message.lower() or "random" in findings[0].fix_hint.lower()
        )

    def test_finding_line_number_is_positive(self, detector, tmp_path):
        """Finding line_number is >= 1."""
        f = tmp_path / "action.yml"
        f.write_text(BUGGY_MEMO_EOF_YAML)

        findings = detector.detect(f)

        assert findings[0].line_number >= 1

    def test_target_files_are_yaml(self, detector):
        """Detector targets only YAML files."""
        assert "*.yml" in detector.target_files
        assert "*.yaml" in detector.target_files

    def test_category_is_security(self, detector):
        """Detector category is security."""
        from caliper.detectors.categories import DetectorCategory

        assert detector.category == DetectorCategory.security
