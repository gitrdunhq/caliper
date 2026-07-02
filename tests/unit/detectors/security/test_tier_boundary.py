"""Tests for TierBoundaryDetector (CAL-022).
# tested-by: tests/unit/detectors/security/test_tier_boundary.py
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from caliper.core.models import FindingSeverity
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.security.tier_boundary import TierBoundaryDetector

_CONFIG_YAML = dedent("""\
    architecture:
      package: myapp
      src_root: src/myapp
      tiers:
        api: presentation
        core: core
        db: data
      allow:
        presentation: [presentation, core, kernel]
        core: [core, data, kernel]
        data: [data, core, kernel]
    """)


def _configured_repo(tmp_path: Path) -> Path:
    (tmp_path / ".caliper.yaml").write_text(_CONFIG_YAML, encoding="utf-8")
    for tier_dir in ("api", "core", "db"):
        (tmp_path / "src" / "myapp" / tier_dir).mkdir(parents=True, exist_ok=True)
    return tmp_path


class TestTierBoundaryDetector:
    @pytest.fixture
    def detector(self) -> TierBoundaryDetector:
        return TierBoundaryDetector()

    # ------------------------------------------------------------------ #
    # Properties                                                          #
    # ------------------------------------------------------------------ #

    def test_detector_id(self, detector: TierBoundaryDetector) -> None:
        assert detector.detector_id == "CAL-022"

    def test_category_is_security(self, detector: TierBoundaryDetector) -> None:
        assert detector.category == DetectorCategory.security

    def test_severity_is_medium(self, detector: TierBoundaryDetector) -> None:
        assert detector.severity == FindingSeverity.medium

    # ------------------------------------------------------------------ #
    # Unconfigured repo -- fail-open, never fabricates a layering         #
    # ------------------------------------------------------------------ #

    def test_no_caliper_yaml_yields_no_findings(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        file_path = tmp_path / "src" / "myapp" / "db" / "writer.py"
        file_path.parent.mkdir(parents=True)
        file_path.write_text("import myapp.api.handlers\n", encoding="utf-8")

        assert detector.detect(file_path) == []

    def test_caliper_yaml_without_architecture_section_yields_no_findings(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        (tmp_path / ".caliper.yaml").write_text("plugins: {}\n", encoding="utf-8")
        file_path = tmp_path / "src" / "myapp" / "db" / "writer.py"
        file_path.parent.mkdir(parents=True)
        file_path.write_text("import myapp.api.handlers\n", encoding="utf-8")

        assert detector.detect(file_path) == []

    # ------------------------------------------------------------------ #
    # Configured repo -- upward/disallowed import is flagged              #
    # ------------------------------------------------------------------ #

    def test_data_tier_importing_presentation_tier_is_flagged(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        repo = _configured_repo(tmp_path)
        file_path = repo / "src" / "myapp" / "db" / "writer.py"
        file_path.write_text("import myapp.api.handlers\n", encoding="utf-8")

        findings = detector.detect(file_path)

        assert len(findings) == 1
        assert findings[0].detector_id == "CAL-022"
        assert findings[0].line_number == 1
        assert "data" in findings[0].message
        assert "presentation" in findings[0].message

    def test_relative_upward_import_is_flagged(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        """A relative import crossing a tier boundary is resolved, not skipped."""
        repo = _configured_repo(tmp_path)
        file_path = repo / "src" / "myapp" / "db" / "writer.py"
        file_path.write_text("from ..api import handlers\n", encoding="utf-8")

        findings = detector.detect(file_path)

        assert len(findings) == 1

    def test_tier_omitted_from_allow_defaults_to_self_only(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        """A tier missing from `allow` may only import itself (default-deny)."""
        (tmp_path / ".caliper.yaml").write_text(
            dedent("""\
                architecture:
                  package: myapp
                  src_root: src/myapp
                  tiers:
                    api: presentation
                    core: core
                  allow: {}
                """),
            encoding="utf-8",
        )
        (tmp_path / "src" / "myapp" / "api").mkdir(parents=True)
        (tmp_path / "src" / "myapp" / "core").mkdir(parents=True)
        file_path = tmp_path / "src" / "myapp" / "api" / "handlers.py"
        file_path.write_text("import myapp.core.service\n", encoding="utf-8")

        findings = detector.detect(file_path)

        assert len(findings) == 1
        assert "presentation" in findings[0].message

    # ------------------------------------------------------------------ #
    # Configured repo -- allowed import is not flagged                    #
    # ------------------------------------------------------------------ #

    def test_core_importing_data_is_allowed(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        repo = _configured_repo(tmp_path)
        file_path = repo / "src" / "myapp" / "core" / "service.py"
        file_path.write_text("import myapp.db.writer\n", encoding="utf-8")

        assert detector.detect(file_path) == []

    def test_file_outside_configured_src_root_yields_no_findings(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        repo = _configured_repo(tmp_path)
        outside = repo / "scripts" / "migrate.py"
        outside.parent.mkdir(parents=True)
        outside.write_text("import myapp.api.handlers\n", encoding="utf-8")

        assert detector.detect(outside) == []

    def test_unmapped_subdirectory_is_skipped(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        repo = _configured_repo(tmp_path)
        (repo / "src" / "myapp" / "unmapped").mkdir()
        file_path = repo / "src" / "myapp" / "unmapped" / "thing.py"
        file_path.write_text("import myapp.api.handlers\n", encoding="utf-8")

        assert detector.detect(file_path) == []

    # ------------------------------------------------------------------ #
    # Fail-open on malformed input                                        #
    # ------------------------------------------------------------------ #

    def test_syntax_error_yields_no_findings(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        repo = _configured_repo(tmp_path)
        file_path = repo / "src" / "myapp" / "db" / "broken.py"
        file_path.write_text("def (:\n", encoding="utf-8")

        assert detector.detect(file_path) == []

    def test_nonexistent_file_returns_empty_list(
        self, detector: TierBoundaryDetector, tmp_path: Path
    ) -> None:
        repo = _configured_repo(tmp_path)
        assert detector.detect(repo / "src" / "myapp" / "db" / "ghost.py") == []
