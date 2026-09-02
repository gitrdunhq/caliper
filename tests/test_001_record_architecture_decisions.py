# Skeleton: task-018 AC1 — PROP-001
# RED agent: fill in the assertion body. Do not rename this function or move this file.
# Traceability: AC1 → test_ac1_docs_adr_001_md_002_md_003_md_004_md_008_md_each_have_status → tests/test_001_record_architecture_decisions.py
"""
Verify docs/adr/001*.md, 002*.md, 003*.md, 004*.md, 008*.md each have a
'## Status' section set to 'Superseded' with a dated line pointing to a
specific docs/decommission-log.md entry.
# tested-by: tests/test_001_record_architecture_decisions.py
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

ADR_NUMBERS = ["001", "002", "003", "004", "008"]

# Matches a dated line (YYYY-MM-DD) referencing docs/decommission-log.md,
# e.g. "Superseded 2026-09-01 — see docs/decommission-log.md entry 15."
DECOMMISSION_POINTER_RE = re.compile(r"\d{4}-\d{2}-\d{2}.*docs/decommission-log\.md")


def _find_adr_path(number: str) -> Path:
    matches = sorted((REPO_ROOT / "docs" / "adr").glob(f"{number}*.md"))
    assert matches, f"expected exactly one ADR file matching {number}*.md, found none"
    assert (
        len(matches) == 1
    ), f"expected exactly one ADR file matching {number}*.md, found {matches}"
    return matches[0]


def _status_section_text(adr_text: str) -> str:
    """Extract the text of the '## Status' section up to the next '## ' heading."""
    match = re.search(r"^## Status\s*\n(.*?)(?=^## |\Z)", adr_text, flags=re.MULTILINE | re.DOTALL)
    assert match is not None, "ADR file has no '## Status' section"
    return match.group(1)


class TestTask018AC1:
    """PROP-001: every named ADR is marked Superseded with a decommission-log pointer."""

    @pytest.mark.parametrize("adr_number", ADR_NUMBERS)
    def test_ac1_docs_adr_001_md_002_md_003_md_004_md_008_md_each_have_status(
        self, adr_number: str
    ) -> None:
        """
        PROP-001: docs/adr/001*.md, 002*.md, 003*.md, 004*.md, 008*.md each have
        '## Status' set to 'Superseded' with a dated line pointing to a specific
        docs/decommission-log.md entry.
        """
        # Arrange
        adr_path = _find_adr_path(adr_number)
        adr_text = adr_path.read_text(encoding="utf-8")

        # Act
        status_text = _status_section_text(adr_text)

        # Assert — prove PROP-001
        assert "Superseded" in status_text, (
            f"{adr_path.name}: expected '## Status' section to contain 'Superseded', "
            f"got: {status_text!r}"
        )
        assert DECOMMISSION_POINTER_RE.search(status_text), (
            f"{adr_path.name}: expected a dated line in '## Status' pointing to "
            f"docs/decommission-log.md, got: {status_text!r}"
        )

    def test_ac1_decommission_log_has_entries_for_each_superseded_adr(self) -> None:
        """
        PROP-001 (companion): docs/decommission-log.md contains an identifiable
        entry for each of the five superseded ADRs (001, 002, 003, 004, 008).
        """
        # Arrange
        log_path = REPO_ROOT / "docs" / "decommission-log.md"
        assert log_path.exists(), "docs/decommission-log.md must exist"
        log_text = log_path.read_text(encoding="utf-8")

        # Act / Assert — prove PROP-001
        for adr_number in ADR_NUMBERS:
            adr_path = _find_adr_path(adr_number)
            assert adr_path.stem in log_text or adr_number in log_text, (
                f"docs/decommission-log.md has no entry referencing ADR {adr_number} "
                f"({adr_path.name})"
            )
