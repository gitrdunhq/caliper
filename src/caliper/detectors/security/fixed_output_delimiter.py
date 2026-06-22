"""FixedOutputDelimiterDetector — fixed heredoc delimiter with GITHUB_OUTPUT/GITHUB_ENV.
# tested-by: tests/unit/detectors/security/test_fixed_output_delimiter.py

GitHub issue: #233
"""

from __future__ import annotations

import re
from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector

# Matches a heredoc marker with a fixed ALL_CAPS constant word (quoted or bare).
# Examples: << 'EOF', << EOF, << 'MEMO_EOF', << DELIMITER
_HEREDOC_RE = re.compile(r"<<\s*'?\"?([A-Z][A-Z_0-9]+)\"?'?")

# Matches any reference to the GitHub Actions output/env sinks.
_GITHUB_SINK_RE = re.compile(r"GITHUB_OUTPUT|GITHUB_ENV")


@register_detector
class FixedOutputDelimiterDetector(BugDetector):
    """Detects fixed heredoc delimiters used to write to GITHUB_OUTPUT or GITHUB_ENV.

    A composite GitHub Action that writes scanner-derived content to
    $GITHUB_OUTPUT or $GITHUB_ENV using a fixed heredoc delimiter (e.g.
    `<< 'EOF'` or `<< MEMO_EOF`) is vulnerable to output injection: if the
    content happens to contain the delimiter string, the heredoc terminates
    early and corrupts or truncates the output block.

    The fix is to use a per-run randomized delimiter, e.g.:
        DELIM=$(openssl rand -hex 8)
        cat >> "$GITHUB_OUTPUT" << "$DELIM"
        key=$value
        $DELIM

    GitHub: #233
    """

    @property
    def detector_id(self) -> str:
        return "CAL-020"

    @property
    def name(self) -> str:
        return "Fixed Heredoc Delimiter with GITHUB_OUTPUT/GITHUB_ENV"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.security

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.low

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.yml", "*.yaml")

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Scan YAML file for fixed heredoc delimiters targeting output sinks."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            return []

        # Fast path: skip files with no reference to GITHUB_OUTPUT or GITHUB_ENV
        if not _GITHUB_SINK_RE.search(content):
            return []

        lines = content.splitlines()
        findings = []

        for i, line in enumerate(lines, 1):
            if not _HEREDOC_RE.search(line):
                continue

            # Look at the current line and up to 3 lines before for a sink reference
            context_start = max(0, i - 4)
            context_lines = lines[context_start:i]
            context = "\n".join(context_lines)

            if not _GITHUB_SINK_RE.search(context):
                continue

            match = _HEREDOC_RE.search(line)
            delimiter = match.group(1) if match else "CONSTANT"

            findings.append(
                DetectorFinding(
                    detector_id=self.detector_id,
                    detector_name=self.name,
                    category=self.category,
                    severity=self.severity,
                    file_path=str(file_path),
                    line_number=i,
                    message=(
                        f"Fixed heredoc delimiter '{delimiter}' used with "
                        f"GITHUB_OUTPUT/GITHUB_ENV; if content contains the delimiter "
                        f"string, it will terminate the block early and corrupt or inject "
                        f"downstream step outputs. Use a randomized delimiter instead."
                    ),
                    snippet=line.strip(),
                    issue_reference="#233",
                    fix_hint=(
                        "Replace the fixed delimiter with a random one: "
                        "DELIM=$(openssl rand -hex 8); "
                        'cat >> "$GITHUB_OUTPUT" << "$DELIM"; ...; $DELIM'
                    ),
                )
            )

        return findings
