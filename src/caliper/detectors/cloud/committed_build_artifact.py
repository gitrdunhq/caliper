"""Detector for committed build artifacts sitting beside their source (#499).
# tested-by: tests/unit/detectors/cloud/test_committed_build_artifact.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.models import FindingSeverity
from caliper.detectors._registry import register_detector
from caliper.detectors.categories import DetectorCategory
from caliper.detectors.findings import DetectorFinding
from caliper.detectors.framework import BugDetector


@register_detector
class CommittedBuildArtifactDetector(BugDetector):
    """Detects compiled output tracked next to the source that produces it.

    Process issue: a ``.js``, ``.d.ts``, or ``.js.map`` that sits beside its
    ``.ts``/``.tsx`` source is compiler output that drifts from the source the
    moment anyone edits it. Likewise an ``output.json`` beside a ``cdk.json``
    is the leftover of ``aws lambda invoke ... output.json``. Neither belongs
    in version control.

    Not AST-based: the decision is made from the file name and its directory
    siblings only. The artifact's content is never read to decide, so binary
    or unreadable artifacts are classified the same as text ones.

    GitHub: #499
    """

    # Any exact path component in this set means the file is vendored or
    # emitted into a build tree, which is not what this detector is about.
    EXCLUDED_COMPONENTS = frozenset({"node_modules", "dist", "cdk.out"})

    # Artifact suffixes, longest first so ``x.d.ts`` / ``x.js.map`` are not
    # mis-stemmed by the shorter ``.js`` rule.
    ARTIFACT_SUFFIXES = (".js.map", ".d.ts", ".js")

    # Source siblings that make a TypeScript artifact compiled output.
    SOURCE_SUFFIXES = (".ts", ".tsx")

    CDK_OUTPUT_NAME = "output.json"
    CDK_CONFIG_NAME = "cdk.json"

    @property
    def detector_id(self) -> str:
        return "CAL-027"

    @property
    def name(self) -> str:
        return "Committed Build Artifact Beside Source"

    @property
    def category(self) -> DetectorCategory:
        return DetectorCategory.process

    @property
    def severity(self) -> FindingSeverity:
        return FindingSeverity.low

    @property
    def target_files(self) -> tuple[str, ...]:
        return ("*.js", "*.d.ts", "*.js.map", self.CDK_OUTPUT_NAME)

    def detect(self, file_path: Path) -> list[DetectorFinding]:
        """Report the artifact when its source sibling exists in the same directory.

        Fail-open: any IO or lookup failure yields no findings.
        """
        try:
            return self._detect(file_path)
        except Exception:  # noqa: BLE001 - fail-open by design
            return []

    def _detect(self, file_path: Path) -> list[DetectorFinding]:
        if not file_path.is_file():
            return []
        if self._in_excluded_tree(file_path):
            return []

        message = self._artifact_message(file_path)
        if message is None:
            return []

        if not self._report_allowed(file_path):
            return []

        return [
            DetectorFinding(
                detector_id=self.detector_id,
                detector_name=self.name,
                category=self.category,
                severity=self.severity,
                file_path=str(file_path),
                line_number=1,
                message=message,
                issue_reference="#499",
                fix_hint="Delete it and add the pattern to .gitignore",
            )
        ]

    def _in_excluded_tree(self, file_path: Path) -> bool:
        """True when any whole path component is an excluded directory name."""
        return any(part in self.EXCLUDED_COMPONENTS for part in file_path.parts[:-1])

    def _artifact_message(self, file_path: Path) -> str | None:
        """Return the finding message, or None when no source sibling exists."""
        name = file_path.name
        directory = file_path.parent

        if name == self.CDK_OUTPUT_NAME:
            if not (directory / self.CDK_CONFIG_NAME).is_file():
                return None
            return (
                f"{name} beside {self.CDK_CONFIG_NAME} is the leftover of an "
                "`aws lambda invoke ... output.json` in a CDK project and "
                "should not be tracked"
            )

        stem = self._artifact_stem(name)
        if stem is None:
            return None
        source = self._source_sibling(directory, stem)
        if source is None:
            return None
        return f"{name} is compiled output of {source} and should not be tracked"

    def _artifact_stem(self, name: str) -> str | None:
        """Strip the artifact suffix; None when the name is not an artifact."""
        for suffix in self.ARTIFACT_SUFFIXES:
            if name.endswith(suffix) and len(name) > len(suffix):
                return name[: -len(suffix)]
        return None

    def _source_sibling(self, directory: Path, stem: str) -> str | None:
        """Name of the first ``.ts``/``.tsx`` sibling for ``stem``, if any."""
        for suffix in self.SOURCE_SUFFIXES:
            candidate = directory / f"{stem}{suffix}"
            if candidate.is_file():
                return candidate.name
        return None

    def _report_allowed(self, file_path: Path) -> bool:
        """Honour a ``# noqa`` on line 1 without requiring readable content.

        The framework decodes the file as UTF-8 and only swallows ``OSError``;
        an undecodable (binary) artifact must still be reported, so a decode
        failure counts as "not suppressed".
        """
        try:
            return self._should_report_finding(file_path, 1)
        except ValueError:  # UnicodeDecodeError is a ValueError
            return True
