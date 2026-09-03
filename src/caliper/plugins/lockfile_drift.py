"""lockfile-drift plugin — manifest changed without its lockfile.
# tested-by: tests/unit/plugins/test_lockfile_drift.py

Pure filesystem inspection: no binary, no subprocess. A changed manifest whose
paired lockfile exists on disk but is absent from the change set means the
resolved dependency set no longer matches the manifest.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path, PurePosixPath

from caliper.core.config import CaliperSettings
from caliper.core.manifest_discovery import LOCKFILE_MAP
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin

# Manifest basename -> lockfile basenames that pair with it (inverse of LOCKFILE_MAP).
_MANIFEST_TO_LOCKFILES: dict[str, list[str]] = {}
for _lockfile, _manifest in LOCKFILE_MAP.items():
    _MANIFEST_TO_LOCKFILES.setdefault(_manifest, []).append(_lockfile)


def _normalize(entry: str, repo_path: Path) -> str | None:
    """Return *entry* as a repo-relative POSIX path, or None if outside the repo."""
    raw = Path(entry)
    if raw.is_absolute():
        candidates = [(raw, repo_path)]
        with contextlib.suppress(OSError):
            candidates.append((raw.resolve(), repo_path.resolve()))
        for abs_path, root in candidates:
            try:
                return PurePosixPath(abs_path.relative_to(root)).as_posix()
            except ValueError:
                continue
        return None
    normalized = os.path.normpath(entry).replace(os.sep, "/")
    if normalized == "." or normalized == ".." or normalized.startswith("../"):
        return None
    return normalized


class LockfileDriftPlugin(ScannerPlugin):
    def __init__(self, settings: CaliperSettings | None = None) -> None:
        # No config knobs yet; accepted for registry/composition symmetry.
        self._settings = settings

    @property
    def name(self) -> str:
        return "lockfile-drift"

    @property
    def description(self) -> str:
        return "Manifest changed without its lockfile"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.supply_chain

    @property
    def diff_only(self) -> bool:
        # A whole-repo file list is suffix-filtered (yarn.lock never appears), so
        # "manifest changed, lockfile did not" is only decidable against a diff.
        return True

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        try:
            return any(PurePosixPath(f).name in _MANIFEST_TO_LOCKFILES for f in files)
        except Exception:
            return False

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            findings = self._detect(files, repo_path)
        except Exception as exc:  # fail-open: never block the pipeline
            return PluginResult(plugin_name=self.name, error=str(exc))
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def _detect(self, files: list[str], repo_path: Path) -> list[dict]:
        changed: set[str] = set()
        for entry in files:
            rel = _normalize(entry, repo_path)
            if rel is not None:
                changed.add(rel)

        findings: list[dict] = []
        for rel in sorted(changed):
            manifest = PurePosixPath(rel)
            lockfile_names = _MANIFEST_TO_LOCKFILES.get(manifest.name)
            if not lockfile_names:
                continue
            present = [
                name for name in lockfile_names if (repo_path / manifest.parent / name).is_file()
            ]
            if not present:
                continue  # no lockfile at all is a different problem
            if any((manifest.parent / name).as_posix() in changed for name in present):
                continue
            lockfile = ", ".join(present)
            findings.append(
                {
                    "file": rel,
                    "line": 1,
                    "rule_id": "lockfile-drift",
                    "severity": "medium",
                    "message": (
                        f"{rel} changed but {lockfile} did not; "
                        "the resolved dependency set no longer matches the manifest"
                    ),
                    "fix_suggestion": f"Regenerate {lockfile} and commit it with the manifest",
                }
            )
        return findings

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        if result.error:
            return f"**lockfile-drift**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>📦 <b>Lockfile drift ({len(result.findings)})</b></summary>\n")
        for n in result.findings[:20]:
            lines.append(f"- `{n['file']}` — {n['message']}")
        if len(result.findings) > 20:
            lines.append(f"- *...{len(result.findings) - 20} more*")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("lockfile-drift")
def build_lockfile_drift_plugin() -> LockfileDriftPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return LockfileDriftPlugin()
