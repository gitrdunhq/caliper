"""Syft plugin — SBOM generation (CycloneDX).
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from caliper.core.errors import ErrorCode, error_msg
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin

_MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pubspec.yaml",
    "mix.exs",
}


class SyftPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "syft"

    @property
    def description(self) -> str:
        return "SBOM generation — CycloneDX JSON (18 ecosystems)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).name in _MANIFEST_NAMES for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        try:
            r = subprocess.run(
                ["syft", f"dir:{repo_path}", "-o", "cyclonedx-json"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.NOT_INSTALLED, "syft")
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.TIMEOUT, "syft", timeout=0)
            )

        try:
            data = json.loads(r.stdout) if r.stdout else {}
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.PARSE_ERROR, "syft")
            )

        components = data.get("components", [])
        # The full CycloneDX document is intentionally excluded from summary:
        # it can be multi-megabyte and would bloat every JSON report / PR
        # comment carrying this PluginResult, plus over-disclose the whole
        # dependency tree unconditionally. Only small, renderer-friendly
        # metadata lives here; the raw document stays out of the pipeline
        # (#223/#257).
        return PluginResult(
            plugin_name=self.name,
            findings=[],
            summary={
                "components": len(components),
                "bom_format": data.get("bomFormat", ""),
                "spec_version": data.get("specVersion", ""),
            },
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        count = result.summary.get("components", 0)
        if result.error:
            return f"**syft**: {result.error}"
        return f"SBOM: {count} components detected" if count else ""


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("syft")
def build_syft_plugin() -> SyftPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return SyftPlugin()
