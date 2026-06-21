"""ScanCode plugin — license detection.
# tested-by: tests/unit/test_plugin_scancode.py
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin


class ScanCodePlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "scancode"

    @property
    def description(self) -> str:
        return "License detection (SPDX expression extraction)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return True

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        include_args: list[str] = []
        for f in files:
            try:
                rel = Path(f).relative_to(repo_path)
                include_args += ["--include", str(rel).replace("\\", "/")]
            except ValueError:
                continue

        if not include_args:
            return PluginResult(plugin_name=self.name, findings=[], summary={"total": 0})

        cmd = [
            "scancode",
            "--license",
            "--copyright",
            "--only-findings",
            "--json-pp",
            "-",
            "--strip-root",
            *include_args,
            str(repo_path),
        ]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.NOT_INSTALLED, "scancode")
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.TIMEOUT, "scancode", timeout=60)
            )

        try:
            data = json.loads(r.stdout) if r.stdout else {}
        except json.JSONDecodeError:
            return PluginResult(
                plugin_name=self.name, error=error_msg(ErrorCode.PARSE_ERROR, "scancode")
            )

        findings = []
        for f in data.get("files", []):
            for lic in f.get("license_detections", []):
                spdx = lic.get("license_expression_spdx") or lic.get("license_expression", "")
                confidence = max((m.get("score", 0) for m in lic.get("matches", [])), default=0)
                findings.append(
                    {
                        "file": f.get("path", ""),
                        "license": spdx,
                        "confidence": confidence,
                        "severity": "info",
                        "category": "license",
                    }
                )
            for holder in f.get("copyrights", []):
                statement = holder.get("copyright", "")
                if statement:
                    findings.append(
                        {
                            "file": f.get("path", ""),
                            "copyright": statement,
                            "severity": "info",
                            "category": "copyright",
                        }
                    )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**scancode**: {result.error}"
        if not result.findings:
            return ""
        return f"ScanCode: {len(result.findings)} license detections"


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("scancode")
def build_scancode_plugin() -> ScanCodePlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return ScanCodePlugin()
