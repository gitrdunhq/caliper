"""typos plugin — source-aware typo detection (crate-ci/typos).
# tested-by: tests/unit/test_typos_plugin.py
"""

from __future__ import annotations

import contextlib
import json
import subprocess
from pathlib import Path

from caliper.core.errors import ErrorCode, error_msg
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin

_TIMEOUT = 60


class TyposPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "typos"

    @property
    def description(self) -> str:
        return "Source-aware typo detection (crate-ci/typos)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return bool(files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        # Run from repo_path with relative paths so typos' ignore-file resolution
        # (.gitignore, _typos.toml) anchors on the project root.
        rel_files = []
        for f in files:
            try:
                rel_files.append(str(Path(f).relative_to(repo_path)))
            except ValueError:
                rel_files.append(f)

        cmd = ["typos", "--format", "json", *rel_files]

        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT,
                check=False,
                cwd=repo_path,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "typos"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "typos", timeout=_TIMEOUT),
            )

        findings = []
        # typos --format json emits newline-delimited JSON, one object per line.
        # Only objects with type == "typo" are findings; other types (errors,
        # binary-file notices) are ignored so the plugin stays fail-open.
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            with contextlib.suppress(json.JSONDecodeError, TypeError):
                obj = json.loads(line)
                if not isinstance(obj, dict) or obj.get("type") != "typo":
                    continue
                corrections = obj.get("corrections") or []
                findings.append(
                    {
                        "file": str(obj.get("path", "")).removeprefix("./"),
                        "line": obj.get("line_num", 0),
                        "severity": "info",
                        "word": obj.get("typo", ""),
                        "suggestions": ", ".join(
                            c if isinstance(c, str) else str(c) for c in corrections
                        ),
                    }
                )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**typos**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>📝 <b>Typos ({len(result.findings)})</b></summary>\n")
        lines.append("| File | Line | Typo | Corrections |")
        lines.append("|------|------|------|-------------|")
        for t in result.findings[:30]:
            lines.append(f"| `{t['file']}` | {t['line']} | `{t['word']}` | {t['suggestions']} |")
        if len(result.findings) > 30:
            lines.append(f"\n*...{len(result.findings) - 30} more*")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("typos")
def build_typos_plugin() -> TyposPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return TyposPlugin()
