"""cspell plugin — code-aware spell checking.
# tested-by: tests/unit/test_cspell_plugin.py
"""

from __future__ import annotations

import contextlib
import json
import re
import subprocess
from pathlib import Path

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import PluginCategory, PluginResult, ScannerPlugin


class CspellPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "cspell"

    @property
    def description(self) -> str:
        return "Code-aware spell checking (en-CA)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return bool(files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        # cspell 8.x skips files given as absolute paths outside the project root.
        # Run from repo_path with relative paths so glob resolution works.
        rel_files = []
        for f in files:
            try:
                rel_files.append(str(Path(f).relative_to(repo_path)))
            except ValueError:
                rel_files.append(f)

        cmd = [
            "cspell",
            "lint",
            "--reporter",
            "@cspell/cspell-json-reporter",
            "--no-progress",
            "--no-summary",
            "--gitignore",
            *rel_files,
        ]

        try:
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                cwd=repo_path,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "cspell"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "cspell", timeout=60),
            )

        findings = []
        output = r.stdout or ""

        with contextlib.suppress(json.JSONDecodeError, KeyError, TypeError):
            data = json.loads(output)
            for issue in data.get("issues", []):
                findings.append(
                    {
                        "file": issue.get("uri", "").removeprefix("file://"),
                        "line": issue.get("row", 0),
                        "severity": "info",
                        "word": issue.get("text", ""),
                        "suggestions": ", ".join(
                            s if isinstance(s, str) else str(s)
                            for s in issue.get("suggestions", [])
                        ),
                    }
                )

        # Fallback: parse text output from default reporter
        if not findings:
            output = r.stdout or r.stderr or ""
            pattern = re.compile(
                r"^(?P<file>.+?):(?P<line>\d+)(?::\d+)?\s*-?\s*Unknown word\s*"
                r"\((?P<word>[^)]+)\)"
            )
            for line in output.strip().split("\n"):
                match = pattern.match(line.strip())
                if match:
                    with contextlib.suppress(ValueError):
                        findings.append(
                            {
                                "file": match.group("file"),
                                "line": int(match.group("line")),
                                "severity": "info",
                                "word": match.group("word"),
                                "suggestions": "",
                            }
                        )

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def render(self, result: PluginResult, template_dir: Path | None = None) -> str:
        if result.error:
            return f"**cspell**: {result.error}"
        if not result.findings:
            return ""
        lines = ["<details open>"]
        lines.append(f"<summary>📝 <b>Spelling ({len(result.findings)})</b></summary>\n")
        lines.append("| File | Line | Word | Suggestions |")
        lines.append("|------|------|------|-------------|")
        for t in result.findings[:30]:
            lines.append(f"| `{t['file']}` | {t['line']} | `{t['word']}` | {t['suggestions']} |")
        if len(result.findings) > 30:
            lines.append(f"\n*...{len(result.findings) - 30} more*")
        lines.append("\n</details>\n")
        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("cspell")
def build_cspell_plugin() -> CspellPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return CspellPlugin()
