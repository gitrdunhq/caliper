"""Semgrep plugin — AST-based code pattern matching.
# tested-by: tests/unit/test_plugin_registry.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.registries import RULE_RUNNERS
from caliper.plugins._runners import (
    semgrep_runner,  # noqa: F401  (registers RULE_RUNNERS["semgrep"])
)

_CODE_EXTS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".rb",
    ".java",
    ".rs",
    ".sh",
    ".tf",
    ".hcl",
    ".yaml",
    ".yml",
    ".swift",
}


class SemgrepPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def description(self) -> str:
        return "Code pattern analysis — AST matching via opengrep (local rules only)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in _CODE_EXTS for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        from caliper.core.repo_config import RepoConfig, load_repo_config

        repo_config: RepoConfig
        try:
            repo_config = load_repo_config(repo_path)
        except (ValueError, OSError):
            repo_config = RepoConfig()
        sg = repo_config.plugins.semgrep

        try:
            data = RULE_RUNNERS.create("semgrep").run(
                files,
                str(repo_path),
                timeout=120,
                extra_config_dirs=sg.extra_config_dirs,
                exclude_rules=sg.exclude_rules,
            )
        except Exception as exc:
            return PluginResult(plugin_name=self.name, error=str(exc))

        if data.get("status") == "error":
            errors = data.get("errors", [])
            msg = errors[0]["message"] if errors else "unknown error"
            return PluginResult(
                plugin_name=self.name,
                error=f"scanner degraded: {msg}",
            )

        findings = []
        for r in data.get("results", []):
            raw_path = r.get("path", "?")
            try:
                rel_path = str(Path(raw_path).relative_to(repo_path))
            except ValueError:
                rel_path = raw_path
            extra = r.get("extra", {})
            # Prefer opengrep/semgrep's native autofix (`extra.fix`) over the
            # custom `extra.metadata.fix_suggestion` convention some rule YAMLs
            # use; fall back to "" so the key always round-trips (#276).
            fix_suggestion = extra.get("fix") or extra.get("metadata", {}).get("fix_suggestion", "")
            findings.append(
                {
                    "rule_id": r.get("check_id", "?"),
                    "file": rel_path,
                    "start_line": r.get("start", {}).get("line", 0),
                    "end_line": r.get("end", {}).get("line", 0),
                    "severity": extra.get("severity", "WARNING"),
                    "message": extra.get("message", ""),
                    "fix_suggestion": fix_suggestion,
                }
            )
        findings.sort(key=lambda f: {"ERROR": 0, "WARNING": 1, "INFO": 2}.get(f["severity"], 3))
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={"total": len(findings)},
        )

    def _render_inline(self, result: PluginResult) -> str:
        if result.error:
            return f"**semgrep**: {result.error}"
        if not result.findings:
            return ""
        lines = [
            "<details open>",
            f"<summary>🔍 <b>Semgrep ({len(result.findings)})</b></summary>\n",
        ]
        for f in result.findings:
            icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(f["severity"], "?")
            rule = f["rule_id"].split(".")[-1]
            lines.append(f"{icon} **`{f['file']}:{f['start_line']}`** — **{rule}**")
            lines.append(f"> {f['message'][:200]}\n")
        lines.append("</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("semgrep")
def build_semgrep_plugin() -> SemgrepPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return SemgrepPlugin()
