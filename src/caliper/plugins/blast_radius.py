"""Blast radius plugin — code graph impact analysis.
# tested-by: tests/unit/test_blast_radius.py

Pure Python. No LLM. No external binary. AST → SQLite → SQL checks.
Extensible via custom SQL checks: graph.register_check(name, query).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import structlog

from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.plugins._runners.graph_builder import CodeGraph, resolve_graph_db_path

logger = structlog.get_logger(__name__)

_CODE_EXTS = {".py", ".ts", ".tsx", ".js", ".jsx"}


class BlastRadiusPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "blast-radius"

    @property
    def description(self) -> str:
        return "Code graph impact analysis — AST to SQLite, SQL checks"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.quality

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).suffix in _CODE_EXTS for f in files)

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        from caliper.core.repo_config import load_repo_config

        config = load_repo_config(repo_path)
        br_thresholds = config.thresholds.get("blast-radius", {})
        fan_out_limit = br_thresholds.get("fan_out_limit", 8)

        # Issue #391: the graph db defaults to the user cache dir — reviewing
        # a repo must not dirty it. Explicit overrides (CALIPER_GRAPH_DB env var
        # or `thresholds.blast-radius.graph_db` in .caliper.yaml) and
        # pre-existing legacy in-repo dbs are honored by the resolver.
        resolved_db = resolve_graph_db_path(repo_path, br_thresholds.get("graph_db"))
        db_dir = resolved_db.parent
        db_name = resolved_db.name
        try:
            db_dir.mkdir(parents=True, exist_ok=True)
            test_file = db_dir / ".write_test"
            test_file.touch()
            test_file.unlink()
        except OSError:
            logger.warning(
                "blast-radius: graph db dir not writable, using temp dir",
                db_dir=str(db_dir),
            )
            db_dir = Path(tempfile.mkdtemp(prefix="caliper-blast-radius-"))
        db_path = str(db_dir / db_name)

        # Issue #387: CodeGraph normalizes repo-relative/absolute paths at its
        # API boundary once repo_root is known — no manual conversion needed.
        graph = CodeGraph(db_path=db_path, fan_out_limit=fan_out_limit, repo_root=repo_path)

        if graph.stats()["symbols"] == 0:
            graph.index_directory(repo_path)
        else:
            graph.rebuild_incremental(files)

        changed = [f for f in files if Path(f).suffix in _CODE_EXTS]

        findings = graph.run_checks(changed)
        stats = graph.stats()

        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={
                "symbols_indexed": stats["symbols"],
                "edges": stats["edges"],
                "files_indexed": stats["files"],
                "checks_run": stats["checks"],
                "findings": len(findings),
            },
        )

    def _template_context(self, result: PluginResult) -> dict:
        ctx = super()._template_context(result)
        by_sev: dict[str, list[dict]] = {}
        for f in result.findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)
        ctx["findings_by_sev"] = by_sev
        return ctx

    def _render_inline(
        self,
        result: PluginResult,
    ) -> str:
        if result.error:
            return f"**blast-radius**: {result.error}"
        if not result.findings:
            s = result.summary
            indexed = s.get("symbols_indexed", 0)
            if indexed:
                return f"**Blast Radius**: {indexed} symbols indexed, no issues found"
            return ""

        by_sev: dict[str, list[dict]] = {}
        for f in result.findings:
            by_sev.setdefault(f.get("severity", "info"), []).append(f)

        lines = ["<details open>"]
        lines.append(f"<summary>💥 <b>Blast Radius ({len(result.findings)})</b></summary>\n")

        sev_order = ["critical", "high", "medium", "info"]
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "info": "ℹ️",
        }

        for sev in sev_order:
            items = by_sev.get(sev, [])
            if not items:
                continue
            lines.append(f"**{icons.get(sev, '•')} {sev.upper()} ({len(items)})**\n")
            for f in items[:10]:
                check = f.get("check", "?")
                desc = f.get("description", "")
                name = f.get("name", "")
                file = f.get("file", "")
                extra = ""
                if "dependents" in f:
                    extra = f" — {f['dependents']} dependents"
                elif "calls_out" in f:
                    extra = f" — {f['calls_out']} outgoing calls"
                elif "depth" in f:
                    extra = f" — depth {f['depth']}"
                if name:
                    lines.append(f"- `{name}` ({file}){extra} — {check}")
                elif "file_a" in f:
                    lines.append(f"- `{f['file_a']}` ↔ `{f['file_b']}` — {check}")
                elif file:
                    lines.append(f"- `{file}` — {check}")
                else:
                    lines.append(f"- {desc}{extra}")

        s = result.summary
        lines.append(
            f"\n*{s.get('symbols_indexed', 0)} symbols,"
            f" {s.get('edges', 0)} edges,"
            f" {s.get('checks_run', 0)} checks*"
        )
        lines.append("\n</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("blast-radius")
def build_blast_radius_plugin() -> BlastRadiusPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return BlastRadiusPlugin()
