"""Semgrep plugin — AST-based code pattern matching.
# tested-by: tests/unit/test_plugin_registry.py
# tested-by: tests/unit/plugins/test_semgrep_plugin.py
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.config import CaliperSettings
from caliper.core.models import FindingSeverity, normalize_severity
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.port_registries import RULE_RUNNERS
from caliper.plugins._runners import (
    semgrep_runner,  # noqa: F401  (registers RULE_RUNNERS["semgrep"])
)

_SEVERITY_ORDER = {s.value: i for i, s in enumerate(FindingSeverity)}
_SEVERITY_ICON = {"critical": "🔴", "high": "🔴", "medium": "🟡", "low": "ℹ️", "info": "ℹ️"}

# Historical plugin-specific default (predates settings wiring, #432a). Kept as
# the fallback when no CaliperSettings is supplied so existing callers that
# construct this plugin bare keep their current timeout; pass ``settings`` to
# honor CaliperSettings.scanner_timeout instead.
_DEFAULT_TIMEOUT = 120

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


def _settings_from_env() -> CaliperSettings | None:
    """Best-effort CaliperSettings from the environment; None if it cannot load."""
    try:
        return CaliperSettings()  # type: ignore[call-arg]
    except Exception:  # noqa: BLE001 — fail-open: no env settings, no community rules
        return None


def _dotted_prefixes(*dirs: str | None) -> tuple[str, ...]:
    """opengrep rewrites a local rule id to ``<dotted config path>.<id>``; these are ours."""
    out = []
    for d in dirs:
        if d:
            out.append(str(d).strip("/").replace("/", ".") + ".")
    return tuple(out)


def _strip_rule_prefix(check_id: str, prefixes: tuple[str, ...]) -> str:
    for pre in prefixes:
        if check_id.startswith(pre):
            return check_id[len(pre) :]
    return check_id


def _resolve_org_rules_dir(settings: CaliperSettings | None) -> str | None:
    """Explicit setting wins; else ``<policies dir>/semgrep`` beside the OPA policy."""
    if settings is None:
        return None
    if settings.semgrep_org_rules_dir:
        return settings.semgrep_org_rules_dir
    policy = Path(settings.opa_policy_path)
    base = policy if policy.is_dir() else policy.parent
    cand = base / "semgrep"
    return str(cand) if cand.is_dir() else None


class SemgrepPlugin(ScannerPlugin):
    def __init__(self, settings: CaliperSettings | None = None) -> None:
        # The registry constructs plugins bare, so env-driven settings (the image
        # sets CALIPER_SEMGREP_RULES_DIR / _ORG_RULES_DIR) must still take effect.
        self._timeout = settings.scanner_timeout if settings is not None else _DEFAULT_TIMEOUT
        resolved = settings if settings is not None else _settings_from_env()
        self._rules_dir = resolved.semgrep_rules_dir if resolved is not None else None
        self._org_rules_dir = _resolve_org_rules_dir(resolved)

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def description(self) -> str:
        return "Code pattern analysis — opengrep over a pinned semgrep-rules snapshot + org rules"

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
                timeout=self._timeout,
                extra_config_dirs=sg.extra_config_dirs,
                exclude_rules=sg.exclude_rules,
                rules_dir=self._rules_dir,
                org_rules_dir=self._org_rules_dir,
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

        prefixes = _dotted_prefixes(self._rules_dir, self._org_rules_dir)
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
                    "rule_id": _strip_rule_prefix(r.get("check_id", "?"), prefixes),
                    "file": rel_path,
                    "start_line": r.get("start", {}).get("line", 0),
                    "end_line": r.get("end", {}).get("line", 0),
                    # One vocabulary at the boundary: opengrep ERROR/WARNING/INFO ->
                    # high/medium/info (core.models.normalize_severity).
                    "severity": normalize_severity(str(extra.get("severity", "WARNING"))).value,
                    "message": extra.get("message", ""),
                    "fix_suggestion": fix_suggestion,
                }
            )
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], len(_SEVERITY_ORDER)))
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
            icon = _SEVERITY_ICON.get(f["severity"], "ℹ️")
            rule = f["rule_id"].split(".")[-1]
            lines.append(f"{icon} **`{f['file']}:{f['start_line']}`** — **{rule}**")
            lines.append(f"> {f['message'][:200]}\n")
        lines.append("</details>\n")
        return "\n".join(lines)


from caliper.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("semgrep")
def build_semgrep_plugin(settings: CaliperSettings | None = None) -> SemgrepPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return SemgrepPlugin(settings=settings)
