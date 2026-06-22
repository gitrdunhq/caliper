"""OSV Scanner plugin — known vulnerability database lookup.
# tested-by: tests/unit/test_osv_plugin.py
"""

from __future__ import annotations

import contextlib
import json
import subprocess
from pathlib import Path

import structlog

from eedom.core.errors import ErrorCode, error_msg
from eedom.core.plugin import (
    PluginCategory,
    PluginResult,
    ScannerPlugin,
    result_with_dict_findings,
)

logger = structlog.get_logger()

_MAX_FINDINGS = 1000

_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}

_MANIFEST_NAMES = {
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pubspec.yaml",
    "pubspec.lock",
    "mix.exs",
    "mix.lock",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pnpm-lock.yaml",
}


def _advisory_url(vuln_id: str) -> str:
    if vuln_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    if vuln_id.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    return f"https://osv.dev/vulnerability/{vuln_id}"


class OsvScannerPlugin(ScannerPlugin):
    @property
    def name(self) -> str:
        return "osv-scanner"

    @property
    def description(self) -> str:
        return "Known vulnerability database lookup (OSV/GHSA/CVE)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.dependency

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        return any(Path(f).name in _MANIFEST_NAMES for f in files)

    def run(
        self,
        files: list[str],
        repo_path: Path,
        timeout: int = 60,
    ) -> PluginResult:
        try:
            r = subprocess.run(
                ["osv-scanner", "--format", "json", "-r", str(repo_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.NOT_INSTALLED, "osv-scanner"),
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.TIMEOUT, "osv-scanner", timeout=0),
            )

        try:
            data = json.loads(r.stdout)
        except (json.JSONDecodeError, ValueError):
            if r.returncode == 0:
                return PluginResult(
                    plugin_name=self.name,
                    summary={"status": "clean", "count": 0},
                )
            return PluginResult(
                plugin_name=self.name,
                error=error_msg(ErrorCode.BINARY_CRASHED, "osv-scanner", exit_code=r.returncode),
            )

        findings = self._extract_findings(data)
        crit = sum(1 for f in findings if f["severity"] in ("critical", "high"))
        return PluginResult(
            plugin_name=self.name,
            findings=findings,
            summary={
                "total": len(findings),
                "critical_high": crit,
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "low": sum(1 for f in findings if f["severity"] == "low"),
            },
        )

    def _extract_findings(self, data: dict) -> list[dict]:
        findings = []
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    sev = self._resolve_severity(vuln)
                    vuln_id = vuln.get("id", "?")
                    aliases = vuln.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), "")
                    display_id = cve_id if cve_id else vuln_id
                    findings.append(
                        {
                            "id": display_id,
                            "ghsa": vuln_id if vuln_id.startswith("GHSA") else "",
                            "url": _advisory_url(display_id),
                            "summary": vuln.get("summary", ""),
                            "severity": sev,
                            "package": pkg_info.get("name", "?"),
                            "version": pkg_info.get("version", "?"),
                            "ecosystem": pkg_info.get("ecosystem", "?"),
                        }
                    )
        return findings[:_MAX_FINDINGS]

    def _resolve_severity(self, vuln: dict) -> str:
        # Take the HIGHEST severity across all signals — never let a lower
        # CVSS-derived band overwrite a higher database_specific rating (a
        # CVSS 5.0 must not downgrade a database_specific "high" to "medium").
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        candidates = ["info"]
        db_sev = vuln.get("database_specific", {}).get("severity", "")
        if isinstance(db_sev, str):
            candidates.append(_SEV_MAP.get(db_sev.upper(), "info"))
        for sv in vuln.get("severity", []):
            score = sv.get("score", "")
            with contextlib.suppress(ValueError):
                cvss = float(str(score))
                if cvss >= 9.0:
                    candidates.append("critical")
                elif cvss >= 7.0:
                    candidates.append("high")
                elif cvss >= 4.0:
                    candidates.append("medium")
                else:
                    candidates.append("low")
        return max(candidates, key=lambda s: rank.get(s, 0))

    def render(
        self,
        result: PluginResult,
        template_dir: Path | None = None,
    ) -> str:
        if result.error:
            return f"**osv-scanner**: {result.error}"
        result = result_with_dict_findings(result)
        if not result.findings:
            return ""
        crit = [f for f in result.findings if f["severity"] in ("critical", "high")]
        other = [f for f in result.findings if f["severity"] not in ("critical", "high")]

        lines: list[str] = []
        if crit:
            lines.append("<details open>")
            lines.append(
                f"<summary>🔴 <b>Critical/High Vulnerabilities ({len(crit)})</b></summary>\n"
            )
            lines.append("| CVE | Package | Version | Severity | Summary |")
            lines.append("|-----|---------|---------|----------|---------|")
            seen: set[tuple] = set()
            for v in crit:
                key = (v["id"], v["package"])
                if key in seen:
                    continue
                seen.add(key)
                icon = "🔴" if v["severity"] == "critical" else "🟠"
                link = f"[{v['id']}]({v['url']})"
                summary = str(v.get("summary") or v.get("message") or "")[:80]
                lines.append(
                    f"| {icon} {link} | `{v['package']}`"
                    f" | {v['version']} | {v['severity']}"
                    f" | {summary} |"
                )
            lines.append("\n</details>\n")

        if other:
            lines.append("<details>")
            lines.append(
                f"<summary>🟡 <b>Medium/Low Vulnerabilities ({len(other)})</b></summary>\n"
            )
            lines.append("| CVE | Package | Severity |")
            lines.append("|-----|---------|----------|")
            seen2: set[tuple] = set()
            for v in other:
                key = (v["id"], v["package"])
                if key in seen2:
                    continue
                seen2.add(key)
                link = f"[{v['id']}]({v['url']})"
                lines.append(f"| {link} | `{v['package']}@{v['version']}` | {v['severity']} |")
            lines.append("\n</details>\n")

        return "\n".join(lines)


from eedom.plugins import ANALYZERS  # noqa: E402  (self-registration wiring)


@ANALYZERS.register("osv-scanner")
def build_osv_scanner_plugin() -> OsvScannerPlugin:
    """Register this analyzer with the ANALYZERS registry."""
    return OsvScannerPlugin()
