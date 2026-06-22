"""Foreman agent tool definitions.
# tested-by: tests/unit/test_agent_tools.py

Three @tool functions wrapping the review pipeline and Semgrep.
Internal helpers live in tool_helpers.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import structlog

try:
    from agent_framework import tool
except ImportError as _exc:
    raise ImportError(
        "agent_framework is required for the Copilot agent. "
        "Install with: pip install caliper[copilot]"
    ) from _exc

from caliper.agent.tool_helpers import (
    _SAFE_NAME_RE,
    clean_package_name,
    clean_triggered_rules,
    detect_manifest_changes,
    extract_changed_files,
    get_agent_settings,
    run_pipeline,
    validate_paths,
)
from caliper.core.models import ReviewDecision
from caliper.plugins import get_default_registry

logger = structlog.get_logger(__name__)


def _validate_repo_path(repo_path: str) -> str:
    """Reject repo paths that contain path traversal sequences.

    Checks raw path parts for '..' before any OS resolution so that a caller
    cannot read files outside the intended repository root.

    Returns the original path string on success; raises ValueError otherwise.
    """
    path = Path(repo_path)
    if any(part == ".." for part in path.parts):
        raise ValueError(f"repo_path contains path traversal sequences: {repo_path!r}")
    return repo_path


def _sanitize_sbom_name(name: str) -> str:
    """Sanitize a component name from SBOM data.

    Strips leading slashes and removes '..' components so that names from
    untrusted SBOM content cannot carry filesystem path injection into output.
    """
    if not name:
        return ""
    # Strip absolute-path indicator
    sanitized = name.lstrip("/")
    # Remove traversal components
    parts = [p for p in sanitized.split("/") if p != ".."]
    return "/".join(parts)


def _serialize_decision(decision: ReviewDecision) -> dict:
    """Serialize an ReviewDecision to a dict for the agent."""
    findings_summary: dict[str, int] = {}
    for f in decision.findings:
        sev = f.severity.value
        findings_summary[sev] = findings_summary.get(sev, 0) + 1

    return {
        "package_name": clean_package_name(decision.request.package_name),
        "version": decision.request.target_version,
        "ecosystem": decision.request.ecosystem,
        "request_type": decision.request.request_type.value,
        "decision": decision.decision.value,
        "triggered_rules": clean_triggered_rules(decision.policy_evaluation.triggered_rules),
        "constraints": decision.policy_evaluation.constraints,
        "policy_version": decision.policy_evaluation.policy_bundle_version,
        "findings_summary": findings_summary,
        "finding_count": len(decision.findings),
        "scanner_results": [
            {
                "tool": sr.tool_name,
                "status": sr.status.value,
                "duration_s": sr.duration_seconds,
            }
            for sr in decision.scan_results
        ],
        "memo_text": decision.memo_text or "",
        "pipeline_duration_s": decision.pipeline_duration_seconds,
    }


def _scribe_agent_findings(findings: list[dict], repo_path: str) -> list[dict]:
    """Run the default detect-then-scribe pass over agent findings (ADR-006).

    Surfaces deterministic context (enclosing symbol, code-graph blast radius) in each
    finding's ``metadata['scribe']`` so Foreman reasons with minimal effort.
    Fail-open: any wiring/scribe error returns the findings unchanged.
    """
    if not findings:
        return findings
    try:
        from caliper.composition.bootstrap import build_default_scribes
        from caliper.core.scribe import ScribeContext
        from caliper.core.scribe_pass import scribe_findings

        scribes = build_default_scribes()
        if not scribes:
            return findings
        ctx = ScribeContext(repo_path=repo_path)
        return scribe_findings(findings, scribes, ctx)
    except Exception:
        logger.exception("scan_code.scribe_failed")
        return findings


@tool(
    name="evaluate_change",
    description=(
        "Run the full review pipeline on a PR diff. Supports 18+ ecosystems "
        "(Python, npm, Cargo, Go, Ruby, Maven, NuGet, Dart, PHP, Elixir, Swift, "
        "CocoaPods, and more). Executes 6 tools: Syft (SBOM), OSV-Scanner, "
        "Trivy, ScanCode (vulnerabilities + licenses) + OPA policy + Semgrep "
        "(code patterns)."
    ),
)
def evaluate_change(
    diff_text: Annotated[str, "The unified diff text from the pull request"],
    pr_url: Annotated[str, "The pull request URL"],
    team: Annotated[str, "The team that owns the repository"],
    repo_path: Annotated[str, "Path to the repository root"],
) -> dict:
    """Run full review pipeline on a PR diff."""
    try:
        decisions, sbom_changes, raw_sbom = run_pipeline(
            diff_text,
            pr_url,
            team,
            repo_path,
        )
        manifest_changes = detect_manifest_changes(diff_text)
        dep_graph = _build_dep_summary(raw_sbom, repo_path)
        return {
            "status": "ok",
            "decisions": [_serialize_decision(d) for d in decisions],
            "dependency_changes": [
                {
                    "action": c.get("action", "unknown"),
                    "package": clean_package_name(c.get("package", "")),
                    "ecosystem": c.get("ecosystem", ""),
                    "old_version": c.get("old_version"),
                    "new_version": c.get("new_version"),
                }
                for c in sbom_changes
            ],
            "dependency_tree": dep_graph,
            "manifest_files": manifest_changes,
            "package_count": len(decisions),
        }
    except TimeoutError:
        logger.warning("evaluate_change.timeout")
        return {
            "status": "error",
            "error": "pipeline_timeout",
            "decisions": [],
        }
    except Exception:
        logger.exception("evaluate_change.failed")
        return {
            "status": "error",
            "error": "pipeline_unavailable",
            "decisions": [],
        }


def _build_dep_summary(raw_sbom: dict, repo_path: str) -> dict:
    """Build a dependency tree summary from a CycloneDX SBOM.

    Returns:
        {
            "direct": [{"name": ..., "version": ..., "deps": [...]}],
            "shared": [{"name": ..., "used_by": N}],
            "total": N, "direct_count": N, "transitive_count": N,
        }
    """
    if not raw_sbom or "components" not in raw_sbom:
        return {}

    import json

    # Validate repo_path before any filesystem access.
    try:
        repo_path = _validate_repo_path(repo_path)
    except ValueError as exc:
        logger.warning("build_dep_summary.invalid_repo_path", error=str(exc))
        return {}

    components = raw_sbom.get("components", [])
    dependencies = raw_sbom.get("dependencies", [])

    purl_to_name: dict[str, str] = {}
    purl_to_ver: dict[str, str] = {}
    for comp in components:
        purl = comp.get("purl", "")
        name = _sanitize_sbom_name(comp.get("name", ""))
        ver = _sanitize_sbom_name(comp.get("version", ""))
        if purl:
            base_purl = purl.split("?")[0]
            purl_to_name[base_purl] = name
            purl_to_ver[base_purl] = ver
            purl_to_name[purl] = name
            purl_to_ver[purl] = ver

    dep_map: dict[str, list[str]] = {}
    for entry in dependencies:
        ref = entry.get("ref", "")
        dep_on = entry.get("dependsOn", [])
        ref_base = ref.split("?")[0]
        ref_name = purl_to_name.get(ref, purl_to_name.get(ref_base, ref))
        dep_names = []
        for d in dep_on:
            d_base = d.split("?")[0]
            dep_names.append(purl_to_name.get(d, purl_to_name.get(d_base, d)))
        dep_map[ref_name] = dep_names

    direct_names: set[str] = set()
    pkg_json = Path(repo_path) / "package.json"
    if pkg_json.exists():
        try:
            pkg = json.loads(pkg_json.read_text())
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                direct_names.update(pkg.get(section, {}).keys())
        except Exception as exc:
            logger.debug("package_json.parse_error", path=str(pkg_json), error=str(exc))

    direct: list[dict] = []
    for name in sorted(direct_names):
        ver = purl_to_ver.get(f"pkg:npm/{name}", "")
        deps = dep_map.get(name, [])
        direct.append({"name": name, "version": ver, "deps": deps[:10]})

    dep_count: dict[str, int] = {}
    for deps in dep_map.values():
        for d in deps:
            dep_count[d] = dep_count.get(d, 0) + 1

    shared = sorted(
        [{"name": name, "used_by": count} for name, count in dep_count.items() if count >= 3],
        key=lambda x: x["used_by"],
        reverse=True,
    )[:20]

    return {
        "direct": direct,
        "shared": shared,
        "total": len(components),
        "direct_count": len(direct_names),
        "transitive_count": len(components) - len(direct_names),
    }


@tool(
    name="check_package",
    description=(
        "Evaluate a single package by name, version, and ecosystem. "
        "Runs scanners and OPA policy. Use for targeted lookups."
    ),
)
def check_package(
    name: Annotated[str, "Package name (e.g. 'requests')"],
    version: Annotated[str, "Package version (e.g. '2.31.0')"],
    ecosystem: Annotated[str, "Package ecosystem (e.g. 'pypi', 'npm')"],
) -> dict:
    """Evaluate a single package. Returns policy verdict and findings."""
    if not _SAFE_NAME_RE.match(name) or not _SAFE_NAME_RE.match(version):
        return {
            "status": "error",
            "error": "invalid_input",
            "message": "Name or version contains invalid characters.",
        }

    ecosystem_manifest = {
        "pypi": ("requirements.txt", f"{name}=={version}"),
        "npm": ("package.json", f'"{name}": "{version}"'),
        "cargo": ("Cargo.toml", f'{name} = "{version}"'),
        "golang": ("go.mod", f"require {name} v{version}"),
        "gem": ("Gemfile", f'gem "{name}", "{version}"'),
        "maven": ("pom.xml", f"<artifactId>{name}</artifactId>"),
        "nuget": ("packages.config", f'id="{name}" version="{version}"'),
    }
    manifest, line = ecosystem_manifest.get(ecosystem, ("requirements.txt", f"{name}=={version}"))
    diff_text = f"diff --git a/{manifest} b/{manifest}\n+{line}\n"
    try:
        decisions, _, _ = run_pipeline(
            diff_text=diff_text,
            pr_url="check://single-package",
            team="check",
            repo_path=".",
        )
        if not decisions:
            return {
                "status": "ok",
                "decision": "no_findings",
                "package": f"{name}@{version}",
                "ecosystem": ecosystem,
                "message": "No dependency changes detected.",
            }
        d = decisions[0]
        result = _serialize_decision(d)
        result["status"] = "ok"
        return result
    except TimeoutError:
        logger.warning("check_package.timeout")
        return {"status": "error", "error": "timeout"}
    except Exception:
        logger.exception("check_package.failed")
        return {"status": "error", "error": "check_unavailable"}


# ── Code quality scan tools — all route through PluginRegistry ──────────────

_SEMGREP_CODE_EXTS = {
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
}
_CPD_CODE_EXTS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".rb",
    ".java",
    ".kt",
    ".swift",
    ".rs",
    ".css",
}
_COMPLEXITY_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".java", ".rs", ".c", ".cpp"}


@tool(
    name="scan_code",
    description=(
        "Run Semgrep on changed files in the PR diff. Surfaces security "
        "footguns, risky APIs, policy violations, and config issues. "
        "Returns findings grouped by severity."
    ),
)
def scan_code(
    diff_text: Annotated[str, "The unified diff text from the pull request"],
    repo_path: Annotated[str, "Path to the repository root"],
) -> dict:
    """Run Semgrep on changed files via PluginRegistry. Returns categorized findings."""
    changed_files = extract_changed_files(diff_text)
    changed_files = validate_paths(changed_files, repo_path)
    if not changed_files:
        return {"status": "ok", "findings": [], "files_scanned": 0}

    registry = get_default_registry()
    plugin = registry.get("semgrep")
    if plugin is None:
        logger.warning("scan_code.plugin_not_found", plugin="semgrep")
        return {"status": "error", "error": "semgrep_unavailable", "findings": []}

    result = plugin.run(changed_files, Path(repo_path))

    if result.error:
        err_lower = result.error.lower()
        if "timed out" in err_lower or "timeout" in err_lower:
            agent_cfg = get_agent_settings()
            logger.warning("scan_code.timeout", timeout=agent_cfg.semgrep_timeout)
            return {
                "status": "error",
                "error": f"semgrep_timeout ({agent_cfg.semgrep_timeout}s)",
                "findings": [],
            }
        if "no such file" in err_lower or "not found" in err_lower:
            logger.warning("scan_code.not_installed")
            return {
                "status": "error",
                "error": "not_installed: semgrep binary not found",
                "findings": [],
            }
        logger.exception("scan_code.failed")
        return {"status": "error", "error": "semgrep_unavailable", "findings": []}

    findings = [
        {
            "rule_id": f.get("rule_id", "unknown"),
            "message": f.get("message", ""),
            "severity": f.get("severity", "WARNING"),
            "file": f.get("file", ""),
            "line": f.get("start_line", 0),  # scribes key on "line"
            "start_line": f.get("start_line", 0),
            "end_line": f.get("end_line", 0),
            "category": f.get("category", "unknown"),
        }
        for f in result.findings
    ]

    findings = _scribe_agent_findings(findings, repo_path)

    return {
        "status": "ok",
        "findings": findings,
        "files_scanned": len(changed_files),
        "finding_count": len(findings),
    }


@tool(
    name="scan_duplicates",
    description=(
        "Run PMD CPD (Copy-Paste Detector) on changed files to find "
        "duplicated code blocks. Supports TypeScript, JavaScript, Python, "
        "Go, Ruby, Java, Kotlin, Swift, Rust, and more."
    ),
)
def scan_duplicates(
    diff_text: Annotated[str, "The unified diff text from the pull request"],
    repo_path: Annotated[str, "Path to the repository root"],
) -> dict:
    """Detect duplicated code in changed files via PluginRegistry (CPD)."""
    changed_files = extract_changed_files(diff_text)
    changed_files = validate_paths(changed_files, repo_path)
    if not changed_files:
        return {"status": "ok", "duplicates": [], "files_scanned": 0}

    registry = get_default_registry()
    plugin = registry.get("cpd")
    if plugin is None:
        logger.warning("scan_duplicates.plugin_not_found", plugin="cpd")
        return {"status": "error", "error": "cpd_unavailable", "duplicates": []}

    result = plugin.run(changed_files, Path(repo_path))

    if result.error:
        logger.exception("scan_duplicates.failed")
        return {"status": "error", "error": result.error, "duplicates": []}

    return {
        "status": "ok",
        "duplicates": result.findings,
        "files_scanned": result.summary.get("files_scanned", 0),
        "duplicate_count": result.summary.get("total", 0),
    }


@tool(
    name="scan_k8s",
    description=(
        "Run kube-linter on Kubernetes YAML and Helm charts. Checks for "
        "security misconfigurations: privileged containers, missing resource "
        "limits, no liveness probes, host networking, NET_RAW capabilities."
    ),
)
def scan_k8s(
    diff_text: Annotated[str, "The unified diff text from the pull request"],
    repo_path: Annotated[str, "Path to the repository root"],
) -> dict:
    """Lint K8s manifests and Helm charts via PluginRegistry (kube-linter)."""
    changed_files = extract_changed_files(diff_text)
    changed_files = validate_paths(changed_files, repo_path)
    if not changed_files:
        return {"status": "ok", "findings": [], "files_scanned": 0}

    registry = get_default_registry()
    plugin = registry.get("kube-linter")
    if plugin is None:
        logger.warning("scan_k8s.plugin_not_found", plugin="kube-linter")
        return {"status": "error", "error": "kube_linter_unavailable", "findings": []}

    result = plugin.run(changed_files, Path(repo_path))

    if result.error:
        logger.exception("scan_k8s.failed")
        return {"status": "error", "error": result.error, "findings": []}

    yaml_files = [f for f in changed_files if Path(f).suffix in (".yaml", ".yml")]
    return {
        "status": "ok",
        "findings": result.findings,
        "files_scanned": len(yaml_files),
        "finding_count": len(result.findings),
    }


@tool(
    name="analyze_complexity",
    description=(
        "Measure code complexity metrics on changed files: cyclomatic "
        "complexity, lines of code, maintainability index, function length. "
        "Supports Python, TypeScript, JavaScript, Go, Java, Rust, C/C++."
    ),
)
def analyze_complexity(
    diff_text: Annotated[str, "The unified diff text from the pull request"],
    repo_path: Annotated[str, "Path to the repository root"],
) -> dict:
    """Measure code complexity on changed files via PluginRegistry (lizard + radon)."""
    changed_files = extract_changed_files(diff_text)
    changed_files = validate_paths(changed_files, repo_path)
    if not changed_files:
        return {"status": "ok", "functions": [], "files_scanned": 0, "summary": {}}

    registry = get_default_registry()
    plugin = registry.get("complexity")
    if plugin is None:
        logger.warning("analyze_complexity.plugin_not_found", plugin="complexity")
        return {"status": "error", "error": "complexity_unavailable", "functions": []}

    result = plugin.run(changed_files, Path(repo_path))

    if result.error:
        logger.exception("analyze_complexity.failed")
        return {"status": "error", "error": result.error, "functions": []}

    supported_files = [f for f in changed_files if Path(f).suffix in _COMPLEXITY_EXTS]
    return {
        "status": "ok",
        "functions": result.findings,
        "files_scanned": len(supported_files),
        "function_count": len(result.findings),
        "summary": result.summary,
    }
