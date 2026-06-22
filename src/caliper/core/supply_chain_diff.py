"""Supply-chain version-bump signal analysis + standalone orchestration.
# tested-by: tests/unit/test_supply_chain_diff.py

The deterministic heart of the version-bump threat-analysis step. Given a
:class:`VersionDiff` (what code changed between two published versions of a
dependency), it scores a fixed set of zero-LLM signals into verdict-eligible
``PluginFinding``s (category ``supply_chain``). High-confidence signals — a new
install hook, obfuscation, a newly-introduced network/exec capability — are what
gate the build via OPA; the LLM narrative attached later is advisory only (ADR-006).

This module is invoked only by the separate, feature-flag-gated step
(``caliper supply-chain-diff``), never by the normal scan. Everything is fail-open:
a fetch/extract failure becomes an informational "source unavailable" finding.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import structlog

from caliper.core.diff import DependencyDiffDetector
from caliper.core.models import Finding, FindingCategory, FindingSeverity, PolicyEvaluation
from caliper.core.plugin import PluginFinding, finding_get
from caliper.core.supply_chain_models import FileChange, VersionDiff

if TYPE_CHECKING:
    from caliper.core.config import CaliperSettings

logger = structlog.get_logger(__name__)

PLUGIN_NAME = "supply-chain-diff"
_MAX_EVIDENCE = 8  # cap evidence lines attached per finding
_MAX_DIFF_FILES_IN_META = 20  # cap files embedded in finding metadata

# Tokens that introduce network / process-execution capability (added lines only).
_RISKY_TOKENS = (
    "subprocess",
    "os.system",
    "os.popen",
    "socket.",
    "urllib",
    "requests.",
    "httpx.",
    "ftplib",
    "__import__",
    "child_process",
    "execSync",
    "spawnSync",
    "net.connect",
    "fetch(",
    "http.get",
    "https.get",
)
_EXEC_DECODE = (
    "eval(",
    "exec(",
    "Function(",
    "atob(",
    "Buffer.from(",
    "base64.b64decode",
    "marshal.loads",
    "pickle.loads",
)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
_HEX_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}")
_SETUP_HOOK_FILES = ("setup.py", "setup.cfg")


def _added_lines(excerpt: str) -> list[str]:
    """Return the added (``+``) content lines of a unified-diff excerpt."""
    return [
        ln[1:] for ln in excerpt.splitlines() if ln.startswith("+") and not ln.startswith("+++")
    ]


def _is_code_file(path: str) -> bool:
    return path.endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"))


def _finding(
    *,
    signal: str,
    severity: str,
    message: str,
    vd: VersionDiff,
    evidence: list[str] | None = None,
) -> PluginFinding:
    """Build a supply_chain PluginFinding carrying the version-diff context."""
    return PluginFinding(
        id=signal,
        severity=severity,
        message=message,
        category=FindingCategory.supply_chain.value,
        package=vd.package,
        version=vd.new_version,
        rule_id=signal,
        metadata={
            "threat_signal": signal,
            "ecosystem": vd.ecosystem,
            "old_version": vd.old_version,
            "new_version": vd.new_version,
            "evidence": (evidence or [])[:_MAX_EVIDENCE],
            "version_diff": _compact_diff(vd),
        },
    )


def _compact_diff(vd: VersionDiff) -> dict:
    """A bounded, JSON-safe summary of the diff for the finding metadata."""
    return {
        "package": vd.package,
        "ecosystem": vd.ecosystem,
        "old_version": vd.old_version,
        "new_version": vd.new_version,
        "available": vd.available,
        "files_changed": len(vd.files),
        "added_paths": list(vd.added_paths[:_MAX_DIFF_FILES_IN_META]),
        "removed_paths": list(vd.removed_paths[:_MAX_DIFF_FILES_IN_META]),
        "old_install_scripts": list(vd.old_install_scripts),
        "new_install_scripts": list(vd.new_install_scripts),
        "old_maintainer": vd.old_maintainer,
        "new_maintainer": vd.new_maintainer,
        "changed_files": [
            {
                "path": f.path,
                "change": f.change.value,
                "added_lines": f.added_lines,
                "removed_lines": f.removed_lines,
                "diff_excerpt": f.diff_excerpt,
            }
            for f in vd.files[:_MAX_DIFF_FILES_IN_META]
        ],
    }


def score_signals(vd: VersionDiff) -> list[PluginFinding]:
    """Deterministically score a VersionDiff into supply_chain findings."""
    if not vd.available:
        return [
            _finding(
                signal="SC-SOURCE-UNAVAILABLE",
                severity="info",
                message=(
                    f"Could not fetch source for {vd.package} "
                    f"{vd.old_version}->{vd.new_version}: {vd.error}"
                ),
                vd=vd,
            )
        ]

    findings: list[PluginFinding] = []

    # 1) Install hooks (critical) -----------------------------------------
    new_hooks = tuple(s for s in vd.new_install_scripts if s not in vd.old_install_scripts)
    if new_hooks:
        findings.append(
            _finding(
                signal="SC-INSTALL-HOOK",
                severity="critical",
                message=(
                    f"{vd.package}@{vd.new_version} adds install-time script(s) "
                    f"not present in {vd.old_version}"
                ),
                vd=vd,
                evidence=list(new_hooks),
            )
        )
    setup_hits = _setup_hook_hits(vd)
    if setup_hits:
        findings.append(
            _finding(
                signal="SC-INSTALL-HOOK",
                severity="critical",
                message=(
                    f"{vd.package}@{vd.new_version} adds exec/network calls in a "
                    "build/install script (setup.py/setup.cfg)"
                ),
                vd=vd,
                evidence=setup_hits,
            )
        )

    # 2) Obfuscation (high) ----------------------------------------------
    obf = _obfuscation_hits(vd)
    if obf:
        findings.append(
            _finding(
                signal="SC-OBFUSCATION",
                severity="high",
                message=f"{vd.package}@{vd.new_version} introduces obfuscated/encoded payloads",
                vd=vd,
                evidence=obf,
            )
        )

    # 3) Newly-introduced risky capability (high) -------------------------
    risky = _risky_capability_hits(vd)
    if risky:
        findings.append(
            _finding(
                signal="SC-RISKY-IMPORT",
                severity="high",
                message=(
                    f"{vd.package}@{vd.new_version} introduces network/process-exec "
                    "capability in changed code"
                ),
                vd=vd,
                evidence=risky,
            )
        )

    # 4) Maintainer change (medium) --------------------------------------
    if vd.old_maintainer and vd.new_maintainer and vd.old_maintainer != vd.new_maintainer:
        findings.append(
            _finding(
                signal="SC-MAINTAINER-CHANGE",
                severity="medium",
                message=(
                    f"{vd.package} publisher changed: "
                    f"{vd.old_maintainer!r} -> {vd.new_maintainer!r}"
                ),
                vd=vd,
                evidence=[f"{vd.old_maintainer} -> {vd.new_maintainer}"],
            )
        )

    # 5) Clean upgrade (info) — always emit something to narrate ----------
    if not findings:
        findings.append(
            _finding(
                signal="SC-CLEAN",
                severity="info",
                message=(
                    f"{vd.package} {vd.old_version}->{vd.new_version}: "
                    f"{len(vd.files)} file(s) changed, no risk signals detected"
                ),
                vd=vd,
            )
        )
    return findings


def _setup_hook_hits(vd: VersionDiff) -> list[str]:
    hits: list[str] = []
    for f in vd.files:
        if not f.path.endswith(_SETUP_HOOK_FILES):
            continue
        if f.change == FileChange.removed:
            continue
        for line in _added_lines(f.diff_excerpt):
            if any(tok in line for tok in (*_RISKY_TOKENS, *_EXEC_DECODE)):
                hits.append(f"{f.path}: {line.strip()[:160]}")
    return hits


def _obfuscation_hits(vd: VersionDiff) -> list[str]:
    hits: list[str] = []
    for f in vd.files:
        if f.change == FileChange.removed:
            continue
        for line in _added_lines(f.diff_excerpt):
            decode_exec = ("atob(" in line or "Buffer.from(" in line or "b64decode" in line) and (
                "eval(" in line or "exec(" in line or "Function(" in line
            )
            if _BASE64_RUN.search(line) or _HEX_RUN.search(line) or decode_exec:
                hits.append(f"{f.path}: {line.strip()[:120]}")
    return hits


def _risky_capability_hits(vd: VersionDiff) -> list[str]:
    hits: list[str] = []
    for f in vd.files:
        if f.change == FileChange.removed or not _is_code_file(f.path):
            continue
        for line in _added_lines(f.diff_excerpt):
            for tok in _RISKY_TOKENS:
                if tok in line:
                    hits.append(f"{f.path}: {tok} :: {line.strip()[:140]}")
                    break
    return hits


# Maps a changed dependency-file basename to (ecosystem, parser-method-name).
_FILE_DISPATCH = {
    "requirements.txt": ("pypi", "parse_requirements_diff"),
    "pyproject.toml": ("pypi", "parse_pyproject_diff"),
    "package.json": ("npm", "parse_package_json_diff"),
}


def detect_upgrades(diff_text: str) -> list[tuple[str, dict]]:
    """Return ``(ecosystem, change)`` for each upgraded/downgraded package in a diff."""
    detector = DependencyDiffDetector()
    out: list[tuple[str, dict]] = []
    seen: set[tuple] = set()
    for path in detector.detect_changed_files(diff_text):
        basename = path.rsplit("/", 1)[-1]
        dispatch = _FILE_DISPATCH.get(basename)
        if dispatch is None:
            continue
        ecosystem, method = dispatch
        before, after = detector.extract_file_content_from_diff(diff_text, path)
        changes = getattr(detector, method)(before, after)
        for change in changes:
            if change["action"] not in ("upgraded", "downgraded"):
                continue
            key = (ecosystem, change["package"], change["old_version"], change["new_version"])
            if key in seen:
                continue
            seen.add(key)
            out.append((ecosystem, change))
    return out


def _to_finding(pf: PluginFinding) -> Finding:
    """Map a supply_chain PluginFinding to the core Finding model for OPA."""
    return Finding(
        severity=FindingSeverity(finding_get(pf, "severity", "info")),
        category=FindingCategory.supply_chain,
        description=finding_get(pf, "message", ""),
        source_tool=PLUGIN_NAME,
        package_name=finding_get(pf, "package", ""),
        version=finding_get(pf, "version", ""),
        advisory_id=finding_get(pf, "id", ""),
    )


def evaluate_gate(findings: list[PluginFinding], settings: CaliperSettings) -> PolicyEvaluation:
    """Gate the build on the deterministic signals via OPA (zero-LLM decision path).

    Only the supply_chain_diff rule is enabled so the focused step does not trip
    unrelated rules (age/license/vuln). Fail-open: OPA unavailable -> needs_review.
    """
    from caliper.core.policy import OpaEvaluator

    opa = OpaEvaluator(settings.opa_policy_path, timeout=settings.opa_timeout)
    config = {
        "rules_enabled": {
            "critical_vuln": False,
            "forbidden_license": False,
            "package_age": False,
            "malicious_package": False,
            "transitive_count": False,
            "supply_chain_diff": True,
        }
    }
    return opa.evaluate([_to_finding(f) for f in findings], {"name": "", "version": ""}, config)
