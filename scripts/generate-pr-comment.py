"""Generate a simulated PR comment from Foreman tool results."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

from caliper.agent.tools import (
    _detect_rulesets,
    _extract_changed_files,
    _get_agent_settings,
    evaluate_change,
    scan_code,
)

_get_agent_settings.cache_clear()

DIFF_PATH = (
    Path(sys.argv[1])
    if len(sys.argv) > 1
    else Path(".temp/stress-test/diffs/12-aws-infra-ops-46.diff")
)
REPO_PATH = (
    sys.argv[2]
    if len(sys.argv) > 2
    else str(Path(".temp/stress-test/repos/aws-infrastructure-operations").resolve())
)
PR_URL = (
    sys.argv[3]
    if len(sys.argv) > 3
    else "https://github.com/farmcreditca/aws-infrastructure-operations/pull/46"
)
OUT_PATH = (
    Path(sys.argv[4]) if len(sys.argv) > 4 else Path(".temp/stress-test/reports/pr-comment.md")
)

diff_text = DIFF_PATH.read_text()
changed = _extract_changed_files(diff_text)
rulesets = _detect_rulesets(changed)

print(f"Running evaluate_change + scan_code on {len(changed)} files...")
result1 = evaluate_change(
    diff_text=diff_text,
    pr_url=PR_URL,
    team="platform",
    repo_path=REPO_PATH,
)
result2 = scan_code(diff_text=diff_text, repo_path=REPO_PATH)

decisions = result1.get("decisions", [])
dep_changes = result1.get("dependency_changes", [])
manifest_files = result1.get("manifest_files", {})
findings = result2.get("findings", [])

rejects = [d for d in decisions if d["decision"] == "reject"]
needs_review = [d for d in decisions if d["decision"] == "needs_review"]
constrained = [d for d in decisions if d["decision"] == "approve_with_constraints"]
approved = [d for d in decisions if d["decision"] == "approve"]

c: list[str] = []

# ── Header + verdict banner ──
c.append("## ⚡ Foreman — Dependency & Code Review")
c.append("")
if rejects:
    c.append("> 🔴 **BLOCKED** — policy violations found.")
elif constrained:
    c.append("> 🟠 **PASS WITH WARNINGS** — review the constraints below.")
elif needs_review:
    c.append("> 🟡 **MANUAL REVIEW REQUIRED**")
else:
    c.append("> 🟢 **ALL CLEAR**")
c.append("")

# ── Stats table ──
ecos = ", ".join(manifest_files.keys()) or "none"
c.append("| | |")
c.append("|---|---|")
c.append(f"| **Ecosystems** | {ecos} |")
c.append(f"| **Packages evaluated** | {len(decisions)} |")
c.append(f"| **Dependency changes** | {len(dep_changes)} |")
c.append(f"| **Semgrep findings** | {len(findings)} |")
c.append("| **Scanners** | Syft, OSV-Scanner, Trivy, ScanCode, OPA, Semgrep |")
c.append(f"| **Semgrep rulesets** | {', '.join(rulesets)} |")
c.append("")

# ── Policy verdicts (right after stats) ──
if rejects or constrained or needs_review:
    c.append("<details open>")
    c.append("<summary>🏛️ <b>Policy Verdicts</b></summary>")
    c.append("")

    if rejects:
        c.append(f"### 🔴 Rejected ({len(rejects)})")
        c.append("")
        by_rule: dict[str, list] = {}
        for d in rejects:
            for r in d.get("triggered_rules", ["unknown"]):
                by_rule.setdefault(r, []).append(d["package_name"])
        for rule, pkgs in by_rule.items():
            c.append(f"**{rule}**")
            for p in pkgs[:10]:
                c.append(f"- `{p}`")
            if len(pkgs) > 10:
                c.append(f"- *...and {len(pkgs) - 10} more*")
            c.append("")

    if constrained:
        c.append(f"### 🟠 Approved with Constraints ({len(constrained)})")
        c.append("")
        by_rule_c: dict[str, list] = {}
        for d in constrained:
            for r in d.get("triggered_rules", ["unknown"]):
                by_rule_c.setdefault(r, []).append(d)
        for rule, pkgs in by_rule_c.items():
            ecos_c = Counter(d["ecosystem"] for d in pkgs)
            eco_str = ", ".join(f"{eco} ({n})" for eco, n in ecos_c.most_common())
            c.append(f"**{rule}**")
            c.append(f"- {len(pkgs)} packages: {eco_str}")
            c.append("")

    if needs_review:
        c.append(f"### 🟡 Needs Review ({len(needs_review)})")
        c.append("")
        for d in needs_review[:10]:
            c.append(f"- `{d['package_name']}@{d['version']}` ({d['ecosystem']})")
        if len(needs_review) > 10:
            c.append(f"- *...and {len(needs_review) - 10} more*")
        c.append("")

    if approved:
        c.append(f"### 🟢 Approved ({len(approved)})")
        c.append(f"{len(approved)} packages passed.")
        c.append("")

    c.append("</details>")
    c.append("")

# ── Code patterns (Semgrep) ──
if findings:
    c.append("<details open>")
    c.append(f"<summary>🔍 <b>Code Patterns — Semgrep ({len(findings)})</b></summary>")
    c.append("")
    for f in findings:
        icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(f["severity"], "?")
        short_rule = f["rule_id"].split(".")[-1]
        c.append(f"{icon} **`{f['file']}:{f['start_line']}`** — **{short_rule}**")
        c.append(f"> {f['message'][:250]}")
        c.append("")
    c.append("</details>")
    c.append("")

# ── Dependency changes (grouped by manifest) ──
c.append("<details>")
c.append(f"<summary>📦 <b>Dependency Changes ({len(dep_changes)})</b></summary>")
c.append("")
if dep_changes:
    by_manifest: dict[str, dict[str, list]] = {}
    for ch in dep_changes:
        eco = ch.get("ecosystem", "unknown")
        action = ch.get("action", "unknown")
        by_manifest.setdefault(eco, {}).setdefault(action, []).append(ch)

    icons = {
        "added": "➕",
        "upgraded": "⬆️",
        "downgraded": "⬇️",
        "removed": "➖",
    }

    for eco, actions in sorted(by_manifest.items()):
        total = sum(len(v) for v in actions.values())
        manifest_list = ", ".join(f"`{f}`" for f in manifest_files.get(eco, [eco]))
        c.append(f"### {eco} — {total} packages ({manifest_list})")
        c.append("")

        for action in ["added", "upgraded", "downgraded", "removed"]:
            items = actions.get(action, [])
            if not items:
                continue
            icon = icons.get(action, "•")
            c.append(f"**{icon} {action.capitalize()} ({len(items)})**")
            c.append("")
            c.append("| Package | Version |")
            c.append("|---------|---------|")
            for ch in items:
                ver = ch.get("new_version") or ch.get("old_version") or "?"
                c.append(f"| `{ch['package']}` | {ver} |")
            c.append("")

c.append("</details>")
c.append("")

# ── Footer ──
c.append("---")
cfg = _get_agent_settings()
c.append(
    f"*Foreman v{cfg.policy_version} • "
    f"Semgrep pinned@fdc7354 • "
    f"{len(decisions)} packages • "
    f"{len(findings)} code findings*"
)

comment = "\n".join(c)
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
OUT_PATH.write_text(comment)
print(f"\nWritten: {OUT_PATH}")
print(
    f"R:{len(rejects)} C:{len(constrained)} "
    f"NR:{len(needs_review)} A:{len(approved)} S:{len(findings)}"
)
