"""Run the full Foreman 7-tool suite against all stress test PRs."""

from __future__ import annotations

import contextlib
import os
from collections import Counter
from pathlib import Path

os.environ.setdefault("FOREMAN_GITHUB_TOKEN", "fake_for_test")

from caliper.agent.tool_helpers import (
    detect_manifest_changes,
    detect_rulesets,
    extract_changed_files,
    get_agent_settings,
)
from caliper.agent.tools import (  # noqa: F401
    analyze_complexity,
    evaluate_change,
    scan_code,
    scan_duplicates,
    scan_k8s,
)

get_agent_settings.cache_clear()

DIFFS = Path(".temp/stress-test/diffs")
REPOS = Path(".temp/stress-test/repos")
OUT = Path(".temp/stress-test/gauntlet")
OUT.mkdir(parents=True, exist_ok=True)

PRS = [
    (
        "01-aws-workload-ci-112",
        "aws-workload-ci",
        "farmcreditca/aws-workload-ci",
        112,
        "Monthly Jenkins update",
    ),
    (
        "02-infrastructure-467",
        "infrastructure",
        "farmcreditca/infrastructure",
        467,
        "Monthly SonarQube update",
    ),
    (
        "03-aws-infra-ops-52",
        "aws-infrastructure-operations",
        "farmcreditca/aws-infrastructure-operations",
        52,
        "ACM perms for MS team",
    ),
    (
        "04-network-mgmt-22",
        "aws-workload-network-mgmt",
        "farmcreditca/aws-workload-network-mgmt",
        22,
        "Perimeter for Network",
    ),
    (
        "05-infra-perimeter-1",
        "aws-infrastructure-perimeter",
        "farmcreditca/aws-infrastructure-perimeter",
        1,
        "Perimeter CDK",
    ),
    ("06-aws-jet-115", "aws-workload-jet", "farmcreditca/aws-workload-jet", 115, "EKS fixes"),
    ("07-aws-jet-116", "aws-workload-jet", "farmcreditca/aws-workload-jet", 116, "EKS fixes"),
    ("08-aws-jet-117", "aws-workload-jet", "farmcreditca/aws-workload-jet", 117, "EKS fixes"),
    (
        "09-k8s-jet-37",
        "kubernetes-workload-jet",
        "farmcreditca/kubernetes-workload-jet",
        37,
        "Multi-sprint K8s sync",
    ),
    (
        "10-network-mgmt-17",
        "aws-workload-network-mgmt",
        "farmcreditca/aws-workload-network-mgmt",
        17,
        "Cisco ISE in LZA",
    ),
    (
        "11-aws-jet-114",
        "aws-workload-jet",
        "farmcreditca/aws-workload-jet",
        114,
        "K8s routes + redirect 443",
    ),
    (
        "12-aws-infra-ops-46",
        "aws-infrastructure-operations",
        "farmcreditca/aws-infrastructure-operations",
        46,
        "Lambda deprecation fix",
    ),
]


def build_comment(
    slug: str,
    repo_full: str,
    pr_num: int,
    title: str,
    diff_text: str,
    repo_path: str,
) -> str:
    changed = extract_changed_files(diff_text)
    rulesets = detect_rulesets(changed)
    manifests = detect_manifest_changes(diff_text)

    r1 = evaluate_change(
        diff_text=diff_text,
        pr_url=f"https://github.com/{repo_full}/pull/{pr_num}",
        team="platform",
        repo_path=repo_path,
    )
    r2 = scan_code(diff_text=diff_text, repo_path=repo_path)
    r3 = scan_duplicates(diff_text=diff_text, repo_path=repo_path)
    r4 = scan_k8s(diff_text=diff_text, repo_path=repo_path)
    r5 = analyze_complexity(diff_text=diff_text, repo_path=repo_path)

    decisions = r1.get("decisions", [])
    dep_changes = r1.get("dependency_changes", [])
    dep_tree = r1.get("dependency_tree", {})
    findings = r2.get("findings", [])
    duplicates = r3.get("duplicates", [])
    k8s_findings = r4.get("findings", [])
    complexity = r5.get("functions", [])
    complexity_summary = r5.get("summary", {})

    rej = [d for d in decisions if d["decision"] == "reject"]
    nr = [d for d in decisions if d["decision"] == "needs_review"]
    con = [d for d in decisions if d["decision"] == "approve_with_constraints"]
    appr = [d for d in decisions if d["decision"] == "approve"]

    c: list[str] = []
    c.append(f"## ⚡ Foreman — {repo_full}#{pr_num}")
    c.append(f"**{title}**")
    c.append("")

    mi_scores = []
    for fn in complexity:
        mi_str = fn.get("maintainability_index", "")
        if "(" in mi_str:
            with contextlib.suppress(ValueError, IndexError):
                mi_scores.append(float(mi_str.split("(")[1].rstrip(")")))
    avg_mi = sum(mi_scores) / len(mi_scores) if mi_scores else 0
    mi_grade = "A" if avg_mi >= 20 else ("B" if avg_mi >= 10 else "C")
    mi_icon = {"A": "🟢", "B": "🟡", "C": "🔴"}.get(mi_grade, "⚪")
    mi_c_count = sum(1 for s in mi_scores if s < 10)

    if rej:
        c.append("> 🔴 **BLOCKED**")
    elif con:
        c.append("> 🟠 **PASS WITH WARNINGS**")
    elif nr:
        c.append("> 🟡 **MANUAL REVIEW**")
    else:
        c.append("> 🟢 **ALL CLEAR**")
    c.append("")

    if complexity:
        hi_ccn = complexity_summary.get("high_complexity_count", 0)
        avg_ccn = complexity_summary.get("avg_cyclomatic_complexity", 0)
        c.append(
            f"> **Maintainability: {mi_icon} {mi_grade} ({avg_mi:.0f}/100)**"
            f" · CCN avg {avg_ccn}"
            + (f" · ⚠️ {hi_ccn} high-complexity functions" if hi_ccn else "")
            + (f" · 🔴 {mi_c_count} grade-C functions" if mi_c_count else "")
        )
        c.append("")

    ecos = ", ".join(manifests.keys()) or "—"
    c.append("| | |")
    c.append("|---|---|")
    c.append(f"| Ecosystems | {ecos} |")
    c.append(f"| Packages | {len(decisions)} |")
    c.append(f"| Dep changes | {len(dep_changes)} |")
    c.append(f"| Semgrep | {len(findings)} |")
    c.append(f"| Duplicates (CPD) | {len(duplicates)} |")
    c.append(f"| K8s/Helm (kube-linter) | {len(k8s_findings)} |")
    c.append(f"| Maintainability | {mi_icon} {mi_grade} ({avg_mi:.0f}/100) |")
    c.append(f"| Files changed | {len(changed)} |")
    c.append(f"| Rulesets | {', '.join(rulesets)} |")
    c.append("")

    # Policy verdicts
    if rej or con or nr:
        c.append("<details open>")
        c.append("<summary>🏛️ <b>Policy</b></summary>\n")
        if rej:
            c.append(f"### 🔴 Rejected ({len(rej)})\n")
            by_r: dict[str, list[str]] = {}
            for d in rej:
                for r in d.get("triggered_rules", ["?"]):
                    by_r.setdefault(r, []).append(d["package_name"])
            for rule, pkgs in by_r.items():
                c.append(f"**{rule}** — {len(pkgs)} packages\n")
        if con:
            c.append(f"### 🟠 Constraints ({len(con)})\n")
            by_r2: dict[str, list[dict]] = {}
            for d in con:
                for r in d.get("triggered_rules", ["?"]):
                    by_r2.setdefault(r, []).append(d)
            for rule, pkgs in by_r2.items():
                ecos_c = Counter(d["ecosystem"] for d in pkgs)
                eco_str = ", ".join(f"{e} ({n})" for e, n in ecos_c.most_common())
                c.append(f"**{rule}** — {len(pkgs)} packages: {eco_str}\n")
        if nr:
            c.append(f"### 🟡 Needs Review ({len(nr)})\n")
            for d in nr[:5]:
                c.append(f"- `{d['package_name']}@{d['version']}`")
            if len(nr) > 5:
                c.append(f"- *...{len(nr) - 5} more*")
            c.append("")
        if appr:
            c.append(f"🟢 {len(appr)} approved\n")
        c.append("</details>\n")

    # Semgrep
    if findings:
        c.append("<details open>")
        c.append(f"<summary>🔍 <b>Semgrep ({len(findings)})</b></summary>\n")
        for f in findings:
            icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(f["severity"], "?")
            c.append(
                f"{icon} **`{f['file']}:{f['start_line']}`** — **{f['rule_id'].split('.')[-1]}**"
            )
            c.append(f"> {f['message'][:200]}\n")
        c.append("</details>\n")

    # CPD
    if duplicates:
        c.append("<details open>")
        c.append(f"<summary>📋 <b>Duplicated Code ({len(duplicates)})</b></summary>\n")
        for d in duplicates[:10]:
            c.append(f"**{d['lines']} lines, {d['tokens']} tokens** ({d['language']})")
            for loc in d["locations"]:
                c.append(f"- `{loc['file']}:{loc['start_line']}-{loc['end_line']}`")
            if d.get("fragment"):
                c.append(f"```\n{d['fragment'][:150]}\n```")
            c.append("")
        c.append("</details>\n")

    # Dep changes
    if dep_changes:
        c.append("<details>")
        c.append(f"<summary>📦 <b>Dependencies ({len(dep_changes)})</b></summary>\n")
        by_eco: dict[str, dict[str, list]] = {}
        for ch in dep_changes:
            eco = ch.get("ecosystem", "?")
            act = ch.get("action", "?")
            by_eco.setdefault(eco, {}).setdefault(act, []).append(ch)
        icons = {"added": "➕", "upgraded": "⬆️", "downgraded": "⬇️", "removed": "➖"}
        for eco, actions in sorted(by_eco.items()):
            total = sum(len(v) for v in actions.values())
            mf = ", ".join(f"`{f}`" for f in manifests.get(eco, [eco]))
            c.append(f"### {eco} — {total} packages ({mf})\n")
            for act in ["added", "upgraded", "downgraded", "removed"]:
                items = actions.get(act, [])
                if not items:
                    continue
                c.append(f"**{icons.get(act, '•')} {act.capitalize()} ({len(items)})**\n")
                c.append("| Package | Version |")
                c.append("|---------|---------|")
                for ch in items:
                    ver = ch.get("new_version") or ch.get("old_version") or "?"
                    c.append(f"| `{ch['package']}` | {ver} |")
                c.append("")
        c.append("</details>\n")

    # Dep tree
    if dep_tree and dep_tree.get("direct"):
        c.append("<details>")
        direct_count = dep_tree.get("direct_count", 0)
        trans_count = dep_tree.get("transitive_count", 0)
        c.append(
            f"<summary>🌳 <b>Dependency Tree"
            f" ({direct_count} direct, {trans_count} transitive)"
            f"</b></summary>\n"
        )

        deps_sig: dict[str, list[str]] = {}
        no_deps: list[str] = []
        for pkg in dep_tree["direct"]:
            name = pkg["name"]
            deps = tuple(sorted(pkg.get("deps", [])))
            if not deps:
                no_deps.append(name)
            else:
                sig = deps
                deps_sig.setdefault(sig, []).append(name)

        for deps, names in sorted(deps_sig.items(), key=lambda x: -len(x[1])):
            dep_list = list(deps)
            dep_str = ", ".join(f"`{d}`" for d in dep_list[:5])
            if len(dep_list) > 5:
                dep_str += f", +{len(dep_list) - 5} more"
            if len(names) > 1:
                c.append(
                    f"**{len(names)} packages** share the same deps ({len(dep_list)} transitive):"
                )
                c.append(f"> {', '.join(f'`{n}`' for n in names)}")
                c.append(f"> → {dep_str}\n")
            else:
                c.append(f"- `{names[0]}` → {dep_str}")

        if no_deps:
            c.append(f"\n**{len(no_deps)} leaf packages** (no transitive deps):")
            c.append(f"> {', '.join(f'`{n}`' for n in no_deps)}")
            c.append("")

        shared = dep_tree.get("shared", [])
        if shared:
            c.append("**Shared dependencies** (used by 3+ packages):\n")
            c.append("| Package | Used by |")
            c.append("|---------|---------|")
            for s in shared[:10]:
                c.append(f"| `{s['name']}` | {s['used_by']} packages |")
        c.append("\n</details>\n")

    # K8s
    if k8s_findings:
        c.append("<details open>")
        c.append(f"<summary>☸️ <b>K8s/Helm ({len(k8s_findings)})</b></summary>\n")
        for f in k8s_findings[:15]:
            c.append(
                f"**{f.get('check', '?')}** — "
                f"`{f.get('object_kind', '?')}/{f.get('object_name', '?')}`"
            )
            c.append(f"> {f.get('message', '')[:200]}")
            if f.get("remediation"):
                c.append(f"> 💡 {f['remediation'][:200]}")
            c.append("")
        c.append("</details>\n")

    # Complexity
    if complexity:
        high = [f for f in complexity if f["cyclomatic_complexity"] > 10]
        c.append("<details>")
        avg = complexity_summary.get("avg_cyclomatic_complexity", 0)
        mx = complexity_summary.get("max_cyclomatic_complexity", 0)
        nloc = complexity_summary.get("total_nloc", 0)
        c.append(
            f"<summary>📊 <b>Complexity (avg CCN: {avg}, max: {mx}, {nloc} NLOC)</b></summary>\n"
        )
        if high:
            c.append("**⚠️ High complexity (CCN > 10):**\n")
            c.append("| Function | File | CCN | NLOC |")
            c.append("|----------|------|-----|------|")
            for f in high:
                c.append(
                    f"| `{f['function']}` | `{f['file']}` "
                    f"| {f['cyclomatic_complexity']} | {f['nloc']} |"
                )
            c.append("")
        c.append("**All functions:**\n")
        c.append("| Function | CCN | NLOC | Params |")
        c.append("|----------|-----|------|--------|")
        for f in complexity:
            c.append(
                f"| `{f['function']}` "
                f"| {f['cyclomatic_complexity']} "
                f"| {f['nloc']} "
                f"| {f['parameters']} |"
            )
        c.append("\n</details>\n")

    # Footer
    c.append("---")
    cfg = get_agent_settings()
    c.append(
        f"*Foreman v{cfg.policy_version} • "
        f"9 tools • {len(decisions)} pkgs • "
        f"{len(findings)} code • {len(duplicates)} dupes • "
        f"CCN avg {complexity_summary.get('avg_cyclomatic_complexity', 0)}*"
    )
    return "\n".join(c)


def main():
    for slug, repo_dir, repo_full, pr_num, title in PRS:
        diff_path = DIFFS / f"{slug}.diff"
        repo_path = REPOS / repo_dir
        if not diff_path.exists():
            print(f"SKIP {slug}: no diff")
            continue
        if not repo_path.exists():
            print(f"SKIP {slug}: repo not cloned")
            continue

        diff_text = diff_path.read_text()
        changed = extract_changed_files(diff_text)
        print(f">>> {slug} ({len(changed)} files, {title})")

        comment = build_comment(
            slug,
            repo_full,
            pr_num,
            title,
            diff_text,
            str(repo_path.resolve()),
        )
        out_path = OUT / f"{slug}.md"
        out_path.write_text(comment)
        print(f"    → {out_path}")

    print(f"\nAll comments in {OUT}/")


if __name__ == "__main__":
    main()
