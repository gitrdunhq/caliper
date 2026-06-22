"""Stress test v2 — runs against cloned repos with real file access."""

from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

DIFFS_DIR = Path(".temp/stress-test/diffs")
REPOS_DIR = Path(".temp/stress-test/repos")
REPORTS_DIR = Path(".temp/stress-test/reports")

TESTS = [
    {
        "slug": "05-infra-perimeter-1",
        "repo_dir": "aws-infrastructure-perimeter",
        "repo": "farmcreditca/aws-infrastructure-perimeter",
        "pr": 1,
        "title": "Perimeter stuff for Network (CDK + package.json + yarn.lock)",
    },
    {
        "slug": "09-k8s-jet-37",
        "repo_dir": "kubernetes-workload-jet",
        "repo": "farmcreditca/kubernetes-workload-jet",
        "pr": 37,
        "title": "Multi-sprint massive branch — K8s manifests",
    },
    {
        "slug": "10-network-mgmt-17",
        "repo_dir": "aws-workload-network-mgmt",
        "repo": "farmcreditca/aws-workload-network-mgmt",
        "pr": 17,
        "title": "Cisco ISE in LZA (network config)",
    },
    {
        "slug": "11-aws-jet-114",
        "repo_dir": "aws-workload-jet",
        "repo": "farmcreditca/aws-workload-jet",
        "pr": 114,
        "title": "Remaining routes for K8s + auto redirect 443",
    },
]

DEP_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pyproject.toml",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
}


def extract_changed_files(diff_text: str) -> list[str]:
    files = []
    for match in re.finditer(r"^diff --git a/.+ b/(.+)$", diff_text, re.MULTILINE):
        path = match.group(1)
        pos = match.start()
        next_diff = diff_text.find("diff --git", pos + 1)
        chunk = diff_text[pos:next_diff] if next_diff > 0 else diff_text[pos:]
        if "+++ /dev/null" not in chunk:
            files.append(path)
    return files


def run_semgrep(repo_path: Path, changed_files: list[str]) -> dict:
    existing = [f for f in changed_files if (repo_path / f).exists()]
    if not existing:
        return {"results": [], "errors": [], "scanned": 0, "attempted": len(changed_files)}

    cmd = ["semgrep", "--config", "p/default", "--json", "--no-git-ignore", *existing]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(repo_path),
            check=False,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            data["scanned"] = len(existing)
            data["attempted"] = len(changed_files)
            return data
    except subprocess.TimeoutExpired:
        return {
            "results": [],
            "errors": [{"message": "timeout 120s"}],
            "scanned": 0,
            "attempted": len(changed_files),
        }
    except Exception as exc:
        return {
            "results": [],
            "errors": [{"message": str(exc)}],
            "scanned": 0,
            "attempted": len(changed_files),
        }

    return {"results": [], "errors": [], "scanned": len(existing), "attempted": len(changed_files)}


def format_report(test: dict, diff_text: str, semgrep_data: dict) -> str:
    changed = extract_changed_files(diff_text)
    dep_changes = [f for f in changed if Path(f).name in DEP_FILES]
    results = semgrep_data.get("results", [])
    errors = semgrep_data.get("errors", [])
    scanned = semgrep_data.get("scanned", 0)

    lines = []
    lines.append(f"# Foreman Review — {test['repo']}#{test['pr']}")
    lines.append(f"**PR**: [{test['title']}](https://github.com/{test['repo']}/pull/{test['pr']})")
    lines.append(f"**Date**: {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Files changed**: {len(changed)} | **Scanned by Semgrep**: {scanned}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Dependencies
    if dep_changes:
        lines.append("## 📦 Dependency Changes Detected")
        lines.append("")
        for f in dep_changes:
            lines.append(f"- `{f}`")
        lines.append("")
        lines.append(
            "> Full pipeline (Syft + OSV-Scanner + Trivy + ScanCode + OPA)"
            " would evaluate these. Requires container with scanner binaries."
        )
        lines.append("")
    else:
        lines.append("## 📦 Dependency Changes")
        lines.append("")
        lines.append("None detected.")
        lines.append("")

    # Semgrep
    if results:
        by_sev = {"ERROR": [], "WARNING": [], "INFO": []}
        for r in results:
            sev = r.get("extra", {}).get("severity", "WARNING")
            by_sev.setdefault(sev, []).append(r)

        lines.append("## 🔍 Code Patterns (Semgrep)")
        lines.append("")

        for sev in ["ERROR", "WARNING", "INFO"]:
            items = by_sev.get(sev, [])
            if not items:
                continue
            icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}[sev]
            lines.append(f"### {icon} {sev} ({len(items)})")
            lines.append("")

            for r in items[:15]:
                rule_full = r.get("check_id", "unknown")
                rule_short = rule_full.split(".")[-1]
                fpath = r.get("path", "?")
                start = r.get("start", {}).get("line", "?")
                end = r.get("end", {}).get("line", start)
                msg = r.get("extra", {}).get("message", "")
                cat = r.get("extra", {}).get("metadata", {}).get("category", "")
                lines.append(f"#### `{fpath}:{start}-{end}` — {rule_short}")
                if cat:
                    lines.append(f"**Category**: {cat}")
                lines.append(f"**Rule**: `{rule_full}`")
                lines.append("")
                if msg:
                    lines.append(f"> {msg[:300]}")
                    lines.append("")

            if len(items) > 15:
                lines.append(f"*...and {len(items) - 15} more {sev} findings*")
                lines.append("")
    elif errors:
        lines.append("## 🔍 Code Patterns (Semgrep)")
        lines.append("")
        for err in errors:
            lines.append(f"- ⚠️ {err.get('message', 'unknown error')}")
        lines.append("")
    else:
        lines.append("## 🔍 Code Patterns (Semgrep)")
        lines.append("")
        lines.append("No findings in changed files.")
        lines.append("")

    # Files
    lines.append("## 📁 Changed Files")
    lines.append("")
    for f in changed[:40]:
        marker = " 📦" if Path(f).name in DEP_FILES else ""
        lines.append(f"- `{f}`{marker}")
    if len(changed) > 40:
        lines.append(f"- *...and {len(changed) - 40} more*")
    lines.append("")

    # Verdict
    lines.append("---")
    lines.append("")
    err_count = len(by_sev.get("ERROR", [])) if results else 0
    warn_count = len(by_sev.get("WARNING", [])) if results else 0
    info_count = len(by_sev.get("INFO", [])) if results else 0

    if err_count > 0:
        lines.append(f"## 🔴 VERDICT: {err_count} ERROR findings require attention")
    elif warn_count > 0:
        lines.append(f"## 🟡 VERDICT: {warn_count} WARNING findings — review recommended")
    elif dep_changes:
        lines.append("## 🟡 VERDICT: Dependency changes — full scanner pipeline needed")
    else:
        lines.append("## 🟢 VERDICT: No issues detected")

    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Semgrep ERROR | {err_count} |")
    lines.append(f"| Semgrep WARNING | {warn_count} |")
    lines.append(f"| Semgrep INFO | {info_count} |")
    lines.append(f"| Dependency changes | {'Yes' if dep_changes else 'No'} |")
    lines.append(f"| Files scanned | {scanned}/{len(changed)} |")
    lines.append("")
    lines.append("*Foreman PoC — dry run, no comments posted*")

    return "\n".join(lines)


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    for test in TESTS:
        diff_path = DIFFS_DIR / f"{test['slug']}.diff"
        repo_path = REPOS_DIR / test["repo_dir"]

        if not diff_path.exists():
            print(f"SKIP {test['slug']}: diff not found")
            continue
        if not repo_path.exists():
            print(f"SKIP {test['slug']}: repo not cloned at {repo_path}")
            continue

        diff_text = diff_path.read_text()
        changed = extract_changed_files(diff_text)
        print(f"Running: {test['slug']} ({len(changed)} files, {len(diff_text)} bytes)...")

        semgrep_data = run_semgrep(repo_path, changed)
        n_results = len(semgrep_data.get("results", []))
        n_errors = len(semgrep_data.get("errors", []))
        print(
            f"  Semgrep: {n_results} findings, {n_errors} errors, "
            f"{semgrep_data.get('scanned', 0)} files scanned"
        )

        report = format_report(test, diff_text, semgrep_data)
        out = REPORTS_DIR / f"{test['slug']}-real.md"
        out.write_text(report)
        print(f"  → {out}")
        print()

    print("Done. Reports in .temp/stress-test/reports/")


if __name__ == "__main__":
    main()
