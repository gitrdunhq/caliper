"""Stress test runner — runs Foreman tools against real PR diffs.
Outputs markdown reports simulating what the agent would comment.
"""

from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

DIFFS_DIR = Path(".temp/stress-test/diffs")
REPORTS_DIR = Path(".temp/stress-test/reports")

PR_METADATA = [
    ("01-aws-workload-ci-112", "farmcreditca/aws-workload-ci", 112, "Monthly Jenkins update"),
    ("02-infrastructure-467", "farmcreditca/infrastructure", 467, "Monthly SonarQube update"),
    (
        "03-aws-infra-ops-52",
        "farmcreditca/aws-infrastructure-operations",
        52,
        "ACM perms adjustment for MS team",
    ),
    (
        "04-network-mgmt-22",
        "farmcreditca/aws-workload-network-mgmt",
        22,
        "Perimeter stuff for Network",
    ),
    (
        "05-infra-perimeter-1",
        "farmcreditca/aws-infrastructure-perimeter",
        1,
        "Perimeter stuff for Network",
    ),
    ("06-aws-jet-115", "farmcreditca/aws-workload-jet", 115, "EKS fixes"),
    ("07-aws-jet-116", "farmcreditca/aws-workload-jet", 116, "EKS fixes"),
    ("08-aws-jet-117", "farmcreditca/aws-workload-jet", 117, "EKS fixes"),
    (
        "09-k8s-jet-37",
        "farmcreditca/kubernetes-workload-jet",
        37,
        "Multi-sprint massive branch sync",
    ),
    ("10-network-mgmt-17", "farmcreditca/aws-workload-network-mgmt", 17, "Cisco ISE in LZA"),
    (
        "11-aws-jet-114",
        "farmcreditca/aws-workload-jet",
        114,
        "Remaining routes for K8s + auto redirect 443",
    ),
]


def extract_changed_files(diff_text: str) -> list[str]:
    files = []
    for match in re.finditer(r"^diff --git a/.+ b/(.+)$", diff_text, re.MULTILINE):
        path = match.group(1)
        start = match.start()
        chunk = diff_text[start : start + 500]
        if (
            "+++ /dev/null" not in chunk.split("diff --git")[0]
            if "diff --git" in chunk[1:]
            else "+++ /dev/null" not in chunk
        ):
            files.append(path)
    return files


def run_semgrep_on_diff(diff_text: str, diff_path: Path) -> dict:
    changed = extract_changed_files(diff_text)
    if not changed:
        return {"results": [], "errors": [], "files": []}

    try:
        cmd = ["semgrep", "--config", "p/default", "--json", "--no-git-ignore"]
        for f in changed:
            cmd.extend(["--include", Path(f).name])
        cmd.append(str(diff_path.parent))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.stdout:
            data = json.loads(result.stdout)
            data["files"] = changed
            return data
        return {"results": [], "errors": [], "files": changed}
    except subprocess.TimeoutExpired:
        return {"results": [], "errors": [{"message": "semgrep timeout (120s)"}], "files": changed}
    except FileNotFoundError:
        return {"results": [], "errors": [{"message": "semgrep not installed"}], "files": changed}
    except Exception as e:
        return {"results": [], "errors": [{"message": str(e)}], "files": changed}


def detect_dependency_changes(diff_text: str) -> list[dict]:
    dep_files = [
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.toml",
        "Cargo.lock",
        "go.mod",
        "go.sum",
        "Gemfile",
        "Gemfile.lock",
        "pom.xml",
        "build.gradle",
    ]
    changes = []
    for f in extract_changed_files(diff_text):
        basename = Path(f).name
        if basename in dep_files:
            changes.append({"file": f, "type": basename})
    return changes


def format_semgrep_findings(results: list[dict]) -> str:
    if not results:
        return ""

    by_severity = {"ERROR": [], "WARNING": [], "INFO": []}
    for r in results:
        sev = r.get("extra", {}).get("severity", "WARNING")
        by_severity.setdefault(sev, []).append(r)

    lines = ["### Code Patterns (Semgrep)", ""]

    for sev in ["ERROR", "WARNING", "INFO"]:
        items = by_severity.get(sev, [])
        if not items:
            continue
        icon = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "ℹ️"}.get(sev, "")
        lines.append(f"**{icon} {sev}** ({len(items)})")
        lines.append("")
        for r in items[:10]:
            rule = r.get("check_id", "unknown").split(".")[-1]
            path = r.get("path", "?")
            start = r.get("start", {}).get("line", "?")
            msg = r.get("extra", {}).get("message", "")[:150]
            lines.append(f"- **{rule}** — `{path}:{start}`")
            lines.append(f"  {msg}")
            lines.append("")
        if len(items) > 10:
            lines.append(f"  *...and {len(items) - 10} more {sev} findings*")
            lines.append("")

    return "\n".join(lines)


def generate_report(
    slug: str, repo: str, pr_num: int, title: str, diff_text: str, diff_path: Path
) -> str:
    changed_files = extract_changed_files(diff_text)
    dep_changes = detect_dependency_changes(diff_text)
    semgrep_raw = run_semgrep_on_diff(diff_text, diff_path)
    semgrep_results = semgrep_raw.get("results", [])
    semgrep_errors = semgrep_raw.get("errors", [])

    lines_changed = sum(
        1 for line in diff_text.split("\n") if line.startswith("+") or line.startswith("-")
    )

    report = []
    report.append(f"# Foreman Review — {repo}#{pr_num}")
    report.append(f"**PR**: [{title}](https://github.com/{repo}/pull/{pr_num})")
    report.append(f"**Date**: {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M UTC')}")
    report.append(f"**Files changed**: {len(changed_files)}")
    report.append(f"**Lines changed**: ~{lines_changed}")
    report.append("")
    report.append("---")
    report.append("")

    # Dependency section
    if dep_changes:
        report.append("## Dependency Changes Detected")
        report.append("")
        for d in dep_changes:
            report.append(f"- `{d['file']}` ({d['type']})")
        report.append("")
        report.append(
            "> Pipeline would run: Syft, OSV-Scanner, Trivy, ScanCode, OPA policy evaluation"
        )
        report.append("> (Not executed in this dry run — requires container with scanner binaries)")
        report.append("")
    else:
        report.append("## Dependency Changes")
        report.append("")
        report.append(
            "No dependency manifest changes detected. Pipeline scanners would not trigger."
        )
        report.append("")

    # Semgrep section
    if semgrep_results:
        report.append(format_semgrep_findings(semgrep_results))
    elif semgrep_errors:
        report.append("### Code Patterns (Semgrep)")
        report.append("")
        for e in semgrep_errors:
            report.append(f"- Error: {e.get('message', 'unknown')}")
        report.append("")
    else:
        report.append("### Code Patterns (Semgrep)")
        report.append("")
        report.append("No code pattern issues found in changed files.")
        report.append("")

    # Changed files summary
    report.append("### Changed Files")
    report.append("")
    for f in changed_files[:30]:
        report.append(f"- `{f}`")
    if len(changed_files) > 30:
        report.append(f"- *...and {len(changed_files) - 30} more*")
    report.append("")

    # Summary
    report.append("---")
    report.append("")
    total_findings = len(semgrep_results)
    errors = len([r for r in semgrep_results if r.get("extra", {}).get("severity") == "ERROR"])
    warnings = len([r for r in semgrep_results if r.get("extra", {}).get("severity") == "WARNING"])

    if errors > 0:
        report.append(f"**Verdict**: 🔴 **{errors} ERROR-level findings** require attention")
    elif warnings > 0:
        report.append(f"**Verdict**: 🟡 **{warnings} WARNING-level findings** — review recommended")
    elif dep_changes:
        report.append(
            "**Verdict**: 🟡 **Dependency changes detected**"
            " — full scanner pipeline required for verdict"
        )
    else:
        report.append("**Verdict**: 🟢 **No issues detected**")

    report.append(f"**Total findings**: {total_findings} (Semgrep)")
    report.append(f"**Dependency changes**: {'Yes' if dep_changes else 'No'}")
    report.append("")
    report.append("*Foreman PoC — dry run, no comments posted*")

    return "\n".join(report)


def main():
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    for slug, repo, pr_num, title in PR_METADATA:
        diff_path = DIFFS_DIR / f"{slug}.diff"
        if not diff_path.exists():
            print(f"SKIP: {slug} — diff not found")
            continue

        diff_text = diff_path.read_text()
        print(f"Running: {slug} ({len(diff_text)} bytes, {title})...")

        report = generate_report(slug, repo, pr_num, title, diff_text, diff_path)

        report_path = REPORTS_DIR / f"{slug}.md"
        report_path.write_text(report)
        print(f"  → {report_path}")

    print()
    print(f"All reports in: {REPORTS_DIR}/")
    print("Done.")


if __name__ == "__main__":
    main()
