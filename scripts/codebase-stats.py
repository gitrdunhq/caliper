#!/usr/bin/env python3
# tested-by: tests/e2e (manual — operational script)
"""codebase-stats.py — Machine-readable codebase inventory with scribeed metadata.

Outputs JSON to stdout. Human-readable table to stderr.

Usage:
    uv run python3 scripts/codebase-stats.py                  # JSON to stdout
    uv run python3 scripts/codebase-stats.py --pretty         # human table only
    uv run python3 scripts/codebase-stats.py > stats.json     # pipe JSON, table to terminal
"""

from __future__ import annotations

import hashlib
import json
import re
import statistics
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    ).stdout.strip()
)

TIER_MAP = {
    "cli": "presentation",
    "core": "logic",
    "data": "data",
    "plugins": "data",
    "agent": "presentation",
    "templates": "data",
    "webhook": "presentation",
}

CATEGORY_MAP = {
    "src/caliper/cli": "source",
    "src/caliper/core": "source",
    "src/caliper/data": "source",
    "src/caliper/plugins": "source",
    "src/caliper/agent": "source",
    "src/caliper/webhook": "source",
    "src/caliper/templates": "source",
    "tests/unit": "test",
    "tests/integration": "test",
    "tests/e2e": "test",
}


def estimate_tokens(text: str) -> int:
    words = len(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", text))
    symbols = len(re.findall(r"[^a-zA-Z0-9_\s]", text))
    return int(words * 1.3 + symbols * 0.7)


def classify_tier(rel_path: str) -> str:
    parts = Path(rel_path).parts
    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "caliper":
        return TIER_MAP.get(parts[2], "unknown")
    return "unknown"


def classify_category(rel_path: str) -> str:
    for prefix, cat in CATEGORY_MAP.items():
        if rel_path.startswith(prefix):
            return cat
    return "other"


def git_last_modified(path: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "log", "-1", "--format=%aI", "--", str(path)],
            capture_output=True,
            text=True,
            check=True,
            cwd=REPO_ROOT,
            timeout=30,
        )
        return r.stdout.strip() or None
    except Exception:
        return None


def tested_by(text: str) -> str | None:
    m = re.search(r"#\s*tested-by:\s*(.+)", text)
    return m.group(1).strip() if m else None


def analyze_file(path: Path) -> dict:
    rel = str(path.relative_to(REPO_ROOT))
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    tokens = estimate_tokens(text)
    sha = hashlib.sha256(text.encode()).hexdigest()[:16]

    blank = sum(1 for ln in lines if not ln.strip())
    comment = sum(1 for ln in lines if ln.strip().startswith("#"))
    code = len(lines) - blank - comment

    imports = [ln.strip() for ln in lines if ln.strip().startswith(("import ", "from "))]

    classes = len(re.findall(r"^class \w+", text, re.MULTILINE))
    functions = len(re.findall(r"^def \w+", text, re.MULTILINE))
    methods = len(re.findall(r"^    def \w+", text, re.MULTILINE))

    import_modules = []
    for imp in imports:
        m = re.match(r"from\s+([\w.]+)", imp) or re.match(r"import\s+([\w.]+)", imp)
        if m:
            import_modules.append(m.group(1))

    public_api = re.findall(r"^(?:class|def)\s+(\w+)", text, re.MULTILINE)
    public_api = [name for name in public_api if not name.startswith("_")]

    return {
        "path": rel,
        "category": classify_category(rel),
        "tier": classify_tier(rel),
        "lines": len(lines),
        "lines_code": code,
        "lines_blank": blank,
        "lines_comment": comment,
        "tokens": tokens,
        "tokens_per_line": round(tokens / max(len(lines), 1), 1),
        "sha256_prefix": sha,
        "classes": classes,
        "functions": functions,
        "methods": methods,
        "imports": len(imports),
        "import_modules": import_modules,
        "public_api": public_api,
        "tested_by": tested_by(text),
        "over_500": len(lines) > 500,
        "last_modified": git_last_modified(path),
    }


def _scribe_dependency_graph(files: list[dict]) -> None:
    """Add imported_by and blast_radius to each file in-place."""
    path_to_module: dict[str, str] = {}
    for f in files:
        p = f["path"]
        if p.startswith("src/"):
            mod = p[4:].replace("/", ".").removesuffix(".py").removesuffix(".__init__")
        else:
            mod = p.replace("/", ".").removesuffix(".py").removesuffix(".__init__")
        path_to_module[f["path"]] = mod

    module_to_path: dict[str, str] = {v: k for k, v in path_to_module.items()}

    for f in files:
        imported_by = []
        my_mod = path_to_module.get(f["path"], "")
        for other in files:
            if other["path"] == f["path"]:
                continue
            for imp in other.get("import_modules", []):
                if imp == my_mod or imp.startswith(my_mod + "."):
                    imported_by.append(other["path"])
                    break
        f["imported_by"] = imported_by
        f["blast_radius"] = len(imported_by)

    for f in files:
        deps = []
        for imp in f.get("import_modules", []):
            resolved = module_to_path.get(imp)
            if not resolved:
                for mod, path in module_to_path.items():
                    if imp.startswith(mod + ".") or mod.startswith(imp + "."):
                        resolved = path
                        break
            if resolved:
                deps.append(resolved)
        f["depends_on"] = deps


def _cluster_concerns(src_files: list[dict]) -> list[dict]:
    """Group source files into concern clusters by shared imports."""
    clusters: dict[str, list[str]] = {}
    for f in src_files:
        parts = Path(f["path"]).parts
        key = "/".join(parts[:3]) if len(parts) >= 3 else f["path"]
        clusters.setdefault(key, []).append(f["path"])

    result = []
    for key, paths in sorted(clusters.items()):
        members = [f for f in src_files if f["path"] in paths]
        total_tokens = sum(m["tokens"] for m in members)
        total_lines = sum(m["lines"] for m in members)
        ext_deps = set()
        for m in members:
            for dep in m.get("depends_on", []):
                if dep not in paths:
                    ext_deps.add(dep)
        result.append(
            {
                "concern": key,
                "files": paths,
                "file_count": len(paths),
                "total_tokens": total_tokens,
                "total_lines": total_lines,
                "external_deps": sorted(ext_deps),
                "max_blast_radius": max((m["blast_radius"] for m in members), default=0),
            }
        )
    return sorted(result, key=lambda c: -c["total_tokens"])


def aggregate(files: list[dict], label: str) -> dict:
    if not files:
        return {"label": label, "file_count": 0}
    lines = [f["lines"] for f in files]
    tokens = [f["tokens"] for f in files]
    return {
        "label": label,
        "file_count": len(files),
        "lines_total": sum(lines),
        "lines_code": sum(f["lines_code"] for f in files),
        "tokens_total": sum(tokens),
        "lines_median": int(statistics.median(lines)),
        "lines_avg": int(statistics.mean(lines)),
        "lines_p25": sorted(lines)[len(lines) // 4],
        "lines_p75": sorted(lines)[3 * len(lines) // 4],
        "lines_max": max(lines),
        "tokens_median": int(statistics.median(tokens)),
        "tokens_avg": int(statistics.mean(tokens)),
        "tokens_max": max(tokens),
    }


def main() -> None:
    pretty = "--pretty" in sys.argv

    all_py = sorted(REPO_ROOT.rglob("*.py"))
    all_py = [p for p in all_py if "__pycache__" not in str(p) and ".venv" not in str(p)]

    files = [analyze_file(p) for p in all_py]
    src_files = [f for f in files if f["category"] == "source"]
    test_files = [f for f in files if f["category"] == "test"]

    commit = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=10,
    ).stdout.strip()

    branch = subprocess.run(
        ["git", "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=10,
    ).stdout.strip()

    over_500 = [f["path"] for f in src_files if f["over_500"]]
    untested = [f["path"] for f in src_files if not f["tested_by"] and f["lines"] > 0]

    _scribe_dependency_graph(files)
    concerns = _cluster_concerns(src_files)

    report = {
        "schema_version": "2.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "commit": commit,
        "branch": branch,
        "summary": {
            "source": aggregate(src_files, "source"),
            "tests": aggregate(test_files, "tests"),
            "total_files": len(files),
            "total_lines": sum(f["lines"] for f in files),
            "total_tokens": sum(f["tokens"] for f in files),
            "test_code_ratio": round(
                sum(f["tokens"] for f in test_files) / max(sum(f["tokens"] for f in src_files), 1),
                2,
            ),
        },
        "flags": {
            "over_500_lines": over_500,
            "missing_tested_by": untested[:20],
        },
        "concerns": concerns,
        "files": sorted(files, key=lambda f: -f["tokens"]),
    }

    json_out = json.dumps(report, indent=2, default=str)

    if pretty:
        _print_table(report)
    else:
        sys.stdout.write(json_out + "\n")
        _print_table(report, file=sys.stderr)


def _print_table(report: dict, file=None) -> None:
    if file is None:
        file = sys.stdout
    s = report["summary"]
    src = s["source"]
    tst = s["tests"]

    def p(*a, **kw):
        print(*a, **kw, file=file)

    p(f"\n  caliper codebase — {report['branch']}@{report['commit']}")
    p(f"  {'=' * 50}")
    p(f"  {'':>20} {'Source':>10} {'Tests':>10} {'Total':>10}")
    p(f"  {'─' * 20} {'─' * 10} {'─' * 10} {'─' * 10}")
    fc = src["file_count"], tst["file_count"], s["total_files"]
    p(f"  {'Files':<20} {fc[0]:>10} {fc[1]:>10} {fc[2]:>10}")
    lt = src["lines_total"], tst["lines_total"], s["total_lines"]
    p(f"  {'Lines':<20} {lt[0]:>10,} {lt[1]:>10,} {lt[2]:>10,}")
    p(f"  {'Lines (code only)':<20} {src['lines_code']:>10,}")
    tt = src["tokens_total"], tst["tokens_total"], s["total_tokens"]
    p(f"  {'Tokens':<20} {tt[0]:>10,} {tt[1]:>10,} {tt[2]:>10,}")
    p(f"  {'Median lines/file':<20} {src['lines_median']:>10} {tst['lines_median']:>10}")
    p(f"  {'Max lines':<20} {src['lines_max']:>10} {tst['lines_max']:>10}")
    r = s["test_code_ratio"]
    p(f"  {'Test:Code ratio':<20} {'':>10} {'':>10} {r:>9.2f}:1")

    flags = report["flags"]
    if flags["over_500_lines"]:
        p(f"\n  Files over 500-line cap: {len(flags['over_500_lines'])}")
        for f in flags["over_500_lines"]:
            p(f"    {f}")
    p()


if __name__ == "__main__":
    main()
