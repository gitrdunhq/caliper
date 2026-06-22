#!/usr/bin/env python3
"""CLI wrapper for the solver module.

Usage:
    uv run python scripts/solve-issues.py --issues 236,237,238
    uv run python scripts/solve-issues.py --group security-trust
    uv run python scripts/solve-issues.py --issues 236 --model google/gemma-3-27b-it:free
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from caliper.core.solver import (
    ModelSpec,
    ModelTier,
    SolverConfig,
    SolverResult,
    SolverTask,
    TaskStatus,
    solve_batch,
)

logger = structlog.get_logger()

_GH_ENV = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
_SOURCE_PATH_RE = re.compile(r"(?:src/caliper/[\w/]+\.py|policies/[\w/]+\.rego)")
_PARENT_BUG_RE = re.compile(r"Parent bug:\s*#(\d+)")


def _gh(*args: str) -> str:
    r = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        env=_GH_ENV,
        timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()


def _gh_safe(*args: str) -> str | None:
    try:
        return _gh(*args)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        logger.warning("gh_cli_failed", args=args[:3], error=str(exc))
        return None


def fetch_issues(numbers: list[int]) -> list[dict]:
    issues = []
    for n in numbers:
        raw = _gh(
            "issue",
            "view",
            str(n),
            "--json",
            "number,title,body,labels",
        )
        try:
            issues.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            logger.error("issue_parse_failed", issue=n, error=str(exc))
    return issues


def fetch_issues_by_label(label: str) -> list[dict]:
    raw = _gh(
        "issue",
        "list",
        "--label",
        label,
        "--state",
        "open",
        "--limit",
        "50",
        "--json",
        "number,title,body,labels",
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("issues_parse_failed", label=label, error=str(exc))
        return []


def _extract_source_paths(body: str) -> list[str]:
    matches = _SOURCE_PATH_RE.findall(body)
    paths = [m.split(":")[0] for m in matches]
    return list(dict.fromkeys(paths))


def _read_file_safe(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    size = p.stat().st_size
    if size > 50_000:
        logger.warning("file_too_large", path=path, size=size)
        return ""
    return p.read_text(encoding="utf-8")


def _resolve_parent_bug(body: str) -> dict | None:
    match = _PARENT_BUG_RE.search(body)
    if not match:
        return None
    parent_num = match.group(1)
    raw = _gh_safe("issue", "view", parent_num, "--json", "number,title,body")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def issue_to_task(issue: dict) -> SolverTask:
    body = issue.get("body") or ""
    combined_body = body

    parent = _resolve_parent_bug(body)
    if parent:
        parent_body = parent.get("body") or ""
        combined_body = (
            f"## Detector Task\n{body}\n\n"
            f"## Parent Bug #{parent['number']}: {parent['title']}\n"
            f"{parent_body}"
        )

    source_text = (parent.get("body") or "") if parent else body
    source_paths = _extract_source_paths(source_text)
    source_files = {}
    test_files = {}

    for sp in source_paths:
        content = _read_file_safe(sp)
        if content:
            source_files[sp] = content
            test_name = f"tests/unit/test_{Path(sp).name}"
            test_content = _read_file_safe(test_name)
            if test_content:
                test_files[test_name] = test_content

    labels = [lbl["name"] for lbl in issue.get("labels", [])]
    group = next((lbl for lbl in labels if lbl.startswith("group:")), "")

    return SolverTask(
        issue_number=issue["number"],
        title=issue["title"],
        body=combined_body,
        group=group,
        source_files=source_files,
        test_files=test_files,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve issues via LLM")
    parser.add_argument(
        "--issues",
        type=str,
        help="Comma-separated issue numbers",
    )
    parser.add_argument(
        "--group",
        type=str,
        help="Group label (e.g. security-trust)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override model (skips ladder)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=3.0,
        help="Seconds between requests (default 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".temp/solver-results",
        help="Output directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build prompts but don't send to API",
    )
    args = parser.parse_args()

    api_key = os.environ.get("OPENROUTER_CALIPER", "")
    if not api_key and not args.dry_run:
        logger.error("missing_api_key", var="OPENROUTER_CALIPER")
        sys.exit(1)

    if args.issues:
        try:
            numbers = [int(n.strip()) for n in args.issues.split(",") if n.strip()]
        except ValueError:
            parser.error("--issues must be comma-separated integers")
            return
        issues = fetch_issues(numbers)
    elif args.group:
        label = f"group:{args.group}"
        issues = fetch_issues_by_label(label)
    else:
        parser.error("--issues or --group required")
        return

    tasks = [issue_to_task(i) for i in issues]

    if not tasks:
        logger.info("no_issues_found")
        return

    logger.info("tasks_loaded", count=len(tasks))
    for t in tasks:
        src = len(t.source_files)
        logger.info(
            "task_summary",
            issue=t.issue_number,
            title=t.title,
            source_files=src,
        )

    if args.dry_run:
        from caliper.core.solver import build_prompt

        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for t in tasks:
            prompt = build_prompt(t)
            path = out / f"prompt_{t.issue_number}.md"
            path.write_text(prompt, encoding="utf-8")
            logger.info("dry_run_wrote", path=str(path), chars=len(prompt))
        return

    config = SolverConfig(
        api_key=api_key,
        output_dir=args.output_dir,
        request_delay=args.delay,
    )

    if args.model:
        config.model_ladder = [
            ModelSpec(id=args.model, tier=ModelTier.DENSE),
        ]

    def on_result(r: SolverResult) -> None:
        logger.info(
            "task_result",
            issue=r.issue_number,
            status=r.status,
            model=r.model_used or "none",
            duration_s=r.duration_s,
        )

    results = solve_batch(tasks, config, on_result=on_result)

    succeeded = sum(1 for r in results if r.status == TaskStatus.SUCCESS)
    logger.info("batch_done", succeeded=succeeded, total=len(results))

    manifest = Path(args.output_dir) / "manifest.json"
    import orjson

    tmp = manifest.with_suffix(".tmp")
    tmp.write_bytes(
        orjson.dumps(
            [
                {
                    "issue": r.issue_number,
                    "status": r.status,
                    "model": r.model_used,
                    "file": (
                        f"test_detector_{r.issue_number}.py"
                        if r.status == TaskStatus.SUCCESS
                        else None
                    ),
                }
                for r in results
            ],
            option=orjson.OPT_INDENT_2,
        )
    )
    os.replace(tmp, manifest)
    logger.info("manifest_written", path=str(manifest))


if __name__ == "__main__":
    main()
