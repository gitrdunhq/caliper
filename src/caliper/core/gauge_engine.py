"""Gauge execution engine — run a promoted/candidate gauge over a file set.

# tested-by: tests/unit/test_gauge_engine.py

A promoted gauge is data (a :class:`CandidateGauge` with ``kind`` + ``draft``); this
module is what *executes* it. It is the shared executor behind two callers:

- ``caliper inspect`` Screen: run active promoted gauges over a part's real files and
  merge their matches into the deterministic Screen findings (closing the flywheel).
- ``caliper gauge backtest``: run a candidate over corpus samples to measure recall /
  precision before a human may promote it.

Only ``semgrep`` gauges are auto-executable: the draft is a declarative rule, run via
the injected semgrep callable with ``extra_config_dirs`` and filtered to this rule's
id. ``ast`` and ``manual`` gauges are model-drafted *code/requests* — running them
would mean exec'ing model output, so they are reported as not-auto-executable and a
human must register a real detector. Either way no LLM is in this path: the engine is
deterministic given a deterministic runner, and all IO is via the injected callable.
"""

from __future__ import annotations

import re
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from caliper.core.models import CandidateGauge, GaugeFinding

# Matches run_semgrep(changed_files, repo_path, timeout=, extra_config_dirs=, exclude_rules=)
SemgrepRun = Callable[..., dict]

_RULE_ID_RE = re.compile(r"id:\s*['\"]?([\w.\-]+)['\"]?")


@dataclass(frozen=True)
class GaugeRun:
    """Result of executing one gauge over a file set."""

    findings: list[GaugeFinding] = field(default_factory=list)
    executable: bool = True  # False when the kind cannot be safely auto-run
    note: str = ""


def _rule_id(draft: str) -> str | None:
    m = _RULE_ID_RE.search(draft or "")
    return m.group(1) if m else None


def _matches_rule(check_id: str, rule_id: str) -> bool:
    # opengrep prefixes local-rule ids with their dotted path; match either form.
    return check_id == rule_id or check_id.endswith(f".{rule_id}")


def run_gauge(
    candidate: CandidateGauge,
    files: Sequence[str],
    repo_path: Path | str,
    *,
    semgrep_run: SemgrepRun,
    timeout: int = 60,
) -> GaugeRun:
    """Execute *candidate* over *files*. Deterministic; only ``semgrep`` kind runs."""
    if candidate.kind != "semgrep":
        return GaugeRun(
            [], executable=False, note=f"kind '{candidate.kind}' needs a human-written detector"
        )
    file_list = list(files)
    if not file_list:
        return GaugeRun([], executable=True, note="no files")

    rule_id = _rule_id(candidate.draft)
    with tempfile.TemporaryDirectory(prefix="caliper-gauge-") as tmp:
        rule_path = Path(tmp) / f"{candidate.cluster_key.replace('/', '_')}.yaml"
        rule_path.write_text(candidate.draft)
        data = semgrep_run(file_list, str(repo_path), timeout=timeout, extra_config_dirs=[tmp])

    findings: list[GaugeFinding] = []
    for i, r in enumerate(data.get("results", []) if isinstance(data, dict) else []):
        check_id = str(r.get("check_id", ""))
        # Keep only this gauge's matches — the runner also applies the repo's standard
        # rulesets, whose hits are not this candidate's evidence.
        if rule_id and not _matches_rule(check_id, rule_id):
            continue
        start = (r.get("start") or {}).get("line", 0)
        end = (r.get("end") or {}).get("line", start)
        extra = r.get("extra") or {}
        findings.append(
            GaugeFinding(
                id=f"gauge:{candidate.cluster_key}:{i}",
                file=str(r.get("path", "")),
                line_range=(int(start), int(end)) if start else None,
                severity=str(extra.get("severity", "info") or "info").lower(),
                category="",  # a promoted gauge is a detection, not a claim category
                message=str(extra.get("message", ""))[:500],
                source=f"gauge:{candidate.cluster_key}",
            )
        )
    return GaugeRun(findings, executable=True, note=f"{len(findings)} matches")


def make_backtest_runner(
    repo_path: Path | str,
    resolve_sample: Callable[[str], list[str]],
    semgrep_run: SemgrepRun,
    *,
    timeout: int = 60,
):
    """Build a ``GaugeRunner`` (``backtest``'s ``(candidate, samples) -> RunOutput``)
    on top of :func:`run_gauge`.

    ``resolve_sample`` maps a corpus sample id to the files to scan. A sample counts as
    a *hit* when the gauge produces at least one finding on it. A non-executable kind
    flags nothing (so it fails the recall floor and cannot be promoted — the same safe
    outcome as the v0 null runner, but now real for ``semgrep`` gauges).
    """
    from caliper.core.backtest import RunOutput

    def runner(candidate: CandidateGauge, samples: list[str]) -> RunOutput:
        hits: set[str] = set()
        for sid in samples:
            run = run_gauge(
                candidate, resolve_sample(sid), repo_path, semgrep_run=semgrep_run, timeout=timeout
            )
            if run.findings:
                hits.add(sid)
        return RunOutput(hits=hits, runtime_ms=0)

    return runner
