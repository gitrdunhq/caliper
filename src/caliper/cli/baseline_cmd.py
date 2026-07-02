"""``caliper baseline`` — write/update the finding suppression baseline.

# tested-by: tests/unit/test_baseline_cmd.py

Scans the repo the same way ``caliper evaluate`` does (ScanOrchestrator +
normalize_findings, so fingerprints match what the pipeline filters against),
then adds a baseline entry for every finding not already covered. Existing
entries are left untouched — re-running against an unchanged finding set is a
no-op.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import click

from caliper.core.accessors import get_scanners
from caliper.core.baseline import load_baseline, merge_new_entries, save_baseline
from caliper.core.normalizer import normalize_findings
from caliper.core.orchestrator import ScanOrchestrator
from caliper.core.repo_config import load_repo_config


@click.group(name="baseline")
def baseline() -> None:
    """Manage the finding suppression baseline."""


@baseline.command("update")
@click.option("--repo-path", type=click.Path(exists=True), default=".", help="Repository root.")
@click.option("--reason", required=True, help="Reason recorded for every newly baselined finding.")
def update_cmd(repo_path: str, reason: str) -> None:
    """Scan the repo and add a baseline entry for every unbaselined finding."""
    from caliper.composition.bootstrap import bootstrap
    from caliper.core.config import CaliperSettings

    repo = Path(repo_path).resolve()
    repo_config = load_repo_config(repo)
    baseline_path = repo / repo_config.baseline.path

    config = CaliperSettings()  # type: ignore[call-arg]
    context = bootstrap(config)
    orchestrator = ScanOrchestrator(
        scanners=get_scanners(context),
        combined_timeout=config.combined_scanner_timeout,
    )
    scan_results = orchestrator.run(repo)
    findings, _summary = normalize_findings(scan_results)

    existing = load_baseline(baseline_path)
    updated = merge_new_entries(
        existing,
        findings,
        reason=reason,
        today=date.today(),
        ttl_days=repo_config.baseline.default_ttl_days,
    )
    save_baseline(baseline_path, updated)

    added = len(updated.entries) - len(existing.entries)
    click.echo(
        f"baseline: {added} new entries added, {len(updated.entries)} total -> {baseline_path}"
    )
