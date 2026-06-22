"""Supply-chain version-bump scan orchestration (data tier).
# tested-by: tests/unit/test_supply_chain_scan.py

Wires the fetch+diff primitive (``data.pkgsrc``) to the deterministic signal
scorer (``core.supply_chain_diff``): for each version bump in a PR diff, download
both versions, diff the source, and score signals. Lives in the data tier because
it performs I/O (registry downloads) — ``core`` stays pure.

Fail-open throughout: a fetch/extract/diff failure for one package becomes a
single informational finding and never aborts the scan or raises.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from caliper.core.registries import PACKAGE_SOURCES
from caliper.core.supply_chain_diff import detect_upgrades, score_signals
from caliper.core.supply_chain_models import VersionDiff
from caliper.data.pkgsrc import diff_versions

if TYPE_CHECKING:
    from caliper.core.config import CaliperSettings
    from caliper.core.plugin import PluginFinding
    from caliper.core.ports import PackageSourcePort

logger = structlog.get_logger(__name__)


def analyze_upgrade(
    change: dict,
    source: PackageSourcePort,
    *,
    ecosystem: str,
) -> list[PluginFinding]:
    """Fetch both versions of one upgraded package, diff them, and score signals.

    Fail-open: any error yields a single informational finding, never raises.
    """
    package = change["package"]
    old_v = change.get("old_version")
    new_v = change.get("new_version")
    if not old_v or not new_v:
        return []
    try:
        with tempfile.TemporaryDirectory(prefix="caliper-scdiff-") as tmp:
            base = Path(tmp)
            old_fp = source.fetch_version(package, str(old_v), base / "old")
            new_fp = source.fetch_version(package, str(new_v), base / "new")
            vd = diff_versions(
                old_fp,
                new_fp,
                package=package,
                ecosystem=ecosystem,
                old_version=str(old_v),
                new_version=str(new_v),
            )
        return score_signals(vd)
    except Exception as exc:  # fail-open
        logger.warning("supply_chain_scan.analyze_failed", package=package, error=str(exc))
        unavailable = VersionDiff(
            package=package,
            ecosystem=ecosystem,
            old_version=str(old_v),
            new_version=str(new_v),
            available=False,
            error=str(exc),
        )
        return score_signals(unavailable)


def run_supply_chain_diff(
    diff_text: str,
    settings: CaliperSettings,
    *,
    sources: dict[str, PackageSourcePort] | None = None,
) -> list[PluginFinding]:
    """Analyze every version bump in *diff_text* (the gated standalone step).

    ``sources`` lets tests inject fake adapters; in production they are built from
    the PACKAGE_SOURCES registry, restricted to ``supply_chain_diff_ecosystems``.
    """
    enabled = set(settings.supply_chain_diff_ecosystems)
    cache: dict[str, PackageSourcePort] = dict(sources or {})
    findings: list[PluginFinding] = []
    for ecosystem, change in detect_upgrades(diff_text):
        if ecosystem not in enabled:
            continue
        source = cache.get(ecosystem)
        if source is None:
            if ecosystem not in PACKAGE_SOURCES:
                continue
            source = PACKAGE_SOURCES.create(ecosystem, timeout=settings.supply_chain_diff_timeout)
            cache[ecosystem] = source
        findings.extend(analyze_upgrade(change, source, ecosystem=ecosystem))
    return findings
