"""The parting plugin — the consumer in caliper's producer/consumer pattern.
# tested-by: tests/unit/test_parting_plugin.py

``caliper part`` is a manual, developer-invoked gate, NOT part of the automatic
review pipeline. This module is therefore underscore-prefixed so ``autodiscover``
skips it, and it self-registers into the dedicated ``PARTING`` registry rather
than ``ANALYZERS`` — it is structurally impossible for it to enter ``caliper
review`` / Foreman / the webhook. The CLI (``caliper part``) is its only caller.

It is a single plugin (the consumer): :meth:`PartingPlugin.cut` invokes the stock
*producer* (``core.part_stock.build_stock``, the impure git step) and feeds the
result to the pure *consumer* (``core.parting.part``), stamping reproducible
provenance. It implements the ``ScannerPlugin`` surface so it genuinely follows
the plugin contract, but ``can_run`` is always ``False`` and ``run`` is a skip:
parting never fires automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from caliper.core.models import CutList, Provenance
from caliper.core.part_stock import build_stock
from caliper.core.parting import config_digest, part
from caliper.core.plugin import PluginCategory, PluginResult, ScannerPlugin
from caliper.core.registries import PARTING
from caliper.core.repo_config import PartingConfig
from caliper.core.tool_runner import ToolRunnerPort
from caliper.core.version import get_version


@dataclass(frozen=True)
class PartingOutcome:
    """The consumer's output: the cut list plus the rename old-path map.

    ``old_paths`` (new path -> old path) is carried alongside the cut list because
    the restack script must restore a rename's old path to remove it, and the
    canonical ``Part.files`` deliberately holds only the new path (counted once).
    """

    cutlist: CutList
    old_paths: dict[str, str]


class PartingPlugin(ScannerPlugin):
    """Cut a stock into an ordered cut list. Manual-only; never auto-run."""

    @property
    def name(self) -> str:
        return "parting"

    @property
    def description(self) -> str:
        return "Propose how to cut a diff into an ordered cut list (manual: `caliper part`)"

    @property
    def category(self) -> PluginCategory:
        return PluginCategory.code

    def can_run(self, files: list[str], repo_path: Path) -> bool:
        # Manual gate: parting never runs in the automatic pipeline. It is also
        # absent from ANALYZERS, so this is belt-and-braces.
        return False

    def run(self, files: list[str], repo_path: Path) -> PluginResult:
        return PluginResult(
            plugin_name=self.name,
            skip_reason="parting is a manual gate",
            skip_remediation="run `caliper part --base <rev> --head <rev>`",
        )

    def cut(
        self,
        repo_path: Path,
        base: str,
        head: str,
        cfg: PartingConfig,
        *,
        runner: ToolRunnerPort | None = None,
        provenance: Provenance | None = None,
    ) -> PartingOutcome:
        """Producer -> consumer: build the stock from git, then part() it.

        ``provenance`` may be supplied by the caller (e.g. with the gate's pinned
        revset ids); otherwise it is built here from the resolved endpoints.
        """
        stock = build_stock(repo_path, base, head, cfg, runner)
        if provenance is None:
            provenance = Provenance(
                caliper_version=get_version(),
                base_sha=stock.base_sha,
                head_sha=stock.head_sha,
                rename_threshold=cfg.rename_threshold,
                config_digest=config_digest(cfg),
            )
        cutlist = part(stock.records, cfg, provenance)
        old_paths = {r.file: r.old_path for r in stock.records if r.old_path}
        return PartingOutcome(cutlist=cutlist, old_paths=old_paths)


@PARTING.register("parting")
def build_parting_plugin() -> PartingPlugin:
    """Register the parting plugin into the dedicated manual PARTING registry."""
    return PartingPlugin()
