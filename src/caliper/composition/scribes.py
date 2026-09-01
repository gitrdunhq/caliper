"""Scribe wiring for the composition root (ADR-006 detect-then-scribe).

# tested-by: tests/unit/test_bootstrap.py

Split out of ``bootstrap.py`` (500-line ratchet). This is where concrete
transports and pinned rule sources get injected into scribes that ``plugins/``
cannot construct on its own (DPS-101).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from caliper.core.config import CaliperSettings


def build_scribes(settings: CaliperSettings) -> list:
    """Build the enabled finding scribes from the SCRIBES registry (ADR-006).

    Detect-then-scribe: these run as a sequential post-detection pass (see
    ``core.scribe_pass.scribe_findings``) attaching deterministic context to each
    finding. Unknown keys are skipped so config can name scribes a given build
    doesn't ship. The factories do no I/O — scribes build tool state lazily.

    ``supply_chain_threat`` is special-cased: it needs the shared
    ``LlmClient`` transport (data/) injected, which plugins/ cannot import
    directly (DPS-101) — this composition root is where the concrete
    transport and the plugin are wired together.
    """
    from caliper.core.port_registries import SCRIBES

    scribes: list = []
    for name in settings.enabled_scribes:
        if name not in SCRIBES:
            continue
        if name == "supply_chain_threat":
            from caliper.data.llm_client import LlmClient
            from caliper.plugins.scribes.supply_chain_threat import SupplyChainThreatScribe

            scribes.append(SupplyChainThreatScribe(LlmClient(settings)))
        elif name == "semgrep":
            # Same pinned rule sources as the semgrep plugin — never the registry.
            from caliper.plugins.semgrep import _resolve_org_rules_dir

            scribes.append(
                SCRIBES.create(
                    name,
                    rules_dir=settings.semgrep_rules_dir,
                    org_rules_dir=_resolve_org_rules_dir(settings),
                )
            )
        else:
            scribes.append(SCRIBES.create(name))
    return scribes


def build_default_scribes() -> list:
    """Build the on-by-default scribes without a full settings object (ADR-006).

    For standalone presentation paths (the Foreman agent's ``scan_code``) that run
    a single plugin outside the wired ``ApplicationContext`` but still want findings
    scribeed. Triggers ``load_adapters`` so the registry is populated, then resolves
    the ``DEFAULT_SCRIBES`` keys (semgrep stays opt-in).
    """
    from caliper.composition.bootstrap import load_adapters  # noqa: PLC0415 — avoid import cycle
    from caliper.core.config import DEFAULT_SCRIBES
    from caliper.core.port_registries import SCRIBES

    load_adapters()
    return [SCRIBES.create(k) for k in DEFAULT_SCRIBES if k in SCRIBES]
