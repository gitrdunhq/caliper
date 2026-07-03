#!/usr/bin/env python3
"""Print the live plugin + scribe registrations, straight from the running registries.

Run from repo root:

    uv run python .claude/skills/caliper-plugin-architecture/scripts/list_plugins_and_scribes.py

No arguments. Exits non-zero if either registry is unexpectedly empty (a signal
that autodiscovery broke), so it doubles as a cheap smoke check.
"""

from __future__ import annotations

import sys


def main() -> int:
    from caliper.composition.bootstrap import load_adapters
    from caliper.core.port_registries import SCRIBES
    from caliper.plugins import get_default_registry

    # Scribes self-register via composition.load_adapters(), same as every
    # other core-owned registry (ADR-006) — call it first or SCRIBES.keys()
    # is empty.
    load_adapters()

    registry = get_default_registry()
    plugins = sorted(registry.list(), key=lambda p: p.name)

    print(f"=== {len(plugins)} scanner plugins (PluginRegistry) ===")
    for p in plugins:
        deps = ",".join(p.depends_on) or "-"
        print(f"  {p.name:<16} category={p.category.value:<14} depends_on={deps}")

    scribe_keys = SCRIBES.keys()
    print(f"\n=== {len(scribe_keys)} registered scribes (SCRIBES registry) ===")
    for key in scribe_keys:
        print(f"  {key}")

    opa_in_registry = registry.get("opa") is not None
    print(f"\n'opa' present in default scanner registry: {opa_in_registry}")
    print("(expected False — OpaPlugin in plugins/_opa.py is excluded from")
    print(" autodiscovery on purpose; live policy enforcement runs through")
    print(" POLICY_ENGINES / PolicyEnginePort, called directly from core/pipeline.py,")
    print(" not through PluginRegistry.)")

    if not plugins or not scribe_keys:
        print("\nFAIL: an expected registry came back empty.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
