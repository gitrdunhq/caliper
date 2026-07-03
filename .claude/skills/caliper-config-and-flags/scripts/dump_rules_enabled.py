#!/usr/bin/env python3
"""Dump the live OPA `rules_enabled` + `config` defaults from the single
source of truth (`caliper.core.opa_input`), not from a hand-copied table.

Run this whenever policies/policy.rego grows/removes a rule, or whenever
`core/opa_input.py::_DEFAULT_RULES_ENABLED` / `_DEFAULT_CONFIG` changes.

Usage (from repo root):
    uv run python .claude/skills/caliper-config-and-flags/scripts/dump_rules_enabled.py
"""

from __future__ import annotations

import sys

from caliper.core.opa_input import _DEFAULT_CONFIG, _DEFAULT_RULES_ENABLED


def main() -> int:
    print("rules_enabled defaults (core/opa_input.py::_DEFAULT_RULES_ENABLED):")
    for name, enabled in _DEFAULT_RULES_ENABLED.items():
        print(f"  {name:<28} {'ON ' if enabled else 'off'} (default)")
    print()
    print("other config defaults (core/opa_input.py::_DEFAULT_CONFIG):")
    for key, value in _DEFAULT_CONFIG.items():
        if key == "rules_enabled":
            continue
        print(f"  {key:<28} {value!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
