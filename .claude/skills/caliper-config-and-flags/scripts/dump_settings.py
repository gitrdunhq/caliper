#!/usr/bin/env python3
"""Dump every CaliperSettings field, its derived CALIPER_* env var name, and
its default value — straight from the live pydantic model, not from memory.

Run this whenever you suspect the config surface has drifted from what this
skill documents (new field added/removed/renamed, default changed).

Usage (from repo root):
    uv run python .claude/skills/caliper-config-and-flags/scripts/dump_settings.py
"""

from __future__ import annotations

import sys

from caliper.core.config import CaliperSettings


def main() -> int:
    fields = CaliperSettings.model_fields
    print(f"{'field':<38} {'env var':<42} {'default'}")
    print("-" * 100)
    for name, info in sorted(fields.items()):
        env_var = f"CALIPER_{name.upper()}"
        default = info.default
        # SecretStr and similar reprs are noisy; keep it short.
        default_repr = repr(default)
        if len(default_repr) > 40:
            default_repr = default_repr[:37] + "..."
        print(f"{name:<38} {env_var:<42} {default_repr}")
    print(f"\ntotal fields: {len(fields)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
