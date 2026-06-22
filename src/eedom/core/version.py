"""Canonical version source for eedom.
# tested-by: tests/unit/test_version_drift.py

Single source of truth — delegates to importlib.metadata so the version
always matches what is installed, with no risk of drift from a hardcoded
literal.
"""

from __future__ import annotations

import importlib.metadata


def get_version() -> str:
    """Return the installed eedom version from importlib.metadata.

    Fail-open: when eedom is not installed as a distribution (e.g. run straight
    from a source checkout), ``version()`` raises ``PackageNotFoundError`` — that
    must not crash importers (the renderer imports this at module load).
    """
    try:
        return importlib.metadata.version("eedom")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+unknown"
