"""Canonical version source for caliper.
# tested-by: tests/unit/test_version_drift.py

Single source of truth — delegates to importlib.metadata so the version
always matches what is installed, with no risk of drift from a hardcoded
literal.
"""

from __future__ import annotations

import importlib.metadata


def get_version() -> str:
    """Return the installed caliper version from importlib.metadata.

    Fail-open: when caliper is not installed as a distribution (e.g. run straight
    from a source checkout), ``version()`` raises ``PackageNotFoundError`` — that
    must not crash importers (the renderer imports this at module load).
    """
    try:
        # The distribution is named "caliper-review" (pyproject.toml [project]
        # name) — "caliper" is only the import package name. Querying the wrong
        # one raises PackageNotFoundError in a clean install and falls through
        # to the "+unknown" footer, which is what a real CI comment showed.
        return importlib.metadata.version("caliper-review")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+unknown"
