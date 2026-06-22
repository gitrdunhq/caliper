"""Composition tier — the presentation-side wiring layer.

This package legally imports ``data`` / ``adapters`` / ``plugins`` to build the
core ``ApplicationContext``.  It is the one place where concrete adapters are
selected and wired; everything else depends on ports.
"""

from __future__ import annotations

from caliper.composition.bootstrap import (
    ApplicationContext,
    bootstrap,
    bootstrap_review,
    bootstrap_test,
)

__all__ = ["ApplicationContext", "bootstrap", "bootstrap_review", "bootstrap_test"]
