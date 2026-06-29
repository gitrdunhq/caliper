"""Shared errors for the gauge flywheel (``caliper gauge``).

# tested-by: tests/unit/test_gauge_promotion.py

The flywheel turns recurring advisory claims into permanent deterministic gauges.
This module holds the shared error type; the pieces live in sibling modules:
``ledger`` (the claims ledger), ``flywheel`` (deterministic clustering/ranking),
``backtest`` (the deterministic gate), and ``tool_crib`` (the promotion gate).
"""

from __future__ import annotations


class GaugeError(ValueError):
    """Raised when a flywheel invariant is violated (e.g. promoting without a gate)."""
