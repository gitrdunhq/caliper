"""Plugins-tier finding enrichers (detect-then-enrich, ADR-006).

Enrichers that build on heavier ``plugins`` machinery — the SQLite ``CodeGraph``
(blast radius) and, later, targeted semgrep — live here because the arch-guard
forbids ``detectors`` from importing ``plugins`` internals. They self-register into
the core-owned ``ENRICHERS`` registry on import; the composition tier triggers that
import via ``load_adapters`` (see ``eedom.composition.bootstrap``).
"""

from __future__ import annotations
