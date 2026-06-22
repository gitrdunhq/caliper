"""Plugins-tier finding scribes (detect-then-scribe, ADR-006).

Scribes that build on heavier ``plugins`` machinery — the SQLite ``CodeGraph``
(blast radius) and, later, targeted semgrep — live here because the arch-guard
forbids ``detectors`` from importing ``plugins`` internals. They self-register into
the core-owned ``SCRIBES`` registry on import; the composition tier triggers that
import via ``load_adapters`` (see ``caliper.composition.bootstrap``).
"""

from __future__ import annotations
