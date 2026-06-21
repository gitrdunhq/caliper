"""Detectors-tier finding enrichers (detect-then-enrich, ADR-006).

Cheap, stdlib-only enrichers that live in the ``detectors`` tier because they
build on ``detectors.ast_utils`` / the core ``enclosing_symbol`` resolver. They
self-register into the core-owned ``ENRICHERS`` registry on import; the
composition tier triggers that import via ``load_adapters`` (see
``eedom.composition.bootstrap``).
"""

from __future__ import annotations
