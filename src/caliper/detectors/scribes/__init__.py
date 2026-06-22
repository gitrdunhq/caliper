"""Detectors-tier finding scribes (detect-then-scribe, ADR-006).

Cheap, stdlib-only scribes that live in the ``detectors`` tier because they
build on ``detectors.ast_utils`` / the core ``enclosing_symbol`` resolver. They
self-register into the core-owned ``SCRIBES`` registry on import; the
composition tier triggers that import via ``load_adapters`` (see
``caliper.composition.bootstrap``).
"""

from __future__ import annotations
