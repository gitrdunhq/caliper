"""Conformance tests for the ENRICHERS registry (detect-then-enrich, ADR-006).
# tested-by: tests/unit/test_enricher_registry.py

Mirrors ``test_port_registries``: the composition tier's ``load_adapters`` triggers
the cross-tier self-registration, then every registered enricher must resolve to an
``EnricherPort``-satisfying instance and unknown keys must raise.
"""

from __future__ import annotations

import pytest

from eedom.composition.bootstrap import load_adapters
from eedom.core.ports import EnricherPort
from eedom.core.registries import ENRICHERS

load_adapters()

_EXPECTED = {"enclosing_symbol", "code_graph"}


def test_expected_enrichers_registered() -> None:
    assert set(ENRICHERS.keys()) >= _EXPECTED


@pytest.mark.parametrize("key", sorted(_EXPECTED))
def test_enricher_satisfies_port(key: str) -> None:
    instance = ENRICHERS.create(key)
    assert isinstance(instance, EnricherPort)
    assert instance.name == key


def test_unknown_enricher_raises() -> None:
    with pytest.raises(KeyError):
        ENRICHERS.create("does-not-exist")
