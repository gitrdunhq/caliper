"""Conformance tests for the SCRIBES registry (detect-then-scribe, ADR-006).
# tested-by: tests/unit/test_scribe_registry.py

Mirrors ``test_port_registries``: the composition tier's ``load_adapters`` triggers
the cross-tier self-registration, then every registered scribe must resolve to an
``ScribePort``-satisfying instance and unknown keys must raise.
"""

from __future__ import annotations

import pytest

from caliper.composition.bootstrap import load_adapters
from caliper.core.ports import ScribePort
from caliper.core.registries import SCRIBES

load_adapters()

_EXPECTED = {"enclosing_symbol", "code_graph", "semgrep", "supply_chain_threat"}


def test_expected_scribes_registered() -> None:
    assert set(SCRIBES.keys()) >= _EXPECTED


@pytest.mark.parametrize("key", sorted(_EXPECTED))
def test_scribe_satisfies_port(key: str) -> None:
    instance = SCRIBES.create(key)
    assert isinstance(instance, ScribePort)
    assert instance.name == key


def test_unknown_scribe_raises() -> None:
    with pytest.raises(KeyError):
        SCRIBES.create("does-not-exist")
