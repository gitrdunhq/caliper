"""Unit tests for the strict Contract value-object base.
# tested-by: tests/unit/test_contract.py

RED phase for issue #405 — these import symbols that do not exist yet and are
expected to fail with ImportError until src/eedom/_base.py is added.
"""

from __future__ import annotations

import pytest

from eedom._base import Contract


class _Sample(Contract):
    name: str
    count: int


class TestContractIsStrict:
    def test_rejects_extra_fields(self):
        with pytest.raises(Exception):
            _Sample(name="a", count=1, extra="nope")

    def test_is_frozen(self):
        sample = _Sample(name="a", count=1)
        with pytest.raises(Exception):
            sample.name = "b"

    def test_strict_rejects_coercible_wrong_type(self):
        # strict=True means an int-looking string is NOT coerced into int.
        with pytest.raises(Exception):
            _Sample(name="a", count="1")

    def test_accepts_well_typed_values(self):
        sample = _Sample(name="a", count=2)
        assert sample.name == "a"
        assert sample.count == 2


class TestContractEquality:
    def test_value_equality(self):
        assert _Sample(name="a", count=1) == _Sample(name="a", count=1)

    def test_hashable_when_frozen(self):
        # Frozen contracts are hashable, so they can live in sets / dict keys.
        s = {_Sample(name="a", count=1), _Sample(name="a", count=1)}
        assert len(s) == 1
