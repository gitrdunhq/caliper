"""Strict value-object base for boundary contracts.
# tested-by: tests/unit/test_contract.py

`Contract` is the frozen, strict, extra-forbidding Pydantic base every
cross-boundary value object should inherit from.  It mirrors the
ports-&-adapters convention used across the codebase: data that crosses a
port is an immutable, fully-typed value — never a loose dict.

Design choices (all enforced by ``model_config``):

* ``strict=True`` — no silent coercion (``"1"`` is not accepted for an ``int``
  field), so a contract validates exactly the types it declares.
* ``frozen=True`` — instances are immutable and therefore hashable, so they
  can be deduplicated in sets and used as dict keys.
* ``extra="forbid"`` — unknown fields are a hard error, catching typos and
  schema drift at the boundary instead of silently dropping data.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Contract(BaseModel):
    """Immutable, strictly-typed base for boundary value objects."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
