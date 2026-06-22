"""Deterministic source-inspection guard for hardcoded ecosystem (Issue #252).

Bug: ReviewPipeline.evaluate() hardcodes ecosystem="pypi" when creating dependency
     change requests.  This means non-PyPI ecosystems (npm, cargo, maven, etc.)
     are evaluated with the wrong ecosystem label, producing incorrect OPA metadata
     and PyPI API lookups against the wrong registry.

Evidence:
  - pipeline.py line 111: ecosystem="pypi" — hardcoded string literal in the
    create_requests() call inside evaluate().

Fix: derive the ecosystem from the changed file's manifest type (requirements.txt →
     pypi, package.json → npm, Cargo.toml → cargo, etc.) via DependencyDiffDetector
     or a dedicated ecosystem resolver.

Status: xfail — hardcoded value still present in pipeline.py.
"""

from __future__ import annotations

import inspect

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #252 — remove hardcoded ecosystem, then green",
    strict=False,
)


def _get_evaluate_source() -> str:
    from caliper.core.pipeline import ReviewPipeline

    src = inspect.getsource(ReviewPipeline.evaluate)
    assert len(src) > 200, (
        "inspect.getsource returned a suspiciously short string — "
        "the import or class structure may have changed"
    )
    return src


def test_252_evaluate_does_not_hardcode_ecosystem_pypi() -> None:
    """evaluate() must not hardcode ecosystem=\"pypi\".

    Using a hardcoded pypi ecosystem means all dependency reviews from evaluate()
    are tagged as pypi regardless of the actual manifest type.  This breaks OPA
    rules that branch on ecosystem and makes PyPI age checks run against non-PyPI
    packages.

    The correct approach is to detect the ecosystem from the file extension or
    manifest name (requirements.txt → pypi, package.json → npm, etc.).
    """
    src = _get_evaluate_source()
    assert 'ecosystem="pypi"' not in src, (
        'BUG #252: evaluate() contains hardcoded ecosystem="pypi". '
        "Non-PyPI packages will be labelled as pypi, producing wrong OPA "
        "metadata and misdirected registry lookups.  Derive the ecosystem "
        "from the manifest type detected by DependencyDiffDetector or an "
        "explicit ecosystem-resolver helper."
    )
