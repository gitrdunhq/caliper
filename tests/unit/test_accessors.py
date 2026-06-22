"""Conformance tests for the core get_* dependency accessors (#409).
# tested-by: tests/unit/test_accessors.py

RED phase — `caliper.core.accessors` and the new ApplicationContext pipeline
fields do not exist yet. The accessors are the seam through which the review
pipeline receives its data-tier collaborators from the injected context.
"""

from __future__ import annotations

import pytest

from caliper.composition.bootstrap import bootstrap_test
from caliper.core.accessors import (
    get_audit_log_appender,
    get_decision_repository,
    get_evidence_writer,
    get_package_metadata,
    get_scanners,
)

_REQUIRED = [
    ("evidence_writer", get_evidence_writer),
    ("package_metadata", get_package_metadata),
    ("decision_repository", get_decision_repository),
    ("audit_log_appender", get_audit_log_appender),
]


class TestAccessorsRaiseWhenMissing:
    @pytest.mark.parametrize(("attr", "accessor"), _REQUIRED)
    def test_missing_dependency_raises_value_error(self, attr, accessor):
        ctx = bootstrap_test()  # all pipeline collaborators default to None
        with pytest.raises(ValueError, match=attr):
            accessor(ctx)

    def test_scanners_default_to_empty_list(self):
        # An empty scanner set is valid (enabled_scanners can be empty), so this
        # accessor returns [] rather than raising.
        ctx = bootstrap_test()
        assert get_scanners(ctx) == []


class TestAccessorsReturnInjected:
    @pytest.mark.parametrize(("attr", "accessor"), _REQUIRED)
    def test_returns_the_injected_collaborator(self, attr, accessor):
        ctx = bootstrap_test()
        sentinel = object()
        setattr(ctx, attr, sentinel)
        assert accessor(ctx) is sentinel

    def test_get_scanners_returns_injected_list(self):
        ctx = bootstrap_test()
        scanners = [object(), object()]
        ctx.scanners = scanners
        assert get_scanners(ctx) == scanners
