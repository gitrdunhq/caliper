# tested-by: tests/unit/test_accessors.py
"""Dependency accessors — the seam between core and its injected collaborators.

Core orchestration (the review pipeline) never constructs data-tier objects;
it pulls them from the injected ``ApplicationContext`` through these get_*
functions.  Each required accessor raises a clear ``ValueError`` when its
collaborator is missing, mirroring datum-ax's ``get_*`` orchestration helpers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from caliper.core.context import ApplicationContext
    from caliper.core.ports import (
        DecisionRepositoryPort,
        EvidenceWriterPort,
        PackageMetadataPort,
        ScannerPort,
        ScribePort,
    )

_HINT = "build the context via caliper.composition.bootstrap.bootstrap(settings)"


def _require(value, name: str):
    if value is None:
        raise ValueError(f"ApplicationContext.{name} is required for the review pipeline; {_HINT}")
    return value


def get_scanners(context: ApplicationContext) -> list[ScannerPort]:
    """Return the injected scanners. An empty list is valid (none enabled)."""
    return context.scanners


def get_scribes(context: ApplicationContext) -> list[ScribePort]:
    """Return the injected finding scribes. An empty list is valid (no scribe).

    Tolerant of contexts that predate the ``scribes`` field (or minimal duck-typed
    doubles): scribe is an optional, fail-open collaborator, so its absence means
    "no scribe", never an error.
    """
    return getattr(context, "scribes", []) or []


def get_evidence_writer(context: ApplicationContext) -> EvidenceWriterPort:
    return _require(context.evidence_writer, "evidence_writer")


def get_package_metadata(context: ApplicationContext) -> PackageMetadataPort:
    return _require(context.package_metadata, "package_metadata")


def get_decision_repository(context: ApplicationContext) -> DecisionRepositoryPort:
    return _require(context.decision_repository, "decision_repository")


def get_audit_log_appender(context: ApplicationContext) -> Callable[[Path, list, str], object]:
    return _require(context.audit_log_appender, "audit_log_appender")
