"""Finding baseline / suppression with expiry.

# tested-by: tests/unit/test_baseline.py

Lets a repo gate on *new* findings only: an existing finding can be suppressed
by adding it to a baseline file with a reason and an expiry date. Suppression
is deterministic (a sha256 fingerprint over stable finding fields, no LLM) and
fails safe — an expired baseline entry stops suppressing rather than silently
dropping the finding forever.

Fingerprint deliberately excludes ``line_number`` so line drift (an unrelated
edit shifting a finding a few lines) doesn't invalidate a suppression.
"""

from __future__ import annotations

import hashlib
from datetime import date, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, Field

from caliper.core.models import Finding

logger = structlog.get_logger()

_BASELINE_FILENAME = ".caliper-baseline.yaml"
_FIELD_SEP = "\x1f"  # ASCII unit separator — won't collide with real field content


def _normalize_path(file_path: str | None) -> str:
    """Normalize a file path for fingerprinting: no leading ./, forward slashes."""
    if not file_path:
        return ""
    return PurePosixPath(file_path.replace("\\", "/")).as_posix()


def finding_fingerprint(finding: Finding) -> str:
    """Deterministic sha256 fingerprint for a finding, stable across line drift.

    Modeled on the normalizer's dedup key (source_tool, category, package_name,
    version, advisory_id-or-description) plus the finding's normalized file
    path — but never its line number.
    """
    key = (
        finding.source_tool,
        finding.category.value,
        finding.package_name,
        finding.version,
        finding.advisory_id or finding.description,
        _normalize_path(finding.file_path),
    )
    payload = _FIELD_SEP.join(key)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class BaselineEntry(BaseModel):
    """One suppressed finding: why, and until when."""

    fingerprint: str
    reason: str
    added: date
    expires: date


class Baseline(BaseModel):
    """A repo's full set of suppressed findings."""

    entries: list[BaselineEntry] = Field(default_factory=list)


def filter_findings(
    findings: list[Finding], baseline: Baseline, today: date
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Partition findings by baseline suppression.

    Returns ``(kept, suppressed, expired)``. A finding whose baseline entry has
    expired (``entry.expires < today``) fails **safe**: it is returned in both
    ``kept`` and ``expired`` — never silently dropped. Duplicate fingerprints in
    the baseline resolve first-entry-wins.
    """
    by_fingerprint: dict[str, BaselineEntry] = {}
    for entry in baseline.entries:
        by_fingerprint.setdefault(entry.fingerprint, entry)

    kept: list[Finding] = []
    suppressed: list[Finding] = []
    expired: list[Finding] = []

    for finding in findings:
        entry = by_fingerprint.get(finding_fingerprint(finding))
        if entry is None:
            kept.append(finding)
        elif entry.expires < today:
            expired.append(finding)
            kept.append(finding)
        else:
            suppressed.append(finding)

    return kept, suppressed, expired


def load_baseline(path: Path) -> Baseline:
    """Load a baseline file. Returns an empty Baseline when absent (fail-open)."""
    if not path.exists():
        return Baseline()

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("baseline.read_failed", path=str(path), error=str(exc))
        return Baseline()

    try:
        data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        logger.warning("baseline.invalid_yaml", path=str(path), error=str(exc))
        return Baseline()

    if data is None:
        return Baseline()

    try:
        return Baseline.model_validate(data)
    except Exception as exc:
        logger.warning("baseline.invalid_schema", path=str(path), error=str(exc))
        return Baseline()


def save_baseline(path: Path, baseline: Baseline) -> None:
    """Write a baseline file, sorted by fingerprint for a stable diff."""
    entries = sorted(baseline.entries, key=lambda e: e.fingerprint)
    payload = {
        "entries": [
            {
                "fingerprint": e.fingerprint,
                "reason": e.reason,
                "added": e.added.isoformat(),
                "expires": e.expires.isoformat(),
            }
            for e in entries
        ]
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def merge_new_entries(
    baseline: Baseline,
    findings: list[Finding],
    reason: str,
    today: date,
    ttl_days: int,
) -> Baseline:
    """Return a new Baseline with an entry added for every finding not already covered.

    Existing entries (matched by fingerprint) are preserved untouched — re-running
    this against an unchanged finding set is a no-op (idempotent).
    """

    existing_fingerprints = {e.fingerprint for e in baseline.entries}
    expires = today + timedelta(days=ttl_days)

    new_entries = list(baseline.entries)
    seen_this_run: set[str] = set()
    for finding in findings:
        fingerprint = finding_fingerprint(finding)
        if fingerprint in existing_fingerprints or fingerprint in seen_this_run:
            continue
        seen_this_run.add(fingerprint)
        new_entries.append(
            BaselineEntry(fingerprint=fingerprint, reason=reason, added=today, expires=expires)
        )

    return Baseline(entries=new_entries)
