"""Parquet evidence writer — append-only columnar audit log.
# tested-by: tests/unit/test_parquet_writer.py

Writes review decisions to a partitioned, append-only Parquet *dataset*
(a directory of part-files) per evidence root. Enables DuckDB-powered
analytics and LLM-queryable audit history without loading individual
JSON files.

Each ``append_decisions()`` call writes exactly one new part-file and
never reads or rewrites prior part-files — true O(1)-in-existing-size
append semantics (issue #256 / #222). ``read_decisions()`` is the single
SSOT read path: it unions every part-file at read time and is the only
place that should ever call ``pq.read_table`` against this dataset.

Schema is flat + nested: top-level columns for fast filtering,
list columns for findings and scan results.
"""

from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import structlog

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    pa = None  # type: ignore[assignment]
    pq = None  # type: ignore[assignment]

from caliper.core.models import ReviewDecision

logger = structlog.get_logger(__name__)

# Directory name for the append-only decision dataset. Historically this
# named a single monolithic file; it is now a directory of part-files so
# that append never has to read (and rewrite) prior history.
PARQUET_FILENAME = "decisions.parquet"

_PART_PREFIX = "part-"
_PART_SUFFIX = ".parquet"


def _build_schema() -> pa.Schema:
    if pa is None:
        raise ImportError(
            "pyarrow is required for parquet support. Install with: pip install caliper[parquet]"
        )
    return pa.schema(
        [
            ("decision_id", pa.string()),
            ("commit_sha", pa.string()),
            ("run_id", pa.string()),
            ("timestamp", pa.timestamp("us", tz="UTC")),
            ("package_name", pa.string()),
            ("package_version", pa.string()),
            ("ecosystem", pa.string()),
            ("team", pa.string()),
            ("scope", pa.string()),
            ("pr_url", pa.string()),
            ("request_type", pa.string()),
            ("operating_mode", pa.string()),
            ("decision", pa.string()),
            ("vuln_critical", pa.int32()),
            ("vuln_high", pa.int32()),
            ("vuln_medium", pa.int32()),
            ("vuln_low", pa.int32()),
            ("vuln_info", pa.int32()),
            ("finding_count", pa.int32()),
            ("triggered_rules", pa.list_(pa.string())),
            ("constraints", pa.list_(pa.string())),
            ("policy_version", pa.string()),
            ("pipeline_duration_seconds", pa.float64()),
            ("scanner_names", pa.list_(pa.string())),
            ("scanner_statuses", pa.list_(pa.string())),
            ("advisory_ids", pa.list_(pa.string())),
            ("memo_text", pa.string()),
        ]
    )


def decision_to_row(decision: ReviewDecision, run_id: str = "") -> dict:
    """Flatten an ReviewDecision into a parquet-ready dict."""
    req = decision.request
    pol = decision.policy_evaluation

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    advisory_ids: list[str] = []
    for f in decision.findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
        if f.advisory_id:
            advisory_ids.append(f.advisory_id)

    return {
        "decision_id": str(decision.decision_id),
        "commit_sha": req.commit_sha or "",
        "run_id": run_id,
        "timestamp": decision.created_at,
        "package_name": req.package_name,
        "package_version": req.target_version,
        "ecosystem": req.ecosystem,
        "team": req.team,
        "scope": req.scope,
        "pr_url": req.pr_url or "",
        "request_type": req.request_type.value,
        "operating_mode": req.operating_mode.value,
        "decision": decision.decision.value,
        "vuln_critical": severity_counts["critical"],
        "vuln_high": severity_counts["high"],
        "vuln_medium": severity_counts["medium"],
        "vuln_low": severity_counts["low"],
        "vuln_info": severity_counts["info"],
        "finding_count": len(decision.findings),
        "triggered_rules": list(pol.triggered_rules),
        "constraints": list(pol.constraints),
        "policy_version": pol.policy_bundle_version,
        "pipeline_duration_seconds": decision.pipeline_duration_seconds,
        "scanner_names": [sr.tool_name for sr in decision.scan_results],
        "scanner_statuses": [sr.status.value for sr in decision.scan_results],
        "advisory_ids": advisory_ids,
        "memo_text": decision.memo_text or "",
    }


def _part_filename() -> str:
    """A sortable, collision-free part-file name for one append batch."""
    return f"{_PART_PREFIX}{time.time_ns():020d}-{uuid4().hex[:8]}{_PART_SUFFIX}"


def append_decisions(
    evidence_root: Path,
    decisions: list[ReviewDecision],
    run_id: str = "",
) -> Path | None:
    """Append decisions as a new part-file in the decisions dataset directory.

    True append semantics: this never reads, loads, or rewrites any
    previously written part-file — cost is O(len(decisions)), independent
    of how much history already exists (Boundedness property, #256/#222).

    Returns the dataset directory path on success, None on failure.
    """
    if not decisions:
        return None

    parts_dir = evidence_root / PARQUET_FILENAME

    try:
        parts_dir.mkdir(parents=True, exist_ok=True)

        schema = _build_schema()
        rows = [decision_to_row(d, run_id) for d in decisions]
        new_table = pa.Table.from_pylist(rows, schema=schema)

        part_path = parts_dir / _part_filename()
        pq.write_table(new_table, part_path)

        logger.info(
            "parquet_written",
            path=str(part_path),
            new_rows=len(rows),
        )
        return parts_dir

    except Exception:
        logger.error("parquet_write_failed", exc_info=True)
        return None


def read_decisions(evidence_root: Path) -> pa.Table | None:
    """Read the full decision audit log for an evidence root.

    The single SSOT read path for the append-only decisions dataset —
    unions every part-file written by ``append_decisions()``. This is the
    only place callers should read the dataset from; never call
    ``pq.read_table`` on individual part-files or the dataset directory
    directly.

    Fails open: returns None if pyarrow is unavailable, nothing has been
    appended yet, or any part-file is unreadable/corrupt.
    """
    if pq is None:
        return None

    parts_dir = evidence_root / PARQUET_FILENAME
    if not parts_dir.is_dir():
        return None

    part_files = sorted(parts_dir.glob(f"{_PART_PREFIX}*{_PART_SUFFIX}"))
    if not part_files:
        return None

    try:
        tables = [pq.read_table(p) for p in part_files]
        return pa.concat_tables(tables)
    except Exception:
        logger.error("parquet_read_failed", path=str(parts_dir), exc_info=True)
        return None
