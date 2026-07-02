"""Deterministic source-inspection guard for Parquet append efficiency (Issue #256).

Bug: append_decisions() reads the entire existing Parquet file before writing,
     performing an O(n) full-file rewrite every time any new decision is appended.

Evidence:
  - parquet_writer.py line 135: `existing = pq.read_table(parquet_path, schema=schema)`
  - parquet_writer.py line 136: `combined = pa.concat_tables([existing, new_table])`
  - parquet_writer.py line 140: `pq.write_table(combined, parquet_path)`

Fix: Use partitioned Parquet writes (one file per run), DuckDB COPY INTO APPEND,
     or a different file-per-run strategy so that appending new decisions never
     requires reading the accumulated history.

Parent bug: #222 / Epic: #146.
Status: fixed — append_decisions() now writes one part-file per append and
never reads/rewrites prior history; read_decisions() is the new SSOT read path.
"""

from __future__ import annotations

import inspect


def _get_append_decisions_source() -> str:
    from caliper.data.parquet_writer import append_decisions

    src = inspect.getsource(append_decisions)
    assert len(src) > 50, (
        "inspect.getsource returned a suspiciously short string — "
        "append_decisions may have been renamed or moved"
    )
    return src


def test_256_append_decisions_does_not_call_read_table() -> None:
    """append_decisions() must not call pq.read_table() during an append.

    Every call to read_table reads the full accumulated audit log from disk.
    As the log grows, each append becomes progressively slower — O(n) in the
    number of previously stored decisions.  True append semantics require
    writing only the new rows.

    When the bug is fixed, read_table will no longer appear in the source of
    append_decisions() and this test will go green.
    """
    src = _get_append_decisions_source()
    assert "read_table" not in src, (
        "BUG #256: append_decisions() calls pq.read_table(), which reads the "
        "entire audit log before rewriting it.  This is O(n) with audit log size. "
        "Eliminate the read_table call by using partitioned writes (one file per "
        "run_id), DuckDB COPY INTO APPEND, or an equivalent true-append strategy."
    )


def test_256_append_decisions_does_not_concat_tables() -> None:
    """append_decisions() must not concat_tables() to merge old and new data.

    pa.concat_tables([existing, new_table]) loads the entire history into memory
    to produce a single combined table.  This is the in-memory manifestation of
    the same rewrite bug detected by the read_table check above.
    """
    src = _get_append_decisions_source()
    assert "concat_tables" not in src, (
        "BUG #256: append_decisions() calls pa.concat_tables(), combining the "
        "full existing log with new rows in memory.  This defeats any attempt at "
        "efficient append.  Remove the concat_tables call as part of switching to "
        "a partitioned-write or true-append strategy."
    )
