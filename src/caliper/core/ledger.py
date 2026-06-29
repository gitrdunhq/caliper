"""The claims ledger — append-only store of advisory/dropped claims over time.

# tested-by: tests/unit/test_gauge_ledger.py

``caliper inspect`` appends every advisory and dropped claim here, each with a
content reference (repo, sha, content hash) so the triggering code can be located
later. This is **advisory data, not the decision audit lake**: a separate store
that never gates anything. The flywheel reads it to find recurring patterns.

Stored as JSONL (one entry per line) so appends are cheap and the file is
human-greppable.
"""

from __future__ import annotations

from pathlib import Path

import orjson

from caliper.core.models import LedgerEntry


def append(ledger_path: Path, entries: list[LedgerEntry]) -> None:
    """Append *entries* to the ledger (append-only; never rewrites prior entries)."""
    if not entries:
        return
    path = Path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as f:
        for e in entries:
            f.write(orjson.dumps(e.model_dump(mode="json")))
            f.write(b"\n")


def load(ledger_path: Path) -> list[LedgerEntry]:
    """Load all ledger entries (empty list when the ledger does not yet exist)."""
    path = Path(ledger_path)
    if not path.exists():
        return []
    out: list[LedgerEntry] = []
    for line in path.read_bytes().splitlines():
        if line.strip():
            out.append(LedgerEntry.model_validate_json(line))
    return out
