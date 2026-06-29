"""Inspection cache — reproducible-in-practice LLM output, keyed on part content.

# tested-by: tests/unit/test_inspect_cache.py

LLM output is cached keyed on a hash of the part's content (file set + changed-line
bytes) plus the model id and prompt version. The same key returns the cached claims
without calling the port; a changed part misses. This does not claim the model is
deterministic — it claims the cache is, so a part inspects identically until it
changes.

The cache lives OUTSIDE the decision audit lake (it is advisory review output, not
a sealed verdict). It is a plain JSON-per-key directory.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import orjson


def content_key(files: list[str], changed_bytes: bytes, model_id: str, prompt_version: str) -> str:
    """Deterministic cache key for a part's review.

    ``files`` is the part's file set, ``changed_bytes`` the concatenated bytes of its
    changed lines (the producer's view). Sorting the file set makes the key order-
    independent. The model id and prompt version are included so a model/prompt swap
    correctly misses.
    """
    h = hashlib.sha256()
    for f in sorted(files):
        h.update(f.encode("utf-8"))
        h.update(b"\0")
    h.update(b"\x01")
    h.update(changed_bytes)
    h.update(b"\x01")
    h.update(model_id.encode("utf-8"))
    h.update(b"\0")
    h.update(prompt_version.encode("utf-8"))
    return h.hexdigest()


class InspectCache:
    """A JSON-per-key cache of raw LLM claims, stored under a directory."""

    def __init__(self, cache_dir: Path) -> None:
        self.dir = Path(cache_dir)

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def get(self, key: str) -> list[dict] | None:
        """Return cached raw claims for *key*, or ``None`` on a miss."""
        path = self._path(key)
        if not path.exists():
            return None
        try:
            return orjson.loads(path.read_bytes())
        except (orjson.JSONDecodeError, OSError):
            return None  # a corrupt cache entry is a miss, never a crash

    def put(self, key: str, raw_claims: list[dict]) -> None:
        """Store raw claims for *key* (outside the audit lake)."""
        self.dir.mkdir(parents=True, exist_ok=True)
        self._path(key).write_bytes(orjson.dumps(raw_claims, option=orjson.OPT_INDENT_2))
