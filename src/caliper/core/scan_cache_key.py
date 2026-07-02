"""Scan cache key construction (ADR-010).
# tested-by: tests/unit/test_scan_cache_key.py

Pure functions only — no I/O. ``settings_digest`` follows the
``core.parting.config_digest`` precedent (sha256 over sorted-key JSON) but is scoped to
only the ``CaliperSettings`` fields that actually affect scanner behavior, so unrelated
config changes (LLM settings, publisher tokens, ...) never cause a spurious cache miss.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import orjson

if TYPE_CHECKING:
    from caliper.core.config import CaliperSettings

# The CaliperSettings fields that affect what a scanner does or produces. Anything
# outside this list (LLM config, publisher tokens, evidence path, ...) must not
# invalidate the scan cache.
_SCAN_RELEVANT_FIELDS = (
    "enabled_scanners",
    "osv_exclude_paths",
    "scanner_timeout",
    "combined_scanner_timeout",
    "file_source",
)


def settings_digest(config: CaliperSettings) -> str:
    """Deterministic digest of the scan-relevant subset of settings."""
    payload = {field: getattr(config, field, None) for field in _SCAN_RELEVANT_FIELDS}
    encoded = orjson.dumps(payload, option=orjson.OPT_SORT_KEYS)
    return hashlib.sha256(encoded).hexdigest()


def compute_cache_key(
    tree_sha: str, scanner_name: str, tool_version: str, config_digest: str
) -> str:
    """Deterministic cache key for one scanner's result against one tree state."""
    h = hashlib.sha256()
    for part in (tree_sha, scanner_name, tool_version, config_digest):
        h.update(part.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()
