#!/usr/bin/env python3
"""Prove the scan-cache key's invariants (ADR-010) by construction, not by reading the ADR.

Demonstrates:
  1. Same (tree_sha, scanner, tool_version, config_digest) -> same key (determinism).
  2. Changing ANY one component changes the key (no silent collisions).
  3. settings_digest() only reacts to scan-relevant CaliperSettings fields --
     an LLM/publisher-only field change must NOT change the digest, or every
     unrelated config edit would invalidate the whole scan cache.

Usage (from repo root):
    uv run python .claude/skills/caliper-proof-and-analysis-toolkit/scripts/prove_scan_cache_key.py
"""

from __future__ import annotations

from caliper.core.config import CaliperSettings
from caliper.core.scan_cache_key import compute_cache_key, settings_digest

if __name__ == "__main__":
    k1 = compute_cache_key("treeA", "osv-scanner", "0.9.0", "cfgdigest1")
    k2 = compute_cache_key("treeA", "osv-scanner", "0.9.0", "cfgdigest1")
    print(f"same inputs twice        : {k1 == k2}  ({k1[:12]}...)")

    k_diff_tree = compute_cache_key("treeB", "osv-scanner", "0.9.0", "cfgdigest1")
    k_diff_scanner = compute_cache_key("treeA", "trivy", "0.9.0", "cfgdigest1")
    k_diff_version = compute_cache_key("treeA", "osv-scanner", "0.9.1", "cfgdigest1")
    k_diff_config = compute_cache_key("treeA", "osv-scanner", "0.9.0", "cfgdigest2")
    print(f"tree_sha changed          : {k1 != k_diff_tree}")
    print(f"scanner_name changed      : {k1 != k_diff_scanner}")
    print(f"tool_version changed      : {k1 != k_diff_version}")
    print(f"config_digest changed     : {k1 != k_diff_config}")

    base = CaliperSettings()
    scan_relevant_changed = CaliperSettings(scanner_timeout=999)
    scan_irrelevant_changed = CaliperSettings(opa_timeout=999)
    print()
    print(f"base digest               : {settings_digest(base)[:12]}...")
    print(
        "scanner_timeout=999 -> digest changes : "
        f"{settings_digest(scan_relevant_changed) != settings_digest(base)}"
    )
    print(
        "opa_timeout=999 (irrelevant) -> same  : "
        f"{settings_digest(scan_irrelevant_changed) == settings_digest(base)}"
    )
