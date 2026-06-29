"""Tests for the inspection cache — reproducible-in-practice LLM output.

# tested-by: tests/unit/test_inspect_cache.py
"""

from __future__ import annotations

from caliper.core.inspect_cache import InspectCache, content_key


def test_key_is_order_independent_over_file_set() -> None:
    a = content_key(["a.py", "b.py"], "prompt", "m", "v0")
    b = content_key(["b.py", "a.py"], "prompt", "m", "v0")
    assert a == b


def test_key_changes_with_prompt_model_or_version() -> None:
    base = content_key(["a.py"], "prompt", "m", "v0")
    assert content_key(["a.py"], "PROMPT-changed", "m", "v0") != base  # changed prompt
    assert content_key(["a.py"], "prompt", "m2", "v0") != base  # changed model
    assert content_key(["a.py"], "prompt", "m", "v1") != base  # changed prompt version


def test_roundtrip_and_miss(tmp_path) -> None:
    cache = InspectCache(tmp_path / "c")
    key = content_key(["a.py"], "prompt", "m", "v0")
    assert cache.get(key) is None  # miss before put
    claims = [{"file": "a.py", "line_range": [1, 2], "severity": "minor", "category": "style"}]
    cache.put(key, claims)
    assert cache.get(key) == claims  # hit returns identical payload
    assert cache.get("deadbeef") is None  # unknown key misses
