"""Enrichment value object + the canonical enclosing-symbol resolver (ADR-006).
# tested-by: tests/unit/test_enrichment.py

Detect-then-enrich: after a plugin detects a finding, eedom attaches deterministic
context (enclosing symbol, code-graph blast radius, related matches) so a downstream
consumer reasons with minimal effort. This module owns the cross-tier-safe pieces —
the ``Enrichment`` value object, the ``EnrichmentContext``, and the single
``enclosing_symbol`` resolver that both the cpd runner (``plugins``) and the
``EnclosingSymbolEnricher`` (``detectors``) reuse (one source of truth).

Everything here is pure (stdlib ``ast``/``re``) and deterministic; enrichers built on
top must stay zero-LLM, fail-open, and time-bounded (the gate never depends on them).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from eedom._base import Contract

# Best-effort "what declares a symbol" matcher for non-Python languages: keyword + name.
_SYMBOL_RE = re.compile(
    r"^\s*(?:export\s+|public\s+|private\s+|protected\s+|static\s+|final\s+|async\s+|pub\s+)*"
    r"(def|function|func|fn|class|interface|struct|impl|trait|enum|object|module|sub|method)\b"
    r"[\s:<]*([A-Za-z_][A-Za-z0-9_]*)"
)
_CLASS_LIKE = {"class", "interface", "struct", "enum", "trait", "object"}


def _python_symbol(source: str, line: int) -> tuple[str, str]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return ("", "")
    best_name, best_kind, best_line = "", "", -1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "function"
        elif isinstance(node, ast.ClassDef):
            kind = "class"
        else:
            continue
        end = getattr(node, "end_lineno", None) or node.lineno
        if node.lineno <= line <= end and node.lineno > best_line:
            best_name, best_kind, best_line = node.name, kind, node.lineno
    return (best_name, best_kind)


def _generic_symbol(lines: list[str], line: int) -> tuple[str, str]:
    for i in range(min(line, len(lines)) - 1, -1, -1):
        match = _SYMBOL_RE.match(lines[i])
        if match:
            keyword = match.group(1)
            kind = "class" if keyword in _CLASS_LIKE else "function"
            return (match.group(2), kind)
    return ("", "")


def enclosing_symbol(text: str, line: int, *, is_python: bool) -> tuple[str, str]:
    """Return ``(name, kind)`` of the innermost symbol enclosing *line* (best-effort).

    Python uses the AST and is authoritative (an empty result means module-level, not
    "scan upward"); other languages use a nearest-preceding-declaration heuristic.
    """
    if is_python:
        return _python_symbol(text, line)
    return _generic_symbol(text.splitlines(), line)


class Enrichment(Contract):
    """Deterministic context attached to a finding (serialized into ``metadata['enrichment']``)."""

    enclosing_symbol: str = ""
    enclosing_kind: str = ""
    blast_radius: tuple[dict, ...] = ()
    related: tuple[dict, ...] = ()
    suggested_home: str = ""
    sources: tuple[str, ...] = ()


@dataclass
class EnrichmentContext:
    """Inputs the enrichment pass hands to each enricher (core types only)."""

    repo_path: str
    enrichment_timeout: float = 30.0
