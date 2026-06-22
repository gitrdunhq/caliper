# tested-by: tests/unit/test_grounding.py
"""Grounding provider adapters — gated, on-demand code-grounding sources.

These adapters implement :class:`GroundingProviderPort` and self-register into
the core-owned ``GROUNDING_PROVIDERS`` registry on import. The composition tier
triggers that import via ``load_adapters`` (autodiscover cannot cross tiers).

Four providers, each fail-open (every method returns ``[]`` on any error):

* ``NullGroundingProvider`` ("null") — the disabled/unavailable default.
* ``CodeGraphGroundingProvider`` ("codegraph") — reuses caliper's SQLite
  ``CodeGraph`` (the same one the blast-radius plugin builds).
* ``CtagsGroundingProvider`` ("ctags") — universal-ctags JSON, falling back to
  ripgrep generic def patterns; mirrors the adversarial-review ground.py logic.
* ``GitnexusGroundingProvider`` ("gitnexus") — best-effort, decoupled: parses a
  generic JSON graph export when a path is supplied; unavailable otherwise.

A "fact sheet" dict is ``{"name","kind","file","line","signature"}``; a
"neighbor" dict is ``{"name","file","line","relation"}``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import structlog

from caliper.core.registries import GROUNDING_PROVIDERS

logger = structlog.get_logger(__name__)

# Kinds that represent a "contract" worth attaching as type context. Mirrors the
# adversarial-review ground.py TYPE_KINDS set.
_TYPE_KINDS = {
    "class",
    "struct",
    "interface",
    "enum",
    "enumerator",
    "enumconstant",
    "typedef",
    "type",
    "trait",
    "record",
    "protocol",
    "union",
    "member",
    "constant",
    "const",
    "macro",
    "namespace",
    "module",
    "annotation",
    "field",
    "property",
    "variable",
    "alias",
    "object",
    "schema",
}

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Generic, multi-language definition patterns for the ripgrep fallback.
_RG_DEF = (
    r"^\s*(?:export\s+|public\s+|pub\s+|private\s+|final\s+|abstract\s+|static\s+)*"
    r"(?:class|struct|interface|enum|trait|protocol|record|type|typedef|"
    r"def|func|function|fn|module|namespace|const|let|var|val)\b"
    r"[\s:]+([A-Za-z_][A-Za-z0-9_]*)"
)

_DEFAULT_MAX_SYMBOLS = 40


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _norm(root: Path, p: str) -> str:
    """Return the repo-relative, forward-slash form of *p*."""
    pp = p.replace("\\", "/")
    try:
        path = Path(pp)
        if path.is_absolute():
            return str(path.resolve().relative_to(Path(root).resolve())).replace("\\", "/")
        return pp
    except Exception:
        return pp


def _identifiers_in(root: Path, files: list[str]) -> set[str]:
    """Collect every identifier token referenced by *files* (fail-open)."""
    idents: set[str] = set()
    for f in files:
        fp = Path(f) if Path(f).is_absolute() else Path(root) / f
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        idents.update(_IDENT_RE.findall(text))
    return idents


# ---------------------------------------------------------------------------
# Null provider
# ---------------------------------------------------------------------------
@GROUNDING_PROVIDERS.register("null")
class NullGroundingProvider:
    """No-op grounding provider — the disabled/unavailable default."""

    name = "null"

    def fact_sheet(self, root: Path, files: list[str]) -> list[dict]:
        return []

    def type_context(self, root: Path, files: list[str]) -> list[dict]:
        return []

    def neighbors(self, root: Path, symbol: str) -> list[dict]:
        return []

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# CodeGraph provider
# ---------------------------------------------------------------------------
@GROUNDING_PROVIDERS.register("codegraph")
class CodeGraphGroundingProvider:
    """Serve grounding from caliper's SQLite ``CodeGraph``.

    Builds/indexes the graph once (when empty) and caches it on the instance.
    Fully fail-open: a missing/unbuildable graph yields ``[]`` everywhere.
    """

    name = "codegraph"

    def __init__(
        self,
        max_symbols: int = _DEFAULT_MAX_SYMBOLS,
        graph_factory: Callable[[Path], object | None] | None = None,
    ) -> None:
        """Construct the provider.

        *graph_factory* is an injected ``(root) -> built+indexed graph | None``
        callable. ``CodeGraph`` lives in the ``plugins`` tier, which ``adapters``
        may NOT import (enforced architecture guard), so the composition root
        supplies the factory (see ``build_default_codegraph_factory``). When the
        factory is ``None`` the provider behaves as unavailable (all ``[]``),
        keeping this module within its tier.
        """
        self._max_symbols = max_symbols
        self._graph_factory = graph_factory
        self._graph = None
        self._graph_root: str | None = None

    def _resolve_graph(self, root: Path):
        """Build (once) or reuse the cached code graph for *root* (fail-open)."""
        if self._graph_factory is None:
            return None
        key = str(Path(root).resolve())
        if self._graph is not None and self._graph_root == key:
            return self._graph
        try:
            graph = self._graph_factory(Path(root))
            if graph is None:
                return None
            self._graph = graph
            self._graph_root = key
        except Exception:
            logger.debug("grounding.codegraph.build_failed", root=str(root))
            return None
        return self._graph

    def fact_sheet(self, root: Path, files: list[str]) -> list[dict]:
        graph = self._resolve_graph(root)
        if graph is None:
            return []
        try:
            wanted = {_norm(root, f) for f in files}
            rows = graph.conn.execute(
                "SELECT name, kind, file, line FROM symbols ORDER BY file, line"
            ).fetchall()
            out: list[dict] = []
            for row in rows:
                if row["file"] in wanted:
                    out.append(
                        {
                            "name": row["name"],
                            "kind": row["kind"],
                            "file": row["file"],
                            "line": row["line"],
                            "signature": "",
                        }
                    )
            out.sort(key=lambda d: (d["file"], d["line"], d["name"]))
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.codegraph.fact_sheet_failed", root=str(root))
            return []

    def type_context(self, root: Path, files: list[str]) -> list[dict]:
        graph = self._resolve_graph(root)
        if graph is None:
            return []
        try:
            wanted = {_norm(root, f) for f in files}
            refs = _identifiers_in(root, files)
            if not refs:
                return []
            rows = graph.conn.execute(
                "SELECT name, kind, file, line FROM symbols ORDER BY name, file, line"
            ).fetchall()
            out: list[dict] = []
            seen: set[tuple] = set()
            for row in rows:
                if (row["kind"] or "").lower() not in _TYPE_KINDS:
                    continue
                if row["name"] not in refs:
                    continue
                if row["file"] in wanted:
                    continue  # defined inside the partition — already in fact sheet
                key = (row["name"], row["file"], row["line"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(
                    {
                        "name": row["name"],
                        "kind": row["kind"],
                        "file": row["file"],
                        "line": row["line"],
                        "signature": "",
                    }
                )
            out.sort(key=lambda d: (d["name"], d["file"], d["line"]))
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.codegraph.type_context_failed", root=str(root))
            return []

    def neighbors(self, root: Path, symbol: str) -> list[dict]:
        graph = self._resolve_graph(root)
        if graph is None:
            return []
        try:
            callers = graph.blast_radius(symbol)
            out = [
                {
                    "name": c.get("name", ""),
                    "file": c.get("file", ""),
                    "line": c.get("line", 0),
                    "relation": c.get("edge", "caller"),
                }
                for c in callers
            ]
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.codegraph.neighbors_failed", root=str(root))
            return []

    def close(self) -> None:
        try:
            if self._graph is not None:
                self._graph.conn.close()
        except Exception:
            logger.debug("grounding.codegraph.close_failed")
        finally:
            self._graph = None
            self._graph_root = None


# ---------------------------------------------------------------------------
# Ctags provider
# ---------------------------------------------------------------------------
@GROUNDING_PROVIDERS.register("ctags")
class CtagsGroundingProvider:
    """Serve grounding via universal-ctags, falling back to ripgrep heuristics.

    Ports the symbol-extraction logic from the adversarial-review ground.py:
    universal-ctags JSON when ``ctags`` is on PATH, else generic ripgrep def
    patterns, else a pure-Python regex fallback applying the same definition
    pattern so grounding still works when no external tool is installed.
    ``neighbors`` is not derivable from a flat tag index, so it returns ``[]``.
    Fully fail-open.
    """

    name = "ctags"

    def __init__(self, max_symbols: int = _DEFAULT_MAX_SYMBOLS) -> None:
        self._max_symbols = max_symbols

    @staticmethod
    def _run(cmd: list[str], cwd: str | None = None) -> str:
        try:
            out = subprocess.run(
                cmd, cwd=cwd, capture_output=True, text=True, timeout=120, check=False
            )
            return out.stdout
        except Exception:  # fail-open: any failure -> no output from this source
            return ""

    def _ctags_tags(self, root: Path, paths: list[str] | None) -> list[dict]:
        if not _have("ctags"):
            return []
        base = ["ctags", "--output-format=json", "--fields=+nKSl", "-f", "-"]
        cmd = base + (paths if paths else ["-R", "."])
        raw = self._run(cmd, cwd=str(root))
        tags: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                t = json.loads(line)
            except Exception:
                continue
            if t.get("_type") != "tag":
                continue
            tags.append(
                {
                    "name": t.get("name", ""),
                    "kind": (t.get("kind") or "").lower(),
                    "file": _norm(root, t.get("path", "")),
                    "line": int(t.get("line", 0) or 0),
                    "signature": t.get("signature", "") or t.get("pattern", "") or "",
                }
            )
        return tags

    def _rg_tags(self, root: Path, paths: list[str] | None) -> list[dict]:
        if not _have("rg"):
            return []
        cmd = ["rg", "--no-heading", "--line-number", "--color", "never", _RG_DEF]
        cmd += paths if paths else ["."]
        raw = self._run(cmd, cwd=str(root))
        tags: list[dict] = []
        for line in raw.splitlines():
            m = re.match(r"^(.*?):(\d+):(.*)$", line)
            if not m:
                continue
            path, lno, text = m.group(1), int(m.group(2)), m.group(3)
            nm = re.search(_RG_DEF, text)
            if not nm:
                continue
            tags.append(
                {
                    "name": nm.group(1),
                    "kind": "def",
                    "file": _norm(root, path),
                    "line": lno,
                    "signature": text.strip()[:160],
                }
            )
        return tags

    def _py_tags(self, root: Path, paths: list[str] | None) -> list[dict]:
        """Pure-Python fallback when neither ctags nor rg is on PATH.

        Applies the same generic ``_RG_DEF`` definition pattern line-by-line by
        reading files directly, so the fact sheet is never empty just because no
        external tool is installed. ``paths=None`` walks the repo for code-ish
        files (bounded), otherwise it scans exactly the given files. Fail-open.
        """
        if paths is None:
            scan: list[str] = []
            try:
                for p in sorted(Path(root).rglob("*")):
                    if not p.is_file():
                        continue
                    if any(
                        seg in p.parts
                        for seg in (".git", "__pycache__", "node_modules", ".venv", ".caliper")
                    ):
                        continue
                    if p.suffix not in {
                        ".py",
                        ".ts",
                        ".tsx",
                        ".js",
                        ".jsx",
                        ".go",
                        ".rs",
                        ".java",
                        ".rb",
                        ".c",
                        ".cc",
                        ".cpp",
                        ".h",
                        ".hpp",
                        ".swift",
                        ".kt",
                    }:
                        continue
                    scan.append(str(p.relative_to(root)))
            except Exception:
                return []
        else:
            scan = list(paths)

        tags: list[dict] = []
        for rel in scan:
            fp = Path(rel) if Path(rel).is_absolute() else Path(root) / rel
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for lno, line in enumerate(text.splitlines(), 1):
                nm = re.search(_RG_DEF, line)
                if not nm:
                    continue
                tags.append(
                    {
                        "name": nm.group(1),
                        "kind": "def",
                        "file": _norm(root, rel),
                        "line": lno,
                        "signature": line.strip()[:160],
                    }
                )
        return tags

    def _tags(self, root: Path, paths: list[str] | None) -> list[dict]:
        return (
            self._ctags_tags(root, paths)
            or self._rg_tags(root, paths)
            or self._py_tags(root, paths)
        )

    def fact_sheet(self, root: Path, files: list[str]) -> list[dict]:
        try:
            tags = self._tags(root, files)
            tags.sort(key=lambda t: (t["file"], t["line"], t["name"]))
            return tags[: self._max_symbols]
        except Exception:
            logger.debug("grounding.ctags.fact_sheet_failed", root=str(root))
            return []

    def type_context(self, root: Path, files: list[str]) -> list[dict]:
        try:
            target_set = {_norm(root, f) for f in files}
            refs = _identifiers_in(root, files)
            if not refs:
                return []
            index = self._tags(root, None)
            out: list[dict] = []
            seen: set[tuple] = set()
            for t in index:
                if t["kind"] not in _TYPE_KINDS:
                    continue
                if t["name"] not in refs:
                    continue
                if t["file"] in target_set:
                    continue
                key = (t["name"], t["file"], t["line"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(t)
            out.sort(key=lambda t: (t["name"], t["file"], t["line"]))
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.ctags.type_context_failed", root=str(root))
            return []

    def neighbors(self, root: Path, symbol: str) -> list[dict]:
        return []

    def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Gitnexus provider
# ---------------------------------------------------------------------------
@GROUNDING_PROVIDERS.register("gitnexus")
class GitnexusGroundingProvider:
    """Serve grounding from a pre-computed gitnexus-style JSON graph export.

    Decoupled/best-effort: this adapter does NOT run gitnexus itself — it reads
    a graph export written elsewhere. When ``graph_path`` is ``None`` or the file
    is missing/unparseable, the provider behaves as unavailable (all methods
    return ``[]``).

    Expected export schema (generic JSON)::

        {
          "symbols": [
            {"name": str, "kind": str, "file": str, "line": int,
             "signature": str (optional)},
            ...
          ],
          "edges": [
            {"src": str, "dst": str, "kind": str},
            ...
          ]
        }

    ``src``/``dst`` are symbol names. ``fact_sheet`` returns symbols whose
    ``file`` is among *files*; ``type_context`` returns type-like symbols
    referenced by *files* but defined elsewhere; ``neighbors`` returns symbols on
    either end of an edge touching the queried symbol.
    """

    name = "gitnexus"

    def __init__(
        self, graph_path: str | None = None, max_symbols: int = _DEFAULT_MAX_SYMBOLS
    ) -> None:
        self._graph_path = graph_path
        self._max_symbols = max_symbols
        self._loaded = False
        self._symbols: list[dict] = []
        self._edges: list[dict] = []

    def _load(self) -> bool:
        """Parse the export once (fail-open). Returns True when data is available."""
        if self._loaded:
            return bool(self._symbols or self._edges)
        self._loaded = True
        if not self._graph_path:
            return False
        path = Path(self._graph_path)
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            logger.debug("grounding.gitnexus.parse_failed", path=str(path))
            return False
        if not isinstance(data, dict):
            return False
        raw_symbols = data.get("symbols") or []
        raw_edges = data.get("edges") or []
        self._symbols = [s for s in raw_symbols if isinstance(s, dict)]
        self._edges = [e for e in raw_edges if isinstance(e, dict)]
        return bool(self._symbols or self._edges)

    @staticmethod
    def _as_symbol(s: dict, root: Path) -> dict:
        return {
            "name": s.get("name", ""),
            "kind": (s.get("kind") or "").lower(),
            "file": _norm(root, str(s.get("file", ""))),
            "line": int(s.get("line", 0) or 0),
            "signature": s.get("signature", "") or "",
        }

    def fact_sheet(self, root: Path, files: list[str]) -> list[dict]:
        if not self._load():
            return []
        try:
            wanted = {_norm(root, f) for f in files}
            out = [
                self._as_symbol(s, root)
                for s in self._symbols
                if _norm(root, str(s.get("file", ""))) in wanted
            ]
            out.sort(key=lambda d: (d["file"], d["line"], d["name"]))
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.gitnexus.fact_sheet_failed", root=str(root))
            return []

    def type_context(self, root: Path, files: list[str]) -> list[dict]:
        if not self._load():
            return []
        try:
            wanted = {_norm(root, f) for f in files}
            refs = _identifiers_in(root, files)
            if not refs:
                return []
            out: list[dict] = []
            seen: set[tuple] = set()
            for s in self._symbols:
                sym = self._as_symbol(s, root)
                if sym["kind"] not in _TYPE_KINDS:
                    continue
                if sym["name"] not in refs:
                    continue
                if sym["file"] in wanted:
                    continue
                key = (sym["name"], sym["file"], sym["line"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(sym)
            out.sort(key=lambda d: (d["name"], d["file"], d["line"]))
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.gitnexus.type_context_failed", root=str(root))
            return []

    def neighbors(self, root: Path, symbol: str) -> list[dict]:
        if not self._load():
            return []
        try:
            by_name: dict[str, dict] = {}
            for s in self._symbols:
                name = s.get("name")
                if name and name not in by_name:
                    by_name[name] = self._as_symbol(s, root)
            out: list[dict] = []
            seen: set[tuple] = set()
            for e in self._edges:
                src, dst = e.get("src"), e.get("dst")
                kind = e.get("kind", "edge")
                other = None
                relation = kind
                if src == symbol and dst:
                    other = dst
                elif dst == symbol and src:
                    other = src
                if not other:
                    continue
                sym = by_name.get(other, {"name": other, "file": "", "line": 0})
                entry = {
                    "name": sym.get("name", other),
                    "file": sym.get("file", ""),
                    "line": sym.get("line", 0),
                    "relation": relation,
                }
                key = (entry["name"], entry["file"], entry["line"], entry["relation"])
                if key in seen:
                    continue
                seen.add(key)
                out.append(entry)
            out.sort(key=lambda d: (d["name"], d["file"], d["line"]))
            return out[: self._max_symbols]
        except Exception:
            logger.debug("grounding.gitnexus.neighbors_failed", root=str(root))
            return []

    def close(self) -> None:
        self._symbols = []
        self._edges = []
        self._loaded = False
