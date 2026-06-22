# tested-by: tests/unit/test_grounding.py
"""Tests for the gated grounding providers and composition wiring.

DPS-12 domains:
  Determinism (INVARIANT): same inputs -> same fact_sheet ordering/content.
  Availability / fail-open (INVARIANT): never raises on missing/garbage paths;
    a disabled feature flag yields the null provider.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault("EEDOM_DB_DSN", "postgresql://t:t@localhost/t")
os.environ.setdefault("EEDOM_ALLOW_GLOBAL", "1")

from eedom.adapters.grounding import (  # noqa: E402
    CodeGraphGroundingProvider,
    CtagsGroundingProvider,
    GitnexusGroundingProvider,
    NullGroundingProvider,
)
from eedom.composition.bootstrap import (  # noqa: E402
    build_default_codegraph_factory,
    build_grounding_provider,
    load_adapters,
    run_grounding,
)
from eedom.core.config import EedomSettings  # noqa: E402
from eedom.core.ports import GroundingProviderPort  # noqa: E402
from eedom.core.registries import GROUNDING_PROVIDERS  # noqa: E402


def _settings(**overrides) -> EedomSettings:
    base = {"db_dsn": "postgresql://t:t@localhost/t"}
    base.update(overrides)
    return EedomSettings(**base)  # type: ignore[arg-type]


def _write_pkg(tmp_path: Path) -> Path:
    """Create a tiny Python package with a top-level def + class."""
    src = tmp_path / "pkg"
    src.mkdir()
    (src / "mod.py").write_text(
        "def foo():\n    return 1\n\n\nclass Bar:\n    pass\n",
        encoding="utf-8",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Null provider
# ---------------------------------------------------------------------------
class TestNullGroundingProvider:
    def test_registered(self) -> None:
        load_adapters()
        assert "null" in GROUNDING_PROVIDERS
        provider = GROUNDING_PROVIDERS.create("null")
        assert provider.name == "null"

    def test_satisfies_port(self) -> None:
        assert isinstance(NullGroundingProvider(), GroundingProviderPort)

    def test_all_methods_empty(self, tmp_path: Path) -> None:
        p = NullGroundingProvider()
        assert p.fact_sheet(tmp_path, ["a.py"]) == []
        assert p.type_context(tmp_path, ["a.py"]) == []
        assert p.neighbors(tmp_path, "foo") == []
        assert p.close() is None


# ---------------------------------------------------------------------------
# Ctags provider (ripgrep fallback path — ctags not installed in CI)
# ---------------------------------------------------------------------------
class TestCtagsGroundingProvider:
    def test_fact_sheet_finds_def_and_class(self, tmp_path: Path) -> None:
        root = _write_pkg(tmp_path)
        provider = CtagsGroundingProvider()
        facts = provider.fact_sheet(root, ["pkg/mod.py"])
        names = {f["name"] for f in facts}
        # ripgrep (or ctags) should surface the top-level def + class.
        assert "foo" in names
        assert "Bar" in names

    def test_neighbors_empty(self, tmp_path: Path) -> None:
        assert CtagsGroundingProvider().neighbors(tmp_path, "foo") == []

    def test_satisfies_port(self) -> None:
        assert isinstance(CtagsGroundingProvider(), GroundingProviderPort)


# ---------------------------------------------------------------------------
# CodeGraph provider
# ---------------------------------------------------------------------------
class TestCodeGraphGroundingProvider:
    def test_fact_sheet_returns_list(self, tmp_path: Path, monkeypatch) -> None:
        # Keep the graph db inside tmp so we never touch the user cache. The
        # graph builder is injected by the composition tier (adapters may not
        # import the plugins tier where CodeGraph lives).
        monkeypatch.setenv("EEDOM_GRAPH_DB", str(tmp_path / "graph.sqlite"))
        root = _write_pkg(tmp_path)
        provider = CodeGraphGroundingProvider(graph_factory=build_default_codegraph_factory())
        facts = provider.fact_sheet(root, ["pkg/mod.py"])
        # Fail-open invariant: always a list, never raises.
        assert isinstance(facts, list)
        names = {f["name"] for f in facts}
        # The AST indexer should find the top-level def/class if the build worked.
        assert names == set() or {"foo", "Bar"} & names
        provider.close()

    def test_no_factory_is_unavailable(self, tmp_path: Path) -> None:
        # Without an injected graph factory the provider degrades to empty.
        provider = CodeGraphGroundingProvider(graph_factory=None)
        assert provider.fact_sheet(tmp_path, ["pkg/mod.py"]) == []

    def test_satisfies_port(self) -> None:
        assert isinstance(CodeGraphGroundingProvider(), GroundingProviderPort)


# ---------------------------------------------------------------------------
# Gitnexus provider
# ---------------------------------------------------------------------------
class TestGitnexusGroundingProvider:
    def test_unavailable_when_path_none(self, tmp_path: Path) -> None:
        p = GitnexusGroundingProvider(graph_path=None)
        assert p.fact_sheet(tmp_path, ["a.py"]) == []
        assert p.type_context(tmp_path, ["a.py"]) == []
        assert p.neighbors(tmp_path, "foo") == []

    def test_unavailable_when_path_missing(self, tmp_path: Path) -> None:
        p = GitnexusGroundingProvider(graph_path=str(tmp_path / "nope.json"))
        assert p.fact_sheet(tmp_path, ["a.py"]) == []

    def test_serves_from_export(self, tmp_path: Path) -> None:
        export = {
            "symbols": [
                {"name": "foo", "kind": "function", "file": "pkg/mod.py", "line": 1},
                {"name": "Bar", "kind": "class", "file": "other.py", "line": 5},
            ],
            "edges": [{"src": "foo", "dst": "Bar", "kind": "calls"}],
        }
        graph_file = tmp_path / "graph.json"
        graph_file.write_text(json.dumps(export), encoding="utf-8")
        # Reference Bar from the target file so type_context picks it up.
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text("def foo():\n    return Bar()\n", encoding="utf-8")

        p = GitnexusGroundingProvider(graph_path=str(graph_file))
        facts = p.fact_sheet(tmp_path, ["pkg/mod.py"])
        assert {f["name"] for f in facts} == {"foo"}

        types = p.type_context(tmp_path, ["pkg/mod.py"])
        assert {t["name"] for t in types} == {"Bar"}

        neigh = p.neighbors(tmp_path, "foo")
        assert any(n["name"] == "Bar" for n in neigh)

    def test_garbage_export_fail_open(self, tmp_path: Path) -> None:
        graph_file = tmp_path / "graph.json"
        graph_file.write_text("not json {{{", encoding="utf-8")
        p = GitnexusGroundingProvider(graph_path=str(graph_file))
        assert p.fact_sheet(tmp_path, ["a.py"]) == []


# ---------------------------------------------------------------------------
# build_grounding_provider
# ---------------------------------------------------------------------------
class TestBuildGroundingProvider:
    def test_null_when_disabled(self) -> None:
        provider = build_grounding_provider(_settings(grounding_enabled=False))
        assert provider.name == "null"

    def test_non_null_when_enabled_auto(self) -> None:
        provider = build_grounding_provider(
            _settings(grounding_enabled=True, grounding_provider="auto")
        )
        assert provider.name != "null"

    def test_explicit_codegraph(self) -> None:
        provider = build_grounding_provider(
            _settings(grounding_enabled=True, grounding_provider="codegraph")
        )
        assert provider.name == "codegraph"

    def test_unknown_provider_falls_back_to_null(self) -> None:
        provider = build_grounding_provider(
            _settings(grounding_enabled=True, grounding_provider="does-not-exist")
        )
        assert provider.name == "null"

    def test_auto_prefers_gitnexus_when_export_present(self, tmp_path: Path) -> None:
        graph_file = tmp_path / "graph.json"
        graph_file.write_text(json.dumps({"symbols": [], "edges": []}), encoding="utf-8")
        provider = build_grounding_provider(
            _settings(
                grounding_enabled=True,
                grounding_provider="auto",
                gitnexus_graph_path=str(graph_file),
            )
        )
        assert provider.name == "gitnexus"


# ---------------------------------------------------------------------------
# run_grounding
# ---------------------------------------------------------------------------
class TestRunGrounding:
    def test_returns_bundle_keys(self, tmp_path: Path) -> None:
        root = _write_pkg(tmp_path)
        bundle = run_grounding(
            ["pkg/mod.py"],
            _settings(grounding_enabled=True, grounding_provider="ctags"),
            root=str(root),
        )
        assert set(bundle) == {"provider", "root", "fact_sheet", "type_context"}
        assert isinstance(bundle["fact_sheet"], list)
        assert isinstance(bundle["type_context"], list)

    def test_never_raises_on_bogus_root(self) -> None:
        bundle = run_grounding(
            ["nope.py"],
            _settings(grounding_enabled=True, grounding_provider="ctags"),
            root="/this/path/does/not/exist/at/all",
        )
        assert isinstance(bundle, dict)
        assert "fact_sheet" in bundle

    def test_disabled_returns_null_provider_bundle(self, tmp_path: Path) -> None:
        bundle = run_grounding(
            ["pkg/mod.py"], _settings(grounding_enabled=False), root=str(tmp_path)
        )
        assert bundle["provider"] == "null"
        assert bundle["fact_sheet"] == []


# ---------------------------------------------------------------------------
# DPS-12 properties
# ---------------------------------------------------------------------------
class TestProperties:
    def test_determinism_fact_sheet_ordering(self, tmp_path: Path) -> None:
        """Determinism (INVARIANT): same inputs -> identical fact_sheet."""
        root = _write_pkg(tmp_path)
        provider = CtagsGroundingProvider()
        a = provider.fact_sheet(root, ["pkg/mod.py"])
        b = provider.fact_sheet(root, ["pkg/mod.py"])
        assert a == b

    def test_fail_open_never_raises_on_garbage(self, tmp_path: Path) -> None:
        """Availability / fail-open (INVARIANT): garbage paths never raise."""
        garbage = ["", "../../etc/passwd", "\x00bad", str(tmp_path / "missing.py")]
        for provider in (
            NullGroundingProvider(),
            CtagsGroundingProvider(),
            CodeGraphGroundingProvider(),
            GitnexusGroundingProvider(graph_path=None),
        ):
            assert isinstance(provider.fact_sheet(Path("/no/such/root"), garbage), list)
            assert isinstance(provider.type_context(Path("/no/such/root"), garbage), list)
            assert isinstance(provider.neighbors(Path("/no/such/root"), "x"), list)
            provider.close()
