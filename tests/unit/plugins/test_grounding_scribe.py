"""GroundingScribe (detect-then-scribe, ADR-006, #481).
# tested-by: tests/unit/plugins/test_grounding_scribe.py

DPS-12 domains: Determinism (same finding+provider -> same packet), Availability
(fail-open: a raising provider never drops the finding), Boundedness (the
attached symbol/contract lists are capped by grounding_max_symbols).
"""

from __future__ import annotations

from pathlib import Path

from caliper.core.plugin import PluginFinding
from caliper.core.scribe import ScribeContext
from caliper.plugins.scribes.grounding import GroundingScribe


def _finding(**kw) -> PluginFinding:
    base = {"id": "x", "severity": "info", "message": "m", "file": "a.py", "line": 2}
    base.update(kw)
    return PluginFinding(**base)


class _FakeProvider:
    name = "fake"

    def __init__(self, defined=None, contracts=None, raises=False):
        self._defined = defined or []
        self._contracts = contracts or []
        self._raises = raises
        self.fact_sheet_calls = 0
        self.type_context_calls = 0

    def fact_sheet(self, root: Path, files: list[str]) -> list[dict]:
        self.fact_sheet_calls += 1
        if self._raises:
            raise RuntimeError("boom")
        return self._defined

    def type_context(self, root: Path, files: list[str]) -> list[dict]:
        self.type_context_calls += 1
        if self._raises:
            raise RuntimeError("boom")
        return self._contracts

    def neighbors(self, root: Path, symbol: str) -> list[dict]:
        return []

    def close(self) -> None:
        pass


def test_applies_only_to_findings_with_a_file() -> None:
    scribe = GroundingScribe(_FakeProvider())
    assert scribe.applies_to(_finding(file="a.py")) is True
    assert scribe.applies_to(_finding(file="")) is False


def test_attaches_defined_contracts_and_provider(tmp_path) -> None:
    provider = _FakeProvider(
        defined=[{"name": "helper", "kind": "function", "line": 1, "file": "a.py"}],
        contracts=[{"name": "Widget", "kind": "class", "file": "b.py", "line": 3}],
    )
    scribe = GroundingScribe(provider)
    ctx = ScribeContext(repo_path=str(tmp_path))

    out = scribe.scribe(_finding(file="a.py"), ctx)

    packet = out.metadata["scribe"]["grounding"]
    assert packet["defined"] == [{"name": "helper", "kind": "function", "line": 1}]
    assert packet["contracts"] == [{"name": "Widget", "defined_in": "b.py"}]
    assert packet["provider"] == "fake"
    assert "grounding" in out.metadata["scribe"]["sources"]


def test_packet_is_capped_by_max_symbols(tmp_path) -> None:
    defined = [{"name": f"f{i}", "kind": "function", "line": i} for i in range(10)]
    provider = _FakeProvider(defined=defined)
    scribe = GroundingScribe(provider, max_symbols=3)
    ctx = ScribeContext(repo_path=str(tmp_path))

    out = scribe.scribe(_finding(file="a.py"), ctx)

    assert len(out.metadata["scribe"]["grounding"]["defined"]) == 3


def test_provider_called_once_per_file_across_findings(tmp_path) -> None:
    """Boundedness/perf: a repo with many findings in one file must not shell
    out to the provider once per finding."""
    provider = _FakeProvider(defined=[{"name": "helper", "kind": "function", "line": 1}])
    scribe = GroundingScribe(provider)
    ctx = ScribeContext(repo_path=str(tmp_path))

    for _ in range(5):
        scribe.scribe(_finding(file="a.py"), ctx)

    assert provider.fact_sheet_calls == 1
    assert provider.type_context_calls == 1


def test_different_files_each_call_the_provider(tmp_path) -> None:
    provider = _FakeProvider(defined=[{"name": "helper", "kind": "function", "line": 1}])
    scribe = GroundingScribe(provider)
    ctx = ScribeContext(repo_path=str(tmp_path))

    scribe.scribe(_finding(file="a.py"), ctx)
    scribe.scribe(_finding(file="b.py"), ctx)

    assert provider.fact_sheet_calls == 2


def test_raising_provider_is_fail_open(tmp_path) -> None:
    provider = _FakeProvider(raises=True)
    scribe = GroundingScribe(provider)
    ctx = ScribeContext(repo_path=str(tmp_path))
    f = _finding(file="a.py")

    out = scribe.scribe(f, ctx)

    packet = out.metadata["scribe"]["grounding"]
    assert packet == {"defined": [], "contracts": [], "provider": "fake"}


def test_finding_without_file_is_untouched(tmp_path) -> None:
    provider = _FakeProvider()
    scribe = GroundingScribe(provider)
    ctx = ScribeContext(repo_path=str(tmp_path))
    f = _finding(file="")

    assert scribe.scribe(f, ctx) == f
