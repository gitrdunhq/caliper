"""Tests for the parting plugin — manual-gate isolation + producer/consumer wiring.

# tested-by: tests/unit/test_parting_plugin.py
"""

from __future__ import annotations

from pathlib import Path

# Importing the module triggers its @PARTING.register side effect.
import caliper.plugins._parting  # noqa: E402,F401
from caliper.core.registries import PARTING
from caliper.core.repo_config import PartingConfig
from caliper.core.tool_runner import ToolInvocation, ToolResult
from caliper.plugins._parting import PartingPlugin  # noqa: E402


class _FakeGit:
    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd

        def ok(out: str) -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        if "rev-parse" in cmd:
            return ok(("aaaa" if cmd[-1] == "BASE" else "bbbb") + "\n")
        if "ls-files" in cmd and "-s" in cmd:
            return ok("100644 sha 0\tapp.py")
        if "ls-files" in cmd:
            return ok("app.py")
        if "--name-status" in cmd:
            return ok("M\tapp.py")
        if "--numstat" in cmd:
            return ok("10\t2\tapp.py")
        return ok("")


def test_registered_in_parting_registry() -> None:
    assert "parting" in PARTING


def test_not_registered_in_analyzers() -> None:
    """The manual gate must never be auto-discovered into the review pipeline."""
    from caliper.plugins import ANALYZERS, get_default_registry

    assert "parting" not in ANALYZERS
    names = {p.name for p in get_default_registry().list()}
    assert "parting" not in names


def test_can_run_is_false_and_run_skips() -> None:
    plugin = PartingPlugin()
    assert plugin.can_run([], Path(".")) is False
    result = plugin.run([], Path("."))
    assert result.skip_reason == "parting is a manual gate"


def test_cut_wires_producer_to_consumer_with_provenance() -> None:
    plugin = PARTING.create("parting")
    outcome = plugin.cut(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner=_FakeGit())
    cut = outcome.cutlist
    assert [p.files for p in cut.parts] == [["app.py"]]
    # provenance stamped from the resolved endpoints + the real caliper version
    assert cut.provenance.base_sha == "aaaa"
    assert cut.provenance.head_sha == "bbbb"
    assert cut.provenance.caliper_version  # non-empty (importlib metadata)
    assert cut.provenance.config_digest
    assert outcome.old_paths == {}  # no renames in this fixture
