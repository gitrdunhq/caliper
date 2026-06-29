"""Tests for the stock producer — ``core.part_stock.build_stock``.

# tested-by: tests/unit/test_part_stock.py

Uses a fake ``ToolRunnerPort`` so no real git/repo is needed. Covers
classification of every ChangeType and the determinism guarantee: the git diff
invocation pins its flags (rename/copy thresholds, rename limit, ignorecase off)
so ambient git config can never change the records.

Property domains (DPS-12):
  Determinism   INVARIANT  pinned flags -> records independent of ambient config
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.models import ChangeType
from caliper.core.part_stock import build_stock
from caliper.core.parting import PartingError
from caliper.core.repo_config import PartingConfig
from caliper.core.tool_runner import ToolInvocation, ToolResult

_SHAS = {"BASE": "aaaaaaaaaaaa", "HEAD": "bbbbbbbbbbbb"}

_LS_FILES = "\n".join(
    ["app.py", "poetry.lock", "new.py", "logo.png", "config.yaml", "test_app.py", "link"]
)
_LS_FILES_S = "\n".join(
    [
        "100644 sha 0\tapp.py",
        "100644 sha 0\tpoetry.lock",
        "100644 sha 0\tnew.py",
        "100644 sha 0\tlogo.png",
        "100644 sha 0\tconfig.yaml",
        "100644 sha 0\ttest_app.py",
        "120000 sha 0\tlink",
    ]
)
_NAME_STATUS = "\n".join(
    [
        "M\tapp.py",
        "M\tpoetry.lock",
        "R100\told.py\tnew.py",
        "D\tgone.py",
        "M\tlogo.png",
        "M\tconfig.yaml",
        "M\ttest_app.py",
        "M\tlink",
    ]
)
_NUMSTAT = "\n".join(
    [
        "10\t2\tapp.py",
        "100\t50\tpoetry.lock",
        "0\t0\told.py => new.py",
        "0\t5\tgone.py",
        "-\t-\tlogo.png",
        "3\t1\tconfig.yaml",
        "4\t0\ttest_app.py",
        "1\t1\tlink",
    ]
)


class FakeRunner:
    """Canned git output keyed by the recognized subcommand; records invocations."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, invocation: ToolInvocation) -> ToolResult:
        cmd = invocation.cmd
        self.calls.append(cmd)

        def ok(out: str) -> ToolResult:
            return ToolResult(exit_code=0, stdout=out, stderr="")

        if "rev-parse" in cmd:
            return ok(_SHAS[cmd[-1]] + "\n")
        if "ls-files" in cmd and "-s" in cmd:
            return ok(_LS_FILES_S)
        if "ls-files" in cmd:
            return ok(_LS_FILES)
        if "--name-status" in cmd:
            return ok(_NAME_STATUS)
        if "--numstat" in cmd:
            return ok(_NUMSTAT)
        return ok("")


def _stock(cfg: PartingConfig | None = None) -> dict[str, tuple[ChangeType, int | None]]:
    runner = FakeRunner()
    stock = build_stock(Path("/repo"), "BASE", "HEAD", cfg or PartingConfig(), runner)
    return {r.file: (r.change_type, r.size) for r in stock.records}


def test_classifies_every_change_type() -> None:
    by_file = _stock()
    assert by_file["app.py"] == (ChangeType.logic, 12)
    assert by_file["poetry.lock"] == (ChangeType.generated, 150)
    assert by_file["config.yaml"] == (ChangeType.config, 4)
    assert by_file["test_app.py"] == (ChangeType.test, 4)
    assert by_file["new.py"] == (ChangeType.move, 0)
    assert by_file["gone.py"] == (ChangeType.delete, 5)
    assert by_file["logo.png"] == (ChangeType.binary, None)  # numstat reported '-'
    assert by_file["link"] == (ChangeType.binary, None)  # symlink mode 120000


def test_rename_keeps_old_path_and_new_canonical_key() -> None:
    runner = FakeRunner()
    stock = build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner)
    move = next(r for r in stock.records if r.file == "new.py")
    assert move.old_path == "old.py"
    # old path never appears as its own record (counted once under the new path)
    assert all(r.file != "old.py" for r in stock.records)


def test_resolves_endpoints_to_shas() -> None:
    runner = FakeRunner()
    stock = build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner)
    assert stock.base_sha == "aaaaaaaaaaaa"
    assert stock.head_sha == "bbbbbbbbbbbb"


def test_diff_invocation_pins_flags_against_ambient_config() -> None:
    """Determinism: the diff command pins rename/copy thresholds, limit, ignorecase."""
    runner = FakeRunner()
    build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), runner)
    diff_cmds = [c for c in runner.calls if "--name-status" in c or "--numstat" in c]
    assert diff_cmds, "expected diff invocations"
    for cmd in diff_cmds:
        assert "core.ignorecase=false" in cmd
        assert "--find-renames=50%" in cmd
        assert "--find-copies=50%" in cmd
        assert "-l" in cmd and "1000" in cmd
        assert "--no-color" in cmd


def test_records_are_identical_run_to_run() -> None:
    """Determinism INVARIANT: same canned git output -> byte-identical records."""
    a = build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), FakeRunner())
    b = build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), FakeRunner())
    assert [r.model_dump() for r in a.records] == [r.model_dump() for r in b.records]


def test_fail_closed_on_git_error() -> None:
    """Fail-closed carve-out: a git failure is a hard error, never a partial stock."""

    class FailingRunner:
        def run(self, invocation: ToolInvocation) -> ToolResult:
            return ToolResult(exit_code=128, stdout="", stderr="fatal: bad revision")

    with pytest.raises(PartingError):
        build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), FailingRunner())


def test_fail_closed_when_git_not_installed() -> None:
    class MissingRunner:
        def run(self, invocation: ToolInvocation) -> ToolResult:
            return ToolResult(exit_code=127, stdout="", stderr="", not_installed=True)

    with pytest.raises(PartingError):
        build_stock(Path("/repo"), "BASE", "HEAD", PartingConfig(), MissingRunner())


# ---------------------------------------------------------------------------
# Two-axis taxonomy classification — the glob precedence is the product
# ---------------------------------------------------------------------------


class TestClassifyPrecedence:
    """``_classify`` glob precedence: structural first, then most-specific globs."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            # Non-code intent buckets.
            ("policies/policy.rego", ChangeType.security_policy),
            ("infra/iam/role.json", ChangeType.security_policy),
            ("package.json", ChangeType.supply_chain),
            ("pyproject.toml", ChangeType.supply_chain),
            (".github/workflows/ci.yml", ChangeType.ci_cd),
            ("Makefile", ChangeType.ci_cd),
            ("api/order.proto", ChangeType.schema_contracts),
            ("db/migrations/0001_init.sql", ChangeType.schema_contracts),
            ("openapi.yaml", ChangeType.schema_contracts),
            ("README.md", ChangeType.documentation),
            ("docs/guide.rst", ChangeType.documentation),
            ("settings.yaml", ChangeType.config),
            ("app.ini", ChangeType.config),
            ("infra/main.tf", ChangeType.infra),
            ("Dockerfile", ChangeType.infra),
            ("cdk/app-stack.ts", ChangeType.infra),
            # Code with no tier glob -> untiered residual.
            ("src/service/order.py", ChangeType.logic),
        ],
    )
    def test_glob_routing(self, path: str, expected: ChangeType) -> None:
        from caliper.core.part_stock import _classify

        assert _classify("M", path, size=5, mode="100644", cfg=PartingConfig()) == expected

    def test_specific_beats_generic_config(self) -> None:
        """A workflow YAML is ci_cd, not generic config; openapi YAML is schema."""
        from caliper.core.part_stock import _classify

        cfg = PartingConfig()
        assert _classify("M", ".github/workflows/x.yaml", 5, "100644", cfg) == ChangeType.ci_cd
        assert _classify("M", "openapi.yaml", 5, "100644", cfg) == ChangeType.schema_contracts

    def test_lockfile_is_generated_not_supply_chain(self) -> None:
        """package-lock.json is generated (checked first), package.json is supply_chain."""
        from caliper.core.part_stock import _classify

        cfg = PartingConfig()
        assert _classify("M", "package-lock.json", 5, "100644", cfg) == ChangeType.generated
        assert _classify("M", "package.json", 5, "100644", cfg) == ChangeType.supply_chain

    @pytest.mark.parametrize(
        ("status", "path", "size", "mode", "expected"),
        [
            ("D", "policies/policy.rego", 5, "100644", ChangeType.delete),
            ("R100", "policies/policy.rego", 5, "100644", ChangeType.move),
            ("M", "policies/policy.rego", None, "100644", ChangeType.binary),
            ("M", "policies/policy.rego", 5, "120000", ChangeType.binary),
        ],
    )
    def test_structural_facts_beat_globs(
        self, status: str, path: str, size: int | None, mode: str, expected: ChangeType
    ) -> None:
        """A delete/move/binary is never reclassified by a content glob."""
        from caliper.core.part_stock import _classify

        assert _classify(status, path, size, mode, PartingConfig()) == expected
