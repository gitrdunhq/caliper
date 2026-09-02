"""scripts/affected_tests.py — deterministic test selection from `# tested-by:` annotations.
# tested-by: tests/unit/test_affected_tests.py

Lanes ran the full 12-minute suite several times each. Every source file names
its test file, so a changed file set maps to a test set without guessing; the
mapper fails SAFE to the full suite whenever it cannot prove the map is complete.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "scripts"))
import affected_tests as sut  # noqa: E402

GUARDS = set(sut.ALWAYS_RUN)


def _lookup(mapping: dict[str, str | None]):
    return lambda path: mapping.get(path)


class TestSelectTests:
    def test_source_change_maps_to_its_tested_by_file(self) -> None:
        sel = sut.select_tests(
            ["src/caliper/core/ignore.py"],
            _lookup({"src/caliper/core/ignore.py": "tests/unit/test_ignore.py"}),
        )
        assert sel.full_suite is False
        assert "tests/unit/test_ignore.py" in sel.tests
        assert set(sel.tests) >= GUARDS

    def test_changed_test_file_selects_itself(self) -> None:
        sel = sut.select_tests(["tests/unit/test_cli.py"], _lookup({}))
        assert sel.full_suite is False and "tests/unit/test_cli.py" in sel.tests

    def test_source_without_annotation_fails_safe_to_full_suite(self) -> None:
        sel = sut.select_tests(
            ["src/caliper/core/new_thing.py"], _lookup({"src/caliper/core/new_thing.py": None})
        )
        assert sel.full_suite is True and sel.tests == ["tests/"]
        assert "no tested-by" in sel.reason

    def test_dependency_or_container_change_fails_safe(self) -> None:
        for f in (
            "pyproject.toml",
            "uv.lock",
            "Dockerfile.test",
            "conftest.py",
            "tests/conftest.py",
        ):
            sel = sut.select_tests([f], _lookup({}))
            assert sel.full_suite is True, f

    def test_workflow_template_and_capabilities_changes_map_to_policy_tests(self) -> None:
        sel = sut.select_tests(
            [
                ".github/workflows/foreman.yml",
                "src/caliper/templates/comment.md.j2",
                "docs/CAPABILITIES.md",
            ],
            _lookup({}),
        )
        assert sel.full_suite is False
        assert "tests/unit/test_github_actions_policy.py" in sel.tests
        assert "tests/unit/test_plugin_templates.py" in sel.tests
        assert "tests/unit/test_capability_counts.py" in sel.tests

    def test_docs_only_change_runs_only_guards(self) -> None:
        sel = sut.select_tests(["README.md", "docs/decommission-log.md"], _lookup({}))
        assert sel.full_suite is False and set(sel.tests) == GUARDS

    def test_missing_target_test_file_fails_safe(self, tmp_path: Path) -> None:
        sel = sut.select_tests(
            ["src/caliper/core/x.py"],
            _lookup({"src/caliper/core/x.py": "tests/unit/test_does_not_exist.py"}),
            exists=lambda p: False,
        )
        assert sel.full_suite is True and "missing" in sel.reason

    def test_output_is_sorted_and_deduplicated(self) -> None:
        sel = sut.select_tests(
            ["src/caliper/core/a.py", "src/caliper/core/b.py", "tests/unit/test_ab.py"],
            _lookup(
                {
                    "src/caliper/core/a.py": "tests/unit/test_ab.py",
                    "src/caliper/core/b.py": "tests/unit/test_ab.py",
                }
            ),
            exists=lambda p: True,
        )
        assert sel.tests == sorted(set(sel.tests))
        assert sel.tests.count("tests/unit/test_ab.py") == 1


class TestTestedByLookup:
    def test_reads_annotation_from_a_real_source_file(self) -> None:
        root = Path(__file__).parents[2]
        assert sut.tested_by_for(root, "src/caliper/core/ignore.py") == "tests/unit/test_ignore.py"

    def test_returns_none_when_absent(self, tmp_path: Path) -> None:
        (tmp_path / "m.py").write_text("x = 1\n")
        assert sut.tested_by_for(tmp_path, "m.py") is None


class TestChangedFiles:
    def test_parses_git_output_lines(self) -> None:
        raw = "src/caliper/core/a.py\n\ntests/unit/test_a.py\n M src/caliper/core/b.py\n?? tests/unit/test_new.py\n"
        assert sut.parse_changed(raw) == [
            "src/caliper/core/a.py",
            "src/caliper/core/b.py",
            "tests/unit/test_a.py",
            "tests/unit/test_new.py",
        ]


class TestDefaultBase:
    def test_lane_worktree_uses_batch_root_head_as_base(self, tmp_path: Path) -> None:
        """Inside a datum lane worktree (<run>-root/.datum/worktrees/<run>/task-NNN) the diff
        base is the batch root's HEAD, i.e. the epic branch at batch start, not main."""
        root = tmp_path / "20260902-1-root"
        lane = root / ".datum" / "worktrees" / "20260902-1" / "task-003"
        lane.mkdir(parents=True)
        (root / ".git").write_text("gitdir: elsewhere\n")
        assert sut.lane_batch_root(lane) == root
        assert sut.lane_batch_root(tmp_path / "plain" / "checkout") is None

    def test_env_override_wins(self, monkeypatch) -> None:
        monkeypatch.setenv("CALIPER_TEST_BASE", "abc123")
        assert sut.default_base(Path("/nowhere"), git=lambda *a: "") == "abc123"
