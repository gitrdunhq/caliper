"""Tests for ``caliper part --push`` — the stacked PR push CLI wiring (#524).

# tested-by: tests/unit/test_part_push_cli.py

Guards are pure CLI-arg checks (no network). The success/failure-path tests
monkeypatch ``resolve_pr``, ``run_part``, and ``part_push.run_push`` so no
real git/gh/network is ever touched — this file proves the CLI wiring (echo
order, exit codes), not the underlying push mechanics (covered by
test_part_push.py) or PR resolution (test_part_pr.py).
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from caliper.cli.part_cmd import part
from caliper.cli.part_pipeline import PartRunResult
from caliper.cli.part_pr import ResolvedPr
from caliper.cli.part_push import StackPushResult
from caliper.core.models import ChangeType, CutList, CutStats, Kerf, Part, Provenance


def _part(bucket: ChangeType, *files: str) -> Part:
    return Part(id="p", files=sorted(files), bucket=bucket, size=1, opened_by=Kerf(fired_rule="r"))


def _cutlist(*parts: Part) -> CutList:
    prov = Provenance(
        caliper_version="0", base_sha="b", head_sha="h", rename_threshold=50, config_digest="d"
    )
    stats = CutStats(
        part_count=len(parts), file_count=0, size_p50=0, size_p90=0, move_logic_pure=True
    )
    return CutList(parts=list(parts), provenance=prov, stats=stats)


def _resolved(tmp_path: Path) -> ResolvedPr:
    return ResolvedPr(
        repo_path=tmp_path,
        base="basesha",
        head="headsha",
        slug="owner/repo",
        number=524,
        workdir=tmp_path,
        out_dir=tmp_path / "out",
        override_store=tmp_path / "overrides",
        previous_cutlist=None,
        base_branch="main",
    )


def _run_result(cut: CutList) -> PartRunResult:
    return PartRunResult(
        cutlist=cut,
        script_text="",
        backup_bookmark="bk",
        rescue_op_id="rid",
        jj_version="",
        can_reconstruct=True,
        subjects={},
        proposed_overrides=[],
        applied_overrides=[],
        restack_path=str(Path("restack.sh")),
        cutlist_path=None,
    )


class TestUsageGuards:
    def test_push_without_pr_raises(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(part, ["--push", "--repo", str(tmp_path)])
        assert result.exit_code != 0
        assert "--push requires --pr" in result.output

    def test_push_with_serve_raises(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            part, ["--push", "--pr", "1", "--serve", "--repo", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "--push" in result.output and "--serve" in result.output

    def test_push_with_target_series_raises(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            part, ["--push", "--pr", "1", "--target", "series", "--repo", str(tmp_path)]
        )
        assert result.exit_code != 0
        assert "--push" in result.output and "series" in result.output


class TestPushSuccess:
    def test_echoes_opened_urls_in_stack_order_and_exits_zero(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        cut = _cutlist(_part(ChangeType.business, "a.py"), _part(ChangeType.logic, "b.py"))
        resolved = _resolved(tmp_path)
        run_result = _run_result(cut)
        urls = ["https://github.com/o/r/pull/1", "https://github.com/o/r/pull/2"]

        monkeypatch.setattr("caliper.cli.part_pr.resolve_pr", lambda *a, **k: resolved)
        monkeypatch.setattr("caliper.cli.part_pr.detect_origin_slug", lambda *a, **k: "owner/repo")
        monkeypatch.setattr("caliper.cli.part_cmd.run_part", lambda *a, **k: run_result)
        monkeypatch.setattr(
            "caliper.cli.part_push.run_push",
            lambda **k: StackPushResult(opened_urls=urls, comment_posted=True),
        )

        result = CliRunner().invoke(part, ["--push", "--pr", "524", "--repo", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert urls[0] in result.output
        assert urls[1] in result.output
        assert result.output.index(urls[0]) < result.output.index(urls[1])

    def test_comment_failure_warns_but_still_exits_zero(self, tmp_path: Path, monkeypatch) -> None:
        cut = _cutlist(_part(ChangeType.business, "a.py"))
        resolved = _resolved(tmp_path)
        run_result = _run_result(cut)

        monkeypatch.setattr("caliper.cli.part_pr.resolve_pr", lambda *a, **k: resolved)
        monkeypatch.setattr("caliper.cli.part_pr.detect_origin_slug", lambda *a, **k: "owner/repo")
        monkeypatch.setattr("caliper.cli.part_cmd.run_part", lambda *a, **k: run_result)
        monkeypatch.setattr(
            "caliper.cli.part_push.run_push",
            lambda **k: StackPushResult(
                opened_urls=["https://github.com/o/r/pull/1"], comment_posted=False
            ),
        )

        result = CliRunner().invoke(part, ["--push", "--pr", "524", "--repo", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert "warning" in result.output.lower()


class TestPushPartialFailure:
    def test_echoes_succeeded_urls_then_failure_and_exits_nonzero(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        cut = _cutlist(_part(ChangeType.business, "a.py"), _part(ChangeType.logic, "b.py"))
        resolved = _resolved(tmp_path)
        run_result = _run_result(cut)

        monkeypatch.setattr("caliper.cli.part_pr.resolve_pr", lambda *a, **k: resolved)
        monkeypatch.setattr("caliper.cli.part_pr.detect_origin_slug", lambda *a, **k: "owner/repo")
        monkeypatch.setattr("caliper.cli.part_cmd.run_part", lambda *a, **k: run_result)
        monkeypatch.setattr(
            "caliper.cli.part_push.run_push",
            lambda **k: StackPushResult(
                opened_urls=["https://github.com/o/r/pull/1"],
                failed_index=2,
                error="push failed for part 2/2 (caliper-pr524-02-logic): boom",
            ),
        )

        result = CliRunner().invoke(part, ["--push", "--pr", "524", "--repo", str(tmp_path)])

        assert result.exit_code != 0
        assert "https://github.com/o/r/pull/1" in result.output
        assert "part 2" in result.output or "2" in result.output
        assert "boom" in result.output

    def test_materialize_failure_reported_and_exits_nonzero(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        cut = _cutlist(_part(ChangeType.business, "a.py"))
        resolved = _resolved(tmp_path)
        run_result = _run_result(cut)

        monkeypatch.setattr("caliper.cli.part_pr.resolve_pr", lambda *a, **k: resolved)
        monkeypatch.setattr("caliper.cli.part_pr.detect_origin_slug", lambda *a, **k: "owner/repo")
        monkeypatch.setattr("caliper.cli.part_cmd.run_part", lambda *a, **k: run_result)
        # run_push returns None on a materialize_parts failure.
        monkeypatch.setattr("caliper.cli.part_push.run_push", lambda **k: None)

        result = CliRunner().invoke(part, ["--push", "--pr", "524", "--repo", str(tmp_path)])

        assert result.exit_code != 0


class TestNoPushFlagUnaffected:
    def test_without_push_no_push_module_is_touched(self, tmp_path: Path, monkeypatch) -> None:
        cut = _cutlist(_part(ChangeType.business, "a.py"))
        resolved = _resolved(tmp_path)
        run_result = _run_result(cut)
        touched = []

        monkeypatch.setattr("caliper.cli.part_pr.resolve_pr", lambda *a, **k: resolved)
        monkeypatch.setattr("caliper.cli.part_pr.detect_origin_slug", lambda *a, **k: "owner/repo")
        monkeypatch.setattr("caliper.cli.part_cmd.run_part", lambda *a, **k: run_result)
        monkeypatch.setattr(
            "caliper.cli.part_push.run_push",
            lambda **k: touched.append(1) or StackPushResult(),
        )

        result = CliRunner().invoke(part, ["--pr", "524", "--repo", str(tmp_path)])

        assert result.exit_code == 0, result.output
        assert touched == []
