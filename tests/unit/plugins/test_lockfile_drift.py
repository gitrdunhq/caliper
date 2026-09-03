"""LockfileDriftPlugin — manifest changed without its lockfile.
# tested-by: tests/unit/plugins/test_lockfile_drift.py

A manifest (package.json, pyproject.toml, Cargo.toml, go.mod, Pipfile) that
appears in the change set while a lockfile paired with it exists on disk but
is NOT in the change set means the resolved dependency set no longer matches
the manifest. The plugin is pure filesystem inspection: no binary, no
subprocess, never raises.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from caliper.core.plugin import PluginCategory, PluginResult
from caliper.plugins.lockfile_drift import LockfileDriftPlugin

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _touch(root: Path, rel: str, content: str = "x\n") -> Path:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return target


def _plugin() -> LockfileDriftPlugin:
    return LockfileDriftPlugin()


def _only_finding(result: PluginResult) -> dict:
    assert result.error == "", result.error
    assert len(result.findings) == 1, result.findings
    return result.findings[0]


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_name_description_category() -> None:
    plugin = _plugin()
    assert plugin.name == "lockfile-drift"
    assert plugin.description == "Manifest changed without its lockfile"
    assert plugin.category == PluginCategory.supply_chain


def test_accepts_settings_kwarg_for_symmetry() -> None:
    from caliper.core.config import CaliperSettings

    plugin = LockfileDriftPlugin(settings=CaliperSettings())
    assert plugin.name == "lockfile-drift"


# ---------------------------------------------------------------------------
# can_run
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest",
    ["package.json", "pyproject.toml", "Cargo.toml", "go.mod", "Pipfile"],
)
def test_can_run_true_when_a_changed_file_is_a_manifest(tmp_path: Path, manifest: str) -> None:
    assert _plugin().can_run([manifest], tmp_path) is True


def test_can_run_true_for_nested_manifest(tmp_path: Path) -> None:
    assert _plugin().can_run(["src/app.py", "services/api/pyproject.toml"], tmp_path) is True


def test_can_run_false_when_no_manifest_changed(tmp_path: Path) -> None:
    assert _plugin().can_run(["src/app.py", "README.md", "uv.lock"], tmp_path) is False


def test_can_run_false_for_empty_change_set(tmp_path: Path) -> None:
    assert _plugin().can_run([], tmp_path) is False


def test_can_run_false_for_lookalike_names(tmp_path: Path) -> None:
    # Basename must match exactly; suffix/prefix variants are not manifests.
    assert _plugin().can_run(["package.json.bak", "my-pyproject.toml"], tmp_path) is False


# ---------------------------------------------------------------------------
# run — core behaviour
# ---------------------------------------------------------------------------


def test_manifest_and_lockfile_both_changed_no_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "pyproject.toml")
    _touch(tmp_path, "uv.lock")

    result = _plugin().run(["pyproject.toml", "uv.lock"], tmp_path)

    assert result.error == ""
    assert result.findings == []
    assert result.summary == {"total": 0}


def test_manifest_changed_lockfile_on_disk_unchanged_one_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "pyproject.toml")
    _touch(tmp_path, "uv.lock")

    result = _plugin().run(["pyproject.toml", "src/app.py"], tmp_path)

    finding = _only_finding(result)
    assert finding["file"] == "pyproject.toml"
    assert finding["line"] == 1
    assert finding["rule_id"] == "lockfile-drift"
    assert finding["severity"] == "medium"
    assert "pyproject.toml" in finding["message"]
    assert "uv.lock" in finding["message"]
    assert "uv.lock" in finding["fix_suggestion"]
    assert result.plugin_name == "lockfile-drift"
    assert result.summary == {"total": 1}


def test_finding_message_and_fix_match_spec_wording(tmp_path: Path) -> None:
    _touch(tmp_path, "Cargo.toml")
    _touch(tmp_path, "Cargo.lock")

    finding = _only_finding(_plugin().run(["Cargo.toml"], tmp_path))

    assert finding["message"] == (
        "Cargo.toml changed but Cargo.lock did not; "
        "the resolved dependency set no longer matches the manifest"
    )
    assert finding["fix_suggestion"] == "Regenerate Cargo.lock and commit it with the manifest"


def test_manifest_changed_no_lockfile_on_disk_no_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "package.json")

    result = _plugin().run(["package.json"], tmp_path)

    assert result.error == ""
    assert result.findings == []
    assert result.summary == {"total": 0}


def test_two_candidates_names_the_present_lockfile(tmp_path: Path) -> None:
    _touch(tmp_path, "package.json")
    _touch(tmp_path, "yarn.lock")
    # package-lock.json deliberately absent

    finding = _only_finding(_plugin().run(["package.json"], tmp_path))

    assert "yarn.lock" in finding["message"]
    assert "package-lock.json" not in finding["message"]
    assert "yarn.lock" in finding["fix_suggestion"]


def test_two_candidates_one_changed_no_finding(tmp_path: Path) -> None:
    # Only the lockfile that exists must be in the change set.
    _touch(tmp_path, "package.json")
    _touch(tmp_path, "yarn.lock")

    result = _plugin().run(["package.json", "yarn.lock"], tmp_path)

    assert result.findings == []


def test_lockfile_in_another_directory_does_not_count(tmp_path: Path) -> None:
    # Root manifest changed; a lockfile only exists in a sibling package dir.
    _touch(tmp_path, "pyproject.toml")
    _touch(tmp_path, "services/api/pyproject.toml")
    _touch(tmp_path, "services/api/uv.lock")

    result = _plugin().run(["pyproject.toml"], tmp_path)

    assert result.findings == []


def test_nested_package_dir_finding_uses_nested_relative_path(tmp_path: Path) -> None:
    _touch(tmp_path, "services/api/pyproject.toml")
    _touch(tmp_path, "services/api/uv.lock")

    finding = _only_finding(_plugin().run(["services/api/pyproject.toml"], tmp_path))

    assert finding["file"] == "services/api/pyproject.toml"
    assert (
        "services/api/pyproject.toml" in finding["message"]
        or "pyproject.toml" in finding["message"]
    )
    assert "uv.lock" in finding["message"]


def test_nested_lockfile_changed_no_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "services/api/pyproject.toml")
    _touch(tmp_path, "services/api/uv.lock")

    result = _plugin().run(["services/api/pyproject.toml", "services/api/uv.lock"], tmp_path)

    assert result.findings == []


def test_absolute_and_relative_paths_produce_same_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "services/api/pyproject.toml")
    _touch(tmp_path, "services/api/uv.lock")

    rel = _plugin().run(["services/api/pyproject.toml"], tmp_path)
    absolute = _plugin().run([str(tmp_path / "services/api/pyproject.toml")], tmp_path)

    assert rel.findings == absolute.findings
    assert _only_finding(absolute)["file"] == "services/api/pyproject.toml"


def test_absolute_lockfile_path_in_files_suppresses_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "go.mod")
    _touch(tmp_path, "go.sum")

    result = _plugin().run(["go.mod", str(tmp_path / "go.sum")], tmp_path)

    assert result.findings == []


def test_dot_slash_relative_path_normalized(tmp_path: Path) -> None:
    _touch(tmp_path, "go.mod")
    _touch(tmp_path, "go.sum")

    result = _plugin().run(["./go.mod", "./go.sum"], tmp_path)

    assert result.findings == []


def test_two_changed_manifests_one_with_drift_one_finding(tmp_path: Path) -> None:
    _touch(tmp_path, "pyproject.toml")
    _touch(tmp_path, "uv.lock")
    _touch(tmp_path, "web/package.json")
    _touch(tmp_path, "web/package-lock.json")

    result = _plugin().run(
        ["pyproject.toml", "uv.lock", "web/package.json"],
        tmp_path,
    )

    finding = _only_finding(result)
    assert finding["file"] == "web/package.json"
    assert "package-lock.json" in finding["message"]
    assert result.summary == {"total": 1}


def test_two_changed_manifests_both_drifting_two_findings(tmp_path: Path) -> None:
    _touch(tmp_path, "Pipfile")
    _touch(tmp_path, "Pipfile.lock")
    _touch(tmp_path, "Cargo.toml")
    _touch(tmp_path, "Cargo.lock")

    result = _plugin().run(["Pipfile", "Cargo.toml"], tmp_path)

    assert result.error == ""
    assert {f["file"] for f in result.findings} == {"Pipfile", "Cargo.toml"}
    assert result.summary == {"total": 2}


def test_non_manifest_files_are_ignored(tmp_path: Path) -> None:
    _touch(tmp_path, "pyproject.toml")
    _touch(tmp_path, "uv.lock")

    result = _plugin().run(["src/app.py", "README.md"], tmp_path)

    assert result.findings == []
    assert result.summary == {"total": 0}


def test_summary_total_matches_finding_count(tmp_path: Path) -> None:
    _touch(tmp_path, "a/package.json")
    _touch(tmp_path, "a/pnpm-lock.yaml")
    _touch(tmp_path, "b/package.json")
    _touch(tmp_path, "b/yarn.lock")
    _touch(tmp_path, "c/package.json")

    result = _plugin().run(["a/package.json", "b/package.json", "c/package.json"], tmp_path)

    assert result.summary == {"total": len(result.findings)}
    assert result.summary["total"] == 2


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_exposes_lockfile_drift() -> None:
    import caliper.plugins.lockfile_drift  # noqa: F401  (trigger self-registration)
    from caliper.plugins import ANALYZERS

    assert "lockfile-drift" in list(ANALYZERS.keys())
    assert isinstance(ANALYZERS.create("lockfile-drift"), LockfileDriftPlugin)


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


def test_render_error_names_plugin() -> None:
    rendered = _plugin().render(PluginResult(plugin_name="lockfile-drift", error="boom"))

    assert "lockfile-drift" in rendered
    assert "boom" in rendered


def test_render_no_findings_is_empty_string() -> None:
    rendered = _plugin().render(PluginResult(plugin_name="lockfile-drift", findings=[]))

    assert rendered == ""


def test_render_findings_has_header_and_manifest_path() -> None:
    result = PluginResult(
        plugin_name="lockfile-drift",
        findings=[
            {
                "file": "services/api/pyproject.toml",
                "line": 1,
                "rule_id": "lockfile-drift",
                "severity": "medium",
                "message": "pyproject.toml changed but uv.lock did not; "
                "the resolved dependency set no longer matches the manifest",
                "fix_suggestion": "Regenerate uv.lock and commit it with the manifest",
            }
        ],
        summary={"total": 1},
    )

    rendered = _plugin().render(result)

    assert "Lockfile drift" in rendered
    assert "(1)" in rendered
    assert "services/api/pyproject.toml" in rendered


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestProperties:
    """Domain: Determinism (INVARIANT), Availability / fail-open (LIVENESS)."""

    def test_determinism_same_inputs_identical_findings(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pyproject.toml")
        _touch(tmp_path, "uv.lock")
        _touch(tmp_path, "web/package.json")
        _touch(tmp_path, "web/yarn.lock")
        files = ["web/package.json", "pyproject.toml"]

        first = _plugin().run(files, tmp_path)
        second = _plugin().run(files, tmp_path)

        assert first.findings == second.findings
        assert first.summary == second.summary
        assert first.error == second.error == ""

    def test_determinism_independent_of_input_order(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pyproject.toml")
        _touch(tmp_path, "uv.lock")
        _touch(tmp_path, "web/package.json")
        _touch(tmp_path, "web/yarn.lock")

        forward = _plugin().run(["pyproject.toml", "web/package.json"], tmp_path)
        backward = _plugin().run(["web/package.json", "pyproject.toml"], tmp_path)

        assert sorted(f["file"] for f in forward.findings) == sorted(
            f["file"] for f in backward.findings
        )

    def test_fail_open_missing_repo_path_returns_result(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"

        result = _plugin().run(["pyproject.toml"], missing)

        assert isinstance(result, PluginResult)
        assert result.plugin_name == "lockfile-drift"

    def test_fail_open_can_run_missing_repo_path_never_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"

        assert _plugin().can_run(["pyproject.toml"], missing) in (True, False)

    def test_fail_open_file_outside_repo_never_raises(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        outside = tmp_path / "elsewhere"
        _touch(repo, "pyproject.toml")
        _touch(outside, "pyproject.toml")
        _touch(outside, "uv.lock")

        result = _plugin().run([str(outside / "pyproject.toml"), "../elsewhere/uv.lock"], repo)

        assert isinstance(result, PluginResult)
        assert result.plugin_name == "lockfile-drift"

    def test_fail_open_manifest_listed_but_absent_on_disk(self, tmp_path: Path) -> None:
        # Deleted manifest in the change set: nothing to pair, must not raise.
        result = _plugin().run(["pyproject.toml"], tmp_path)

        assert isinstance(result, PluginResult)
        assert result.error == ""
        assert result.findings == []
