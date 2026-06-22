"""Tests for opengrep runner — binary name and local-only rules.
# tested-by: tests/unit/test_opengrep_runner.py
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from caliper.plugins._runners.semgrep_runner import run_semgrep


class TestOpengrepBinaryName:
    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_uses_opengrep_binary(self, mock_run):
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "opengrep"
        assert "semgrep" not in cmd[0]


class TestRegistryAndLocalRules:
    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_includes_default_registry_rulesets(self, mock_run):
        """p/default and p/ci should always be present for max coverage."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert "p/default" in config_values
        assert "p/ci" in config_values

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_python_file_adds_python_ruleset(self, mock_run):
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert "p/python" in config_values

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_uses_local_policies_dir(self, mock_run):
        """Should use policies/semgrep/ when it exists."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        repo = str(Path(__file__).resolve().parent.parent.parent)
        run_semgrep(["app.py"], repo)
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert any("policies/semgrep" in v for v in config_values)


class TestExtraConfigDirs:
    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_extra_config_dirs_added(self, mock_run, tmp_path):
        """Extra config dirs from .caliper.yaml appear as --config args."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        extra = tmp_path / "community-rules"
        extra.mkdir()
        (extra / "rule.yaml").touch()
        run_semgrep(["app.py"], "/workspace", extra_config_dirs=[str(extra)])
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert str(extra) in config_values

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_extra_config_dir_missing_is_skipped(self, mock_run):
        """Non-existent extra config dirs are silently skipped."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace", extra_config_dirs=["/no/such/dir"])
        cmd = mock_run.call_args[0][0]
        config_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--config"]
        assert "/no/such/dir" not in config_values


class TestFailClosedOnAbort:
    """Issue #396 — opengrep aborting the whole scan must fail CLOSED.

    When opengrep exits with code >= 2 it can still print valid JSON with
    empty results and level=error entries (e.g. one broken symlink in the
    target list aborts the entire scan). That must never look like a clean
    scan to the caller.
    """

    _ABORT_STDOUT = (
        '{"results": [], "errors": [{"code": 2, "level": "error", '
        '"type": "SemgrepError", '
        '"message": "File not found: .antigravitycli/dead.json"}]}'
    )

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_abort_with_fatal_exit_code_sets_status_error(self, mock_run):
        """returncode 2 + empty results + level=error -> status error, never clean."""
        mock_run.return_value.stdout = self._ABORT_STDOUT
        mock_run.return_value.returncode = 2
        data = run_semgrep(["app.py"], "/workspace")
        assert data.get("status") == "error"
        assert data["results"] == []
        assert data["errors"], "fail-closed result must carry an error entry"
        assert "File not found" in data["errors"][0]["message"]

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_fatal_exit_code_without_error_entries_sets_status_error(self, mock_run):
        """returncode >= 2 fails closed even when the JSON errors list is empty."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 2
        data = run_semgrep(["app.py"], "/workspace")
        assert data.get("status") == "error"
        assert data["errors"], "fail-closed result must carry an error entry"

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_zero_results_with_fatal_errors_sets_status_error(self, mock_run):
        """Empty results + level=error entries fail closed even if exit code is 0."""
        mock_run.return_value.stdout = self._ABORT_STDOUT
        mock_run.return_value.returncode = 0
        data = run_semgrep(["app.py"], "/workspace")
        assert data.get("status") == "error"

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_clean_scan_stays_clean(self, mock_run):
        """No findings, no errors, exit 0 -> genuinely clean, no status injected."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        data = run_semgrep(["app.py"], "/workspace")
        assert data.get("status") is None
        assert data["results"] == []

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_warn_level_errors_with_zero_results_stay_clean(self, mock_run):
        """Non-fatal (level=warn) errors with zero results are not an abort."""
        mock_run.return_value.stdout = (
            '{"results": [], "errors": [{"level": "warn", "message": "skipped file"}]}'
        )
        mock_run.return_value.returncode = 0
        data = run_semgrep(["app.py"], "/workspace")
        assert data.get("status") is None

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_partial_scan_with_findings_keeps_findings(self, mock_run):
        """Per-file level=error entries alongside real findings: scan ran, keep results."""
        mock_run.return_value.stdout = (
            '{"results": [{"check_id": "rule-x", "path": "a.py"}], '
            '"errors": [{"level": "error", "message": "parse error: b.py"}]}'
        )
        mock_run.return_value.returncode = 0
        data = run_semgrep(["app.py"], "/workspace")
        assert data.get("status") is None
        assert len(data["results"]) == 1


class TestExcludeRules:
    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_exclude_rules_passed_to_cli(self, mock_run):
        """Excluded rule IDs are passed as --exclude-rule flags."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(
            ["app.py"],
            "/workspace",
            exclude_rules=["path-traversal", "unvalidated-path-construction"],
        )
        cmd = mock_run.call_args[0][0]
        exclude_values = [cmd[i + 1] for i, v in enumerate(cmd) if v == "--exclude-rule"]
        assert "path-traversal" in exclude_values
        assert "unvalidated-path-construction" in exclude_values

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_no_exclude_rules_by_default(self, mock_run):
        """No --exclude-rule flags when list is empty/None."""
        mock_run.return_value.stdout = '{"results": [], "errors": []}'
        mock_run.return_value.returncode = 0
        run_semgrep(["app.py"], "/workspace")
        cmd = mock_run.call_args[0][0]
        assert "--exclude-rule" not in cmd

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_exclude_rules_post_filter_prefixed_ids(self, mock_run):
        """Local-rule ids get dotted path prefixes (e.g. policies.semgrep.X);
        post-filter must drop them when the bare rule id is excluded."""
        mock_run.return_value.stdout = (
            '{"results": ['
            '{"check_id": "policies.semgrep.path-traversal", "path": "a.py"},'
            '{"check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "path": "a.py"},'
            '{"check_id": "policies.semgrep.sql-injection", "path": "a.py"}'
            '], "errors": []}'
        )
        mock_run.return_value.returncode = 0
        data = run_semgrep(["a.py"], "/workspace", exclude_rules=["path-traversal"])
        ids = [r["check_id"] for r in data["results"]]
        assert "policies.semgrep.path-traversal" not in ids
        assert "policies.semgrep.sql-injection" in ids
        assert any("subprocess-shell-true" in i for i in ids)

    @patch("caliper.plugins._runners.semgrep_runner.subprocess.run")
    def test_exclude_rules_post_filter_exact_and_suffix(self, mock_run):
        """Exclusion matches the full check_id or its trailing dotted segment,
        never a bare substring (excluding 'traversal' must not drop path-traversal)."""
        mock_run.return_value.stdout = (
            '{"results": ['
            '{"check_id": "policies.semgrep.path-traversal", "path": "a.py"},'
            '{"check_id": "unsafe-deserialization", "path": "a.py"}'
            '], "errors": []}'
        )
        mock_run.return_value.returncode = 0
        data = run_semgrep(
            ["a.py"], "/workspace", exclude_rules=["traversal", "unsafe-deserialization"]
        )
        ids = [r["check_id"] for r in data["results"]]
        assert "policies.semgrep.path-traversal" in ids  # substring must NOT match
        assert "unsafe-deserialization" not in ids  # exact bare id matches
