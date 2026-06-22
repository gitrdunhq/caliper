"""Tests for cdk-nag plugin.
# tested-by: tests/unit/test_cdk_nag_plugin.py
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from caliper.core.plugin import PluginCategory

RUNNER_PATH = "caliper.plugins._runners.cdk_nag_runner"

CFN_NAG_OUTPUT = json.dumps(
    [
        {
            "filename": "cdk.out/MyStack.template.json",
            "file_results": {
                "violations": [
                    {
                        "type": "FAIL",
                        "id": "W28",
                        "message": "Resource found with an explicit name",
                        "logical_resource_ids": ["MyBucket"],
                        "line_numbers": [10],
                    },
                    {
                        "type": "WARN",
                        "id": "W35",
                        "message": "S3 Bucket should have access logging configured",
                        "logical_resource_ids": ["MyBucket"],
                        "line_numbers": [15],
                    },
                ],
                "failure_count": 1,
            },
        }
    ]
)

CLEAN_OUTPUT = json.dumps(
    [
        {
            "filename": "cdk.out/MyStack.template.json",
            "file_results": {"violations": [], "failure_count": 0},
        }
    ]
)


class TestCdkNagPlugin:
    def test_name(self):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        p = CdkNagPlugin()
        assert p.name == "cdk-nag"

    def test_description(self):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        p = CdkNagPlugin()
        assert "CDK" in p.description
        assert "CloudFormation" in p.description

    def test_category(self):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        p = CdkNagPlugin()
        assert p.category == PluginCategory.infra

    def test_can_run_with_cdk_json(self, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")
        p = CdkNagPlugin()
        assert p.can_run([], tmp_path) is True

    def test_can_run_with_cdk_out_dir(self, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.out").mkdir()
        p = CdkNagPlugin()
        assert p.can_run([], tmp_path) is True

    def test_cannot_run_without_cdk_files(self, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        p = CdkNagPlugin()
        assert p.can_run([], tmp_path) is False

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_run_with_existing_cdk_out(self, mock_run, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")
        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        template = cdk_out / "MyStack.template.json"
        template.write_text("{}")

        def side_effect(*args, **kwargs):
            cmd = args[0]
            result = MagicMock()
            if "synth" in cmd:
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
            else:
                result.returncode = 0
                result.stdout = CFN_NAG_OUTPUT
            return result

        mock_run.side_effect = side_effect

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 2
        assert result.findings[0]["severity"] == "critical"
        assert result.findings[0]["rule_id"] == "W28"
        assert result.findings[1]["severity"] == "warning"
        assert result.findings[1]["rule_id"] == "W35"
        assert result.summary["total"] == 2

        # synth always called first, then cfn_nag_scan
        assert mock_run.call_count == 2
        first_cmd = mock_run.call_args_list[0][0][0]
        assert "cdk" in first_cmd
        assert "synth" in first_cmd
        second_cmd = mock_run.call_args_list[1][0][0]
        assert "cfn_nag_scan" in second_cmd

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_run_triggers_cdk_synth_when_no_cdk_out(self, mock_run, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")

        def synth_side_effect(*args, **kwargs):
            cmd = args[0]
            result = MagicMock()
            if "synth" in cmd:
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
                cdk_out = tmp_path / "cdk.out"
                cdk_out.mkdir(exist_ok=True)
                (cdk_out / "MyStack.template.json").write_text("{}")
            else:
                result.returncode = 0
                result.stdout = CFN_NAG_OUTPUT
            return result

        mock_run.side_effect = synth_side_effect

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error == ""
        assert mock_run.call_count == 2
        first_cmd = mock_run.call_args_list[0][0][0]
        assert "cdk" in first_cmd
        assert "synth" in first_cmd

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_cdk_synth_failure_returns_error(self, mock_run, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")

        synth_result = MagicMock()
        synth_result.returncode = 1
        synth_result.stderr = "Error: Cannot find module 'aws-cdk-lib'"
        mock_run.return_value = synth_result

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error != ""
        assert len(result.findings) == 0

    @patch(f"{RUNNER_PATH}.subprocess.run", side_effect=FileNotFoundError)
    def test_cdk_not_installed(self, _mock, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        # No cdk.out → will attempt cdk synth → FileNotFoundError
        (tmp_path / "cdk.json").write_text("{}")
        p = CdkNagPlugin()
        result = p.run([], tmp_path)
        assert "NOT_INSTALLED" in result.error

    def test_cfn_nag_not_installed(self, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        # synth succeeds, then cfn_nag_scan raises FileNotFoundError
        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "MyStack.template.json").write_text("{}")

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "synth" in cmd:
                result = MagicMock()
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
                return result
            raise FileNotFoundError

        with patch(f"{RUNNER_PATH}.subprocess.run", side_effect=side_effect):
            p = CdkNagPlugin()
            result = p.run([], tmp_path)
            assert "NOT_INSTALLED" in result.error

    def test_cdk_synth_timeout(self, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")

        with patch(
            f"{RUNNER_PATH}.subprocess.run",
            side_effect=subprocess.TimeoutExpired("cdk", 120),
        ):
            p = CdkNagPlugin()
            result = p.run([], tmp_path)
            assert "TIMEOUT" in result.error

    def test_cfn_nag_scan_timeout(self, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        # synth succeeds, then cfn_nag_scan times out
        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "MyStack.template.json").write_text("{}")

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if "synth" in cmd:
                result = MagicMock()
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
                return result
            raise subprocess.TimeoutExpired("cfn_nag_scan", 60)

        with patch(f"{RUNNER_PATH}.subprocess.run", side_effect=side_effect):
            p = CdkNagPlugin()
            result = p.run([], tmp_path)
            assert "TIMEOUT" in result.error

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_clean_scan_no_findings(self, mock_run, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "MyStack.template.json").write_text("{}")

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = CLEAN_OUTPUT
        mock_run.return_value = mock_result

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 0
        assert result.summary["total"] == 0

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_synth_called_when_cdk_json_exists(self, mock_run, tmp_path):
        """Synth must run when cdk.json exists — stale output guard."""
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")
        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "MyStack.template.json").write_text("{}")

        def side_effect(*args, **kwargs):
            cmd = args[0]
            result = MagicMock()
            if "synth" in cmd:
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
            else:
                result.returncode = 0
                result.stdout = CFN_NAG_OUTPUT
            return result

        mock_run.side_effect = side_effect

        p = CdkNagPlugin()
        p.run([], tmp_path)

        assert mock_run.call_count == 2
        first_cmd = mock_run.call_args_list[0][0][0]
        assert "cdk" in first_cmd
        assert "synth" in first_cmd

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_synth_failure_with_existing_cdk_out_returns_error(self, mock_run, tmp_path):
        """Synth failure must return an error even when stale cdk.out/ exists."""
        from caliper.plugins.cdk_nag import CdkNagPlugin

        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "MyStack.template.json").write_text("{}")

        synth_result = MagicMock()
        synth_result.returncode = 1
        synth_result.stderr = "Synthesis failed — missing context"
        mock_run.return_value = synth_result

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error != ""
        assert len(result.findings) == 0

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_no_templates_in_cdk_out(self, mock_run, tmp_path):
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.json").write_text("{}")
        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        # No .template.json files

        synth_result = MagicMock()
        synth_result.returncode = 0
        synth_result.stdout = ""
        synth_result.stderr = ""
        mock_run.return_value = synth_result

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error == ""
        assert result.findings == []
        # synth is called, but cfn_nag_scan is never reached (no templates)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "synth" in cmd

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_scanner_crash_nonzero_exit_returns_error(self, mock_run, tmp_path):
        """cfn_nag_scan non-zero exit + empty stdout during template scan must error."""
        from caliper.plugins.cdk_nag import CdkNagPlugin

        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "Stack.template.json").write_text("{}")

        synth_result = MagicMock()
        synth_result.returncode = 0
        synth_result.stdout = ""
        synth_result.stderr = ""

        scan_result = MagicMock()
        scan_result.returncode = 1
        scan_result.stdout = ""
        scan_result.stderr = "cfn_nag_scan crashed"

        mock_run.side_effect = [synth_result, scan_result]

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert (
            result.error is not None and result.error != ""
        ), "Non-zero exit from cfn_nag_scan must be an error, not a clean pass"

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_assembly_only_skips_synth(self, mock_run, tmp_path):
        """cdk.out/ exists but no cdk.json → scan templates without running cdk synth."""
        from caliper.plugins.cdk_nag import CdkNagPlugin

        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "MyStack.template.json").write_text("{}")

        scan_result = MagicMock()
        scan_result.returncode = 0
        scan_result.stdout = CFN_NAG_OUTPUT
        mock_run.return_value = scan_result

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 2
        assert mock_run.call_count == 1
        cmd = mock_run.call_args[0][0]
        assert "cfn_nag_scan" in cmd
        assert "cdk" not in cmd or "synth" not in cmd

    def test_assembly_only_no_templates_returns_empty(self, tmp_path):
        """cdk.out/ exists with no templates and no cdk.json → no findings, no error."""
        from caliper.plugins.cdk_nag import CdkNagPlugin

        (tmp_path / "cdk.out").mkdir()

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert result.findings == []
        assert result.error == ""

    @patch(f"{RUNNER_PATH}.subprocess.run")
    def test_scanner_malformed_json_returns_error(self, mock_run, tmp_path):
        """cfn_nag_scan exit-0 + malformed JSON during template scan must error."""
        from caliper.plugins.cdk_nag import CdkNagPlugin

        cdk_out = tmp_path / "cdk.out"
        cdk_out.mkdir()
        (cdk_out / "Stack.template.json").write_text("{}")

        synth_result = MagicMock()
        synth_result.returncode = 0
        synth_result.stdout = ""
        synth_result.stderr = ""

        scan_result = MagicMock()
        scan_result.returncode = 0
        scan_result.stdout = "not valid json"
        scan_result.stderr = ""

        mock_run.side_effect = [synth_result, scan_result]

        p = CdkNagPlugin()
        result = p.run([], tmp_path)

        assert (
            result.error is not None and result.error != ""
        ), "Malformed JSON from cfn_nag_scan must be an error, not a clean pass"
