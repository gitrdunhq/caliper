"""Tests for cfn-nag plugin.
# tested-by: tests/unit/test_cfn_nag_plugin.py
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from caliper.core.plugin import PluginCategory
from caliper.plugins.cfn_nag import CfnNagPlugin

# Realistic cfn-nag JSON output with one FAIL and one WARN
CFN_NAG_OUTPUT = json.dumps(
    [
        {
            "filename": "template.yaml",
            "file_results": {
                "security_groups": [],
                "violations": [
                    {
                        "id": "F3",
                        "type": "FAIL",
                        "message": "IAM role should not allow * action on its permissions policy",
                        "logical_resource_ids": ["MyRole"],
                        "line_numbers": [10],
                    },
                    {
                        "id": "W9",
                        "type": "WARN",
                        "message": "Security Groups found with ingress cidr that is not /32 or /128",
                        "logical_resource_ids": ["MySG"],
                        "line_numbers": [25],
                    },
                ],
            },
        }
    ]
)

CFN_NAG_CLEAN_OUTPUT = json.dumps(
    [
        {
            "filename": "template.yaml",
            "file_results": {
                "security_groups": [],
                "violations": [],
            },
        }
    ]
)


class TestCfnNagPluginProperties:
    def test_name(self):
        p = CfnNagPlugin()
        assert p.name == "cfn-nag"

    def test_description(self):
        p = CfnNagPlugin()
        assert "CloudFormation" in p.description or "cfn" in p.description.lower()

    def test_category_is_infra(self):
        p = CfnNagPlugin()
        assert p.category == PluginCategory.infra


class TestCfnNagPluginCanRun:
    def test_can_run_yaml_cfn_template(self, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
        p = CfnNagPlugin()
        assert p.can_run([str(template)], tmp_path) is True

    def test_can_run_json_cfn_template(self, tmp_path):
        template = tmp_path / "template.json"
        template.write_text(json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}))
        p = CfnNagPlugin()
        assert p.can_run([str(template)], tmp_path) is True

    def test_can_run_yml_extension(self, tmp_path):
        template = tmp_path / "stack.yml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
        p = CfnNagPlugin()
        assert p.can_run([str(template)], tmp_path) is True

    def test_cannot_run_non_cfn_yaml(self, tmp_path):
        manifest = tmp_path / "docker-compose.yaml"
        manifest.write_text("version: '3'\nservices:\n  web:\n    image: nginx\n")
        p = CfnNagPlugin()
        assert p.can_run([str(manifest)], tmp_path) is False

    def test_cannot_run_python_file(self, tmp_path):
        pyfile = tmp_path / "app.py"
        pyfile.write_text("print('hello')\n")
        p = CfnNagPlugin()
        assert p.can_run([str(pyfile)], tmp_path) is False

    def test_can_run_with_resources_marker(self, tmp_path):
        """File with only 'Resources:' (no AWSTemplateFormatVersion) still qualifies."""
        template = tmp_path / "partial.yaml"
        template.write_text("Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n")
        p = CfnNagPlugin()
        assert p.can_run([str(template)], tmp_path) is True

    def test_cannot_run_empty_file_list(self, tmp_path):
        p = CfnNagPlugin()
        assert p.can_run([], tmp_path) is False

    def test_can_run_nonexistent_file(self, tmp_path):
        """Nonexistent file cannot be verified as CFN — returns False."""
        p = CfnNagPlugin()
        assert p.can_run([str(tmp_path / "ghost.yaml")], tmp_path) is False


class TestCfnNagPluginRun:
    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_findings_parsed_correctly(self, mock_run, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = CFN_NAG_OUTPUT

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 2

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_fail_type_maps_to_critical_severity(self, mock_run, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = CFN_NAG_OUTPUT

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        fail_findings = [f for f in result.findings if f.get("rule_id") == "F3"]
        assert len(fail_findings) == 1
        assert fail_findings[0]["severity"] == "critical"

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_warn_type_maps_to_warning_severity(self, mock_run, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = CFN_NAG_OUTPUT

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        warn_findings = [f for f in result.findings if f.get("rule_id") == "W9"]
        assert len(warn_findings) == 1
        assert warn_findings[0]["severity"] == "warning"

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_finding_has_message_and_file(self, mock_run, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = CFN_NAG_OUTPUT

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        f0 = result.findings[0]
        assert "message" in f0
        assert "file" in f0
        assert f0["message"] != ""

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_clean_scan_no_findings(self, mock_run, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = CFN_NAG_CLEAN_OUTPUT

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert result.error == ""
        assert len(result.findings) == 0

    @patch(
        "caliper.plugins._runners.cfn_nag_runner.subprocess.run",
        side_effect=FileNotFoundError,
    )
    def test_not_installed_error(self, _mock, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert "NOT_INSTALLED" in result.error

    @patch(
        "caliper.plugins._runners.cfn_nag_runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="cfn_nag_scan", timeout=60),
    )
    def test_timeout_error(self, _mock, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert "TIMEOUT" in result.error

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_summary_contains_totals(self, mock_run, tmp_path):
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = CFN_NAG_OUTPUT

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert "total" in result.summary
        assert result.summary["total"] == 2

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_crashed_with_empty_stdout_returns_error(self, mock_run, tmp_path):
        """Non-zero exit + empty stdout must report an error, not a clean scan."""
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = "cfn_nag_scan: command failed"

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert "BINARY_CRASHED" in result.error
        assert result.findings == []

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_crashed_with_invalid_json_returns_error(self, mock_run, tmp_path):
        """Non-zero exit + non-JSON stdout must report an error, not a clean scan."""
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = "Traceback (most recent call last):\n  RuntimeError: boom"
        mock_run.return_value.stderr = ""

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert "BINARY_CRASHED" in result.error
        assert result.findings == []

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_exit_zero_malformed_json_returns_error(self, mock_run, tmp_path):
        """Exit 0 + malformed JSON stdout must NOT produce empty findings."""
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "not valid json at all"
        mock_run.return_value.stderr = ""

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert result.error, "Malformed JSON on exit-0 must report error, not silently return clean"

    @patch("caliper.plugins._runners.cfn_nag_runner.subprocess.run")
    def test_exit_zero_empty_stdout_returns_error(self, mock_run, tmp_path):
        """Exit 0 + empty stdout must NOT produce empty findings."""
        template = tmp_path / "template.yaml"
        template.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = ""
        mock_run.return_value.stderr = ""

        p = CfnNagPlugin()
        result = p.run([str(template)], tmp_path)

        assert result.error, "Empty stdout on exit-0 must report error, not silently return clean"
