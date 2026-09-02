"""Tests for TrivyPlugin (src/caliper/plugins/trivy.py).
# tested-by: tests/unit/test_trivy_plugin.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from caliper.core.tool_runner import ToolResult
from caliper.plugins.trivy import TrivyPlugin

_TRIVY_OUTPUT = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-32681",
                        "PkgName": "requests",
                        "InstalledVersion": "2.25.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "MEDIUM",
                        "Title": "Proxy-Auth header leak",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-32681",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-00001",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.0",
                        "FixedVersion": "",
                        "Severity": "HIGH",
                        "Title": "No fix available",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-00001",
                    },
                ],
            }
        ],
    }
)

_TRIVY_OUTPUT_MISSING_FIXED = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-00001",
                        "PkgName": "flask",
                        "InstalledVersion": "2.0.0",
                        # FixedVersion key absent entirely
                        "Severity": "CRITICAL",
                        "Title": "RCE in flask",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2025-00001",
                    },
                ],
            }
        ],
    }
)


class TestTrivyPluginFixedVersion:
    """TrivyPlugin findings must include fixed_version from FixedVersion field."""

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_finding_includes_fixed_version_field(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout=_TRIVY_OUTPUT, stderr="", returncode=0)
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        assert all("fixed_version" in f for f in result.findings)

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_fixed_version_populated_when_present(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout=_TRIVY_OUTPUT, stderr="", returncode=0)
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        finding = next(f for f in result.findings if f["id"] == "CVE-2023-32681")
        assert finding["fixed_version"] == "2.31.0"

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_fixed_version_empty_string_when_no_fix_available(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(stdout=_TRIVY_OUTPUT, stderr="", returncode=0)
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        finding = next(f for f in result.findings if f["id"] == "CVE-2024-00001")
        assert finding["fixed_version"] == ""

    @patch("caliper.core.subprocess_runner.subprocess.run")
    def test_fixed_version_empty_string_when_key_absent_in_trivy_output(
        self, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout=_TRIVY_OUTPUT_MISSING_FIXED, stderr="", returncode=0
        )
        plugin = TrivyPlugin()

        result = plugin.run([], Path("/project"))

        finding = result.findings[0]
        assert "fixed_version" in finding
        assert finding["fixed_version"] == ""


class TestTrivySkipDirs:
    """Trivy must pass --skip-dirs for .caliperignore patterns."""

    def test_caliperignore_dirs_become_skip_dirs(self):
        import caliper.plugins.trivy as trivy_mod

        mock_ignore = MagicMock(return_value=[".git/", "tests/e2e/fixtures/", "node_modules/"])
        with patch.object(trivy_mod, "load_ignore_patterns", mock_ignore):
            runner = MagicMock()
            runner.run.return_value = ToolResult(exit_code=0, stdout="{}", stderr="")
            plugin = TrivyPlugin(tool_runner=runner)
            plugin.run([], Path("/workspace"))
        cmd = runner.run.call_args[0][0].cmd
        assert "--skip-dirs" in cmd
        skip_idx = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        skip_vals = [cmd[i + 1] for i in skip_idx]
        assert "tests/e2e/fixtures" in skip_vals
        assert ".git" in skip_vals

    def test_glob_patterns_excluded_from_skip_dirs(self):
        import caliper.plugins.trivy as trivy_mod

        mock_ignore = MagicMock(return_value=["*.egg-info/", "tests/e2e/fixtures/"])
        with patch.object(trivy_mod, "load_ignore_patterns", mock_ignore):
            runner = MagicMock()
            runner.run.return_value = ToolResult(exit_code=0, stdout="{}", stderr="")
            plugin = TrivyPlugin(tool_runner=runner)
            plugin.run([], Path("/workspace"))
        cmd = runner.run.call_args[0][0].cmd
        skip_idx = [i for i, v in enumerate(cmd) if v == "--skip-dirs"]
        skip_vals = [cmd[i + 1] for i in skip_idx]
        assert "*.egg-info" not in skip_vals
        assert "tests/e2e/fixtures" in skip_vals


class TestTrivyPluginExitCode:
    """TrivyPlugin must surface tool failures via exit_code, not just not_installed/timed_out."""

    def test_nonzero_exit_no_stdout_returns_binary_crashed_error(self) -> None:
        """exit_code=2, no stdout → BINARY_CRASHED error (total failure, no partial output)."""
        runner = MagicMock()
        runner.run.return_value = ToolResult(
            exit_code=2, stdout="", stderr="fatal error from trivy"
        )
        plugin = TrivyPlugin(tool_runner=runner)

        result = plugin.run([], Path("/project"))

        assert "BINARY_CRASHED" in result.error

    def test_nonzero_exit_with_stdout_proceeds_with_findings(self) -> None:
        """exit_code=1, stdout present → warn and surface findings (scanner uses non-zero for hits)."""
        runner = MagicMock()
        runner.run.return_value = ToolResult(exit_code=1, stdout=_TRIVY_OUTPUT, stderr="")
        plugin = TrivyPlugin(tool_runner=runner)

        result = plugin.run([], Path("/project"))

        assert result.error == ""
        assert len(result.findings) == 2


_TRIVY_OUTPUT_MISCONFIG = json.dumps(
    {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "template.yaml",
                "Class": "config",
                "Type": "cloudformation",
                "Misconfigurations": [
                    {
                        "ID": "AVD-AWS-0088",
                        "AVDID": "AVD-AWS-0088",
                        "Title": "Unencrypted S3 bucket.",
                        "Description": "S3 Buckets should be encrypted.",
                        "Message": "Bucket does not have encryption enabled",
                        "Resolution": "Configure bucket encryption",
                        "Severity": "HIGH",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0088",
                        "Status": "FAIL",
                        "CauseMetadata": {
                            "Resource": "InsecureBucket",
                            "StartLine": 12,
                            "EndLine": 18,
                        },
                    },
                    {
                        "ID": "AVD-AWS-0090",
                        "Title": "Versioning disabled.",
                        "Severity": "MEDIUM",
                        "Status": "PASS",
                        "CauseMetadata": {"StartLine": 12},
                    },
                ],
            },
            {
                "Target": "deployment.yaml",
                "Class": "config",
                "Type": "kubernetes",
                "Misconfigurations": [
                    {
                        "ID": "KSV012",
                        "Title": "Runs as root user",
                        "Message": "Container should set runAsNonRoot",
                        "Resolution": "Set securityContext.runAsNonRoot to true",
                        "Severity": "MEDIUM",
                        "PrimaryURL": "https://avd.aquasec.com/misconfig/ksv012",
                        "Status": "FAIL",
                        "CauseMetadata": {"StartLine": 20, "EndLine": 24},
                    }
                ],
            },
        ],
    }
)


class TestTrivyMisconfig:
    """Trivy also scans IaC (CloudFormation, Terraform, K8s, Dockerfile) for misconfigurations.

    This replaces cfn-nag (a Ruby gem) and cdk-nag (Node + aws-cdk) with a binary
    the image already carries.
    """

    @staticmethod
    def _plugin_with(stdout: str):
        runner = MagicMock()
        runner.run.return_value = ToolResult(
            stdout=stdout, stderr="", exit_code=0, timed_out=False, not_installed=False
        )
        return TrivyPlugin(tool_runner=runner), runner

    def test_scanners_include_misconfig(self) -> None:
        plugin, runner = self._plugin_with(_TRIVY_OUTPUT)
        plugin.run([], Path("/repo"))
        cmd = runner.run.call_args[0][0].cmd
        i = cmd.index("--scanners")
        assert set(cmd[i + 1].split(",")) == {"vuln", "misconfig"}

    def test_failed_misconfigurations_become_findings_with_file_and_line(self) -> None:
        plugin, _ = self._plugin_with(_TRIVY_OUTPUT_MISCONFIG)
        result = plugin.run([], Path("/repo"))
        assert result.error == ""
        by_id = {f["id"]: f for f in result.findings}
        assert "AVD-AWS-0090" not in by_id, "PASS status must not be reported"
        s3 = by_id["AVD-AWS-0088"]
        assert s3["file"] == "template.yaml"
        assert s3["line"] == 12
        assert s3["severity"] == "high"
        assert s3["category"] == "security"
        assert s3["rule_id"] == "AVD-AWS-0088"
        assert "encryption" in s3["message"].lower()
        assert s3["fix_suggestion"] == "Configure bucket encryption"
        k8s = by_id["KSV012"]
        assert k8s["file"] == "deployment.yaml" and k8s["line"] == 20

    def test_summary_counts_vulns_and_misconfigs_separately(self) -> None:
        plugin, _ = self._plugin_with(_TRIVY_OUTPUT_MISCONFIG)
        result = plugin.run([], Path("/repo"))
        assert result.summary["misconfigurations"] == 2
        assert result.summary["vulnerabilities"] == 0
        assert result.summary["total"] == 2

    def test_vuln_only_output_still_works(self) -> None:
        plugin, _ = self._plugin_with(_TRIVY_OUTPUT)
        result = plugin.run([], Path("/repo"))
        assert result.summary["vulnerabilities"] == 2
        assert result.summary["misconfigurations"] == 0


# ---------------------------------------------------------------------------
# task-015: trivy/osv-scanner findings carry db_version/db_updated_at metadata
# ---------------------------------------------------------------------------

_TRIVY_DB_VERSION_OUTPUT = json.dumps(
    {
        "Version": "0.48.0",
        "VulnerabilityDB": {
            "Version": 2,
            "UpdatedAt": "2026-01-01T06:08:37Z",
            "NextUpdate": "2026-01-01T12:08:37Z",
        },
    }
)


class TestTrivyDbUpdatedAtMetadata:
    """AC1: every trivy Finding has metadata['db_updated_at'] set from trivy's

    DB metadata output (ISO8601 string) when available, else None.
    """

    @staticmethod
    def _plugin_with_db_metadata(scan_output: str, version_output: str | None):
        runner = MagicMock()

        def side_effect(invocation):
            if "version" in invocation.cmd:
                if version_output is None:
                    return ToolResult(exit_code=1, stdout="", stderr="db metadata unavailable")
                return ToolResult(exit_code=0, stdout=version_output, stderr="")
            return ToolResult(exit_code=0, stdout=scan_output, stderr="")

        runner.run.side_effect = side_effect
        return TrivyPlugin(tool_runner=runner), runner

    def test_every_finding_has_db_updated_at_from_trivy_db_metadata(self) -> None:
        from caliper.core.plugin import normalize_finding

        plugin, _ = self._plugin_with_db_metadata(_TRIVY_OUTPUT, _TRIVY_DB_VERSION_OUTPUT)
        result = plugin.run([], Path("/project"))

        assert len(result.findings) == 2
        for raw in result.findings:
            finding = normalize_finding(raw)
            assert finding.metadata.get("db_updated_at") == "2026-01-01T06:08:37Z"

    def test_db_updated_at_is_none_when_db_metadata_unavailable(self) -> None:
        from caliper.core.plugin import normalize_finding

        plugin, _ = self._plugin_with_db_metadata(_TRIVY_OUTPUT, None)
        result = plugin.run([], Path("/project"))

        assert len(result.findings) == 2
        for raw in result.findings:
            finding = normalize_finding(raw)
            assert "db_updated_at" in finding.metadata
            assert finding.metadata["db_updated_at"] is None


class TestOsvScannerDbUpdatedAtMetadata:
    """AC2: every osv-scanner Finding has metadata['db_updated_at'] set from

    the OSV DB/output timestamp when available, else None.
    """

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_finding_has_db_updated_at_from_vuln_modified_field(self, mock_run: MagicMock) -> None:
        from caliper.core.plugin import normalize_finding
        from caliper.plugins.osv_scanner import OsvScannerPlugin

        output = json.dumps(
            {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {
                                    "name": "flask",
                                    "version": "2.0.0",
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-abcd-1234",
                                        "summary": "RCE in flask",
                                        "modified": "2026-02-01T00:00:00Z",
                                        "database_specific": {"severity": "HIGH"},
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
        plugin = OsvScannerPlugin()

        result = plugin.run(["requirements.txt"], Path("/project"))

        assert len(result.findings) == 1
        finding = normalize_finding(result.findings[0])
        assert finding.metadata.get("db_updated_at") == "2026-02-01T00:00:00Z"

    @patch("caliper.plugins.osv_scanner.subprocess.run")
    def test_finding_db_updated_at_none_when_modified_field_absent(
        self, mock_run: MagicMock
    ) -> None:
        from caliper.core.plugin import normalize_finding
        from caliper.plugins.osv_scanner import OsvScannerPlugin

        output = json.dumps(
            {
                "results": [
                    {
                        "packages": [
                            {
                                "package": {
                                    "name": "flask",
                                    "version": "2.0.0",
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-abcd-1234",
                                        "summary": "RCE in flask",
                                        "database_specific": {"severity": "HIGH"},
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        )
        mock_run.return_value = MagicMock(stdout=output, stderr="", returncode=0)
        plugin = OsvScannerPlugin()

        result = plugin.run(["requirements.txt"], Path("/project"))

        assert len(result.findings) == 1
        finding = normalize_finding(result.findings[0])
        assert "db_updated_at" in finding.metadata
        assert finding.metadata["db_updated_at"] is None


class TestRenderMarkdownVulnerabilityDataAsOf:
    """AC3: render_markdown() prints one 'vulnerability data as of <timestamp>'

    line per scanner that reported a db_updated_at.
    """

    def test_prints_one_line_per_scanner_with_db_updated_at(self) -> None:
        from caliper.core.renderer import render_markdown

        findings = [
            {
                "id": "CVE-2023-32681",
                "plugin": "trivy",
                "db_updated_at": "2026-01-01T06:08:37Z",
                "package": "requests",
                "severity": "high",
            },
            {
                "id": "CVE-2024-00001",
                "plugin": "trivy",
                "db_updated_at": "2026-01-01T06:08:37Z",
                "package": "urllib3",
                "severity": "medium",
            },
            {
                "id": "GHSA-abcd-1234",
                "plugin": "osv-scanner",
                "db_updated_at": "2025-12-31T00:00:00Z",
                "package": "flask",
                "severity": "high",
            },
        ]

        output = render_markdown(findings)

        assert output.count("vulnerability data as of 2026-01-01T06:08:37Z") == 1
        assert "vulnerability data as of 2025-12-31T00:00:00Z" in output

    def test_no_line_emitted_when_scanner_has_no_db_updated_at(self) -> None:
        from caliper.core.renderer import render_markdown

        findings = [
            {
                "id": "CVE-2023-32681",
                "plugin": "trivy",
                "package": "requests",
                "severity": "high",
            }
        ]

        output = render_markdown(findings)

        assert "vulnerability data as of" not in output


def _trivy_output_for_package(pkg_name: str, target: str = "requirements.txt") -> str:
    return json.dumps(
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": target,
                    "Class": "lang-pkgs",
                    "Type": "pip",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2030-00001",
                            "PkgName": pkg_name,
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Severity": "HIGH",
                            "Title": f"Vuln in {pkg_name}",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2030-00001",
                        },
                    ],
                }
            ],
        }
    )


class TestTrivyDependencyKindMetadata:
    """AC1 (task-010): trivy vulnerability findings carry metadata['dependency_kind'].

    PROP-001: every trivy Finding produced from a dependency-vulnerability result
    has metadata['dependency_kind'] in {'direct', 'transitive', 'unknown'},
    computed via manifest_discovery.classify_dependency_kind.
    """

    @staticmethod
    def _plugin_with(stdout: str) -> tuple[TrivyPlugin, MagicMock]:
        runner = MagicMock()
        runner.run.return_value = ToolResult(
            stdout=stdout, stderr="", exit_code=0, timed_out=False, not_installed=False
        )
        return TrivyPlugin(tool_runner=runner), runner

    def test_ac1_direct_dependency_finding_has_dependency_kind_direct(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        stdout = _trivy_output_for_package("requests")
        plugin, _ = self._plugin_with(stdout)

        result = plugin.run([], tmp_path)

        finding = next(f for f in result.findings if f.get("package") == "requests")
        assert "metadata" in finding, "trivy vuln finding must carry a metadata dict"
        assert finding["metadata"]["dependency_kind"] == "direct"

    def test_ac1_unlisted_dependency_finding_has_dependency_kind_unknown(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        stdout = _trivy_output_for_package("totally-unlisted-pkg")
        plugin, _ = self._plugin_with(stdout)

        result = plugin.run([], tmp_path)

        finding = next(f for f in result.findings if f.get("package") == "totally-unlisted-pkg")
        assert "metadata" in finding, "trivy vuln finding must carry a metadata dict"
        assert finding["metadata"]["dependency_kind"] == "unknown"

    def test_ac1_dependency_kind_always_in_legal_set(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        stdout = _trivy_output_for_package("requests")
        plugin, _ = self._plugin_with(stdout)

        result = plugin.run([], tmp_path)

        assert result.findings, "expected at least one finding to check"
        for f in result.findings:
            assert f["metadata"]["dependency_kind"] in {"direct", "transitive", "unknown"}


class TestTrivyLockfileTarget:
    """CORR-001: trivy reports lockfiles as ``Target``; classification must
    still resolve direct/transitive via the sibling manifest."""

    @staticmethod
    def _plugin_with(stdout: str) -> TrivyPlugin:
        runner = MagicMock()
        runner.run.return_value = ToolResult(
            stdout=stdout, stderr="", exit_code=0, timed_out=False, not_installed=False
        )
        return TrivyPlugin(tool_runner=runner)

    def test_package_lock_target_direct(self, tmp_path: Path) -> None:
        (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "^4"}}')
        (tmp_path / "package-lock.json").write_text('{"packages": {"node_modules/lodash": {}}}')
        plugin = self._plugin_with(_trivy_output_for_package("lodash", target="package-lock.json"))

        result = plugin.run([], tmp_path)

        finding = next(f for f in result.findings if f.get("package") == "lodash")
        assert finding["metadata"]["dependency_kind"] == "direct"

    def test_cargo_lock_target_transitive(self, tmp_path: Path) -> None:
        (tmp_path / "Cargo.toml").write_text('[dependencies]\nserde = "1"\n')
        (tmp_path / "Cargo.lock").write_text(
            '[[package]]\nname = "serde"\n\n[[package]]\nname = "itoa"\n'
        )
        plugin = self._plugin_with(_trivy_output_for_package("itoa", target="Cargo.lock"))

        result = plugin.run([], tmp_path)

        finding = next(f for f in result.findings if f.get("package") == "itoa")
        assert finding["metadata"]["dependency_kind"] == "transitive"


class TestTrivyManifestCachePerRun:
    """PERF-002: one ManifestCache per run; every package classifies through it,
    so the manifest is read once for a many-package result."""

    def test_manifest_read_once_for_many_packages(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.25.0\n")
        vulns = [
            {
                "VulnerabilityID": f"CVE-2030-{i:05d}",
                "PkgName": f"pkg{i}",
                "InstalledVersion": "1.0.0",
                "Severity": "HIGH",
                "Title": "x",
            }
            for i in range(50)
        ]
        stdout = json.dumps(
            {
                "Results": [
                    {"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": vulns}
                ]
            }
        )
        runner = MagicMock()
        runner.run.return_value = ToolResult(
            stdout=stdout, stderr="", exit_code=0, timed_out=False, not_installed=False
        )
        plugin = TrivyPlugin(tool_runner=runner)
        reads: list[Path] = []

        def counting_read(path: Path) -> str:
            reads.append(path)
            return path.read_text()

        with patch("caliper.core.manifest_discovery._read_text", side_effect=counting_read):
            result = plugin.run([], tmp_path)

        assert len(result.findings) == 50
        assert reads.count(tmp_path / "requirements.txt") == 1
