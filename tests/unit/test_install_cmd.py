"""`caliper install-scanners` CLI + the review-time install offer.
# tested-by: tests/unit/test_install_cmd.py
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from caliper.cli.install_cmd import install_scanners, offer_install
from caliper.core.scanner_install import InstallItem, InstallPlan


class _FakeInstaller:
    def __init__(self) -> None:
        self.installed: list[str] = []

    def install(self, item: InstallItem, bin_dir: Path) -> Path:
        self.installed.append(item.name)
        return bin_dir / item.name


class TestInstallScannersCommand:
    def test_dry_run_lists_plan_without_installing(self, monkeypatch, tmp_path: Path) -> None:
        fake = _FakeInstaller()
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr("caliper.cli.install_cmd._which", lambda n: None)
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        result = CliRunner().invoke(
            install_scanners, ["syft", "trivy", "--bin-dir", str(tmp_path), "--dry-run"]
        )
        assert result.exit_code == 0, result.output
        assert "syft" in result.output and "trivy" in result.output
        assert fake.installed == []

    def test_installs_missing_and_reports_path_hint(self, monkeypatch, tmp_path: Path) -> None:
        fake = _FakeInstaller()
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr(
            "caliper.cli.install_cmd._which", lambda n: "/x/syft" if n == "syft" else None
        )
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "darwin-arm64")
        monkeypatch.setenv("PATH", "/usr/bin")
        result = CliRunner().invoke(
            install_scanners, ["syft", "trivy", "--bin-dir", str(tmp_path), "--yes"]
        )
        assert result.exit_code == 0, result.output
        assert fake.installed == ["trivy"]
        assert "already" in result.output.lower()
        assert "PATH" in result.output

    def test_unknown_name_exits_nonzero(self, monkeypatch, tmp_path: Path) -> None:
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: _FakeInstaller())
        monkeypatch.setattr("caliper.cli.install_cmd._which", lambda n: None)
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        result = CliRunner().invoke(install_scanners, ["nope", "--bin-dir", str(tmp_path), "--yes"])
        assert result.exit_code != 0
        assert "nope" in result.output

    def test_download_failure_is_a_hard_error(self, monkeypatch, tmp_path: Path) -> None:
        class Boom(_FakeInstaller):
            def install(self, item: InstallItem, bin_dir: Path) -> Path:
                raise RuntimeError("checksum mismatch for trivy")

        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: Boom())
        monkeypatch.setattr("caliper.cli.install_cmd._which", lambda n: None)
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        result = CliRunner().invoke(
            install_scanners, ["trivy", "--bin-dir", str(tmp_path), "--yes"]
        )
        assert result.exit_code == 1
        assert "checksum mismatch" in result.output


class TestOfferInstall:
    def test_non_interactive_prints_hint_and_returns_false(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("caliper.cli.install_cmd._isatty", lambda: False)
        assert offer_install(["trivy", "opengrep"]) is False
        err = capsys.readouterr().err
        assert "caliper install-scanners trivy opengrep" in err

    def test_interactive_yes_runs_installer(self, monkeypatch, tmp_path: Path) -> None:
        fake = _FakeInstaller()
        monkeypatch.setattr("caliper.cli.install_cmd._isatty", lambda: True)
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr("caliper.cli.install_cmd._which", lambda n: None)
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        monkeypatch.setattr("caliper.cli.install_cmd._confirm", lambda msg: True)
        monkeypatch.setenv("CALIPER_BIN_DIR", str(tmp_path))
        assert offer_install(["trivy"]) is True
        assert fake.installed == ["trivy"]

    def test_interactive_no_does_nothing(self, monkeypatch) -> None:
        fake = _FakeInstaller()
        monkeypatch.setattr("caliper.cli.install_cmd._isatty", lambda: True)
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr("caliper.cli.install_cmd._confirm", lambda msg: False)
        assert offer_install(["trivy"]) is False
        assert fake.installed == []

    def test_empty_missing_is_a_noop(self, monkeypatch) -> None:
        monkeypatch.setattr("caliper.cli.install_cmd._isatty", lambda: True)
        assert offer_install([]) is False


def _plan_of(names: list[str]) -> InstallPlan:  # keep the import used for type clarity
    return InstallPlan(items=[], already_present=names, unsupported=[])


class TestInstallScannersPresentElsewhereOnPath:
    """task-023: a same-named binary elsewhere on PATH must not silently make
    install-scanners skip --bin-dir installation — that must be opt-in via
    --skip-present, and the plan must say exactly where the shadowing binary
    lives and that --bin-dir needs to come first on PATH to take effect.
    """

    def test_ac1_default_still_installs_into_bin_dir_when_present_elsewhere(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        fake = _FakeInstaller()
        elsewhere = "/usr/local/bin/trivy"
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr(
            "caliper.cli.install_cmd._which", lambda n: elsewhere if n == "trivy" else None
        )
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        monkeypatch.setenv("PATH", "/usr/local/bin")
        result = CliRunner().invoke(
            install_scanners, ["trivy", "--bin-dir", str(tmp_path), "--yes"]
        )
        assert result.exit_code == 0, result.output
        assert fake.installed == ["trivy"]

    def test_ac2_skip_present_flag_skips_install_and_notes_why(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        fake = _FakeInstaller()
        elsewhere = "/usr/local/bin/trivy"
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr(
            "caliper.cli.install_cmd._which", lambda n: elsewhere if n == "trivy" else None
        )
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        monkeypatch.setenv("PATH", "/usr/local/bin")
        result = CliRunner().invoke(
            install_scanners,
            ["trivy", "--bin-dir", str(tmp_path), "--yes", "--skip-present"],
        )
        assert result.exit_code == 0, result.output
        assert fake.installed == []
        assert "skipped" in result.output.lower()
        assert "present elsewhere" in result.output.lower()

    def test_ac3_plan_reports_exact_present_elsewhere_string(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        fake = _FakeInstaller()
        elsewhere = "/usr/local/bin/trivy"
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr(
            "caliper.cli.install_cmd._which", lambda n: elsewhere if n == "trivy" else None
        )
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        monkeypatch.setenv("PATH", "/usr/local/bin")
        result = CliRunner().invoke(
            install_scanners, ["trivy", "--bin-dir", str(tmp_path), "--dry-run"]
        )
        assert result.exit_code == 0, result.output
        assert f"present elsewhere: {elsewhere} (version mismatch unknown)" in result.output

    def test_ac4_plan_includes_path_hint_that_bin_dir_must_precede_elsewhere(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        fake = _FakeInstaller()
        elsewhere = "/usr/local/bin/trivy"
        monkeypatch.setattr("caliper.cli.install_cmd._installer", lambda: fake)
        monkeypatch.setattr(
            "caliper.cli.install_cmd._which", lambda n: elsewhere if n == "trivy" else None
        )
        monkeypatch.setattr("caliper.cli.install_cmd._platform", lambda: "linux-amd64")
        monkeypatch.setenv("PATH", "/usr/local/bin")
        result = CliRunner().invoke(
            install_scanners, ["trivy", "--bin-dir", str(tmp_path), "--dry-run"]
        )
        assert result.exit_code == 0, result.output
        assert str(tmp_path) in result.output
        assert "must precede" in result.output.lower()
        assert "/usr/local/bin" in result.output
