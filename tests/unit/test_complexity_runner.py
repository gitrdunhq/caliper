"""Tests for complexity runner — Lizard output parsing + Halstead MI.
# tested-by: tests/unit/test_complexity_runner.py
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from caliper.plugins._runners.complexity_runner import (
    _halstead_mi,
    run_complexity,
)


class TestLizardOutputParsing:
    """Lizard CSV output is parsed with clean function names and paths."""

    def _fake_lizard(self, stdout: str) -> MagicMock:
        result = MagicMock()
        result.stdout = stdout
        result.returncode = 0
        return result

    def test_function_name_strips_leading_quotes(self, tmp_path):
        csv = '10,3,50,2,15,"check_unpinned_deps,"/abs/path/supply_chain.py",0,0,0'
        src = tmp_path / "supply_chain.py"
        src.write_text("def check_unpinned_deps(): pass")

        with patch("subprocess.run", return_value=self._fake_lizard(csv)):
            data = run_complexity([str(src)], str(tmp_path))

        assert len(data["functions"]) == 1
        assert data["functions"][0]["function"] == "check_unpinned_deps"
        assert '"' not in data["functions"][0]["function"]

    def test_file_path_strips_quotes(self, tmp_path):
        csv = '10,3,50,2,15,my_func,"/abs/path/app.py",0,0,0'
        src = tmp_path / "app.py"
        src.write_text("def my_func(): pass")

        with patch("subprocess.run", return_value=self._fake_lizard(csv)):
            data = run_complexity([str(src)], str(tmp_path))

        assert len(data["functions"]) == 1
        assert '"' not in data["functions"][0]["file"]

    def test_clean_names_no_quotes(self, tmp_path):
        csv = "10,3,50,2,15,clean_func,/abs/path/mod.py,0,0,0"
        src = tmp_path / "mod.py"
        src.write_text("def clean_func(): pass")

        with patch("subprocess.run", return_value=self._fake_lizard(csv)):
            data = run_complexity([str(src)], str(tmp_path))

        assert data["functions"][0]["function"] == "clean_func"

    def test_lizard_not_installed_returns_error(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text("def f(): pass")

        with patch("subprocess.run", side_effect=FileNotFoundError):
            data = run_complexity([str(src)], str(tmp_path))

        assert "error" in data
        assert "NOT_INSTALLED" in data["error"]


# ---------------------------------------------------------------------------
# Helpers for JS/TS Halstead-MI tests
# ---------------------------------------------------------------------------

_LIZARD_CSV_LINE = "10,3,50,2,15,myFunc@10,app.js,1,0,\n"


def _lizard_result(stdout: str = _LIZARD_CSV_LINE) -> MagicMock:
    r = MagicMock()
    r.stdout = stdout
    r.returncode = 0
    return r


# ---------------------------------------------------------------------------
# Unit: _halstead_mi helper
# ---------------------------------------------------------------------------


class TestHalsteadMi:
    def test_returns_float_in_range(self):
        mi = _halstead_mi(nloc=10, ccn=3, tokens=50)
        assert isinstance(mi, float)
        assert 0.0 <= mi <= 100.0

    def test_clamped_at_zero(self):
        # Pathologically large function — MI should clamp to 0, not go negative
        mi = _halstead_mi(nloc=10_000, ccn=1000, tokens=1_000_000)
        assert mi == 0.0

    def test_clamped_at_100(self):
        # Trivially small function — MI should clamp to 100, not exceed it
        mi = _halstead_mi(nloc=1, ccn=1, tokens=5)
        assert mi == 100.0 or mi <= 100.0


# ---------------------------------------------------------------------------
# Per-language MI source: Python uses radon, everything else uses Halstead
# ---------------------------------------------------------------------------


class TestPerLanguageMiSource:
    def test_python_uses_radon_for_mi(self):
        """Python files use radon for MI (only two subprocess calls: lizard, radon)."""
        lizard_csv = "12,4,60,3,20,compute@8,utils.py,1,0,\n"
        lizard_side = [_lizard_result(lizard_csv)]
        radon_out = MagicMock()
        radon_out.stdout = "utils.py - A (87.50)\n"
        radon_out.returncode = 0

        with patch("subprocess.run", side_effect=lizard_side + [radon_out]) as mock_run:
            result = run_complexity(["utils.py"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        assert fns[0]["maintainability_index"] == "A (87.50)"
        assert mock_run.call_count == 2


# ---------------------------------------------------------------------------
# JS/TS MI overlay: bundled typhonjs-escomplex helper (#441). When the helper
# is unavailable, MI falls back to the Halstead approximation (fail-open).
# ---------------------------------------------------------------------------

# Recorded real output of the bundled helper (typhonjs-escomplex, MI rescaled
# to radon's 0-100) run against scripts/part_ui — never hand-invented (#441).
_HELPER_JSON = (
    '[{"file":"api.ts","mi":69.2},{"file":"app.ts","mi":58.9},'
    '{"file":"types.ts","mi":77.5},{"file":"build.ts","mi":51.4}]'
)


def _helper_result(stdout: str = _HELPER_JSON) -> MagicMock:
    r = MagicMock()
    r.stdout = stdout
    r.returncode = 0
    return r


class TestJsTsMiOverlay:
    _TS_CSV = "10,3,50,2,15,fetchParts@10,api.ts,1,0,\n12,5,80,1,20,render@30,app.ts,1,0,\n"

    def test_ts_files_get_mi_from_bundled_helper(self):
        """MI for JS/TS files comes from the node helper, radon-style formatted."""
        with patch(
            "subprocess.run",
            side_effect=[_lizard_result(self._TS_CSV), _helper_result()],
        ) as mock_run:
            result = run_complexity(["api.ts", "app.ts"], "/repo")

        by_file = {f["file"]: f["maintainability_index"] for f in result["functions"]}
        assert by_file["api.ts"] == "A (69.2)"
        assert by_file["app.ts"] == "A (58.9)"
        # lizard + node helper — no radon (no .py files)
        assert mock_run.call_count == 2
        node_argv = mock_run.call_args_list[1][0][0]
        assert node_argv[0] == "node"
        assert node_argv[1].endswith("mi.cjs")
        assert "api.ts" in node_argv and "app.ts" in node_argv

    def test_node_missing_falls_back_to_halstead(self):
        """No node on PATH → Halstead MI stays, no error key (fail-open)."""
        with patch(
            "subprocess.run",
            side_effect=[_lizard_result(_LIZARD_CSV_LINE), FileNotFoundError()],
        ):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        mi_str = fns[0]["maintainability_index"]
        assert mi_str[0] in ("A", "B", "C")
        assert "(" in mi_str
        assert "error" not in result

    def test_helper_timeout_falls_back_to_halstead(self):
        """Helper timeout → Halstead MI stays, no error key (fail-open)."""
        import subprocess as _subprocess

        with patch(
            "subprocess.run",
            side_effect=[
                _lizard_result(_LIZARD_CSV_LINE),
                _subprocess.TimeoutExpired(cmd="node", timeout=1),
            ],
        ):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        assert fns[0]["maintainability_index"][0] in ("A", "B", "C")
        assert "error" not in result

    def test_helper_garbage_output_falls_back_to_halstead(self):
        """Unparseable helper stdout → Halstead MI stays (fail-open)."""
        with patch(
            "subprocess.run",
            side_effect=[_lizard_result(_LIZARD_CSV_LINE), _helper_result("not json {")],
        ):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        assert fns[0]["maintainability_index"][0] in ("A", "B", "C")
        assert "error" not in result

    def test_python_only_never_invokes_node(self):
        """A .py-only change list must not spawn the node helper."""
        radon_out = MagicMock()
        radon_out.stdout = "utils.py - A (87.50)\n"
        radon_out.returncode = 0
        csv = "12,4,60,3,20,compute@8,utils.py,1,0,\n"

        with patch("subprocess.run", side_effect=[_lizard_result(csv), radon_out]) as mock_run:
            run_complexity(["utils.py"], "/repo")

        for call in mock_run.call_args_list:
            assert call[0][0][0] != "node"


# ---------------------------------------------------------------------------
# No supported files
# ---------------------------------------------------------------------------


class TestNoSupportedFiles:
    def test_empty_result_for_unsupported_extensions(self):
        result = run_complexity(["README.md", "Makefile"], "/repo")
        assert result == {"functions": [], "files_scanned": 0, "summary": {}}
