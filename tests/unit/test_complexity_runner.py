"""Tests for complexity runner — Lizard output parsing + escomplex MI override.
# tested-by: tests/unit/test_complexity_runner.py
"""

from __future__ import annotations

import json
import subprocess
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
# Helpers for escomplex tests
# ---------------------------------------------------------------------------

_LIZARD_CSV_LINE = "10,3,50,2,15,myFunc@10,app.js,1,0,\n"

_ESCOMPLEX_OUTPUT = json.dumps(
    {
        "reports": [
            {
                "path": "app.js",
                "maintainability": 72.34,
            }
        ]
    }
)

_ESCOMPLEX_OUTPUT_TS = json.dumps(
    {
        "reports": [
            {
                "path": "server.ts",
                "maintainability": 55.10,
            }
        ]
    }
)


def _lizard_result(stdout: str = _LIZARD_CSV_LINE) -> MagicMock:
    r = MagicMock()
    r.stdout = stdout
    r.returncode = 0
    return r


def _escomplex_result(stdout: str = _ESCOMPLEX_OUTPUT) -> MagicMock:
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
# JS/TS: escomplex override
# ---------------------------------------------------------------------------


class TestEscomplexOverride:
    def test_js_mi_comes_from_escomplex_not_approximation(self):
        """MI for a JS file must use escomplex output, not the Halstead approximation."""
        lizard_side = [_lizard_result(_LIZARD_CSV_LINE)]
        escomplex_side = [_escomplex_result(_ESCOMPLEX_OUTPUT)]

        with patch("subprocess.run", side_effect=lizard_side + escomplex_side):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        mi_str = fns[0]["maintainability_index"]
        # escomplex score is 72.34 — must appear in the string
        assert "72.3" in mi_str

        # Confirm it differs from the pure Halstead approximation
        fn = fns[0]
        approx = _halstead_mi(
            nloc=fn["nloc"], ccn=fn["cyclomatic_complexity"], tokens=fn["token_count"]
        )
        approx_str = f"{('A' if approx >= 20 else ('B' if approx >= 10 else 'C'))} ({approx:.1f})"
        assert (
            mi_str != approx_str
        ), "MI string should differ from Halstead approximation when escomplex is available"

    def test_ts_mi_comes_from_escomplex(self):
        """MI for a TS file also uses escomplex."""
        lizard_csv = "8,2,40,1,12,handler@5,server.ts,1,0,\n"
        lizard_side = [_lizard_result(lizard_csv)]
        escomplex_side = [_escomplex_result(_ESCOMPLEX_OUTPUT_TS)]

        with patch("subprocess.run", side_effect=lizard_side + escomplex_side):
            result = run_complexity(["server.ts"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        assert "55.1" in fns[0]["maintainability_index"]

    def test_python_unchanged_uses_radon_not_escomplex(self):
        """Python files must still use radon, not escomplex."""
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

        # escomplex must NOT have been called for a .py file
        calls = [str(c) for c in mock_run.call_args_list]
        assert not any("escomplex" in c for c in calls)


# ---------------------------------------------------------------------------
# Fallback: escomplex not installed
# ---------------------------------------------------------------------------


class TestEscomplexFallback:
    def test_fallback_to_halstead_when_escomplex_not_installed(self):
        """When escomplex is not installed, MI falls back to Halstead approximation."""
        lizard_side = [_lizard_result(_LIZARD_CSV_LINE)]
        escomplex_not_found = FileNotFoundError("No such file: escomplex")

        with patch("subprocess.run", side_effect=lizard_side + [escomplex_not_found]):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        mi_str = fns[0]["maintainability_index"]

        # Should still have a grade prefix (A/B/C) from the Halstead approximation
        assert mi_str[0] in ("A", "B", "C")
        assert "(" in mi_str

    def test_fallback_warning_logged(self, caplog):
        """A structlog warning is emitted when escomplex is missing."""
        lizard_side = [_lizard_result(_LIZARD_CSV_LINE)]
        escomplex_not_found = FileNotFoundError("No such file: escomplex")

        with patch("subprocess.run", side_effect=lizard_side + [escomplex_not_found]):
            with patch("caliper.plugins._runners.complexity_runner.logger") as mock_logger:
                run_complexity(["app.js"], "/repo")
                mock_logger.warning.assert_called_once()
                call_kwargs = mock_logger.warning.call_args
                assert "escomplex" in str(call_kwargs).lower()

    def test_escomplex_timeout_falls_back(self):
        """escomplex timeout also falls back gracefully to Halstead."""
        lizard_side = [_lizard_result(_LIZARD_CSV_LINE)]

        with patch(
            "subprocess.run",
            side_effect=lizard_side + [subprocess.TimeoutExpired(cmd="escomplex", timeout=60)],
        ):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        mi_str = fns[0]["maintainability_index"]
        assert mi_str[0] in ("A", "B", "C")

    def test_escomplex_bad_json_falls_back(self):
        """Malformed escomplex JSON falls back gracefully."""
        lizard_side = [_lizard_result(_LIZARD_CSV_LINE)]
        bad_json = MagicMock()
        bad_json.stdout = "not valid json{"
        bad_json.returncode = 0

        with patch("subprocess.run", side_effect=lizard_side + [bad_json]):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        mi_str = fns[0]["maintainability_index"]
        assert mi_str[0] in ("A", "B", "C")


# ---------------------------------------------------------------------------
# No supported files
# ---------------------------------------------------------------------------


class TestNoSupportedFiles:
    def test_empty_result_for_unsupported_extensions(self):
        result = run_complexity(["README.md", "Makefile"], "/repo")
        assert result == {"functions": [], "files_scanned": 0, "summary": {}}
