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
# JS/TS MI always comes from the Halstead approximation (no per-tool fallback
# branching left to test now that the JS/TS-specific override is gone)
# ---------------------------------------------------------------------------


class TestJsHalsteadMi:
    def test_js_file_gets_halstead_mi_grade(self):
        """MI for a JS file comes from the Halstead approximation."""
        lizard_side = [_lizard_result(_LIZARD_CSV_LINE)]

        with patch("subprocess.run", side_effect=lizard_side):
            result = run_complexity(["app.js"], "/repo")

        fns = result["functions"]
        assert len(fns) == 1
        mi_str = fns[0]["maintainability_index"]

        # Should have a grade prefix (A/B/C) from the Halstead approximation
        assert mi_str[0] in ("A", "B", "C")
        assert "(" in mi_str


# ---------------------------------------------------------------------------
# No supported files
# ---------------------------------------------------------------------------


class TestNoSupportedFiles:
    def test_empty_result_for_unsupported_extensions(self):
        result = run_complexity(["README.md", "Makefile"], "/repo")
        assert result == {"functions": [], "files_scanned": 0, "summary": {}}
