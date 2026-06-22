"""Tests for mypy/pyright plugin — deterministic type checking.
# tested-by: tests/unit/test_mypy_plugin.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from caliper.core.plugin import PluginCategory
from caliper.plugins.mypy import MypyPlugin

MYPY_OUTPUT = """\
src/app.py:5: error: Argument 1 to "parse_tasks" has incompatible type "Path"; expected "str"  [arg-type]
src/app.py:12: error: "Task" has no attribute "__getitem__"  [attr-defined]
src/lib.py:30: note: Revealed type is "builtins.str"
Found 2 errors in 2 files (checked 3 source files)
"""

MYPY_OUTPUT_WITH_COLUMNS = """\
src/app.py:5:10: error: Argument 1 to "parse_tasks" has incompatible type "Path"; expected "str"  [arg-type]
src/app.py:12:5: error: "Task" has no attribute "__getitem__"  [attr-defined]
src/lib.py:30:1: note: Revealed type is "builtins.str"
Found 2 errors in 2 files (checked 3 source files)
"""

PYRIGHT_OUTPUT = json.dumps(
    {
        "generalDiagnostics": [
            {
                "file": "src/app.py",
                "severity": "error",
                "message": 'Argument of type "Path" cannot be assigned to parameter of type "str"',
                "range": {"start": {"line": 4, "character": 0}},
                "rule": "reportArgumentType",
            },
            {
                "file": "src/lib.py",
                "severity": "warning",
                "message": "Variable is not accessed",
                "range": {"start": {"line": 10, "character": 0}},
                "rule": "reportUnusedVariable",
            },
        ],
        "summary": {"errorCount": 1, "warningCount": 1},
    }
)


class TestMypyPlugin:
    def test_name_and_category(self):
        p = MypyPlugin()
        assert p.name == "mypy"
        assert p.category == PluginCategory.code

    def test_can_run_with_python_files(self):
        p = MypyPlugin()
        assert p.can_run(["src/app.py", "tests/test_app.py"], Path(".")) is True

    def test_can_run_false_without_python_files(self):
        p = MypyPlugin()
        assert p.can_run(["src/app.ts", "README.md"], Path(".")) is False

    @patch("caliper.plugins.mypy.subprocess.run")
    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: "/usr/bin/mypy" if t == "mypy" else None,
    )
    def test_mypy_parses_errors(self, _which, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = MYPY_OUTPUT
        mock_run.return_value.stderr = ""

        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        assert len(result.findings) == 2
        assert result.findings[0]["file"] == "src/app.py"
        assert result.findings[0]["line"] == 5
        assert result.findings[0]["rule"] == "arg-type"
        assert result.findings[0]["severity"] == "high"
        assert "parse_tasks" in result.findings[0]["message"]

    @patch("caliper.plugins.mypy.subprocess.run")
    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: "/usr/bin/mypy" if t == "mypy" else None,
    )
    def test_mypy_parses_column_number_format(self, _which, mock_run):
        """Regression: --show-column-numbers adds file:line:col: format."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = MYPY_OUTPUT_WITH_COLUMNS
        mock_run.return_value.stderr = ""

        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        assert len(result.findings) == 2
        assert result.findings[0]["line"] == 5
        assert result.findings[0]["rule"] == "arg-type"
        assert result.findings[1]["line"] == 12

    @patch("caliper.plugins.mypy.subprocess.run")
    @patch("caliper.plugins.mypy.shutil.which", return_value="/usr/bin/pyright")
    def test_pyright_parses_json(self, _which, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = PYRIGHT_OUTPUT
        mock_run.return_value.stderr = ""

        p = MypyPlugin()
        p._tool = "pyright"
        result = p.run(["src/app.py"], Path("/workspace"))

        assert len(result.findings) == 2
        assert result.findings[0]["severity"] == "high"
        assert result.findings[0]["rule"] == "reportArgumentType"
        assert result.findings[1]["severity"] == "medium"

    @patch("caliper.plugins.mypy.subprocess.run")
    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: "/usr/bin/mypy" if t == "mypy" else None,
    )
    def test_clean_scan(self, _which, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "Success: no issues found in 3 source files\n"
        mock_run.return_value.stderr = ""

        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        assert result.error == ""
        assert len(result.findings) == 0

    @patch("caliper.plugins.mypy.shutil.which", return_value=None)
    def test_not_installed(self, _which):
        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        assert "NOT_INSTALLED" in result.error

    @patch("caliper.plugins.mypy.subprocess.run")
    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: "/usr/bin/mypy" if t == "mypy" else None,
    )
    def test_timeout(self, _which, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="mypy", timeout=60)

        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        assert "TIMEOUT" in result.error

    @patch("caliper.plugins.mypy.subprocess.run")
    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: "/usr/bin/mypy" if t == "mypy" else None,
    )
    def test_notes_excluded_from_findings(self, _which, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = MYPY_OUTPUT
        mock_run.return_value.stderr = ""

        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        for f in result.findings:
            assert f["severity"] != "info"
