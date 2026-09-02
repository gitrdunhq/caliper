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

PYREFLY_OUTPUT = json.dumps(
    {
        "errors": [
            {
                "line": 5,
                "column": 10,
                "stop_line": 5,
                "stop_column": 20,
                "path": "src/app.py",
                "code": -2,
                "name": "bad-argument-type",
                "description": "Argument of type `Path` is not assignable to parameter of type `str`",
                "concise_description": "Argument of type `Path` is not assignable to parameter of type `str`",
                "severity": "error",
            },
            {
                "line": 10,
                "column": 1,
                "stop_line": 10,
                "stop_column": 5,
                "path": "src/lib.py",
                "code": -3,
                "name": "unused-variable",
                "description": "Variable is not accessed",
                "concise_description": "Variable is not accessed",
                "severity": "warning",
            },
        ]
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
        side_effect=lambda t: "/usr/bin/pyrefly" if t == "pyrefly" else None,
    )
    def test_pyrefly_parses_json(self, _which, mock_run):
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = PYREFLY_OUTPUT
        mock_run.return_value.stderr = ""

        p = MypyPlugin()
        result = p.run(["src/app.py"], Path("/workspace"))

        assert len(result.findings) == 2
        assert result.findings[0]["line"] == 5
        assert result.findings[0]["file"] == "src/app.py"
        assert result.findings[0]["rule"] == "bad-argument-type"
        assert result.findings[0]["severity"] == "high"
        assert result.findings[1]["severity"] == "medium"
        assert result.summary["tool"] == "pyrefly"

    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: f"/usr/bin/{t}",
    )
    def test_pyrefly_preferred_over_pyright_and_mypy(self, _which):
        p = MypyPlugin()

        assert p._detect_tool() == "pyrefly"

    @patch(
        "caliper.plugins.mypy.shutil.which",
        side_effect=lambda t: "/usr/bin/pyright" if t == "pyright" else None,
    )
    def test_falls_back_to_pyright_when_pyrefly_missing(self, _which):
        p = MypyPlugin()

        assert p._detect_tool() == "pyright"

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


class TestArgvBatchingAndShape:
    """pyrefly/pyright/mypy get every file on argv; large repos exceed ARG_MAX.
    Files are batched by byte size and results merged; JSON of an unexpected
    shape is a typed PARSE_ERROR, never a raw exception."""

    def _ok(self, *a, **k):
        class R:
            returncode = 0
            stdout = '{"errors": []}'
            stderr = ""

        return R()

    def test_files_are_batched_under_the_argv_limit(self, tmp_path: Path) -> None:
        from caliper.plugins import mypy as m

        files = [f"pkg/module_{i:04d}/very_long_file_name_{i:04d}.py" for i in range(3000)]
        with (
            patch.object(m, "_ARGV_LIMIT_BYTES", 50_000),
            patch("caliper.plugins.mypy.subprocess.run", side_effect=self._ok) as run,
            patch.object(MypyPlugin, "_detect_tool", return_value="pyrefly"),
        ):
            result = MypyPlugin().run(files, tmp_path)
        assert result.error == ""
        assert run.call_count > 1
        for call in run.call_args_list:
            argv = call.args[0]
            assert sum(len(a) + 1 for a in argv) <= 50_000 + 200

    def test_batches_are_merged(self, tmp_path: Path) -> None:
        from caliper.plugins import mypy as m

        calls = []

        def fake(argv, **k):
            calls.append(argv)

            class R:
                returncode = 1
                stderr = ""
                stdout = json.dumps(
                    {
                        "errors": [
                            {
                                "path": argv[-1],
                                "line": 1,
                                "severity": "error",
                                "description": "boom",
                                "name": "x",
                            }
                        ]
                    }
                )

            return R()

        files = [f"f{i}.py" for i in range(40)]
        with (
            patch.object(m, "_ARGV_LIMIT_BYTES", 120),
            patch("caliper.plugins.mypy.subprocess.run", side_effect=fake),
            patch.object(MypyPlugin, "_detect_tool", return_value="pyrefly"),
        ):
            result = MypyPlugin().run(files, tmp_path)
        assert len(calls) > 1
        assert len(result.findings) == len(calls)

    def test_top_level_list_is_a_parse_error(self, tmp_path: Path) -> None:
        class R:
            returncode = 1
            stdout = "[1, 2]"
            stderr = ""

        with (
            patch("caliper.plugins.mypy.subprocess.run", return_value=R()),
            patch.object(MypyPlugin, "_detect_tool", return_value="pyrefly"),
        ):
            result = MypyPlugin().run(["a.py"], tmp_path)
        assert "[PARSE_ERROR]" in result.error and "pyrefly" in result.error

    def test_null_errors_field_yields_no_findings(self, tmp_path: Path) -> None:
        class R:
            returncode = 0
            stdout = '{"errors": null}'
            stderr = ""

        with (
            patch("caliper.plugins.mypy.subprocess.run", return_value=R()),
            patch.object(MypyPlugin, "_detect_tool", return_value="pyrefly"),
        ):
            result = MypyPlugin().run(["a.py"], tmp_path)
        assert result.error == "" and result.findings == []
