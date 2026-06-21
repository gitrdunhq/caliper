"""Tests for PMD CPD output parsing.
# tested-by: tests/unit/test_cpd_runner.py
"""

from __future__ import annotations

from unittest.mock import patch

from eedom.plugins._runners.cpd_runner import (
    _enclosing_symbol,
    _enrich_clones,
    _parse_cpd_xml,
    run_cpd,
)


def test_parse_cpd_xml_handles_pmd_7_namespace() -> None:
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<pmd-cpd xmlns="https://pmd-code.org/schema/cpd-report">
  <duplication lines="22" tokens="112">
    <file line="8" endline="29" path="/repo/duplicate_block.py"/>
    <file line="56" endline="77" path="/repo/duplicate_block.py"/>
    <codefragment><![CDATA[def duplicated(): pass]]></codefragment>
  </duplication>
</pmd-cpd>
"""

    dupes = _parse_cpd_xml(xml, "python")

    assert dupes == [
        {
            "tokens": 112,
            "lines": 22,
            "language": "python",
            "locations": [
                {
                    "file": "/repo/duplicate_block.py",
                    "start_line": 8,
                    "end_line": 29,
                },
                {
                    "file": "/repo/duplicate_block.py",
                    "start_line": 56,
                    "end_line": 77,
                },
            ],
            "fragment": "def duplicated(): pass",
        }
    ]


@patch("eedom.plugins._runners.cpd_runner.subprocess.run")
def test_run_cpd_parses_xml_with_stdout_preamble(mock_run) -> None:
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = (
        "PMD CPD started\n"
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<pmd-cpd xmlns="https://pmd-code.org/schema/cpd-report">\n'
        '  <duplication lines="10" tokens="80">\n'
        '    <file line="1" endline="10" path="/repo/a.py"/>\n'
        '    <file line="20" endline="29" path="/repo/b.py"/>\n'
        "  </duplication>\n"
        "</pmd-cpd>\n"
    )
    mock_run.return_value.stderr = ""

    result = run_cpd(["a.py", "b.py"], "/repo")

    assert result["duplicate_count"] == 1
    assert result["duplicates"][0]["tokens"] == 80


def test_enclosing_symbol_python_picks_innermost(tmp_path) -> None:
    f = tmp_path / "m.py"
    f.write_text(
        "def alpha():\n"
        "    x = 1\n"
        "    return x\n"
        "\n"
        "class Beta:\n"
        "    def gamma(self):\n"
        "        return 2\n"
    )
    assert _enclosing_symbol(str(f), 2) == "alpha"
    assert _enclosing_symbol(str(f), 7) == "gamma"  # innermost (method) wins over the class
    assert _enclosing_symbol(str(f), 99) == ""  # out of range, fail-open


def test_enrich_clones_adds_occurrences_symbol_and_home(tmp_path) -> None:
    a = tmp_path / "a.py"
    a.write_text("def foo():\n    return 1\n")
    b = tmp_path / "b.py"
    b.write_text("def bar():\n    return 1\n")
    dupes = [
        {  # cross-file, lower impact
            "tokens": 50,
            "lines": 2,
            "language": "python",
            "locations": [
                {"file": str(a), "start_line": 1, "end_line": 2},
                {"file": str(b), "start_line": 1, "end_line": 2},
            ],
        },
        {  # same-file, higher impact (tokens x occurrences)
            "tokens": 90,
            "lines": 2,
            "language": "python",
            "locations": [
                {"file": str(a), "start_line": 1, "end_line": 2},
                {"file": str(a), "start_line": 1, "end_line": 2},
            ],
        },
    ]

    out = _enrich_clones(dupes, str(tmp_path))

    assert out[0]["tokens"] == 90  # ranked by tokens x occurrences
    assert out[0]["occurrences"] == 2
    assert "local helper" in out[0]["suggested_home"]  # same file
    cross = next(d for d in out if d["tokens"] == 50)
    assert "shared module" in cross["suggested_home"]  # cross file
    assert cross["locations"][0]["symbol"] == "foo"
    assert cross["locations"][1]["symbol"] == "bar"
