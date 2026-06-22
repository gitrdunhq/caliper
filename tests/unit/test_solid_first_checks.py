"""Tests for SOLID/FIRST violation detection via SQL checks and Semgrep rules.
# tested-by: tests/unit/test_solid_first_checks.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import yaml

from caliper.plugins._runners.graph_builder import CodeGraph

_POLICIES_DIR = Path(__file__).parent.parent.parent / "policies" / "semgrep"
_SOLID_FIRST_YAML = _POLICIES_DIR / "solid-first.yaml"


# ── SQL check: srp_high_fan_out_imports ──────────────────────────────────────


class TestSrpHighFanOutImports:
    def test_fires_for_module_with_five_imports(self):
        """A file with 5 distinct top-level imports triggers the SRP fan-out check."""
        source = textwrap.dedent("""\
            import os
            import sys
            import json
            import re
            import pathlib

            def do_work():
                return os.getcwd()
        """)
        g = CodeGraph()
        g.index_file("big_module.py", source)
        g.conn.commit()

        findings = g.run_checks(["big_module.py"])
        check_findings = [f for f in findings if f["check"] == "srp_high_fan_out_imports"]

        assert len(check_findings) >= 1, "Expected srp_high_fan_out_imports to fire"
        assert check_findings[0]["import_count"] >= 5

    def test_does_not_fire_for_two_imports(self):
        """A file with only 2 imports does not trigger the SRP fan-out check."""
        source = textwrap.dedent("""\
            import os
            import sys

            def do_work():
                return os.getcwd()
        """)
        g = CodeGraph()
        g.index_file("small_module.py", source)
        g.conn.commit()

        findings = g.run_checks(["small_module.py"])
        check_findings = [f for f in findings if f["check"] == "srp_high_fan_out_imports"]

        assert (
            len(check_findings) == 0
        ), "Expected srp_high_fan_out_imports NOT to fire for 2 imports"

    def test_fires_only_for_changed_files(self):
        """srp_high_fan_out_imports only fires for files in the changed_files list."""
        source = textwrap.dedent("""\
            import os
            import sys
            import json
            import re
            import pathlib
        """)
        g = CodeGraph()
        g.index_file("module_a.py", source)
        g.conn.commit()

        # Run checks for a different file — should not fire
        findings = g.run_checks(["module_b.py"])
        check_findings = [f for f in findings if f["check"] == "srp_high_fan_out_imports"]

        assert len(check_findings) == 0


# ── SQL check: srp_large_class ───────────────────────────────────────────────


class TestSrpLargeClass:
    def test_fires_for_class_with_twenty_methods(self):
        """A class with 20 methods triggers the SRP large-class check."""
        methods = "\n".join(f"    def method_{i:02d}(self): return {i}" for i in range(1, 21))
        source = f"class FatClass:\n{methods}\n"

        g = CodeGraph()
        g.index_file("fat_class.py", source)
        g.conn.commit()

        findings = g.run_checks(["fat_class.py"])
        check_findings = [f for f in findings if f["check"] == "srp_large_class"]

        assert len(check_findings) >= 1, "Expected srp_large_class to fire for 20 methods"
        assert check_findings[0]["method_count"] >= 16

    def test_does_not_fire_for_small_class(self):
        """A class with 3 methods does not trigger the SRP large-class check."""
        source = textwrap.dedent("""\
            class SmallClass:
                def method_one(self): return 1
                def method_two(self): return 2
                def method_three(self): return 3
        """)
        g = CodeGraph()
        g.index_file("small_class.py", source)
        g.conn.commit()

        findings = g.run_checks(["small_class.py"])
        check_findings = [f for f in findings if f["check"] == "srp_large_class"]

        assert len(check_findings) == 0, "Expected srp_large_class NOT to fire for 3 methods"

    def test_class_at_threshold_does_not_fire(self):
        """A class with exactly 15 methods (at the threshold) does not trigger the check."""
        methods = "\n".join(f"    def method_{i:02d}(self): return {i}" for i in range(1, 16))
        source = f"class ThresholdClass:\n{methods}\n"

        g = CodeGraph()
        g.index_file("threshold_class.py", source)
        g.conn.commit()

        findings = g.run_checks(["threshold_class.py"])
        check_findings = [f for f in findings if f["check"] == "srp_large_class"]

        assert (
            len(check_findings) == 0
        ), "Class with exactly 15 methods should NOT fire (threshold is >15)"

    def test_class_just_above_threshold_fires(self):
        """A class with 16 methods (just above threshold) triggers the check."""
        methods = "\n".join(f"    def method_{i:02d}(self): return {i}" for i in range(1, 17))
        source = f"class BigClass:\n{methods}\n"

        g = CodeGraph()
        g.index_file("big_class.py", source)
        g.conn.commit()

        findings = g.run_checks(["big_class.py"])
        check_findings = [f for f in findings if f["check"] == "srp_large_class"]

        assert len(check_findings) >= 1, "Class with 16 methods SHOULD fire (>15 threshold)"


# ── SQL checks registered ────────────────────────────────────────────────────


class TestSolidFirstChecksRegistered:
    def test_srp_checks_are_registered(self):
        """Both SRP checks must be loaded from checks.yaml at CodeGraph init."""
        g = CodeGraph()
        checks = g.conn.execute("SELECT name FROM checks").fetchall()
        names = {r["name"] for r in checks}

        assert "srp_high_fan_out_imports" in names
        assert "srp_large_class" in names

    def test_total_check_count_includes_new_checks(self):
        """The total check count must be at least 10 after adding 2 new SOLID checks."""
        g = CodeGraph()
        checks = g.conn.execute("SELECT name FROM checks").fetchall()
        assert len(checks) >= 10, f"Expected >= 10 checks, got {len(checks)}"


# ── Semgrep rules file ───────────────────────────────────────────────────────


class TestSemgrepSolidFirstRulesFile:
    def test_solid_first_yaml_exists(self):
        assert _SOLID_FIRST_YAML.exists(), f"Expected {_SOLID_FIRST_YAML} to exist"

    def test_solid_first_yaml_is_valid(self):
        data = yaml.safe_load(_SOLID_FIRST_YAML.read_text())
        assert "rules" in data, "solid-first.yaml must have a top-level 'rules' key"
        assert isinstance(data["rules"], list)
        assert len(data["rules"]) >= 4

    def test_required_rule_ids_present(self):
        data = yaml.safe_load(_SOLID_FIRST_YAML.read_text())
        rule_ids = {r["id"] for r in data["rules"]}

        assert "first-no-sleep-in-tests" in rule_ids
        assert "first-no-environ-in-tests" in rule_ids
        assert "first-test-no-assert" in rule_ids
        assert "ocp-isinstance-chain" in rule_ids

    def test_all_rules_have_required_fields(self):
        data = yaml.safe_load(_SOLID_FIRST_YAML.read_text())
        for rule in data["rules"]:
            rid = rule.get("id", "<unknown>")
            assert "id" in rule, f"Rule missing 'id': {rule}"
            assert "message" in rule, f"Rule {rid} missing 'message'"
            assert "severity" in rule, f"Rule {rid} missing 'severity'"
            assert "languages" in rule, f"Rule {rid} missing 'languages'"
            assert rule["severity"] in {
                "ERROR",
                "WARNING",
                "INFO",
            }, f"Rule {rid} has invalid severity: {rule['severity']}"

    def test_test_scoped_rules_have_paths_include_tests(self):
        data = yaml.safe_load(_SOLID_FIRST_YAML.read_text())
        test_scoped_ids = {
            "first-no-sleep-in-tests",
            "first-no-environ-in-tests",
            "first-test-no-assert",
        }
        for rule in data["rules"]:
            if rule["id"] in test_scoped_ids:
                paths = rule.get("paths", {})
                includes = paths.get("include", [])
                assert any(
                    "tests" in inc for inc in includes
                ), f"Rule {rule['id']} should include 'tests/' in paths"
