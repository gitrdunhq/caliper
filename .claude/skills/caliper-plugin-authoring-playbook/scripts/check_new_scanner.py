#!/usr/bin/env python3
"""Gate check for a freshly authored plugin or detector file.

Not a substitute for the real test suite (`bash scripts/build-test.sh`) — this
is a fast, host-runnable lint over the *contract* (registration, tested-by
annotation, matching test file, fail-open/timeout hygiene for subprocess
plugins). Run it before you ask a human/agent to review the file, and again
before `make dogfood`.

Usage (from repo root):

    uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py <path>

Examples:

    uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py src/caliper/plugins/typos.py
    uv run python .claude/skills/caliper-plugin-authoring-playbook/scripts/check_new_scanner.py src/caliper/detectors/security/jwt_audience.py

Exit code 0 = no hard failures (warnings may still print). Exit code 1 = at
least one hard failure. This script does not import caliper — it is a pure
text/AST check over the one file you pass it, so it works even before the
file is wired into any registry.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check_plugin(path: Path, source: str) -> list[str]:
    """Return a list of hard-failure messages for a src/caliper/plugins/*.py file."""
    failures: list[str] = []
    tree = ast.parse(source, filename=str(path))

    scanner_plugin_classes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            (isinstance(base, ast.Name) and base.id == "ScannerPlugin")
            or (isinstance(base, ast.Attribute) and base.attr == "ScannerPlugin")
            for base in node.bases
        )
    ]
    if not scanner_plugin_classes:
        failures.append(
            "No class subclassing ScannerPlugin found. Every in-tree plugin must "
            "subclass caliper.core.plugin.ScannerPlugin (see docs/PLUGIN_SDK.md)."
        )

    if "@ANALYZERS.register(" not in source:
        failures.append(
            "Missing '@ANALYZERS.register(\"<name>\")' on a zero-arg factory function. "
            "autodiscover() only imports the module — nothing puts your plugin in the "
            "ANALYZERS registry without this decorator (see every existing "
            "src/caliper/plugins/*.py file for the pattern; docs/plugin-sdk.md's Quick "
            "Start omits this step, do not copy it verbatim)."
        )

    if "# tested-by:" not in source:
        failures.append(
            "Missing '# tested-by: tests/unit/test_<name>_plugin.py' annotation "
            "(CAL-014 will flag this; see docs/detectors.md)."
        )

    if path.name.startswith("_"):
        failures.append(
            f"Filename '{path.name}' starts with '_' — autodiscover() skips "
            "underscore-prefixed modules, your plugin will never load."
        )

    # Fail-open / timeout hygiene: any subprocess.run(...) call should carry
    # timeout= somewhere in the same call and be guarded for FileNotFoundError.
    if re.search(r"subprocess\.run\(", source):
        calls_without_timeout = 0
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            ):
                has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
                if not has_timeout:
                    calls_without_timeout += 1
        if calls_without_timeout:
            failures.append(
                f"{calls_without_timeout} subprocess.run(...) call(s) with no timeout= "
                "kwarg. Every external call must have a timeout — CLAUDE.md 'Fail-open'."
            )
        if "FileNotFoundError" not in source:
            failures.append(
                "subprocess.run(...) is used but FileNotFoundError is never caught — "
                "a missing binary will raise instead of returning "
                "PluginResult(error=error_msg(ErrorCode.NOT_INSTALLED, ...))."
            )

    return failures


def check_detector(path: Path, source: str) -> list[str]:
    """Return a list of hard-failure messages for a src/caliper/detectors/**/*.py file."""
    failures: list[str] = []
    tree = ast.parse(source, filename=str(path))

    bug_detector_classes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and any(
            (isinstance(base, ast.Name) and base.id == "BugDetector")
            or (isinstance(base, ast.Attribute) and base.attr == "BugDetector")
            for base in node.bases
        )
    ]
    if not bug_detector_classes:
        failures.append(
            "No class subclassing BugDetector found " "(caliper.detectors.framework.BugDetector)."
        )

    if "@register_detector" not in source:
        failures.append(
            "Missing '@register_detector' class decorator "
            "(caliper.detectors._registry.register_detector) — discover_detectors() "
            "imports the module but nothing puts it in the DETECTORS registry "
            "without this decorator."
        )

    if "# tested-by:" not in source:
        failures.append(
            "Missing '# tested-by: tests/unit/detectors/<category>/test_<name>.py' "
            "annotation (CAL-014 will flag this)."
        )

    ids = sorted(set(re.findall(r"CAL-\d{3}", source)))
    if not ids:
        failures.append('No detector_id matching "CAL-NNN" found in the file.')
    else:
        for detector_id in ids:
            num = int(detector_id.split("-")[1])
            if num < 1 or num > 999:
                failures.append(f"detector_id '{detector_id}' is out of range CAL-001..CAL-999.")

    if "def detect(self" not in source:
        failures.append("No detect(self, file_path) method found — BugDetector requires it.")

    return failures


def find_matching_test_file(path: Path) -> Path | None:
    """Best-effort convention check — does NOT fail the run, only warns."""
    rel = path.relative_to(REPO_ROOT)
    parts = rel.parts
    if parts[:2] == ("src", "caliper") and parts[2] == "plugins":
        stem = path.stem
        candidate = REPO_ROOT / "tests" / "unit" / f"test_{stem}_plugin.py"
        return candidate if candidate.exists() else None
    if parts[:2] == ("src", "caliper") and parts[2] == "detectors":
        # tests/unit/detectors/<same subpath>/test_<stem>.py
        sub = Path(*parts[3:-1])
        candidate = REPO_ROOT / "tests" / "unit" / "detectors" / sub / f"test_{path.stem}.py"
        return candidate if candidate.exists() else None
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1

    path = Path(argv[1]).resolve()
    if not path.is_file():
        print(f"ERROR: not a file: {path}")
        return 1

    try:
        rel = path.relative_to(REPO_ROOT)
    except ValueError:
        print(f"ERROR: {path} is not inside repo root {REPO_ROOT}")
        return 1

    source = _read(path)
    parts = rel.parts

    if len(parts) >= 3 and parts[0] == "src" and parts[1] == "caliper" and parts[2] == "plugins":
        kind = "plugin"
        failures = check_plugin(path, source)
    elif (
        len(parts) >= 3 and parts[0] == "src" and parts[1] == "caliper" and parts[2] == "detectors"
    ):
        kind = "detector"
        failures = check_detector(path, source)
    else:
        print(
            f"ERROR: {rel} is not under src/caliper/plugins/ or src/caliper/detectors/ "
            "— this script only checks those two locations."
        )
        return 1

    print(f"=== check_new_scanner: {rel} ({kind}) ===")

    test_file = find_matching_test_file(path)
    if test_file is None:
        print(
            "WARN: no matching test file found by naming convention "
            "(this is a warning, not a hard failure — RED/GREEN TDD may not have "
            "produced it yet, or your name deviates from convention)."
        )
    else:
        print(f"OK: matching test file exists at {test_file.relative_to(REPO_ROOT)}")

    if not failures:
        print("PASS: no hard-failure contract violations found.")
        return 0

    print(f"FAIL: {len(failures)} hard-failure contract violation(s):")
    for f in failures:
        print(f"  - {f}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
