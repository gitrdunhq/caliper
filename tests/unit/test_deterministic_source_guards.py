"""Deterministic source guards — tests that detect known bugs via static analysis.

# tested-by: tests/unit/test_deterministic_source_guards.py

These tests use AST analysis and file inspection to detect specific code
patterns that indicate known bugs. Marked with xfail to track until fixed.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

# =============================================================================
# Issue #268: Normalizer Collapse Rule
# =============================================================================


def _get_normalizer_source_info():
    """Get source info for normalizer.py to parse AST."""
    from caliper.core import normalizer

    source_path = Path(inspect.getfile(normalizer))
    source = source_path.read_text()
    return ast.parse(source), source_path


@pytest.mark.xfail(
    reason="deterministic bug detector #234: normalizer collapse without advisory_id",
    strict=False,
)
def test_normalizer_dedup_key_missing_source_tool():
    """Detect that normalizer dedup key doesn't include source_tool.

    Bug #234: When findings have None advisory_id, the dedup key treats them
    as equal even if they come from different source tools. This causes
    distinct findings to be incorrectly collapsed.

    Current code (normalizer.py:40):
        key = (f.advisory_id, f.category, f.package_name, f.version)

    Should include source_tool to prevent cross-tool collapse.
    """
    tree, source_path = _get_normalizer_source_info()

    # Find the normalize_findings function
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "normalize_findings":
            # Look for the dedup key construction
            for stmt in ast.walk(node):
                if isinstance(stmt, (ast.Tuple, ast.List)):
                    # Check tuple elements
                    elements = ast.dump(stmt)
                    # The dedup key should include source_tool
                    if "advisory_id" in elements and "source_tool" not in elements:
                        pytest.fail(
                            f"BUG DETECTED: dedup key at {source_path} lacks source_tool.\n"
                            f"Current key: (advisory_id, category, package_name, version)\n"
                            f"This causes findings with None advisory_id from different "
                            f"tools to be incorrectly collapsed.\n"
                            f"Fix #234: Add source_tool to the dedup key."
                        )

    # Alternative detection: look for the specific line pattern
    source = source_path.read_text()
    if "key = (f.advisory_id, f.category, f.package_name, f.version)" in source:
        pytest.fail(
            "BUG DETECTED: normalizer.py uses weak dedup key without source_tool.\n"
            "Line: key = (f.advisory_id, f.category, f.package_name, f.version)\n"
            "Bug #234: Findings with None advisory_id from different tools collapse.\n"
            "Fix: Add f.source_tool to the tuple."
        )


# =============================================================================
# Issue #267: Composite Action Delimiter Rule
# =============================================================================


def _load_action_yml():
    """Load action.yml from repo root."""
    repo_root = Path(__file__).parent.parent.parent
    action_path = repo_root / "action.yml"
    if not action_path.exists():
        pytest.skip("action.yml not found")

    import yaml

    return yaml.safe_load(action_path.read_text()), action_path


@pytest.mark.xfail(
    reason="deterministic bug detector #233: fixed MEMO_EOF delimiter vulnerability",
    strict=False,
)
def test_composite_action_fixed_memo_eof_delimiter():
    """Detect fixed MEMO_EOF delimiter in composite action output.

    Bug #233: The composite action uses a fixed delimiter 'MEMO_EOF' for
    multiline GitHub output. If memo content contains a line with just
    'MEMO_EOF', it would prematurely terminate the output block.

    Target (action.yml:82-84):
        echo "memo<<MEMO_EOF" >> "$GITHUB_OUTPUT"
        cat "$MEMO_FILE" >> "$GITHUB_OUTPUT"
        echo "MEMO_EOF" >> "$GITHUB_OUTPUT"

    Fix #233: Use a randomized delimiter or JSON encoding.
    """
    action_data, action_path = _load_action_yml()

    # Navigate to the composite action steps
    runs = action_data.get("runs", {})
    steps = runs.get("steps", [])

    found_delimiter_usage = False
    for step in steps:
        run_script = step.get("run", "")
        if "MEMO_EOF" in run_script:
            found_delimiter_usage = True
            # Check if it's a fixed pattern (not randomized)
            if 'echo "memo<<MEMO_EOF"' in run_script:
                pytest.fail(
                    f"BUG DETECTED: Fixed MEMO_EOF delimiter in {action_path}.\n"
                    f"Vulnerability: Memo content containing 'MEMO_EOF' could "
                    f"prematurely terminate output block.\n"
                    f"Bug #233: Use randomized delimiter or JSON encoding.\n"
                    f"Location: action.yml step with GITHUB_OUTPUT"
                )

    if not found_delimiter_usage:
        pytest.fail(
            "Could not find MEMO_EOF delimiter usage in action.yml. "
            "The test may need updating if the action structure changed."
        )


# =============================================================================
# Issue #266: FileEvidenceStore Security Rule
# =============================================================================


def _get_persistence_source_info():
    """Get source info for persistence.py to parse AST."""
    from caliper.adapters import persistence

    source_path = Path(inspect.getfile(persistence))
    source = source_path.read_text()
    return ast.parse(source), source_path, source


@pytest.mark.xfail(
    reason="deterministic bug detector #232: FileEvidenceStore lacks security guards",
    strict=False,
)
def test_file_evidence_store_lacks_traversal_validation():
    """Detect that FileEvidenceStore lacks path traversal validation.

    Bug #232: FileEvidenceStore.write_artifact lacks security controls present
    in EvidenceStore:
    - No path traversal validation (no is_relative_to checks)
    - No atomic write (direct write_bytes instead of temp+rename)

    Target (persistence.py:49-57):
        def write_artifact(self, path: str, content: bytes) -> str:
            target = self.base_dir / path  # Direct concatenation!
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)    # Direct write, no atomicity
            return str(target)

    Compare to EvidenceStore (evidence.py:43-103) which has:
    - is_relative_to checks for traversal
    - temp file + rename for atomicity

    Fix #232: Add is_relative_to() validation or delegate to EvidenceStore.
    """
    tree, source_path, source_text = _get_persistence_source_info()

    # Find FileEvidenceStore class
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "FileEvidenceStore":
            # Find write_artifact method
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == "write_artifact":
                    method_source = ast.unparse(item)

                    # Check for missing traversal validation
                    if "is_relative_to" not in method_source:
                        # Also verify this is the problematic implementation
                        if "target = self.base_dir / path" in method_source:
                            pytest.fail(
                                f"BUG DETECTED: FileEvidenceStore lacks traversal validation.\n"
                                f"Location: {source_path}, write_artifact method\n"
                                f"Issue: Direct Path concatenation without is_relative_to check.\n"
                                f"Risk: Path traversal vulnerability.\n"
                                f"Bug #232: Add is_relative_to validation like EvidenceStore."
                            )

    # Fallback: check raw source for the vulnerable pattern
    if "class FileEvidenceStore" in source_text:
        if "is_relative_to" not in source_text:
            pytest.fail(
                f"BUG DETECTED: FileEvidenceStore class lacks is_relative_to checks.\n"
                f"Location: {source_path}\n"
                f"Bug #232: Path traversal validation missing. "
                f"See EvidenceStore for correct implementation."
            )


@pytest.mark.xfail(
    reason="deterministic bug detector #232: FileEvidenceStore lacks atomic writes",
    strict=False,
)
def test_file_evidence_store_lacks_atomic_write():
    """Detect that FileEvidenceStore lacks atomic write pattern.

    Bug #232: FileEvidenceStore.write_artifact writes directly to the target
    path instead of using temp+rename pattern for atomicity.

    EvidenceStore uses: tempfile.mkstemp + write + os.rename
    FileEvidenceStore uses: direct write_bytes

    Risk: Half-written files on crash, inconsistent state.

    Fix #232: Use temp file + atomic rename pattern.
    """
    tree, source_path, source_text = _get_persistence_source_info()

    # Check FileEvidenceStore for atomic write pattern
    if "class FileEvidenceStore" in source_text:
        # Look for write_artifact and check if it uses atomic pattern
        # Atomic pattern requires: temp file creation + rename
        has_atomic_pattern = (
            "mkstemp" in source_text
            or "NamedTemporaryFile" in source_text
            or "os.rename" in source_text
        )

        if not has_atomic_pattern:
            # Verify direct write pattern exists (confirming the bug)
            if ".write_bytes(content)" in source_text:
                pytest.fail(
                    f"BUG DETECTED: FileEvidenceStore lacks atomic writes.\n"
                    f"Location: {source_path}, write_artifact method\n"
                    f"Issue: Uses direct write_bytes instead of temp+rename.\n"
                    f"Risk: Half-written files on crash.\n"
                    f"Bug #232: Use atomic write pattern like EvidenceStore "
                    f"(tempfile.mkstemp + os.rename)."
                )
