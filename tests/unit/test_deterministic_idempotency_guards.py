# tested-by: tests/unit/test_deterministic_idempotency_guards.py
"""Deterministic detector for missing idempotency keys in background jobs (#172).

Detects when job processing code lacks idempotency key validation. Background
jobs that process work items without idempotency keys are vulnerable to:
- Duplicate processing on retries
- Race conditions in parallel job runners
- Inconsistent state on worker restarts

These tests intentionally encode the invariant that job processing must check
idempotency keys before execution. They may fail while the corresponding
bugs are open.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Mark all tests as xfail — these are deterministic bug detectors
pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector for #172 — add idempotency keys to fix",
    strict=False,
)

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"


# Files that contain job processing code
_JOB_PROCESSING_PATHS = (
    _SRC / "core" / "concern_remediate.py",
    _SRC / "core" / "concern_review.py",
    _SRC / "data" / "catalog.py",
)

# Idempotency patterns that should be present in job processing code
_IDEMPOTENCY_PATTERNS = (
    "idempotency",
    "idempotent",
    "idempotency_key",
    "dedup_key",
    "duplicate_check",
    "already_processed",
    "job_exists",
    "seen_jobs",
)


def _python_files(root: Path) -> list[Path]:
    """Get all Python files under root, excluding __pycache__."""
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _rel(path: Path) -> str:
    """Get repo-relative path string."""
    return path.relative_to(_REPO).as_posix()


def _has_idempotency_pattern(source_text: str) -> bool:
    """Check if source text contains any idempotency-related patterns."""
    source_lower = source_text.lower()
    return any(pattern.lower() in source_lower for pattern in _IDEMPOTENCY_PATTERNS)


def _find_threadpool_job_processing(tree: ast.Module) -> list[tuple[str, int]]:
    """Find ThreadPoolExecutor usage that submits work without idempotency checks.

    Returns list of (function_name, lineno) tuples for job processing functions.
    """
    findings: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        # Look for ThreadPoolExecutor usage
        if isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    call = item.context_expr
                    if isinstance(call.func, ast.Name) and call.func.id == "ThreadPoolExecutor":
                        # Found ThreadPoolExecutor context manager
                        # Check if the with block submits jobs
                        for stmt in node.body:
                            if isinstance(stmt, ast.For):
                                # Look for pool.submit() inside a for loop
                                for subnode in ast.walk(stmt):
                                    if (
                                        isinstance(subnode, ast.Call)
                                        and isinstance(subnode.func, ast.Attribute)
                                        and subnode.func.attr == "submit"
                                    ):
                                        findings.append(("ThreadPoolExecutor.submit", stmt.lineno))

        # Look for direct ThreadPoolExecutor().submit() calls outside context managers
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "submit":
                # Check if this is a pool/executor submit
                if isinstance(node.func.value, ast.Name):
                    if (
                        "pool" in node.func.value.id.lower()
                        or "executor" in node.func.value.id.lower()
                    ):
                        findings.append((f"{node.func.value.id}.submit", node.lineno))

    return findings


def _find_queue_scan_inserts(tree: ast.Module) -> list[tuple[str, int]]:
    """Find database queue operations that insert without idempotency checks.

    Returns list of (operation_type, lineno) tuples.
    """
    findings: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        # Look for INSERT INTO scan_queue patterns
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            sql = node.value.upper()
            if "INSERT INTO SCAN_QUEUE" in sql or "INSERT INTO JOB" in sql:
                findings.append(("queue_insert", node.lineno))

        # Look for queue_scan method definitions
        if isinstance(node, ast.FunctionDef) and node.name == "queue_scan":
            findings.append(("queue_scan_method", node.lineno))

    return findings


@pytest.mark.xfail(reason="deterministic bug detector for #172", strict=False)
def test_concern_remediate_lacks_job_idempotency() -> None:
    """#172: Concern remediation parallel fan-out lacks idempotency keys.

    The remediation code submits jobs to ThreadPoolExecutor without checking
    if the same concern has already been processed. This can cause duplicate
    remediation attempts when:
    - The same concern appears in multiple batches
    - Workers restart and reprocess
    - Retries happen after partial failures

    Target (concern_remediate.py:217-223):
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(_remediate_one, remediator, f, repo_path): ...
                for f in remaining
            }

    Fix #172: Add idempotency key check before submitting to pool.
    """
    path = _SRC / "core" / "concern_remediate.py"
    if not path.exists():
        pytest.skip("concern_remediate.py not found")

    source_text = path.read_text()
    tree = _parse(path)

    # Check if the file has idempotency patterns
    has_idempotency = _has_idempotency_pattern(source_text)

    # Find ThreadPoolExecutor job processing
    job_sites = _find_threadpool_job_processing(tree)

    # If there are job processing sites but no idempotency patterns, it's a bug
    if job_sites and not has_idempotency:
        pytest.fail(
            f"BUG DETECTED: concern_remediate.py processes jobs without idempotency keys.\n"
            f"Location: {_rel(path)}\n"
            f"Found {len(job_sites)} job submission site(s) without idempotency checks.\n"
            f"Issue: Parallel fan-out via ThreadPoolExecutor.submit() lacks deduplication.\n"
            f"Risk: Duplicate processing on retries or restarts.\n"
            f"Bug #172: Add idempotency key validation before job submission."
        )


@pytest.mark.xfail(reason="deterministic bug detector for #172", strict=False)
def test_concern_review_lacks_job_idempotency() -> None:
    """#172: Concern review parallel processing lacks idempotency keys.

    The review code uses ThreadPoolExecutor to process concerns in parallel
    without checking if concerns have already been reviewed. This can lead to:
    - Duplicate AI calls for the same concern
    - Wasted tokens and API quota
    - Inconsistent review state

    Target (concern_review.py:479+):
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_review_one, ...): ... for ...}

    Fix #172: Add idempotency key check before submitting review jobs.
    """
    path = _SRC / "core" / "concern_review.py"
    if not path.exists():
        pytest.skip("concern_review.py not found")

    source_text = path.read_text()
    tree = _parse(path)

    # Check if the file has idempotency patterns
    has_idempotency = _has_idempotency_pattern(source_text)

    # Find ThreadPoolExecutor job processing
    job_sites = _find_threadpool_job_processing(tree)

    # If there are job processing sites but no idempotency patterns, it's a bug
    if job_sites and not has_idempotency:
        pytest.fail(
            f"BUG DETECTED: concern_review.py processes jobs without idempotency keys.\n"
            f"Location: {_rel(path)}\n"
            f"Found {len(job_sites)} job submission site(s) without idempotency checks.\n"
            f"Issue: Parallel concern review lacks deduplication.\n"
            f"Risk: Duplicate AI calls and wasted tokens.\n"
            f"Bug #172: Add idempotency key validation before review submission."
        )


@pytest.mark.xfail(reason="deterministic bug detector for #172", strict=False)
def test_catalog_queue_scan_lacks_idempotency() -> None:
    """#172: Catalog queue_scan lacks idempotency check on insert.

    The queue_scan method inserts directly into scan_queue table without
    checking if an identical scan request already exists. This causes:
    - Duplicate scan queue entries for the same package
    - Redundant scanning work
    - Database bloat from duplicate rows

    Target (catalog.py:315-320):
        INSERT INTO scan_queue
            (ecosystem, package_name, version, scan_type, priority, requested_by)
        VALUES (%s, %s, %s, %s, %s, %s)

    Fix #172: Use INSERT ... ON CONFLICT or check existence before insert.
    """
    path = _SRC / "data" / "catalog.py"
    if not path.exists():
        pytest.skip("catalog.py not found")

    source_text = path.read_text()

    # Check if queue_scan method specifically has idempotency protection
    # Look for ON CONFLICT within the queue_scan function specifically
    # We need to extract the queue_scan function and check it

    tree = _parse(path)

    # Find queue_scan method and check its SQL for ON CONFLICT
    queue_scan_has_upsert = False
    queue_scan_found = False

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "queue_scan":
            queue_scan_found = True
            # Get the source of just this function
            func_source = ast.unparse(node)
            # Check if this specific function has ON CONFLICT
            if "ON CONFLICT" in func_source.upper():
                queue_scan_has_upsert = True
            break

    # If queue_scan exists but doesn't have ON CONFLICT, it's a bug
    if queue_scan_found and not queue_scan_has_upsert:
        pytest.fail(
            f"BUG DETECTED: catalog.py queue_scan lacks idempotency protection.\n"
            f"Location: {_rel(path)}:queue_scan\n"
            f"Issue: INSERT INTO scan_queue without ON CONFLICT clause.\n"
            f"Risk: Duplicate scan entries for same package/version.\n"
            f"Bug #172: Add ON CONFLICT (ecosystem, package_name, version) DO NOTHING."
        )


@pytest.mark.xfail(reason="deterministic bug detector for #172", strict=False)
def test_job_processing_files_have_idempotency_keywords() -> None:
    """#172: Job processing files should reference idempotency concepts.

    This is a broader check that any file containing job/queue/worker patterns
    has at least some reference to idempotency, deduplication, or duplicate
    prevention in comments, variable names, or function names.
    """
    violations: list[str] = []

    job_related_patterns = ("queue", "job", "worker", "executor", "pool")

    for path in _python_files(_SRC):
        source_text = path.read_text()
        source_lower = source_text.lower()

        # Check if file has job-related patterns
        has_job_patterns = any(pattern in source_lower for pattern in job_related_patterns)

        # Skip files without job patterns
        if not has_job_patterns:
            continue

        # Check for idempotency patterns
        has_idempotency = _has_idempotency_pattern(source_text)

        # Skip files that already have idempotency
        if has_idempotency:
            continue

        # Check for ThreadPoolExecutor usage (actual job processing)
        tree = _parse(path)
        job_sites = _find_threadpool_job_processing(tree)
        queue_ops = _find_queue_scan_inserts(tree)

        # If it has actual job processing without idempotency, flag it
        if job_sites or queue_ops:
            violations.append(
                f"{_rel(path)}: job processing without idempotency references "
                f"({len(job_sites)} thread sites, {len(queue_ops)} queue ops)"
            )

    # Only report if we found violations (with a threshold to avoid noise)
    if len(violations) > 0:
        pytest.fail(
            f"BUG DETECTED: {len(violations)} file(s) with job processing lack idempotency keywords.\n"
            f"Bug #172: Background jobs should have idempotency key handling.\n"
            f"Files:\n" + "\n".join(f"  - {v}" for v in violations)
        )
