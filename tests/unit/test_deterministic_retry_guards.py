"""Deterministic retry guards for GitHub API client code.

These tests use AST analysis to detect missing 429 (rate limit) retry handling
in GitHub publisher code. The code currently handles 5xx errors via subprocess
but does not handle 429 rate limit responses.

When violations are fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Files where GitHub API calls must have retry handling for 429 rate limits (issue #232)
_GITHUB_API_RETRY_FILES: tuple[Path, ...] = (_SRC / "adapters" / "github_publisher.py",)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _call_name(node: ast.AST) -> str | None:
    """Extract the full name of a function call (e.g., 'subprocess.run')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _has_retry_for_429(tree: ast.Module, func_name: str) -> bool:
    """
    Check if a function has retry logic for 429 status code.

    Returns True if the function contains:
    - A loop structure (for/while) with retry logic
    - A check for 429 status code or 'rate limit' in the retry logic
    - Backoff or sleep handling
    """
    retry_indicators = ("429", "rate_limit", "rate-limit", "RateLimit")
    backoff_indicators = ("time.sleep", "backoff", "retry", "wait")

    for node in ast.walk(tree):
        # Look for loop structures that might be retry loops
        if isinstance(node, (ast.For, ast.While)):
            # Check if the loop contains retry-related keywords
            loop_source = ast.unparse(node)
            has_429_check = any(ind in loop_source for ind in retry_indicators)
            has_backoff = any(ind in loop_source for ind in backoff_indicators)
            if has_429_check and has_backoff:
                return True

        # Look for try-except blocks that handle 429 specifically
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                if handler.type:
                    handler_source = ast.unparse(handler)
                    if any(ind in handler_source for ind in retry_indicators):
                        return True

    return False


def _find_github_api_call_sites(tree: ast.Module) -> list[tuple[int, str]]:
    """
    Find all GitHub API call sites in the AST.

    Returns list of (lineno, call_name) tuples for calls that need retry handling.
    """
    call_sites: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _call_name(node.func)
        if not call_name:
            continue

        # subprocess.run calls that invoke 'gh' CLI (these hit GitHub API)
        if call_name == "subprocess.run":
            # Check if this is a gh CLI call
            for arg in node.args:
                arg_source = ast.unparse(arg) if hasattr(ast, "unparse") else ""
                if "gh" in arg_source or (
                    isinstance(arg, ast.List)
                    and any(
                        isinstance(elt, ast.Constant)
                        and isinstance(elt.value, str)
                        and "gh" in elt.value
                        for elt in arg.elts
                    )
                ):
                    call_sites.append((node.lineno or 0, "subprocess.run (gh CLI)"))
                    break

        # httpx/requests calls to api.github.com
        if call_name in (
            "httpx.get",
            "httpx.post",
            "httpx.request",
            "httpx.AsyncClient",
            "requests.get",
            "requests.post",
            "requests.request",
        ):
            call_sites.append((node.lineno or 0, call_name))

    return call_sites


def _has_429_retry_logic(tree: ast.Module) -> bool:
    """
    Check if the module has retry logic specifically handling 429 status code.

    This looks for:
    1. A RETRYABLE_STATUS constant or similar that includes 429
    2. An explicit check for status_code == 429
    3. A function that handles rate limiting with backoff
    """
    source = ast.unparse(tree)

    # Check for 429 in retryable status codes
    if "429" in source:
        # Look for patterns like _RETRYABLE_STATUS = {..., 429, ...}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and "RETRY" in target.id.upper():
                        assign_source = ast.unparse(node)
                        if "429" in assign_source:
                            return True

            # Check for comparison with 429 (status_code == 429)
            if isinstance(node, ast.Compare):
                comp_source = ast.unparse(node)
                if "429" in comp_source and (
                    "status" in comp_source.lower() or "code" in comp_source.lower()
                ):
                    return True

    return False


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #232 - GitHub API client retries on 5xx but not on 429 rate limit",
    strict=False,
)
def test_232_github_api_client_has_429_retry_handling() -> None:
    """Detect missing 429 (rate limit) retry handling in GitHub API client code.

    Issue #232 (parent #198): GitHub API client code should retry on 429 rate limit
    responses with appropriate backoff, but currently only handles 5xx errors.

    According to GitHub API docs, 429 responses include X-RateLimit-Reset header
    that should be used to calculate backoff time.

    Violations:
        - GitHub API calls without retry logic for 429 status code
        - Missing check for rate limit headers (X-RateLimit-Remaining, X-RateLimit-Reset)
        - No backoff/wait logic when 429 is received

    Acceptance criteria for fix:
        - All GitHub API calls have retry logic that includes 429 status code
        - Rate limit headers are checked and respected
        - Exponential backoff with jitter is applied on 429 responses
    """
    violations: list[str] = []

    for path in _GITHUB_API_RETRY_FILES:
        if not path.exists():
            violations.append(f"{path}: file does not exist")
            continue

        tree = _parse(path)

        # Check if the file has any 429 retry handling
        has_429_handling = _has_429_retry_logic(tree)

        # Find GitHub API call sites
        call_sites = _find_github_api_call_sites(tree)

        if call_sites and not has_429_handling:
            for lineno, call_type in call_sites:
                violations.append(
                    f"{_rel(path)}:{lineno}: {call_type} lacks 429 rate limit retry handling (issue #232)"
                )

    assert violations == [], (
        "GitHub API client code must retry on 429 rate limit responses:\n"
        + "\n".join(violations)
        + "\n\nExpected: Retry logic that handles 429 with X-RateLimit-Reset header"
        + "\nSee: solver.py _RETRYABLE_STATUS and _extract_rate_limit for reference implementation"
    )
