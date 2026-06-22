# tested-by: tests/unit/test_deterministic_webhook_sig_guards.py
"""Deterministic detector for missing webhook signature validation.

Issue #221: GitHub webhook handler doesn't validate signature (parent #187).

These tests use AST analysis to detect webhook handlers that process
GitHub webhook payloads without validating the X-Hub-Signature-256 header.
Missing signature validation allows attackers to forge webhook events.

When the violation is fixed, the test will "pass" and xfail will report
an XPASS, at which point the xfail marker should be removed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Set

_REPO = Path(__file__).resolve().parents[2]
_SRC = _REPO / "src" / "caliper"

# Webhook handler files to check
_WEBHOOK_HANDLER_FILES: tuple[Path, ...] = (_SRC / "webhook" / "server.py",)

# Function names that indicate signature verification
_SIGNATURE_VERIFY_NAMES: Set[str] = {
    "_verify_signature",
    "verify_signature",
    "_check_signature",
    "check_signature",
    "hmac.compare_digest",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _get_call_name(node: ast.AST) -> str | None:
    """Extract the name of a function call from AST node."""
    if isinstance(node, ast.Call):
        return _get_call_name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _is_webhook_handler(node: ast.AST) -> bool:
    """Check if AST node is a webhook handler function.

    Webhook handlers are typically:
    - Async functions (async def)
    - Named 'webhook' or similar
    - Take a 'request' parameter
    """
    if not isinstance(node, ast.AsyncFunctionDef):
        return False

    # Check if it's the main webhook handler
    if node.name == "webhook":
        return True

    # Check if it has a 'request' parameter
    all_args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
    arg_names = {arg.arg for arg in all_args}

    # Common webhook handler patterns
    return "request" in arg_names and any(
        keyword in node.name.lower() for keyword in ("webhook", "hook", "github", "pr", "pull")
    )


def _has_signature_validation_in_body(body: list[ast.stmt]) -> bool:
    """Check if a list of AST statements contains signature validation.

    Looks for calls to:
    - _verify_signature
    - verify_signature
    - hmac.compare_digest
    - Any function containing 'signature' or 'hmac' in the name
    """
    for stmt in body:
        # Walk the AST looking for signature verification calls
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call):
                call_name = _get_call_name(child.func)
                if call_name:
                    # Check against known signature verification function names
                    if call_name in _SIGNATURE_VERIFY_NAMES:
                        return True
                    # Check for any signature-related function
                    if "signature" in call_name.lower() and (
                        "verify" in call_name.lower() or "check" in call_name.lower()
                    ):
                        return True
                    # Check for hmac operations
                    if "hmac" in call_name.lower():
                        return True
    return False


def _find_webhook_handlers_without_sig_validation(path: Path) -> list[str]:
    """Find webhook handlers in a file that lack signature validation.

    Returns a list of violation strings describing each issue found.
    """
    violations: list[str] = []
    tree = _parse(path)

    for node in ast.walk(tree):
        if _is_webhook_handler(node) and isinstance(node, ast.AsyncFunctionDef):
            # Check if the webhook handler has signature validation
            if not _has_signature_validation_in_body(node.body):
                violations.append(
                    f"{_rel(path)}:{node.lineno}: "
                    f"AsyncFunctionDef '{node.name}' processes webhooks "
                    f"without signature validation (no call to _verify_signature, "
                    f"verify_signature, hmac.compare_digest, or similar)"
                )

    return violations


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #187 - webhook handler doesn't validate signature",
    strict=False,
)
def test_187_webhook_handler_validates_signature() -> None:
    """Detect webhook handlers that lack signature validation.

    Issue #187 (via #221): GitHub webhook handlers must validate the
    X-Hub-Signature-256 header using HMAC-SHA256 to prevent attackers
    from forging webhook events.

    Violation: The webhook handler in server.py processes webhook payloads
    without calling _verify_signature or equivalent signature validation.

    Acceptance criteria for fix:
        - Webhook handler calls _verify_signature before processing payload
        - Returns 401 if signature is missing or invalid
        - Uses hmac.compare_digest for timing-safe comparison
    """
    violations: list[str] = []

    for path in _WEBHOOK_HANDLER_FILES:
        if not path.exists():
            continue

        file_violations = _find_webhook_handlers_without_sig_validation(path)
        violations.extend(file_violations)

    assert (
        violations == []
    ), "Webhook handlers must validate signatures before processing payloads:\n" + "\n".join(
        violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #221 - webhook signature validation missing",
    strict=False,
)
def test_221_webhook_server_has_verify_signature_call() -> None:
    """Specific test for _verify_signature call in webhook server.

    The webhook handler in src/caliper/webhook/server.py must call
    _verify_signature() to validate GitHub webhook signatures.
    Missing this call allows forged webhook events.
    """
    path = _SRC / "webhook" / "server.py"

    if not path.exists():
        pytest.skip(f"File not found: {path}")

    tree = _parse(path)

    found_verify_call = False

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _get_call_name(node.func)
            if call_name == "_verify_signature":
                found_verify_call = True
                break

    assert found_verify_call, (
        f"{_rel(path)}: Missing call to _verify_signature() in webhook server. "
        f"GitHub webhook handlers must validate HMAC-SHA256 signatures."
    )
