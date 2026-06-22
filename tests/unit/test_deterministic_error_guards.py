"""Deterministic error guards — tests that detect exposed stack traces in error responses.

# tested-by: tests/unit/test_deterministic_error_guards.py

These tests use AST analysis to detect when exception handling exposes internal
details (like stack traces) in external-facing error responses.

Issue #213: Deterministic rule for #179 — Error responses expose internal stack traces.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

# =============================================================================
# Issue #179: Error responses expose internal stack traces
# =============================================================================


def _get_webhook_server_source_info():
    """Get source info for webhook server to parse AST."""
    from caliper.webhook import server

    source_path = Path(inspect.getfile(server))
    source = source_path.read_text()
    return ast.parse(source), source_path, source


@pytest.mark.xfail(
    reason="deterministic bug detector #179: error responses expose internal stack traces",
    strict=False,
)
def test_webhook_exposes_exception_in_error_response():
    """Detect that webhook server exposes raw exceptions in external responses.

    Bug #179: The webhook server catches exceptions and includes them directly
    in user-facing responses (PR comments), potentially exposing internal stack
    traces and sensitive implementation details.

    Target (server.py:213-215):
        except Exception as exc:
            logger.error("webhook_review_failed", error=str(exc), pr_url=pr_url)
            review_output = f"caliper review could not run: {exc}"  # EXPOSED!

    The `exc` object (when converted to string) may contain full stack traces
    depending on how the exception was raised. This gets posted as a PR comment,
    leaking internal implementation details to external users.

    Fix #179: Sanitize error messages before including in external responses.
    Use generic error messages for users, log detailed errors internally.
    """
    tree, source_path, source_text = _get_webhook_server_source_info()

    # Find the webhook handler function
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "webhook":
            # Look for exception handlers that expose exc in responses
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.ExceptHandler):
                    # Check if this handler captures an exception variable
                    if stmt.name:
                        exc_var = stmt.name

                        # Walk through the handler body to find string formatting
                        # that includes the exception variable
                        for handler_stmt in ast.walk(stmt):
                            # Look for f-strings or .format() that include exc
                            if isinstance(handler_stmt, ast.JoinedStr):
                                # Check if exc variable appears in f-string
                                for value in ast.walk(handler_stmt):
                                    if isinstance(value, ast.Name) and value.id == exc_var:
                                        # Found exc in an f-string - check if it's
                                        # assigned to a response variable
                                        pytest.fail(
                                            f"BUG DETECTED: Exception variable '{exc_var}' "
                                            f"exposed in f-string within error handler.\n"
                                            f"Location: {source_path}\n"
                                            f"Issue: Raw exception included in user-facing response.\n"
                                            f"Risk: Stack traces and internal details leaked to PR comments.\n"
                                            f"Bug #179: Sanitize error messages before external exposure.\n"
                                            f"Use generic messages for users, detailed logs for internals."
                                        )

    # Fallback: check raw source for the specific vulnerable pattern
    vulnerable_patterns = [
        'review_output = f"caliper review could not run: {exc}"',
        "review_output = f'caliper review could not run: {exc}'",
    ]

    for pattern in vulnerable_patterns:
        if pattern in source_text:
            pytest.fail(
                f"BUG DETECTED: Raw exception exposed in error response.\n"
                f"Location: {source_path}\n"
                f"Pattern found: {pattern}\n"
                f"Issue: Exception object may contain stack traces when converted to string.\n"
                f"Risk: Internal implementation details leaked to external PR comments.\n"
                f"Bug #179: Use sanitized error messages for external responses.\n"
                f"Fix: Replace with generic message like 'caliper review could not run: internal error'"
            )

    # Also check for other patterns that might expose exception details
    # Look for str(exc) in string formatting
    if "str(exc)" in source_text or "{exc}" in source_text:
        # Verify this is in the context of a user-facing message
        lines = source_text.split("\n")
        for i, line in enumerate(lines):
            if "str(exc)" in line or "{exc}" in line:
                # Check surrounding context for response/comment/output patterns
                context = "\n".join(lines[max(0, i - 3) : min(len(lines), i + 3)])
                if any(
                    kw in context.lower()
                    for kw in ["review_output", "comment", "response", "output"]
                ):
                    pytest.fail(
                        f"BUG DETECTED: Exception details may be exposed in user-facing output.\n"
                        f"Location: {source_path}:{i + 1}\n"
                        f"Context:\n{context}\n"
                        f"Issue: Exception variable used in output context.\n"
                        f"Bug #179: Sanitize error messages before external exposure."
                    )


@pytest.mark.xfail(
    reason="deterministic bug detector #179: error response lacks sanitization",
    strict=False,
)
def test_webhook_error_response_uses_safe_error_function():
    """Detect that webhook server lacks _scrub_token_from_error for exception messages.

    Bug #179: The webhook has `_scrub_token_from_error` to sanitize token exposure,
    but similar sanitization is not applied to exception messages that may contain
    internal paths, function names, or stack traces.

    Target (server.py:213-215):
        review_output = f"caliper review could not run: {exc}"

    The `_scrub_token_from_error` function is used for comment errors (line 228)
    but not for review errors (line 215).

    Fix #179: Create a `_sanitize_error_for_external` function that removes
    internal details from error messages before they go to PR comments.
    """
    tree, source_path, source_text = _get_webhook_server_source_info()

    # Check if there's any sanitization function for error messages
    has_error_sanitization = "_sanitize" in source_text or "_scrub" in source_text

    # Look for the specific pattern where exc is used without sanitization
    # in the review error context
    lines = source_text.split("\n")
    in_review_error_section = False

    for i, line in enumerate(lines):
        # Track when we're in the review error handling section
        if "webhook_review_failed" in line:
            in_review_error_section = True

        if in_review_error_section:
            # Check if exc is used directly
            if "{exc}" in line or "str(exc)" in line:
                # Verify it's not using a sanitizer
                if not any(s in line for s in ["_sanitize", "_scrub", "safe_"]):
                    pytest.fail(
                        f"BUG DETECTED: Exception used without sanitization in error response.\n"
                        f"Location: {source_path}:{i + 1}\n"
                        f"Line: {line.strip()}\n"
                        f"Issue: Raw exception may expose stack traces and internal details.\n"
                        f"Bug #179: Add error message sanitization before external exposure.\n"
                        f"Fix: Use sanitized error messages or generic error text for PR comments."
                    )

            # Exit the section after we've processed the relevant lines
            if i > 0 and line.strip().startswith("# ---"):
                in_review_error_section = False
