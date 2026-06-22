# tested-by: tests/unit/test_deterministic_webhook_guards.py
"""Deterministic webhook guards — tests that detect payload bloat issues.

These tests use AST analysis and file inspection to detect when webhook
payloads include full finding objects that can cause size blowup.
Marked with xfail to track until fixed.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# =============================================================================
# Issue #210: Webhook Payload Size Blowup Rule
# =============================================================================


@pytest.mark.xfail(
    reason="deterministic bug detector #210: webhook payload includes full finding objects",
    strict=False,
)
def test_webhook_payload_does_not_include_full_findings():
    """Detect that webhook payload builder includes full finding objects.

    Bug #210: The webhook payload builder was including the full `results`
    list from ReviewResult, which contains complete PluginResult objects
    with all findings. This causes payload size blowup when there are many
    findings, potentially exceeding limits and causing memory/DoS issues.

    Current safe code (server.py:204-208):
        review_output = (
            f"verdict: {result.verdict}, "
            f"security: {result.security_score:.1f}, "
            f"quality: {result.quality_score:.1f}"
        )

    Bug pattern to detect:
        - Any reference to result.results in the webhook handler
        - Serializing full ReviewResult to JSON
        - Including raw findings list in the payload

    Fix #210: Only extract necessary summary fields (verdict, scores)
    and never include the full results list.
    """
    repo_root = Path(__file__).parent.parent.parent
    server_path = repo_root / "src" / "caliper" / "webhook" / "server.py"

    if not server_path.exists():
        pytest.skip("webhook server.py not found")

    source = server_path.read_text()
    tree = ast.parse(source)

    # Detection strategy 1: Look for result.results access in webhook handler
    in_webhook_handler = False
    webhook_func = None

    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "webhook":
            webhook_func = node
            break
        # Also check for the async function inside build_app
        if isinstance(node, ast.AsyncFunctionDef):
            # Check if it contains webhook route handling logic
            source_segment = ast.get_source_segment(source, node)
            if source_segment and (
                "request.json()" in source_segment or "X-GitHub-Event" in source_segment
            ):
                webhook_func = node
                break

    if webhook_func:
        # Walk the webhook function AST to find result.results access
        func_source = ast.get_source_segment(source, webhook_func) or ""

        # Check for dangerous patterns that include full results
        dangerous_patterns = [
            "result.results",
            "result.findings",
            "json.dumps(result)",
            "json.dumps({**result",
            "result.dict()",
            "result.model_dump",
        ]

        for pattern in dangerous_patterns:
            if pattern in func_source:
                pytest.fail(
                    f"BUG DETECTED: Webhook payload includes full finding objects.\n"
                    f"Location: {server_path}\n"
                    f"Pattern found: {pattern}\n"
                    f"Bug #210: Including full results/findings causes payload size blowup.\n"
                    f"Fix: Only extract verdict, security_score, quality_score.\n"
                    f"Never serialize result.results or raw findings."
                )

    # Detection strategy 2: Look for any JSON serialization of result object
    import_pattern_found = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            # Check for json.dumps(result) or similar
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name in ("json.dumps", "dumps"):
                # Check arguments for result
                for arg in node.args:
                    if isinstance(arg, ast.Name) and arg.id == "result":
                        pytest.fail(
                            f"BUG DETECTED: Full ReviewResult serialized to JSON in webhook.\n"
                            f"Location: {server_path}\n"
                            f"Pattern: json.dumps(result)\n"
                            f"Bug #210: This includes full finding objects causing size blowup.\n"
                            f"Fix: Only serialize specific fields (verdict, scores)."
                        )

    # Detection strategy 3: Check for result.model_dump() or similar
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("model_dump", "dict", "json"):
                    if isinstance(node.func.value, ast.Name):
                        if node.func.value.id == "result":
                            pytest.fail(
                                f"BUG DETECTED: ReviewResult converted to dict/JSON in webhook.\n"
                                f"Location: {server_path}\n"
                                f"Pattern: result.{node.func.attr}()\n"
                                f"Bug #210: This includes full finding objects causing size blowup.\n"
                                f"Fix: Only extract specific fields needed for output."
                            )

    # Detection strategy 4: Direct source text analysis for result.results access
    # Look specifically in the review output building section
    lines = source.splitlines()
    in_output_building = False
    paren_depth = 0

    for i, line in enumerate(lines):
        # Track when we're in the review output building section
        if "review_output" in line or "review_output:" in line:
            in_output_building = True

        if in_output_building:
            # Check for result.results or similar full object access
            if "result.results" in line or "result[" in line and "results" in line:
                pytest.fail(
                    f"BUG DETECTED: Webhook includes full results list at line {i+1}.\n"
                    f"Code: {line.strip()}\n"
                    f"Bug #210: Including result.results causes payload size blowup.\n"
                    f"Fix: Only use result.verdict, result.security_score, result.quality_score."
                )

            # Track parentheses to know when assignment ends
            paren_depth += line.count("(") - line.count(")")
            if line.strip().endswith(")") and paren_depth <= 0:
                in_output_building = False

    # Final validation: Ensure only safe fields are accessed
    # The safe pattern is: only verdict, security_score, quality_score
    safe_fields = {"verdict", "security_score", "quality_score"}
    result_access_pattern = "result."

    for i, line in enumerate(lines):
        if result_access_pattern in line:
            # Extract what field is being accessed
            start = line.find(result_access_pattern) + len(result_access_pattern)
            end = start
            while end < len(line) and (line[end].isalnum() or line[end] == "_"):
                end += 1
            field = line[start:end]

            if field and field not in safe_fields and not field.startswith("_"):
                # Check if this is inside the webhook handler function
                # by looking at surrounding context
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 5)
                context = "\n".join(lines[context_start:context_end])

                if "webhook" in context.lower() or "review_output" in context:
                    pytest.fail(
                        f"BUG DETECTED: Unsafe field access in webhook payload: result.{field}\n"
                        f"Location: {server_path}:{i+1}\n"
                        f"Code: {line.strip()}\n"
                        f"Bug #210: Accessing result.{field} may include full finding objects.\n"
                        f"Safe fields are: {safe_fields}\n"
                        f"Fix: Only access verdict, security_score, quality_score."
                    )


@pytest.mark.xfail(
    reason="deterministic bug detector #210: webhook payload size limit not enforced",
    strict=False,
)
def test_webhook_payload_has_size_enforcement():
    """Detect that webhook payload builder doesn't enforce size limits.

    Bug #210: Even with safe field extraction, the payload could grow
    large if many findings are summarized. There should be explicit size
    limits and/or truncation on the output.

    Current code should have:
        - Max length limits on comment_body
        - Truncation when review_output exceeds threshold
        - Logging when truncation occurs
    """
    repo_root = Path(__file__).parent.parent.parent
    server_path = repo_root / "src" / "caliper" / "webhook" / "server.py"

    if not server_path.exists():
        pytest.skip("webhook server.py not found")

    source = server_path.read_text()

    # Check for size limiting patterns
    size_patterns = [
        "len(comment_body)",
        "comment_body[:",
        "truncat",
        "MAX_COMMENT",
        "max_length",
    ]

    has_size_limit = any(pattern in source for pattern in size_patterns)

    if not has_size_limit:
        pytest.fail(
            f"BUG DETECTED: Webhook payload has no size enforcement.\n"
            f"Location: {server_path}\n"
            f"Bug #210: Large review outputs could exceed GitHub comment limits.\n"
            f"Fix: Add size check and truncation before posting comment:\n"
            f"  if len(comment_body) > MAX_COMMENT_LENGTH:\n"
            f"      comment_body = comment_body[:MAX_COMMENT_LENGTH] + '... (truncated)'"
        )


@pytest.mark.xfail(
    reason="deterministic bug detector #210: findings logged at debug/info level",
    strict=False,
)
def test_webhook_does_not_log_full_findings():
    """Detect that webhook logs full finding objects at debug/info level.

    Bug #210: Even if not sent in HTTP payload, logging full findings
    at debug or info level causes log bloat and potential PII exposure.

    Current safe pattern: Only log verdict/scores, never raw findings.
    """
    repo_root = Path(__file__).parent.parent.parent
    server_path = repo_root / "src" / "caliper" / "webhook" / "server.py"

    if not server_path.exists():
        pytest.skip("webhook server.py not found")

    source = server_path.read_text()
    tree = ast.parse(source)

    # Look for logger calls that include findings
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                # Check if it's a logger method
                if isinstance(node.func.value, ast.Attribute):
                    if node.func.value.attr in ("info", "debug", "warning", "error"):
                        func_name = f"{node.func.value.attr}.{node.func.attr}"

            if func_name in ("info", "debug", "warning"):
                # Check if findings/results are in the keywords
                for keyword in node.keywords:
                    if keyword.arg in ("findings", "results", "raw_results"):
                        pytest.fail(
                            f"BUG DETECTED: Webhook logs full findings at {func_name} level.\n"
                            f"Location: {server_path}\n"
                            f"Pattern: logger.{func_name}(..., {keyword.arg}=...)\n"
                            f"Bug #210: Logging full findings causes log bloat.\n"
                            f"Fix: Only log summary counts, not full finding objects."
                        )

    # Also do text search for explicit patterns
    lines = source.splitlines()
    for i, line in enumerate(lines):
        # Skip comments
        code = line.split("#")[0]

        # Check for findings in log calls
        if any(level in code for level in ["logger.info", "logger.debug"]):
            if "finding" in code.lower() or "results" in code.lower():
                # Allow count patterns like "findings_count" or "len(findings)"
                if not any(safe in code for safe in ["_count", "len(", "count="]):
                    pytest.fail(
                        f"BUG DETECTED: Potential full findings in log at line {i+1}.\n"
                        f"Code: {line.strip()}\n"
                        f"Bug #210: Logging full finding objects causes bloat.\n"
                        f"Fix: Use count-based logging only."
                    )


# =============================================================================
# Regression P20-2 — webhook PR handler must use select_file_source(), not rglob
# =============================================================================


def test_p20_2_webhook_handler_uses_select_file_source() -> None:
    """Regression P20-2: the PR handler must enumerate files via
    select_file_source() instead of Path.rglob.

    Before the fix, the webhook handler called Path(...).rglob(...)
    directly, bypassing the caliper exclusion layer in core/ignore.py and
    the FileSourcePort seam.  The fix replaced that with:

        from caliper.core.file_source import select_file_source
        _source = select_file_source(_repo_path)
        _files = [str(p) for p in _source.list_files(_repo_path, suffixes=...)]

    This test reads server.py as text and AST to assert:
      1. "select_file_source" appears in the source (the import and call are present).
      2. ".rglob(" is NOT present in the webhook handler closure.
    """
    repo_root = Path(__file__).parent.parent.parent
    server_path = repo_root / "src" / "caliper" / "webhook" / "server.py"

    if not server_path.exists():
        pytest.skip("webhook server.py not found")

    source = server_path.read_text()

    # 1. select_file_source must be referenced (imported and called).
    assert "select_file_source" in source, (
        "P20-2 regression: 'select_file_source' not found in webhook/server.py. "
        "The PR handler must import and call select_file_source() to enumerate "
        "files through the FileSourcePort seam instead of using Path.rglob."
    )

    # 2. list_files must be called on the source object.
    assert "list_files" in source, (
        "P20-2 regression: 'list_files' not found in webhook/server.py. "
        "The PR handler must call _source.list_files(suffixes=...) to enumerate files."
    )

    # 3. The handler closure must NOT use .rglob — that bypasses the seam.
    tree = ast.parse(source)
    webhook_func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            seg = ast.get_source_segment(source, node) or ""
            if "X-GitHub-Event" in seg or "pull_request" in seg:
                webhook_func = node
                break

    if webhook_func is not None:
        handler_source = ast.get_source_segment(source, webhook_func) or ""
        assert ".rglob(" not in handler_source, (
            "P20-2 regression: '.rglob(' found inside the webhook handler. "
            "File enumeration must go through select_file_source().list_files(), "
            "not Path.rglob — rglob bypasses the caliper exclusion layer."
        )


def test_p20_2_webhook_does_not_import_ignore_directly() -> None:
    """The rglob removal also dropped direct caliper.core.ignore imports from
    server.py (those were only needed to replicate ignore logic inline).

    This test confirms that server.py delegates ignore logic to file_source
    and does not re-implement it by importing from core.ignore directly.
    """
    repo_root = Path(__file__).parent.parent.parent
    server_path = repo_root / "src" / "caliper" / "webhook" / "server.py"

    if not server_path.exists():
        pytest.skip("webhook server.py not found")

    source = server_path.read_text()

    # After P20-2, server.py should NOT import from caliper.core.ignore.
    assert "from caliper.core.ignore" not in source, (
        "P20-2 regression: server.py still imports from caliper.core.ignore. "
        "Ignore logic must be delegated to select_file_source().list_files() — "
        "the server should not re-implement the exclusion layer."
    )
    assert "import caliper.core.ignore" not in source, (
        "P20-2 regression: server.py still imports caliper.core.ignore. "
        "File enumeration and exclusions belong in the FileSourcePort seam."
    )
