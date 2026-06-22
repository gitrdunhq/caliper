"""Deterministic detector for policy bundle download checksum verification (Issue #222).

# tested-by: tests/unit/test_deterministic_checksum_guards.py

This module detects missing checksum verification when downloading policy bundles
from remote URLs. Issue #188 identified that policy bundle downloads don't verify
checksums, creating a supply chain vulnerability.

Acceptance criteria for fix:
- Policy bundle downloads must verify SHA256 checksums
- Download functions must include hash verification logic
- Failed checksum verification must raise an error
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

# Patterns that indicate a download function
_DOWNLOAD_PATTERNS: Set[str] = {
    "download",
    "fetch",
    "get",
    "request",
    "urlopen",
}

# Patterns that indicate policy bundle related code
_POLICY_BUNDLE_PATTERNS: Set[str] = {
    "policy",
    "bundle",
    "policy_bundle",
    "opa_policy",
}

# Patterns that indicate checksum verification
_CHECKSUM_PATTERNS: Set[str] = {
    "sha256",
    "hashlib",
    "checksum",
    "hash",
    "verify",
    "digest",
    "hexdigest",
}


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _is_download_function(node: ast.FunctionDef) -> bool:
    """Check if function name suggests it's a download function."""
    name_lower = node.name.lower()
    return any(pattern in name_lower for pattern in _DOWNLOAD_PATTERNS)


def _is_policy_bundle_related(node: ast.FunctionDef) -> bool:
    """Check if function name suggests policy bundle handling."""
    name_lower = node.name.lower()
    return any(pattern in name_lower for pattern in _POLICY_BUNDLE_PATTERNS)


def _contains_checksum_verification(func_body: list[ast.stmt]) -> bool:
    """
    Check if function body contains checksum verification patterns.

    Looks for:
    - hashlib.sha256() usage
    - checksum comparison
    - hash verification calls
    """
    body_source = ast.dump(func_body, indent=2).lower()
    return any(pattern in body_source for pattern in _CHECKSUM_PATTERNS)


def _contains_http_download(func_body: list[ast.stmt]) -> bool:
    """
    Check if function body contains HTTP download patterns.

    Looks for:
    - requests.get() / requests.post()
    - httpx.get() / httpx.Client()
    - urllib.request.urlopen()
    """
    body_dump = ast.dump(func_body, indent=2).lower()
    http_patterns = {
        "requests.get",
        "requests.post",
        "httpx.get",
        "httpx.client",
        "httpx.asyncclient",
        "urlopen",
        "urllib.request",
    }
    return any(pattern in body_dump for pattern in http_patterns)


def _scan_file_for_download_functions(path: Path) -> list[dict]:
    """Scan a Python file for functions that download without checksum verification."""
    if not path.exists():
        return []

    try:
        tree = ast.parse(path.read_text(), filename=str(path))
    except SyntaxError:
        return []

    violations = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            # Check if this looks like a download function
            is_download = _is_download_function(node)
            is_policy_related = _is_policy_bundle_related(node)
            has_http = _contains_http_download(node.body)
            has_checksum = _contains_checksum_verification(node.body)

            # Flag functions that:
            # 1. Are named like download functions OR policy-related functions
            # 2. Contain HTTP download patterns
            # 3. Do NOT contain checksum verification
            if (is_download or is_policy_related) and has_http and not has_checksum:
                violations.append(
                    {
                        "function": node.name,
                        "lineno": node.lineno,
                        "path": path,
                        "reason": "downloads content without checksum verification",
                    }
                )

    return violations


@pytest.mark.xfail(
    reason="deterministic bug detector for #188: policy bundle download lacks checksum verification",
    strict=False,
)
def test_188_policy_bundle_download_missing_checksum_verification() -> None:
    """
    Detect policy bundle downloads that don't verify checksums.

    Issue #188: Policy bundle downloads don't verify checksums, allowing
    potential supply chain attacks where a compromised bundle could be
    substituted without detection.

    This test scans for functions that:
    1. Have names suggesting download or policy bundle handling
    2. Use HTTP client libraries (requests, httpx, urllib)
    3. Do NOT use hashlib or checksum verification

    Acceptance criteria for fix:
    - Policy bundle downloads must compute and verify SHA256 checksums
    - Downloaded bundles must match expected hash before use
    - Checksum failures must prevent bundle activation
    """
    violations: list[str] = []

    # Scan all Python source files
    for py_file in _SRC.rglob("*.py"):
        # Skip __init__.py and test files
        if py_file.name == "__init__.py" or "test" in py_file.name:
            continue

        file_violations = _scan_file_for_download_functions(py_file)

        for v in file_violations:
            violations.append(
                f"{_rel(v['path'])}:{v['lineno']}: " f"function '{v['function']}' {v['reason']}"
            )

    # Also check for any configuration that might enable remote policy downloads
    # without specifying checksum verification
    config_path = _SRC / "core" / "config.py"
    if config_path.exists():
        try:
            tree = ast.parse(config_path.read_text(), filename=str(config_path))
            config_source = ast.dump(tree).lower()

            # Check for remote URL configuration without checksum fields
            if "policy_url" in config_source or "remote_policy" in config_source:
                if "checksum" not in config_source and "sha256" not in config_source:
                    violations.append(
                        f"{_rel(config_path)}: "
                        f"remote policy URL configuration lacks checksum verification fields"
                    )
        except SyntaxError:
            pass

    # If no violations found, the bug is present (we expect to find download code
    # without checksum verification). If code is added later, this test will
    # catch missing checksum verification.
    if not violations:
        # Check if there's any policy download code at all
        has_download_code = False
        for py_file in _SRC.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue
            try:
                tree = ast.parse(py_file.read_text(), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        if _is_policy_bundle_related(node) and _contains_http_download(node.body):
                            has_download_code = True
                            break
            except SyntaxError:
                continue

        if not has_download_code:
            # No policy download code found - bug is latent
            pytest.fail(
                "BUG #188 DETECTED: No policy bundle download code with checksum "
                "verification found. When policy bundle download is implemented, "
                "it MUST include SHA256 checksum verification to prevent supply "
                "chain attacks.\n\n"
                "Acceptance criteria:\n"
                "1. Policy bundle downloads must verify SHA256 checksums\n"
                "2. Download functions must include hash verification logic\n"
                "3. Failed checksum verification must raise an error\n"
            )
    else:
        # Found download code without checksum verification
        pytest.fail(
            "BUG #188 DETECTED: Policy bundle download functions lack checksum "
            "verification:\n\n" + "\n".join(violations) + "\n\n"
            "Each download function must:\n"
            "1. Compute SHA256 hash of downloaded content\n"
            "2. Compare against expected/pinned checksum\n"
            "3. Reject bundles with mismatched checksums\n"
        )


@pytest.mark.xfail(
    reason="deterministic bug detector for #188: policy bundle lacks checksum config",
    strict=False,
)
def test_188_policy_config_requires_checksum_field() -> None:
    """
    Verify that policy bundle configuration includes checksum fields.

    When remote policy bundles are configured, the configuration must
    include a way to specify the expected checksum for verification.

    This prevents:
    - Using outdated policy versions
    - Accidental or malicious bundle substitution
    - Silent deployment of untrusted policies
    """
    config_path = _SRC / "core" / "config.py"

    if not config_path.exists():
        pytest.skip("config.py not found")

    tree = ast.parse(config_path.read_text(), filename=str(config_path))

    # Look for CaliperSettings class
    config_fields: list[tuple[str, str, int]] = []  # (name, annotation, lineno)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "CaliperSettings":
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id.lower()
                    annotation = ast.unparse(item.annotation) if item.annotation else ""
                    config_fields.append((field_name, annotation.lower(), item.lineno))

    # Check for policy URL fields without corresponding checksum fields
    has_policy_url = any("policy" in f[0] and "url" in f[0] for f in config_fields)
    has_checksum_field = any(
        "checksum" in f[0] or "sha256" in f[0] or "hash" in f[0] for f in config_fields
    )

    if has_policy_url and not has_checksum_field:
        pytest.fail(
            f"BUG #188 DETECTED: {_rel(config_path)} has policy URL configuration "
            f"but lacks corresponding checksum/hash configuration field.\n\n"
            f"When policy bundles are downloaded from remote URLs, the configuration "
            f"must include a field to specify the expected SHA256 checksum.\n\n"
            f"Required: Add 'policy_bundle_checksum: str' or similar field to "
            f"CaliperSettings for checksum verification."
        )

    # If no policy URL config exists, the bug is latent - documented as detection
    if not has_policy_url:
        pytest.fail(
            "BUG #188 DETECTED (latent): No policy bundle URL configuration found. "
            "When remote policy bundle download is added, it MUST include:\n\n"
            "1. A configuration field for the policy bundle URL\n"
            "2. A configuration field for the expected SHA256 checksum\n"
            "3. Verification logic that rejects bundles with mismatched checksums\n"
        )


@pytest.mark.xfail(
    reason="deterministic bug detector for #188: no checksum verification in download flow",
    strict=False,
)
def test_188_no_download_without_checksum_pattern() -> None:
    """
    Verify that any download function includes checksum verification pattern.

    This is a broad-spectrum check: any function that downloads files
    should verify their integrity using cryptographic checksums.

    The test looks for the pattern:
    - hashlib.sha256() followed by .update() or direct hash computation
    - Comparison of computed hash against expected value
    - Error handling for hash mismatches
    """
    violations: list[str] = []

    for py_file in _SRC.rglob("*.py"):
        if py_file.name == "__init__.py" or "test" in py_file.name:
            continue

        try:
            source = py_file.read_text()
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_source = ast.unparse(node)
                func_dump = ast.dump(node.body).lower()

                # Check for download patterns
                has_download = any(
                    pattern in func_source.lower()
                    for pattern in ["requests.get", "httpx.get", "urlopen", "download"]
                )

                # Check for checksum patterns
                has_checksum = any(pattern in func_dump for pattern in _CHECKSUM_PATTERNS)

                # Also check for hash comparison (expected_hash == computed_hash)
                has_hash_comparison = (
                    "compare" in func_dump
                    or "==" in func_source
                    and any(h in func_source.lower() for h in ["hash", "sha", "digest"])
                )

                if has_download and not (has_checksum or has_hash_comparison):
                    violations.append(
                        f"{_rel(py_file)}:{node.lineno}: "
                        f"'{node.name}' downloads content without checksum verification"
                    )

    # Report violations
    if violations:
        pytest.fail(
            "BUG #188 DETECTED: Functions download content without "
            "cryptographic checksum verification:\n\n" + "\n".join(violations) + "\n\n"
            "Each download must:\n"
            "1. Compute SHA256 of downloaded content\n"
            "2. Compare against expected/trusted checksum\n"
            "3. Reject content with mismatched checksums\n"
        )
