"""Deterministic rotation guards for secrets automation.

These tests intentionally encode rotation invariants as static checks.
They use @pytest.mark.xfail to allow the test suite to pass while
violations exist, documenting the security debt.

When violations are fixed, the test will "pass" and xfail will report
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

# Files that handle secrets and should have rotation automation
_SECRET_HANDLING_FILES: tuple[Path, ...] = (
    _SRC / "core" / "config.py",
    _SRC / "agent" / "config.py",
    _SRC / "webhook" / "config.py",
)

# Patterns indicating automated rotation triggers
_ROTATION_TRIGGER_PATTERNS: Set[str] = {
    "cron",
    "schedule",
    "rotate",
    "rotation",
    "expiry",
    "expiration",
    "renew",
    "refresh_token",
    "vault",  # HashiCorp Vault, etc. handle rotation
    "aws secrets",  # AWS Secrets Manager auto-rotation
    "azure keyvault",
    "gcp secret",
}

# Secret-bearing field name patterns (case-insensitive)
_SECRET_FIELD_PATTERNS = (
    "api_key",
    "apikey",
    "credential",
    "dsn",
    "password",
    "private_key",
    "secret",
    "token",
    "github_token",
)


def _rel(path: Path) -> str:
    """Return relative path from repo root as posix string."""
    return path.relative_to(_REPO).as_posix()


def _parse(path: Path) -> ast.Module:
    """Parse a Python file into an AST."""
    return ast.parse(path.read_text(), filename=str(path))


def _get_secret_fields(tree: ast.Module) -> list[tuple[str, int]]:
    """Extract secret-bearing field names and their line numbers from AST."""
    secrets: list[tuple[str, int]] = []

    for node in ast.walk(tree):
        # Check annotated assignments (Pydantic Settings fields)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            field_name = node.target.id
            if any(pattern in field_name.lower() for pattern in _SECRET_FIELD_PATTERNS):
                secrets.append((field_name, node.lineno or 0))

        # Check regular assignments in class bodies
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    field_name = target.id
                    if any(pattern in field_name.lower() for pattern in _SECRET_FIELD_PATTERNS):
                        secrets.append((field_name, node.lineno or 0))

    return secrets


def _has_rotation_trigger(tree: ast.Module) -> bool:
    """Check if the AST contains any rotation automation patterns."""
    for node in ast.walk(tree):
        # Check string literals and comments
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            lower_value = node.value.lower()
            if any(pattern in lower_value for pattern in _ROTATION_TRIGGER_PATTERNS):
                return True

        # Check function/method names
        if isinstance(node, ast.FunctionDef):
            lower_name = node.name.lower()
            if any(pattern in lower_name for pattern in _ROTATION_TRIGGER_PATTERNS):
                return True

        # Check class names
        if isinstance(node, ast.ClassDef):
            lower_name = node.name.lower()
            if "rotation" in lower_name or "secret" in lower_name:
                return True

        # Check attribute names (method calls like vault.rotate())
        if isinstance(node, ast.Attribute):
            lower_attr = node.attr.lower()
            if any(pattern in lower_attr for pattern in _ROTATION_TRIGGER_PATTERNS):
                return True

        # Check import statements for rotation libraries
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name:
                    lower_name = alias.name.lower()
                    if any(
                        pattern in lower_name
                        for pattern in {"vault", "secretsmanager", "keyvault", "rotate"}
                    ):
                        return True

    return False


def _has_rotation_ci_workflow() -> bool:
    """Check if there are CI/CD workflows for secret rotation."""
    ci_paths = [
        _REPO / ".github" / "workflows" / "rotate-secrets.yml",
        _REPO / ".github" / "workflows" / "secret-rotation.yml",
        _REPO / ".github" / "workflows" / "rotate.yml",
        _REPO / "scripts" / "rotate_secrets.py",
        _REPO / "scripts" / "rotate-secrets.sh",
        _REPO / "scripts" / "secret_rotation.py",
    ]
    return any(path.exists() for path in ci_paths)


@pytest.mark.xfail(
    reason="deterministic bug detector: issue #198 - secrets rotation lacks automated trigger",
    strict=False,
)
def test_198_secrets_rotation_lacks_automated_trigger() -> None:
    """Detect secrets handling without automated rotation triggers.

    Issue #198 (parent #164): Secrets-bearing configurations must have
    automated rotation triggers to prevent stale secrets and reduce
    blast radius from leaked credentials.

    Violations:
        - src/caliper/core/config.py - llm_api_key: SecretStr with no rotation
        - src/caliper/agent/config.py - github_token: SecretStr with no rotation
        - src/caliper/webhook/config.py - secret: str with no rotation
        - src/caliper/webhook/config.py - github_token: SecretStr with no rotation
        - No CI workflow for automated rotation detected

    Acceptance criteria for fix:
        - Each secret-bearing config must have rotation automation (cron,
          scheduled task, Vault integration, cloud secrets manager, etc.)
        - CI workflow exists for automated secret rotation
        - Rotation triggers are discoverable via code inspection
    """
    violations: list[str] = []

    # Check for CI workflow rotation automation
    if not _has_rotation_ci_workflow():
        violations.append(
            "No CI/CD workflow for secret rotation found "
            "(expected .github/workflows/rotate-secrets.yml or similar)"
        )

    # Check each secret-handling file for rotation triggers
    for path in _SECRET_HANDLING_FILES:
        if not path.exists():
            continue

        tree = _parse(path)

        # Find secret fields in this file
        secret_fields = _get_secret_fields(tree)

        if secret_fields and not _has_rotation_trigger(tree):
            fields_str = ", ".join(f"{name} (line {lineno})" for name, lineno in secret_fields)
            violations.append(
                f"{_rel(path)}: secrets [{fields_str}] "
                f"have no automated rotation trigger (cron, scheduler, vault, etc.)"
            )

    assert (
        violations == []
    ), "Secrets-bearing configurations must have automated rotation triggers:\n" + "\n".join(
        f"  - {v}" for v in violations
    )


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_198_config_has_secret_rotation_automation() -> None:
    """Specific test for core/config.py secrets rotation."""
    path = _SRC / "core" / "config.py"
    tree = _parse(path)

    violations: list[str] = []

    # Check for llm_api_key field
    has_llm_api_key = False
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "llm_api_key":
                has_llm_api_key = True
                break

    if has_llm_api_key and not _has_rotation_trigger(tree):
        violations.append(
            f"{_rel(path)}: llm_api_key has no automated rotation trigger "
            f"(no cron, schedule, vault integration, or cloud secrets manager)"
        )

    assert violations == [], "\n".join(violations)


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_198_agent_config_has_secret_rotation_automation() -> None:
    """Specific test for agent/config.py secrets rotation."""
    path = _SRC / "agent" / "config.py"
    tree = _parse(path)

    violations: list[str] = []

    # Check for github_token field
    has_github_token = False
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "github_token":
                has_github_token = True
                break

    if has_github_token and not _has_rotation_trigger(tree):
        violations.append(
            f"{_rel(path)}: github_token has no automated rotation trigger "
            f"(no cron, schedule, vault integration, or cloud secrets manager)"
        )

    assert violations == [], "\n".join(violations)


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_198_webhook_config_has_secret_rotation_automation() -> None:
    """Specific test for webhook/config.py secrets rotation."""
    path = _SRC / "webhook" / "config.py"
    tree = _parse(path)

    violations: list[str] = []

    # Check for secret and github_token fields
    secret_fields = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id in ("secret", "github_token"):
                secret_fields.append(node.target.id)

    if secret_fields and not _has_rotation_trigger(tree):
        fields_str = ", ".join(secret_fields)
        violations.append(
            f"{_rel(path)}: {fields_str} have no automated rotation trigger "
            f"(no cron, schedule, vault integration, or cloud secrets manager)"
        )

    assert violations == [], "\n".join(violations)


@pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)
def test_198_has_secret_rotation_ci_workflow() -> None:
    """Verify existence of CI workflow for secret rotation."""
    violations: list[str] = []

    if not _has_rotation_ci_workflow():
        violations.append(
            "Missing CI/CD workflow for secret rotation. "
            "Expected one of:\n"
            "  - .github/workflows/rotate-secrets.yml\n"
            "  - .github/workflows/secret-rotation.yml\n"
            "  - .github/workflows/rotate.yml\n"
            "  - scripts/rotate_secrets.py\n"
            "  - scripts/rotate-secrets.sh\n"
            "  - scripts/secret_rotation.py"
        )

    assert violations == [], "\n".join(violations)
