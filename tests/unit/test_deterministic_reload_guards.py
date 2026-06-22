"""Deterministic guards for policy bundle hot-reload file watching bugs.

# tested-by: tests/unit/test_deterministic_reload_guards.py
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.xfail(
    reason="deterministic bug detector",
    strict=False,
)


@pytest.mark.xfail(reason="deterministic bug detector for #242", strict=False)
def test_242_policy_bundle_reload_watches_correct_file_patterns() -> None:
    """Policy bundle hot-reload must watch .rego files, not just source files.

    Issue #208 / Detector #242: The file watcher watches for changes to trigger
    hot-reload of policy bundles. If the watch pattern doesn't include .rego
    files (the actual policy bundle files), policy changes won't trigger reloads.

    This test verifies that _WATCH_EXTENSIONS includes .rego to match the
    opa_policy_path default of "./policies/policy.rego".
    """
    from caliper.cli.watch import _WATCH_EXTENSIONS
    from caliper.core.config import CaliperSettings

    # The watch extensions must include .rego for policy bundle hot-reload
    assert ".rego" in _WATCH_EXTENSIONS, (
        "_WATCH_EXTENSIONS missing '.rego' — policy bundle changes won't trigger reload. "
        f"Current extensions: {sorted(_WATCH_EXTENSIONS)}"
    )

    # Verify that the default policy path uses a .rego extension
    settings = CaliperSettings(
        db_dsn="postgresql://test:test@localhost/test",
    )
    policy_path = Path(settings.opa_policy_path)

    # The default policy path must use an extension that's in the watch list
    assert policy_path.suffix in _WATCH_EXTENSIONS, (
        f"Default opa_policy_path suffix '{policy_path.suffix}' not in _WATCH_EXTENSIONS. "
        f"Policy file at {settings.opa_policy_path} changes won't trigger hot-reload. "
        f"Watch extensions: {sorted(_WATCH_EXTENSIONS)}"
    )


@pytest.mark.xfail(reason="deterministic bug detector for #242", strict=False)
def test_242_policy_directory_files_match_watch_patterns(tmp_path: Path) -> None:
    """Policy directory files must have extensions that are watched.

    If policy files exist with extensions not in _WATCH_EXTENSIONS, they won't
    trigger hot-reload when modified. This test scans the policies directory
    and verifies all policy files have watchable extensions.
    """
    from caliper.cli.watch import _WATCH_EXTENSIONS

    # Find the policies directory relative to this test file
    test_file = Path(__file__)
    repo_root = test_file.parent.parent.parent
    policies_dir = repo_root / "policies"

    # If policies directory exists, scan it for unwatched policy files
    if not policies_dir.exists():
        pytest.skip("policies directory not found")

    unwatched_files: list[Path] = []
    for policy_file in policies_dir.rglob("*"):
        if policy_file.is_file() and policy_file.suffix:
            if policy_file.suffix not in _WATCH_EXTENSIONS:
                unwatched_files.append(policy_file.relative_to(repo_root))

    assert not unwatched_files, (
        f"Policy files with unwatched extensions found: {unwatched_files}. "
        f"These files won't trigger hot-reload when modified. "
        f"Add their extensions to _WATCH_EXTENSIONS or remove them."
    )
