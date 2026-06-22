"""Deterministic bug detector for config merge issues (#262).

# tested-by: tests/unit/test_deterministic_config_guards.py
"""

from __future__ import annotations

from pathlib import Path


def test_262_config_merge_preserves_telemetry_settings(tmp_path: Path) -> None:
    """Detect when telemetry settings are dropped during config merge.

    Bug #262: When merging root and package config, telemetry settings
    from the root config should be preserved if not explicitly overridden
    in the package config.

    Acceptance criteria:
    - Root telemetry settings (enabled, endpoint) must survive merge
    - Package config can override, but root values are the default
    """
    from eedom.core.repo_config import load_merged_config

    # Create root config with explicit telemetry settings
    (tmp_path / ".eagle-eyed-dom.yaml").write_text(
        "telemetry:\n"
        "  enabled: true\n"
        "  endpoint: https://custom.telemetry.example.com/v1/events\n"
        "plugins:\n"
        "  disabled:\n"
        "    - trivy\n"
    )

    # Create package config WITHOUT telemetry section
    package_root = tmp_path / "packages" / "api"
    package_root.mkdir(parents=True)
    (package_root / ".eagle-eyed-dom.yaml").write_text(
        "thresholds:\n" "  semgrep:\n" "    max_findings: 5\n"
    )

    merged = load_merged_config(tmp_path, package_root=package_root)

    # These assertions will fail if telemetry settings are dropped
    assert merged.telemetry.enabled is True, (
        f"Expected telemetry.enabled=True from root config, " f"but got {merged.telemetry.enabled}"
    )
    assert merged.telemetry.endpoint == "https://custom.telemetry.example.com/v1/events", (
        f"Expected custom telemetry endpoint from root config, "
        f"but got {merged.telemetry.endpoint}"
    )
