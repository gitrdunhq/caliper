"""Deterministic guards for telemetry settings being dropped during config merge (Issue #262).

Bug: load_merged_config() correctly merges plugins and thresholds from the root
     and package-level configs, but always produces a RepoConfig with the default
     TelemetryConfig(), silently discarding any custom telemetry settings in the
     root config.

Evidence:
  - repo_config.py line 65 (return statement):
      return RepoConfig(plugins=merged_plugins, thresholds=merged_thresholds)
    No `telemetry=` keyword argument is passed, so the root config's telemetry
    is replaced with TelemetryConfig() defaults on every package-level merge.

Fix: Compute merged_telemetry (package value takes precedence; falls back to root),
     and pass `telemetry=merged_telemetry` to the returned RepoConfig.

Parent bug: #228 / Epic: #146.
Status: xfail — telemetry dropped by the merge.
"""

from __future__ import annotations

import inspect
from pathlib import Path

# xfail for #262 removed — telemetry merge fix is live (P05-1).

_CALIPER_CFG = ".caliper.yaml"


def test_262_load_merged_config_source_handles_telemetry() -> None:
    """load_merged_config() source must include telemetry handling.

    When the bug exists, the return statement constructs RepoConfig with only
    plugins= and thresholds= — there is no reference to "telemetry" in the
    entire function body.  When the bug is fixed, a telemetry merge will appear.
    """
    from caliper.core.repo_config import load_merged_config

    src = inspect.getsource(load_merged_config)
    assert len(src) > 50, "inspect.getsource returned empty source — load_merged_config not found"
    assert "telemetry" in src, (
        "BUG #262: load_merged_config() contains no reference to 'telemetry'. "
        "The function silently drops telemetry settings when merging root and "
        "package-level configs.  Add telemetry merging logic and pass "
        "`telemetry=merged_telemetry` to the returned RepoConfig."
    )


def test_262_merged_config_preserves_root_telemetry_endpoint(tmp_path: Path) -> None:
    """Behavioral: root telemetry endpoint must survive a package-level merge.

    When load_merged_config() merges a root config (custom telemetry endpoint)
    with a package config (different plugins), the resulting RepoConfig must
    retain the root's telemetry endpoint, not revert to the class default.
    """
    from caliper.core.repo_config import load_merged_config

    root_dir = tmp_path / "root"
    root_dir.mkdir()
    pkg_dir = root_dir / "sub"
    pkg_dir.mkdir()

    custom_endpoint = "https://custom-telemetry.example.com/v1/events"
    (root_dir / _CALIPER_CFG).write_text(
        f"telemetry:\n  enabled: true\n  endpoint: {custom_endpoint}\n"
    )
    (pkg_dir / _CALIPER_CFG).write_text("plugins:\n  disabled:\n    - mypy\n")

    result = load_merged_config(root_dir, package_root=pkg_dir)

    assert result.telemetry.enabled is True, (
        "BUG #262: telemetry.enabled was True in root config but load_merged_config() "
        "returned enabled=False (the default).  Telemetry settings are dropped during merge."
    )
    assert result.telemetry.endpoint == custom_endpoint, (
        f"BUG #262: telemetry.endpoint should be '{custom_endpoint}' (from root config) "
        f"but got '{result.telemetry.endpoint}' (the default).  "
        "load_merged_config() discards telemetry when merging with a package config."
    )
