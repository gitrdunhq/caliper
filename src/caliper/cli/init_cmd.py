"""``caliper init`` — write the standard ``.caliper.yaml``.
# tested-by: tests/unit/test_init_cmd.py

Caliper's defaults *are* the standard: a bare ``caliper review`` runs every
default plugin with the default thresholds. ``init`` writes those defaults
out as a commented file so a repo's config is a visible diff from the
standard, not a guess (#291). Every value below equals ``RepoConfig()``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from caliper.core.repo_config import _CONFIG_FILENAME

_DEFAULT_CONFIG = """\
# .caliper.yaml — caliper's standard configuration.
#
# Every value in this file is the default. A bare `caliper review` behaves
# exactly like this file; edit only what you want to change from the standard.
# Schema: `caliper schema`. Docs: docs/configuration.md.

# Which scanner plugins run. `enabled: null` means "all default plugins".
# `scancode` (license detection) is opt-in — list it under `enabled` to run it.
plugins:
  # enabled: [syft, osv-scanner, trivy, semgrep, gitleaks, kube-linter, pmd, cpd, scancode]
  # disabled: [cpd]
  semgrep:
    # Extra semgrep rule directories, resolved relative to the repo root.
    extra_config_dirs: []
    # Rule ids to drop from the results.
    exclude_rules: []

# Numeric gates. Keys are plugin names; values are that plugin's knobs.
# Example: `complexity: {ccn: 10}` — the cyclomatic-complexity threshold (default 10).
# Example: `semgrep: {min_severity: medium}` — the minimum semgrep severity
# that produces a finding (default "medium").
thresholds: {}

# .caliperignore — one `<glob>` per line skips the file entirely; a scoped
# line limits the skip to specific rules instead of the whole file:
#   <glob> !<rule-id-prefix>
# e.g. `tests/fixtures/** !CAL-` ignores only CAL-NNN detector findings
# under that glob, leaving other scanners active there.

# Deterministic AST detectors (CAL-NNN). `default` is the standard profile;
# add `house-rules` for the stricter opinionated set. `enable`/`disable`
# take individual detector ids and win over the profile.
detectors:
  profiles: [default]
  enable: []
  disable: []

# Known findings that are accepted for a while (`caliper baseline`).
baseline:
  path: .caliper-baseline.yaml
  default_ttl_days: 90

# Import-direction rules for the architecture check. Leave `package` empty
# to skip it; see docs/configuration.md for `tiers` and `allow`.
architecture:
  package: ""
  src_root: ""
  tiers: {}
  allow: {}

# `caliper part` — how a change is cut into reviewable commits.
parting:
  # One commit per bucket by default; set a number to split big buckets.
  size_cap: null
  target: stack
  # Human reclassifications, first matching glob wins; provenance-tracked.
  overrides: []
"""


def render_default_config() -> str:
    """The standard config as commented YAML; loads to ``RepoConfig()``."""
    return _DEFAULT_CONFIG


@click.command("init")
@click.option(
    "--repo-path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=".",
    show_default=True,
    help="Repository to write the config into.",
)
@click.option("--force", is_flag=True, help="Overwrite an existing .caliper.yaml.")
@click.option(
    "--print", "print_only", is_flag=True, help="Print the standard config; write nothing."
)
def init(repo_path: Path, force: bool, print_only: bool) -> None:
    """Write the standard .caliper.yaml (every value is the default)."""
    text = render_default_config()
    if print_only:
        click.echo(text, nl=False)
        return
    target = repo_path / _CONFIG_FILENAME
    if target.exists() and not force:
        click.echo(f"{target} already exists; pass --force to overwrite it.", err=True)
        sys.exit(1)
    target.write_text(text, encoding="utf-8")
    click.echo(f"Wrote {target} — the standard config; edit only what you want to change.")
