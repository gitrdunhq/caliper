"""PyPI distribution rename guard (task-013).
# tested-by: tests/unit/test_pyproject_distribution_name.py

Caliper's PyPI *distribution* name is being renamed to ``caliper-review`` while
the import package and the ``caliper`` console script stay unchanged. These
tests parse ``pyproject.toml`` (and ``uv.lock``) directly rather than trusting
prose, so a partial rename fails loudly.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def _load_pyproject() -> dict:
    return tomllib.loads((_REPO / "pyproject.toml").read_text())


class TestTask013DistributionRename:
    def test_ac1_pyproject_toml_project_name_caliper_review(self):
        """AC1: pyproject.toml [project].name == 'caliper-review'."""
        data = _load_pyproject()
        assert data["project"]["name"] == "caliper-review"

    def test_ac2_pyproject_toml_project_scripts_still_maps_caliper_to_its_entry_point(self):
        """AC2: [project.scripts] still maps 'caliper' to its entry point —
        the import package/console script name is unchanged by the distribution
        rename."""
        data = _load_pyproject()
        scripts = data["project"]["scripts"]
        assert "caliper" in scripts
        assert scripts["caliper"] == "caliper.cli.main:cli"

    def test_ac3_distribution_name_differs_from_import_package_console_script(self):
        """AC3: the distribution name (what you `pip install`) is not the string
        'caliper', while the console_scripts entry 'caliper' still exists —
        i.e. distribution and import-package/console-script names have diverged
        on purpose."""
        data = _load_pyproject()
        project = data["project"]
        assert project["name"] != "caliper"
        assert project["name"] == "caliper-review"
        assert "caliper" in project["scripts"]

    def test_ac4_uv_lock_top_level_package_name_matches_caliper_review(self):
        """AC4: uv.lock is regenerated and its top-level (editable-source, i.e.
        this repo's own package) entry has name == 'caliper-review'."""
        lock_text = (_REPO / "uv.lock").read_text()
        # tomllib can't parse uv.lock's repeated [[package]] tables generically
        # here without a TOML parse of the whole file — but uv.lock IS valid
        # TOML, so parse it directly and find the editable-source package.
        lock = tomllib.loads(lock_text)
        editable_packages = [
            pkg
            for pkg in lock.get("package", [])
            if isinstance(pkg.get("source"), dict) and pkg["source"].get("editable") == "."
        ]
        assert len(editable_packages) == 1, (
            f"expected exactly one editable-source package in uv.lock, found "
            f"{[p.get('name') for p in editable_packages]}"
        )
        assert editable_packages[0]["name"] == "caliper-review"
